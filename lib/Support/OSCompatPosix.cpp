/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#if !defined(_WINDOWS) && !defined(__EMSCRIPTEN__)

#include "hermes/Support/Compiler.h"
#include "hermes/Support/ErrorHandling.h"
#include "hermes/Support/OSCompat.h"

#include <cassert>
#include <fstream>
#include <vector>

#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>

#if defined(__linux__)
#if !defined(RUSAGE_THREAD)
#define RUSAGE_THREAD 1
#endif
#endif             

#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __MACH__
#include <mach/mach.h>

#endif            

#ifdef __linux__

#if !defined(_POSIX_TIMERS) || _POSIX_TIMERS <= 0
#error "Timers not supported on this Android platform."
#endif

#ifndef CLOCK_THREAD_CPUTIME_ID
#error "CLOCK_THREAD_CPUTIME_ID not supported by clock_gettime"
#endif

#include <sys/syscall.h>
#include <time.h>

#endif             

#if defined(__linux__) || defined(__ANDROID__)
#include <sys/prctl.h>
#endif

#ifdef __ANDROID__
#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif

#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif
#endif               

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#include "llvh/Config/config.h"
#include "llvh/Support/raw_ostream.h"

namespace hermes {
namespace oscompat {

#ifndef NDEBUG
static size_t testPgSz = 0;

void set_test_page_size(size_t pageSz) {
  testPgSz = pageSz;
}

void reset_test_page_size() {
  testPgSz = 0;
}
#endif

static inline size_t page_size_real() {
  return getpagesize();
}

size_t page_size() {
#ifndef NDEBUG
  if (testPgSz != 0) {
    return testPgSz;
  }
#endif
  return page_size_real();
}

#ifndef NDEBUG
static constexpr size_t unsetVMAllocLimit = std::numeric_limits<size_t>::max();
static size_t totalVMAllocLimit = unsetVMAllocLimit;

void set_test_vm_allocate_limit(size_t totSz) {
  totalVMAllocLimit = totSz;
}

void unset_test_vm_allocate_limit() {
  totalVMAllocLimit = unsetVMAllocLimit;
}
#endif           

static llvh::ErrorOr<void *>
vm_mmap(void *addr, size_t sz, int prot, int flags, bool checkDebugLimit) {
  assert(sz % page_size_real() == 0);
#ifndef NDEBUG
  if (checkDebugLimit) {
    if (LLVM_UNLIKELY(sz > totalVMAllocLimit)) {
      return make_error_code(OOMError::TestVMLimitReached);
    } else if (LLVM_UNLIKELY(totalVMAllocLimit != unsetVMAllocLimit)) {
      totalVMAllocLimit -= sz;
    }
  }
#endif           
  void *result = mmap(addr, sz, prot, flags, -1, 0);
  if (result == MAP_FAILED) {
                                                                           
                        
    return std::error_code(errno, std::generic_category());
  }
  return result;
}

static void vm_munmap(void *addr, size_t sz) {
  auto ret = munmap(addr, sz);
  assert(!ret && "Failed to free memory region.");
  (void)ret;

#ifndef NDEBUG
  if (LLVM_UNLIKELY(totalVMAllocLimit != unsetVMAllocLimit) && addr) {
    totalVMAllocLimit += sz;
  }
#endif
}

static char *alignAlloc(void *p, size_t alignment) {
  return reinterpret_cast<char *>(
      llvh::alignTo(reinterpret_cast<uintptr_t>(p), alignment));
}

static llvh::ErrorOr<void *>
vm_mmap_aligned(void *addr, size_t sz, size_t alignment, int prot, int flags) {
  assert(sz > 0 && sz % page_size() == 0);
  assert(alignment > 0 && alignment % page_size() == 0);

                                                                            
                                                                               
                
  const size_t excessSize = sz + alignment - page_size_real();
  auto result = vm_mmap(addr, excessSize, prot, flags, true);
  if (!result)
    return result;

  void *raw = *result;
  char *aligned = alignAlloc(raw, alignment);
  size_t excessAtFront = aligned - static_cast<char *>(raw);
  size_t excessAtBack = excessSize - excessAtFront - sz;

  if (excessAtFront)
    vm_munmap(raw, excessAtFront);
  if (excessAtBack)
    vm_munmap(aligned + sz, excessAtBack);

  return aligned;
}

static constexpr int kVMAllocateFlags = MAP_PRIVATE | MAP_ANONYMOUS;
static constexpr int kVMAllocateProt = PROT_READ | PROT_WRITE;

llvh::ErrorOr<void *> vm_allocate(size_t sz, void *hint) {
  assert(sz % page_size() == 0);
#ifndef NDEBUG
  if (testPgSz != 0 && testPgSz > static_cast<size_t>(page_size_real())) {
    return vm_allocate_aligned(sz, testPgSz);
  }
#endif           
  return vm_mmap(hint, sz, kVMAllocateProt, kVMAllocateFlags, true);
}

llvh::ErrorOr<void *>
vm_allocate_aligned(size_t sz, size_t alignment, void *hint) {
  assert(sz > 0 && sz % page_size() == 0);
  assert(alignment > 0 && alignment % page_size() == 0);
                                                                            
                                                                          
  assert(llvh::isPowerOf2_64(alignment));

                                                             
                                                 
                                                                
                                                       
  auto result = vm_mmap(hint, sz, kVMAllocateProt, kVMAllocateFlags, true);
  if (!result) {
    return result;
  }
  void *mem = *result;
  if (mem == alignAlloc(mem, alignment)) {
    return mem;
  }

                                       
  vm_munmap(mem, sz);

  return vm_mmap_aligned(
      hint, sz, alignment, kVMAllocateProt, kVMAllocateFlags);
}

void vm_free(void *p, size_t sz) {
  vm_munmap(p, sz);
}

void vm_free_aligned(void *p, size_t sz) {
  vm_free(p, sz);
}

static constexpr int kVMReserveProt = PROT_NONE;
static constexpr int kVMReserveFlags =
    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;

llvh::ErrorOr<void *>
vm_reserve_aligned(size_t sz, size_t alignment, void *hint) {
  return vm_mmap_aligned(hint, sz, alignment, kVMReserveProt, kVMReserveFlags);
}

void vm_release_aligned(void *p, size_t sz) {
  vm_munmap(p, sz);
}

llvh::ErrorOr<void *> vm_commit(void *p, size_t sz) {
  return vm_mmap(p, sz, kVMAllocateProt, kVMAllocateFlags | MAP_FIXED, false);
}

void vm_uncommit(void *p, size_t sz) {
  auto res = vm_mmap(p, sz, kVMReserveProt, kVMReserveFlags | MAP_FIXED, false);
  (void)res;
  assert(res && "uncommit failed");
}

void vm_hugepage(void *p, size_t sz) {
  assert(
      reinterpret_cast<uintptr_t>(p) % page_size() == 0 &&
      "Precondition: pointer is page-aligned.");

#if defined(__linux__) || defined(__ANDROID__)
                                                                
  madvise(p, sz, MADV_HUGEPAGE);
#endif
}

void vm_unused(void *p, size_t sz) {
#ifndef NDEBUG
  const size_t PS = page_size();
  assert(
      reinterpret_cast<intptr_t>(p) % PS == 0 &&
      "Precondition: pointer is page-aligned.");
#endif

                                                                               
                                                                           
#if defined(__MACH__)

                                                                             
                                     
#define MADV_UNUSED MADV_FREE

#elif defined(__linux__)

                                                                              
                                                                     
#define MADV_UNUSED MADV_DONTNEED

#else
#error "Don't know how to return memory to the OS on this platform."
#endif                       

  madvise(p, sz, MADV_UNUSED);

#undef MADV_UNUSED
}

void vm_prefetch(void *p, size_t sz) {
  assert(
      reinterpret_cast<intptr_t>(p) % page_size() == 0 &&
      "Precondition: pointer is page-aligned.");
  madvise(p, sz, MADV_WILLNEED);
}

void vm_name(void *p, size_t sz, const char *name) {
#ifdef __ANDROID__
  prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, p, sz, name);
#else
  (void)p;
  (void)sz;
  (void)name;
#endif               
}

bool vm_protect(void *p, size_t sz, ProtectMode mode) {
  auto prot = PROT_NONE;
  if (mode == ProtectMode::ReadWrite) {
    prot = PROT_WRITE | PROT_READ;
  }
  int err = mprotect(p, sz, prot);
  return err != -1;
}

bool vm_madvise(void *p, size_t sz, MAdvice advice) {
#ifndef NDEBUG
  const size_t PS = page_size();
  assert(
      reinterpret_cast<intptr_t>(p) % PS == 0 &&
      "Precondition: pointer is page-aligned.");
#endif

  int param = MADV_NORMAL;
  switch (advice) {
    case MAdvice::Random:
      param = MADV_RANDOM;
      break;
    case MAdvice::Sequential:
      param = MADV_SEQUENTIAL;
      break;
  }
  return madvise(p, sz, param) == 0;
}

llvh::ErrorOr<size_t> vm_footprint(char *start, char *end) {
#ifdef __MACH__
  const task_t self = mach_task_self();

  vm_address_t vAddr = reinterpret_cast<vm_address_t>(start);
  vm_size_t vSz = static_cast<vm_size_t>(end - start);
  vm_region_extended_info_data_t info;
  mach_msg_type_number_t fields = VM_REGION_EXTENDED_INFO_COUNT;
  mach_port_t unused;

  auto ret = vm_region_64(
      self,
      &vAddr,
      &vSz,
      VM_REGION_EXTENDED_INFO,
                                                                               
                                                                               
                                                   
      reinterpret_cast<vm_region_info_t>(&info),
      &fields,
      &unused);

  if (ret != KERN_SUCCESS)
    return std::error_code(errno, std::generic_category());

  return info.pages_dirtied;
#else
  auto rStart = reinterpret_cast<uintptr_t>(start);
  auto rEnd = reinterpret_cast<uintptr_t>(end);

  char label[] = "Rss:";

  std::ifstream smaps("/proc/self/smaps");

  while (smaps) {
    std::string firstToken;
    smaps >> firstToken;

                                   
    smaps.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    if (firstToken.find_last_of(':') != std::string::npos) {
                                                                              
                          
      continue;
    }

                                                                               
                                                             
    std::stringstream ris(firstToken);
    uintptr_t mStart, mEnd;
    ris >> std::hex >> mStart;
                 
    ris.ignore();
    ris >> mEnd;

                                                                               
                                                                               
    if (mStart <= rStart && rEnd <= mEnd) {
                                                                    
      break;
    }
  }

  while (smaps) {
    std::string line;
    std::getline(smaps, line);

    if (line.compare(0, sizeof(label) - 1, label) != 0) {
      continue;
    }

    std::stringstream lis(line);
    lis.ignore(line.length(), ' ');                 

    size_t rss;
    std::string unit;
    lis >> std::skipws >> rss >> unit;

    assert(unit == "kB");
    return rss * 1024 / page_size();
  }

  return std::error_code(errno, std::generic_category());
#endif
}

int pages_in_ram(const void *p, size_t sz, llvh::SmallVectorImpl<int> *runs) {
  const auto PS = page_size();
  {
                                                
    const uintptr_t addr = reinterpret_cast<uintptr_t>(p);
    const size_t adjust = addr % PS;
    p = reinterpret_cast<const void *>(addr - adjust);
    sz += adjust;
  }
                                                    
  const size_t mapSize = (sz + PS - 1) / PS;
#ifdef __linux__
  using MapElm = unsigned char;
#else
  using MapElm = char;
#endif
  std::vector<MapElm> bitMap(mapSize);
  if (mincore(const_cast<void *>(p), sz, bitMap.data())) {
    return -1;
  }
                        
  int totalIn = 0;
  bool currentRunStatus = true;
  if (runs)
    runs->push_back(0);
  for (auto elm : bitMap) {
                                       
    bool thisStatus = (elm & 1);
    totalIn += thisStatus;
    if (runs) {
      if (thisStatus != currentRunStatus)
        runs->push_back(0);
      currentRunStatus = thisStatus;
      ++runs->back();
    }
  }
  return totalIn;
}

uint64_t peak_rss() {
  rusage ru;
  if (getrusage(RUSAGE_SELF, &ru)) {
             
    return 0;
  }
  uint64_t rss = ru.ru_maxrss;
#if !defined(__APPLE__) || !defined(__MACH__)
                                                     
  rss *= 1024;
#endif
  return rss;
}

uint64_t current_rss() {
#if defined(__APPLE__) && defined(__MACH__)
  struct mach_task_basic_info info;
  mach_msg_type_number_t infoCount = MACH_TASK_BASIC_INFO_COUNT;
  if (task_info(
          mach_task_self(),
          MACH_TASK_BASIC_INFO,
          (task_info_t)&info,
          &infoCount) != KERN_SUCCESS)
    return 0;
  return info.resident_size * page_size_real();
#else
  FILE *fp = fopen("/proc/self/statm", "r");
  if (!fp) {
    return 0;
  }
  long rss = 0;
                                                                              
  if (fscanf(fp, "%*d %ld", &rss) != 1) {
    fclose(fp);
    return 0;
  }
  fclose(fp);
                                                                               
                                          
  return rss * page_size_real();
#endif
}

uint64_t current_private_dirty() {
#if defined(__linux__)
  uint64_t sum = 0;
  FILE *fp = fopen("/proc/self/smaps", "r");
  static const char kPrefix[] = "Private_Dirty:";
  constexpr size_t kPrefixLen = sizeof(kPrefix) - 1;
  char buf[128];                                              
  while (fgets(buf, sizeof(buf), fp))
    if (strncmp(buf, kPrefix, kPrefixLen) == 0)
      sum += atoll(buf + kPrefixLen);
  fclose(fp);
  return sum * 1024;
#else
  return 0;
#endif
}

#if defined(__linux__)
static bool overlap(uintptr_t a, size_t asize, uintptr_t b, size_t bsize) {
                                      
  if (asize == 0 || bsize == 0)
    return false;
                            
  if (a > b)
    return overlap(b, bsize, a, asize);
                                                                           
  return a + asize > b;
}
#endif

std::vector<std::string> get_vm_protect_modes(const void *p, size_t sz) {
  std::vector<std::string> modes;
#if defined(__linux__)
  unsigned long long begin;
  unsigned long long end;
  char mode[4 + 1];
  FILE *fp = fopen("/proc/self/maps", "r");
  if (!fp) {
    modes.emplace_back("unknown");
    return modes;
  }
  while (fscanf(fp, "%llx-%llx %4s", &begin, &end, mode) == 3) {
    if (overlap(
            reinterpret_cast<uintptr_t>(p),
            sz,
            static_cast<uintptr_t>(begin),
            static_cast<size_t>(end - begin))) {
      modes.push_back(mode);
    }
                                     
    int result;
    do {
      result = fgetc(fp);
    } while (result != '\n' && result > 0);
  }
#endif
  return modes;
}

bool num_context_switches(long &voluntary, long &involuntary) {
  voluntary = involuntary = -1;
  rusage ru;
                                               
#if defined(__linux__)
  const int who = RUSAGE_THREAD;
#else
  const int who = RUSAGE_SELF;
#endif
  if (getrusage(who, &ru)) {
             
    return false;
  }
  voluntary = ru.ru_nvcsw;
  involuntary = ru.ru_nivcsw;
  return true;
}

uint64_t process_id() {
  return getpid();
}

                                                        
#if defined(__APPLE__) && defined(__MACH__)

uint64_t global_thread_id() {
  uint64_t tid = 0;
  auto ret = pthread_threadid_np(nullptr, &tid);
  assert(ret == 0 && "pthread_threadid_np shouldn't fail for current thread");
  (void)ret;
  return tid;
}

#elif defined(__ANDROID__)

uint64_t global_thread_id() {
  return gettid();
}

#elif defined(__linux__)

uint64_t global_thread_id() {
  return syscall(__NR_gettid);
}

#else
#error "Thread ID not supported on this platform"
#endif

namespace detail {

#if defined(__APPLE__) && defined(__MACH__)

std::pair<const void *, size_t> thread_stack_bounds_impl() {
  pthread_t tid = pthread_self();
  void *origin = pthread_get_stackaddr_np(tid);
  rlim_t size = 0;
  if (pthread_main_np()) {
                   
                                                                                                      
                                                                             
              
    struct rlimit limit;
    getrlimit(RLIMIT_STACK, &limit);
    size = limit.rlim_cur;
  } else {
    size = pthread_get_stacksize_np(tid);
  }

  return {origin, size};
}

#else

std::pair<const void *, size_t> thread_stack_bounds_impl() {
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_getattr_np(pthread_self(), &attr);

  void *origin;
  size_t size;
  if (pthread_attr_getstack(&attr, &origin, &size))
    hermes_fatal("Unable to obtain native stack bounds");

#ifdef __BIONIC__
                                                             
                                                                                
                     
  size_t guardSize;
  if (pthread_attr_getguardsize(&attr, &guardSize)) {
                                      
    guardSize = 0;
  }
  if (guardSize > size)
    guardSize = size;
                                                      
  origin = (char *)origin + guardSize;
  size -= guardSize;
#endif

  pthread_attr_destroy(&attr);

                                               
  return {(char *)origin + size, size};
}

#endif

}                    

void set_thread_name(const char *name) {
                                                                                
                                                             
  TsanThreadName(name);
#if defined(__linux__) || defined(__ANDROID__)
  prctl(PR_SET_NAME, name);
#elif defined(__APPLE__)
  ::pthread_setname_np(name);
#endif
                                                   
}

                                                       
#if defined(__APPLE__) && defined(__MACH__)

std::chrono::microseconds thread_cpu_time() {
  using namespace std::chrono;

  struct thread_basic_info tbi;
  mach_port_t self = pthread_mach_thread_np(pthread_self());
  mach_msg_type_number_t fields = THREAD_BASIC_INFO_COUNT;

  if (thread_info(self, THREAD_BASIC_INFO, (thread_info_t)&tbi, &fields) !=
      KERN_SUCCESS) {
    return microseconds::max();
  }

  microseconds::rep total = 0;
  total += tbi.user_time.microseconds;
  total += tbi.user_time.seconds * 1000000;

  total += tbi.system_time.microseconds;
  total += tbi.system_time.seconds * 1000000;

  return microseconds(total);
}

#elif defined(__linux__)                            

std::chrono::microseconds thread_cpu_time() {
  using namespace std::chrono;

  struct timespec ts;

  if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) != 0) {
    return microseconds::max();
  }

  microseconds::rep total = 0;
  total += ts.tv_nsec / 1000;
  total += ts.tv_sec * 1000000;
  return microseconds(total);
}

#else                                        
#error "Thread CPU Time not supported on this platform"
#endif                                                       

                                                               

#if defined(__APPLE__) && defined(__MACH__)

bool thread_page_fault_count(int64_t *outMinorFaults, int64_t *outMajorFaults) {
  task_events_info eventsInfo;
  mach_msg_type_number_t count = TASK_EVENTS_INFO_COUNT;
  kern_return_t kr = task_info(
      mach_task_self(), TASK_EVENTS_INFO, (task_info_t)&eventsInfo, &count);
  if (kr == KERN_SUCCESS) {
    *outMinorFaults = eventsInfo.faults;
    *outMajorFaults = eventsInfo.pageins;
  }
  return kr == KERN_SUCCESS;
}

#elif defined(__linux__)                            

bool thread_page_fault_count(int64_t *outMinorFaults, int64_t *outMajorFaults) {
  struct rusage stats = {};
  int ret = getrusage(RUSAGE_THREAD, &stats);
  if (ret == 0) {
    *outMinorFaults = stats.ru_minflt;
    *outMajorFaults = stats.ru_majflt;
  }
  return ret == 0;
}

#else                                        
#error "Thread page fault count not supported on this platform"
#endif                                                               

std::string thread_name() {
  constexpr int kMaxThreadNameSize = 100;
  int ret = 0;
  char threadName[kMaxThreadNameSize];
#ifdef __ANDROID__
  ret = prctl(PR_GET_NAME, threadName);
#else
  ret = pthread_getname_np(pthread_self(), threadName, sizeof(threadName));
#endif
  if (ret != 0) {
                                                                              
    perror("thread_name failed");
    return "";
  }
  return threadName;
}

#ifdef __linux__
std::vector<bool> sched_getaffinity() {
  std::vector<bool> v;
  cpu_set_t mask;
  CPU_ZERO(&mask);
  int status = ::sched_getaffinity(0, sizeof(mask), &mask);
  if (status != 0) {
    return v;
  }
  int lastSet = -1;
  for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
    v.push_back(CPU_ISSET(cpu, &mask));
    if (v.back())
      lastSet = cpu;
  }
                          
  v.resize(lastSet + 1);
  return v;
}

int sched_getcpu() {
  return ::sched_getcpu();
}
#else
std::vector<bool> sched_getaffinity() {
                       
  return std::vector<bool>();
}

int sched_getcpu() {
                       
  return -1;
}
#endif

uint64_t cpu_cycle_counter() {
#if defined(__aarch64__)
                                                                   
  uint64_t cnt;
  __asm __volatile("mrs %0, cntvct_el0" : "=&r"(cnt));
  return cnt;
#elif __has_builtin(__builtin_readcyclecounter)
  return __builtin_readcyclecounter();
#else
  timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec * 1000LL * 1000LL * 1000LL + t.tv_nsec;
#endif
}

bool set_env(const char *name, const char *value) {
                                                                       
  assert(*value != '\0' && "value cannot be empty string");
  return setenv(name, value, 1) == 0;
}

bool unset_env(const char *name) {
  return unsetenv(name) == 0;
}

          
void *SigAltStackLeakSuppressor::stackRoot_{nullptr};

SigAltStackLeakSuppressor::~SigAltStackLeakSuppressor() {
#ifdef HAVE_SIGALTSTACK
  stack_t oldAltStack;
  if (sigaltstack(nullptr, &oldAltStack) == 0) {
    stackRoot_ = oldAltStack.ss_sp;
  }
#endif
}

}                      
}                    

#endif                

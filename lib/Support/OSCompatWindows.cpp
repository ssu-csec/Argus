/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifdef _WINDOWS

#include "hermes/Support/Compiler.h"
#include "hermes/Support/ErrorHandling.h"
#include "hermes/Support/OSCompat.h"

#include <cassert>

                                                                           
                                                                     
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX                                
#endif
#include <windows.h>

#include <intrin.h>
#include <io.h>
#include <psapi.h>

#include "llvh/ADT/Twine.h"
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
  SYSTEM_INFO system_info;
  GetSystemInfo(&system_info);
  return system_info.dwPageSize;
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

static char *alignAlloc(void *p, size_t alignment) {
  return reinterpret_cast<char *>(
      llvh::alignTo(reinterpret_cast<uintptr_t>(p), alignment));
}

static llvh::ErrorOr<void *>
vm_allocate_impl(void *addr, size_t sz, DWORD flags) {
  void *result = VirtualAlloc(addr, sz, flags, PAGE_READWRITE);
  if (result == nullptr) {
                                                                        
                                                                              
                 
    return std::error_code(GetLastError(), std::system_category());
  }
  return result;
}

static std::error_code vm_free_impl(void *p, size_t sz) {
  BOOL ret = VirtualFree(p, 0, MEM_RELEASE);

  return ret ? std::error_code{}
             : std::error_code(GetLastError(), std::system_category());
}

                                        
static llvh::ErrorOr<void *> vm_allocate_aligned_impl(
    size_t sz,
    size_t alignment,
    bool commit,
    void *           ) {
                                                       
                                                                    
                                                                        
                                                                  
  constexpr int aligned_allocation_attempts = 3;

#ifndef NDEBUG
  assert(sz > 0 && sz % page_size() == 0);
  assert(alignment > 0 && alignment % page_size() == 0);
  if (LLVM_UNLIKELY(sz > totalVMAllocLimit)) {
    return make_error_code(OOMError::TestVMLimitReached);
  } else if (LLVM_UNLIKELY(totalVMAllocLimit != unsetVMAllocLimit)) {
    totalVMAllocLimit -= sz;
  }
#endif           

  DWORD commitFlag = commit ? MEM_COMMIT : 0;

                                                             
                                                 
                                                                
                                                       
  llvh::ErrorOr<void *> result =
      vm_allocate_impl(nullptr, sz, MEM_RESERVE | commitFlag);
  if (!result) {
                                                                     
    return result;
  }
  void *addr = *result;
  if (LLVM_LIKELY(addr == alignAlloc(addr, alignment))) {
    return addr;
  }
                                      
  if (std::error_code err = vm_free_impl(addr, sz)) {
    hermes_fatal(
        "Failed to free memory region in vm_allocate_aligned_impl", err);
  }

  for (int attempts = 0; attempts < aligned_allocation_attempts; attempts++) {
                                                           
                                               
    result = vm_allocate_impl(
        nullptr, sz + alignment - page_size_real(), MEM_RESERVE);
    if (!result) {
      return result;
    }
    addr = *result;
                                  
    char *aligned = alignAlloc(addr, alignment);

                                                                    
    if (std::error_code err = vm_free_impl(addr, sz)) {
      hermes_fatal(
          "Failed to free memory region in vm_allocate_aligned_impl", err);
    }

                                                   
    result = vm_allocate_impl(aligned, sz, MEM_RESERVE | commitFlag);
    if (result) {
      assert(result.get() == aligned);
      return result.get();
    }
  }

                                                                    
                                                                          
                                     
                                                                       
                           
  result =
      vm_allocate_impl(nullptr, sz + alignment - page_size_real(), MEM_RESERVE);
  if (!result) {
    return result;
  }
  addr = *result;
  addr = alignAlloc(addr, alignment);
  if (commit) {
    result = vm_allocate_impl(addr, alignment, MEM_COMMIT);
    if (!result) {
      hermes_fatal(
          "Failed to commit subsection of reserved memory in vm_allocate_aligned_impl",
          result.getError());
    }
    return result;
  } else {
    return addr;
  }
}

llvh::ErrorOr<void *> vm_allocate(size_t sz, void *           ) {
#ifndef NDEBUG
  assert(sz % page_size() == 0);
  if (testPgSz != 0 && testPgSz > static_cast<size_t>(page_size_real())) {
    return vm_allocate_aligned(sz, testPgSz);
  }
  if (LLVM_UNLIKELY(sz > totalVMAllocLimit)) {
    return make_error_code(OOMError::TestVMLimitReached);
  } else if (LLVM_UNLIKELY(totalVMAllocLimit != unsetVMAllocLimit)) {
    totalVMAllocLimit -= sz;
  }
#endif           
  return vm_allocate_impl(nullptr, sz, MEM_RESERVE | MEM_COMMIT);
}

llvh::ErrorOr<void *>
vm_allocate_aligned(size_t sz, size_t alignment, void *hint) {
  constexpr bool commit = true;
  return vm_allocate_aligned_impl(sz, alignment, commit, hint);
}

void vm_free(void *p, size_t sz) {
#ifndef NDEBUG
  if (testPgSz != 0 && testPgSz > static_cast<size_t>(page_size_real())) {
    vm_free_aligned(p, sz);
    return;
  }
#endif           

  if (std::error_code err = vm_free_impl(p, sz)) {
    hermes_fatal("Failed to free virtual memory region", err);
  }

#ifndef NDEBUG
  if (LLVM_UNLIKELY(totalVMAllocLimit != unsetVMAllocLimit) && p) {
    totalVMAllocLimit += sz;
  }
#endif
}

void vm_free_aligned(void *p, size_t sz) {
                                                                     
                                                                              
  MEMORY_BASIC_INFORMATION mbi;
  SIZE_T query_ret = VirtualQuery(p, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
  assert(query_ret != 0 && "Failed to invoke VirtualQuery in vm_free_aligned");

  BOOL ret = VirtualFree(mbi.AllocationBase, 0, MEM_RELEASE);
  assert(ret && "Failed to invoke VirtualFree in vm_free_aligned.");
  (void)ret;

#ifndef NDEBUG
  if (LLVM_UNLIKELY(totalVMAllocLimit != unsetVMAllocLimit) && p) {
    totalVMAllocLimit += sz;
  }
#endif
}

                                                          
llvh::ErrorOr<void *>
vm_reserve_aligned(size_t sz, size_t alignment, void *hint) {
  constexpr bool commit = false;
  return vm_allocate_aligned_impl(sz, alignment, commit, hint);
}

void vm_release_aligned(void *p, size_t sz) {
  vm_free_aligned(p, sz);
}

llvh::ErrorOr<void *> vm_commit(void *p, size_t sz) {
                                                                              
                                                                      
                                                                          
                                                                     
                                                                    
  if (p == nullptr) {
                                                                       
                                                         
    return std::error_code(ERROR_INVALID_OPERATION, std::system_category());
  }
  void *result = VirtualAlloc(p, sz, MEM_COMMIT, PAGE_READWRITE);
  if (result == nullptr) {
                                                                        
                                                                              
                 
    return std::error_code(GetLastError(), std::system_category());
  }
  return result;
}

void vm_uncommit(void *p, size_t sz) {
  VirtualFree(p, sz, MEM_DECOMMIT);
}

void vm_hugepage(void *p, size_t sz) {
  assert(
      reinterpret_cast<uintptr_t>(p) % page_size() == 0 &&
      "Precondition: pointer is page-aligned.");
}

void vm_unused(void *p, size_t sz) {
#ifndef NDEBUG
  const size_t PS = page_size();
  assert(
      reinterpret_cast<intptr_t>(p) % PS == 0 &&
      "Precondition: pointer is page-aligned.");
  assert(sz % PS == 0 && "Precondition: size is page-aligned.");
#endif

                                                                           
                   

                

                                                                         
                                                                
                                                                        
                                                                 
                                           
                                                                          
                                                                           
}

void vm_prefetch(void *p, size_t sz) {
  assert(
      reinterpret_cast<intptr_t>(p) % page_size() == 0 &&
      "Precondition: pointer is page-aligned.");

                                                             

               
}

void vm_name(void *p, size_t sz, const char *name) {
  (void)p;
  (void)sz;
  (void)name;
}

bool vm_protect(void *p, size_t sz, ProtectMode mode) {
  DWORD oldProtect;
  DWORD newProtect = PAGE_NOACCESS;
  if (mode == ProtectMode::ReadWrite) {
    newProtect = PAGE_READWRITE;
  }
  BOOL err = VirtualProtect(p, sz, newProtect, &oldProtect);
  return err != 0;
}

bool vm_madvise(void *p, size_t sz, MAdvice advice) {
                     
  return false;
}

llvh::ErrorOr<size_t> vm_footprint(char *start, char *end) {
  return std::error_code(errno, std::generic_category());
}

int pages_in_ram(const void *p, size_t sz, llvh::SmallVectorImpl<int> *runs) {
                       
  return -1;
}

uint64_t peak_rss() {
  PROCESS_MEMORY_COUNTERS pmc;
  BOOL ret = GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
  if (!ret) {
             
    return 0;
  }
  return pmc.PeakWorkingSetSize;
}

uint64_t current_rss() {
  PROCESS_MEMORY_COUNTERS pmc;
  BOOL ret = GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
  if (!ret) {
             
    return 0;
  }
  return pmc.WorkingSetSize;
}

uint64_t current_private_dirty() {
                       
  return 0;
}

std::vector<std::string> get_vm_protect_modes(const void *p, size_t sz) {
                       
  return std::vector<std::string>{};
}

bool num_context_switches(long &voluntary, long &involuntary) {
                       
  voluntary = involuntary = -1;
  return false;
}

uint64_t process_id() {
  return GetCurrentProcessId();
}

uint64_t global_thread_id() {
  return GetCurrentThreadId();
}

namespace detail {

std::pair<const void *, size_t> thread_stack_bounds_impl() {
                                                  
  return {nullptr, 0};
}

}                    

void set_thread_name(const char *name) {
                                                                                
                                                             
  TsanThreadName(name);
                                                                     
                                                                
                                          
}

static std::chrono::microseconds::rep fromFileTimeToMicros(
    const FILETIME &fileTime) {
  ULARGE_INTEGER uli;
  uli.LowPart = fileTime.dwLowDateTime;
  uli.HighPart = fileTime.dwHighDateTime;
                                               
  return uli.QuadPart / 10;
}

std::chrono::microseconds thread_cpu_time() {
  FILETIME creationTime;
  FILETIME exitTime;
  FILETIME kernelTime;
  FILETIME userTime;
  GetThreadTimes(
      GetCurrentThread(), &creationTime, &exitTime, &kernelTime, &userTime);
  return std::chrono::microseconds(
      fromFileTimeToMicros(kernelTime) + fromFileTimeToMicros(userTime));
}

bool thread_page_fault_count(int64_t *outMinorFaults, int64_t *outMajorFaults) {
                                                                           
                                                                     
                                                                         
                                                                            

                             
  return false;
}

std::string thread_name() {
                                                                
                              
                                                                
                                          
  return "";
}

std::vector<bool> sched_getaffinity() {
                       
  return std::vector<bool>();
}

int sched_getcpu() {
                       
  return -1;
}

uint64_t cpu_cycle_counter() {
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
  return __rdtsc();
#elif __has_builtin(__builtin_readcyclecounter)
  return __builtin_readcyclecounter();
#else
  LARGE_INTEGER cnt;
  QueryPerformanceCounter(&cnt);
  return static_cast<uint64_t>(cnt.QuadPart);
#endif
}

bool set_env(const char *name, const char *value) {
                                                                   
  assert(*value != '\0' && "value cannot be empty string");
  return _putenv_s(name, value) == 0;
}

bool unset_env(const char *name) {
  return _putenv_s(name, "") == 0;
}

                                                                               
       
          
void *SigAltStackLeakSuppressor::stackRoot_{nullptr};

SigAltStackLeakSuppressor::~SigAltStackLeakSuppressor() {}

}                      
}                    

#endif            

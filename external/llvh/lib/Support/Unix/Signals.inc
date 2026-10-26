//===- Signals.cpp - Generic Unix Signals Implementation -----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines some helpful functions for dealing with the possibility of
// Unix signals occurring while your program is running.
//
//===----------------------------------------------------------------------===//
//
// This file is extremely careful to only do signal-safe things while in a
// signal handler. In particular, memory allocation and acquiring a mutex
// while in a signal handler should never occur. ManagedStatic isn't usable from
// a signal handler for 2 reasons:
//
//  1. Creating a new one allocates.
//  2. The signal handler could fire while llvm_shutdown is being processed, in
//     which case the ManagedStatic is in an unknown state because it could
//     already have been destroyed, or be in the process of being destroyed.
//
// Modifying the behavior of the signal handlers (such as registering new ones)
// can acquire a mutex, but all this guarantees is that the signal handler
// behavior is only modified by one thread at a time. A signal handler can still
// fire while this occurs!
//
// Adding work to a signal handler requires lock-freedom (and assume atomics are
// always lock-free) because the signal handler could fire while new work is
// being added.
//
//===----------------------------------------------------------------------===//

#include "Unix.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/Config/config.h"
#include "llvh/Demangle/Demangle.h"
#include "llvh/Support/FileSystem.h"
#include "llvh/Support/FileUtilities.h"
#include "llvh/Support/Format.h"
#include "llvh/Support/MemoryBuffer.h"
#include "llvh/Support/Mutex.h"
#include "llvh/Support/Program.h"
#include "llvh/Support/UniqueLock.h"
#include "llvh/Support/raw_ostream.h"
#include <algorithm>
#include <string>
#if defined(HAVE_BACKTRACE) && ENABLE_BACKTRACES
# include BACKTRACE_HEADER                            
#endif
#if HAVE_SIGNAL_H
#include <signal.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_DLFCN_H
#include <dlfcn.h>
#endif
#if HAVE_MACH_MACH_H
#include <mach/mach.h>
#endif
#if HAVE_LINK_H
#include <link.h>
#endif
#ifdef HAVE__UNWIND_BACKTRACE
                                                                        
                                                                       
                                                                          
                 
#ifdef __GLIBC__
#include <unwind.h>
#else
#undef HAVE__UNWIND_BACKTRACE
#endif
#endif

using namespace llvh;

static RETSIGTYPE SignalHandler(int Sig);                   

                                              
using InterruptFunctionType = void (*)();
static std::atomic<InterruptFunctionType> InterruptFunction =
    ATOMIC_VAR_INIT(nullptr);

namespace {
                                 
                                                                               
                                                                               
                                        
class FileToRemoveList {
  std::atomic<char *> Filename = ATOMIC_VAR_INIT(nullptr);
  std::atomic<FileToRemoveList *> Next = ATOMIC_VAR_INIT(nullptr);

  FileToRemoveList() = default;
                     
  FileToRemoveList(const std::string &str) : Filename(strdup(str.c_str())) {}

public:
                     
  ~FileToRemoveList() {
    if (FileToRemoveList *N = Next.exchange(nullptr))
      delete N;
    if (char *F = Filename.exchange(nullptr))
      free(F);
  }

                     
  static void insert(std::atomic<FileToRemoveList *> &Head,
                     const std::string &Filename) {
                                                  
    FileToRemoveList *NewHead = new FileToRemoveList(Filename);
    std::atomic<FileToRemoveList *> *InsertionPoint = &Head;
    FileToRemoveList *OldHead = nullptr;
    while (!InsertionPoint->compare_exchange_strong(OldHead, NewHead)) {
      InsertionPoint = &OldHead->Next;
      OldHead = nullptr;
    }
  }

                     
  static void erase(std::atomic<FileToRemoveList *> &Head,
                    const std::string &Filename) {
                                                                        
                     
    static ManagedStatic<sys::SmartMutex<true>> Lock;
    sys::SmartScopedLock<true> Writer(*Lock);

    for (FileToRemoveList *Current = Head.load(); Current;
         Current = Current->Next.load()) {
      if (char *OldFilename = Current->Filename.load()) {
        if (OldFilename != Filename)
          continue;
                                   
        OldFilename = Current->Filename.exchange(nullptr);
                                                                  
                                           
        if (OldFilename)
          free(OldFilename);
      }
    }
  }

                 
  static void removeAllFiles(std::atomic<FileToRemoveList *> &Head) {
                                                                                
                                                                               
                                                                             
                          
    FileToRemoveList *OldHead = Head.exchange(nullptr);

    for (FileToRemoveList *currentFile = OldHead; currentFile;
         currentFile = currentFile->Next.load()) {
                                                                             
                                                                      
      if (char *path = currentFile->Filename.exchange(nullptr)) {
                                                                                
                                          
        struct stat buf;
        if (stat(path, &buf) != 0)
          continue;

                                                                               
                                                                             
                                           
        if (!S_ISREG(buf.st_mode))
          continue;

                                                                            
                                  
        unlink(path);

                                                                    
        currentFile->Filename.exchange(path);
      }
    }

                                                             
    Head.exchange(OldHead);
  }
};
static std::atomic<FileToRemoveList *> FilesToRemove = ATOMIC_VAR_INIT(nullptr);

                                                                                
                                                                             
                                                                      
static std::atomic<InterruptFunctionType> FilesToRemoveInterruptFunc = ATOMIC_VAR_INIT(nullptr);

                                                  
                                                                               
                                                                        
struct FilesToRemoveCleanup {
                     
  ~FilesToRemoveCleanup() {
    FileToRemoveList *Head = FilesToRemove.exchange(nullptr);
    if (Head)
      delete Head;
  }
};
}             

static StringRef Argv0;

                                                                              
                                                                            
                                              
static const int IntSigs[] = {
  SIGHUP, SIGINT, SIGPIPE, SIGTERM, SIGUSR1, SIGUSR2
};

                                                                            
                
static const int KillSigs[] = {
  SIGILL, SIGTRAP, SIGABRT, SIGFPE, SIGBUS, SIGSEGV, SIGQUIT
#ifdef SIGSYS
  , SIGSYS
#endif
#ifdef SIGXCPU
  , SIGXCPU
#endif
#ifdef SIGXFSZ
  , SIGXFSZ
#endif
#ifdef SIGEMT
  , SIGEMT
#endif
};

static std::atomic<unsigned> NumRegisteredSignals = ATOMIC_VAR_INIT(0);
static struct {
  struct sigaction SA;
  int SigNo;
} RegisteredSignalInfo[array_lengthof(IntSigs) + array_lengthof(KillSigs)];

#if defined(HAVE_SIGALTSTACK)
                                                                         
                                                                         
                                                                         
                                                    
static stack_t OldAltStack;
LLVM_ATTRIBUTE_USED static void* NewAltStackPointer;

static void CreateSigAltStack() {
  const size_t AltStackSize = MINSIGSTKSZ + 64 * 1024;

                                                                               
                                                                            
                                                                              
                
  if (sigaltstack(nullptr, &OldAltStack) != 0 ||
      OldAltStack.ss_flags & SS_ONSTACK ||
      (OldAltStack.ss_sp && OldAltStack.ss_size >= AltStackSize))
    return;

  stack_t AltStack = {};
  AltStack.ss_sp = static_cast<char *>(safe_malloc(AltStackSize));
  NewAltStackPointer = AltStack.ss_sp;                                   
  AltStack.ss_size = AltStackSize;
  if (sigaltstack(&AltStack, &OldAltStack) != 0)
    free(AltStack.ss_sp);
}
#else
static void CreateSigAltStack() {}
#endif

static void RegisterHandlers() {                    
                                                                           
                                                                           
                                                                  
  static ManagedStatic<sys::SmartMutex<true>> SignalHandlerRegistrationMutex;
  sys::SmartScopedLock<true> Guard(*SignalHandlerRegistrationMutex);

                                                        
  if (NumRegisteredSignals.load() != 0)
    return;

                                                                               
                                                              
  CreateSigAltStack();

  auto registerHandler = [&](int Signal) {
    unsigned Index = NumRegisteredSignals.load();
    assert(Index < array_lengthof(RegisteredSignalInfo) &&
           "Out of space for signal handlers!");

    struct sigaction NewHandler;

    NewHandler.sa_handler = SignalHandler;
    NewHandler.sa_flags = SA_NODEFER | SA_RESETHAND | SA_ONSTACK;
    sigemptyset(&NewHandler.sa_mask);

                                                                         
    sigaction(Signal, &NewHandler, &RegisteredSignalInfo[Index].SA);
    RegisteredSignalInfo[Index].SigNo = Signal;
    ++NumRegisteredSignals;
  };

  for (auto S : IntSigs)
    registerHandler(S);
  for (auto S : KillSigs)
    registerHandler(S);
}

static void UnregisterHandlers() {
                                                                             
  for (unsigned i = 0, e = NumRegisteredSignals.load(); i != e; ++i) {
    sigaction(RegisteredSignalInfo[i].SigNo,
              &RegisteredSignalInfo[i].SA, nullptr);
    --NumRegisteredSignals;
  }
}

                                   
static void RemoveFilesToRemove() {
  FileToRemoveList::removeAllFiles(FilesToRemove);
}

                                
static RETSIGTYPE SignalHandler(int Sig) {
                                                                         
                                                                               
                                                                               
                                                
  UnregisterHandlers();

                                                 
  sigset_t SigMask;
  sigfillset(&SigMask);
  sigprocmask(SIG_UNBLOCK, &SigMask, nullptr);

  {
    if(auto *fn = FilesToRemoveInterruptFunc.load())
      fn();

    if (std::find(std::begin(IntSigs), std::end(IntSigs), Sig)
        != std::end(IntSigs)) {
      if (auto OldInterruptFunction = InterruptFunction.exchange(nullptr))
        return OldInterruptFunction();

      raise(Sig);                                  
      return;
   }
  }

                                                            
  llvh::sys::RunSignalHandlers();

#ifdef __s390__
                                                                         
                                                                        
                                                                  
                                                                      
  if (Sig == SIGILL || Sig == SIGFPE || Sig == SIGTRAP)
    raise(Sig);
#endif
}

void llvh::sys::RunInterruptHandlers() {
  if(auto *fn = FilesToRemoveInterruptFunc.load())
    fn();
}

void llvh::sys::SetInterruptFunction(void (*IF)()) {
  InterruptFunction.exchange(IF);
  RegisterHandlers();
}

                 
bool llvh::sys::RemoveFileOnSignal(StringRef Filename,
                                   std::string* ErrMsg) {
                                                                 
  static ManagedStatic<FilesToRemoveCleanup> FilesToRemoveCleanup;
  *FilesToRemoveCleanup;
  FilesToRemoveInterruptFunc = RemoveFilesToRemove;
  FileToRemoveList::insert(FilesToRemove, Filename.str());
  RegisterHandlers();
  return false;
}

                 
void llvh::sys::DontRemoveFileOnSignal(StringRef Filename) {
  FileToRemoveList::erase(FilesToRemove, Filename.str());
}

                                                                              
                                                                           
                  
void llvh::sys::AddSignalHandler(sys::SignalHandlerCallback FnPtr,
                                 void *Cookie) {                
  insertSignalHandler(FnPtr, Cookie);
  RegisterHandlers();
}

#if defined(HAVE_BACKTRACE) && ENABLE_BACKTRACES && HAVE_LINK_H &&    \
    (defined(__linux__) || defined(__FreeBSD__) ||                             \
     defined(__FreeBSD_kernel__) || defined(__NetBSD__))
struct DlIteratePhdrData {
  void **StackTrace;
  int depth;
  bool first;
  const char **modules;
  intptr_t *offsets;
  const char *main_exec_name;
};

static int dl_iterate_phdr_cb(dl_phdr_info *info, size_t size, void *arg) {
  DlIteratePhdrData *data = (DlIteratePhdrData*)arg;
  const char *name = data->first ? data->main_exec_name : info->dlpi_name;
  data->first = false;
  for (int i = 0; i < info->dlpi_phnum; i++) {
    const auto *phdr = &info->dlpi_phdr[i];
    if (phdr->p_type != PT_LOAD)
      continue;
    intptr_t beg = info->dlpi_addr + phdr->p_vaddr;
    intptr_t end = beg + phdr->p_memsz;
    for (int j = 0; j < data->depth; j++) {
      if (data->modules[j])
        continue;
      intptr_t addr = (intptr_t)data->StackTrace[j];
      if (beg <= addr && addr < end) {
        data->modules[j] = name;
        data->offsets[j] = addr - info->dlpi_addr;
      }
    }
  }
  return 0;
}

                                                                                
                                   
static bool findModulesAndOffsets(void **StackTrace, int Depth,
                                  const char **Modules, intptr_t *Offsets,
                                  const char *MainExecutableName,
                                  StringSaver &StrPool) {
  DlIteratePhdrData data = {StackTrace, Depth,   true,
                            Modules,    Offsets, MainExecutableName};
  dl_iterate_phdr(dl_iterate_phdr_cb, &data);
  return true;
}
#else
                                                                             
                         
static bool findModulesAndOffsets(void **StackTrace, int Depth,
                                  const char **Modules, intptr_t *Offsets,
                                  const char *MainExecutableName,
                                  StringSaver &StrPool) {
  return false;
}
#endif                                                       

#if ENABLE_BACKTRACES && defined(HAVE__UNWIND_BACKTRACE)
static int unwindBacktrace(void **StackTrace, int MaxEntries) {
  if (MaxEntries < 0)
    return 0;

                                                     
  int Entries = -1;

  auto HandleFrame = [&](_Unwind_Context *Context) -> _Unwind_Reason_Code {
                                                                            
    void *IP = (void *)_Unwind_GetIP(Context);
    if (!IP)
      return _URC_END_OF_STACK;

    assert(Entries < MaxEntries && "recursively called after END_OF_STACK?");
    if (Entries >= 0)
      StackTrace[Entries] = IP;

    if (++Entries == MaxEntries)
      return _URC_END_OF_STACK;
    return _URC_NO_REASON;
  };

  _Unwind_Backtrace(
      [](_Unwind_Context *Context, void *Handler) {
        return (*static_cast<decltype(HandleFrame) *>(Handler))(Context);
      },
      static_cast<void *>(&HandleFrame));
  return std::max(Entries, 0);
}
#endif

                                                                               
                                                   
  
                                                                             
                            
void llvh::sys::PrintStackTrace(raw_ostream &OS) {
#if ENABLE_BACKTRACES
  static void *StackTrace[256];
  int depth = 0;
#if defined(HAVE_BACKTRACE)
                                                                       
  if (!depth)
    depth = backtrace(StackTrace, static_cast<int>(array_lengthof(StackTrace)));
#endif
#if defined(HAVE__UNWIND_BACKTRACE)
                                                   
  if (!depth)
    depth = unwindBacktrace(StackTrace,
                        static_cast<int>(array_lengthof(StackTrace)));
#endif
  if (!depth)
    return;

  if (printSymbolizedStackTrace(Argv0, StackTrace, depth, OS))
    return;
#if HAVE_DLFCN_H && HAVE_DLADDR
  int width = 0;
  for (int i = 0; i < depth; ++i) {
    Dl_info dlinfo;
    dladdr(StackTrace[i], &dlinfo);
    const char* name = strrchr(dlinfo.dli_fname, '/');

    int nwidth;
    if (!name) nwidth = strlen(dlinfo.dli_fname);
    else       nwidth = strlen(name) - 1;

    if (nwidth > width) width = nwidth;
  }

  for (int i = 0; i < depth; ++i) {
    Dl_info dlinfo;
    dladdr(StackTrace[i], &dlinfo);

    OS << format("%-2d", i);

    const char* name = strrchr(dlinfo.dli_fname, '/');
    if (!name) OS << format(" %-*s", width, dlinfo.dli_fname);
    else       OS << format(" %-*s", width, name+1);

    OS << format(" %#0*lx", (int)(sizeof(void*) * 2) + 2,
                 (unsigned long)StackTrace[i]);

    if (dlinfo.dli_sname != nullptr) {
      OS << ' ';
      int res;
      char* d = itaniumDemangle(dlinfo.dli_sname, nullptr, nullptr, &res);
      if (!d) OS << dlinfo.dli_sname;
      else    OS << d;
      free(d);

                                                                          
                                                                            
                                                                              
      OS << format(" + %u",(unsigned)((char*)StackTrace[i]-
                                      (char*)dlinfo.dli_saddr));
    }
    OS << '\n';
  }
#elif defined(HAVE_BACKTRACE)
  backtrace_symbols_fd(StackTrace, depth, STDERR_FILENO);
#endif
#endif
}

static void PrintStackTraceSignalHandler(void *) {
  sys::PrintStackTrace(llvh::errs());
}

void llvh::sys::DisableSystemDialogsOnCrash() {}

                                                                         
                                               
void llvh::sys::PrintStackTraceOnErrorSignal(StringRef Argv0,
                                             bool DisableCrashReporting) {
  ::Argv0 = Argv0;

  AddSignalHandler(PrintStackTraceSignalHandler, nullptr);

#if defined(__APPLE__) && ENABLE_CRASH_OVERRIDES
                                                              
  if (DisableCrashReporting || getenv("LLVM_DISABLE_CRASH_REPORT")) {
    mach_port_t self = mach_task_self();

    exception_mask_t mask = EXC_MASK_CRASH;

    kern_return_t ret = task_set_exception_ports(self,
                             mask,
                             MACH_PORT_NULL,
                             EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
                             THREAD_STATE_NONE);
    (void)ret;
  }
#endif
}

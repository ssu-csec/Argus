//= llvm/Support/Win32/Mutex.inc - Win32 Reader/Writer Mutual Exclusion Lock  =//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the Win32 specific (non-pthread) RWMutex class.
//
//===----------------------------------------------------------------------===//

                                                                                
                                                                            
                                                             
                                                                                

#include "WindowsSupport.h"

namespace llvh {

                                                                       
                                                                       
                                                                        
                                                                          
#if defined(__MINGW32__)
                       
  typedef struct _RTL_SRWLOCK {
    PVOID Ptr;
  } RTL_SRWLOCK, *PRTL_SRWLOCK;

                         
  typedef RTL_SRWLOCK SRWLOCK, *PSRWLOCK;
#endif

static VOID (WINAPI *fpInitializeSRWLock)(PSRWLOCK lock) = NULL;
static VOID (WINAPI *fpAcquireSRWLockExclusive)(PSRWLOCK lock) = NULL;
static VOID (WINAPI *fpAcquireSRWLockShared)(PSRWLOCK lock) = NULL;
static VOID (WINAPI *fpReleaseSRWLockExclusive)(PSRWLOCK lock) = NULL;
static VOID (WINAPI *fpReleaseSRWLockShared)(PSRWLOCK lock) = NULL;

static bool sHasSRW = false;

static bool loadSRW() {
  static bool sChecked = false;
  if (!sChecked) {
    sChecked = true;

    if (HMODULE hLib = ::GetModuleHandleW(L"Kernel32.dll")) {
      fpInitializeSRWLock =
        (VOID (WINAPI *)(PSRWLOCK))::GetProcAddress(hLib,
                                               "InitializeSRWLock");
      fpAcquireSRWLockExclusive =
        (VOID (WINAPI *)(PSRWLOCK))::GetProcAddress(hLib,
                                               "AcquireSRWLockExclusive");
      fpAcquireSRWLockShared =
        (VOID (WINAPI *)(PSRWLOCK))::GetProcAddress(hLib,
                                               "AcquireSRWLockShared");
      fpReleaseSRWLockExclusive =
        (VOID (WINAPI *)(PSRWLOCK))::GetProcAddress(hLib,
                                               "ReleaseSRWLockExclusive");
      fpReleaseSRWLockShared =
        (VOID (WINAPI *)(PSRWLOCK))::GetProcAddress(hLib,
                                               "ReleaseSRWLockShared");

      if (fpInitializeSRWLock != NULL) {
        sHasSRW = true;
      }
    }
  }
  return sHasSRW;
}

sys::RWMutexImpl::RWMutexImpl() {
  if (loadSRW()) {
    data_ = safe_calloc(1, sizeof(SRWLOCK));
    fpInitializeSRWLock(static_cast<PSRWLOCK>(data_));
  } else {
    data_ = safe_calloc(1, sizeof(CRITICAL_SECTION));
    InitializeCriticalSection(static_cast<LPCRITICAL_SECTION>(data_));
  }
}

sys::RWMutexImpl::~RWMutexImpl() {
  if (!sHasSRW)
    DeleteCriticalSection(static_cast<LPCRITICAL_SECTION>(data_));
                                                                             
  free(data_);
}

bool sys::RWMutexImpl::reader_acquire() {
  if (sHasSRW) {
    fpAcquireSRWLockShared(static_cast<PSRWLOCK>(data_));
  } else {
    EnterCriticalSection(static_cast<LPCRITICAL_SECTION>(data_));
  }
  return true;
}

bool sys::RWMutexImpl::reader_release() {
  if (sHasSRW) {
    fpReleaseSRWLockShared(static_cast<PSRWLOCK>(data_));
  } else {
    LeaveCriticalSection(static_cast<LPCRITICAL_SECTION>(data_));
  }
  return true;
}

bool sys::RWMutexImpl::writer_acquire() {
  if (sHasSRW) {
    fpAcquireSRWLockExclusive(static_cast<PSRWLOCK>(data_));
  } else {
    EnterCriticalSection(static_cast<LPCRITICAL_SECTION>(data_));
  }
  return true;
}

bool sys::RWMutexImpl::writer_release() {
  if (sHasSRW) {
    fpReleaseSRWLockExclusive(static_cast<PSRWLOCK>(data_));
  } else {
    LeaveCriticalSection(static_cast<LPCRITICAL_SECTION>(data_));
  }
  return true;
}


}

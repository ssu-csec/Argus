//===- Windows/Threading.inc - Win32 Threading Implementation - -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides the Win32 specific implementation of Threading functions.
//
//===----------------------------------------------------------------------===//

#include "llvh/ADT/SmallString.h"
#include "llvh/ADT/Twine.h"

#include "Windows/WindowsSupport.h"
#include <process.h>

                                            
#ifdef MemoryFence
#undef MemoryFence
#endif

namespace {
  struct ThreadInfo {
    void(*func)(void*);
    void *param;
  };
}

static unsigned __stdcall ThreadCallback(void *param) {
  struct ThreadInfo *info = reinterpret_cast<struct ThreadInfo *>(param);
  info->func(info->param);

  return 0;
}

void llvh::llvm_execute_on_thread(void(*Fn)(void*), void *UserData,
  unsigned RequestedStackSize) {
  struct ThreadInfo param = { Fn, UserData };

  HANDLE hThread = (HANDLE)::_beginthreadex(NULL,
    RequestedStackSize, ThreadCallback,
    &param, 0, NULL);

  if (hThread) {
                                                                    
                                                                        
                                                                        
                                                                          
                        
    (void)::WaitForSingleObject(hThread, INFINITE);
    ::CloseHandle(hThread);
  }
}

uint64_t llvh::get_threadid() {
  return uint64_t(::GetCurrentThreadId());
}

uint32_t llvh::get_max_thread_name_length() { return 0; }

#if defined(_MSC_VER)
static void SetThreadName(DWORD Id, LPCSTR Name) {
  constexpr DWORD MS_VC_EXCEPTION = 0x406D1388;

#pragma pack(push, 8)
  struct THREADNAME_INFO {
    DWORD dwType;                       
    LPCSTR szName;                             
    DWORD dwThreadId;                                    
    DWORD dwFlags;                             
  };
#pragma pack(pop)

  THREADNAME_INFO info;
  info.dwType = 0x1000;
  info.szName = Name;
  info.dwThreadId = Id;
  info.dwFlags = 0;

  __try {
    ::RaiseException(MS_VC_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR),
      (ULONG_PTR *)&info);
  }
  __except (EXCEPTION_EXECUTE_HANDLER) {
  }
}
#endif

void llvh::set_thread_name(const Twine &Name) {
#if defined(_MSC_VER)
                                            
  SmallString<64> Storage;
  StringRef NameStr = Name.toNullTerminatedStringRef(Storage);
  SetThreadName(::GetCurrentThreadId(), NameStr.data());
#endif
}

void llvh::get_thread_name(SmallVectorImpl<char> &Name) {
                                                                              
                                                                             
                                                                           
                                                                 
                                                                            
           
  Name.clear();
}

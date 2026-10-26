//===-- llvm/Support/Threading.h - Control multithreading mode --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares helper functions for running LLVM in a multi-threaded
// environment.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_THREADING_H
#define LLVM_SUPPORT_THREADING_H

#include "llvh/ADT/SmallVector.h"
#include "llvh/Config/llvm-config.h"                    
#include "llvh/Support/Compiler.h"
#include <ciso646>                                                
#include <functional>

#if defined(_MSC_VER)
                                                                             
                                        
#define LLVM_THREADING_USE_STD_CALL_ONCE 1
#elif defined(LLVM_ON_UNIX) &&                                                 \
    (defined(_LIBCPP_VERSION) ||                                               \
     !(defined(__NetBSD__) || defined(__OpenBSD__) || defined(__ppc__)))
                                                                  
                                                                       
                       
#define LLVM_THREADING_USE_STD_CALL_ONCE 1
#else
#define LLVM_THREADING_USE_STD_CALL_ONCE 0
#endif

#if LLVM_THREADING_USE_STD_CALL_ONCE
#include <mutex>
#else
#include "llvh/Support/Atomic.h"
#endif

namespace llvh {
class Twine;

                                                                          
                    
bool llvm_is_multithreaded();

                                                                      
                                                                    
               
   
                                                                            
                                                                              
                                         
   
                                            
                                                                   
                                                                            
                     
void llvm_execute_on_thread(void (*UserFn)(void *), void *UserData,
                            unsigned RequestedStackSize = 0);

#if LLVM_THREADING_USE_STD_CALL_ONCE

  typedef std::once_flag once_flag;

#else

  enum InitStatus { Uninitialized = 0, Wait = 1, Done = 2 };

                                   
     
                                                                            
                                                                              
                                                        
  struct once_flag {
    volatile sys::cas_flag status = Uninitialized;
  };

#endif

                                                         
     
                    
           
                         
           
                              
                             
              
     
                                                                     
                                     
  template <typename Function, typename... Args>
  void call_once(once_flag &flag, Function &&F, Args &&... ArgList) {
#if LLVM_THREADING_USE_STD_CALL_ONCE
    std::call_once(flag, std::forward<Function>(F),
                   std::forward<Args>(ArgList)...);
#else
                                                                             
               
    sys::cas_flag old_val = sys::CompareAndSwap(&flag.status, Wait, Uninitialized);
    if (old_val == Uninitialized) {
      std::forward<Function>(F)(std::forward<Args>(ArgList)...);
      sys::MemoryFence();
      TsanIgnoreWritesBegin();
      TsanHappensBefore(&flag.status);
      flag.status = Done;
      TsanIgnoreWritesEnd();
    } else {
                                                           
      sys::cas_flag tmp = flag.status;
      sys::MemoryFence();
      while (tmp != Done) {
        tmp = flag.status;
        sys::MemoryFence();
      }
    }
    TsanHappensAfter(&flag.status);
#endif
  }

                                                                       
                                                                      
                                                            
                                     
                                                                    
  unsigned heavyweight_hardware_concurrency();

                                                                    
                                                                               
                                                                            
                                                                     
                                                                             
                    
  unsigned hardware_concurrency();

                                                                       
                                                                           
                                                                         
           
  uint64_t get_threadid();

                                                               
                                           
  uint32_t get_max_thread_name_length();

                                                                      
                                                                         
                                                                       
                                                                        
                                                                             
                             
  void set_thread_name(const Twine &Name);

                                                                   
                                                                            
                                                                             
                                                                               
                                                                            
                                                    
  void get_thread_name(SmallVectorImpl<char> &Name);
}

#endif

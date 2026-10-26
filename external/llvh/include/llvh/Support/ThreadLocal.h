//===- llvm/Support/ThreadLocal.h - Thread Local Data ------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the llvh::sys::ThreadLocal class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_THREADLOCAL_H
#define LLVM_SUPPORT_THREADLOCAL_H

#include "llvh/Support/DataTypes.h"
#include "llvh/Support/Threading.h"
#include <cassert>

namespace llvh {
  namespace sys {
                                                                             
                                          
    class ThreadLocalImpl {
      typedef uint64_t ThreadLocalDataTy;
                                              
         
                                                                            
                                                                               
      union {
        char data[sizeof(ThreadLocalDataTy)];
        ThreadLocalDataTy align_data;
      };
    public:
      ThreadLocalImpl();
      virtual ~ThreadLocalImpl();
      void setInstance(const void* d);
      void *getInstance();
      void removeInstance();
    };

                                                                               
                                                             
    template<class T>
    class ThreadLocal : public ThreadLocalImpl {
    public:
      ThreadLocal() : ThreadLocalImpl() { }

                                                                           
                                                                         
      T* get() { return static_cast<T*>(getInstance()); }

                                                                         
      void set(T* d) { setInstance(d); }

                                                                        
      void erase() { removeInstance(); }
    };
  }
}

#endif

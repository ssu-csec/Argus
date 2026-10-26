//===- llvm/Support/Mutex.h - Mutex Operating System Concept -----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the llvh::sys::Mutex class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_MUTEX_H
#define LLVM_SUPPORT_MUTEX_H

#include "llvh/Config/llvm-config.h"
#include "llvh/Support/Compiler.h"
#include "llvh/Support/Threading.h"
#include <cassert>

namespace llvh
{
  namespace sys
  {
                                      
    class MutexImpl
    {
                          
          
    public:

                                                                             
                                                                             
                                                                           
                
                              
      explicit MutexImpl(bool recursive = true);

                                       
                    
      ~MutexImpl();

          
                     
          
    public:

                                                                              
                                                                              
                                                                     
                                           
      bool acquire();

                                                                          
                                                                            
               
                                                                     
                                           
      bool release();

                                                                           
                                                                               
                                                
                                                                       
                                    
                                  
      bool tryacquire();

        
                                     
          
    private:
#if defined(LLVM_ENABLE_THREADS) && LLVM_ENABLE_THREADS != 0
      void* data_;                                         
#endif

          
                              
          
    private:
      MutexImpl(const MutexImpl &) = delete;
      void operator=(const MutexImpl &) = delete;
          
    };


                                                                        
                                                                         
                                      
    template<bool mt_only>
    class SmartMutex {
      MutexImpl impl;
      unsigned acquired;
      bool recursive;
    public:
      explicit SmartMutex(bool rec = true) :
        impl(rec), acquired(0), recursive(rec) { }

      bool lock() {
        if (!mt_only || llvm_is_multithreaded()) {
          return impl.acquire();
        } else {
                                                                   
                                                                         
                           
          assert((recursive || acquired == 0) && "Lock already acquired!!");
          ++acquired;
          return true;
        }
      }

      bool unlock() {
        if (!mt_only || llvm_is_multithreaded()) {
          return impl.release();
        } else {
                                                                   
                                                                         
                           
          assert(((recursive && acquired) || (acquired == 1)) &&
                 "Lock not acquired before release!");
          --acquired;
          return true;
        }
      }

      bool try_lock() {
        if (!mt_only || llvm_is_multithreaded())
          return impl.tryacquire();
        else return true;
      }

      private:
        SmartMutex(const SmartMutex<mt_only> & original);
        void operator=(const SmartMutex<mt_only> &);
    };

                                                  
    typedef SmartMutex<false> Mutex;

    template<bool mt_only>
    class SmartScopedLock  {
      SmartMutex<mt_only>& mtx;

    public:
      SmartScopedLock(SmartMutex<mt_only>& m) : mtx(m) {
        mtx.lock();
      }

      ~SmartScopedLock() {
        mtx.unlock();
      }
    };

    typedef SmartScopedLock<false> ScopedLock;
  }
}

#endif

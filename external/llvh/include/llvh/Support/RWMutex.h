//===- RWMutex.h - Reader/Writer Mutual Exclusion Lock ----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the llvh::sys::RWMutex class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_RWMUTEX_H
#define LLVM_SUPPORT_RWMUTEX_H

#include "llvh/Config/llvm-config.h"
#include "llvh/Support/Threading.h"
#include <cassert>

namespace llvh {
namespace sys {

                                        
    class RWMutexImpl
    {
                          
          
    public:

                                                      
                              
      explicit RWMutexImpl();

          
                              
          
      RWMutexImpl(const RWMutexImpl & original) = delete;
      RWMutexImpl &operator=(const RWMutexImpl &) = delete;
          

                                       
                    
      ~RWMutexImpl();

          
                     
          
    public:

                                                                             
                                                                              
                   
                                                                     
                                                          
      bool reader_acquire();

                                                      
                                                                     
                                                          
      bool reader_release();

                                                                             
                                                                         
                           
                                                                     
                                                          
      bool writer_acquire();

                                                      
                                                                     
                                                         
      bool writer_release();

        
                                     
          
    private:
#if defined(LLVM_ENABLE_THREADS) && LLVM_ENABLE_THREADS != 0
      void* data_ = nullptr;                                         
#endif
    };

                                                                             
                                                                         
                                      
    template<bool mt_only>
    class SmartRWMutex {
      RWMutexImpl impl;
      unsigned readers = 0;
      unsigned writers = 0;

    public:
      explicit SmartRWMutex() = default;
      SmartRWMutex(const SmartRWMutex<mt_only> & original) = delete;
      SmartRWMutex<mt_only> &operator=(const SmartRWMutex<mt_only> &) = delete;

      bool lock_shared() {
        if (!mt_only || llvm_is_multithreaded())
          return impl.reader_acquire();

                                                                               
                                                                        
        ++readers;
        return true;
      }

      bool unlock_shared() {
        if (!mt_only || llvm_is_multithreaded())
          return impl.reader_release();

                                                                               
                                                                        
        assert(readers > 0 && "Reader lock not acquired before release!");
        --readers;
        return true;
      }

      bool lock() {
        if (!mt_only || llvm_is_multithreaded())
          return impl.writer_acquire();

                                                                               
                                                                        
        assert(writers == 0 && "Writer lock already acquired!");
        ++writers;
        return true;
      }

      bool unlock() {
        if (!mt_only || llvm_is_multithreaded())
          return impl.writer_release();

                                                                               
                                                                        
        assert(writers == 1 && "Writer lock not acquired before release!");
        --writers;
        return true;
      }
    };

    typedef SmartRWMutex<false> RWMutex;

                                                        
    template<bool mt_only>
    struct SmartScopedReader {
      SmartRWMutex<mt_only>& mutex;

      explicit SmartScopedReader(SmartRWMutex<mt_only>& m) : mutex(m) {
        mutex.lock_shared();
      }

      ~SmartScopedReader() {
        mutex.unlock_shared();
      }
    };

    typedef SmartScopedReader<false> ScopedReader;

                                                        
    template<bool mt_only>
    struct SmartScopedWriter {
      SmartRWMutex<mt_only>& mutex;

      explicit SmartScopedWriter(SmartRWMutex<mt_only>& m) : mutex(m) {
        mutex.lock();
      }

      ~SmartScopedWriter() {
        mutex.unlock();
      }
    };

    typedef SmartScopedWriter<false> ScopedWriter;

}                     
}                      

#endif                          

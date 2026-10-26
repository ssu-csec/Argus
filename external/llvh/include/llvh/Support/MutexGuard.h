//===-- Support/MutexGuard.h - Acquire/Release Mutex In Scope ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines a guard for a block of code that ensures a Mutex is locked
// upon construction and released upon destruction.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_MUTEXGUARD_H
#define LLVM_SUPPORT_MUTEXGUARD_H

#include "llvh/Support/Mutex.h"

namespace llvh {
                                                                             
                                                                              
                                                                        
                                                                            
                                                                              
                                           
  class MutexGuard {
    sys::Mutex &M;
    MutexGuard(const MutexGuard &) = delete;
    void operator=(const MutexGuard &) = delete;
  public:
    MutexGuard(sys::Mutex &m) : M(m) { M.lock(); }
    ~MutexGuard() { M.unlock(); }
                                                                              
                                                                            
                
    bool holds(const sys::Mutex& lock) const { return &M == &lock; }
  };
}

#endif                             

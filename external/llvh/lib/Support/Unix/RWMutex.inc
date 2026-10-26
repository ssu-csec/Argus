//= llvm/Support/Unix/RWMutex.inc - Unix Reader/Writer Mutual Exclusion Lock  =//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the Unix specific (non-pthread) RWMutex class.
//
//===----------------------------------------------------------------------===//

                                                                                
                                                                           
                                                            
                                                                                

#include "llvh/Support/Mutex.h"

namespace llvh {

using namespace sys;

                                                                      
                                                                   
                  

RWMutexImpl::RWMutexImpl() : data_(new MutexImpl(false)) { }

RWMutexImpl::~RWMutexImpl() {
  delete static_cast<MutexImpl *>(data_);
}

bool RWMutexImpl::reader_acquire() {
  return static_cast<MutexImpl *>(data_)->acquire();
}

bool RWMutexImpl::reader_release() {
  return static_cast<MutexImpl *>(data_)->release();
}

bool RWMutexImpl::writer_acquire() {
  return static_cast<MutexImpl *>(data_)->acquire();
}

bool RWMutexImpl::writer_release() {
  return static_cast<MutexImpl *>(data_)->release();
}

}

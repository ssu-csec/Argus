//===- llvm/ADT/EpochTracker.h - ADT epoch tracking --------------*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the DebugEpochBase and DebugEpochBase::HandleBase classes.
// These can be used to write iterators that are fail-fast when LLVM is built
// with asserts enabled.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_EPOCH_TRACKER_H
#define LLVM_ADT_EPOCH_TRACKER_H

#include "llvh/Config/abi-breaking.h"

#include <cstdint>

namespace llvh {

#if LLVM_ENABLE_ABI_BREAKING_CHECKS

                                                                     
                                                                          
                                                  
   
                                                                              
                                                                  
                                                                                
                   
   
class DebugEpochBase {
  uint64_t Epoch;

public:
  DebugEpochBase() : Epoch(0) {}

                                                                      
                       
  void incrementEpoch() { ++Epoch; }

                                                                     
                                             
  ~DebugEpochBase() { incrementEpoch(); }

                                                                         
                                                                           
                                                                               
     
                                                                                
                                                                                
                                                 
     
  class HandleBase {
    const uint64_t *EpochAddress;
    uint64_t EpochAtCreation;

  public:
    HandleBase() : EpochAddress(nullptr), EpochAtCreation(UINT64_MAX) {}

    explicit HandleBase(const DebugEpochBase *Parent)
        : EpochAddress(&Parent->Epoch), EpochAtCreation(Parent->Epoch) {}

                                                                       
                                                                      
                            
    bool isHandleInSync() const { return *EpochAddress == EpochAtCreation; }

                                                                        
                                                                             
                                     
    const void *getEpochAddress() const { return EpochAddress; }
  };
};

#else

class DebugEpochBase {
public:
  void incrementEpoch() {}

  class HandleBase {
  public:
    HandleBase() = default;
    explicit HandleBase(const DebugEpochBase *) {}
    bool isHandleInSync() const { return true; }
    const void *getEpochAddress() const { return nullptr; }
  };
};

#endif                                   

}                  

#endif

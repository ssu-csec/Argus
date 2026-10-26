/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_WEAKREFSLOT_H
#define HERMES_VM_WEAKREFSLOT_H

#include "hermes/VM/CompressedPointer.h"
#include "hermes/VM/GCCell.h"
#include "hermes/VM/GCConcurrency.h"
#include "hermes/VM/HermesValue.h"
#include "hermes/VM/PointerBase.h"
#include "hermes/VM/WeakRoot.h"

namespace hermes {
namespace vm {

                                                                               
                                                                               
                                                                           
class WeakRefSlot {
 public:
                     

                                                                      
  bool hasValue() const {
    assert(!isFree() && "Should never query a free WeakRef");
    return value_.root != CompressedPointer(nullptr);
  }

                                                          
  inline GCCell *get(PointerBase &base, GC &gc) const;

                                             
  GCCell *getNoBarrierUnsafe(PointerBase &base) const {
                                                                       
    assert(hasValue() && "tried to access collected referent");
    return value_.root.getNonNullNoBarrierUnsafe(base);
  }

  CompressedPointer getNoBarrierUnsafe() const {
    assert(hasValue() && "tried to access collected referent");
    return value_.root.getNoBarrierUnsafe();
  }

  void markWeakRoots(WeakRootAcceptor &acceptor) {
    assert(!isFree() && "Cannot mark the weak root of a freed slot.");
    acceptor.acceptWeak(value_.root);
  }

                                                        

                                                           
  void setPointer(CompressedPointer ptr) {
                                                                       
    value_.root = ptr;
  }

                                                  
  void clearPointer() {
    value_.root = CompressedPointer(nullptr);
  }

                                  

                                                                            
                                                                    
  void free() {
                                                                   
                                                 
                                                       
                                                       
                                                                               
                                                               
    free_.store(true, std::memory_order_relaxed);
  }

                                             

  WeakRefSlot() = default;

                                                                        
                                                                             
  bool isFree() const {
    return free_.load(std::memory_order_relaxed);
  }

  WeakRefSlot *getNextFree() {
    assert(isFree() && "Can only get nextFree on a free slot");
    return value_.nextFree;
  }

  void setNextFree(WeakRefSlot *nextFree) {
    assert(isFree() && "can only set nextFree on a free slot");
    value_.nextFree = nextFree;
  }

                                     
  void emplace(CompressedPointer ptr) {
    assert(isFree() && "Slot must be free.");
    value_.root = ptr;
    free_.store(false, std::memory_order_relaxed);
  }

 private:
                                                                             
                                                                              
                                                                              
                                                                             
                                       
  union WeakRootOrIndex {
    WeakRoot<GCCell> root;
    WeakRefSlot *nextFree;
    WeakRootOrIndex() {}
  } value_;
                                                                            
                                                                   
  std::atomic<bool> free_{true};
};

class JSObject;
class JSWeakMapImplBase;

                                                                               
                                                                             
                                                                           
                                                                      
       
                      
               
                
                  
       
                                                                           
                                              
class WeakMapEntrySlot {
                            
  std::atomic_bool freed_{true};

 public:
                                                
  WeakRoot<GCCell> owner;
                                                  
  union {
    WeakRoot<GCCell> key;
    WeakMapEntrySlot *nextFree;
  };
                                          
                                                                          
  PinnedHermesValue mappedValue;

  void markWeakRoots(WeakRootAcceptor &acceptor) {
    acceptor.acceptWeak(key);
    acceptor.acceptWeak(owner);
  }

  void free() {
    freed_.store(true, std::memory_order_relaxed);
  }

                                            

  WeakMapEntrySlot() {}

  bool isFree() const {
    return freed_.load(std::memory_order_relaxed);
  }

  WeakMapEntrySlot *getNextFree() const {
    assert(isFree() && "Can only get nextFree on a free slot");
    return nextFree;
  }

  void setNextFree(WeakMapEntrySlot *nextFree) {
    assert(isFree() && "can only set nextFree on a free slot");
    this->nextFree = nextFree;
  }

                                     
  void emplace(
      CompressedPointer keyPtr,
      HermesValue value,
      CompressedPointer ownerPtr) {
    freed_.store(false, std::memory_order_relaxed);
    key = keyPtr;
    mappedValue = value;
    owner = ownerPtr;
  }
};

}                
}                    

#endif

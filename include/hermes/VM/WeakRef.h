/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_WEAKREF_H
#define HERMES_VM_WEAKREF_H

#include "hermes/VM/GC.h"
#include "hermes/VM/GCPointer-inline.h"
#include "hermes/VM/GCPointer.h"
#include "hermes/VM/Handle.h"
#include "hermes/VM/Runtime.h"
#include "hermes/VM/WeakRefSlot-inline.h"

namespace hermes {
namespace vm {

class HandleRootOwner;

                                                                           
                    
class WeakRefBase {
 protected:
  WeakRefSlot *slot_;
  WeakRefBase(WeakRefSlot *slot) : slot_(slot) {}

 public:
                                                              
  bool isValid() const {
    return isSlotValid(slot_);
  }

                                                              
  static bool isSlotValid(const WeakRefSlot *slot) {
    assert(slot && "slot must not be null");
    return slot->hasValue();
  }

                                                                               
                                                              
  void releaseSlot() {
    slot_->free();
  }
};

                                                                              
                                                                                
                                                                               
                                                                             
                                                                                
                        
template <class T>
class WeakRef : public WeakRefBase {
 public:
  explicit WeakRef(Runtime &runtime, Handle<T> handle)
      : WeakRef(runtime, runtime.getHeap(), *handle) {}

  explicit WeakRef(PointerBase &base, GC &gc, T *ptr)
      : WeakRefBase(gc.allocWeakSlot(CompressedPointer::encode(ptr, base))) {}

  explicit WeakRef(PointerBase &base, GC &gc, Handle<T> handle)
      : WeakRef(base, gc, *handle) {}

                                                                          
                                                                            
                                            
  explicit WeakRef(WeakRefSlot *slot) : WeakRefBase(slot) {}

                                       
  template <
      typename U,
      typename =
          typename std::enable_if<IsHermesValueConvertible<U, T>::value>::type>
  WeakRef(const WeakRef<U> &other) : WeakRefBase(other) {}

  ~WeakRef() = default;

  WeakRef(const WeakRef &) = default;
  WeakRef &operator=(const WeakRef &) = default;

  bool operator==(const WeakRef &other) const {
    return slot_ == other.slot_;
  }

                                                                          
  T *get(Runtime &runtime) const {
    if (!isValid()) {
      return nullptr;
    }
    GCCell *value = slot_->get(runtime, runtime.getHeap());
    return static_cast<T *>(value);
  }

                                                           
                                                                               
                                                                            
                                                                            
                         
  T *getNoBarrierUnsafe(PointerBase &base) const {
    if (!isValid()) {
      return nullptr;
    }
    return static_cast<T *>(slot_->getNoBarrierUnsafe(base));
  }

                                                  
  bool isEmpty() const {
    return !slot_;
  }

                                           
  bool isSlotFree() const {
    return slot_->isFree();
  }
};

}                
}                    

#endif                       

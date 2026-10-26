/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_JSWEAKMAPIMPL_H
#define HERMES_VM_JSWEAKMAPIMPL_H

#include "hermes/VM/CallResult.h"
#include "hermes/VM/CellKind.h"
#include "hermes/VM/GCPointer.h"
#include "hermes/VM/JSObject.h"
#include "hermes/VM/Runtime.h"
#include "hermes/VM/WeakRef.h"

namespace hermes {
namespace vm {

namespace detail {

                                                     
                                              
                                                                 
class WeakRefKey {
                                                   
  static constexpr uint32_t kEmptyKey = 0;
  static constexpr uint32_t kTombstoneKey = 1;

                                                                             
  WeakMapEntrySlot *slot_;

                                                                               
  uint32_t hash_;

  explicit WeakRefKey(WeakMapEntrySlot *slot, uint32_t hash)
      : slot_(slot), hash_(hash) {}

 public:
  WeakRefKey(
      Runtime &runtime,
      Handle<JSObject> key,
      HermesValue value,
      JSWeakMapImplBase *ownerMapPtr)
      : slot_(
            runtime.getHeap().allocWeakMapEntrySlot(*key, value, ownerMapPtr)),
        hash_(runtime.gcStableHashHermesValue(key)) {}

                                                                               
                                                       
  JSObject *getKeyNonNull(PointerBase &base, GC &gc) const {
    assert(isKeyValid() && "tried to access collected weak ref object");
    return static_cast<JSObject *>(slot_->key.getNonNull(base, gc));
  }

                                                     
  HermesValue getMappedValue(GC &gc) const {
                                                                              
                                                                    
                                                                            
                                                                             
                                                                              
                  
    gc.weakRefReadBarrier(slot_->mappedValue);
    return slot_->mappedValue;
  }

                                            
  void setMappedValue(HermesValue value) {
    slot_->mappedValue = value;
  }

                                                 
  static WeakRefKey createEmptyKey() {
    return WeakRefKey{
        reinterpret_cast<WeakMapEntrySlot *>(kEmptyKey), kEmptyKey};
  }

                                                    
  static WeakRefKey createTombstoneKey() {
    return WeakRefKey{
        reinterpret_cast<WeakMapEntrySlot *>(kTombstoneKey), kTombstoneKey};
  }

                                                                    
  bool isKeyValid() const {
    return !!slot_->key;
  }

                                                                              
             
  bool isKeyEqual(const WeakRefKey &other) const {
                                                                          
                                                   
    if (slot_ == other.slot_)
      return true;
                                                                     
                                                                      
    if (reinterpret_cast<uintptr_t>(slot_) <= kTombstoneKey ||
        reinterpret_cast<uintptr_t>(other.slot_) <= kTombstoneKey)
      return false;

                                                                             
                                                                               
    return slot_->key && other.slot_->key &&
        slot_->key.getNoBarrierUnsafe() ==
        other.slot_->key.getNoBarrierUnsafe();
  }

                                                                          
                                                                          
                           
  bool isKeyEqual(CompressedPointer keyObject) const {
    if (reinterpret_cast<uintptr_t>(slot_) <= kTombstoneKey)
      return false;
    return slot_->key.getNoBarrierUnsafe() == keyObject;
  }

                                                       
  void releaseSlot() {
    slot_->free();
  }

  uint32_t getHash() const {
    return hash_;
  }
};

                                                                           
                                                                            
                                                                                
struct WeakRefLookupKey {
                                
  CompressedPointer refCellPtr;

                                                                               
  uint32_t hash;

  WeakRefLookupKey(Runtime &runtime, Handle<JSObject> keyObj)
      : refCellPtr(CompressedPointer::encode(*keyObj, runtime)),
        hash(runtime.gcStableHashHermesValue(keyObj)) {}
};

                                        
struct WeakRefInfo {
                                             
  static inline WeakRefKey getEmptyKey() {
    return WeakRefKey::createEmptyKey();
  }
                                                                             
  static inline WeakRefKey getTombstoneKey() {
    return WeakRefKey::createTombstoneKey();
  }
                                 
  static inline unsigned getHashValue(const WeakRefKey &key) {
    return key.getHash();
  }
                                     
  static inline unsigned getHashValue(const WeakRefLookupKey &key) {
    return key.hash;
  }
                                                                
                                         
  static inline bool isEqual(const WeakRefKey &a, const WeakRefKey &b) {
    return a.isKeyEqual(b);
  }
                                                                            
                                                                               
                                                                               
                                                                             
                                                                              
                                                                             
                                                                      
  static inline bool isEqual(const WeakRefLookupKey &a, const WeakRefKey &b) {
    assert(a.refCellPtr && "LookupKey should not use a null object pointer");
    return b.isKeyEqual(a.refCellPtr);
  }
};

}                    

                                                 
                                                         
class JSWeakMapImplBase : public JSObject {
  using Super = JSObject;
  using WeakRefKey = detail::WeakRefKey;
  using DenseSetT = llvh::DenseSet<WeakRefKey, detail::WeakRefInfo>;

 protected:
  JSWeakMapImplBase(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz)
      : JSObject(runtime, *parent, *clazz),
        targetSize_(                   0.5,                8) {}

 public:
  static const ObjectVTable vt;

  static bool classof(const GCCell *cell) {
    return kindInRange(
        cell->getKind(),
        CellKind::WeakMapImplBaseKind_first,
        CellKind::WeakMapImplBaseKind_last);
  }

  static void WeakMapImplBaseBuildMeta(
      const GCCell *cell,
      Metadata::Builder &mb);

                                                                  
                                                      
  static ExecutionStatus setValue(
      Handle<JSWeakMapImplBase> self,
      Runtime &runtime,
      Handle<JSObject> key,
      Handle<> value);

                                    
                                                            
  static bool deleteValue(
      Handle<JSWeakMapImplBase> self,
      Runtime &runtime,
      Handle<JSObject> key);

                                                   
  static bool hasValue(
      Handle<JSWeakMapImplBase> self,
      Runtime &runtime,
      Handle<JSObject> key);

                                                                        
  static HermesValue getValue(
      Handle<JSWeakMapImplBase> self,
      Runtime &runtime,
      Handle<JSObject> key);

                                                                            
                                                               
  static uint32_t debugFreeSlotsAndGetSize(
      Runtime &runtime,
      JSWeakMapImplBase *self);

                                                                           
                                                                         
                                                 
  void clearFreeableEntries();

                                           
  using KeyIterator = DenseSetT::iterator;

 protected:
  static void _finalizeImpl(GCCell *cell, GC &gc) {
    auto *self = vmcast<JSWeakMapImplBase>(cell);
    for (auto &element : self->set_) {
                                                                            
                                        
      element.releaseSlot();
    }
    self->~JSWeakMapImplBase();
  }

  static size_t _mallocSizeImpl(GCCell *cell) {
    auto *self = vmcast<JSWeakMapImplBase>(cell);
    return self->getMallocSize();
  }

#ifdef HERMES_MEMORY_INSTRUMENTATION
  static void _snapshotAddEdgesImpl(GCCell *cell, GC &gc, HeapSnapshot &snap);
  static void _snapshotAddNodesImpl(GCCell *cell, GC &gc, HeapSnapshot &snap);
#endif

 public:
                      

                                                                             
                                             
  HeapSnapshot::NodeID getMapID(GC &gc);

                                                                       
  size_t getMallocSize() const {
    return set_.getMemorySize();
  }

 private:
                                    
  DenseSetT set_;

                                                                              
                                                                     
  ExponentialMovingAverage targetSize_;

                                                 
  static constexpr double kOccupancyTarget = 0.5;
};

                                                                 
   
                                                                    
                                                                              
                                                                            
                                                                                
                                                                               
                                                                            
                                   
                                                                           
                                                                         
                                                                           
                                
                                                                               
                                                                         
                              
                                                  
                                           
                                                                        
                                                                              
                           
                                                                           
                                 
template <CellKind C>
class JSWeakMapImpl final : public JSWeakMapImplBase {
  using Super = JSWeakMapImplBase;

 public:
  static const ObjectVTable vt;

  static constexpr CellKind getCellKind() {
    return C;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == C;
  }

                                                                   
  static CallResult<PseudoHandle<JSWeakMapImpl<C>>> create(
      Runtime &runtime,
      Handle<JSObject> parentHandle);

  static void WeakMapOrSetBuildMeta(const GCCell *cell, Metadata::Builder &mb);

  JSWeakMapImpl(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz)
      : JSWeakMapImplBase(runtime, parent, clazz) {}
};

using JSWeakMap = JSWeakMapImpl<CellKind::JSWeakMapKind>;
using JSWeakSet = JSWeakMapImpl<CellKind::JSWeakSetKind>;

}                
}                    

#endif

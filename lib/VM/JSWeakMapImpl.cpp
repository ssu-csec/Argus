/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/JSWeakMapImpl.h"

#include "hermes/VM/Casting.h"
#include "hermes/VM/Runtime-inline.h"
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

using WeakRefLookupKey = detail::WeakRefLookupKey;

void JSWeakMapImplBase::WeakMapImplBaseBuildMeta(
    const GCCell *cell,
    Metadata::Builder &mb) {
  mb.addJSObjectOverlapSlots(JSObject::numOverlapSlots<JSWeakMapImplBase>());
  JSObjectBuildMeta(cell, mb);
}

                                                                
                                                    
ExecutionStatus JSWeakMapImplBase::setValue(
    Handle<JSWeakMapImplBase> self,
    Runtime &runtime,
    Handle<JSObject> key,
    Handle<> value) {
                                                            
  NoAllocScope noAlloc{runtime};
  WeakRefLookupKey lookupKey{runtime, key};
  DenseSetT::iterator it = self->set_.find_as(lookupKey);

  if (it != self->set_.end()) {
                                                 
    it->setMappedValue(*value);
    return ExecutionStatus::RETURNED;
  }

                                                                               
                      
  if (self->set_.size() >= self->targetSize_) {
    self->clearFreeableEntries();
  }
  WeakRefKey mapKey{runtime, key, *value, *self};
  auto result = self->set_.insert(mapKey);
  (void)result;
  assert(result.second && "unable to add a new value to map");

  return ExecutionStatus::RETURNED;
}

                                  
                                                          
bool JSWeakMapImplBase::deleteValue(
    Handle<JSWeakMapImplBase> self,
    Runtime &runtime,
    Handle<JSObject> key) {
  NoAllocScope noAlloc{runtime};
  WeakRefLookupKey lookupKey{runtime, key};
  DenseSetT ::iterator it = self->set_.find_as(lookupKey);
  if (it == self->set_.end()) {
    return false;
  }
  it->releaseSlot();
  self->set_.erase(it);
  return true;
}

                                                 
bool JSWeakMapImplBase::hasValue(
    Handle<JSWeakMapImplBase> self,
    Runtime &runtime,
    Handle<JSObject> key) {
  NoAllocScope noAlloc{runtime};
  WeakRefLookupKey lookupKey{runtime, key};
  DenseSetT::iterator it = self->set_.find_as(lookupKey);
  return it != self->set_.end();
}

HermesValue JSWeakMapImplBase::getValue(
    Handle<JSWeakMapImplBase> self,
    Runtime &runtime,
    Handle<JSObject> key) {
  NoAllocScope noAlloc{runtime};
  WeakRefLookupKey lookupKey{runtime, key};
  DenseSetT::iterator it = self->set_.find_as(lookupKey);
  if (it == self->set_.end()) {
    return HermesValue::encodeUndefinedValue();
  }
  return it->getMappedValue(runtime.getHeap());
}

uint32_t JSWeakMapImplBase::debugFreeSlotsAndGetSize(
    Runtime &runtime,
    JSWeakMapImplBase *self) {
  self->clearFreeableEntries();
  return self->set_.size();
}

void JSWeakMapImplBase::clearFreeableEntries() {
                                                                              
                                                                          
  for (auto it = set_.begin(); it != set_.end(); ++it) {
    if (!it->isKeyValid()) {
      it->releaseSlot();
                                                                          
               
                                                                              
                                                                              
                                                              
      set_.erase(it);
    }
  }
                             
  targetSize_.update(set_.size() / kOccupancyTarget + 1);
}

HeapSnapshot::NodeID JSWeakMapImplBase::getMapID(GC &gc) {
  assert(set_.size() && "Shouldn't call getMapID on an empty map");
  GCBase::IDTracker &tracker = gc.getIDTracker();
  const auto id = gc.getObjectID(this);
  auto &nativeIDList = tracker.getExtraNativeIDs(id);
  if (nativeIDList.empty()) {
    nativeIDList.push_back(tracker.nextNativeID());
  }
  return nativeIDList[0];
}

#ifdef HERMES_MEMORY_INSTRUMENTATION
void JSWeakMapImplBase::_snapshotAddEdgesImpl(
    GCCell *cell,
    GC &gc,
    HeapSnapshot &snap) {
  auto *const self = vmcast<JSWeakMapImplBase>(cell);
  JSObject::_snapshotAddEdgesImpl(self, gc, snap);
  if (self->set_.size()) {
    snap.addNamedEdge(
        HeapSnapshot::EdgeType::Internal, "map", self->getMapID(gc));
  }

                                                                        
  uint32_t edge_index = 0;
  for (const auto &key : self->set_) {
                                    
    if (!key.isKeyValid()) {
      continue;
    }
    auto indexName = std::to_string(edge_index++);
    snap.addNamedEdge(
        HeapSnapshot::EdgeType::Weak,
        indexName,
        gc.getObjectID(key.getKeyNonNull(gc.getPointerBase(), gc)));

    auto mappedValue = key.getMappedValue(gc);
    if (auto id = gc.getSnapshotID(mappedValue)) {
      snap.addNamedEdge(
          HeapSnapshot::EdgeType::Internal,
                                                       
          indexName + "[value]",
          id.getValue());
    }
  }
}

void JSWeakMapImplBase::_snapshotAddNodesImpl(
    GCCell *cell,
    GC &gc,
    HeapSnapshot &snap) {
  auto *const self = vmcast<JSWeakMapImplBase>(cell);
  if (self->set_.size()) {
    snap.beginNode();
    snap.endNode(
        HeapSnapshot::NodeType::Native,
        "DenseSet",
        self->getMapID(gc),
        self->set_.getMemorySize(),
        0);
  }
}
#endif

template <CellKind C>
void JSWeakMapImpl<C>::WeakMapOrSetBuildMeta(
    const GCCell *cell,
    Metadata::Builder &mb) {
  mb.addJSObjectOverlapSlots(JSObject::numOverlapSlots<JSWeakMapImpl<C>>());
  WeakMapImplBaseBuildMeta(cell, mb);
}

void JSWeakMapBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  JSWeakMap::WeakMapOrSetBuildMeta(cell, mb);
  mb.setVTable(&JSWeakMap::vt);
}

void JSWeakSetBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  JSWeakSet::WeakMapOrSetBuildMeta(cell, mb);
  mb.setVTable(&JSWeakSet::vt);
}

template <CellKind C>
const ObjectVTable JSWeakMapImpl<C>::vt{
    VTable(
        C,
        cellSize<JSWeakMapImpl>(),
        JSWeakMapImpl::_finalizeImpl,
        JSWeakMapImpl::_mallocSizeImpl,
        nullptr
#ifdef HERMES_MEMORY_INSTRUMENTATION
        ,
        VTable::HeapSnapshotMetadata{
            HeapSnapshot::NodeType::Object,
            nullptr,
            _snapshotAddEdgesImpl,
            _snapshotAddNodesImpl,
            nullptr}
#endif
        ),
    JSWeakMapImpl::_getOwnIndexedRangeImpl,
    JSWeakMapImpl::_haveOwnIndexedImpl,
    JSWeakMapImpl::_getOwnIndexedPropertyFlagsImpl,
    JSWeakMapImpl::_getOwnIndexedImpl,
    JSWeakMapImpl::_setOwnIndexedImpl,
    JSWeakMapImpl::_deleteOwnIndexedImpl,
    JSWeakMapImpl::_checkAllOwnIndexedImpl,
};

template <CellKind C>
CallResult<PseudoHandle<JSWeakMapImpl<C>>> JSWeakMapImpl<C>::create(
    Runtime &runtime,
    Handle<JSObject> parentHandle) {
  auto *cell = runtime.makeAFixed<JSWeakMapImpl<C>, HasFinalizer::Yes>(
      runtime,
      parentHandle,
      runtime.getHiddenClassForPrototype(
          *parentHandle, numOverlapSlots<JSWeakMapImpl>()));
  return JSObjectInit::initToPseudoHandle(runtime, cell);
}

template class JSWeakMapImpl<CellKind::JSWeakMapKind>;
template class JSWeakMapImpl<CellKind::JSWeakSetKind>;

}                
}                    

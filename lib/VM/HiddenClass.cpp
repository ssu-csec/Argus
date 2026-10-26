/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "class"
#include "hermes/VM/HiddenClass.h"

#include "hermes/VM/ArrayStorage.h"
#include "hermes/VM/GCPointer-inline.h"
#include "hermes/VM/JSArray.h"
#include "hermes/VM/JSObject.h"
#include "hermes/VM/Operations.h"
#include "hermes/VM/StringView.h"

#include "llvh/Support/Debug.h"
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
using llvh::dbgs;

namespace hermes {
namespace vm {

namespace detail {

#ifdef HERMES_MEMORY_INSTRUMENTATION
void TransitionMap::snapshotAddNodes(GC &gc, HeapSnapshot &snap) {
  if (!isLarge()) {
    return;
  }
                                                                           
                                       
                                                                             
              
  snap.beginNode();
  snap.endNode(
      HeapSnapshot::NodeType::Native,
      "WeakValueMap",
      gc.getNativeID(large()),
      getMemorySize(),
      0);
}

void TransitionMap::snapshotAddEdges(GC &gc, HeapSnapshot &snap) {
  uint32_t edge_index = 0;
  forEachEntry([&snap, &gc, &edge_index](
                   const Transition &, const WeakRef<HiddenClass> &value) {
                                               
    if (value.isValid()) {
      snap.addNamedEdge(
          HeapSnapshot::EdgeType::Weak,
          std::to_string(edge_index++),
          gc.getObjectID(value.getNoBarrierUnsafe(gc.getPointerBase())));
    }
  });

  if (!isLarge()) {
    return;
  }
  snap.addNamedEdge(
      HeapSnapshot::EdgeType::Internal,
      "transitionMap",
      gc.getNativeID(large()));
}

void TransitionMap::snapshotUntrackMemory(GC &gc) {
                                                   
  if (isLarge()) {
    gc.getIDTracker().untrackNative(large());
  }
}
#endif

size_t TransitionMap::getMemorySize() const {
                                                                            
  return isLarge() ? sizeof(*large()) + large()->getMemorySize() : 0;
}

void TransitionMap::uncleanMakeLarge(Runtime &runtime) {
  assert(!isClean() && "must not still be clean");
  assert(!isLarge() && "must not yet be large");
  auto large = new WeakValueMap<Transition, HiddenClass>();
                                                 
  if (auto value = smallValue().get(runtime))
    large->insertNew(runtime, smallKey_, runtime.makeHandle(value));
  smallValue().releaseSlot();
  u.large_ = large;
  smallKey_.symbolID = SymbolID::deleted();
  assert(isLarge());
}

}                    

const VTable HiddenClass::vt{
    CellKind::HiddenClassKind,
    cellSize<HiddenClass>(),
    _finalizeImpl,
    _mallocSizeImpl,
    nullptr
#ifdef HERMES_MEMORY_INSTRUMENTATION
    ,
    VTable::HeapSnapshotMetadata{
        HeapSnapshot::NodeType::Object,
        HiddenClass::_snapshotNameImpl,
        HiddenClass::_snapshotAddEdgesImpl,
        HiddenClass::_snapshotAddNodesImpl,
        nullptr}
#endif
};

void HiddenClassBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  const auto *self = static_cast<const HiddenClass *>(cell);
  mb.setVTable(&HiddenClass::vt);
  mb.addField("symbol", &self->symbolID_);
  mb.addField("parent", &self->parent_);
  mb.addField("propertyMap", &self->propertyMap_);
  mb.addField("forInCache", &self->forInCache_);
}

void HiddenClass::_finalizeImpl(GCCell *cell, GC &gc) {
  auto *self = vmcast<HiddenClass>(cell);
#ifdef HERMES_MEMORY_INSTRUMENTATION
  self->transitionMap_.snapshotUntrackMemory(gc);
#endif
  self->~HiddenClass();
}

size_t HiddenClass::_mallocSizeImpl(GCCell *cell) {
  auto *self = vmcast<HiddenClass>(cell);
  return self->transitionMap_.getMemorySize();
}

#ifdef HERMES_MEMORY_INSTRUMENTATION
std::string HiddenClass::_snapshotNameImpl(GCCell *cell, GC &gc) {
  auto *const self = vmcast<HiddenClass>(cell);
  std::string name{cell->getVT()->snapshotMetaData.defaultNameForNode(self)};
  if (self->isDictionary()) {
    return name + "(Dictionary)";
  }
  return name;
}

void HiddenClass::_snapshotAddEdgesImpl(
    GCCell *cell,
    GC &gc,
    HeapSnapshot &snap) {
  auto *const self = vmcast<HiddenClass>(cell);
  self->transitionMap_.snapshotAddEdges(gc, snap);
}

void HiddenClass::_snapshotAddNodesImpl(
    GCCell *cell,
    GC &gc,
    HeapSnapshot &snap) {
  auto *const self = vmcast<HiddenClass>(cell);
  self->transitionMap_.snapshotAddNodes(gc, snap);
}
#endif

CallResult<HermesValue> HiddenClass::createRoot(Runtime &runtime) {
  return create(
      runtime,
      ClassFlags{},
      Runtime::makeNullHandle<HiddenClass>(),
      SymbolID{},
      PropertyFlags{},
      0);
}

CallResult<HermesValue> HiddenClass::create(
    Runtime &runtime,
    ClassFlags flags,
    Handle<HiddenClass> parent,
    SymbolID symbolID,
    PropertyFlags propertyFlags,
    unsigned numProperties) {
  assert(
      (flags.dictionaryMode || numProperties == 0 || *parent) &&
      "non-empty non-dictionary orphan");
  auto *obj =
      runtime.makeAFixed<HiddenClass, HasFinalizer::Yes, LongLived::Yes>(
          runtime, flags, parent, symbolID, propertyFlags, numProperties);
  return HermesValue::encodeObjectValue(obj);
}

Handle<HiddenClass> HiddenClass::copyToNewDictionary(
    Handle<HiddenClass> selfHandle,
    Runtime &runtime,
    bool noCache) {
  assert(
      !selfHandle->isDictionaryNoCache() && "class already in no-cache mode");

  auto newFlags = selfHandle->flags_;
  newFlags.dictionaryMode = true;
                                                   
  if (noCache) {
    newFlags.dictionaryNoCacheMode = true;
  }

                                            
  auto newClassHandle =
      runtime.makeHandle<HiddenClass>(runtime.ignoreAllocationFailure(
          HiddenClass::create(
              runtime,
              newFlags,
              Runtime::makeNullHandle<HiddenClass>(),
              SymbolID{},
              PropertyFlags{},
              selfHandle->numProperties_)));

                                                                       
  if (LLVM_UNLIKELY(!selfHandle->propertyMap_))
    initializeMissingPropertyMap(selfHandle, runtime);

  newClassHandle->propertyMap_.set(
      runtime, selfHandle->propertyMap_, runtime.getHeap());
  selfHandle->propertyMap_.setNull(runtime.getHeap());

  LLVM_DEBUG(
      dbgs() << "Converted Class:" << selfHandle->getDebugAllocationId()
             << " to dictionary Class:"
             << newClassHandle->getDebugAllocationId() << "\n");

  return newClassHandle;
}

void HiddenClass::forEachPropertyNoAlloc(
    HiddenClass *self,
    PointerBase &base,
    std::function<void(SymbolID, NamedPropertyDescriptor)> callback) {
  std::vector<std::pair<SymbolID, NamedPropertyDescriptor>> properties;
  HiddenClass *curr = self;
  while (curr && !curr->propertyMap_) {
                                                                        
                             
    if (curr->symbolID_.isValid() && !curr->propertyFlags_.flagsTransition) {
      properties.emplace_back(
          curr->symbolID_,
          NamedPropertyDescriptor{
              curr->propertyFlags_, curr->numProperties_ - 1});
    }
    curr = curr->parent_.get(base);
  }

                                                                       
                                                                        
  if (curr) {
    assert(
        curr->propertyMap_ &&
        "If it's not the root class, it must have a property map");
                                                                           
    DictPropertyMap::forEachPropertyNoAlloc(
        curr->propertyMap_.getNonNull(base), callback);
  }
                                            
                                                                          
                                                                            
           
  for (auto it = properties.rbegin(); it != properties.rend(); ++it) {
    callback(it->first, it->second);
  }
}

OptValue<HiddenClass::PropertyPos> HiddenClass::findProperty(
    PseudoHandle<HiddenClass> self,
    Runtime &runtime,
    SymbolID name,
    PropertyFlags expectedFlags,
    NamedPropertyDescriptor &desc) {
                                    
  if (LLVM_UNLIKELY(!self->propertyMap_)) {
                                                                      
                                                                            
                                                                               
                                                                  
    if (expectedFlags.isValid()) {
      Transition t{name, expectedFlags};
      if (self->transitionMap_.containsKey(t, runtime.getHeap())) {
        LLVM_DEBUG(
            dbgs()
            << "Property " << runtime.formatSymbolID(name)
            << " NOT FOUND in Class:" << self->getDebugAllocationId()
            << " due to existing transition to Class:"
            << self->transitionMap_.lookup(runtime, t)->getDebugAllocationId()
            << "\n");
        return llvh::None;
      }
    }

    auto selfHandle = runtime.makeHandle(std::move(self));
    initializeMissingPropertyMap(selfHandle, runtime);
    self = selfHandle;
  }

  auto *propMap = self->propertyMap_.getNonNull(runtime);
  {
                                                                         
    NoAllocScope noAlloc(runtime);
    auto found = DictPropertyMap::find(propMap, name);
    if (!found)
      return llvh::None;
                                                                           
                                                                               
                                                                               
    desc = DictPropertyMap::getDescriptorPair(propMap, *found)->second;
    return *found;
  }
}

llvh::Optional<NamedPropertyDescriptor> HiddenClass::findPropertyNoAlloc(
    HiddenClass *self,
    PointerBase &base,
    SymbolID name) {
  for (HiddenClass *curr = self; curr; curr = curr->parent_.get(base)) {
    if (curr->propertyMap_) {
                                                                
      auto found =
          DictPropertyMap::find(curr->propertyMap_.getNonNull(base), name);
      if (found) {
        return DictPropertyMap::getDescriptorPair(
                   curr->propertyMap_.getNonNull(base), *found)
            ->second;
      }
    }
                                                                          
                 
    if (curr->symbolID_ == name) {
      return NamedPropertyDescriptor{
          curr->propertyFlags_, curr->numProperties_ - 1};
    }
  }
                                                                        
                                                  
  return llvh::None;
}

bool HiddenClass::debugIsPropertyDefined(
    HiddenClass *self,
    PointerBase &base,
    SymbolID name) {
  do {
                                                   
    if (self->propertyMap_)
      return DictPropertyMap::find(self->propertyMap_.getNonNull(base), name)
          .hasValue();
                                             
    if (self->symbolID_ == name)
      return true;
    self = self->parent_.get(base);
  } while (self);
  return false;
}

Handle<HiddenClass> HiddenClass::deleteProperty(
    Handle<HiddenClass> selfHandle,
    Runtime &runtime,
    PropertyPos pos) {
                                                           
                                                                      
                                                    
  auto newHandle = LLVM_UNLIKELY(!selfHandle->isDictionaryNoCache())
      ? copyToNewDictionary(selfHandle, runtime, selfHandle->isDictionary())
      : selfHandle;

  --newHandle->numProperties_;

  DictPropertyMap::erase(newHandle->propertyMap_.get(runtime), runtime, pos);

  LLVM_DEBUG(
      dbgs() << "Deleting from Class:" << selfHandle->getDebugAllocationId()
             << " produces Class:" << newHandle->getDebugAllocationId()
             << "\n");

  return newHandle;
}

CallResult<std::pair<Handle<HiddenClass>, SlotIndex>> HiddenClass::addProperty(
    Handle<HiddenClass> selfHandle,
    Runtime &runtime,
    SymbolID name,
    PropertyFlags propertyFlags) {
  assert(propertyFlags.isValid() && "propertyFlags must be valid");

  if (LLVM_UNLIKELY(selfHandle->isDictionary())) {
    auto isIndexLike =
        toArrayIndex(runtime.getIdentifierTable().getStringView(runtime, name))
            .hasValue();
    selfHandle->flags_ =
        computeFlags(selfHandle->flags_, propertyFlags, isIndexLike);

                           
                                                                        
                                                                               
                                                                               
                                                                           
                          
    SlotIndex newSlot = DictPropertyMap::allocatePropertySlot(
        selfHandle->propertyMap_.get(runtime), runtime);

    if (LLVM_UNLIKELY(
            addToPropertyMap(
                selfHandle,
                runtime,
                name,
                NamedPropertyDescriptor(propertyFlags, newSlot)) ==
            ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }

    ++selfHandle->numProperties_;
    return std::make_pair(selfHandle, newSlot);
  }

                                                                  
  auto existingChild =
      selfHandle->transitionMap_.lookup(runtime, {name, propertyFlags});
  if (LLVM_LIKELY(existingChild)) {
    auto childHandle = runtime.makeHandle(existingChild);
                                                                              
                            
    if (!childHandle->propertyMap_ && selfHandle->propertyMap_) {
      LLVM_DEBUG(
          dbgs() << "Adding property " << runtime.formatSymbolID(name)
                 << " to Class:" << selfHandle->getDebugAllocationId()
                 << " transitions Map to existing Class:"
                 << childHandle->getDebugAllocationId() << "\n");

      if (LLVM_UNLIKELY(
              addToPropertyMap(
                  selfHandle,
                  runtime,
                  name,
                  NamedPropertyDescriptor(
                      propertyFlags, selfHandle->numProperties_)) ==
              ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      childHandle->propertyMap_.set(
          runtime, selfHandle->propertyMap_, runtime.getHeap());
    } else {
      LLVM_DEBUG(
          dbgs() << "Adding property " << runtime.formatSymbolID(name)
                 << " to Class:" << selfHandle->getDebugAllocationId()
                 << " transitions to existing Class:"
                 << childHandle->getDebugAllocationId() << "\n");
    }

                                      
    selfHandle->propertyMap_.setNull(runtime.getHeap());

    return std::make_pair(childHandle, selfHandle->numProperties_);
  }

                                         
  if (LLVM_UNLIKELY(selfHandle->numProperties_ == kDictionaryThreshold)) {
             
    auto childHandle = copyToNewDictionary(selfHandle, runtime);

    auto isIndexLike =
        toArrayIndex(runtime.getIdentifierTable().getStringView(runtime, name))
            .hasValue();
    childHandle->flags_ =
        computeFlags(childHandle->flags_, propertyFlags, isIndexLike);

                                     
    if (LLVM_UNLIKELY(
            addToPropertyMap(
                childHandle,
                runtime,
                name,
                NamedPropertyDescriptor(
                    propertyFlags, childHandle->numProperties_)) ==
            ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    return std::make_pair(childHandle, childHandle->numProperties_++);
  }

  auto isIndexLike =
      toArrayIndex(runtime.getIdentifierTable().getStringView(runtime, name))
          .hasValue();
  auto newFlags = computeFlags(selfHandle->flags_, propertyFlags, isIndexLike);

                        
  auto childHandle =
      runtime.makeHandle<HiddenClass>(runtime.ignoreAllocationFailure(
          HiddenClass::create(
              runtime,
              newFlags,
              selfHandle,
              name,
              propertyFlags,
              selfHandle->numProperties_ + 1)));

                                    
  auto inserted = selfHandle->transitionMap_.insertNew(
      runtime, Transition(name, propertyFlags), childHandle);
  (void)inserted;
  assert(
      inserted &&
      "transition already exists when adding a new property to hidden class");

  if (selfHandle->propertyMap_) {
    assert(
        !DictPropertyMap::find(selfHandle->propertyMap_.get(runtime), name) &&
        "Adding an existing property to hidden class");

    LLVM_DEBUG(
        dbgs() << "Adding property " << runtime.formatSymbolID(name)
               << " to Class:" << selfHandle->getDebugAllocationId()
               << " transitions Map to new Class:"
               << childHandle->getDebugAllocationId() << "\n");

                                       
    childHandle->propertyMap_.set(
        runtime, selfHandle->propertyMap_, runtime.getHeap());
    selfHandle->propertyMap_.setNull(runtime.getHeap());

    if (LLVM_UNLIKELY(
            addToPropertyMap(
                childHandle,
                runtime,
                name,
                NamedPropertyDescriptor(
                    propertyFlags, selfHandle->numProperties_)) ==
            ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
  } else {
    LLVM_DEBUG(
        dbgs() << "Adding property " << runtime.formatSymbolID(name)
               << " to Class:" << selfHandle->getDebugAllocationId()
               << " transitions to new Class:"
               << childHandle->getDebugAllocationId() << "\n");
  }

  return std::make_pair(childHandle, selfHandle->numProperties_);
}

Handle<HiddenClass> HiddenClass::updateProperty(
    Handle<HiddenClass> selfHandle,
    Runtime &runtime,
    PropertyPos pos,
    PropertyFlags newFlags) {
  assert(newFlags.isValid() && "newFlags must be valid");

                                                                    
  if (LLVM_UNLIKELY(selfHandle->isDictionary())) {
    assert(
        selfHandle->propertyMap_ &&
        "propertyMap must exist in dictionary mode");
    selfHandle->flags_ = computeFlags(selfHandle->flags_, newFlags, false);
    DictPropertyMap::getDescriptorPair(
        selfHandle->propertyMap_.getNonNull(runtime), pos)
        ->second.flags = newFlags;
                                                      
    if (!selfHandle->isDictionaryNoCache()) {
      selfHandle = copyToNewDictionary(selfHandle, runtime,             true);
    }
    return selfHandle;
  }

  assert(
      selfHandle->propertyMap_ && "propertyMap must exist in updateProperty()");

  auto *descPair = DictPropertyMap::getDescriptorPair(
      selfHandle->propertyMap_.get(runtime), pos);
                                                     
  if (descPair->second.flags == newFlags)
    return selfHandle;

  auto name = descPair->first;

                                                                        
  PropertyFlags transitionFlags = newFlags;
  transitionFlags.flagsTransition = 1;

                                                                  
  auto existingChild =
      selfHandle->transitionMap_.lookup(runtime, {name, transitionFlags});
  if (LLVM_LIKELY(existingChild)) {
                                                                              
                            
    if (!existingChild->propertyMap_) {
      LLVM_DEBUG(
          dbgs() << "Updating property " << runtime.formatSymbolID(name)
                 << " in Class:" << selfHandle->getDebugAllocationId()
                 << " transitions Map to existing Class:"
                 << existingChild->getDebugAllocationId() << "\n");

      descPair->second.flags = newFlags;
      existingChild->propertyMap_.set(
          runtime, selfHandle->propertyMap_, runtime.getHeap());
    } else {
      LLVM_DEBUG(
          dbgs() << "Updating property " << runtime.formatSymbolID(name)
                 << " in Class:" << selfHandle->getDebugAllocationId()
                 << " transitions to existing Class:"
                 << existingChild->getDebugAllocationId() << "\n");
    }

                                      
    selfHandle->propertyMap_.setNull(runtime.getHeap());

    return runtime.makeHandle(existingChild);
  }

                                                                           
                  
  descPair->second.flags = newFlags;

                        
  auto childHandle =
      runtime.makeHandle<HiddenClass>(runtime.ignoreAllocationFailure(
          HiddenClass::create(
              runtime,
              computeFlags(selfHandle->flags_, newFlags, false),
              selfHandle,
              name,
              transitionFlags,
              selfHandle->numProperties_)));

                                    
  auto inserted = selfHandle->transitionMap_.insertNew(
      runtime, Transition(name, transitionFlags), childHandle);
  (void)inserted;
  assert(
      inserted &&
      "transition already exists when updating a property in hidden class");

  LLVM_DEBUG(
      dbgs() << "Updating property " << runtime.formatSymbolID(name)
             << " in Class:" << selfHandle->getDebugAllocationId()
             << " transitions Map to new Class:"
             << childHandle->getDebugAllocationId() << "\n");

                                             
  childHandle->propertyMap_.set(
      runtime, selfHandle->propertyMap_, runtime.getHeap());
  selfHandle->propertyMap_.setNull(runtime.getHeap());

  return childHandle;
}

Handle<HiddenClass> HiddenClass::makeAllNonConfigurable(
    Handle<HiddenClass> selfHandle,
    Runtime &runtime) {
  if (!selfHandle->propertyMap_)
    initializeMissingPropertyMap(selfHandle, runtime);

  LLVM_DEBUG(
      dbgs() << "Class:" << selfHandle->getDebugAllocationId()
             << " making all non-configurable\n");

                                                                         
                                                                   
  auto mapHandle = runtime.makeHandle(selfHandle->propertyMap_);

  MutableHandle<HiddenClass> curHandle{runtime, *selfHandle};

                                                                             
                                         
  DictPropertyMap::forEachProperty(
      mapHandle,
      runtime,
      [&runtime, &curHandle](SymbolID id, NamedPropertyDescriptor desc) {
        if (!desc.flags.configurable)
          return;
        PropertyFlags newFlags = desc.flags;
        newFlags.configurable = 0;

        assert(
            curHandle->propertyMap_ &&
            "propertyMap must exist after updateOwnProperty()");

        auto found =
            DictPropertyMap::find(curHandle->propertyMap_.get(runtime), id);
        assert(found && "property not found during enumeration");
        curHandle = *updateProperty(curHandle, runtime, *found, newFlags);
      });
  return std::move(curHandle);
}

Handle<HiddenClass> HiddenClass::makeAllReadOnly(
    Handle<HiddenClass> selfHandle,
    Runtime &runtime) {
  if (!selfHandle->propertyMap_)
    initializeMissingPropertyMap(selfHandle, runtime);

  LLVM_DEBUG(
      dbgs() << "Class:" << selfHandle->getDebugAllocationId()
             << " making all read-only\n");

                                                                         
                                                                   
  auto mapHandle = runtime.makeHandle(selfHandle->propertyMap_);

  MutableHandle<HiddenClass> curHandle{runtime, *selfHandle};

                                                                             
                                         
  DictPropertyMap::forEachProperty(
      mapHandle,
      runtime,
      [&runtime, &curHandle](SymbolID id, NamedPropertyDescriptor desc) {
        PropertyFlags newFlags = desc.flags;
        if (!newFlags.accessor) {
          newFlags.writable = 0;
          newFlags.configurable = 0;
        } else {
          newFlags.configurable = 0;
        }
        if (desc.flags == newFlags)
          return;

        assert(
            curHandle->propertyMap_ &&
            "propertyMap must exist after updateOwnProperty()");

        auto found =
            DictPropertyMap::find(curHandle->propertyMap_.get(runtime), id);
        assert(found && "property not found during enumeration");
        curHandle = *updateProperty(curHandle, runtime, *found, newFlags);
      });

  return std::move(curHandle);
}

Handle<HiddenClass> HiddenClass::updatePropertyFlagsWithoutTransitions(
    Handle<HiddenClass> selfHandle,
    Runtime &runtime,
    PropertyFlags flagsToClear,
    PropertyFlags flagsToSet,
    OptValue<llvh::ArrayRef<SymbolID>> props) {
                                                                      
  MutableHandle<HiddenClass> classHandle{runtime};
  if (selfHandle->isDictionary()) {
    classHandle = *selfHandle;
  } else {
    classHandle = *copyToNewDictionary(selfHandle, runtime);
  }

  auto mapHandle =
      runtime.makeHandle<DictPropertyMap>(classHandle->propertyMap_);

  auto changeFlags = [&flagsToClear,
                      &flagsToSet](NamedPropertyDescriptor &desc) {
    desc.flags.changeFlags(flagsToClear, flagsToSet);
  };

                                                                                
                           
  if (props) {
                                                                  
    for (auto id : *props) {
      auto pos = DictPropertyMap::find(*mapHandle, id);
      if (!pos) {
        continue;
      }
      auto descPair = DictPropertyMap::getDescriptorPair(*mapHandle, *pos);
      changeFlags(descPair->second);
    }
  } else {
    DictPropertyMap::forEachMutablePropertyDescriptor(
        mapHandle, runtime, changeFlags);
  }
  classHandle->flags_ = computeFlags(classHandle->flags_, flagsToSet, false);

  return std::move(classHandle);
}

CallResult<std::pair<Handle<HiddenClass>, SlotIndex>> HiddenClass::reserveSlot(
    Handle<HiddenClass> selfHandle,
    Runtime &runtime) {
  assert(
      !selfHandle->isDictionary() &&
      "Reserved slots can only be added in class mode");
  SlotIndex index = selfHandle->numProperties_;
  assert(
      index < InternalProperty::NumAnonymousInternalProperties &&
      "Reserved slot index is too large");

  return HiddenClass::addProperty(
      selfHandle,
      runtime,
      InternalProperty::getSymbolID(index),
      PropertyFlags{});
}

bool HiddenClass::areAllNonConfigurable(
    Handle<HiddenClass> selfHandle,
    Runtime &runtime) {
  return forEachPropertyWhile(
      selfHandle,
      runtime,
      [](Runtime &, SymbolID, NamedPropertyDescriptor desc) {
        return !desc.flags.configurable;
      });
}

bool HiddenClass::areAllReadOnly(
    Handle<HiddenClass> selfHandle,
    Runtime &runtime) {
  return forEachPropertyWhile(
      selfHandle,
      runtime,
      [](Runtime &, SymbolID, NamedPropertyDescriptor desc) {
        if (!desc.flags.accessor && desc.flags.writable)
          return false;
        return !desc.flags.configurable;
      });
}

ExecutionStatus HiddenClass::addToPropertyMap(
    Handle<HiddenClass> selfHandle,
    Runtime &runtime,
    SymbolID name,
    NamedPropertyDescriptor desc) {
  assert(selfHandle->propertyMap_ && "the property map must be initialized");

                                           
  MutableHandle<DictPropertyMap> updatedMap{
      runtime, selfHandle->propertyMap_.get(runtime)};

  if (LLVM_UNLIKELY(
          DictPropertyMap::add(updatedMap, runtime, name, desc) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  selfHandle->propertyMap_.setNonNull(runtime, *updatedMap, runtime.getHeap());
  return ExecutionStatus::RETURNED;
}

void HiddenClass::initializeMissingPropertyMap(
    Handle<HiddenClass> selfHandle,
    Runtime &runtime) {
  assert(!selfHandle->propertyMap_ && "property map is already initialized");

                                                                         
                                        
  if (selfHandle->parent_ &&
      selfHandle->parent_.getNonNull(runtime)->propertyMap_)
    return stealPropertyMapFromParent(selfHandle, runtime);

  LLVM_DEBUG(
      dbgs() << "Class:" << selfHandle->getDebugAllocationId()
             << " allocating new map\n");

                                                                       
  using MapEntry = std::pair<SymbolID, PropertyFlags>;
  llvh::SmallVector<MapEntry, 4> entries;
  entries.reserve(selfHandle->numProperties_);
  {
                                                
    NoAllocScope _(runtime);
    for (auto *cur = *selfHandle; cur->numProperties_ > 0;
         cur = cur->parent_.getNonNull(runtime)) {
      auto tmpFlags = cur->propertyFlags_;
      tmpFlags.flagsTransition = 0;
      entries.emplace_back(cur->symbolID_, tmpFlags);
    }
  }

  assert(
      entries.size() <= DictPropertyMap::getMaxCapacity() &&
      "There shouldn't ever be this many properties");
                                            
  auto res = DictPropertyMap::create(
      runtime,
      std::max(
          (DictPropertyMap::size_type)entries.size(),
          toRValue(DictPropertyMap::DEFAULT_CAPACITY)));
  assert(
      res != ExecutionStatus::EXCEPTION &&
      "Since the entries would fit, there shouldn't be an exception");
  MutableHandle<DictPropertyMap> mapHandle{runtime, res->get()};

                                                                         
                
  SlotIndex slotIndex = 0;
  for (auto it = entries.rbegin(), e = entries.rend(); it != e; ++it) {
    auto inserted = DictPropertyMap::findOrAdd(mapHandle, runtime, it->first);
    assert(
        inserted != ExecutionStatus::EXCEPTION &&
        "Space was already reserved, this couldn't have grown");

    inserted->first->flags = it->second;
                                                       
    if (LLVM_LIKELY(inserted->second))
      inserted->first->slot = slotIndex++;
  }

  selfHandle->propertyMap_.setNonNull(runtime, *mapHandle, runtime.getHeap());
}

void HiddenClass::stealPropertyMapFromParent(
    Handle<HiddenClass> selfHandle,
    Runtime &runtime) {
                                           
  NoAllocScope noAlloc(runtime);
  auto *self = *selfHandle;
  assert(
      self->parent_ && self->parent_.getNonNull(runtime)->propertyMap_ &&
      !self->propertyMap_ &&
      "stealPropertyMapFromParent() must be called with a valid parent with a property map");

  LLVM_DEBUG(
      dbgs() << "Class:" << self->getDebugAllocationId()
             << " stealing map from parent Class:"
             << self->parent_.getNonNull(runtime)->getDebugAllocationId()
             << "\n");

                                                                   
  self->propertyMap_.set(
      runtime,
      self->parent_.getNonNull(runtime)->propertyMap_,
      runtime.getHeap());
  self->parent_.getNonNull(runtime)->propertyMap_.setNull(runtime.getHeap());

                                       
  if (LLVM_LIKELY(!self->propertyFlags_.flagsTransition)) {
                                                   
    assert(
        self->numProperties_ - 1 ==
            self->propertyMap_.getNonNull(runtime)->size() &&
        "propertyMap->size() must match HiddenClass::numProperties-1 in "
        "new prop transition");

                                            
    NamedPropertyDescriptor desc{
        self->propertyFlags_, self->numProperties_ - 1};
                                                 
    noAlloc.release();
    addToPropertyMap(selfHandle, runtime, selfHandle->symbolID_, desc);
    return;
  }
                                                                        
                              

  assert(
      self->numProperties_ == self->propertyMap_.getNonNull(runtime)->size() &&
      "propertyMap->size() must match HiddenClass::numProperties in "
      "flag update transition");

  auto pos =
      DictPropertyMap::find(self->propertyMap_.get(runtime), self->symbolID_);
  assert(pos && "property must exist in flag update transition");
  auto tmpFlags = self->propertyFlags_;
  tmpFlags.flagsTransition = 0;
  DictPropertyMap::getDescriptorPair(self->propertyMap_.get(runtime), *pos)
      ->second.flags = tmpFlags;
}

}                
}                    

#undef DEBUG_TYPE

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/Domain.h"

#include "hermes/VM/Callable.h"
#include "hermes/VM/GCPointer-inline.h"
#include "hermes/VM/JSLib.h"
#include "hermes/VM/Profiler/SamplingProfiler.h"
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

const VTable Domain::vt{
    CellKind::DomainKind,
    cellSize<Domain>(),
    _finalizeImpl,
    _mallocSizeImpl,
    nullptr
#ifdef HERMES_MEMORY_INSTRUMENTATION
    ,
    VTable::HeapSnapshotMetadata{
        HeapSnapshot::NodeType::Code,
        nullptr,
        Domain::_snapshotAddEdgesImpl,
        Domain::_snapshotAddNodesImpl,
        nullptr}
#endif
};

void DomainBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  const auto *self = static_cast<const Domain *>(cell);
  mb.setVTable(&Domain::vt);
  mb.addField("cjsModules", &self->cjsModules_);
  mb.addField("throwingRequire", &self->throwingRequire_);
}

PseudoHandle<Domain> Domain::create(Runtime &runtime) {
  auto *cell = runtime.makeAFixed<Domain, HasFinalizer::Yes>();
  auto self = createPseudoHandle(cell);
  return self;
}

void Domain::_finalizeImpl(GCCell *cell, GC &gc) {
  auto *self = vmcast<Domain>(cell);
  for (RuntimeModule *rm : self->runtimeModules_) {
    gc.getIDTracker().untrackNative(rm);
  }
  self->~Domain();
}

PseudoHandle<NativeFunction> Domain::getThrowingRequire(
    Runtime &runtime) const {
  return createPseudoHandle(throwingRequire_.get(runtime));
}

size_t Domain::_mallocSizeImpl(GCCell *cell) {
  auto *self = vmcast<Domain>(cell);
  size_t rmSize = 0;
  for (auto *rm : self->runtimeModules_)
    rmSize += sizeof(RuntimeModule) + rm->additionalMemorySize();

  return self->cjsRuntimeModules_.capacity_in_bytes() +
      self->cjsModuleTable_.getMemorySize() +
      self->runtimeModules_.capacity_in_bytes() + rmSize;
}

#ifdef HERMES_MEMORY_INSTRUMENTATION
void Domain::_snapshotAddEdgesImpl(GCCell *cell, GC &gc, HeapSnapshot &snap) {
  auto *const self = vmcast<Domain>(cell);
  for (RuntimeModule *rm : self->runtimeModules_)
    snap.addNamedEdge(
        HeapSnapshot::EdgeType::Internal, "RuntimeModule", gc.getNativeID(rm));
}

void Domain::_snapshotAddNodesImpl(GCCell *cell, GC &gc, HeapSnapshot &snap) {
  auto *const self = vmcast<Domain>(cell);
  for (RuntimeModule *rm : self->runtimeModules_) {
                                                                        
    rm->snapshotAddNodes(gc, snap);
    snap.beginNode();
    rm->snapshotAddEdges(gc, snap);
    snap.endNode(
        HeapSnapshot::NodeType::Native,
        "RuntimeModule",
        gc.getNativeID(rm),
        sizeof(RuntimeModule) + rm->additionalMemorySize(),
        0);
  }
}
#endif

ExecutionStatus Domain::importCJSModuleTable(
    Handle<Domain> self,
    Runtime &runtime,
    RuntimeModule *runtimeModule) {
  if (runtimeModule->getBytecode()->getCJSModuleTable().empty() &&
      runtimeModule->getBytecode()->getCJSModuleTableStatic().empty()) {
                                                         
    return ExecutionStatus::RETURNED;
  }

  static_assert(
      CJSModuleSize < 10, "CJSModuleSize must be small to avoid overflow");

  MutableHandle<ArrayStorage> cjsModules{runtime};

  if (!self->cjsModules_) {
                                               
                                                                             
                              

    const uint64_t firstSegmentModules =
        runtimeModule->getBytecode()->getCJSModuleTable().size() +
        runtimeModule->getBytecode()->getCJSModuleTableStatic().size();

    assert(
        firstSegmentModules <= std::numeric_limits<uint32_t>::max() &&
        "number of modules is 32 bits due to the bytecode format");

                                                      
    const uint64_t requiredSize = firstSegmentModules * CJSModuleSize;
    if (requiredSize > std::numeric_limits<uint32_t>::max()) {
      return runtime.raiseRangeError("Loaded module count exceeded limit");
    }

    auto cjsModulesRes = ArrayStorage::create(runtime, requiredSize);
    if (LLVM_UNLIKELY(cjsModulesRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    cjsModules = vmcast<ArrayStorage>(*cjsModulesRes);
    self->cjsRuntimeModules_.reserve(firstSegmentModules);
    for (size_t i = self->cjsRuntimeModules_.size(); i < firstSegmentModules;
         i++) {
      self->cjsRuntimeModules_.push_back(nullptr, runtime.getHeap());
    }

    auto requireFn = NativeFunction::create(
        runtime,
        Handle<JSObject>::vmcast(&runtime.functionPrototype),
        (void *)TypeErrorKind::InvalidDynamicRequire,
        throwTypeError,
        Predefined::getSymbolID(Predefined::emptyString),
        0,
        Runtime::makeNullHandle<JSObject>());

    auto context = RequireContext::create(
        runtime,
        self,
        runtime.getPredefinedStringHandle(Predefined::emptyString));

                                        
    PropertyFlags pf = PropertyFlags::defaultNewNamedPropertyFlags();
    pf.writable = 0;
    pf.configurable = 0;
    if (LLVM_UNLIKELY(
            JSObject::defineNewOwnProperty(
                requireFn,
                runtime,
                Predefined::getSymbolID(Predefined::context),
                pf,
                context) == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }

    self->throwingRequire_.set(runtime, *requireFn, runtime.getHeap());
  } else {
    cjsModules = self->cjsModules_.get(runtime);
  }

  assert(cjsModules && "cjsModules not set");

                                                                            
                   
  uint64_t maxModuleID = cjsModules->size() / CJSModuleSize;

                                                                             
                                                                             
                         
  for (const auto &pair : runtimeModule->getBytecode()->getCJSModuleTable()) {
    SymbolID symbolId =
        runtimeModule->getSymbolIDFromStringIDMayAllocate(pair.first);
    if (self->cjsModuleTable_.find(symbolId) == self->cjsModuleTable_.end()) {
      ++maxModuleID;
    }
  }

                                                                              
                    
  for (const auto &pair :
       runtimeModule->getBytecode()->getCJSModuleTableStatic()) {
    const auto &moduleID = pair.first;
    if (moduleID > maxModuleID) {
      maxModuleID = moduleID;
    }
  }

  assert(
      maxModuleID <= std::numeric_limits<uint32_t>::max() &&
      "number of modules is 32 bits due to the bytecode format");

                                                    
  const uint64_t requiredSize = (maxModuleID + 1) * CJSModuleSize;
  if (requiredSize > std::numeric_limits<uint32_t>::max()) {
    return runtime.raiseRangeError("Loaded module count exceeded limit");
  }

                                                                 
  if (requiredSize > cjsModules->size()) {
    if (LLVM_UNLIKELY(
            ArrayStorage::resize(cjsModules, runtime, requiredSize) ==
            ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    self->cjsRuntimeModules_.reserve(maxModuleID + 1);
    for (size_t i = self->cjsRuntimeModules_.size(); i <= maxModuleID; i++) {
      self->cjsRuntimeModules_.push_back(nullptr, runtime.getHeap());
    }
  }

                                                                               
                                                                           
                 
  const auto isModuleRegistered = [&cjsModules,
                                   maxModuleID](uint32_t moduleID) -> bool {
    assert(
        moduleID <= maxModuleID &&
        "CJS module ID exceeds maximum known module ID");
    (void)maxModuleID;
    uint32_t index = moduleID * CJSModuleSize;
    uint32_t requiredSize = index + CJSModuleSize;
    assert(
        cjsModules->size() >= requiredSize &&
        "CJS module ID exceeds allocated storage");
    (void)requiredSize;
    return !cjsModules->at(index + FunctionIndexOffset).isEmpty();
  };

                                                                      
                                                                          
                                                                           
                                                                       
                         
                                                                
  auto &cjsEntryModuleID = self->cjsEntryModuleID_;
  auto &cjsRuntimeModules = self->cjsRuntimeModules_;
  const auto registerModule =
      [&runtime,
       &cjsModules,
       &cjsRuntimeModules,
       runtimeModule,
       &isModuleRegistered,
       &cjsEntryModuleID](uint32_t moduleID, uint32_t functionID) -> uint32_t {
    assert(!isModuleRegistered(moduleID) && "CJS module ID collision occurred");
    (void)isModuleRegistered;
    if (LLVM_UNLIKELY(!cjsEntryModuleID.hasValue())) {
      cjsEntryModuleID = moduleID;
    }
    uint32_t index = moduleID * CJSModuleSize;
    cjsModules->set(
        index + CachedExportsOffset,
        HermesValue::encodeEmptyValue(),
        runtime.getHeap());
    cjsModules->set(
        index + ModuleOffset,
        HermesValue::encodeNullValue(),
        runtime.getHeap());
    cjsModules->set(
        index + FunctionIndexOffset,
        HermesValue::encodeNativeUInt32(functionID),
        runtime.getHeap());
    cjsRuntimeModules[moduleID] = runtimeModule;
    assert(isModuleRegistered(moduleID) && "CJS module was not registered");
    return index;
  };

                                                    
  for (const auto &pair : runtimeModule->getBytecode()->getCJSModuleTable()) {
    SymbolID symbolId =
        runtimeModule->getSymbolIDFromStringIDMayAllocate(pair.first);
    auto emplaceRes = self->cjsModuleTable_.try_emplace(symbolId, 0xffffffff);
    if (emplaceRes.second) {
                                                    
                                                                         
                                                 
                                                                               
                                                                        
                           
      uint32_t moduleID = self->cjsModuleTable_.size() - 1;
      const auto functionID = pair.second;
      auto index = registerModule(moduleID, functionID);
                                                                      
      emplaceRes.first->second = index;
    }
  }

                                             
  for (const auto &pair :
       runtimeModule->getBytecode()->getCJSModuleTableStatic()) {
    const auto &moduleID = pair.first;
    const auto &functionID = pair.second;
    if (!isModuleRegistered(moduleID)) {
      registerModule(moduleID, functionID);
    }
  }

  self->cjsModules_.set(runtime, cjsModules.get(), runtime.getHeap());
  return ExecutionStatus::RETURNED;
}

const ObjectVTable RequireContext::vt{
    VTable(CellKind::RequireContextKind, cellSize<RequireContext>()),
    RequireContext::_getOwnIndexedRangeImpl,
    RequireContext::_haveOwnIndexedImpl,
    RequireContext::_getOwnIndexedPropertyFlagsImpl,
    RequireContext::_getOwnIndexedImpl,
    RequireContext::_setOwnIndexedImpl,
    RequireContext::_deleteOwnIndexedImpl,
    RequireContext::_checkAllOwnIndexedImpl,
};

void RequireContextBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  mb.addJSObjectOverlapSlots(JSObject::numOverlapSlots<RequireContext>());
  JSObjectBuildMeta(cell, mb);
  const auto *self = static_cast<const RequireContext *>(cell);
  mb.setVTable(&RequireContext::vt);
  mb.addField(&self->domain_);
  mb.addField(&self->dirname_);
}

Handle<RequireContext> RequireContext::create(
    Runtime &runtime,
    Handle<Domain> domain,
    Handle<StringPrimitive> dirname) {
  auto objProto = Handle<JSObject>::vmcast(&runtime.objectPrototype);
  auto *cell = runtime.makeAFixed<RequireContext>(
      runtime,
      objProto,
      runtime.getHiddenClassForPrototype(
          *objProto, numOverlapSlots<RequireContext>()));
  auto self = JSObjectInit::initToHandle(runtime, cell);
  self->domain_.set(runtime, *domain, runtime.getHeap());
  self->dirname_.set(runtime, *dirname, runtime.getHeap());
  return self;
}

}                
}                    

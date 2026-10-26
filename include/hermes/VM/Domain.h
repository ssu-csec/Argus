/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_DOMAIN_H
#define HERMES_VM_DOMAIN_H

#include "hermes/VM/ArrayStorage.h"
#include "hermes/VM/CopyableVector.h"
#include "hermes/VM/GCCell.h"
#include "hermes/VM/JSObject.h"
#include "hermes/VM/Runtime.h"
#include "hermes/VM/StringPrimitive.h"

namespace hermes {
namespace vm {

                                                                         
                                                                      
                                                            
   
                                                                          
                                                                                
                                                                       
   
                                                                                
                                                                            
                                                                            
           
   
                                                                   
                                                                                
   
                                                                              
                                                                                
                                                                               
                                                                                
                                                                             
class Domain final : public GCCell {
  using Super = GCCell;
  friend void DomainBuildMeta(const GCCell *cell, Metadata::Builder &mb);

  static const VTable vt;

                                                                      
                                               
  enum Offsets : uint32_t {
                                                                       
                                                                               
                                                                         
                                                              
    CachedExportsOffset,

                                                   
                                                             
                                                                            
    ModuleOffset,

                                                   
                                              
    FunctionIndexOffset,

                                                                  
    CJSModuleSize,
  };

                                                                             
                                                                     
                                               
                                                                           
                                                                          
                                                                                
                        
                                                                               
                  
                                                                                
  GCPointer<ArrayStorage> cjsModules_;

                                                                                
                                                                              
                          
  CopyableVector<RuntimeModule *> cjsRuntimeModules_{};

                                              
                                                                             
                                                                       
  llvh::DenseMap<SymbolID, uint32_t> cjsModuleTable_{};

                                          
                                                                              
           
  CopyableVector<RuntimeModule *> runtimeModules_{};

                                                                             
                                                                                
                           
                                                                           
  GCPointer<NativeFunction> throwingRequire_{};

                                                                             
                                                                              
                                 
  OptValue<uint32_t> cjsEntryModuleID_;

 public:
  static constexpr CellKind getCellKind() {
    return CellKind::DomainKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::DomainKind;
  }

                                                        
  static PseudoHandle<Domain> create(Runtime &runtime);

                                                                              
  static void addRuntimeModule(
      Handle<Domain> self,
      Runtime &runtime,
      RuntimeModule *runtimeModule) {
    self->runtimeModules_.push_back(runtimeModule, runtime.getHeap());
  }

                                                                       
                                                                        
  LLVM_NODISCARD static ExecutionStatus importCJSModuleTable(
      Handle<Domain> self,
      Runtime &runtime,
      RuntimeModule *runtimeModule);

                                             
                                                            
                             
  uint32_t getCJSEntryModuleID() const {
    return *cjsEntryModuleID_;
  }

                                                                                
              
  OptValue<uint32_t> getCJSModuleOffset(SymbolID filename) const {
    assert(cjsModules_ && "CJS Modules not initialized");
    auto it = cjsModuleTable_.find(filename);
    return it != cjsModuleTable_.end() ? OptValue<uint32_t>{it->second}
                                       : llvh::None;
  }

                                                                          
                                                   
  OptValue<uint32_t> getCJSModuleOffset(Runtime &runtime, uint32_t id) const {
    assert(cjsModules_ && "CJS Modules not initialized");
    if (LLVM_UNLIKELY(
            id >= cjsModules_.getNonNull(runtime)->size() / CJSModuleSize)) {
                       
      return llvh::None;
    }
    uint32_t offset = id * CJSModuleSize;
    if (LLVM_UNLIKELY(cjsModules_.getNonNull(runtime)
                          ->at(offset + FunctionIndexOffset)
                          .isEmpty())) {
                                              
      return llvh::None;
    }
    return offset;
  }

                                                                      
  PseudoHandle<> getCachedExports(Runtime &runtime, uint32_t cjsModuleOffset)
      const {
    return createPseudoHandle(cjsModules_.getNonNull(runtime)->at(
        cjsModuleOffset + CachedExportsOffset));
  }

                                                              
  PseudoHandle<JSObject> getModule(Runtime &runtime, uint32_t cjsModuleOffset)
      const {
    return createPseudoHandle(
        dyn_vmcast<JSObject>(cjsModules_.getNonNull(runtime)->at(
            cjsModuleOffset + ModuleOffset)));
  }

                                                               
  uint32_t getFunctionIndex(Runtime &runtime, uint32_t cjsModuleOffset) const {
    return cjsModules_.getNonNull(runtime)
        ->at(cjsModuleOffset + FunctionIndexOffset)
        .getNativeUInt32();
  }

                                                               
  RuntimeModule *getRuntimeModule(Runtime &runtime, uint32_t cjsModuleOffset)
      const {
    assert(cjsModuleOffset % CJSModuleSize == 0 && "Invalid cjsModuleOffset");
    return cjsRuntimeModules_[cjsModuleOffset / CJSModuleSize];
  }

                                                          
  void setCachedExports(
      uint32_t cjsModuleOffset,
      Runtime &runtime,
      HermesValue cachedExports) {
    cjsModules_.getNonNull(runtime)->set(
        cjsModuleOffset + CachedExportsOffset,
        cachedExports,
        runtime.getHeap());
  }

                                                          
  void setModule(uint32_t cjsModuleOffset, Runtime &runtime, Handle<> module) {
    cjsModules_.getNonNull(runtime)->set(
        cjsModuleOffset + ModuleOffset,
        module.getHermesValue(),
        runtime.getHeap());
  }

                                                                           
                              
  PseudoHandle<NativeFunction> getThrowingRequire(Runtime &runtime) const;

 private:
  ~Domain() = default;

                                                                   
  static void _finalizeImpl(GCCell *cell, GC &gc);

                                                                          
  static size_t _mallocSizeImpl(GCCell *cell);

#ifdef HERMES_MEMORY_INSTRUMENTATION
                              
  static void _snapshotAddEdgesImpl(GCCell *cell, GC &gc, HeapSnapshot &snap);
  static void _snapshotAddNodesImpl(GCCell *cell, GC &gc, HeapSnapshot &snap);
#endif
};

                                                                          
                                                                            
                                                                   
                                                                               
                                                                             
                          
class RequireContext final : public JSObject {
  using Super = JSObject;

  static const ObjectVTable vt;
  friend void RequireContextBuildMeta(
      const GCCell *cell,
      Metadata::Builder &mb);
  friend void RequireContextSerialize(Serializer &, const GCCell *);

 public:
  static constexpr CellKind getCellKind() {
    return CellKind::RequireContextKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::RequireContextKind;
  }

                                                                           
  static Handle<RequireContext> create(
      Runtime &runtime,
      Handle<Domain> domain,
      Handle<StringPrimitive> dirname);

                                                  
  static Domain *getDomain(Runtime &runtime, RequireContext *self) {
    return self->domain_.get(runtime);
  }

                                                           
  static StringPrimitive *getDirname(Runtime &runtime, RequireContext *self) {
    return self->dirname_.get(runtime);
  }

  RequireContext(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz)
      : JSObject(runtime, *parent, *clazz) {}

 private:
  GCPointer<Domain> domain_;
  GCPointer<StringPrimitive> dirname_;
};

}                
}                    

#endif

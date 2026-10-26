/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_RUNTIMEMODULE_H
#define HERMES_VM_RUNTIMEMODULE_H

#include "hermes/BCGen/HBC/BytecodeDataProvider.h"
#include "hermes/Public/DebuggerTypes.h"
#include "hermes/Support/HashString.h"
#include "hermes/VM/CodeBlock.h"
#include "hermes/VM/IdentifierTable.h"

#include "hermes/VM/StringRefUtils.h"
#include "hermes/VM/WeakRoot.h"

#include "llvh/ADT/simple_ilist.h"

#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

class CodeBlock;
class Runtime;

using BigIntID = uint32_t;
using StringID = uint32_t;

namespace detail {
                                                                    
                                                                    
                       
StringID mapStringMayAllocate(RuntimeModule &module, const char *str);
}                    

                                   
union RuntimeModuleFlags {
  struct {
                                                                            
                                                                            
                                                                             
                                                                               
                          
    bool persistent : 1;

                                                                  
                               
    bool hidesEpilogue : 1;
  };
  uint8_t flags;
  RuntimeModuleFlags() : flags(0) {}
};

                                                                         
                                                                               
                                                                               
                                                                        
                                                                              
                                                    
                                                                              
                                                          
   
                                                            
                                                                               
                                                                        
   
                                                                           
                                                                       
class RuntimeModule final : public llvh::ilist_node<RuntimeModule> {
 private:
  friend StringID detail::mapStringMayAllocate(
      RuntimeModule &module,
      const char *str);

                                                 
  Runtime &runtime_;

                                                                      
               
  std::vector<RootSymbolID> stringIDMap_;

                                                                       
                                                                             
                     
                                                                              
                                      
  WeakRoot<Domain> domain_;

                                                          
  std::vector<CodeBlock *> functionMap_{};

                                                                         
                                                                          
                                                                             
                                                                             
                                                                               
                                     
  std::shared_ptr<hbc::BCProvider> bcProvider_{};

                                       
  RuntimeModuleFlags flags_{};

                                                                    
  std::string sourceURL_{};

                                                  
                                                                         
               
  facebook::hermes::debugger::ScriptID scriptID_;

                                                                             
                              
                                                                           
                                         
                                                            
  llvh::DenseMap<uint32_t, WeakRoot<HiddenClass>> objectLiteralHiddenClasses_;

                                                         
  llvh::DenseMap<uint32_t, JSObject *> templateMap_;

                                                                      
                                                                   
                           
  explicit RuntimeModule(
      Runtime &runtime,
      Handle<Domain> domain,
      RuntimeModuleFlags flags,
      llvh::StringRef sourceURL,
      facebook::hermes::debugger::ScriptID scriptID);

  CodeBlock *getCodeBlockSlowPath(unsigned index);

#ifndef HERMESVM_LEAN
                                                                             
                                              
  RuntimeModule *lazyRoot_;
#endif

 public:
  ~RuntimeModule();

                                                                      
                                  
                                                                 
                                                                        
                                                                      
                                                  
  static CallResult<RuntimeModule *> create(
      Runtime &runtime,
      Handle<Domain> domain,
      facebook::hermes::debugger::ScriptID scriptID,
      std::shared_ptr<hbc::BCProvider> &&bytecode = nullptr,
      RuntimeModuleFlags flags = {},
      llvh::StringRef sourceURL = {});

                                                                        
                                                 
                                                                 
                                                  
  static RuntimeModule *createUninitialized(
      Runtime &runtime,
      Handle<Domain> domain,
      RuntimeModuleFlags flags = {},
      facebook::hermes::debugger::ScriptID scriptID =
          facebook::hermes::debugger::kInvalidLocation);

#ifndef HERMESVM_LEAN
                                                                          
                                                                 
  static RuntimeModule *createLazyModule(
      Runtime &runtime,
      Handle<Domain> domain,
      RuntimeModule *parent,
      uint32_t functionID);

                                                                              
                                                                             
                          
  CodeBlock *getOnlyLazyCodeBlock() const {
    assert(functionMap_.size() == 1 && functionMap_[0] && "Not a lazy module?");
    return functionMap_[0];
  }

                                                                        
  SymbolID getLazyName();

                                                                  
                                                      
                                                              
  void initializeLazyMayAllocate(std::unique_ptr<hbc::BCProvider> bytecode);
#endif

                                                                             
                                                                       
                                                                        
                                                                       
                                                                            
                                                                         
  RuntimeModule *getLazyRootModule() {
#if defined(HERMESVM_LEAN)
    return this;
#else
    return lazyRoot_;
#endif
  }

                                                             
                                                                            
                                                              
  void initializeWithoutCJSModulesMayAllocate(
      std::shared_ptr<hbc::BCProvider> &&bytecode);

                                                                               
                                                   
                                                              
  LLVM_NODISCARD ExecutionStatus
  initializeMayAllocate(std::shared_ptr<hbc::BCProvider> &&bytecode);

                                                                             
                                                                                
                                                                              
                                                                              
                                     
  void prepareForDestruction();

                                                                            
                                                                          
                                                                               
                                                                    
  SymbolID getSymbolIDMustExist(StringID stringID) {
    assert(
        stringIDMap_[stringID].isValid() &&
        "Symbol must exist for this string ID");
    return stringIDMap_[stringID];
  }

                                                                              
                                                                            
                 
  SymbolID getSymbolIDFromStringIDMayAllocate(StringID stringID) {
    SymbolID id = stringIDMap_[stringID];
    if (LLVM_UNLIKELY(!id.isValid())) {
                                                
      auto entry = bcProvider_->getStringTableEntry(stringID);
      id = createSymbolFromStringIDMayAllocate(stringID, entry, llvh::None);
    }
    assert(id.isValid() && "Failed to create symbol for stringID");
    return id;
  }

                                                                          
                                                               
  StringPrimitive *getStringPrimFromStringIDMayAllocate(StringID stringID);

                                                               
                                 
  std::string getStringFromStringID(StringID stringID);

                                                       
  llvh::ArrayRef<uint8_t> getBigIntBytesFromBigIntId(BigIntID bigIntId) const;

                                                        
  llvh::ArrayRef<uint8_t> getRegExpBytecodeFromRegExpID(
      uint32_t regExpId) const;

                                                          
  uint32_t getNumCodeBlocks() const {
    return functionMap_.size();
  }

                                                             
  inline CodeBlock *getCodeBlockMayAllocate(unsigned index) {
    if (LLVM_LIKELY(functionMap_[index])) {
      return functionMap_[index];
    }
    return getCodeBlockSlowPath(index);
  }

                                                              
  bool isInitialized() const {
    return !bcProvider_->isLazy();
  }

  const hbc::BCProvider *getBytecode() const {
    return bcProvider_.get();
  }

  hbc::BCProvider *getBytecode() {
    return bcProvider_.get();
  }

  std::shared_ptr<hbc::BCProvider> getBytecodeSharedPtr() {
    return bcProvider_;
  }

                                                                          
                          
  bool hasCJSModules() const {
    return !getBytecode()->getCJSModuleTable().empty();
  }

                                                                               
                 
  bool hasCJSModulesStatic() const {
    return !getBytecode()->getCJSModuleTableStatic().empty();
  }

                                                       
  inline Handle<Domain> getDomain(Runtime &);

                                                                        
  inline Domain *getDomainUnsafe(Runtime &);

                                                                        
                                                                           
                                                                
  inline Domain *getDomainForSamplingProfiler(PointerBase &base);

                                         
  Runtime &getRuntime() {
    return runtime_;
  }

                                                       
  const std::vector<CodeBlock *> &getFunctionMap() {
    return functionMap_;
  }

                                                        
  llvh::StringRef getSourceURL() const {
    return sourceURL_;
  }

                                                         
                             
  bool hidesEpilogue() const {
    return flags_.hidesEpilogue;
  }

                                                        
  llvh::ArrayRef<uint8_t> getEpilogue() const {
    return bcProvider_->getEpilogue();
  }

  facebook::hermes::debugger::ScriptID getScriptID() const {
    return scriptID_;
  }

                                                          
  void markRoots(RootAcceptor &acceptor, bool markLongLived);

                                                                 
  void markLongLivedWeakRoots(WeakRootAcceptor &acceptor);

                                                                          
  void markDomainRef(WeakRootAcceptor &acceptor) {
    acceptor.acceptWeak(domain_);
  }

                                                                  
  bool isOwningDomainDead() const {
    return !domain_;
  }

                                                                       
                    
  size_t additionalMemorySize() const;

#ifdef HERMES_MEMORY_INSTRUMENTATION
                                                   
  void snapshotAddNodes(GC &gc, HeapSnapshot &snap) const;
  void snapshotAddEdges(GC &gc, HeapSnapshot &snap) const;
#endif

                                                                        
                                                                     
                                                                   
                                      
                                      
  llvh::Optional<Handle<HiddenClass>> findCachedLiteralHiddenClass(
      Runtime &runtime,
      unsigned keyBufferIndex,
      unsigned numLiterals) const;

                                                                           
                                              
                                                                     
                                             
  void tryCacheLiteralHiddenClass(
      Runtime &runtime,
      unsigned keyBufferIndex,
      HiddenClass *clazz);

                                                                     
                                            
  JSObject *findCachedTemplateObject(uint32_t templateObjID) {
    return templateMap_.lookup(templateObjID);
  }

                                                                               
          
                                                                           
                       
                                                                
  void cacheTemplateObject(
      uint32_t templateObjID,
      Handle<JSObject> templateObj) {
    assert(
        templateMap_.count(templateObjID) == 0 &&
        "The template object already exists.");
    templateMap_[templateObjID] = templateObj.get();
  }

 private:
                                                       
  void importStringIDMapMayAllocate();

                                                                         
                                              
  void initializeFunctionMap();

                                       
                                                                     
  LLVM_NODISCARD ExecutionStatus importCJSModuleTable();

                                                                        
                                                  
                                                             
  template <typename T>
  SymbolID mapStringMayAllocate(llvh::ArrayRef<T> str, StringID stringID) {
    return mapStringMayAllocate(str, stringID, hermes::hashString(str));
  }

                                                                        
                                                  
  template <typename T>
  SymbolID
  mapStringMayAllocate(llvh::ArrayRef<T> str, StringID stringID, uint32_t hash);

                                                                        
                                                                           
                                                                          
                                              
  SymbolID createSymbolFromStringIDMayAllocate(
      StringID stringID,
      const StringTableEntry &entry,
      OptValue<uint32_t> mhash);

                                                                      
                                                                            
                      
                                                                   
                                                             
  static uint32_t getLiteralHiddenClassCacheHashKey(
      unsigned keyBufferIndex,
      unsigned numLiterals) {
    assert(
        canGenerateLiteralHiddenClassCacheKey(keyBufferIndex, numLiterals) &&
        "<keyBufferIndex, numLiterals> tuple can't be used as cache key.");
    return ((uint32_t)keyBufferIndex << 8) | numLiterals;
  }

                                                                        
                                                 
                                                                             
                                                 
  static bool canGenerateLiteralHiddenClassCacheKey(
      uint32_t keyBufferIndex,
      unsigned numLiterals) {
    return (keyBufferIndex & 0xFF000000) == 0 && numLiterals < 256;
  }
};

using RuntimeModuleList = llvh::simple_ilist<RuntimeModule>;

}                
}                    
#pragma GCC diagnostic pop

#endif

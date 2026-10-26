/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_CODEBLOCK_H
#define HERMES_VM_CODEBLOCK_H

#include "hermes/BCGen/HBC/BytecodeDataProvider.h"
#include "hermes/BCGen/HBC/BytecodeFileFormat.h"
#include "hermes/Inst/Inst.h"
#include "hermes/Support/SourceErrorManager.h"
#include "hermes/VM/HermesValue.h"
#include "hermes/VM/IdentifierTable.h"
#include "hermes/VM/Profiler.h"
#include "hermes/VM/PropertyCache.h"
#include "hermes/VM/SerializedLiteralParser.h"
#include "llvh/ADT/DenseSet.h"
#include "llvh/ADT/Optional.h"
#include "llvh/Support/TrailingObjects.h"

#include <memory>
#include <vector>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

class RuntimeModule;
class CodeBlock;

                                                                   
class CodeBlock final
    : private llvh::TrailingObjects<CodeBlock, PropertyCacheEntry> {
  friend TrailingObjects;
                                                                              
            
  RuntimeModule *const runtimeModule_;

                                     
  hbc::RuntimeFunctionHeader functionHeader_;

                                      
  const uint8_t *bytecode_;

                                                        
  uint32_t functionID_;

#ifdef HERMES_ENABLE_DEBUGGER
                                                                     
  uint32_t numInstalledBreakpoints_ = 0;
#endif

                                       
  const uint32_t propertyCacheSize_;

                                                                              
            
  const uint32_t writePropCacheOffset_;

#ifndef HERMESVM_LEAN
                                                                        
  ExecutionStatus lazyCompileImpl(Runtime &runtime);
#endif

                                                          
                                                                                
                                                                               
  SourceErrorManager::SourceCoords getLazyFunctionLoc(bool start) const;

                                                     
  PropertyCacheEntry *propertyCache() {
    return getTrailingObjects<PropertyCacheEntry>();
  }

  PropertyCacheEntry *writePropertyCache() {
    return getTrailingObjects<PropertyCacheEntry>() + writePropCacheOffset_;
  }

  CodeBlock(
      RuntimeModule *runtimeModule,
      hbc::RuntimeFunctionHeader header,
      const uint8_t *bytecode,
      uint32_t functionID,
      uint32_t cacheSize,
      uint32_t writePropCacheOffset)
      : runtimeModule_(runtimeModule),
        functionHeader_(header),
        bytecode_(bytecode),
        functionID_(functionID),
        propertyCacheSize_(cacheSize),
        writePropCacheOffset_(writePropCacheOffset) {
    std::uninitialized_fill_n(propertyCache(), cacheSize, PropertyCacheEntry{});
  }

 public:
#if defined(HERMESVM_PROFILER_JSFUNCTION)
                                                                             
  ProfilerID profilerID{NO_PROFILER_ID};
#endif

                                                                                
                                                          
                                                                           
                                                                             
                                                              
  static CodeBlock *create(
      RuntimeModule *runtimeModule,
      hbc::RuntimeFunctionHeader header,
      const uint8_t *bytecode,
      uint32_t functionID,
      uint32_t cacheSize,
      uint32_t writePropCacheOffset) {
    auto allocSize = totalSizeToAlloc<PropertyCacheEntry>(cacheSize);
    void *mem = checkedMalloc(allocSize);
    return new (mem) CodeBlock(
        runtimeModule,
        header,
        bytecode,
        functionID,
        cacheSize,
        writePropCacheOffset);
  }

                                                                           
                                                    
  static void operator delete(void *cb) {
    free(cb);
  }

  using const_iterator = const uint8_t *;

  uint32_t getParamCount() const {
    return functionHeader_.paramCount();
  }
  uint32_t getFrameSize() const {
    return functionHeader_.frameSize();
  }
  uint32_t getEnvironmentSize() const {
    return functionHeader_.environmentSize();
  }
  uint32_t getFunctionID() const {
    return functionID_;
  }

                                                                   
                                                              
                                            
  int32_t findCatchTargetOffset(uint32_t exceptionOffset);

                                                                               
                                                                       
                                                
  uint32_t getVirtualOffset() const;

  SerializedLiteralParser getArrayBufferIter(
      uint32_t idx,
      unsigned int numLiterals) const;

  SerializedLiteralParser getObjectBufferKeyIter(
      uint32_t idx,
      unsigned int numLiterals) const;

  SerializedLiteralParser getObjectBufferValueIter(
      uint32_t idx,
      unsigned int numLiterals) const;

  RuntimeModule *getRuntimeModule() const {
    return runtimeModule_;
  }

  hbc::FunctionHeaderFlag getHeaderFlags() const {
    return functionHeader_.flags();
  }

  bool isStrictMode() const {
    return functionHeader_.flags().strictMode;
  }

  SymbolID getNameMayAllocate() const;

                                                                     
                                 
  std::string getNameString(GCBase::GCCallbacks &runtime) const;

  const_iterator begin() const {
    return bytecode_;
  }
  const_iterator end() const {
    return bytecode_ + functionHeader_.bytecodeSizeInBytes();
  }
  llvh::ArrayRef<uint8_t> getOpcodeArray() const {
    return {bytecode_, functionHeader_.bytecodeSizeInBytes()};
  }

                                                                       
  bool contains(const inst::Inst *inst) const {
    return begin() <= reinterpret_cast<const uint8_t *>(inst) &&
        reinterpret_cast<const uint8_t *>(inst) < end();
  }

  OptValue<uint32_t> getDebugSourceLocationsOffset() const;

                                                                              
                                  
  OptValue<hbc::DebugSourceLocation> getSourceLocation(
      uint32_t offset = 0) const;

                                                                            
                                                                           
  OptValue<uint32_t> getFunctionSourceID() const;

  OptValue<uint32_t> getScopeDescDataOffset() const;

  OptValue<uint32_t> getTextifiedCalleeOffset() const;

  const inst::Inst *getOffsetPtr(uint32_t offset) const {
    assert(begin() + offset < end() && "offset out of bounds");
    return reinterpret_cast<const inst::Inst *>(begin() + offset);
  }

  uint32_t getOffsetOf(const inst::Inst *inst) const {
    assert(
        reinterpret_cast<const uint8_t *>(inst) >= begin() &&
        "inst not in this codeBlock");
    uint32_t offset = reinterpret_cast<const uint8_t *>(inst) - begin();
    assert(begin() + offset < end() && "inst not in this codeBlock");
    return offset;
  }

#ifndef HERMESVM_LEAN
                                                      
  bool isLazy() const {
                                                               
    return !bytecode_;
  }

                                                                     
  ExecutionStatus lazyCompile(Runtime &runtime) {
    if (LLVM_UNLIKELY(isLazy())) {
      return lazyCompileImpl(runtime);
    }
    return ExecutionStatus::RETURNED;
  }
#else
                                                      
  bool isLazy() const {
    return false;
  }
  ExecutionStatus lazyCompile(Runtime &) {
    return ExecutionStatus::RETURNED;
  }
#endif

                                                            
  SourceErrorManager::SourceCoords getLazyFunctionStartLoc() const {
    return getLazyFunctionLoc(true);
  }

                                                          
  SourceErrorManager::SourceCoords getLazyFunctionEndLoc() const {
    return getLazyFunctionLoc(false);
  }

  inline PropertyCacheEntry *getReadCacheEntry(uint8_t idx) {
    assert(idx < writePropCacheOffset_ && "idx out of ReadCache bound");
    return &propertyCache()[idx];
  }

  inline PropertyCacheEntry *getWriteCacheEntry(uint8_t idx) {
    assert(
        writePropCacheOffset_ + idx < propertyCacheSize_ &&
        "idx out of WriteCache bound");
    return &propertyCache()[writePropCacheOffset_ + idx];
  }

                                                            
  void markCachedHiddenClasses(Runtime &runtime, WeakRootAcceptor &acceptor);

  static CodeBlock *createCodeBlock(
      RuntimeModule *runtimeModule,
      hbc::RuntimeFunctionHeader header,
      const uint8_t *bytecode,
      uint32_t functionID);

                                                                       
                
  size_t additionalMemorySize() const {
    return propertyCacheSize_ * sizeof(PropertyCacheEntry);
  }

#ifdef HERMES_ENABLE_DEBUGGER
                                                                 
                            
                                                                 
                                                                 
  void installBreakpointAtOffset(uint32_t offset);

                                                                
                                                         
                                                        
                                                           
                                                                 
  void uninstallBreakpointAtOffset(uint32_t offset, uint8_t opCode);

                                                                     
  uint32_t getNumInstalledBreakpoints() const {
    return numInstalledBreakpoints_;
  }
#endif
};

}                
}                    
#pragma GCC diagnostic pop

#endif                         

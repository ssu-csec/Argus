/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_HBC_BYTECODEPROVIDERFROMSRC_H
#define HERMES_BCGEN_HBC_BYTECODEPROVIDERFROMSRC_H

#include "hermes/BCGen/HBC/Bytecode.h"
#include "hermes/BCGen/HBC/BytecodeDataProvider.h"

#include "llvh/ADT/Optional.h"

namespace hermes {
namespace hbc {

                                                                           
struct CompileFlags {
  bool debug{false};
  bool lazy{false};
  bool enableBlockScoping{false};

                                                                       
                                                                              
                                                                          
                                                                              
                                                                    
  unsigned preemptiveFileCompilationThreshold{1 << 16};
                                                                           
  unsigned preemptiveFunctionCompilationThreshold{160};

  bool strict{false};
                                                                              
                                                                                
                                                                                
                  
  llvh::Optional<bool> staticBuiltins;
  bool verifyIR{false};
                                                                              
                                                                        
                                                                              
                            
  bool emitAsyncBreakCheck{false};
                                                                             
                                             
  bool includeLibHermes{true};
                                                   
  bool instrumentIR{false};
                        
  bool enableGenerator{true};
                                
  bool enableES6Classes{false};
                                                                               
                                                              
  OutputFormatKind format{Execute};
};

#ifndef HERMESVM_LEAN
                                                                        
                                                                        
                                                                    
                                                                     
                                                                 
class BCProviderFromSrc final : public BCProviderBase {
                                                         
  std::unique_ptr<hbc::BytecodeModule> module_;

                                                      
  bool singleFunction_;

                               
  SHA1 sourceHash_{SHA1{}};

  explicit BCProviderFromSrc(std::unique_ptr<hbc::BytecodeModule> module);

                                                                  
                                                 
  void createDebugInfo() override {}

                                                                       
                                                          
                                                                             
                                                                            
                                                                     
                                                                             
                                    
                                                               
                                          
                                                                   
                                                           
                                                                        
                                                                             
                                                                          
                                                                        
                                                          
                                                                              
                                                                         
                                                                                
     
                                                                                
                                                                              
  static std::pair<std::unique_ptr<BCProviderFromSrc>, std::string>
  createBCProviderFromSrcImpl(
      std::unique_ptr<Buffer> buffer,
      llvh::StringRef sourceURL,
      std::unique_ptr<SourceMap> sourceMap,
      const CompileFlags &compileFlags,
      const ScopeChain &scopeChain,
      SourceErrorManager::DiagHandlerTy diagHandler,
      void *diagContext,
      const std::function<void(Module &)> &runOptimizationPasses,
      const BytecodeGenerationOptions &defaultBytecodeGenerationOptions);

 public:
  static std::unique_ptr<BCProviderFromSrc> createBCProviderFromSrc(
      std::unique_ptr<hbc::BytecodeModule> module) {
    return std::unique_ptr<BCProviderFromSrc>(
        new BCProviderFromSrc(std::move(module)));
  }

                                                                    
                                                                             
                                                                            
                                                                     
                                                                             
                                    
                                          
     
                                                                                
                  
  static std::pair<std::unique_ptr<BCProviderFromSrc>, std::string>
  createBCProviderFromSrc(
      std::unique_ptr<Buffer> buffer,
      llvh::StringRef sourceURL,
      const CompileFlags &compileFlags);

                                                                    
                                                                             
                                                                            
                                                                     
                                                                             
                                    
                                                               
                                          
     
                                                                                
                  
  static std::pair<std::unique_ptr<BCProviderFromSrc>, std::string>
  createBCProviderFromSrc(
      std::unique_ptr<Buffer> buffer,
      llvh::StringRef sourceURL,
      std::unique_ptr<SourceMap> sourceMap,
      const CompileFlags &compileFlags);

                                                                    
                                                                             
                                                                            
                                                                     
                                                                             
                                    
                                                               
                                          
                                                                   
                                                                    
                                                                        
     
                                                                                
                                                                              
  static std::pair<std::unique_ptr<BCProviderFromSrc>, std::string>
  createBCProviderFromSrc(
      std::unique_ptr<Buffer> buffer,
      llvh::StringRef sourceURL,
      std::unique_ptr<SourceMap> sourceMap,
      const CompileFlags &compileFlags,
      const ScopeChain &scopeChain,
      SourceErrorManager::DiagHandlerTy diagHandler = nullptr,
      void *diagContext = nullptr,
      const std::function<void(Module &)> &runOptimizationPasses = {},
      const BytecodeGenerationOptions &defaultBytecodeGenerationOptions =
          BytecodeGenerationOptions::defaults());

  RuntimeFunctionHeader getFunctionHeader(uint32_t functionID) const override {
    return RuntimeFunctionHeader(&module_->getFunction(functionID).getHeader());
  }

  StringTableEntry getStringTableEntry(uint32_t index) const override {
    assert(index < stringCount_ && "invalid string table index");
    return module_->getStringTable()[index];
  }

  const uint8_t *getBytecode(uint32_t functionID) const override {
    return module_->getFunction(functionID).getOpcodeArray().data();
  }

  llvh::ArrayRef<hbc::HBCExceptionHandlerInfo> getExceptionTable(
      uint32_t functionID) const override {
    return module_->getFunction(functionID).getExceptionHandlers();
  }

  const hbc::DebugOffsets *getDebugOffsets(uint32_t functionID) const override {
    return module_->getFunction(functionID).getDebugOffsets();
  }

  bool isFunctionLazy(uint32_t functionID) const override {
    return module_->getFunction(functionID).isLazy();
  }

  bool isLazy() const override {
    return false;
  }

  bool isSingleFunction() const {
    return singleFunction_;
  }

  hbc::BytecodeModule *getBytecodeModule() {
    return module_.get();
  }

  SHA1 getSourceHash() const override {
    return sourceHash_;
  };

  void setSourceHash(const SHA1 &hash) {
    sourceHash_ = hash;
  };
};

                                                                              
                                                                       
                                       
class BCProviderLazy final : public BCProviderBase {
                                      
  hbc::BytecodeFunction *bytecodeFunction_;

  explicit BCProviderLazy(hbc::BytecodeFunction *bytecodeFunction);

                                                                  
  void createDebugInfo() override {
    hermes_fatal("Accessing debug info from a lazy module");
  }

 public:
  static std::unique_ptr<BCProviderBase> createBCProviderLazy(
      hbc::BytecodeFunction *bytecodeFunction) {
    return std::unique_ptr<BCProviderBase>(
        new BCProviderLazy(bytecodeFunction));
  }

  RuntimeFunctionHeader getFunctionHeader(uint32_t) const override {
    return RuntimeFunctionHeader(&bytecodeFunction_->getHeader());
  }

  StringTableEntry getStringTableEntry(uint32_t index) const override {
    hermes_fatal("Accessing string table from a lazy module");
  }

  const uint8_t *getBytecode(uint32_t) const override {
    hermes_fatal("Accessing bytecode from a lazy module");
  }

  llvh::ArrayRef<hbc::HBCExceptionHandlerInfo> getExceptionTable(
      uint32_t) const override {
    hermes_fatal("Accessing exception info from a lazy module");
  }

  const hbc::DebugOffsets *getDebugOffsets(uint32_t) const override {
    hermes_fatal("Accessing debug offsets from a lazy module");
  }

  bool isFunctionLazy(uint32_t) const override {
    return true;
  }

  bool isLazy() const override {
    return true;
  }

                                                  
  hbc::BytecodeFunction *getBytecodeFunction() {
    return bytecodeFunction_;
  }
};
#endif                 
}                 
}                    

#endif                                              

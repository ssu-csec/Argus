/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_AST_CONTEXT_H
#define HERMES_AST_CONTEXT_H

#include "hermes/Parser/PreParser.h"
#include "hermes/Regex/RegexSerialization.h"
#include "hermes/Support/Allocator.h"
#include "hermes/Support/SourceErrorManager.h"
#include "hermes/Support/StringTable.h"

#include "llvh/ADT/DenseSet.h"
#include "llvh/ADT/StringRef.h"

namespace hermes {

namespace hbc {
class BackendContext;
}

#ifdef HERMES_RUN_WASM
class EmitWasmIntrinsicsContext;
#endif                   

struct CodeGenerationSettings_DumpSettings {
  bool all{false};
  llvh::SmallDenseSet<llvh::StringRef> passes;
  llvh::SmallDenseSet<llvh::StringRef> functions;
};

struct CodeGenerationSettings {
  using DumpSettings = CodeGenerationSettings_DumpSettings;

                                        
  bool enableTDZ{false};
                                                                    
                                                                   
                                                  
  bool unlimitedRegisters{true};
                                                      
  bool dumpOperandRegisters{false};
                                                    
  bool dumpSourceLocation{false};
                                                    
  bool dumpSourceLevelScope{false};
                                                      
  bool dumpTextifiedCallee{false};
                                                          
  bool dumpUseList{false};
                                                                     
  bool instrumentIR{false};
                                                                           
  bool generateNameForUnnamedFunctions{false};
                                       
  bool enableBlockScoping{false};

                                                                                
                 
  DumpSettings dumpBefore;

                                                                               
                 
  DumpSettings dumpAfter;

                                                                               
                 
  llvh::SmallDenseSet<llvh::StringRef> functionsToDump;
};

struct OptimizationSettings {
                                                                          
                  
                                                          
                                                
  bool aggressiveNonStrictModeOptimizations{true};

                                       
  bool inlining{true};

                                                          
  bool reusePropCache{true};

                                                                          
                         
  bool staticBuiltins{false};

                                                                  
  bool staticRequire{false};

                                                                
  bool useUnsafeIntrinsics{false};
};

enum class DebugInfoSetting {
                                                                             
                                        
  THROWING,

                                                                            
                   
  SOURCE_MAP,

                                                                            
                                                              
  ALL,
};

enum class ParseFlowSetting {
                                        
  NONE,

                                 
  ALL,

                                                                              
                                                                               
                 
     
                                                                          
                                                                               
                                                    
  UNAMBIGUOUS,
};

                                                                                
                                                                              
                                                                               
                                                                               
   
                                                                            
                                                                  
enum class SourceVisibility {
                                                                 
                                 
  Default,

                                                                          
  ShowSource,

                                                                          
                          
  HideSource,

                                                                               
                                                                          
  Sensitive,
};

                                        
class Context {
 public:
  using Allocator = hermes::BumpPtrAllocator;

                                                                
                                                                              
             
  using ResolutionTableEntry = llvh::DenseMap<llvh::StringRef, llvh::StringRef>;

                                                                              
                                                                              
             
  using ResolutionTable = llvh::DenseMap<llvh::StringRef, ResolutionTableEntry>;

 private:
                                                                             
                                            
  Allocator allocator_{};

                                                                             
                                                                          
  Allocator identifierAllocator_{};

                                                                    
  std::unique_ptr<parser::PreParsedData> preParsed_{};

                              
  StringTable stringTable_{identifierAllocator_};

  std::map<std::pair<UniqueString *, UniqueString *>, CompiledRegExp>
      compiledRegExps_{};

                                                                               
                       
  std::unique_ptr<SourceErrorManager> ownSm_;

                                                    
  SourceErrorManager &sm_;

                                                               
  bool strictMode_{false};

                             
  bool enableEval_{true};

                                                                          
                 
  bool lazyCompilation_{false};

                                                                                
            
  unsigned preemptiveFunctionCompilationThreshold_{0};

                                                                            
            
  unsigned preemptiveFileCompilationThreshold_{0};

                                                                               
  bool allowReturnOutsideFunction_{false};

                                                
  bool generatorEnabled_{true};

                                                                      
                                         
  bool useCJSModules_{false};

                                                         
  bool parseJSX_{false};

                                                                          
  bool parseFlowComponentSyntax_{false};

                                                                  
                             
  bool parseFlowMatch_{false};

                                        
  ParseFlowSetting parseFlow_{ParseFlowSetting::NONE};

                                         
  bool parseTS_{false};

                                                     
  bool convertES6Classes_{false};

                                                                        
  const std::unique_ptr<ResolutionTable> resolutionTable_;

                                                                        
                                         
  const std::vector<uint32_t> segments_;

                                                                
                                 
  DebugInfoSetting debugInfoSetting_{DebugInfoSetting::THROWING};

                                                           
  bool emitAsyncBreakCheck_{false};

  CodeGenerationSettings codeGenerationSettings_;

  OptimizationSettings optimizationSettings_;

                                                                                
                        
  std::shared_ptr<hbc::BackendContext> hbcBackendContext_{};

#ifdef HERMES_RUN_WASM
  std::shared_ptr<EmitWasmIntrinsicsContext> wasmIntrinsicsContext_{};
#endif                   

 public:
  explicit Context(
      SourceErrorManager &sm,
      CodeGenerationSettings codeGenOpts = CodeGenerationSettings(),
      OptimizationSettings optimizationOpts = OptimizationSettings(),
      std::unique_ptr<ResolutionTable> resolutionTable = nullptr,
      std::vector<uint32_t> segments = {})
      : sm_(sm),
        resolutionTable_(std::move(resolutionTable)),
        segments_(std::move(segments)),
        codeGenerationSettings_(std::move(codeGenOpts)),
        optimizationSettings_(std::move(optimizationOpts)) {}

  explicit Context(
      CodeGenerationSettings codeGenOpts = CodeGenerationSettings(),
      OptimizationSettings optimizationOpts = OptimizationSettings(),
      std::unique_ptr<ResolutionTable> resolutionTable = nullptr,
      std::vector<uint32_t> segments = {})
      : ownSm_(new SourceErrorManager()),
        sm_(*ownSm_),
        resolutionTable_(std::move(resolutionTable)),
        segments_(std::move(segments)),
        codeGenerationSettings_(std::move(codeGenOpts)),
        optimizationSettings_(std::move(optimizationOpts)) {}

  Context(const Context &) = delete;
  void operator=(const Context &) = delete;

  Allocator &getAllocator() {
    return allocator_;
  }

  StringTable &getStringTable() {
    return stringTable_;
  }

  void addCompiledRegExp(
      UniqueString *pattern,
      UniqueString *flags,
      CompiledRegExp &&compiled) {
    compiledRegExps_.emplace(
        std::make_pair(pattern, flags), std::move(compiled));
  }

  CompiledRegExp &getCompiledRegExp(
      UniqueString *pattern,
      UniqueString *flags) {
    auto it = compiledRegExps_.find(std::make_pair(pattern, flags));
    assert(it != compiledRegExps_.end() && "Regex hasn't been compiled");
    return it->second;
  }

  parser::PreParsedBufferInfo *getPreParsedBufferInfo(uint32_t bufferId) {
    if (!preParsed_)
      preParsed_ = std::make_unique<parser::PreParsedData>();
    return preParsed_->getBufferInfo(bufferId);
  }

  SourceErrorManager &getSourceErrorManager() {
    return sm_;
  }

  const SourceErrorManager &getSourceErrorManager() const {
    return sm_;
  }

                                                                               
  const std::vector<uint32_t> &getSegments() const {
    return segments_;
  }

                                                                               
  const ResolutionTable *getResolutionTable() const {
    return resolutionTable_.get();
  }

                                                                             
                                
  Identifier getIdentifier(llvh::StringRef str) {
    return stringTable_.getIdentifier(str);
  }

                                                          
  llvh::StringRef toString(Identifier iden) {
    return iden.str();
  }

  void setStrictMode(bool strictMode) {
    strictMode_ = strictMode;
  }
  bool isStrictMode() const {
    return strictMode_;
  }

  bool getEnableEval() const {
    return enableEval_;
  }
  void setEnableEval(bool enableEval) {
    enableEval_ = enableEval;
  }

  void setDebugInfoSetting(DebugInfoSetting debugInfoSetting) {
    debugInfoSetting_ = debugInfoSetting;
  }
  DebugInfoSetting getDebugInfoSetting() const {
    return debugInfoSetting_;
  }

  void setEmitAsyncBreakCheck(bool check) {
    emitAsyncBreakCheck_ = check;
  }
  bool getEmitAsyncBreakCheck() const {
    return emitAsyncBreakCheck_;
  }

                                                                        
  void setUseCJSModules(bool useCJSModules) {}
  bool getUseCJSModules() const {
    return false;
  }
                                                                               
                                                                               
                                                        
  void setTransformCJSModules(bool useCJSModules) {
    useCJSModules_ = useCJSModules;
  }
  bool getTransformCJSModules() const {
    return useCJSModules_;
  }

  void setParseJSX(bool parseJSX) {
    parseJSX_ = parseJSX;
  }
  bool getParseJSX() const {
    return parseJSX_;
  }

  void setParseFlow(ParseFlowSetting parseFlow) {
    parseFlow_ = parseFlow;
  }
  bool getParseFlow() const {
    return parseFlow_ != ParseFlowSetting::NONE;
  }
  bool getParseFlowAmbiguous() const {
    return parseFlow_ == ParseFlowSetting::ALL;
  }

  void setParseFlowComponentSyntax(bool parseFlowComponentSyntax) {
    parseFlowComponentSyntax_ = parseFlowComponentSyntax;
  }
  bool getParseFlowComponentSyntax() const {
    return parseFlowComponentSyntax_;
  }

  void setParseFlowMatch(bool parseFlowMatch) {
    parseFlowMatch_ = parseFlowMatch;
  }
  bool getParseFlowMatch() const {
    return parseFlowMatch_;
  }

  void setParseTS(bool parseTS) {
    parseTS_ = parseTS;
  }
  bool getParseTS() const {
    return parseTS_;
  }

  void setConvertES6Classes(bool convertES6Classes) {
    convertES6Classes_ = convertES6Classes;
  }

  bool getConvertES6Classes() const {
#ifndef HERMES_FACEBOOK_BUILD
    return convertES6Classes_;
#else
    return false;
#endif
  }

                                                        
  bool getParseTypes() const {
    return getParseFlow() || getParseTS();
  }

  bool isLazyCompilation() const {
    return lazyCompilation_;
  }

  void setLazyCompilation(bool lazyCompilation) {
    lazyCompilation_ = lazyCompilation;
  }

  unsigned getPreemptiveFunctionCompilationThreshold() {
    return preemptiveFunctionCompilationThreshold_;
  }

  void setPreemptiveFunctionCompilationThreshold(unsigned byteCount) {
    preemptiveFunctionCompilationThreshold_ = byteCount;
  };

  unsigned getPreemptiveFileCompilationThreshold() {
    return preemptiveFileCompilationThreshold_;
  }

  void setPreemptiveFileCompilationThreshold(unsigned byteCount) {
    preemptiveFileCompilationThreshold_ = byteCount;
  };

  bool allowReturnOutsideFunction() const {
    return allowReturnOutsideFunction_;
  }

  void setAllowReturnOutsideFunction(bool allowReturnOutsideFunction) {
    allowReturnOutsideFunction_ = allowReturnOutsideFunction;
  }

  bool isGeneratorEnabled() const {
    return generatorEnabled_;
  }

  void setGeneratorEnabled(bool v) {
    generatorEnabled_ = v;
  }

  void setStaticBuiltinOptimization(bool staticBuiltins) {
    optimizationSettings_.staticBuiltins = staticBuiltins;
  }

  bool getStaticBuiltinOptimization() const {
    return optimizationSettings_.staticBuiltins;
  }

  bool getUseUnsafeIntrinsics() const {
    return optimizationSettings_.useUnsafeIntrinsics;
  }

  const CodeGenerationSettings &getCodeGenerationSettings() const {
    return codeGenerationSettings_;
  }

  const OptimizationSettings &getOptimizationSettings() const {
    return optimizationSettings_;
  }

                                                                      
                                             
  template <typename T>
  T *allocateNode(size_t num = 1) {
    return allocator_.template Allocate<T>(num);
  }
  void *allocateNode(size_t size, size_t alignment) {
    return allocator_.Allocate(size, alignment);
  }

  hbc::BackendContext *getHBCBackendContext() {
    return hbcBackendContext_.get();
  }

  void setHBCBackendContext(
      std::shared_ptr<hbc::BackendContext> hbcBackendContext) {
    hbcBackendContext_ = std::move(hbcBackendContext);
  }

#ifdef HERMES_RUN_WASM
  EmitWasmIntrinsicsContext *getWasmIntrinsicsContext() {
    return wasmIntrinsicsContext_.get();
  }

  void setWasmIntrinsicsContext(
      std::shared_ptr<EmitWasmIntrinsicsContext> wasmIntrinsicsContext) {
    wasmIntrinsicsContext_ = std::move(wasmIntrinsicsContext);
  }
#endif                   
};

}                    

#endif                        

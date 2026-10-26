/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_DEBUGGER_DEBUGGER_H
#define HERMES_VM_DEBUGGER_DEBUGGER_H

#ifdef HERMES_ENABLE_DEBUGGER

#include "hermes/BCGen/HBC/BytecodeInstructionGenerator.h"
#include "hermes/BCGen/HBC/DebugInfo.h"
#include "hermes/Inst/Inst.h"
#include "hermes/Public/DebuggerTypes.h"
#include "hermes/Support/OptValue.h"
#include "hermes/VM/Debugger/DebugCommand.h"
#include "hermes/VM/HermesValue.h"
#include "hermes/VM/InterpreterState.h"
#include "hermes/VM/RuntimeModule.h"
#include "llvh/ADT/DenseSet.h"
#include "llvh/ADT/MapVector.h"

#include <atomic>
#include <cstdint>
#include <string>

namespace hermes {
namespace vm {
class HermesValue;
class CodeBlock;
class Runtime;
}                
}                    

namespace hermes {
namespace vm {

                                                                        
                                                                     
class Debugger {
 public:
  struct EvalResultMetadata;

  using DidPauseCallback = std::function<DebugCommand(
      InterpreterState state,
      ::facebook::hermes::debugger::PauseReason pauseReason,
      HermesValue evalResult,
      const EvalResultMetadata &evalResultMetadata,
      ::facebook::hermes::debugger::BreakpointID)>;

  using BreakpointResolvedCallback =
      std::function<void(facebook::hermes::debugger::BreakpointID)>;

 private:
  friend DebugCommand;

  using PauseOnThrowMode = ::facebook::hermes::debugger::PauseOnThrowMode;
  using BreakpointID = ::facebook::hermes::debugger::BreakpointID;
  using BreakpointInfo = ::facebook::hermes::debugger::BreakpointInfo;
  using CallFrameInfo = ::facebook::hermes::debugger::CallFrameInfo;
  using ExceptionDetails = ::facebook::hermes::debugger::ExceptionDetails;
  using PauseReason = ::facebook::hermes::debugger::PauseReason;
  using SourceLocation = ::facebook::hermes::debugger::SourceLocation;
  using StackTrace = ::facebook::hermes::debugger::StackTrace;
  using StepMode = ::facebook::hermes::debugger::StepMode;
  using String = ::facebook::hermes::debugger::String;
  using LexicalInfo = ::facebook::hermes::debugger::LexicalInfo;
  using ScriptID = ::facebook::hermes::debugger::ScriptID;
  using AsyncPauseKind = ::facebook::hermes::debugger::AsyncPauseKind;

  Runtime &runtime_;

                               
  DidPauseCallback didPauseCallback_;

                                              
  BreakpointResolvedCallback breakpointResolvedCallback_;

                         
  struct Breakpoint {
    CodeBlock *codeBlock;
    uint32_t offset;

                                                                        
                                                        
    bool enabled;

                                                         
                                                                              
    std::string condition{};

                                             
    SourceLocation requestedLocation;
                                            
                                                           
    llvh::Optional<SourceLocation> resolvedLocation{llvh::None};

    bool isResolved() const {
      return resolvedLocation.hasValue();
    }
  };

                                            
                                                            
                                                    
  llvh::MapVector<BreakpointID, Breakpoint> userBreakpoints_{};
  BreakpointID nextBreakpointId_{1};

                                                               
                                                             
  std::vector<Breakpoint> tempBreakpoints_{};

                                                                                
                                                                           
               
  std::vector<Breakpoint> restorationBreakpoints_{};

                                   
  struct BreakpointLocation {
                                 
    hbc::opcode_atom_t opCode;

                                                   
                                                          
                               
    OptValue<BreakpointID> user{llvh::None};

                                                            
    bool onLoad{false};
                                                        
    bool hasStepBreakpoint{false};
                                                               
    bool hasRestorationBreakpoint{false};

                                                                           
                                                
                                                               
                                                         
                                                       
                                                                       
                                                                    
                                                              
                                                  
    llvh::DenseSet<uint32_t> callStackDepths{};

    BreakpointLocation(hbc::opcode_atom_t opCode) : opCode(opCode) {}

                                                                 
    uint32_t count() const {
      return callStackDepths.size() + (user ? 1 : 0) + (onLoad ? 1 : 0);
    }
  };

  llvh::DenseMap<const inst::Inst *, BreakpointLocation> breakpointLocations_{};

                                                       
  bool isDebugging_{false};

                                                                           
                                  
                                                                
  OptValue<StepMode> curStepMode_{llvh::None};

                                                
                                                               
  bool pauseOnAllCodeBlocks_{false};

                                                                        
                                                                             
                                                                                
                                                                       
                                                                        
                                                                            
                                                               
                                                                       
                                 
  bool pauseOnAllCodeBlocksToRestoreBreakpoint_{false};

                                                 
                                                                               
                                    
  std::pair<CodeBlock *, uint32_t> breakpointToRestore_{nullptr, 0};

                                                               
  PauseOnThrowMode pauseOnThrowMode_{PauseOnThrowMode::None};

                                                                   
                                                                          
                                                                          
                                                                      
                                                                               
                                                                     
                                                                             
                                                                               
  bool isUnwindingException_{false};

                                                                            
                       
  bool pauseOnScriptLoad_{false};

                                                                           
                                                     
  InterpreterState preStepState_{};

                                                   
                                                                            
  std::atomic<bool> isDebuggerAttached_{false};

 public:
  explicit Debugger(Runtime &runtime) : runtime_(runtime) {}

                                                                              
                                                                              
                                                                           
                               
  enum class RunReason {
                                              
    Opcode,

                                         
    Exception,

                                                                            
                                                     
    AsyncBreakExplicit,

                                                                      
                  
                                                         
    AsyncBreakImplicit,
  };

                                                                               
                         
  struct EvalResultMetadata {
    bool isException = false;
    ExceptionDetails exceptionDetails;
  };

                                                       
                                                                            
                                               
                                                
                                                                              
                             
                                                                                
                                                                          
                                                         
  ExecutionStatus runDebugger(RunReason runReason, InterpreterState &state);

  bool isDebugging() const {
    return isDebugging_;
  }

                                                                                
                              
                                      
  StackTrace getStackTrace() const;

  llvh::Optional<const BreakpointLocation> getBreakpointLocation(
      const inst::Inst *ip) const {
    auto it = breakpointLocations_.find(ip);
    if (it == breakpointLocations_.end()) {
      return llvh::None;
    }
    return {it->second};
  }
  llvh::Optional<const BreakpointLocation> getBreakpointLocation(
      CodeBlock *codeBlock,
      uint32_t offset) const;

  void setDidPauseCallback(DidPauseCallback callback) {
    didPauseCallback_ = std::move(callback);
  }

  void setBreakpointResolvedCallback(BreakpointResolvedCallback callback) {
    breakpointResolvedCallback_ = std::move(callback);
  }

  void setShouldPauseOnScriptLoad(bool flag) {
    pauseOnScriptLoad_ = flag;
  }

  bool getShouldPauseOnScriptLoad() const {
    return pauseOnScriptLoad_;
  }

  void setPauseOnThrowMode(PauseOnThrowMode mode) {
    pauseOnThrowMode_ = mode;
  }

  PauseOnThrowMode getPauseOnThrowMode() const {
    return pauseOnThrowMode_;
  }

                                                                                
                                
  void setIsDebuggerAttached(bool isAttached) {
    isDebuggerAttached_ = isAttached;
  }

                                                                                
                                
  bool getIsDebuggerAttached() const {
    return isDebuggerAttached_;
  }

                                                                     
                                                                         
                                     
  void finishedUnwindingException() {
    isUnwindingException_ = false;
  }

                                                                             
              
  void triggerAsyncPause(AsyncPauseKind kind);

                                                                 
                                                    
                                                                          
              
  BreakpointID createBreakpoint(const SourceLocation &loc);

                                         
                                                          
                                                                            
  void setBreakpointCondition(BreakpointID id, std::string condition);

                                   
  void deleteBreakpoint(BreakpointID id);

                              
  void deleteAllBreakpoints();

                                            
                                                 
                                                     
  void setBreakpointEnabled(BreakpointID id, bool enable);

                                                              
                                                                
                         
  BreakpointInfo getBreakpointInfo(BreakpointID id) const {
    auto it = userBreakpoints_.find(id);
    if (it == userBreakpoints_.end()) {
                       
      BreakpointInfo result{};
      result.id = ::facebook::hermes::debugger::kInvalidBreakpoint;
      return result;
    }

    const auto &breakpoint = it->second;
    BreakpointInfo result{};
    result.id = id;
    result.enabled = breakpoint.enabled;
    result.resolved = breakpoint.isResolved();
    result.requestedLocation = breakpoint.requestedLocation;
    if (breakpoint.isResolved()) {
      result.resolvedLocation = *breakpoint.resolvedLocation;
    }
    return result;
  }

                                                  
  std::vector<BreakpointID> getBreakpoints() const {
    std::vector<BreakpointID> result{};
    result.reserve(userBreakpoints_.size());
    for (const auto &it : userBreakpoints_) {
      result.push_back(it.first);
    }
    return result;
  }

                                                                  
  LexicalInfo getLexicalInfoInFrame(uint32_t frame) const;

                                                                              
                                                                              
                                                                   
  HermesValue getVariableInFrame(
      uint32_t frame,
      uint32_t scopeDepth,
      uint32_t variableIndex,
      std::string *outName = nullptr) const;

                                                                    
                                           
  HermesValue getThisValue(uint32_t frame) const;

                                                                               
                                                               
  void willExecuteModule(RuntimeModule *module, CodeBlock *codeBlock);

                                                                          
                                                               
  void willUnloadModule(RuntimeModule *module);

                                                                               
                   
                                                                       
  void willEnterCodeBlock(CodeBlock *codeBlock) {
    if (LLVM_UNLIKELY(pauseOnAllCodeBlocks_)) {
      setEntryBreakpointForCodeBlock(codeBlock);
    }
  }

                                         
                                                                          
                                                                         
  void resolveBreakpoints(CodeBlock *codeBlock);

                                                                             
  String getSourceMappingUrl(ScriptID scriptId) const;

                                                                        
  std::vector<SourceLocation> getLoadedScripts() const;

                                                           
                                                                             
                                          
  llvh::Optional<std::pair<InterpreterState, uint32_t>> findCatchTarget(
      const InterpreterState &state) const;

                                                                             
                                                   
  ScriptID resolveScriptId(RuntimeModule *runtimeModule, uint32_t filenameId)
      const;

                                                                              
                                                                
  inst::OpCode getRealOpCode(CodeBlock *block, uint32_t offset) const;

                                                                               
                                                                               
                                                                              
                                                                              
                                                                               
                                                                           
                                                                            
                                                                            
                                                                       
                                                                                
                                                                    
                                     
  ExecutionStatus processInstUnderDebuggerOpCode(InterpreterState &state);

 private:
                                        
  ExecutionStatus debuggerLoop(
      InterpreterState &state,
      PauseReason pauseReason,
      BreakpointID breakpoint);

                                                                      
                                                           
                                                                        
                                                                
                                                                 
  BreakpointLocation &installBreakpoint(CodeBlock *codeBlock, uint32_t offset);

                                                                            
                                                                               
                                                                    
  void uninstallBreakpoint(
      CodeBlock *codeBlock,
      uint32_t offset,
      hbc::opcode_atom_t opCode);

                                                         
                                                                
                                                                        
                     
                                      
  void
  setUserBreakpoint(CodeBlock *codeBlock, uint32_t offset, BreakpointID id);

                                                                            
                                                                                
                                                                                
                                                                                
                     
                                             
                                                                 
                                                                      
                                                                      
                                                       
                                                                           
                             
  void doSetNonUserBreakpoint(
      CodeBlock *codeBlock,
      uint32_t offset,
      uint32_t callStackDepth,
      bool isStepBreakpoint);

                                                             
  void setStepBreakpoint(
      CodeBlock *codeBlock,
      uint32_t offset,
      uint32_t callStackDepth);

                                                             
                                                                
                                                                        
                     
                                             
  void setOnLoadBreakpoint(CodeBlock *codeBlock, uint32_t offset);

                                          
                                                                         
  void unsetUserBreakpoint(const Breakpoint &breakpoint);

                                                            
                                                             
                                   
                                                          
                                                                         
  void setEntryBreakpointForCodeBlock(CodeBlock *codeBlock);

                                                                       
                                                                    
                                                                   
                                                                        
                                     
  void breakpointCaller(bool forRestorationBreakpoint);

                                                                           
                                                
  void breakpointExceptionHandler(const InterpreterState &state);

                                                                               
                                                                               
                                                
                                                                            
                              
  void doClearNonUserBreakpoints(bool isStepBreakpoint);

                                                                   
  void clearTempBreakpoints();

                                                                
  void setRestorationBreakpoint(
      CodeBlock *codeBlock,
      uint32_t offset,
      uint32_t callStackDepth);

                                                                  
                                                                         
  bool restoreBreakpointIfAny();

                                                               
  void clearRestorationBreakpoints();

                                 
                                                                          
                       
                                                                                
  ExecutionStatus stepInstruction(InterpreterState &state);

                                                                              
                                                                       
                                   
                                        
  HermesValue evalInFrame(
      const EvalArgs &args,
      const std::string &src,
      const InterpreterState &state,
      EvalResultMetadata *outMetadata);

                                                                            
                                                            
  HermesValue getExceptionAsEvalResult(EvalResultMetadata *outMetadata);

                                              
                                                                           
                                                                             
                                      
                                                                             
                                                 
                                                                   
  DebugCommand getNextCommand(
      InterpreterState state,
      PauseReason pauseReason,
      HermesValue evalResult,
      const EvalResultMetadata &evalMetadata,
      BreakpointID breakpoint) {
                                                                             
                                      
    if (didPauseCallback_)
      return didPauseCallback_(
          state, pauseReason, evalResult, evalMetadata, breakpoint);

    return DebugCommand::makeContinue();
  }

                                                                              
                
                                                                     
                              
  inline bool sameStatementDifferentInstruction(
      const InterpreterState &a,
      const InterpreterState &b) const {
    auto aLoc = getLocationForState(a);
    auto bLoc = getLocationForState(b);

                                                                   
    return a.codeBlock == b.codeBlock && aLoc->statement == bLoc->statement &&
        a.offset != b.offset;
  }

  OptValue<hbc::DebugSourceLocation> getLocationForState(
      const InterpreterState &state) const {
    return state.codeBlock->getSourceLocation(state.offset);
  }

                                                                
                                                                               
                                                      
                                                              
  bool resolveBreakpointLocation(Breakpoint &breakpoint) const;

                                
  void unresolveBreakpointLocation(Breakpoint &breakpoint);

                                                                               
                          
  CallFrameInfo getCallFrameInfo(const CodeBlock *codeBlock, uint32_t offset)
      const;

                                                               
  llvh::Optional<uint32_t> findJumpTarget(CodeBlock *block, uint32_t offset);

                                                                              
  void breakAtPossibleNextInstructions(const InterpreterState &state);
};

}                
}                    

#endif                          
#endif

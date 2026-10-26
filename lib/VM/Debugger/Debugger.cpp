/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifdef HERMES_ENABLE_DEBUGGER

#include "hermes/VM/Debugger/Debugger.h"

#include "hermes/Inst/InstDecode.h"
#include "hermes/Support/UTF8.h"
#include "hermes/VM/Callable.h"
#include "hermes/VM/CodeBlock.h"
#include "hermes/VM/JSError.h"
#include "hermes/VM/JSLib.h"
#include "hermes/VM/Operations.h"
#include "hermes/VM/Profiler/SamplingProfiler.h"
#include "hermes/VM/Runtime.h"
#include "hermes/VM/RuntimeModule.h"
#include "hermes/VM/StackFrame-inline.h"
#include "hermes/VM/StringView.h"
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif

namespace hermes {
namespace vm {

using namespace hermes::inst;
namespace fhd = ::facebook::hermes::debugger;

                                                               
                                                              
static inline bool shouldSingleStep(OpCode opCode) {
  return opCode == OpCode::Throw || opCode == OpCode::SwitchImm;
}

static StringView getFunctionName(
    Runtime &runtime,
    const CodeBlock *codeBlock) {
  auto functionName = codeBlock->getNameMayAllocate();
  if (functionName == Predefined::getSymbolID(Predefined::emptyString)) {
    functionName = Predefined::getSymbolID(Predefined::anonymous);
  }
  return runtime.getIdentifierTable().getStringView(runtime, functionName);
}

static std::string getFileNameAsUTF8(
    Runtime &runtime,
    RuntimeModule *runtimeModule,
    uint32_t filenameId) {
  const auto *debugInfo = runtimeModule->getBytecode()->getDebugInfo();
  return debugInfo->getFilenameByID(filenameId);
}

                                                                               
                                                                               
                     
static unsigned
getIPOffsetInBlock(Runtime &runtime, const CodeBlock *cb, uint32_t frame) {
  if (frame == 0) {
                                                                                
    return cb->getOffsetOf(runtime.getCurrentIP());
  }

                                                        
  auto prevFrameInfo = runtime.stackFrameInfoByIndex(frame - 1);
  return cb->getOffsetOf(prevFrameInfo->frame->getSavedIP());
}

                                                                         
             
struct ScopeRegAndDescriptorChain {
                                              
  unsigned reg;

                                 
  llvh::SmallVector<hbc::DebugScopeDescriptor, 4> scopeDescs;
};

                                                                           
                                                                                
                                                                                
                                                          
static llvh::Optional<ScopeRegAndDescriptorChain>
scopeDescChainForBlock(Runtime &runtime, const CodeBlock *cb, uint32_t frame) {
  OptValue<hbc::DebugSourceLocation> locationOpt =
      cb->getSourceLocation(getIPOffsetInBlock(runtime, cb, frame));

  if (!locationOpt) {
    return llvh::None;
  }

  unsigned envReg = locationOpt->envReg;
  if (envReg == hbc::DebugSourceLocation::NO_REG) {
                                                                          
    return llvh::None;
  }

  ScopeRegAndDescriptorChain ret;
  ret.reg = envReg;
  RuntimeModule *runtimeModule = cb->getRuntimeModule();
  const hbc::BCProvider *bytecode = runtimeModule->getBytecode();
  const hbc::DebugInfo *debugInfo = bytecode->getDebugInfo();

  OptValue<unsigned> currentScopeDescOffset = locationOpt->scopeAddress;
  while (currentScopeDescOffset) {
    ret.scopeDescs.push_back(
        debugInfo->getScopeDescriptor(*currentScopeDescOffset));

    currentScopeDescOffset = ret.scopeDescs.back().parentOffset;
  }

  return ret;
}

                                                                
static OptValue<uint32_t> getScopeDescIndexForFrame(
    const llvh::SmallVectorImpl<hbc::DebugScopeDescriptor> &scopeDescs,
    uint32_t frame) {
                                                                              
                                                                              
                                                                     
  bool newFrame = true;

                                                                       
  uint32_t numSeenFrames = 0;
  for (uint32_t i = 0, end = scopeDescs.size(); i < end; ++i) {
    const hbc::DebugScopeDescriptor &currScopeDesc = scopeDescs[i];
    if (newFrame) {
                                                                           
                                                      
      if (numSeenFrames == frame) {
        return i;
      }
      ++numSeenFrames;
    }
                                                                               
                                        
    newFrame = !currScopeDesc.flags.isInnerScope;
  }

  return llvh::None;
}

void Debugger::triggerAsyncPause(AsyncPauseKind kind) {
  runtime_.triggerDebuggerAsyncBreak(kind);
}

llvh::Optional<uint32_t> Debugger::findJumpTarget(
    CodeBlock *block,
    uint32_t offset) {
  const Inst *ip = block->getOffsetPtr(offset);

#define DEFINE_JUMP_LONG_VARIANT(name, nameLong) \
  case OpCode::name: {                           \
    return offset + ip->i##name.op1;             \
  }                                              \
  case OpCode::nameLong: {                       \
    return offset + ip->i##nameLong.op1;         \
  }

  switch (ip->opCode) {
#include "hermes/BCGen/HBC/BytecodeList.def"
    default:
      return llvh::None;
  }
#undef DEFINE_JUMP_LONG_VARIANT
}

void Debugger::breakAtPossibleNextInstructions(const InterpreterState &state) {
  auto nextOffset =
      state.offset + getInstSize(getRealOpCode(state.codeBlock, state.offset));
                                                                              
                          
  if (nextOffset < state.codeBlock->getOpcodeArray().size()) {
    setStepBreakpoint(
        state.codeBlock, nextOffset, runtime_.getCurrentFrameOffset());
  }
                                                                    
                                                                
                                                                            
                                                                              
                                                    
    
                                                                         
                                                      
  auto jumpTarget = findJumpTarget(state.codeBlock, state.offset);
  if (jumpTarget.hasValue() && jumpTarget.getValue() != nextOffset) {
    setStepBreakpoint(
        state.codeBlock,
        jumpTarget.getValue(),
        runtime_.getCurrentFrameOffset());
  }
}

inst::OpCode Debugger::getRealOpCode(CodeBlock *block, uint32_t offset) const {
  auto breakpointOpt = getBreakpointLocation(block, offset);
  if (breakpointOpt) {
    const auto *inst =
        reinterpret_cast<const inst::Inst *>(&(breakpointOpt->opCode));
    return inst->opCode;
  }

  auto opcodes = block->getOpcodeArray();
  assert(offset < opcodes.size() && "opCode offset out of bounds");
  const auto *inst = reinterpret_cast<const inst::Inst *>(&opcodes[offset]);
  return inst->opCode;
}

ExecutionStatus Debugger::runDebugger(
    Debugger::RunReason runReason,
    InterpreterState &state) {
  assert(!isDebugging_ && "can't run debugger while debugging is in progress");
  isDebugging_ = true;

                                                                                
                                                            
  OptValue<PauseReason> pauseReason;

                                                                              
  BreakpointID breakpoint = fhd::kInvalidBreakpoint;

  if (runReason == RunReason::Exception) {
                                                                 
    if (isUnwindingException_) {
                                                                   
                                                             
      isDebugging_ = false;
      return ExecutionStatus::EXCEPTION;
    }
    isUnwindingException_ = true;
    clearTempBreakpoints();
    pauseReason = PauseReason::Exception;
  } else if (runReason == RunReason::AsyncBreakImplicit) {
    if (curStepMode_.hasValue()) {
                                                           
      isDebugging_ = false;
      return ExecutionStatus::RETURNED;
    }
    pauseReason = PauseReason::AsyncTriggerImplicit;
  } else if (runReason == RunReason::AsyncBreakExplicit) {
                                                                        
                                                                       
                
    if (curStepMode_) {
      clearTempBreakpoints();
      curStepMode_ = llvh::None;
    }
    pauseReason = PauseReason::AsyncTriggerExplicit;
  } else {
    assert(runReason == RunReason::Opcode && "Unknown run reason");

                                                                             
                                                                            
                                                          
                                        
    if (restoreBreakpointIfAny()) {
                                                                             
                                                                          
                                                                              
                                                                           
      clearRestorationBreakpoints();

                                                                        
                                                                            
                                                                             
                                                                           
                       
      auto breakpointOpt = getBreakpointLocation(state.codeBlock, state.offset);
      OpCode curCode = getRealOpCode(state.codeBlock, state.offset);
      if (!breakpointOpt.hasValue() && curCode != OpCode::Debugger) {
        isDebugging_ = false;
        return ExecutionStatus::RETURNED;
      }
    }

                                                                   
    auto breakpointOpt = getBreakpointLocation(state.codeBlock, state.offset);
    if (breakpointOpt.hasValue() &&
        (breakpointOpt->hasStepBreakpoint || breakpointOpt->onLoad)) {
                                                               
                                                                            
      if (breakpointOpt->onLoad) {
        pauseReason = PauseReason::ScriptLoaded;
        clearTempBreakpoints();
      } else if (
          breakpointOpt->callStackDepths.count(0) ||
          breakpointOpt->callStackDepths.count(
              runtime_.getCurrentFrameOffset())) {
                                                                          
        assert(curStepMode_ && "no step to finish");
        clearTempBreakpoints();
        auto locationOpt = getLocationForState(state);

        if (*curStepMode_ == StepMode::Into ||
            *curStepMode_ == StepMode::Over) {
                                                                       
                         
                                                                    
          while (!locationOpt.hasValue() || locationOpt->statement == 0 ||
                 sameStatementDifferentInstruction(state, preStepState_)) {
                                                
            OpCode curCode = getRealOpCode(state.codeBlock, state.offset);

            if (curCode == OpCode::Ret) {
                                        
              breakpointCaller(                             false);
              pauseOnAllCodeBlocks_ = true;
              curStepMode_ = StepMode::Out;
              isDebugging_ = false;
              return ExecutionStatus::RETURNED;
            }

                                                                           
                                                                          
                                       
            if (shouldSingleStep(curCode)) {
              ExecutionStatus status = stepInstruction(state);
              if (status == ExecutionStatus::EXCEPTION) {
                breakpointExceptionHandler(state);
                isDebugging_ = false;
                return status;
              }
              locationOpt = getLocationForState(state);
              continue;
            }

                                                                     
            breakAtPossibleNextInstructions(state);
            if (*curStepMode_ == StepMode::Into) {
              pauseOnAllCodeBlocks_ = true;
            }
            isDebugging_ = false;
            return ExecutionStatus::RETURNED;
          }
        }

                         
        curStepMode_ = llvh::None;
        pauseReason = PauseReason::StepFinish;
      } else {
                                                         
        isDebugging_ = false;
        return ExecutionStatus::RETURNED;
      }
    } else {
      auto checkBreakpointCondition =
          [&](const std::string &condition) -> bool {
        if (condition.empty()) {
                                                     
                                                     
          return true;
        }
        EvalResultMetadata metadata;
        EvalArgs args;
        args.frameIdx = 0;
                                                                     
                                                      
        HermesValue conditionResult =
            evalInFrame(args, condition, state, &metadata);
        NoAllocScope noAlloc(runtime_);
        if (metadata.isException) {
                               
                                            
          return false;
        }
        noAlloc.release();
        return toBoolean(conditionResult);
      };

                                                                           
                                                                                
                                                             
                                         
      if (breakpointOpt.hasValue()) {
        assert(
            breakpointOpt->user.hasValue() &&
            "must be stopped on a user breakpoint");
        const auto &condition =
            userBreakpoints_[*breakpointOpt->user].condition;
        if (checkBreakpointCondition(condition)) {
          pauseReason = PauseReason::Breakpoint;
          breakpoint = *(breakpointOpt->user);
        } else {
          isDebugging_ = false;
          return ExecutionStatus::RETURNED;
        }
      } else {
        pauseReason = PauseReason::DebuggerStatement;
      }

                                   
      if (curStepMode_) {
                                                                            
                                                                   
        curStepMode_ = llvh::None;
        clearTempBreakpoints();
      }
    }
  }

  assert(pauseReason.hasValue() && "runDebugger failed to set PauseReason");
  return debuggerLoop(state, *pauseReason, breakpoint);
}

ExecutionStatus Debugger::debuggerLoop(
    InterpreterState &state,
    PauseReason pauseReason,
    BreakpointID breakpoint) {
  const InterpreterState startState = state;
  const bool startException = pauseReason == PauseReason::Exception;
  EvalResultMetadata evalResultMetadata;
  CallResult<InterpreterState> result{ExecutionStatus::EXCEPTION};
  GCScope gcScope{runtime_};
  MutableHandle<> evalResult{runtime_};
                                                                      
  static constexpr unsigned KEEP_HANDLES = 1;
#if HERMESVM_SAMPLING_PROFILER_AVAILABLE
  SuspendSamplingProfilerRAII ssp{
      runtime_, SamplingProfiler::SuspendFrameInfo::Kind::Debugger};
#endif                                        
  while (true) {
    GCScopeMarkerRAII marker{runtime_};
    auto command = getNextCommand(
        state, pauseReason, *evalResult, evalResultMetadata, breakpoint);
    evalResult.clear();
    switch (command.type) {
      case DebugCommandType::NONE:
        break;
      case DebugCommandType::CONTINUE:
        isDebugging_ = false;
        curStepMode_ = llvh::None;
        return ExecutionStatus::RETURNED;
      case DebugCommandType::EVAL:
        evalResult = evalInFrame(
            command.evalArgs, command.text, startState, &evalResultMetadata);
        pauseReason = PauseReason::EvalComplete;
        break;
      case DebugCommandType::STEP: {
                                                                        
        pauseReason = PauseReason::StepFinish;
        const StepMode stepMode = command.stepArgs.mode;
                                                                         
                     
        const auto startLocationOpt = getLocationForState(state);
        (void)startLocationOpt;
        assert(
            startLocationOpt.hasValue() &&
            "starting step from a location without debug info");
        preStepState_ = state;
        if (stepMode == StepMode::Into || stepMode == StepMode::Over) {
          if (startException) {
                                                                 
                                                                  
            breakpointExceptionHandler(state);
            isDebugging_ = false;
            curStepMode_ = stepMode;
            return ExecutionStatus::RETURNED;
          }
          while (true) {
                                                                               
                                                                      
            gcScope.flushToSmallCount(KEEP_HANDLES);
            OpCode curCode = getRealOpCode(state.codeBlock, state.offset);

            if (curCode == OpCode::Ret) {
              breakpointCaller(                             false);
              pauseOnAllCodeBlocks_ = true;
              isDebugging_ = false;
                                          
              curStepMode_ = StepMode::Out;
              return ExecutionStatus::RETURNED;
            }

                                                                           
                                                                          
                                       
            if (shouldSingleStep(curCode)) {
              ExecutionStatus status = stepInstruction(state);
              if (status == ExecutionStatus::EXCEPTION) {
                breakpointExceptionHandler(state);
                isDebugging_ = false;
                curStepMode_ = stepMode;
                return status;
              }
              auto locationOpt = getLocationForState(state);
              if (locationOpt.hasValue() && locationOpt->statement != 0 &&
                  !sameStatementDifferentInstruction(state, preStepState_)) {
                                                                        
                break;
              }
              continue;
            }

                                                                     
                                                                              
                                                                      
                                               
            auto breakpointOpt =
                getBreakpointLocation(state.codeBlock, state.offset);
            if (breakpointOpt) {
              uninstallBreakpoint(
                  state.codeBlock, state.offset, breakpointOpt->opCode);
            }
            breakAtPossibleNextInstructions(state);
            if (breakpointOpt) {
              state.codeBlock->installBreakpointAtOffset(state.offset);
            }
            if (stepMode == StepMode::Into) {
                                                            
                                                                 
              pauseOnAllCodeBlocks_ = true;
            }
            isDebugging_ = false;
            curStepMode_ = stepMode;
            return ExecutionStatus::RETURNED;
          }
        } else {
          ExecutionStatus status;
          if (startException) {
            breakpointExceptionHandler(state);
            status = ExecutionStatus::EXCEPTION;
          } else {
            breakpointCaller(                             false);
            status = ExecutionStatus::RETURNED;
          }
                                                            
          isDebugging_ = false;
          curStepMode_ = StepMode::Out;
          return status;
        }
        break;
      }
    }
  }
}

void Debugger::willExecuteModule(RuntimeModule *module, CodeBlock *codeBlock) {
                                                                             
                                                                       
  assert(
      module == module->getLazyRootModule() &&
      "Expected to only run on lazy root module");

  if (!getShouldPauseOnScriptLoad())
    return;
                                                              
                                                                 
  auto globalFunctionIndex = module->getBytecode()->getGlobalFunctionIndex();
  auto globalCode = module->getCodeBlockMayAllocate(globalFunctionIndex);
  setOnLoadBreakpoint(globalCode, 0);
}

void Debugger::willUnloadModule(RuntimeModule *module) {
  if (tempBreakpoints_.size() == 0 && restorationBreakpoints_.size() == 0 &&
      userBreakpoints_.size() == 0) {
    return;
  }

  llvh::DenseSet<CodeBlock *> unloadingBlocks;
  for (auto *block : module->getFunctionMap()) {
    if (block) {
      unloadingBlocks.insert(block);
    }
  }

  for (auto &bp : userBreakpoints_) {
    if (unloadingBlocks.count(bp.second.codeBlock)) {
      unresolveBreakpointLocation(bp.second);
    }
  }

  auto cleanNonUserBreakpoint = [&](Breakpoint &bp) {
    if (!unloadingBlocks.count(bp.codeBlock))
      return false;

    auto *ptr = bp.codeBlock->getOffsetPtr(bp.offset);
    auto it = breakpointLocations_.find(ptr);
    if (it != breakpointLocations_.end()) {
      auto &location = it->second;
      assert(!location.user.hasValue() && "Unexpected user breakpoint");
      uninstallBreakpoint(bp.codeBlock, bp.offset, location.opCode);
      breakpointLocations_.erase(it);
    }
    return true;
  };

  tempBreakpoints_.erase(
      std::remove_if(
          tempBreakpoints_.begin(),
          tempBreakpoints_.end(),
          cleanNonUserBreakpoint),
      tempBreakpoints_.end());

  restorationBreakpoints_.erase(
      std::remove_if(
          restorationBreakpoints_.begin(),
          restorationBreakpoints_.end(),
          cleanNonUserBreakpoint),
      restorationBreakpoints_.end());
}

void Debugger::resolveBreakpoints(CodeBlock *codeBlock) {
  for (auto &it : userBreakpoints_) {
    auto &breakpoint = it.second;
    if (!breakpoint.isResolved()) {
      resolveBreakpointLocation(breakpoint);
      if (breakpoint.isResolved() && breakpoint.enabled) {
        setUserBreakpoint(breakpoint.codeBlock, breakpoint.offset, it.first);
        if (breakpointResolvedCallback_) {
          breakpointResolvedCallback_(it.first);
        }
      }
    }
  }
}

auto Debugger::getCallFrameInfo(const CodeBlock *codeBlock, uint32_t ipOffset)
    const -> CallFrameInfo {
  GCScopeMarkerRAII marker{runtime_};
  CallFrameInfo frameInfo;
  if (!codeBlock) {
    frameInfo.functionName = "(native)";
  } else {
                                                                              
                              
    GCScopeMarkerRAII gcMarker{runtime_};

    llvh::SmallVector<char16_t, 64> storage;
    UTF16Ref functionName =
        getFunctionName(runtime_, codeBlock).getUTF16Ref(storage);
    convertUTF16ToUTF8WithReplacements(frameInfo.functionName, functionName);
    auto locationOpt = codeBlock->getSourceLocation(ipOffset);
    if (locationOpt) {
      frameInfo.location.line = locationOpt->line;
      frameInfo.location.column = locationOpt->column;
      frameInfo.location.fileId = resolveScriptId(
          codeBlock->getRuntimeModule(), locationOpt->filenameId);
      frameInfo.location.fileName = getFileNameAsUTF8(
          runtime_, codeBlock->getRuntimeModule(), locationOpt->filenameId);
    }
  }
  return frameInfo;
}

auto Debugger::getStackTrace() const -> StackTrace {
                                                                             
                                    
  assert(
      runtime_.getCurrentFrame() &&
      "Must have at least one stack frame to call this function");
  using fhd::CallFrameInfo;
  GCScopeMarkerRAII marker{runtime_};
  MutableHandle<> displayName{runtime_};
  MutableHandle<JSObject> propObj{runtime_};
  std::vector<CallFrameInfo> frames;
                                                       
                                                                        
                                                                                
                                           
  const CodeBlock *codeBlock =
      runtime_.getCurrentFrame()->getCalleeCodeBlock(runtime_);
  const inst::Inst *ip = runtime_.getCurrentIP();
  GCScopeMarkerRAII marker2{runtime_};
  for (auto cf : runtime_.getStackFrames()) {
    marker2.flush();
    uint32_t ipOffset = (codeBlock && ip) ? codeBlock->getOffsetOf(ip) : 0;
    CallFrameInfo frameInfo = getCallFrameInfo(codeBlock, ipOffset);
    if (auto callableHandle = Handle<Callable>::dyn_vmcast(
            Handle<>(&cf.getCalleeClosureOrCBRef()))) {
      NamedPropertyDescriptor desc;
      propObj = JSObject::getNamedDescriptorPredefined(
          callableHandle, runtime_, Predefined::displayName, desc);
      if (propObj) {
        auto displayNameRes = JSObject::getNamedSlotValue(
            createPseudoHandle(*propObj), runtime_, desc);
        if (LLVM_UNLIKELY(displayNameRes == ExecutionStatus::EXCEPTION)) {
          displayName = HermesValue::encodeUndefinedValue();
        } else {
          displayName = std::move(*displayNameRes);
          if (displayName->isString()) {
            llvh::SmallVector<char16_t, 64> storage;
            displayName->getString()->appendUTF16String(storage);
            convertUTF16ToUTF8WithReplacements(frameInfo.functionName, storage);
          }
        }
      }
    }
    frames.push_back(frameInfo);

    codeBlock = cf.getSavedCodeBlock();
    ip = cf.getSavedIP();
    if (!codeBlock && ip) {
                                                                              
                                                                          
                          
      StackFramePtr prev = cf->getPreviousFrame();
      assert(prev && "bound function calls must have a caller");
      if (CodeBlock *parentCB = prev->getCalleeCodeBlock(runtime_)) {
        codeBlock = parentCB;
      }
    }
  }
  return StackTrace(std::move(frames));
}

auto Debugger::createBreakpoint(const SourceLocation &loc) -> BreakpointID {
  using fhd::kInvalidBreakpoint;

  OptValue<hbc::DebugSearchResult> locationOpt{llvh::None};

  Breakpoint breakpoint{};
  breakpoint.requestedLocation = loc;
                                        
  breakpoint.enabled = true;
  bool resolved = resolveBreakpointLocation(breakpoint);

  BreakpointID breakpointId;
  if (resolved) {
    auto breakpointLoc =
        getBreakpointLocation(breakpoint.codeBlock, breakpoint.offset);
    if (breakpointLoc.hasValue() && breakpointLoc->user) {
                                             
      return kInvalidBreakpoint;
    }

    breakpointId = nextBreakpointId_++;
    setUserBreakpoint(breakpoint.codeBlock, breakpoint.offset, breakpointId);
  } else {
    breakpointId = nextBreakpointId_++;
  }

  userBreakpoints_[breakpointId] = std::move(breakpoint);

  return breakpointId;
}

void Debugger::setBreakpointCondition(BreakpointID id, std::string condition) {
  auto it = userBreakpoints_.find(id);

  if (it == userBreakpoints_.end()) {
    return;
  }

  auto &breakpoint = it->second;
  breakpoint.condition = std::move(condition);
}

void Debugger::deleteBreakpoint(BreakpointID id) {
  auto it = userBreakpoints_.find(id);

  if (it == userBreakpoints_.end()) {
    return;
  }

  auto &breakpoint = it->second;
  if (breakpoint.enabled && breakpoint.isResolved()) {
    unsetUserBreakpoint(breakpoint);
  }
  userBreakpoints_.erase(it);
}

void Debugger::deleteAllBreakpoints() {
  for (auto &it : userBreakpoints_) {
    auto &breakpoint = it.second;
    if (breakpoint.enabled && breakpoint.isResolved()) {
      unsetUserBreakpoint(breakpoint);
    }
  }
  userBreakpoints_.clear();
}

void Debugger::setBreakpointEnabled(BreakpointID id, bool enable) {
  auto it = userBreakpoints_.find(id);

  if (it == userBreakpoints_.end()) {
    return;
  }

  auto &breakpoint = it->second;
  if (enable && !breakpoint.enabled) {
    breakpoint.enabled = true;
    if (breakpoint.isResolved()) {
      setUserBreakpoint(breakpoint.codeBlock, breakpoint.offset, id);
    }
  } else if (!enable && breakpoint.enabled) {
    breakpoint.enabled = false;
    if (breakpoint.isResolved()) {
      unsetUserBreakpoint(breakpoint);
    }
  }
}

llvh::Optional<const Debugger::BreakpointLocation>
Debugger::getBreakpointLocation(CodeBlock *codeBlock, uint32_t offset) const {
  return getBreakpointLocation(codeBlock->getOffsetPtr(offset));
}

auto Debugger::installBreakpoint(CodeBlock *codeBlock, uint32_t offset)
    -> BreakpointLocation & {
  auto opcodes = codeBlock->getOpcodeArray();
  assert(offset < opcodes.size() && "invalid offset to set breakpoint");
  auto &location =
      breakpointLocations_
          .try_emplace(codeBlock->getOffsetPtr(offset), opcodes[offset])
          .first->second;
  if (location.count() == 0) {
                                                                   
    codeBlock->installBreakpointAtOffset(offset);
  }
  return location;
}

void Debugger::uninstallBreakpoint(
    CodeBlock *codeBlock,
    uint32_t offset,
    hbc::opcode_atom_t opCode) {
                                                                              
                                                                          
             
  if (breakpointToRestore_.first == codeBlock &&
      breakpointToRestore_.second == offset) {
    breakpointToRestore_ = {nullptr, 0};
  } else {
    codeBlock->uninstallBreakpointAtOffset(offset, opCode);
  }
}

void Debugger::setUserBreakpoint(
    CodeBlock *codeBlock,
    uint32_t offset,
    BreakpointID id) {
  BreakpointLocation &location = installBreakpoint(codeBlock, offset);
  location.user = id;
}

void Debugger::doSetNonUserBreakpoint(
    CodeBlock *codeBlock,
    uint32_t offset,
    uint32_t callStackDepth,
    bool isStepBreakpoint) {
  BreakpointLocation &location = installBreakpoint(codeBlock, offset);
  std::vector<Breakpoint> &breakpoints =
      isStepBreakpoint ? tempBreakpoints_ : restorationBreakpoints_;
  if (location.callStackDepths.count(callStackDepth) == 0) {
    location.callStackDepths.insert(callStackDepth);
  }

  if ((isStepBreakpoint && !location.hasStepBreakpoint) ||
      (!isStepBreakpoint && !location.hasRestorationBreakpoint)) {
                                                 
                                        
    Breakpoint breakpoint{};
    breakpoint.codeBlock = codeBlock;
    breakpoint.offset = offset;
    breakpoint.enabled = true;
    breakpoints.push_back(breakpoint);
  }

  if (isStepBreakpoint) {
    location.hasStepBreakpoint = true;
  } else {
    location.hasRestorationBreakpoint = true;
  }
}

void Debugger::setStepBreakpoint(
    CodeBlock *codeBlock,
    uint32_t offset,
    uint32_t callStackDepth) {
  doSetNonUserBreakpoint(
      codeBlock, offset, callStackDepth,                      true);
}

void Debugger::setOnLoadBreakpoint(CodeBlock *codeBlock, uint32_t offset) {
  BreakpointLocation &location = installBreakpoint(codeBlock, offset);
                                               
                                      
  Breakpoint breakpoint{};
  breakpoint.codeBlock = codeBlock;
  breakpoint.offset = offset;
  breakpoint.enabled = true;
  assert(!location.onLoad && "can't set duplicate on-load breakpoint");
  location.onLoad = true;
  tempBreakpoints_.push_back(breakpoint);
  assert(location.count() && "invalid count following set breakpoint");
}

void Debugger::unsetUserBreakpoint(const Breakpoint &breakpoint) {
  CodeBlock *codeBlock = breakpoint.codeBlock;
  uint32_t offset = breakpoint.offset;

  auto opcodes = codeBlock->getOpcodeArray();
  (void)opcodes;
  assert(offset < opcodes.size() && "invalid offset to set breakpoint");

  const Inst *offsetPtr = codeBlock->getOffsetPtr(offset);

  auto locIt = breakpointLocations_.find(offsetPtr);
  assert(
      locIt != breakpointLocations_.end() &&
      "can't unset a non-existent breakpoint");

  auto &location = locIt->second;

  assert(location.user && "no user breakpoints to unset");
  location.user = llvh::None;
  if (location.count() == 0) {
                                                   
                                                                    
    uninstallBreakpoint(codeBlock, offset, location.opCode);
    breakpointLocations_.erase(offsetPtr);
  }
}

void Debugger::setEntryBreakpointForCodeBlock(CodeBlock *codeBlock) {
  assert(!codeBlock->isLazy() && "can't set breakpoint on a lazy codeblock");
  assert(
      (pauseOnAllCodeBlocks_ || pauseOnAllCodeBlocksToRestoreBreakpoint_) &&
      "can't set temp breakpoint while not stepping");
  if (pauseOnAllCodeBlocks_) {
    setStepBreakpoint(codeBlock, 0, 0);
  }
  if (pauseOnAllCodeBlocksToRestoreBreakpoint_) {
    setRestorationBreakpoint(codeBlock, 0, 0);
  }
}

void Debugger::breakpointCaller(bool forRestorationBreakpoint) {
  auto callFrames = runtime_.getStackFrames();

  assert(callFrames.begin() != callFrames.end() && "empty call stack");

                                                                             
  auto frameIt = callFrames.begin();
  const Inst *ip = nullptr;
  for (; frameIt != callFrames.end(); ++frameIt) {
    ip = frameIt->getSavedIP();
    if (ip) {
      break;
    }
  }
  if (!ip) {
    return;
  }
                                                                       
                                                                         
                                                       
  do {
    frameIt++;
    assert(
        frameIt != callFrames.end() &&
        "The frame that has saved ip cannot be the bottom frame");
  } while (!frameIt->getCalleeCodeBlock(runtime_));
                                                                  
                            
  CodeBlock *codeBlock = frameIt->getCalleeCodeBlock(runtime_);
  assert(codeBlock && "The code block must exist since we have ip");
                                                                    

  uint32_t offset = codeBlock->getOffsetOf(ip);
  uint32_t newOffset = offset + getInstSize(getRealOpCode(codeBlock, offset));

  if (forRestorationBreakpoint) {
    setRestorationBreakpoint(
        codeBlock, newOffset, runtime_.calcFrameOffset(frameIt));
  } else {
    setStepBreakpoint(codeBlock, newOffset, runtime_.calcFrameOffset(frameIt));
  }
}

void Debugger::breakpointExceptionHandler(const InterpreterState &state) {
  auto target = findCatchTarget(state);
  if (!target) {
    return;
  }
  auto *codeBlock = target->first.codeBlock;
  auto offset = target->first.offset;
  setStepBreakpoint(codeBlock, offset, target->second);
}

void Debugger::doClearNonUserBreakpoints(bool isStepBreakpoint) {
  llvh::SmallVector<const Inst *, 4> toErase{};

  std::vector<Breakpoint> &breakpointsToClear =
      isStepBreakpoint ? tempBreakpoints_ : restorationBreakpoints_;

  for (const auto &breakpoint : breakpointsToClear) {
    auto *codeBlock = breakpoint.codeBlock;
    auto offset = breakpoint.offset;
    const Inst *inst = codeBlock->getOffsetPtr(offset);
    auto it = breakpointLocations_.find(inst);
    if (it == breakpointLocations_.end()) {
      continue;
    }
    auto &location = it->second;

    if (isStepBreakpoint) {
      location.hasStepBreakpoint = false;
      if (location.hasRestorationBreakpoint) {
        continue;
      }
    } else {
      location.hasRestorationBreakpoint = false;
      if (location.hasStepBreakpoint) {
        continue;
      }
    }

    if (location.count()) {
      location.callStackDepths.clear();
      location.onLoad = false;
      if (location.count() == 0) {
        uninstallBreakpoint(codeBlock, offset, location.opCode);
        toErase.push_back(inst);
      }
    }
  }
  for (const Inst *inst : toErase) {
    breakpointLocations_.erase(inst);
  }
  breakpointsToClear.clear();
}

void Debugger::clearTempBreakpoints() {
  doClearNonUserBreakpoints(                     true);
  pauseOnAllCodeBlocks_ = false;
}

void Debugger::setRestorationBreakpoint(
    CodeBlock *codeBlock,
    uint32_t offset,
    uint32_t callStackDepth) {
  doSetNonUserBreakpoint(
      codeBlock, offset, callStackDepth,                      false);
}

bool Debugger::restoreBreakpointIfAny() {
  if (breakpointToRestore_.first != nullptr) {
    breakpointToRestore_.first->installBreakpointAtOffset(
        breakpointToRestore_.second);
    breakpointToRestore_ = {nullptr, 0};
    return true;
  }
  return false;
}

void Debugger::clearRestorationBreakpoints() {
  doClearNonUserBreakpoints(                     false);
  pauseOnAllCodeBlocksToRestoreBreakpoint_ = false;
}

ExecutionStatus Debugger::stepInstruction(InterpreterState &state) {
  auto *codeBlock = state.codeBlock;
  uint32_t offset = state.offset;
  assert(
      getRealOpCode(codeBlock, offset) != OpCode::Ret &&
      "can't stepInstruction in Ret, use step-out semantics instead");
  assert(
      shouldSingleStep(getRealOpCode(codeBlock, offset)) &&
      "can't stepInstruction through Call, use step-in semantics instead");
  auto locationOpt = getBreakpointLocation(codeBlock, offset);
  ExecutionStatus status;
  InterpreterState newState{state};
  if (locationOpt.hasValue()) {
                                                                               
    uninstallBreakpoint(codeBlock, offset, locationOpt->opCode);
    status = runtime_.stepFunction(newState);
    codeBlock->installBreakpointAtOffset(offset);
  } else {
    status = runtime_.stepFunction(newState);
  }

  if (status != ExecutionStatus::EXCEPTION)
    state = newState;
  return status;
}

ExecutionStatus Debugger::processInstUnderDebuggerOpCode(
    InterpreterState &state) {
  auto *codeBlock = state.codeBlock;
  uint32_t offset = state.offset;
  InterpreterState newState{state};
  const inst::Inst *ip = codeBlock->getOffsetPtr(offset);

  auto locationOpt = getBreakpointLocation(codeBlock, offset);
  if (locationOpt.hasValue()) {
    uninstallBreakpoint(codeBlock, offset, locationOpt->opCode);
    if (ip->opCode == OpCode::Debugger) {
                                                             
                                                                     
      newState.offset = offset + 1;
      state = newState;
    } else if (ip->opCode == OpCode::Ret || isCallType(ip->opCode)) {
      if (ip->opCode == OpCode::Ret) {
                                                                               
                                  
        breakpointCaller(                             true);
      }

                                                                           
                                
      pauseOnAllCodeBlocksToRestoreBreakpoint_ = true;

                                                                           
                                                                                
                                                                       
                                                                           
                                            
      breakpointToRestore_ = {codeBlock, offset};
    } else {
      runtime_.setCurrentIP(ip);
      ExecutionStatus status = runtime_.stepFunction(newState);
      runtime_.invalidateCurrentIP();
      codeBlock->installBreakpointAtOffset(offset);
      if (status == ExecutionStatus::EXCEPTION) {
        return status;
      }
      state = newState;
    }
  } else if (ip->opCode == OpCode::Debugger) {
                                                                          
    newState.offset = offset + 1;
    state = newState;
  }
                                                                          
                                                                            
                      

  return ExecutionStatus::RETURNED;
}

                                                                              
                                                                       
static unsigned getFrameSize(
    const llvh::SmallVector<hbc::DebugScopeDescriptor, 4> &scopeDescs,
    uint32_t i) {
  unsigned frameSize = 0;

  do {
    frameSize += scopeDescs[i].names.size();
  } while (scopeDescs[i++].flags.isInnerScope);

  return frameSize;
}

auto Debugger::getLexicalInfoInFrame(uint32_t frame) const -> LexicalInfo {
  auto frameInfo = runtime_.stackFrameInfoByIndex(frame);
  assert(frameInfo && "Invalid frame");

  LexicalInfo result;
  if (frameInfo->isGlobal) {
                                 
                                                                               
    result.variableCountsByScope_.push_back(0);
    return result;
  }
  const CodeBlock *cb = frameInfo->frame->getCalleeCodeBlock(runtime_);
  if (!cb) {
                                                 
    result.variableCountsByScope_.push_back(0);
    return result;
  }

  llvh::Optional<ScopeRegAndDescriptorChain> envRegAndDescChain =
      scopeDescChainForBlock(runtime_, cb, frame);
  if (!envRegAndDescChain) {
                                                       
    result.variableCountsByScope_.push_back(0);
    return result;
  }

  const llvh::SmallVector<hbc::DebugScopeDescriptor, 4> &scopeDescs =
      envRegAndDescChain->scopeDescs;
  uint32_t currFrame = 0;
  while (auto idx = getScopeDescIndexForFrame(scopeDescs, currFrame++)) {
    result.variableCountsByScope_.push_back(getFrameSize(scopeDescs, *idx));
  }
  return result;
}

HermesValue Debugger::getVariableInFrame(
    uint32_t frame,
    uint32_t scopeDepth,
    uint32_t variableIndex,
    std::string *outName) const {
  GCScope gcScope{runtime_};
  auto frameInfo = runtime_.stackFrameInfoByIndex(frame);
  assert(frameInfo && "Invalid frame");

  const HermesValue undefined = HermesValue::encodeUndefinedValue();

                                                                
  if (outName)
    outName->clear();

  if (frameInfo->isGlobal) {
                                 
                          
    return undefined;
  }
  const CodeBlock *cb = frameInfo->frame->getCalleeCodeBlock(runtime_);
  assert(cb && "Unexpectedly null code block");
  llvh::Optional<ScopeRegAndDescriptorChain> envRegAndDescChain =
      scopeDescChainForBlock(runtime_, cb, frame);
  if (!envRegAndDescChain) {
                                                       
    return undefined;
  }

  const llvh::SmallVector<hbc::DebugScopeDescriptor, 4> &scopeDescs =
      envRegAndDescChain->scopeDescs;

                                                                              
                        
  auto idx = getScopeDescIndexForFrame(scopeDescs, scopeDepth);
  if (!idx) {
                           
    return undefined;
  }

                                                        
  const PinnedHermesValue &envPHV =
      (&frameInfo->frame.getFirstLocalRef())[envRegAndDescChain->reg];
  assert(envPHV.isObject() && dyn_vmcast<Environment>(envPHV));

                                                                                
                                                       
  MutableHandle<Environment> env(runtime_, vmcast<Environment>(envPHV));
  unsigned varScopeIndex = *idx;
  for (uint32_t i = varScopeIndex; env && i > 0; --i) {
    env = env->getParentEnvironment(runtime_);
  }

                                                                        
                                                                             
                              
  bool newFrame = false;
  while (env && env->getSize() <= variableIndex) {
                                                                       
                                                                          
                                     
    assert(!newFrame && "accessing variables from another frame");
    (void)newFrame;

                                                                             
    variableIndex -= env->getSize();
    env = env->getParentEnvironment(runtime_);

                                                                              
                                                                     
    newFrame = !scopeDescs[varScopeIndex++].flags.isInnerScope;
  }

  if (!env) {
    return undefined;
  }
  assert(varScopeIndex < scopeDescs.size() && "OOB scope desc access");

                                                        
  if (outName)
    *outName = scopeDescs[varScopeIndex].names[variableIndex];

                                                                         
  return env->slot(variableIndex);
}

HermesValue Debugger::getThisValue(uint32_t frame) const {
  const auto frameInfo = runtime_.stackFrameInfoByIndex(frame);
  assert(frameInfo && "Invalid frame");

  if (frameInfo->isGlobal) {
                                                             
    return runtime_.getGlobal().getHermesValue();
  }

  return frameInfo->frame.getThisArgRef();
}

HermesValue Debugger::getExceptionAsEvalResult(
    EvalResultMetadata *outMetadata) {
  outMetadata->isException = true;

  Handle<> thrownValue = runtime_.makeHandle(runtime_.getThrownValue());
  assert(!thrownValue->isEmpty() && "Runtime did not throw");
  runtime_.clearThrownValue();

                                                                         
                                                                          
  auto res = toString_RJS(runtime_, thrownValue);
  if (res != ExecutionStatus::EXCEPTION) {
    llvh::SmallVector<char16_t, 64> errorText;
    res->get()->appendUTF16String(errorText);
    convertUTF16ToUTF8WithReplacements(
        outMetadata->exceptionDetails.text, errorText);
  }

                                                                        
                                                                          
                                                        
  if (auto errorHandle = Handle<JSError>::dyn_vmcast(thrownValue)) {
    if (auto stackTracePtr = errorHandle->getStackTrace()) {
                                                                         
      const auto stackTraceCopy = *stackTracePtr;
      std::vector<CallFrameInfo> frames;
      frames.reserve(stackTraceCopy.size());
      for (const StackTraceInfo &sti : stackTraceCopy)
        frames.push_back(getCallFrameInfo(sti.codeBlock, sti.bytecodeOffset));
      outMetadata->exceptionDetails.stackTrace_ = StackTrace{std::move(frames)};
    }
  }
  return *thrownValue;
}

HermesValue Debugger::evalInFrame(
    const EvalArgs &args,
    const std::string &src,
    const InterpreterState &state,
    EvalResultMetadata *outMetadata) {
  GCScope gcScope{runtime_};
  *outMetadata = EvalResultMetadata{};
  uint32_t frame = args.frameIdx;
  auto frameInfo = runtime_.stackFrameInfoByIndex(frame);
  if (!frameInfo) {
    return HermesValue::encodeUndefinedValue();
  }

  MutableHandle<> resultHandle(runtime_);
  bool singleFunction = false;

  const CodeBlock *cb = frameInfo->frame->getCalleeCodeBlock(runtime_);
  llvh::Optional<ScopeRegAndDescriptorChain> envRegAndScopeChain =
      scopeDescChainForBlock(runtime_, cb, frame);

                                                                 
                                                                          
  Handle<> savedThrownValue = runtime_.makeHandle(runtime_.getThrownValue());
  runtime_.clearThrownValue();

  CallResult<HermesValue> result{ExecutionStatus::EXCEPTION};

  if (!envRegAndScopeChain) {
    result = runtime_.raiseError("Can't evalInFrame: Environment not found");
  } else {
                                                       
    const PinnedHermesValue &env =
        (&frameInfo->frame.getFirstLocalRef())[envRegAndScopeChain->reg];
    assert(env.isObject() && dyn_vmcast<Environment>(env));

                                                                    
                                                                        
               
    ScopeChain chain;
    for (const hbc::DebugScopeDescriptor &scopeDesc :
         envRegAndScopeChain->scopeDescs) {
      chain.scopes.emplace_back();
      ScopeChainItem &scopeItem = chain.scopes.back();
      for (const llvh::StringRef &name : scopeDesc.names) {
        scopeItem.variables.push_back(name);
      }
    }

    result = evalInEnvironment(
        runtime_,
        src,
        Handle<Environment>::vmcast(runtime_, env),
        chain,
        Handle<>(&frameInfo->frame->getThisArgRef()),
        false,
        singleFunction);
  }

                                      
  if (result.getStatus() == ExecutionStatus::EXCEPTION) {
    resultHandle = getExceptionAsEvalResult(outMetadata);
  } else {
    assert(
        !result->isEmpty() &&
        "eval result should not be empty unless exception was thrown");
    resultHandle = *result;
  }

  runtime_.setThrownValue(savedThrownValue.getHermesValue());
  return *resultHandle;
}

llvh::Optional<std::pair<InterpreterState, uint32_t>> Debugger::findCatchTarget(
    const InterpreterState &state) const {
  auto *codeBlock = state.codeBlock;
  auto offset = state.offset;
  auto frames = runtime_.getStackFrames();
  for (auto it = frames.begin(), e = frames.end(); it != e; ++it) {
    if (codeBlock) {
      auto handlerOffset = codeBlock->findCatchTargetOffset(offset);
      if (handlerOffset != -1) {
        return std::make_pair(
            InterpreterState(codeBlock, handlerOffset),
            runtime_.calcFrameOffset(it));
      }
    }
    codeBlock = it->getSavedCodeBlock();
    if (codeBlock) {
      offset = codeBlock->getOffsetOf(it->getSavedIP());
    }
  }
  return llvh::None;
}

bool Debugger::resolveBreakpointLocation(Breakpoint &breakpoint) const {
  using fhd::kInvalidLocation;
  assert(!breakpoint.isResolved() && "breakpoint already resolved");

  OptValue<hbc::DebugSearchResult> locationOpt{};

#ifndef HERMESVM_LEAN
                                                                              
                                                               
                                                                            
                                                                          
                                                             
                                                                     
                                                                               
                                                       
                                               
  GCScope gcScope{runtime_};
  for (auto &runtimeModule : runtime_.getRuntimeModules()) {
    llvh::DenseSet<CodeBlock *> visited{};
    std::vector<CodeBlock *> toVisit{};
    for (uint32_t i = 0, e = runtimeModule.getNumCodeBlocks(); i < e; ++i) {
      GCScopeMarkerRAII marker{gcScope};
                                                                            
      toVisit.push_back(runtimeModule.getCodeBlockMayAllocate(i));
    }

    while (!toVisit.empty()) {
      GCScopeMarkerRAII marker{gcScope};
      CodeBlock *codeBlock = toVisit.back();
      toVisit.pop_back();

      if (!codeBlock || !codeBlock->isLazy()) {
                                                        
                                                         
        continue;
      }

      if (visited.count(codeBlock) > 0) {
                                   
        continue;
      }

      visited.insert(codeBlock);
      auto start = codeBlock->getLazyFunctionStartLoc();
      auto end = codeBlock->getLazyFunctionEndLoc();

      const auto &request = breakpoint.requestedLocation;
      if ((start.line < request.line && request.line < end.line) ||
          ((start.line == request.line || request.line == end.line) &&
           (start.col <= request.column && request.column <= end.col))) {
                                                                          
                                
        if (LLVM_UNLIKELY(
                codeBlock->lazyCompile(runtime_) ==
                ExecutionStatus::EXCEPTION)) {
                                             
          runtime_.clearThrownValue();
        }

                                                                   
                                                     
                                                               
        toVisit.clear();

                                                                               
                                                         
        for (uint32_t i = 0, e = runtimeModule.getNumCodeBlocks(); i < e; ++i) {
          GCScopeMarkerRAII marker2{gcScope};
                                                                                
          toVisit.push_back(runtimeModule.getCodeBlockMayAllocate(i));
        }
      }
    }
  }
#endif

                                                                         
                                                                          
                                          
                                                                                
               
  for (auto it = runtime_.getRuntimeModules().rbegin();
       it != runtime_.getRuntimeModules().rend();
       ++it) {
    auto &runtimeModule = *it;
    GCScope gcScope{runtime_};

    if (!runtimeModule.isInitialized()) {
                              
      continue;
    }
    if (!runtimeModule.getBytecode()->getDebugInfo()) {
                                                  
      continue;
    }

    const auto *debugInfo = runtimeModule.getBytecode()->getDebugInfo();
    const auto &fileRegions = debugInfo->viewFiles();
    if (fileRegions.empty()) {
      continue;
    }

    uint32_t resolvedFileId = kInvalidLocation;
    std::string resolvedFileName{};

    if (!breakpoint.requestedLocation.fileName.empty()) {
      for (const auto &region : fileRegions) {
        std::string storage =
            getFileNameAsUTF8(runtime_, &runtimeModule, region.filenameId);
        llvh::StringRef storageRef{storage};
        if (storageRef.consume_back(breakpoint.requestedLocation.fileName)) {
          resolvedFileId = region.filenameId;
          resolvedFileName = std::move(storage);
          break;
        }
      }
    } else if (breakpoint.requestedLocation.fileId != kInvalidLocation) {
      for (const auto &region : fileRegions) {
                                                                              
                                                                                
                                                                              
                                          
        assert(
            region.filenameId == 0 && "Unexpected multiple filenames per RM");
        if (resolveScriptId(&runtimeModule, region.filenameId) ==
            breakpoint.requestedLocation.fileId) {
          resolvedFileId = region.filenameId;
          resolvedFileName =
              getFileNameAsUTF8(runtime_, &runtimeModule, resolvedFileId);
          break;
        }
      }
    } else {
                                                    
      resolvedFileId = fileRegions.front().filenameId;
      resolvedFileName =
          getFileNameAsUTF8(runtime_, &runtimeModule, resolvedFileId);
    }

    if (resolvedFileId == kInvalidLocation) {
                                      
      continue;
    }

    locationOpt = debugInfo->getAddressForLocation(
        resolvedFileId,
        breakpoint.requestedLocation.line,
        breakpoint.requestedLocation.column == kInvalidLocation
            ? llvh::None
            : OptValue<uint32_t>{breakpoint.requestedLocation.column});

    if (locationOpt.hasValue()) {
      breakpoint.codeBlock =
          runtimeModule.getCodeBlockMayAllocate(locationOpt->functionIndex);
      breakpoint.offset = locationOpt->bytecodeOffset;

      SourceLocation resolvedLocation;
      resolvedLocation.line = locationOpt->line;
      resolvedLocation.column = locationOpt->column;
      resolvedLocation.fileId = resolveScriptId(&runtimeModule, resolvedFileId);
      resolvedLocation.fileName = std::move(resolvedFileName);
      breakpoint.resolvedLocation = resolvedLocation;
      return true;
    }
  }

  return false;
}

void Debugger::unresolveBreakpointLocation(Breakpoint &breakpoint) {
  assert(breakpoint.isResolved() && "Breakpoint already unresolved");
  if (breakpoint.enabled) {
    unsetUserBreakpoint(breakpoint);
  }
  breakpoint.resolvedLocation.reset();
  breakpoint.codeBlock = nullptr;
  breakpoint.offset = -1;
}

auto Debugger::getSourceMappingUrl(ScriptID scriptId) const -> String {
  for (auto &runtimeModule : runtime_.getRuntimeModules()) {
    if (!runtimeModule.isInitialized()) {
                              
      continue;
    }

    auto *debugInfo = runtimeModule.getBytecode()->getDebugInfo();
    if (!debugInfo) {
                                                  
      continue;
    }

    for (const auto &file : debugInfo->viewFiles()) {
      if (resolveScriptId(&runtimeModule, file.filenameId) == scriptId) {
        if (file.sourceMappingUrlId == fhd::kInvalidBreakpoint) {
          return "";
        }
        return getFileNameAsUTF8(
            runtime_, &runtimeModule, file.sourceMappingUrlId);
      }
    }
  }

  return "";
}

auto Debugger::getLoadedScripts() const -> std::vector<SourceLocation> {
  std::vector<SourceLocation> loadedScripts;
  for (auto &runtimeModule : runtime_.getRuntimeModules()) {
    if (!runtimeModule.isInitialized()) {
                              
      continue;
    }
                                                           
    if (runtimeModule.getLazyRootModule() != &runtimeModule) {
      continue;
    }

    auto *debugInfo = runtimeModule.getBytecode()->getDebugInfo();
    if (!debugInfo) {
                                                  
      continue;
    }

                                                                              
                              
    auto globalFunctionIndex =
        runtimeModule.getBytecode()->getGlobalFunctionIndex();
    auto globalCodeBlock =
        runtimeModule.getCodeBlockMayAllocate(globalFunctionIndex);
    OptValue<hbc::DebugSourceLocation> debugSrcLoc =
        globalCodeBlock->getSourceLocation();
    if (!debugSrcLoc) {
      continue;
    }

    SourceLocation loc;
    loc.fileId = resolveScriptId(&runtimeModule, debugSrcLoc->filenameId);
    loc.line = debugSrcLoc->line;
    loc.column = debugSrcLoc->column;
    loc.fileName = debugInfo->getFilenameByID(debugSrcLoc->filenameId);

    loadedScripts.push_back(loc);
  }
  return loadedScripts;
}

auto Debugger::resolveScriptId(
    RuntimeModule *runtimeModule,
    uint32_t filenameId) const -> ScriptID {
  return runtimeModule->getScriptID();
}

}                
}                    

#endif                          

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/JSError.h"

#include "hermes/BCGen/HBC/DebugInfo.h"
#include "hermes/Support/OptValue.h"
#include "hermes/VM/BuildMetadata.h"
#include "hermes/VM/Callable.h"
#include "hermes/VM/JSArray.h"
#include "hermes/VM/JSCallSite.h"
#include "hermes/VM/PropertyAccessor.h"
#include "hermes/VM/RuntimeModule-inline.h"
#include "hermes/VM/StackFrame-inline.h"
#include "hermes/VM/StringBuilder.h"
#include "hermes/VM/StringView.h"

#include "llvh/ADT/ScopeExit.h"
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {
                                                                                
                

const ObjectVTable JSError::vt{
    VTable(
        CellKind::JSErrorKind,
        cellSize<JSError>(),
        JSError::_finalizeImpl,
        JSError::_mallocSizeImpl),
    JSError::_getOwnIndexedRangeImpl,
    JSError::_haveOwnIndexedImpl,
    JSError::_getOwnIndexedPropertyFlagsImpl,
    JSError::_getOwnIndexedImpl,
    JSError::_setOwnIndexedImpl,
    JSError::_deleteOwnIndexedImpl,
    JSError::_checkAllOwnIndexedImpl,
};

void JSErrorBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  mb.addJSObjectOverlapSlots(JSObject::numOverlapSlots<JSError>());
  JSObjectBuildMeta(cell, mb);
  const auto *self = static_cast<const JSError *>(cell);
  mb.setVTable(&JSError::vt);
  mb.addField("funcNames", &self->funcNames_);
  mb.addField("domains", &self->domains_);
}

                                                         
                                                                          
                           
                                    
static llvh::Optional<Handle<JSError>> getErrorFromStackTarget(
    Runtime &runtime,
    Handle<JSObject> targetHandle) {
  MutableHandle<JSObject> mutHnd =
      runtime.makeMutableHandle<JSObject>(targetHandle.get());
  targetHandle = mutHnd;

  while (targetHandle) {
    NamedPropertyDescriptor desc;
    bool exists = JSObject::getOwnNamedDescriptor(
        targetHandle,
        runtime,
        Predefined::getSymbolID(Predefined::InternalPropertyCapturedError),
        desc);
    if (exists) {
      auto sv = JSObject::getNamedSlotValueUnsafe(*targetHandle, runtime, desc);
      return runtime.makeHandle(vmcast<JSError>(sv.getObject(runtime)));
    }
    if (vmisa<JSError>(*targetHandle)) {
      return Handle<JSError>::vmcast(targetHandle);
    }

    mutHnd.set(targetHandle->getParent(runtime));
  }
  return llvh::None;
}

CallResult<HermesValue>
errorStackGetter(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);

  auto targetHandle = args.dyncastThis<JSObject>();
  auto errorHandleOpt = getErrorFromStackTarget(runtime, targetHandle);
  if (!errorHandleOpt.hasValue()) {
    return HermesValue::encodeUndefinedValue();
  }
  auto errorHandle = *errorHandleOpt;
  if (!errorHandle->stacktrace_) {
                                                                  
                                                                        
                                                                 
                 
    return HermesValue::encodeStringValue(
        runtime.getPredefinedString(Predefined::emptyString));
  }
                                                               
                                                                 
  vm::ScopedNativeDepthReducer reducer(runtime);
  SmallU16String<32> stack;

  auto errorCtor = Handle<JSObject>::vmcast(&runtime.errorConstructor);

  auto prepareStackTraceRes = JSObject::getNamed_RJS(
      errorCtor,
      runtime,
      Predefined::getSymbolID(Predefined::prepareStackTrace),
      PropOpFlags().plusThrowOnError());

  if (prepareStackTraceRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }

  MutableHandle<> stackTraceFormatted{runtime};

  auto prepareStackTrace = Handle<Callable>::dyn_vmcast(
      runtime.makeHandle(std::move(*prepareStackTraceRes)));
  if (LLVM_UNLIKELY(prepareStackTrace && !runtime.formattingStackTrace())) {
    const auto &recursionGuard = llvh::make_scope_exit(
        [&runtime]() { runtime.setFormattingStackTrace(false); });
    (void)recursionGuard;

    runtime.setFormattingStackTrace(true);

    auto callSitesRes = JSError::constructCallSitesArray(runtime, errorHandle);

    if (LLVM_UNLIKELY(callSitesRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    auto prepareRes = Callable::executeCall2(
        prepareStackTrace,
        runtime,
        runtime.getNullValue(),
        targetHandle.getHermesValue(),
        *callSitesRes);
    if (LLVM_UNLIKELY(prepareRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    stackTraceFormatted = std::move(*prepareRes);
  } else {
    if (JSError::constructStackTraceString_RJS(
            runtime, errorHandle, targetHandle, stack) ==
        ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }

    auto strRes = StringPrimitive::create(runtime, stack);
    if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
                                                                           
                                                                    
      stackTraceFormatted = HermesValue::encodeStringValue(
          runtime.getPredefinedString(Predefined::stacktraceTooLong));
      runtime.clearThrownValue();
    } else {
      stackTraceFormatted = std::move(*strRes);
    }
  }

                                                                             
              
  DefinePropertyFlags dpf = DefinePropertyFlags::getNewNonEnumerableFlags();
  if (JSObject::defineOwnProperty(
          targetHandle,
          runtime,
          Predefined::getSymbolID(Predefined::stack),
          dpf,
          stackTraceFormatted) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  return *stackTraceFormatted;
}

CallResult<HermesValue>
errorStackSetter(void *, Runtime &runtime, NativeArgs args) {
  auto res = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto selfHandle = runtime.makeHandle<JSObject>(res.getValue());

                                                        
  DefinePropertyFlags dpf = DefinePropertyFlags::getNewNonEnumerableFlags();
  if (JSObject::defineOwnProperty(
          selfHandle,
          runtime,
          Predefined::getSymbolID(Predefined::stack),
          dpf,
          args.getArgHandle(0)) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }

  return HermesValue::encodeUndefinedValue();
}

PseudoHandle<JSError> JSError::create(
    Runtime &runtime,
    Handle<JSObject> parentHandle) {
  return create(runtime, parentHandle,               true);
}

PseudoHandle<JSError> JSError::createUncatchable(
    Runtime &runtime,
    Handle<JSObject> parentHandle) {
  return create(runtime, parentHandle,               false);
}

PseudoHandle<JSError> JSError::create(
    Runtime &runtime,
    Handle<JSObject> parentHandle,
    bool catchable) {
  auto *cell = runtime.makeAFixed<JSError, HasFinalizer::Yes>(
      runtime,
      parentHandle,
      runtime.getHiddenClassForPrototype(
          *parentHandle, numOverlapSlots<JSError>()),
      catchable);
  return JSObjectInit::initToPseudoHandle(runtime, cell);
}

CallResult<Handle<StringPrimitive>> JSError::toString(
    Handle<JSObject> O,
    Runtime &runtime) {
                                          

                                                     

                                     
  auto propRes = JSObject::getNamed_RJS(
      O, runtime, Predefined::getSymbolID(Predefined::name), PropOpFlags());
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<> name = runtime.makeHandle(std::move(*propRes));

                                                                          
                    
  MutableHandle<StringPrimitive> nameStr{runtime};
  if (name->isUndefined()) {
    nameStr = runtime.getPredefinedString(Predefined::Error);
  } else {
    auto strRes = toString_RJS(runtime, name);
    if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    nameStr = strRes->get();
  }

                                       
  if (LLVM_UNLIKELY(
          (propRes = JSObject::getNamed_RJS(
               O,
               runtime,
               Predefined::getSymbolID(Predefined::message),
               PropOpFlags())) == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<> msg = runtime.makeHandle(std::move(*propRes));

                                                         
                                             
  MutableHandle<StringPrimitive> msgStr{runtime};
  if (msg->isUndefined()) {
                                                             
    msgStr = runtime.getPredefinedString(Predefined::emptyString);
  } else {
    auto strRes = toString_RJS(runtime, msg);
    if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    msgStr = strRes->get();
  }

                                                
  if (nameStr->getStringLength() == 0) {
    return msgStr;
  }

                                                
  if (msgStr->getStringLength() == 0) {
    return nameStr;
  }

                                                                              
                                           
  SafeUInt32 length{nameStr->getStringLength()};
  length.add(2);
  length.add(msgStr->getStringLength());
  CallResult<StringBuilder> builderRes =
      StringBuilder::createStringBuilder(runtime, length);
  if (LLVM_UNLIKELY(builderRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto builder = std::move(*builderRes);
  builder.appendStringPrim(nameStr);
  builder.appendASCIIRef({": ", 2});
  builder.appendStringPrim(msgStr);
  return builder.getStringPrimitive();
}

ExecutionStatus JSError::setMessage(
    Handle<JSError> selfHandle,
    Runtime &runtime,
    Handle<> message) {
  auto stringMessage = Handle<StringPrimitive>::dyn_vmcast(message);
  if (LLVM_UNLIKELY(!stringMessage)) {
    auto strRes = toString_RJS(runtime, message);
    if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    stringMessage = runtime.makeHandle(std::move(*strRes));
  }

  DefinePropertyFlags dpf = DefinePropertyFlags::getNewNonEnumerableFlags();
  return JSObject::defineOwnProperty(
             selfHandle,
             runtime,
             Predefined::getSymbolID(Predefined::message),
             dpf,
             stringMessage)
      .getStatus();
}

                                                                              
                                                                              
                                                                       
                                                                              
                                                                      
                                              
                                                    
static Handle<PropStorage> getCallStackFunctionNames(
    Runtime &runtime,
    bool skipTopFrame,
    size_t sizeHint) {
  auto arrRes = PropStorage::create(runtime, sizeHint);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    runtime.clearThrownValue();
    return Runtime::makeNullHandle<PropStorage>();
  }
  MutableHandle<PropStorage> names{runtime, vmcast<PropStorage>(*arrRes)};

  GCScope gcScope(runtime);
  MutableHandle<> name{runtime};
  auto marker = gcScope.createMarker();

  uint32_t frameIndex = 0;
  uint32_t namesIndex = 0;
  for (StackFramePtr cf : runtime.getStackFrames()) {
    if (frameIndex++ == 0 && skipTopFrame)
      continue;

    name = HermesValue::encodeUndefinedValue();
    if (auto callableHandle = Handle<Callable>::dyn_vmcast(
            Handle<>(&cf.getCalleeClosureOrCBRef()))) {
      NamedPropertyDescriptor desc;
      JSObject *propObj = JSObject::getNamedDescriptorPredefined(
          callableHandle, runtime, Predefined::displayName, desc);

      if (!propObj) {
        propObj = JSObject::getNamedDescriptorPredefined(
            callableHandle, runtime, Predefined::name, desc);
      }

      if (propObj && !desc.flags.accessor &&
          LLVM_LIKELY(!desc.flags.proxyObject) &&
          LLVM_LIKELY(!desc.flags.hostObject)) {
        name = JSObject::getNamedSlotValueUnsafe(propObj, runtime, desc)
                   .unboxToHV(runtime);
      } else if (desc.flags.proxyObject) {
        name = HermesValue::encodeStringValue(
            runtime.getPredefinedString(Predefined::proxyTrap));
      }
    } else if (!cf.getCalleeClosureOrCBRef().isObject()) {
                                                                                
                                
      auto *cb =
          cf.getCalleeClosureOrCBRef().getNativePointer<const CodeBlock>();
      if (cb->getNameMayAllocate().isValid())
        name = HermesValue::encodeStringValue(
            runtime.getStringPrimFromSymbolID(cb->getNameMayAllocate()));
    }
    if (PropStorage::resize(names, runtime, namesIndex + 1) ==
        ExecutionStatus::EXCEPTION) {
      runtime.clearThrownValue();
      return Runtime::makeNullHandle<PropStorage>();
    }
    auto shv =
        SmallHermesValue::encodeHermesValue(name.getHermesValue(), runtime);
    names->set(namesIndex, shv, runtime.getHeap());
    ++namesIndex;
    gcScope.flushToMarker(marker);
  }

  return std::move(names);
}

ExecutionStatus JSError::recordStackTrace(
    Handle<JSError> selfHandle,
    Runtime &runtime,
    bool skipTopFrame,
    CodeBlock *codeBlock,
    const Inst *ip) {
  if (selfHandle->stacktrace_)
    return ExecutionStatus::RETURNED;

  auto frames = runtime.getStackFrames();

                                                                         
                           
  if (!skipTopFrame && !codeBlock && frames.begin() != frames.end() &&
      frames.begin()->getCalleeCodeBlock(runtime)) {
    return ExecutionStatus::RETURNED;
  }

  StackTracePtr stack{new StackTrace()};
  auto domainsRes = ArrayStorageSmall::create(runtime, 1);
  if (LLVM_UNLIKELY(domainsRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto domains = runtime.makeMutableHandle<ArrayStorageSmall>(
      vmcast<ArrayStorageSmall>(*domainsRes));

                                                                               
                                                                            
                                                                            
                 
  auto addDomain = [&domains,
                    &runtime](CodeBlock *codeBlock) -> ExecutionStatus {
    GCScopeMarkerRAII marker{runtime};
    Handle<Domain> domain = codeBlock->getRuntimeModule()->getDomain(runtime);
    if (domains->size() > 0 &&
        vmcast<Domain>(domains->at(domains->size() - 1).getObject(runtime)) ==
            domain.get()) {
      return ExecutionStatus::RETURNED;
    }
    return ArrayStorageSmall::push_back(domains, runtime, domain);
  };

  if (!skipTopFrame) {
    if (codeBlock) {
      stack->emplace_back(codeBlock, codeBlock->getOffsetOf(ip));
      if (LLVM_UNLIKELY(addDomain(codeBlock) == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
    } else {
      stack->emplace_back(nullptr, 0);
    }
  }

  const StackFramePtr framesEnd = *runtime.getStackFrames().end();

                            
                                                          
  for (StackFramePtr cf : runtime.getStackFrames()) {
    CodeBlock *savedCodeBlock = cf.getSavedCodeBlock();
    const Inst *const savedIP = cf.getSavedIP();
                                                                        
                                                                            
                                                                               
                       
    StackFramePtr prev = cf->getPreviousFrame();
    if (prev != framesEnd) {
      if (CodeBlock *parentCB = prev->getCalleeCodeBlock(runtime)) {
        savedCodeBlock = parentCB;
      }
    }
    if (savedCodeBlock && savedIP) {
      stack->emplace_back(savedCodeBlock, savedCodeBlock->getOffsetOf(savedIP));
      if (LLVM_UNLIKELY(
              addDomain(savedCodeBlock) == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
    } else {
      stack->emplace_back(nullptr, 0);
    }
  }
  selfHandle->domains_.set(runtime, domains.get(), runtime.getHeap());

                           
  stack->pop_back();

  auto funcNames =
      getCallStackFunctionNames(runtime, skipTopFrame, stack->size());

                                                                     
  assert(
      (!funcNames || funcNames->size() == stack->size()) &&
      "Function names and stack trace must have same size.");

  selfHandle->stacktrace_ = std::move(stack);
  selfHandle->funcNames_.set(runtime, *funcNames, runtime.getHeap());
  return ExecutionStatus::RETURNED;
}

                                                                        
OptValue<hbc::DebugSourceLocation> JSError::getDebugInfo(
    CodeBlock *codeBlock,
    uint32_t bytecodeOffset) {
  auto offset = codeBlock->getDebugSourceLocationsOffset();
  if (!offset.hasValue()) {
    return llvh::None;
  }

  return codeBlock->getRuntimeModule()
      ->getBytecode()
      ->getDebugInfo()
      ->getLocationForAddress(offset.getValue(), bytecodeOffset);
}

Handle<StringPrimitive> JSError::getFunctionNameAtIndex(
    Runtime &runtime,
    Handle<JSError> selfHandle,
    size_t index) {
  IdentifierTable &idt = runtime.getIdentifierTable();
  MutableHandle<StringPrimitive> name{
      runtime, runtime.getPredefinedString(Predefined::emptyString)};

                                                                    
  if (selfHandle->funcNames_) {
    assert(
        index < selfHandle->funcNames_.getNonNull(runtime)->size() &&
        "Index out of bounds");
    name = dyn_vmcast<StringPrimitive>(
        selfHandle->funcNames_.getNonNull(runtime)->at(index).unboxToHV(
            runtime));
  }

  if (!name || name->getStringLength() == 0) {
                                                                          
                                                           
    if (const CodeBlock *codeBlock =
            selfHandle->stacktrace_->at(index).codeBlock) {
      name = idt.getStringPrim(runtime, codeBlock->getNameMayAllocate());
    }
  }

  if (!name || name->getStringLength() == 0) {
    return runtime.makeNullHandle<StringPrimitive>();
  }

  return std::move(name);
}

bool JSError::appendFunctionNameAtIndex(
    Runtime &runtime,
    Handle<JSError> selfHandle,
    size_t index,
    llvh::SmallVectorImpl<char16_t> &str) {
  auto name = getFunctionNameAtIndex(runtime, selfHandle, index);

  if (!name)
    return false;

  name->appendUTF16String(str);
  return true;
}

ExecutionStatus JSError::constructStackTraceString_RJS(
    Runtime &runtime,
    Handle<JSError> selfHandle,
    Handle<JSObject> targetHandle,
    SmallU16String<32> &stack) {
                                                                             
                    
  ScopedNativeDepthTracker depthTracker(runtime);
  if (LLVM_UNLIKELY(depthTracker.overflowed())) {
    return runtime.raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  }

  GCScope gcScope(runtime);
                                                    
                                        
  CallResult<Handle<StringPrimitive>> res =
      JSError::toString(targetHandle, runtime);
                                                                           
                                                                            
          
  const bool targetHandleToStringThrew = res == ExecutionStatus::EXCEPTION;

  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
                                                                              
                                                                        
    if (!isUncatchableError(runtime.getThrownValue())) {
      HermesValue thrownValue = runtime.getThrownValue();
      if (thrownValue.isObject()) {
                                                                                
                                                        
        runtime.clearThrownValue();
        res = JSError::toString(
            runtime.makeHandle<JSObject>(thrownValue), runtime);
      }
    }
  }

  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
                                                                               
    if (isUncatchableError(runtime.getThrownValue())) {
                                                                            
      return ExecutionStatus::EXCEPTION;
    }
                                                                          
              
    runtime.clearThrownValue();
                                                   
    stack.append(u"<error>");
  } else {
    if (targetHandleToStringThrew) {
      stack.append(u"<while converting error to string: ");
    }
    res->get()->appendUTF16String(stack);
    if (targetHandleToStringThrew) {
      stack.append(u">");
    }
  }

                                                                               
                                                                                
                                                                            
                              
  llvh::DenseMap<const CodeBlock *, uint32_t> virtualOffsetCache;

                                                                    
  auto marker = gcScope.createMarker();
  for (size_t index = 0,
              max = selfHandle->stacktrace_->size() -
           selfHandle->firstExposedFrameIndex_;
       index < max;
       index++) {
    char buf[NUMBER_TO_STRING_BUF_SIZE];

                                                                           
                                                                                
    static constexpr unsigned PRINT_HEAD = 50;
    static constexpr unsigned PRINT_TAIL = 50;
    if (LLVM_UNLIKELY(max > PRINT_HEAD + PRINT_TAIL)) {
      if (index == PRINT_HEAD) {
        stack.append("\n    ... skipping ");
        numberToString(max - PRINT_HEAD - PRINT_TAIL, buf, sizeof(buf));
        stack.append(buf);
        stack.append(" frames");
        continue;
      }

                                
      if (index > PRINT_HEAD && index < max - PRINT_TAIL) {
        index = max - PRINT_TAIL;
      }
    }

    const size_t absIndex = index + selfHandle->firstExposedFrameIndex_;
    const StackTraceInfo &sti = selfHandle->stacktrace_->at(absIndex);
    gcScope.flushToMarker(marker);
                                                                          
                                                         

    stack.append(u"\n    at ");

    if (!appendFunctionNameAtIndex(runtime, selfHandle, absIndex, stack))
      stack.append(u"anonymous");

                                                                             
                         
    if (!sti.codeBlock) {
      stack.append(u" (native)");
      continue;
    }

                                    
    int32_t lineNo;
    int32_t columnNo;
    OptValue<SymbolID> fileName;
    bool isAddress = false;
    OptValue<hbc::DebugSourceLocation> location =
        getDebugInfo(sti.codeBlock, sti.bytecodeOffset);
    if (location) {
                                                     
      lineNo = location->line;
      columnNo = location->column;
    } else {
                                                                 
                                                                         
                                                                               
                                                                                
                                                          
                                                                   
                                                                              
                                                                   
      auto pair = virtualOffsetCache.insert({sti.codeBlock, 0});
      uint32_t &virtualOffset = pair.first->second;
      if (pair.second) {
                                                             
        virtualOffset = sti.codeBlock->getVirtualOffset();
      }
                                                                  
                             
      lineNo =
          sti.codeBlock->getRuntimeModule()->getBytecode()->getSegmentID() + 1;
      columnNo = sti.bytecodeOffset + virtualOffset;
      isAddress = true;
    }

    stack.append(u" (");
    if (isAddress)
      stack.append(u"address at ");

                                                                               
                                                                            
                      
    RuntimeModule *runtimeModule = sti.codeBlock->getRuntimeModule();
    if (location) {
      stack.append(
          runtimeModule->getBytecode()->getDebugInfo()->getFilenameByID(
              location->filenameId));
    } else {
      auto sourceURL = runtimeModule->getSourceURL();
      stack.append(sourceURL.empty() ? "unknown" : sourceURL);
    }
    stack.push_back(u':');

    numberToString(lineNo, buf, NUMBER_TO_STRING_BUF_SIZE);
    stack.append(buf);

    stack.push_back(u':');

    numberToString(columnNo, buf, NUMBER_TO_STRING_BUF_SIZE);
    stack.append(buf);

    stack.push_back(u')');
  }
  return ExecutionStatus::RETURNED;
}

CallResult<HermesValue> JSError::constructCallSitesArray(
    Runtime &runtime,
    Handle<JSError> selfHandle) {
  auto max = selfHandle->stacktrace_
      ? selfHandle->stacktrace_->size() - selfHandle->firstExposedFrameIndex_
      : 0;
  auto arrayRes = JSArray::create(runtime, max, 0);
  if (LLVM_UNLIKELY(arrayRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  auto array = std::move(*arrayRes);
  if (!selfHandle->stacktrace_) {
    return array.getHermesValue();
  }

  size_t callSiteIndex = 0;

  GCScope gcScope(runtime);
  auto marker = gcScope.createMarker();

  for (size_t index = 0; index < max; index++) {
                                                            
                                                                                
                                                                               
                                                                

    auto absIndex = index + selfHandle->firstExposedFrameIndex_;

                                                                              
                                                                             
    auto callSiteRes = JSCallSite::create(runtime, selfHandle, absIndex);
    if (callSiteRes == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    auto callSite = runtime.makeHandle(*callSiteRes);

    JSArray::setElementAt(array, runtime, callSiteIndex++, callSite);

    gcScope.flushToMarker(marker);
  }

  auto cr =
      JSArray::setLengthProperty(array, runtime, callSiteIndex, PropOpFlags{});
  (void)cr;
  assert(
      cr != ExecutionStatus::EXCEPTION && *cr && "JSArray::setLength() failed");

  return array.getHermesValue();
}

                                                                       
                                                    
static const CodeBlock *getLeafCodeBlock(
    Handle<Callable> callableHandle,
    Runtime &runtime) {
  const Callable *callable = callableHandle.get();
  while (callable) {
    if (auto *asFunction = dyn_vmcast<const JSFunction>(callable)) {
      return asFunction->getCodeBlock(runtime);
    }
    if (auto *asBoundFunction = dyn_vmcast<const BoundFunction>(callable)) {
      callable = asBoundFunction->getTarget(runtime);
    } else {
      break;
    }
  }

  return nullptr;
}

void JSError::popFramesUntilInclusive(
    Runtime &runtime,
    Handle<JSError> selfHandle,
    Handle<Callable> callableHandle) {
  assert(
      selfHandle->stacktrace_ && "Cannot pop frames when stacktrace_ is null");
                                                                             
                  
  selfHandle->firstExposedFrameIndex_ = selfHandle->stacktrace_->size();
  auto codeBlock = getLeafCodeBlock(callableHandle, runtime);
  if (!codeBlock) {
    return;
  }
  for (size_t index = 0, max = selfHandle->stacktrace_->size(); index < max;
       index++) {
    const StackTraceInfo &sti = selfHandle->stacktrace_->at(index);
    if (sti.codeBlock == codeBlock) {
      selfHandle->firstExposedFrameIndex_ = index + 1;
      break;
    }
  }
}

void JSError::_finalizeImpl(GCCell *cell, GC &) {
  JSError *self = vmcast<JSError>(cell);
  self->~JSError();
}

size_t JSError::_mallocSizeImpl(GCCell *cell) {
  JSError *self = vmcast<JSError>(cell);
  auto stacktrace = self->stacktrace_.get();
  return stacktrace ? sizeof(StackTrace) +
          stacktrace->capacity() * sizeof(StackTrace::value_type)
                    : 0;
}

}                
}                    

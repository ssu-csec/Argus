/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/JSCallableProxy.h"

#include "hermes/VM/JSArray.h"

namespace hermes {
namespace vm {

                                                                                
                        

const CallableVTable JSCallableProxy::vt{
    {
        VTable(CellKind::JSCallableProxyKind, cellSize<JSCallableProxy>()),
        JSCallableProxy::_getOwnIndexedRangeImpl,
        JSCallableProxy::_haveOwnIndexedImpl,
        JSCallableProxy::_getOwnIndexedPropertyFlagsImpl,
        JSCallableProxy::_getOwnIndexedImpl,
        JSCallableProxy::_setOwnIndexedImpl,
        JSCallableProxy::_deleteOwnIndexedImpl,
        JSCallableProxy::_checkAllOwnIndexedImpl,
    },
    JSCallableProxy::_newObjectImpl,
    JSCallableProxy::_callImpl,
};

void JSCallableProxyBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  mb.addJSObjectOverlapSlots(JSObject::numOverlapSlots<JSCallableProxy>());
  NativeFunctionBuildMeta(cell, mb);
  const auto *self = static_cast<const JSCallableProxy *>(cell);
  mb.setVTable(&JSCallableProxy::vt);
  mb.addField("@target", &self->slots_.target);
  mb.addField("@handler", &self->slots_.handler);
}

PseudoHandle<JSCallableProxy> JSCallableProxy::create(Runtime &runtime) {
  auto *cproxy = runtime.makeAFixed<JSCallableProxy>(
      runtime,
      HandleRootOwner::makeNullHandle<JSObject>(),
      runtime.getHiddenClassForPrototype(
          nullptr, JSObject::numOverlapSlots<JSCallableProxy>()));

  cproxy->flags_.proxyObject = true;

  return JSObjectInit::initToPseudoHandle(runtime, cproxy);
}

void JSCallableProxy::setTargetAndHandler(
    Runtime &runtime,
    Handle<JSObject> target,
    Handle<JSObject> handler) {
  slots_.target.set(runtime, target.get(), runtime.getHeap());
  slots_.handler.set(runtime, handler.get(), runtime.getHeap());
}

CallResult<bool> JSCallableProxy::isConstructor(Runtime &runtime) {
  ScopedNativeDepthTracker depthTracker(runtime);
  if (LLVM_UNLIKELY(depthTracker.overflowed())) {
    return runtime.raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  }
  return vm::isConstructor(
      runtime, vmcast_or_null<Callable>(slots_.target.get(runtime)));
}

CallResult<HermesValue>
JSCallableProxy::_proxyNativeCall(void *, Runtime &runtime, NativeArgs) {
  GCScope gcScope(runtime);
                                                                       
                          
  StackFramePtr callerFrame = runtime.getCurrentFrame();
  auto selfHandle =
      Handle<JSCallableProxy>::vmcast(&callerFrame.getCalleeClosureOrCBRef());
                                                                  
                                                                    
                                                                   
               
                                                                            
  auto &slots = detail::slots(*selfHandle);
  Handle<JSObject> target = runtime.makeHandle(slots.target);
  Handle<JSObject> handler = runtime.makeHandle(slots.handler);
  Predefined::Str trapName = callerFrame->isConstructorCall()
      ? Predefined::construct
      : Predefined::apply;
  CallResult<Handle<Callable>> trapRes =
      detail::findTrap(selfHandle, runtime, trapName);
  if (trapRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                  
  if (!*trapRes) {
                                                               
         
                                                  
                                                                 
    MutableHandle<> receiver{runtime, callerFrame.getThisArgRef()};
    if (callerFrame->isConstructorCall()) {
      auto prepared = Callable::prepareThisForConstruct_RJS(
          Handle<Callable>::vmcast(target), runtime,
          Handle<Callable>::vmcast(&callerFrame.getNewTargetRef()));
      if (prepared == ExecutionStatus::EXCEPTION)
        return ExecutionStatus::EXCEPTION;
      receiver = prepared->getHermesValue();
    }
    ScopedNativeCallFrame newFrame{
        runtime,
        callerFrame.getArgCount(),
        target.getHermesValue(),
        callerFrame.getNewTargetRef(),
        receiver.getHermesValue()};
    if (LLVM_UNLIKELY(newFrame.overflowed()))
      return runtime.raiseStackOverflow(
          Runtime::StackOverflowKind::NativeStack);
    std::uninitialized_copy_n(
        callerFrame.argsBegin(),
        callerFrame.getArgCount(),
        newFrame->argsBegin());
                                                                     
                                                                     
                       
    auto res = Callable::call(Handle<Callable>::vmcast(target), runtime);
    if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    return callerFrame->isConstructorCall() && !res->get().isObject()
        ? receiver.getHermesValue() : res->get();
  }
                                                           
  CallResult<Handle<JSArray>> argArrayRes = JSArray::create(
      runtime, callerFrame->getArgCount(), callerFrame->getArgCount());
  if (LLVM_UNLIKELY(argArrayRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<JSArray> argArray = *argArrayRes;
  JSArray::setStorageEndIndex(argArray, runtime, callerFrame->getArgCount());
  for (uint32_t i = 0; i < callerFrame->getArgCount(); ++i) {
    const auto shv =
        SmallHermesValue::encodeHermesValue(callerFrame.getArgRef(i), runtime);
    JSArray::unsafeSetExistingElementAt(*argArray, runtime, i, shv);
  }
                                                                             
  if (callerFrame->isConstructorCall()) {
    CallResult<PseudoHandle<>> newObjRes = Callable::executeCall3(
        *trapRes,
        runtime,
        handler,
        target.getHermesValue(),
        argArray.getHermesValue(),
        callerFrame.getNewTargetRef());
    if (LLVM_UNLIKELY(newObjRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
                                                                     
    if (!vmisa<JSObject>(newObjRes->get())) {
      return runtime.raiseTypeError("Proxy construct trap returned non-Object");
    }
                         
    return newObjRes->get();
  } else {
                                                                           
    auto res = Callable::executeCall3(
        *trapRes,
        runtime,
        handler,
        target.getHermesValue(),
        callerFrame.getThisArgRef(),
        argArray.getHermesValue());
    if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    return res->get();
  }
}

CallResult<PseudoHandle<JSObject>> JSCallableProxy::_newObjectImpl(
    Handle<Callable> callable,
    Runtime &runtime,
    Handle<JSObject> protoHandle) {
  CallResult<bool> isConstructorRes =
      vmcast<JSCallableProxy>(*callable)->isConstructor(runtime);
  if (LLVM_UNLIKELY(isConstructorRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if (!*isConstructorRes) {
    return runtime.raiseTypeError("Function is not a constructor");
  }
  return vm::Callable::newObject(
      Handle<Callable>::vmcast(
          runtime.makeHandle(detail::slots(*callable).target)),
      runtime,
      protoHandle);
}

}                
}                    

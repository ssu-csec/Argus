/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/JSProxy.h"

#include "hermes/VM/ArrayLike.h"
#include "hermes/VM/Callable.h"
#include "hermes/VM/JSArray.h"
#include "hermes/VM/JSCallableProxy.h"
#include "hermes/VM/OrderedHashMap.h"
#include "hermes/VM/PropertyAccessor.h"

#include "llvh/ADT/SmallSet.h"

#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

namespace detail {

ProxySlots &slots(JSObject *self) {
  if (auto *proxy = dyn_vmcast<JSProxy>(self)) {
    return proxy->slots_;
  } else {
    auto *cproxy = dyn_vmcast<JSCallableProxy>(self);
    assert(
        cproxy && "JSProxy methods must be passed JSProxy or JSCallableProxy");
    return cproxy->slots_;
  }
}

CallResult<Handle<Callable>>
findTrap(Handle<JSObject> selfHandle, Runtime &runtime, Predefined::Str name) {
                                          
                                                        
  JSObject *handlerPtr = detail::slots(*selfHandle).handler.get(runtime);
  if (!handlerPtr) {
    return runtime.raiseTypeError("Proxy handler is null");
  }
                                        
                                        
                                                   
  CallResult<PseudoHandle<>> trapVal = [&]() {
    GCScope gcScope(runtime);
    Handle<JSObject> handler = runtime.makeHandle(handlerPtr);
    return JSObject::getNamed_RJS(
        handler, runtime, Predefined::getSymbolID(name));
  }();

  if (trapVal == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  if ((*trapVal)->isUndefined() || (*trapVal)->isNull()) {
    return Runtime::makeNullHandle<Callable>();
  }

  if (!vmisa<Callable>(trapVal->get())) {
    return runtime.raiseTypeErrorForValue(
        runtime.makeHandle(std::move(*trapVal)),
        " is not a Proxy trap function");
  }
  return runtime.makeHandle<Callable>(trapVal->get());
}

}                    

                                                                                
                

const ObjectVTable JSProxy::vt{
    VTable(CellKind::JSProxyKind, cellSize<JSProxy>()),
    JSProxy::_getOwnIndexedRangeImpl,
    JSProxy::_haveOwnIndexedImpl,
    JSProxy::_getOwnIndexedPropertyFlagsImpl,
    JSProxy::_getOwnIndexedImpl,
    JSProxy::_setOwnIndexedImpl,
    JSProxy::_deleteOwnIndexedImpl,
    JSProxy::_checkAllOwnIndexedImpl,
};

void JSProxyBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  mb.addJSObjectOverlapSlots(JSObject::numOverlapSlots<JSProxy>());
  JSObjectBuildMeta(cell, mb);
  const auto *self = static_cast<const JSProxy *>(cell);
  mb.setVTable(&JSProxy::vt);
  mb.addField("@target", &self->slots_.target);
  mb.addField("@handler", &self->slots_.handler);
}

PseudoHandle<JSProxy> JSProxy::create(Runtime &runtime) {
  JSProxy *proxy = runtime.makeAFixed<JSProxy>(
      runtime,
                                                                            
              
      Runtime::makeNullHandle<JSObject>(),
      runtime.getHiddenClassForPrototype(
          nullptr, JSObject::numOverlapSlots<JSProxy>()));

  proxy->flags_.proxyObject = true;

  return JSObjectInit::initToPseudoHandle(runtime, proxy);
}

void JSProxy::setTargetAndHandler(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    Handle<JSObject> target,
    Handle<JSObject> handler) {
  auto &slots = detail::slots(*selfHandle);
  slots.target.set(runtime, target.get(), runtime.getHeap());
  slots.handler.set(runtime, handler.get(), runtime.getHeap());
}

namespace {

void completePropertyDescriptor(DefinePropertyFlags &desc) {
  if ((desc.setValue || desc.setWritable) ||
      (!desc.setGetter && !desc.setSetter)) {
    if (!desc.setWritable) {
      desc.writable = false;
    }
  }
  if (!desc.setEnumerable) {
    desc.enumerable = false;
  }
  if (!desc.setConfigurable) {
    desc.configurable = false;
  }
}

                                             
                                             
                                                                    
                                                                   
                                               
ExecutionStatus isCompatiblePropertyDescriptor(
    Runtime &runtime,
    const DefinePropertyFlags &desc,
    Handle<> descValueOrAccessor,
    const ComputedPropertyDescriptor &current,
    Handle<> currentValueOrAccessor) {
                                                  
  if (!current.flags.configurable) {
                                                                           
             
    if (desc.setConfigurable && desc.configurable) {
      return runtime.raiseTypeError(
          "trap result is configurable but target property is non-configurable");
    }
                                                                  
                                                                  
                           
    if (desc.setEnumerable && desc.enumerable != current.flags.enumerable) {
      return runtime.raiseTypeError(
          TwineChar16("trap result is ") + (desc.enumerable ? "" : "not ") +
          "enumerable but target property is " +
          (current.flags.enumerable ? "" : "not ") + "enumerable");
    }
  }

                                                                                
  bool descIsAccessor = desc.setSetter || desc.setGetter;
  bool descIsData = desc.setValue || desc.setWritable;
  assert(
      (!descIsData || !descIsAccessor) &&
      "descriptor cannot be both Data and Accessor");
  if (!descIsData && !descIsAccessor) {
    return ExecutionStatus::RETURNED;
  }
                                                                    
                                 
  bool currentIsAccessor = current.flags.accessor;
  bool currentIsData = !currentIsAccessor;
  if (currentIsData != descIsData) {
                                                             
    if (!current.flags.configurable) {
      return runtime.raiseTypeError(
          TwineChar16("trap result is ") +
          (currentIsData ? "data " : "accessor ") + "but target property is " +
          (descIsData ? "data " : "accessor ") + "and non-configurable");
    }
  }
                                                                             
               
                                                                          
                  
  if (currentIsData && descIsData && !current.flags.configurable &&
      !current.flags.writable) {
                                                                        
                    
    if (desc.setWritable && desc.writable) {
      return runtime.raiseTypeError(
          "trap result is writable but "
          "target property is non-configurable and non-writable");
    }
                                                                     
                                                 
    if (desc.setValue &&
        !isSameValue(
            descValueOrAccessor.getHermesValue(),
            currentValueOrAccessor.getHermesValue())) {
      return runtime.raiseTypeError(
          "trap result has different value than target property but "
          "target property is non-configurable and non-writable");
    }
                        
    return ExecutionStatus::RETURNED;
  }
                                                                             
               
                                                    
  if (currentIsAccessor && descIsAccessor && !current.flags.configurable) {
    PropertyAccessor *descAccessor =
        vmcast<PropertyAccessor>(descValueOrAccessor.get());
    PropertyAccessor *currentAccessor =
        vmcast<PropertyAccessor>(currentValueOrAccessor.get());
                                                                
                                               
    if (descAccessor->setter &&
        descAccessor->setter != currentAccessor->setter) {
      return runtime.raiseTypeError(
          "trap result has different setter than target property but "
          "target property is non-configurable");
    }
                                                                 
                                               
    if (descAccessor->getter &&
        descAccessor->getter != currentAccessor->getter) {
      return runtime.raiseTypeError(
          "trap result has different getter than target property but "
          "target property is non-configurable");
    }
                        
  }
  return ExecutionStatus::RETURNED;
}

}             

CallResult<PseudoHandle<JSObject>> JSProxy::getPrototypeOf(
    Handle<JSObject> selfHandle,
    Runtime &runtime) {
                                                                 
                                                                 
                                                                   
                                                                     
                                                      
  GCScope gcScope(runtime);
  ScopedNativeDepthTracker depthTracker(runtime);
  if (LLVM_UNLIKELY(depthTracker.overflowed())) {
    return runtime.raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  }
                                                                            
  auto &slots = detail::slots(*selfHandle);
  Handle<JSObject> target = runtime.makeHandle(slots.target);
  Handle<JSObject> handler = runtime.makeHandle(slots.handler);
  CallResult<Handle<Callable>> trapRes =
      detail::findTrap(selfHandle, runtime, Predefined::getPrototypeOf);
  if (LLVM_UNLIKELY(trapRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
                                  
  if (!*trapRes) {
                                                  
    return JSObject::getPrototypeOf(target, runtime);
  }
                                                              
  CallResult<PseudoHandle<>> handlerProtoRes = Callable::executeCall1(
      *trapRes, runtime, handler, target.getHermesValue());
  if (handlerProtoRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                                                           
               
  if (!(*handlerProtoRes)->isObject() && !(*handlerProtoRes)->isNull()) {
    return runtime.raiseTypeError(
        "getPrototypeOf trap result is neither Object nor Null");
  }
  Handle<JSObject> handlerProto =
      runtime.makeHandle(dyn_vmcast<JSObject>(handlerProtoRes->get()));

                                                       
  CallResult<bool> extensibleRes = JSObject::isExtensible(target, runtime);
  if (extensibleRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                                          
  if (*extensibleRes) {
    return createPseudoHandle(*handlerProto);
  }
                                                          
  CallResult<PseudoHandle<JSObject>> targetProtoRes =
      JSObject::getPrototypeOf(target, runtime);
  if (targetProtoRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                                                            
               
  if (handlerProto.get() != targetProtoRes->get()) {
    return runtime.raiseTypeError(
        "getPrototypeOf trap result is not the same as non-extensible target getPrototypeOf");
  }
                             
  return std::move(*targetProtoRes);
}

CallResult<bool> JSProxy::setPrototypeOf(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    Handle<JSObject> parent) {
  GCScope gcScope{runtime};
  ScopedNativeDepthTracker depthTracker(runtime);
  if (LLVM_UNLIKELY(depthTracker.overflowed())) {
    return runtime.raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  }
                                                                            
  auto &slots = detail::slots(*selfHandle);
  Handle<JSObject> target = runtime.makeHandle(slots.target);
  Handle<JSObject> handler = runtime.makeHandle(slots.handler);
  CallResult<Handle<Callable>> trapRes =
      detail::findTrap(selfHandle, runtime, Predefined::setPrototypeOf);
  if (trapRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                  
  if (!*trapRes) {
                                                  
    return JSObject::setParent(*target, runtime, *parent);
  }
                                                                            
         
  CallResult<PseudoHandle<>> booleanTrapRes = Callable::executeCall2(
      *trapRes,
      runtime,
      handler,
      target.getHermesValue(),
      *parent ? parent.getHermesValue() : HermesValue::encodeNullValue());
  if (booleanTrapRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                                    
  if (!toBoolean(booleanTrapRes->get())) {
    return false;
  }
                                                        
  CallResult<bool> extensibleRes = JSObject::isExtensible(target, runtime);
  if (extensibleRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                                  
  if (*extensibleRes) {
    return true;
  }
                                                          
  CallResult<PseudoHandle<JSObject>> targetProtoRes =
      JSObject::getPrototypeOf(target, runtime);
  if (targetProtoRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                                                            
  if (parent.get() != targetProtoRes->get()) {
    return runtime.raiseTypeError(
        "setPrototypeOf trap changed prototype on non-extensible target");
  }
                     
  return true;
}

CallResult<bool> JSProxy::isExtensible(
    Handle<JSObject> selfHandle,
    Runtime &runtime) {
  GCScope gcScope{runtime};
  ScopedNativeDepthTracker depthTracker(runtime);
  if (LLVM_UNLIKELY(depthTracker.overflowed())) {
    return runtime.raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  }
                                                                            
  auto &slots = detail::slots(*selfHandle);
  Handle<JSObject> target = runtime.makeHandle(slots.target);
  Handle<JSObject> handler = runtime.makeHandle(slots.handler);
  CallResult<Handle<Callable>> trapRes =
      detail::findTrap(selfHandle, runtime, Predefined::isExtensible);
  if (trapRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                  
  if (!*trapRes) {
                                               
    return JSObject::isExtensible(target, runtime);
  }
                                                                              
  CallResult<PseudoHandle<>> res = Callable::executeCall1(
      *trapRes, runtime, handler, target.getHermesValue());
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  bool booleanTrapResult = toBoolean(res->get());
  res->invalidate();
                                                        
  CallResult<bool> targetRes = JSObject::isExtensible(target, runtime);
  if (targetRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                                                     
                              
  if (booleanTrapResult != *targetRes) {
    return runtime.raiseTypeError(
        "isExtensible trap returned different value than target");
  }
                                  
  return booleanTrapResult;
}

CallResult<bool> JSProxy::preventExtensions(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    PropOpFlags opFlags) {
  GCScope gcScope{runtime};
  ScopedNativeDepthTracker depthTracker(runtime);
  if (LLVM_UNLIKELY(depthTracker.overflowed())) {
    return runtime.raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  }
                                                                            
  auto &slots = detail::slots(*selfHandle);
  Handle<JSObject> target = runtime.makeHandle(slots.target);
  Handle<JSObject> handler = runtime.makeHandle(slots.handler);
  CallResult<Handle<Callable>> trapRes =
      detail::findTrap(selfHandle, runtime, Predefined::preventExtensions);
  if (trapRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                  
  if (!*trapRes) {
                                                    
                                                                         
                                                                        
                                                                           
                                               
    return JSObject::preventExtensions(target, runtime, opFlags);
  }
                                                                              
  CallResult<PseudoHandle<>> res = Callable::executeCall1(
      *trapRes, runtime, handler, target.getHermesValue());
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  bool booleanTrapResult = toBoolean(res->get());
  if (booleanTrapResult) {
                                                                
    CallResult<bool> targetRes = JSObject::isExtensible(target, runtime);
    if (targetRes == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
                                                                     
    if (*targetRes) {
      return runtime.raiseTypeError(
          "preventExtensions trap returned true for extensible target");
    }
  }
                                  
  if (!booleanTrapResult && opFlags.getThrowOnError()) {
    return runtime.raiseTypeError("preventExtensions trap returned false");
  }
  return booleanTrapResult;
}

CallResult<bool> JSProxy::getOwnProperty(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    Handle<> nameValHandle,
    ComputedPropertyDescriptor &desc,
    MutableHandle<> *valueOrAccessor) {
  GCScope gcScope{runtime};
  ScopedNativeDepthTracker depthTracker(runtime);
  if (LLVM_UNLIKELY(depthTracker.overflowed())) {
    return runtime.raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  }
                                                                            
  auto &slots = detail::slots(*selfHandle);
  Handle<JSObject> target = runtime.makeHandle(slots.target);
  Handle<JSObject> handler = runtime.makeHandle(slots.handler);
  CallResult<Handle<Callable>> trapRes = detail::findTrap(
      selfHandle, runtime, Predefined::getOwnPropertyDescriptor);
  if (trapRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  MutableHandle<SymbolID> tmpPropNameStorage{runtime};
                                  
  if (!*trapRes) {
                                                  
    return valueOrAccessor
        ? JSObject::getOwnComputedDescriptor(
              target,
              runtime,
              nameValHandle,
              tmpPropNameStorage,
              desc,
              *valueOrAccessor)
        : JSObject::getOwnComputedDescriptor(
              target, runtime, nameValHandle, tmpPropNameStorage, desc);
  }
                                                                  
                                                                       
                         
  CallResult<PseudoHandle<>> trapResultRes = Callable::executeCall2(
      *trapRes,
      runtime,
      handler,
      target.getHermesValue(),
      nameValHandle.getHermesValue());
  if (trapResultRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<> trapResultObj = runtime.makeHandle(std::move(*trapResultRes));
                                                          
  ComputedPropertyDescriptor targetDesc;
  MutableHandle<> targetValueOrAccessor{runtime};
  CallResult<bool> targetDescRes = JSObject::getOwnComputedDescriptor(
      target,
      runtime,
      nameValHandle,
      tmpPropNameStorage,
      targetDesc,
      targetValueOrAccessor);
  if (targetDescRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                            
  if (trapResultObj->isUndefined()) {
                                                         
    if (!*targetDescRes) {
      return false;
    }
                                                                      
                   
    if (!targetDesc.flags.configurable) {
      return runtime.raiseTypeError(
          "getOwnPropertyDescriptor trap result is not configurable");
    }
                                                           
    CallResult<bool> extensibleRes = JSObject::isExtensible(target, runtime);
    if (extensibleRes == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
                                                      
                                                                      
    if (!*extensibleRes) {
      return runtime.raiseTypeErrorForValue(
          target, " is not extensible (getOwnPropertyDescriptor target)");
    }
                             
    return false;
  } else if (!trapResultObj->isObject()) {
                                                                         
                           
    return runtime.raiseTypeErrorForValue(
        trapResultObj,
        " is not undefined or Object (Proxy getOwnPropertyDescriptor)");
  }
                                                        
  CallResult<bool> extensibleRes = JSObject::isExtensible(target, runtime);
  if (extensibleRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                                                 
                                                     
  DefinePropertyFlags resultDesc;
  MutableHandle<> resultValueOrAccessor{runtime};
  Handle<JSObject> trapResult = runtime.makeHandle<JSObject>(*trapResultObj);
  if (LLVM_UNLIKELY(
          toPropertyDescriptor(
              trapResult, runtime, resultDesc, resultValueOrAccessor) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  completePropertyDescriptor(resultDesc);
                                                                      
                             
                                                        

                                                                           
  if (!*targetDescRes) {
                                               
    if (!*extensibleRes) {
      return runtime.raiseTypeErrorForValue(
          "getOwnPropertyDescriptor target is not extensible and has no property ",
          nameValHandle,
          "");
    }
                     
                                      
  } else {
    if (LLVM_UNLIKELY(
            isCompatiblePropertyDescriptor(
                runtime,
                resultDesc,
                resultValueOrAccessor,
                targetDesc,
                targetValueOrAccessor) == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
  }
                                                      
                                                                            
           
                                        
  if (!resultDesc.configurable &&
      (!*targetDescRes || targetDesc.flags.configurable)) {
    return runtime.raiseTypeErrorForValue(
        "getOwnPropertyDescriptor trap result is not configurable but "
        "target property ",
        nameValHandle,
        " is configurable or non-existent");
  }
                           
  desc.flags.enumerable = resultDesc.enumerable;
  desc.flags.configurable = resultDesc.configurable;
  desc.flags.writable = resultDesc.writable;
  if (resultDesc.setGetter || resultDesc.setSetter) {
    desc.flags.accessor = true;
  }
  if (valueOrAccessor) {
    *valueOrAccessor = std::move(resultValueOrAccessor);
  }
  return true;
}

CallResult<bool> JSProxy::defineOwnProperty(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    Handle<> nameValHandle,
    DefinePropertyFlags dpFlags,
    Handle<> valueOrAccessor,
    PropOpFlags opFlags) {
  GCScope gcScope{runtime};
  ScopedNativeDepthTracker depthTracker(runtime);
  if (LLVM_UNLIKELY(depthTracker.overflowed())) {
    return runtime.raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  }
                                                                            
  auto &slots = detail::slots(*selfHandle);
  Handle<JSObject> target = runtime.makeHandle(slots.target);
  Handle<JSObject> handler = runtime.makeHandle(slots.handler);
  CallResult<Handle<Callable>> trapRes =
      detail::findTrap(selfHandle, runtime, Predefined::defineProperty);
  if (trapRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                  
  if (!*trapRes) {
                                                  
    return JSObject::defineOwnComputedPrimitive(
        target, runtime, nameValHandle, dpFlags, valueOrAccessor, opFlags);
  }
                                                    
  CallResult<HermesValue> descObjRes =
      objectFromPropertyDescriptor(runtime, dpFlags, valueOrAccessor);
  if (descObjRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                                                             
                 
  CallResult<PseudoHandle<>> trapResultRes = Callable::executeCall3(
      *trapRes,
      runtime,
      handler,
      target.getHermesValue(),
      nameValHandle.getHermesValue(),
      *descObjRes);
  if (trapResultRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  bool trapResult = toBoolean(trapResultRes->get());
                                                     
  if (!trapResult) {
    if (opFlags.getThrowOnError()) {
      return runtime.raiseTypeError("defineProperty proxy trap returned false");
    } else {
      return false;
    }
  }
                                                          
  ComputedPropertyDescriptor targetDesc;
  MutableHandle<> targetDescValueOrAccessor{runtime};
  MutableHandle<SymbolID> tmpPropNameStorage{runtime};
  CallResult<bool> targetDescRes = JSObject::getOwnComputedDescriptor(
      target,
      runtime,
      nameValHandle,
      tmpPropNameStorage,
      targetDesc,
      targetDescValueOrAccessor);
  if (targetDescRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                                        
  CallResult<bool> extensibleRes = JSObject::isExtensible(target, runtime);
  if (extensibleRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                                                             
                
                                         
                                               
  bool settingConfigFalse = dpFlags.setConfigurable && !dpFlags.configurable;
                                         
  if (!*targetDescRes) {
                                                                      
    if (!*extensibleRes) {
      return runtime.raiseTypeError(
          "defineProperty trap called for non-existent property on non-extensible target");
    }
                                                                       
    if (settingConfigFalse) {
      return runtime.raiseTypeError(
          "defineProperty trap attempted to define non-configurable property for non-existent property in the target");
    }
  } else {
                                            
                                                                     
                                                           
    if (LLVM_UNLIKELY(
            isCompatiblePropertyDescriptor(
                runtime,
                dpFlags,
                valueOrAccessor,
                targetDesc,
                targetDescValueOrAccessor) == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
                                                                            
                                           
    if (settingConfigFalse && targetDesc.flags.configurable) {
      return runtime.raiseTypeError(
          "defineProperty trap attempted to define non-configurable property for configurable property in the target");
    }
  }
                     
  return true;
}

namespace {

                                        
CallResult<bool> hasWithTrap(
    Runtime &runtime,
    Handle<> nameValHandle,
    Handle<Callable> trap,
    Handle<JSObject> handler,
    Handle<JSObject> target) {
                                         
  assert(isPropertyKey(nameValHandle) && "key is not a String or Symbol");
                                                                            
         
  CallResult<PseudoHandle<>> trapResultRes = Callable::executeCall2(
      trap,
      runtime,
      handler,
      target.getHermesValue(),
      nameValHandle.getHermesValue());
  if (trapResultRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  bool trapResult = toBoolean(trapResultRes->get());
                                           
  if (!trapResult) {
                                                             
    ComputedPropertyDescriptor targetDesc;
    MutableHandle<SymbolID> tmpPropNameStorage{runtime};
    CallResult<bool> targetDescRes = JSObject::getOwnComputedDescriptor(
        target, runtime, nameValHandle, tmpPropNameStorage, targetDesc);
    if (targetDescRes == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
                                                
    if (*targetDescRes) {
                                                                          
                       
      if (!targetDesc.flags.configurable) {
        return runtime.raiseTypeError(
            "HasProperty trap result is not configurable");
      }
                                                                
      CallResult<bool> extensibleRes = JSObject::isExtensible(target, runtime);
      if (extensibleRes == ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
                                                                            
      if (!*extensibleRes) {
        return runtime.raiseTypeError(
            "HasProperty proxy target is not extensible");
      }
    }
  }
                           
  return trapResult;
}

}             

CallResult<bool> JSProxy::hasNamed(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    SymbolID name) {
  GCScope gcScope{runtime};
  ScopedNativeDepthTracker depthTracker(runtime);
  if (LLVM_UNLIKELY(depthTracker.overflowed())) {
    return runtime.raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  }
                                                                            
  auto &slots = detail::slots(*selfHandle);
  Handle<JSObject> target = runtime.makeHandle(slots.target);
  Handle<JSObject> handler = runtime.makeHandle(slots.handler);
  CallResult<Handle<Callable>> trapRes =
      detail::findTrap(selfHandle, runtime, Predefined::has);
  if (trapRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                  
  if (!*trapRes) {
                                                         
    return JSObject::hasNamed(target, runtime, name);
  }
  return hasWithTrap(
      runtime,
      runtime.makeHandle(
          HermesValue::encodeStringValue(
              runtime.getStringPrimFromSymbolID(name))),
      *trapRes,
      handler,
      target);
}

CallResult<bool> JSProxy::hasComputed(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    Handle<> nameValHandle) {
  GCScope gcScope{runtime};
  ScopedNativeDepthTracker depthTracker(runtime);
  if (LLVM_UNLIKELY(depthTracker.overflowed())) {
    return runtime.raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  }
                                                                            
  auto &slots = detail::slots(*selfHandle);
  Handle<JSObject> target = runtime.makeHandle(slots.target);
  Handle<JSObject> handler = runtime.makeHandle(slots.handler);
  CallResult<Handle<Callable>> trapRes =
      detail::findTrap(selfHandle, runtime, Predefined::has);
  if (trapRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  if (!*trapRes) {
                                    
                                                         
    return JSObject::hasComputed(target, runtime, nameValHandle);
  }
  return hasWithTrap(runtime, nameValHandle, *trapRes, handler, target);
}

namespace {

                                        
CallResult<PseudoHandle<>> getWithTrap(
    Runtime &runtime,
    Handle<> nameValHandle,
    Handle<Callable> trap,
    Handle<JSObject> handler,
    Handle<JSObject> target,
    Handle<> receiver) {
                                         
  assert(isPropertyKey(nameValHandle) && "key is not a String or Symbol");
                                                                         
  CallResult<PseudoHandle<>> trapResultRes = Callable::executeCall3(
      trap,
      runtime,
      handler,
      target.getHermesValue(),
      nameValHandle.getHermesValue(),
      receiver.getHermesValue());
  if (trapResultRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<> trapResult = runtime.makeHandle(std::move(*trapResultRes));
                                                         
  ComputedPropertyDescriptor targetDesc;
  MutableHandle<> targetValueOrAccessor{runtime};
  MutableHandle<SymbolID> tmpPropNameStorage{runtime};
  CallResult<bool> targetDescRes = JSObject::getOwnComputedDescriptor(
      target,
      runtime,
      nameValHandle,
      tmpPropNameStorage,
      targetDesc,
      targetValueOrAccessor);
  if (targetDescRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                                                          
                
  if (*targetDescRes && !targetDesc.flags.configurable) {
                                                                               
                       
    if (!targetDesc.flags.accessor && !targetDesc.flags.writable) {
                                                                                
                                 
      if (!isSameValue(*trapResult, targetValueOrAccessor.getHermesValue())) {
        return runtime.raiseTypeError(
            "target property is non-configurable and non-writable, and get trap result differs from target property value");
      }
    }
                                                                              
                           
                                                                          
    if (targetDesc.flags.accessor &&
        !vmcast<PropertyAccessor>(*targetValueOrAccessor)->getter &&
        !trapResult->isUndefined()) {
      return runtime.raiseTypeError(
          "target property is non-configurable accessor with no getter, but get trap returned not undefined");
    }
  }

                           
  return {trapResult};
}

}             

CallResult<PseudoHandle<>> JSProxy::getNamed(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    SymbolID name,
    Handle<> receiver) {
  GCScope gcScope{runtime};
  ScopedNativeDepthTracker depthTracker(runtime);
  if (LLVM_UNLIKELY(depthTracker.overflowed())) {
    return runtime.raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  }
                                                                             
                                                                                
             
  auto &slots = detail::slots(*selfHandle);
  Handle<JSObject> target = runtime.makeHandle(slots.target);
  Handle<JSObject> handler = runtime.makeHandle(slots.handler);
  CallResult<Handle<Callable>> trapRes =
      detail::findTrap(selfHandle, runtime, Predefined::get);
  if (trapRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                  
  if (!*trapRes) {
                                                 
    return JSObject::getNamedWithReceiver_RJS(target, runtime, name, receiver);
  }
  return getWithTrap(
      runtime,
      name.isUniqued() ? runtime.makeHandle(
                             HermesValue::encodeStringValue(
                                 runtime.getStringPrimFromSymbolID(name)))
                       : runtime.makeHandle(name),
      *trapRes,
      handler,
      target,
      receiver);
}

CallResult<PseudoHandle<>> JSProxy::getComputed(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    Handle<> nameValHandle,
    Handle<> receiver) {
  GCScope gcScope{runtime};
  ScopedNativeDepthTracker depthTracker(runtime);
  if (LLVM_UNLIKELY(depthTracker.overflowed())) {
    return runtime.raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  }
                                                                            
  auto &slots = detail::slots(*selfHandle);
  Handle<JSObject> target = runtime.makeHandle(slots.target);
  Handle<JSObject> handler = runtime.makeHandle(slots.handler);
  CallResult<Handle<Callable>> trapRes =
      detail::findTrap(selfHandle, runtime, Predefined::get);
  if (trapRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                  
  if (!*trapRes) {
                                                 
    return JSObject::getComputedWithReceiver_RJS(
        target, runtime, nameValHandle, receiver);
  }
  return getWithTrap(
      runtime, nameValHandle, *trapRes, handler, target, receiver);
}

namespace {

                                        
CallResult<bool> setWithTrap(
    Runtime &runtime,
    Handle<> nameValHandle,
    Handle<> valueHandle,
    Handle<Callable> trap,
    Handle<JSObject> handler,
    Handle<JSObject> target,
    Handle<> receiver) {
                                         
  assert(isPropertyKey(nameValHandle) && "key is not a String or Symbol");
                                                                                
                  
  CallResult<PseudoHandle<>> trapResultRes = Callable::executeCall4(
      trap,
      runtime,
      handler,
      target.getHermesValue(),
      nameValHandle.getHermesValue(),
      valueHandle.getHermesValue(),
      receiver.getHermesValue());
  if (trapResultRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                                    
  if (!toBoolean(trapResultRes->get())) {
    return false;
  }
                                                          
  ComputedPropertyDescriptor targetDesc;
  MutableHandle<> targetValueOrAccessor{runtime};
  MutableHandle<SymbolID> tmpPropNameStorage{runtime};
  CallResult<bool> targetDescRes = JSObject::getOwnComputedDescriptor(
      target,
      runtime,
      nameValHandle,
      tmpPropNameStorage,
      targetDesc,
      targetValueOrAccessor);
  if (targetDescRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                                                          
                
  if (*targetDescRes && !targetDesc.flags.configurable) {
                                                                               
                       
    if (!targetDesc.flags.accessor && !targetDesc.flags.writable) {
                                                                       
                                 
      if (!isSameValue(
              valueHandle.getHermesValue(),
              targetValueOrAccessor.getHermesValue())) {
        return runtime.raiseTypeError(
            "target property is non-configurable and non-writable, and set trap value differs from target property value");
      }
    }
                                                             
                                                                              
    if (targetDesc.flags.accessor &&
        !vmcast<PropertyAccessor>(*targetValueOrAccessor)->setter) {
      return runtime.raiseTypeError(
          "set trap called, but target property is non-configurable accessor with no setter");
    }
  }

                     
  return true;
}

}             

CallResult<bool> JSProxy::setNamed(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    SymbolID name,
    Handle<> valueHandle,
                                
    Handle<> receiver) {
  GCScope gcScope{runtime};
  ScopedNativeDepthTracker depthTracker(runtime);
  if (LLVM_UNLIKELY(depthTracker.overflowed())) {
    return runtime.raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  }
                                                                            
  auto &slots = detail::slots(*selfHandle);
  Handle<JSObject> target = runtime.makeHandle(slots.target);
  Handle<JSObject> handler = runtime.makeHandle(slots.handler);
  CallResult<Handle<Callable>> trapRes =
      detail::findTrap(selfHandle, runtime, Predefined::set);
  if (trapRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                  
  if (!*trapRes) {
                                                    
    return JSObject::putNamedWithReceiver_RJS(
        target, runtime, name, valueHandle, receiver);
  }
  return setWithTrap(
      runtime,
      name.isUniqued() ? runtime.makeHandle(
                             HermesValue::encodeStringValue(
                                 runtime.getStringPrimFromSymbolID(name)))
                       : runtime.makeHandle(name),
      valueHandle,
      *trapRes,
      handler,
      target,
      receiver);
}

CallResult<bool> JSProxy::setComputed(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    Handle<> nameValHandle,
    Handle<> valueHandle,
                                
    Handle<> receiver) {
  GCScope gcScope{runtime};
  ScopedNativeDepthTracker depthTracker(runtime);
  if (LLVM_UNLIKELY(depthTracker.overflowed())) {
    return runtime.raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  }
                                                                            
  auto &slots = detail::slots(*selfHandle);
  Handle<JSObject> target = runtime.makeHandle(slots.target);
  Handle<JSObject> handler = runtime.makeHandle(slots.handler);
  CallResult<Handle<Callable>> trapRes =
      detail::findTrap(selfHandle, runtime, Predefined::set);
  if (trapRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                  
  if (!*trapRes) {
                                                    
    return JSObject::putComputedWithReceiver_RJS(
        target, runtime, nameValHandle, valueHandle, receiver);
  }
  return setWithTrap(
      runtime, nameValHandle, valueHandle, *trapRes, handler, target, receiver);
}

namespace {

                                              
CallResult<bool> deleteWithTrap(
    Runtime &runtime,
    Handle<> nameValHandle,
    Handle<Callable> trap,
    Handle<JSObject> handler,
    Handle<JSObject> target) {
                                         
  assert(isPropertyKey(nameValHandle) && "key is not a String or Symbol");
                                                                            
         
  CallResult<PseudoHandle<>> trapResultRes = Callable::executeCall2(
      trap,
      runtime,
      handler,
      target.getHermesValue(),
      nameValHandle.getHermesValue());
  if (trapResultRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  bool trapResult = toBoolean(trapResultRes->getHermesValue());
                                                    
  if (!trapResult) {
    return false;
  }
                                                          
  ComputedPropertyDescriptor targetDesc;
  MutableHandle<> targetValueOrAccessor{runtime};
  MutableHandle<SymbolID> tmpPropNameStorage{runtime};
  CallResult<bool> targetDescRes = JSObject::getOwnComputedDescriptor(
      target,
      runtime,
      nameValHandle,
      tmpPropNameStorage,
      targetDesc,
      targetValueOrAccessor);
  if (targetDescRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                                 
  if (!*targetDescRes) {
    return true;
  }
                                                                              
  if (!targetDesc.flags.configurable) {
    return runtime.raiseTypeError(
        "Delete trap target called, but target property is non-configurable");
  }
                     
  return true;
}

}             

CallResult<bool> JSProxy::deleteNamed(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    SymbolID name) {
  GCScope gcScope{runtime};
  ScopedNativeDepthTracker depthTracker(runtime);
  if (LLVM_UNLIKELY(depthTracker.overflowed())) {
    return runtime.raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  }
                                                                            
  auto &slots = detail::slots(*selfHandle);
  Handle<JSObject> target = runtime.makeHandle(slots.target);
  Handle<JSObject> handler = runtime.makeHandle(slots.handler);
  CallResult<Handle<Callable>> trapRes =
      detail::findTrap(selfHandle, runtime, Predefined::deleteProperty);
  if (trapRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                  
  if (!*trapRes) {
                                                    
    return JSObject::deleteNamed(target, runtime, name);
  }
  return deleteWithTrap(
      runtime,
      runtime.makeHandle(
          HermesValue::encodeStringValue(
              runtime.getStringPrimFromSymbolID(name))),
      *trapRes,
      handler,
      target);
}

CallResult<bool> JSProxy::deleteComputed(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    Handle<> nameValHandle) {
  GCScope gcScope{runtime};
  ScopedNativeDepthTracker depthTracker(runtime);
  if (LLVM_UNLIKELY(depthTracker.overflowed())) {
    return runtime.raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  }
                                                                            
  auto &slots = detail::slots(*selfHandle);
  Handle<JSObject> target = runtime.makeHandle(slots.target);
  Handle<JSObject> handler = runtime.makeHandle(slots.handler);
  CallResult<Handle<Callable>> trapRes =
      detail::findTrap(selfHandle, runtime, Predefined::deleteProperty);
  if (trapRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                  
  if (!*trapRes) {
                                                    
    return JSObject::deleteComputed(target, runtime, nameValHandle);
  }
  return deleteWithTrap(runtime, nameValHandle, *trapRes, handler, target);
}

namespace {

CallResult<PseudoHandle<JSArray>> filterKeys(
    Handle<JSObject> selfHandle,
    Handle<JSArray> keys,
    Runtime &runtime,
    OwnKeysFlags okFlags) {
  assert(
      (okFlags.getIncludeNonSymbols() || okFlags.getIncludeSymbols()) &&
      "Can't exclude symbols and strings");
                                                         
  if (okFlags.getIncludeNonSymbols() && okFlags.getIncludeSymbols() &&
      okFlags.getIncludeNonEnumerable()) {
    return createPseudoHandle(*keys);
  }
                                               
  assert(
      ((okFlags.getIncludeSymbols() ? 0 : 1) +
       (okFlags.getIncludeNonSymbols() ? 0 : 1)) == 1 &&
      "Exactly one of Symbols or non-Symbols is included here");
  bool onlySymbols = okFlags.getIncludeSymbols();
  uint32_t len = JSArray::getLength(*keys, runtime);
  uint32_t count = 0;
                                   
  {
    NoAllocScope noAlloc(runtime);
    for (uint32_t i = 0; i < len; ++i) {
      if (keys->at(runtime, i).isSymbol() == onlySymbols) {
        ++count;
      }
    }
  }
                                                                  
                    
  if (len == count && okFlags.getIncludeNonEnumerable()) {
    return createPseudoHandle(*keys);
  }
                                                        
  auto resultRes = JSArray::create(runtime, count, count);
  if (LLVM_UNLIKELY(resultRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<JSArray> resultHandle = *resultRes;
  MutableHandle<> elemHandle{runtime};
  uint32_t resultIndex = 0;
  GCScopeMarkerRAII marker{runtime};
  for (uint32_t i = 0; i < len; ++i) {
    marker.flush();
    SmallHermesValue elem = keys->at(runtime, i);
    if (elem.isSymbol() ? !okFlags.getIncludeSymbols()
                        : !okFlags.getIncludeNonSymbols()) {
      continue;
    }
    elemHandle = elem.unboxToHV(runtime);
    if (!okFlags.getIncludeNonEnumerable()) {
      ComputedPropertyDescriptor desc;
      CallResult<bool> propRes = JSProxy::getOwnProperty(
          selfHandle, runtime, elemHandle, desc, nullptr);
      if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      if (!*propRes || !desc.flags.enumerable) {
        continue;
      }
    }
    JSArray::setElementAt(resultHandle, runtime, resultIndex++, elemHandle);
  }
  assert(
      (!okFlags.getIncludeNonEnumerable() || resultIndex == count) &&
      "Expected count was not correct");
  CallResult<bool> setLenRes =
      JSArray::setLengthProperty(resultHandle, runtime, resultIndex);
  if (LLVM_UNLIKELY(setLenRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return createPseudoHandle(*resultHandle);
}

}             

CallResult<PseudoHandle<JSArray>> JSProxy::ownPropertyKeys(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    OwnKeysFlags okFlags) {
  GCScope gcScope{runtime};
  ScopedNativeDepthTracker depthTracker(runtime);
  if (LLVM_UNLIKELY(depthTracker.overflowed())) {
    return runtime.raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  }
                                                                            
  auto &slots = detail::slots(*selfHandle);
  Handle<JSObject> target = runtime.makeHandle(slots.target);
  Handle<JSObject> handler = runtime.makeHandle(slots.handler);
  CallResult<Handle<Callable>> trapRes =
      detail::findTrap(selfHandle, runtime, Predefined::ownKeys);
  if (trapRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                  
  if (!*trapRes) {
                                                  
    CallResult<Handle<JSArray>> targetRes =
                                                                      
                                      
        JSObject::getOwnPropertyKeys(
            target,
            runtime,
            OwnKeysFlags()
                .plusIncludeSymbols()
                .plusIncludeNonSymbols()
                .plusIncludeNonEnumerable());
    if (targetRes == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    return filterKeys(selfHandle, *targetRes, runtime, okFlags);
  }
                                                                 
  CallResult<PseudoHandle<>> trapResultArrayRes = Callable::executeCall1(
      *trapRes, runtime, handler, target.getHermesValue());
  if (trapResultArrayRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  if (!vmisa<JSObject>(trapResultArrayRes->get())) {
    return runtime.raiseTypeErrorForValue(
        runtime.makeHandle(std::move(*trapResultArrayRes)),
        " ownKeys trap result is not an Object");
  }
  auto trapResultArray =
      runtime.makeHandle<JSObject>(trapResultArrayRes->get());
                                                                              
              
                                                                       
               
  CallResult<uint64_t> countRes =
      getArrayLikeLength_RJS(trapResultArray, runtime);
  if (LLVM_UNLIKELY(countRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if (*countRes > UINT32_MAX) {
    return runtime.raiseRangeError(
        "Too many elements returned from ownKeys trap");
  }
  uint32_t count = static_cast<uint32_t>(*countRes);
  auto trapResultRes = JSArray::create(runtime, count, count);
  if (LLVM_UNLIKELY(trapResultRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<JSArray> trapResult = *trapResultRes;
  CallResult<PseudoHandle<OrderedHashMap>> dupcheckRes =
      OrderedHashMap::create(runtime);
  if (LLVM_UNLIKELY(dupcheckRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<OrderedHashMap> dupcheck = runtime.makeHandle(std::move(*dupcheckRes));
  if (LLVM_UNLIKELY(
          createListFromArrayLike_RJS(
              trapResultArray,
              runtime,
              count,
              [&dupcheck, &trapResult](
                  Runtime &runtime, uint64_t index, PseudoHandle<> value) {
                Handle<> valHandle = runtime.makeHandle(std::move(value));
                if (!valHandle->isString() && !valHandle->isSymbol()) {
                  return runtime.raiseTypeErrorForValue(
                      valHandle,
                      " ownKeys trap result element is not String or Symbol");
                }
                if (OrderedHashMap::has(dupcheck, runtime, valHandle)) {
                  return runtime.raiseTypeErrorForValue(
                      "ownKeys trap result has duplicate ", valHandle, "");
                }
                if (LLVM_UNLIKELY(
                        OrderedHashMap::insert(
                            dupcheck, runtime, valHandle, valHandle) ==
                        ExecutionStatus::EXCEPTION))
                  return ExecutionStatus::RETURNED;
                JSArray::setElementAt(trapResult, runtime, index, valHandle);
                return ExecutionStatus::RETURNED;
              }) == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

                                                        
  CallResult<bool> extensibleRes = JSObject::isExtensible(target, runtime);
  if (extensibleRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                                          
  CallResult<Handle<JSArray>> targetKeysRes = JSObject::getOwnPropertyKeys(
      target,
      runtime,
      OwnKeysFlags()
          .plusIncludeSymbols()
          .plusIncludeNonSymbols()
          .plusIncludeNonEnumerable());
  if (targetKeysRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<JSArray> targetKeys = *targetKeysRes;
                                                                               
                                                          
                                                        
                                                           
  llvh::SmallSet<uint32_t, 8> nonConfigurable;
  MutableHandle<SymbolID> tmpPropNameStorage{runtime};
                                               
  GCScopeMarkerRAII marker{runtime};
  for (uint32_t i = 0, len = JSArray::getLength(*targetKeys, runtime); i < len;
       ++i) {
    marker.flush();
                                                         
    ComputedPropertyDescriptor desc;
    CallResult<bool> descRes = JSObject::getOwnComputedDescriptor(
        target,
        runtime,
        runtime.makeHandle(targetKeys->at(runtime, i).unboxToHV(runtime)),
        tmpPropNameStorage,
        desc);
    if (descRes == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
                                                                             
                                                                    
                 
                                                                 
    if (*descRes && !desc.flags.configurable) {
      nonConfigurable.insert(i);
    }
  }
                                                                            
         
  if (*extensibleRes && nonConfigurable.empty()) {
                              
    return filterKeys(selfHandle, trapResult, runtime, okFlags);
  }
                                                                             
                                                                         
                                                                            
                                                         
  auto inTrapResult = [&runtime, &trapResult](HermesValue value) {
    for (uint32_t j = 0, len = JSArray::getLength(*trapResult, runtime);
         j < len;
         ++j) {
      if (isSameValue(value, trapResult->at(runtime, j).unboxToHV(runtime))) {
        return true;
      }
    }
    return false;
  };
  for (auto i : nonConfigurable) {
    if (!inTrapResult(targetKeys->at(runtime, i).unboxToHV(runtime))) {
      return runtime.raiseTypeError(
          "ownKeys target key is non-configurable but not present in trap result");
    }
  }
                                                        
  if (*extensibleRes) {
    return filterKeys(selfHandle, trapResult, runtime, okFlags);
  }
                                                                      
                                                                            
                                                         
  for (uint32_t i = 0, len = JSArray::getLength(*targetKeys, runtime); i < len;
       ++i) {
    if (nonConfigurable.count(i) > 0) {
      continue;
    }
    if (!inTrapResult(targetKeys->at(runtime, i).unboxToHV(runtime))) {
      return runtime.raiseTypeError(
          "ownKeys target is non-extensible but key is missing from trap result");
    }
  }
                                                                          
  if (JSArray::getLength(*targetKeys, runtime) !=
      JSArray::getLength(*trapResult, runtime)) {
    return runtime.raiseTypeError(
        "ownKeys target is non-extensible but trap result keys differ from target keys");
  }
                           
  return filterKeys(selfHandle, trapResult, runtime, okFlags);
}

}                
}                    

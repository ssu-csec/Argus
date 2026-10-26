/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                                                 
                                                                                

#include "JSLibInternal.h"

#include "hermes/VM/CallResult.h"
#include "hermes/VM/Operations.h"
#include "hermes/VM/PropertyAccessor.h"
#include "hermes/VM/StringBuilder.h"
#include "hermes/VM/StringPrimitive.h"

namespace hermes {
namespace vm {

                                                                                
                

Handle<JSObject> createErrorConstructor(Runtime &runtime) {
  auto errorPrototype = Handle<JSObject>::vmcast(&runtime.ErrorPrototype);

                                 
  defineMethod(
      runtime,
      errorPrototype,
      Predefined::getSymbolID(Predefined::toString),
      nullptr,
      errorPrototypeToString,
      0);

                                    
                                                                        
  auto defaultName = runtime.getPredefinedString(Predefined::Error);
  defineProperty(
      runtime,
      errorPrototype,
      Predefined::getSymbolID(Predefined::name),
      runtime.makeHandle(HermesValue::encodeStringValue(defaultName)));

  auto defaultMessage = runtime.getPredefinedString(Predefined::emptyString);
  defineProperty(
      runtime,
      errorPrototype,
      Predefined::getSymbolID(Predefined::message),
      runtime.makeHandle(HermesValue::encodeStringValue(defaultMessage)));

  auto getter = NativeFunction::create(
      runtime,
      Handle<JSObject>::vmcast(&runtime.functionPrototype),
      nullptr,
      errorStackGetter,
      Predefined::getSymbolID(Predefined::emptyString),
      0,
      Runtime::makeNullHandle<JSObject>());

  auto setter = NativeFunction::create(
      runtime,
      Handle<JSObject>::vmcast(&runtime.functionPrototype),
      nullptr,
      errorStackSetter,
      Predefined::getSymbolID(Predefined::emptyString),
      1,
      Runtime::makeNullHandle<JSObject>());

                                                                                
  runtime.jsErrorStackAccessor =
      PropertyAccessor::create(runtime, getter, setter);

  auto accessor =
      Handle<PropertyAccessor>::vmcast(&runtime.jsErrorStackAccessor);

  DefinePropertyFlags dpf{};
  dpf.setEnumerable = 1;
  dpf.setConfigurable = 1;
  dpf.setGetter = 1;
  dpf.setSetter = 1;
  dpf.enumerable = 0;
  dpf.configurable = 1;

  auto stackRes = JSObject::defineOwnProperty(
      errorPrototype,
      runtime,
      Predefined::getSymbolID(Predefined::stack),
      dpf,
      accessor);
  (void)stackRes;

  assert(*stackRes && "Failed to define stack accessor");

  auto cons = defineSystemConstructor<JSError>(
      runtime,
      Predefined::getSymbolID(Predefined::Error),
      ErrorConstructor,
      errorPrototype,
      1,
      CellKind::JSErrorKind);

  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::captureStackTrace),
      nullptr,
      errorCaptureStackTrace,
      2);

  return cons;
}

                                                                             
                                                      
#define ERR_HELPER(error_name, argCount)                                    \
  Handle<JSObject> create##error_name##Constructor(Runtime &runtime) {      \
    auto errorPrototype =                                                   \
        Handle<JSObject>::vmcast(&runtime.error_name##Prototype);           \
    auto defaultName = runtime.getPredefinedString(Predefined::error_name); \
    defineProperty(                                                         \
        runtime,                                                            \
        errorPrototype,                                                     \
        Predefined::getSymbolID(Predefined::name),                          \
        runtime.makeHandle(HermesValue::encodeStringValue(defaultName)));   \
    defineProperty(                                                         \
        runtime,                                                            \
        errorPrototype,                                                     \
        Predefined::getSymbolID(Predefined::message),                       \
        runtime.getPredefinedStringHandle(Predefined::emptyString));        \
    return defineSystemConstructor(                                         \
        runtime,                                                            \
        Predefined::getSymbolID(Predefined::error_name),                    \
        error_name##Constructor,                                            \
        errorPrototype,                                                     \
        Handle<JSObject>::vmcast(&runtime.errorConstructor),                \
        argCount,                                                           \
        NativeConstructor::creatorFunction<JSError>,                        \
        CellKind::JSErrorKind);                                             \
  }
                                                                              
                           
#define NATIVE_ERROR_TYPE(name) ERR_HELPER(name, 1)
#define AGGREGATE_ERROR_TYPE(name) ERR_HELPER(name, 2)
#include "hermes/FrontEndDefs/NativeErrorTypes.def"

static CallResult<HermesValue> constructErrorObject(
    Runtime &runtime,
    NativeArgs args,
    Handle<> message,
    Handle<> opts,
    Handle<JSObject> prototype) {
  MutableHandle<JSError> selfHandle{runtime};
                                                                            
  if (args.isConstructorCall()) {
    selfHandle = vmcast<JSError>(args.getThisArg());
  } else {
    selfHandle = JSError::create(runtime, prototype).get();
  }
                                                 
  if (LLVM_UNLIKELY(
          JSError::recordStackTrace(selfHandle, runtime, true) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

                        
                                                        
  if (!message->isUndefined()) {
    if (LLVM_UNLIKELY(
            JSError::setMessage(selfHandle, runtime, message) ==
            ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
  }

                                          
                                   
                                                                           
  if (auto options = Handle<JSObject>::dyn_vmcast(opts)) {
    GCScopeMarkerRAII marker{runtime};
    NamedPropertyDescriptor desc;
    Handle<JSObject> propObj = runtime.makeHandle(
        JSObject::getNamedDescriptorPredefined(
            options, runtime, Predefined::cause, desc));
    if (propObj) {
                                                 
      auto causeRes = JSObject::getNamedPropertyValue_RJS(
          selfHandle, runtime, std::move(propObj), desc);
      if (LLVM_UNLIKELY(causeRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      Handle<> cause = runtime.makeHandle(std::move(*causeRes));
                                                                                
      if (LLVM_UNLIKELY(
              JSObject::defineOwnProperty(
                  selfHandle,
                  runtime,
                  Predefined::getSymbolID(Predefined::cause),
                  DefinePropertyFlags::getNewNonEnumerableFlags(),
                  cause,
                  PropOpFlags().plusThrowOnError()) ==
              ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
    }
  }

  return selfHandle.getHermesValue();
}

                    
static CallResult<HermesValue> constructAggregateErrorObject(
    Runtime &runtime,
    NativeArgs args,
    Handle<JSObject> prototype) {
                                        
  CallResult<HermesValue> errorObj = constructErrorObject(
      runtime, args, args.getArgHandle(1), args.getArgHandle(2), prototype);
  if (LLVM_UNLIKELY(errorObj == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto errorObjHandle = runtime.makeHandle<JSObject>(*errorObj);

                                                   
  CallResult<Handle<JSArray>> errorsList =
      iterableToArray(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(errorsList == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
                                                                         
                                                                       
                                                   

  CallResult<bool> res = JSObject::defineOwnProperty(
      errorObjHandle,
      runtime,
      Predefined::getSymbolID(Predefined::errors),
      DefinePropertyFlags::getNewNonEnumerableFlags(),
      *errorsList);
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
                 
  return errorObjHandle.getHermesValue();
}

                                                                              
                                                                           
                                  
CallResult<HermesValue>
ErrorConstructor(void *, Runtime &runtime, NativeArgs args) {
  auto prototype = runtime.makeHandle<JSObject>(runtime.ErrorPrototype);
  return constructErrorObject(
      runtime, args, args.getArgHandle(0), args.getArgHandle(1), prototype);
}

                                                                         
CallResult<HermesValue>
AggregateErrorConstructor(void *, Runtime &runtime, NativeArgs args) {
  return constructAggregateErrorObject(
      runtime,
      args,
      runtime.makeHandle<JSObject>(runtime.AggregateErrorPrototype));
}

                                                                        
                                                                        
                                                                                
                                    
#define NATIVE_ERROR_TYPE(name)                                                \
  CallResult<HermesValue> name##Constructor(                                   \
      void *, Runtime &runtime, NativeArgs args) {                             \
    auto prototype = runtime.makeHandle<JSObject>(runtime.name##Prototype);    \
    return constructErrorObject(                                               \
        runtime, args, args.getArgHandle(0), args.getArgHandle(1), prototype); \
  }
#include "hermes/FrontEndDefs/NativeErrorTypes.def"

                   
CallResult<HermesValue>
errorPrototypeToString(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};

                                
  auto O = args.dyncastThis<JSObject>();

                                                              
  if (LLVM_UNLIKELY(!O)) {
    return runtime.raiseTypeErrorForValue(
        "Error.prototype.toString called on incompatible receiver ",
        args.getThisHandle(),
        "");
  }

                                                             
  CallResult<Handle<StringPrimitive>> toStringRes =
      JSError::toString(O, runtime);
  if (LLVM_UNLIKELY(toStringRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  return toStringRes->getHermesValue();
}

                                                   
   
                                                                              
                                                                            
              
   
                                                                              
                                                                               
                                                         
CallResult<HermesValue>
errorCaptureStackTrace(void *, Runtime &runtime, NativeArgs args) {
                           
  auto targetHandle = args.dyncastArg<JSObject>(0);
  if (!targetHandle || targetHandle->isHostObject() ||
      targetHandle->isProxyObject()) {
    return runtime.raiseTypeError("Invalid argument");
  }

                                          
  auto errorPrototype = Handle<JSObject>::vmcast(&runtime.ErrorPrototype);
  auto errorHandle =
      runtime.makeHandle(JSError::create(runtime, errorPrototype));

                                                                             
  const bool skipTopFrame = true;
  JSError::recordStackTrace(errorHandle, runtime, skipTopFrame);

                                                                   
  if (auto sentinel = args.dyncastArg<Callable>(1)) {
    JSError::popFramesUntilInclusive(runtime, errorHandle, sentinel);
  }

                                                                            
  auto res = JSObject::defineOwnProperty(
      targetHandle,
      runtime,
      Predefined::getSymbolID(Predefined::InternalPropertyCapturedError),
      DefinePropertyFlags::getDefaultNewPropertyFlags(),
      errorHandle);

                                                                           
                                             
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if (LLVM_UNLIKELY(!*res)) {
    return runtime.raiseTypeError(
        TwineChar16("Cannot add new properties to object"));
  }

                                                          
  DefinePropertyFlags dpf{};
  dpf.setEnumerable = 1;
  dpf.setConfigurable = 1;
  dpf.setGetter = 1;
  dpf.setSetter = 1;
  dpf.enumerable = 0;
  dpf.configurable = 1;

  auto stackRes = JSObject::defineOwnProperty(
      targetHandle,
      runtime,
      Predefined::getSymbolID(Predefined::stack),
      dpf,
      Handle<>(&runtime.jsErrorStackAccessor));

                                                                     
  if (LLVM_UNLIKELY(stackRes == ExecutionStatus::EXCEPTION)) {
    runtime.clearThrownValue();
  }

  return HermesValue::encodeUndefinedValue();
}

}                
}                    

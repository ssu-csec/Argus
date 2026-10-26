/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                                                 
                                                                                
#include "Object.h"
#include "JSLibInternal.h"

#include "hermes/VM/HermesValueTraits.h"
#include "hermes/VM/Operations.h"
#include "hermes/VM/PrimitiveBox.h"
#include "hermes/VM/PropertyAccessor.h"
#include "hermes/VM/StringBuilder.h"

namespace hermes {
namespace vm {

                                                                                
           

Handle<JSObject> createObjectConstructor(Runtime &runtime) {
  auto objectPrototype = Handle<JSObject>::vmcast(&runtime.objectPrototype);

  auto cons = defineSystemConstructor<JSObject>(
      runtime,
      Predefined::getSymbolID(Predefined::Object),
      objectConstructor,
      Handle<JSObject>::vmcast(&runtime.objectPrototype),
      1,
      CellKind::JSObjectKind);
  void *ctx = nullptr;

                                  
  defineMethod(
      runtime,
      objectPrototype,
      Predefined::getSymbolID(Predefined::toString),
      ctx,
      objectPrototypeToString,
      0);
  defineMethod(
      runtime,
      objectPrototype,
      Predefined::getSymbolID(Predefined::toLocaleString),
      ctx,
      objectPrototypeToLocaleString,
      0);
  defineMethod(
      runtime,
      objectPrototype,
      Predefined::getSymbolID(Predefined::valueOf),
      ctx,
      objectPrototypeValueOf,
      0);
  defineMethod(
      runtime,
      objectPrototype,
      Predefined::getSymbolID(Predefined::hasOwnProperty),
      ctx,
      objectPrototypeHasOwnProperty,
      1);
  defineMethod(
      runtime,
      objectPrototype,
      Predefined::getSymbolID(Predefined::isPrototypeOf),
      ctx,
      objectPrototypeIsPrototypeOf,
      1);
  defineMethod(
      runtime,
      objectPrototype,
      Predefined::getSymbolID(Predefined::propertyIsEnumerable),
      ctx,
      objectPrototypePropertyIsEnumerable,
      1);
  defineAccessor(
      runtime,
      objectPrototype,
      Predefined::getSymbolID(Predefined::underscore_proto),
      ctx,
      objectPrototypeProto_getter,
      objectPrototypeProto_setter,
      false,
      true);
  defineMethod(
      runtime,
      objectPrototype,
      Predefined::getSymbolID(Predefined::__defineGetter__),
      ctx,
      objectPrototypeDefineGetter,
      2);
  defineMethod(
      runtime,
      objectPrototype,
      Predefined::getSymbolID(Predefined::__defineSetter__),
      ctx,
      objectPrototypeDefineSetter,
      2);
  defineMethod(
      runtime,
      objectPrototype,
      Predefined::getSymbolID(Predefined::__lookupGetter__),
      ctx,
      objectPrototypeLookupGetter,
      1);
  defineMethod(
      runtime,
      objectPrototype,
      Predefined::getSymbolID(Predefined::__lookupSetter__),
      ctx,
      objectPrototypeLookupSetter,
      1);

                          
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::getPrototypeOf),
      ctx,
      objectGetPrototypeOf,
      1);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::getOwnPropertyDescriptor),
      ctx,
      objectGetOwnPropertyDescriptor,
      2);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::getOwnPropertyDescriptors),
      ctx,
      objectGetOwnPropertyDescriptors,
      1);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::getOwnPropertyNames),
      ctx,
      objectGetOwnPropertyNames,
      1);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::getOwnPropertySymbols),
      ctx,
      objectGetOwnPropertySymbols,
      1);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::hasOwn),
      ctx,
      objectHasOwn,
      2);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::seal),
      ctx,
      objectSeal,
      1);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::freeze),
      ctx,
      objectFreeze,
      1);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::fromEntries),
      ctx,
      objectFromEntries,
      1);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::preventExtensions),
      ctx,
      objectPreventExtensions,
      1);

  defineMethod(
      runtime, cons, Predefined::getSymbolID(Predefined::is), ctx, objectIs, 2);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::isSealed),
      ctx,
      objectIsSealed,
      1);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::isFrozen),
      ctx,
      objectIsFrozen,
      1);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::isExtensible),
      ctx,
      objectIsExtensible,
      1);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::keys),
      ctx,
      objectKeys,
      1);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::values),
      ctx,
      objectValues,
      1);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::entries),
      ctx,
      objectEntries,
      1);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::create),
      ctx,
      objectCreate,
      2);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::defineProperty),
      ctx,
      objectDefineProperty,
      3);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::defineProperties),
      ctx,
      objectDefineProperties,
      2);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::assign),
      ctx,
      objectAssign,
      2);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::setPrototypeOf),
      ctx,
      objectSetPrototypeOf,
      2);

  return cons;
}

                                                           
                
CallResult<HermesValue>
objectConstructor(void *, Runtime &runtime, NativeArgs args) {
  auto &newTarget = args.getNewTarget();
                                                                              
  if (!newTarget.isUndefined() &&
      newTarget.getRaw() != runtime.objectConstructor.getRaw()) {
                                                           
                             
                                                                             
                                                                                
                         
    assert(
        args.getThisArg().isObject() &&
        "'this' must be an object in a constructor call");
    return args.getThisArg();
  }

  auto value = args.getArgHandle(0);
                                                    
                                              
  if (value->isUndefined() || value->isNull()) {
                                                           
                                                                       
    if (newTarget.getRaw() == runtime.objectConstructor.getRaw()) {
      return args.getThisArg();
    }
    return JSObject::create(runtime).getHermesValue();
  }

                                 
  return toObject(runtime, value);
}

CallResult<HermesValue> getPrototypeOf(Runtime &runtime, Handle<JSObject> obj) {
  CallResult<PseudoHandle<JSObject>> protoRes =
      JSObject::getPrototypeOf(obj, runtime);
  if (LLVM_UNLIKELY(protoRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
                                                              
  if (!*protoRes) {
    return HermesValue::encodeNullValue();
  }
  return protoRes->getHermesValue();
}

CallResult<HermesValue>
objectGetPrototypeOf(void *, Runtime &runtime, NativeArgs args) {
  CallResult<HermesValue> res = toObject(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  return getPrototypeOf(runtime, runtime.makeHandle(vmcast<JSObject>(*res)));
}

CallResult<HermesValue> getOwnPropertyDescriptor(
    Runtime &runtime,
    Handle<JSObject> object,
    Handle<> key) {
  ComputedPropertyDescriptor desc;
  MutableHandle<> valueOrAccessor{runtime};
  MutableHandle<SymbolID> tmpPropNameStorage{runtime};
  {
    auto result = JSObject::getOwnComputedDescriptor(
        object, runtime, key, tmpPropNameStorage, desc, valueOrAccessor);
    if (result == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    if (!*result) {
      if (LLVM_LIKELY(!object->isHostObject()))
        return HermesValue::encodeUndefinedValue();
                                                                                
                                                                   
                                                                         
                                                                        
      desc.flags.enumerable = true;
      desc.flags.writable = true;
      desc.flags.hostObject = true;
    }
  }

  if (LLVM_UNLIKELY(!desc.flags.accessor && desc.flags.hostObject)) {
    auto propRes = JSObject::getComputed_RJS(object, runtime, key);
    if (propRes == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    valueOrAccessor = std::move(*propRes);
  }

  DefinePropertyFlags dpFlags;
  dpFlags.configurable = desc.flags.configurable;
  dpFlags.enumerable = desc.flags.enumerable;
  dpFlags.writable = desc.flags.writable;
  dpFlags.setEnumerable = true;
  dpFlags.setWritable = true;
  dpFlags.setConfigurable = true;
  dpFlags.setGetter = desc.flags.accessor;
  dpFlags.setSetter = desc.flags.accessor;
  dpFlags.setValue = !desc.flags.accessor;

  return objectFromPropertyDescriptor(runtime, dpFlags, valueOrAccessor);
}

CallResult<HermesValue>
objectGetOwnPropertyDescriptor(void *, Runtime &runtime, NativeArgs args) {
  auto objRes = toObject(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<JSObject> O = runtime.makeHandle<JSObject>(objRes.getValue());

  return getOwnPropertyDescriptor(runtime, O, args.getArgHandle(1));
}

                   
CallResult<HermesValue>
objectGetOwnPropertyDescriptors(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};

                                 
  auto objRes = toObject(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<JSObject> obj = runtime.makeHandle<JSObject>(objRes.getValue());

                                                   
  auto ownKeysRes = JSObject::getOwnPropertyKeys(
      obj,
      runtime,
      OwnKeysFlags()
          .plusIncludeNonSymbols()
          .plusIncludeSymbols()
          .plusIncludeNonEnumerable());
  if (LLVM_UNLIKELY(ownKeysRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<JSArray> ownKeys = *ownKeysRes;
  uint32_t len = JSArray::getLength(*ownKeys, runtime);

                                                             
  auto descriptors = runtime.makeHandle<JSObject>(JSObject::create(runtime));

  MutableHandle<> key{runtime};
  MutableHandle<> descriptor{runtime};

  DefinePropertyFlags dpf = DefinePropertyFlags::getDefaultNewPropertyFlags();

  auto marker = gcScope.createMarker();
                                                         
  for (uint32_t i = 0; i < len; ++i) {
    gcScope.flushToMarker(marker);
    key = ownKeys->at(runtime, i).unboxToHV(runtime);
                                                    
                                                           
    auto descriptorRes = getOwnPropertyDescriptor(runtime, obj, key);
    if (LLVM_UNLIKELY(descriptorRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
                                         
                                                                    
    if (!descriptorRes->isUndefined()) {
      descriptor = *descriptorRes;
      auto res = JSObject::defineOwnComputedPrimitive(
          descriptors, runtime, key, dpf, descriptor);
      (void)res;
      assert(
          res != ExecutionStatus::EXCEPTION &&
          "defining own property on a new object cannot fail");
    }
  }
                           
  return descriptors.getHermesValue();
}

                                                                 
                                                       
                                                                   
                                                                    
CallResult<HermesValue> getOwnPropertyKeysAsStrings(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    OwnKeysFlags okFlags) {
  auto cr = JSObject::getOwnPropertyKeys(selfHandle, runtime, okFlags);
  if (cr == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto array = *cr;
  MutableHandle<> prop(runtime);
  GCScope gcScope(runtime);
  auto marker = gcScope.createMarker();
  for (unsigned i = 0, e = array->getEndIndex(); i < e; ++i) {
    gcScope.flushToMarker(marker);
    prop = array->at(runtime, i).unboxToHV(runtime);
    if (prop->isString() || prop->isSymbol()) {
                                                          
      continue;
    }
    assert(prop->isNumber() && "Property name is either string or number");
                                                                
    auto status = toString_RJS(runtime, prop);
    assert(
        status != ExecutionStatus::EXCEPTION &&
        "toString() on property name cannot fail");
    JSArray::setElementAt(
        array, runtime, i, runtime.makeHandle(std::move(*status)));
  }
  return array.getHermesValue();
}

CallResult<HermesValue>
objectGetOwnPropertyNames(void *, Runtime &runtime, NativeArgs args) {
  auto objRes = toObject(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto objHandle = runtime.makeHandle<JSObject>(objRes.getValue());
  auto cr = getOwnPropertyKeysAsStrings(
      objHandle,
      runtime,
      OwnKeysFlags().plusIncludeNonSymbols().plusIncludeNonEnumerable());
  if (LLVM_UNLIKELY(cr == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return *cr;
}

CallResult<HermesValue>
objectGetOwnPropertySymbols(void *, Runtime &runtime, NativeArgs args) {
  auto objRes = toObject(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto objHandle = runtime.makeHandle<JSObject>(objRes.getValue());
  auto cr = JSObject::getOwnPropertySymbols(objHandle, runtime);
  if (LLVM_UNLIKELY(cr == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return cr->getHermesValue();
}

CallResult<bool>
defineProperty(Runtime &runtime, NativeArgs args, PropOpFlags opFlags) {
                                                                          
  auto O = args.dyncastArg<JSObject>(0);
                                                              
  if (!O) {
    return runtime.raiseTypeError(
        "Object.defineProperty() called on non-object");
  }

                                      
                                                                    
                                                                 
                                                              
                                                          
                 
  CallResult<Handle<>> keyRes =
      toPropertyKeyIfObject(runtime, args.getArgHandle(1));
  if (LLVM_UNLIKELY(keyRes == ExecutionStatus::EXCEPTION))
    return ExecutionStatus::EXCEPTION;

                                                       
  DefinePropertyFlags descFlags;
  MutableHandle<> descValueOrAccessor{runtime};
  if (toPropertyDescriptor(
          args.getArgHandle(2), runtime, descFlags, descValueOrAccessor) ==
      ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }

                                                                    
                                                                   
  return JSObject::defineOwnComputedPrimitive(
      O, runtime, *keyRes, descFlags, descValueOrAccessor, opFlags);
}

CallResult<HermesValue>
objectDefineProperty(void *, Runtime &runtime, NativeArgs args) {
                 
  CallResult<bool> res =
      defineProperty(runtime, args, PropOpFlags().plusThrowOnError());
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  assert(*res && "defineProperty with throwOnError == true returned false");
                 
  return args.getArg(0);
}

static CallResult<HermesValue>
objectDefinePropertiesInternal(Runtime &runtime, Handle<> obj, Handle<> props) {
                                               
  auto *objPtr = dyn_vmcast<JSObject>(obj.get());
  if (!objPtr) {
    return runtime.raiseTypeError(
        "Object.defineProperties() called on non-object");
  }
  auto objHandle = runtime.makeHandle(objPtr);

                                                           
  auto objRes = toObject(runtime, props);
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto propsHandle = runtime.makeHandle<JSObject>(objRes.getValue());

                                          
  auto cr = JSObject::getOwnPropertyKeys(
      propsHandle,
      runtime,
      OwnKeysFlags()
          .plusIncludeSymbols()
          .plusIncludeNonSymbols()
                                                                              
                                                                        
                                
          .setIncludeNonEnumerable(propsHandle->isProxyObject()));
  if (cr == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto propNames = *cr;

                                                                
  GCScope scope{runtime, "objectDefinePropertiesInternal", UINT_MAX};

                                                                  
                                                                   
                                                                   
                                                                    
                           
  struct NewProps {
    unsigned propNameIndex;
    DefinePropertyFlags flags;
    MutableHandle<> valueOrAccessor;

    NewProps(unsigned i, DefinePropertyFlags f, MutableHandle<> voa)
        : propNameIndex(i), flags(f), valueOrAccessor(std::move(voa)) {}
  };
  llvh::SmallVector<NewProps, 4> newProps;

                                                                      
                                               
  MutableHandle<> propName{runtime};
  MutableHandle<SymbolID> tmpPropNameStorage{runtime};

  for (unsigned i = 0, e = propNames->getEndIndex(); i < e; ++i) {
    propName = propNames->at(runtime, i).unboxToHV(runtime);
    ComputedPropertyDescriptor desc;
    CallResult<bool> descRes = JSObject::getOwnComputedDescriptor(
        propsHandle, runtime, propName, tmpPropNameStorage, desc);
    if (LLVM_UNLIKELY(descRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (LLVM_UNLIKELY(!*descRes || !desc.flags.enumerable)) {
      continue;
    }
    CallResult<PseudoHandle<>> propRes = propsHandle->isProxyObject()
        ? JSObject::getComputed_RJS(propsHandle, runtime, propName)
        : JSObject::getComputedPropertyValueInternal_RJS(
              propsHandle, runtime, propsHandle, desc);
    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    DefinePropertyFlags flags;
    MutableHandle<> valueOrAccessor{runtime};
    if (LLVM_UNLIKELY(
            toPropertyDescriptor(
                runtime.makeHandle(std::move(*propRes)),
                runtime,
                flags,
                valueOrAccessor) == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    newProps.emplace_back(i, flags, std::move(valueOrAccessor));
  }

                                                           
  for (const auto &newProp : newProps) {
    propName = propNames->at(runtime, newProp.propNameIndex).unboxToHV(runtime);
    auto result = JSObject::defineOwnComputedPrimitive(
        objHandle,
        runtime,
        propName,
        newProp.flags,
        newProp.valueOrAccessor,
        PropOpFlags().plusThrowOnError());
    if (result == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
  }
  return objHandle.getHermesValue();
}

CallResult<HermesValue>
objectCreate(void *, Runtime &runtime, NativeArgs args) {
                                                                
  auto obj = args.dyncastArg<JSObject>(0);
  if (!obj && !args.getArg(0).isNull()) {
    return runtime.raiseTypeError(
        "Object prototype argument must be an Object or null");
  }

  auto newObj = JSObject::create(runtime, obj).getHermesValue();
  auto arg1 = args.getArgHandle(1);
  if (arg1->isUndefined()) {
    return newObj;
  }
                                                      
  auto cr =
      objectDefinePropertiesInternal(runtime, runtime.makeHandle(newObj), arg1);
  if (LLVM_UNLIKELY(cr == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return *cr;
}

CallResult<HermesValue>
objectDefineProperties(void *, Runtime &runtime, NativeArgs args) {
  auto cr = objectDefinePropertiesInternal(
      runtime, args.getArgHandle(0), args.getArgHandle(1));
  if (cr == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  return *cr;
}

CallResult<HermesValue> objectSeal(void *, Runtime &runtime, NativeArgs args) {
  auto objHandle = args.dyncastArg<JSObject>(0);

  if (!objHandle) {
    return args.getArg(0);
  }

  if (LLVM_UNLIKELY(
          JSObject::seal(objHandle, runtime) == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return objHandle.getHermesValue();
}

CallResult<HermesValue>
objectFreeze(void *, Runtime &runtime, NativeArgs args) {
  auto objHandle = args.dyncastArg<JSObject>(0);

  if (!objHandle) {
    return args.getArg(0);
  }

  if (LLVM_UNLIKELY(
          JSObject::freeze(objHandle, runtime) == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return objHandle.getHermesValue();
}

CallResult<HermesValue>
objectPreventExtensions(void *, Runtime &runtime, NativeArgs args) {
  Handle<JSObject> obj = args.dyncastArg<JSObject>(0);

  if (!obj) {
    return args.getArg(0);
  }

  CallResult<bool> statusRes = JSObject::preventExtensions(
      obj, runtime, PropOpFlags().plusThrowOnError());
  if (LLVM_UNLIKELY(statusRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  assert(
      *statusRes &&
      "Object.preventExtensions with ThrowOnError returned false");
  return args.getArg(0);
}

CallResult<HermesValue> objectIs(void *, Runtime &runtime, NativeArgs args) {
  return HermesValue::encodeBoolValue(
      isSameValue(args.getArg(0), args.getArg(1)));
}

CallResult<HermesValue>
objectIsSealed(void *, Runtime &runtime, NativeArgs args) {
  auto objHandle = args.dyncastArg<JSObject>(0);

  if (!objHandle) {
                                                              
    return HermesValue::encodeBoolValue(true);
  }

  return HermesValue::encodeBoolValue(JSObject::isSealed(objHandle, runtime));
}

CallResult<HermesValue>
objectIsFrozen(void *, Runtime &runtime, NativeArgs args) {
  auto objHandle = args.dyncastArg<JSObject>(0);

  if (!objHandle) {
                                                              
    return HermesValue::encodeBoolValue(true);
  }

  return HermesValue::encodeBoolValue(JSObject::isFrozen(objHandle, runtime));
}

CallResult<HermesValue>
objectIsExtensible(void *, Runtime &runtime, NativeArgs args) {
  PseudoHandle<JSObject> obj =
      createPseudoHandle(dyn_vmcast<JSObject>(args.getArg(0)));

  if (!obj) {
                                                               
    return HermesValue::encodeBoolValue(false);
  }

  CallResult<bool> extRes = JSObject::isExtensible(std::move(obj), runtime);
  if (LLVM_UNLIKELY(extRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return HermesValue::encodeBoolValue(*extRes);
}

                 
                                                                           
CallResult<HermesValue> enumerableOwnProperties_RJS(
    Runtime &runtime,
    Handle<JSObject> objHandle,
    EnumerableOwnPropertiesKind kind) {
  GCScope gcScope{runtime};

  auto namesRes = getOwnPropertyKeysAsStrings(
      objHandle,
      runtime,
      OwnKeysFlags().plusIncludeNonSymbols().setIncludeNonEnumerable(
          objHandle->isProxyObject()));
  if (namesRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  if (kind == EnumerableOwnPropertiesKind::Key && !objHandle->isProxyObject()) {
    return *namesRes;
  }
  auto names = runtime.makeHandle<JSArray>(*namesRes);
  uint32_t len = JSArray::getLength(*names, runtime);

  auto propertiesRes = JSArray::create(runtime, len, len);
  if (LLVM_UNLIKELY(propertiesRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto properties = *propertiesRes;

  MutableHandle<StringPrimitive> name{runtime};
  MutableHandle<> value{runtime};
  MutableHandle<> entry{runtime};
  MutableHandle<SymbolID> tmpPropNameStorage{runtime};

  uint32_t targetIdx = 0;

                                              
                                                                               
                                                                               
                               
  auto marker = gcScope.createMarker();
  for (uint32_t i = 0, len = JSArray::getLength(*names, runtime); i < len;
       ++i) {
    gcScope.flushToMarker(marker);

    name = names->at(runtime, i).getString(runtime);
                                                                
    ComputedPropertyDescriptor desc;
    CallResult<bool> descRes = JSObject::getOwnComputedPrimitiveDescriptor(
        objHandle,
        runtime,
        name,
        JSObject::IgnoreProxy::Yes,
        tmpPropNameStorage,
        desc);
    if (LLVM_UNLIKELY(descRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (LLVM_LIKELY(*descRes && desc.flags.enumerable)) {
                                                                           
                                                                 

                                                                               
      auto valueRes = JSObject::getComputedPropertyValueInternal_RJS(
          objHandle, runtime, objHandle, desc);
      if (LLVM_UNLIKELY(valueRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      value = std::move(*valueRes);
    } else if (!objHandle->isProxyObject()) {
      continue;
    } else {
                                                                    
                                                            
      descRes =
          JSProxy::getOwnProperty(objHandle, runtime, name, desc, nullptr);
      if (LLVM_UNLIKELY(descRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      if (!*descRes || !desc.flags.enumerable) {
                                        
        continue;
      }
                                                                  
             
      if (kind != EnumerableOwnPropertiesKind::Key) {
        auto valueRes =
            JSProxy::getComputed(objHandle, runtime, name, objHandle);
        if (LLVM_UNLIKELY(valueRes == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }
        value = std::move(*valueRes);
      }
    }

    if (kind == EnumerableOwnPropertiesKind::KeyValue) {
      auto entryRes = JSArray::create(runtime, 2, 2);
      if (LLVM_UNLIKELY(entryRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      entry = entryRes->getHermesValue();
      JSArray::setElementAt(Handle<JSArray>::vmcast(entry), runtime, 0, name);
      JSArray::setElementAt(Handle<JSArray>::vmcast(entry), runtime, 1, value);
    } else if (kind == EnumerableOwnPropertiesKind::Value) {
      entry = value.getHermesValue();
    } else {
      assert(
          objHandle->isProxyObject() &&
          "Key kind did not return early but not proxy");
      entry = names->at(runtime, i).unboxToHV(runtime);
    }

                                                      
    JSArray::setElementAt(properties, runtime, targetIdx++, entry);
  }

                                                                       
                                                                                
                 
  if (LLVM_UNLIKELY(
          JSArray::setLengthProperty(properties, runtime, targetIdx) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  return properties.getHermesValue();
}

CallResult<HermesValue> objectKeys(void *, Runtime &runtime, NativeArgs args) {
  auto objRes = toObject(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  return enumerableOwnProperties_RJS(
      runtime,
      runtime.makeHandle<JSObject>(*objRes),
      EnumerableOwnPropertiesKind::Key);
}

CallResult<HermesValue>
objectValues(void *, Runtime &runtime, NativeArgs args) {
  auto objRes = toObject(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  return enumerableOwnProperties_RJS(
      runtime,
      runtime.makeHandle<JSObject>(*objRes),
      EnumerableOwnPropertiesKind::Value);
}

CallResult<HermesValue>
objectEntries(void *, Runtime &runtime, NativeArgs args) {
  auto objRes = toObject(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  return enumerableOwnProperties_RJS(
      runtime,
      runtime.makeHandle<JSObject>(*objRes),
      EnumerableOwnPropertiesKind::KeyValue);
}

                                              
                                                             
CallResult<HermesValue>
objectFromEntries(void *, Runtime &runtime, NativeArgs args) {
                                                   
  if (args.getArg(0).isNull() || args.getArg(0).isUndefined()) {
    return runtime.raiseTypeError(
        "fromEntries argument is not coercible to Object");
  }

  GCScopeMarkerRAII marker{runtime};

                                                   
  Handle<JSObject> obj = runtime.makeHandle(JSObject::create(runtime));
                                                                            

                                                         
                                             
                                                             
                                                                               
                                             
                                                              
  return addEntriesFromIterable(
      runtime,
      obj,
      args.getArgHandle(0),
      [obj, &runtime](Runtime &, Handle<> key, Handle<> value) {
        const DefinePropertyFlags dpf =
            DefinePropertyFlags::getDefaultNewPropertyFlags();
        return JSObject::defineOwnComputed(
            obj, runtime, key, dpf, value, PropOpFlags().plusThrowOnError());
      });
}

CallResult<HermesValue>
objectAssign(void *, Runtime &runtime, NativeArgs args) {
  vm::GCScope gcScope(runtime);

                                   
  auto objRes = toObject(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
                             
    return ExecutionStatus::EXCEPTION;
  }
  auto toHandle = runtime.makeHandle<JSObject>(objRes.getValue());

                                                   
  if (LLVM_UNLIKELY(args.getArgCount() == 1)) {
    return toHandle.getHermesValue();
  }

                                                                           
              
                                                                         

                                                     
  MutableHandle<JSObject> fromHandle{runtime};
                                                                     
  MutableHandle<> nextKeyHandle{runtime};
                                                
  MutableHandle<> propValueHandle{runtime};
                                                
  MutableHandle<SymbolID> tmpPropNameStorage{runtime};

  for (uint32_t argIdx = 1; argIdx < args.getArgCount(); argIdx++) {
    GCScopeMarkerRAII markerOuter(gcScope);
    auto nextSource = args.getArgHandle(argIdx);
                                                                          
    if (nextSource->isNull() || nextSource->isUndefined()) {
      continue;
    }

                                               
    if (LLVM_UNLIKELY(
            (objRes = toObject(runtime, nextSource)) ==
            ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    fromHandle = vmcast<JSObject>(objRes.getValue());

                                                      
    auto cr = JSObject::getOwnPropertyKeys(
        fromHandle,
        runtime,
        OwnKeysFlags()
            .plusIncludeSymbols()
            .plusIncludeNonSymbols()
            .setIncludeNonEnumerable(fromHandle->isProxyObject()));
    if (LLVM_UNLIKELY(cr == ExecutionStatus::EXCEPTION)) {
                                      
      return ExecutionStatus::EXCEPTION;
    }

    auto keys = *cr;
    ComputedPropertyDescriptor desc;
                                                                  
    for (uint32_t nextKeyIdx = 0, endIdx = keys->getEndIndex();
         nextKeyIdx < endIdx;
         ++nextKeyIdx) {
      GCScopeMarkerRAII markerInner(gcScope);

      nextKeyHandle = keys->at(runtime, nextKeyIdx).unboxToHV(runtime);

                                                             
      auto descCr = JSObject::getOwnComputedDescriptor(
          fromHandle, runtime, nextKeyHandle, tmpPropNameStorage, desc);
      if (LLVM_UNLIKELY(descCr == ExecutionStatus::EXCEPTION)) {
                                        
        return ExecutionStatus::EXCEPTION;
      }
                                                                                
      if (LLVM_UNLIKELY(!*descCr) || LLVM_UNLIKELY(!desc.flags.enumerable)) {
        continue;
      }

                                                        

                                                                 
                                                                  
                                                                      
                                                                    
      CallResult<PseudoHandle<>> propRes = fromHandle->isProxyObject()
          ? JSObject::getComputed_RJS(fromHandle, runtime, nextKeyHandle)
          : JSObject::getComputedPropertyValue_RJS(
                fromHandle,
                runtime,
                fromHandle,
                tmpPropNameStorage,
                desc,
                nextKeyHandle);
      if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
                                                
        return ExecutionStatus::EXCEPTION;
      }
      propValueHandle = std::move(*propRes);

                                                                    
      auto statusCr = JSObject::putComputed_RJS(
          toHandle,
          runtime,
          nextKeyHandle,
          propValueHandle,
          PropOpFlags().plusThrowOnError());
      if (LLVM_UNLIKELY(statusCr == ExecutionStatus::EXCEPTION)) {
                                            
        return ExecutionStatus::EXCEPTION;
      }
    }
  }

                 
  return toHandle.getHermesValue();
}

CallResult<HermesValue>
objectSetPrototypeOf(void *, Runtime &runtime, NativeArgs args) {
  Handle<> O = args.getArgHandle(0);
  Handle<> proto = args.getArgHandle(1);
                                           
  if (O->isNull() || O->isUndefined()) {
    return runtime.raiseTypeError(
        "setPrototypeOf argument is not coercible to Object");
  }

                                                                               
  if (!(proto->isObject() || proto->isNull())) {
    return runtime.raiseTypeError(
        "setPrototypeOf new prototype must be object or null");
  }
                                           
  if (!vmisa<JSObject>(*O)) {
    return *O;
  }
                                                  
  auto status = JSObject::setParent(
      vmcast<JSObject>(*O),
      runtime,
      dyn_vmcast<JSObject>(*proto),
      PropOpFlags().plusThrowOnError());
                                                        
                                                                     
  if (LLVM_UNLIKELY(status == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

                 
  return *O;
}

                                                                                
                     

CallResult<HermesValue> directObjectPrototypeToString(
    Runtime &runtime,
    Handle<> arg) {
  StringPrimitive *str;

  if (arg->isUndefined()) {
    str = runtime.getPredefinedString(Predefined::squareObjectUndefined);
  } else if (arg->isNull()) {
    str = runtime.getPredefinedString(Predefined::squareObjectNull);
  } else if (arg->getRaw() == runtime.getGlobal().getHermesValue().getRaw()) {
    str = runtime.getPredefinedString(Predefined::squareObjectGlobal);
  } else {
    auto res = toObject(runtime, arg);
    if (res == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }

    auto O = runtime.makeHandle<JSObject>(res.getValue());
                                             
    auto tagRes = JSObject::getNamed_RJS(
        O, runtime, Predefined::getSymbolID(Predefined::SymbolToStringTag));
    if (LLVM_UNLIKELY(tagRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }

    if ((*tagRes)->isString()) {
      auto tag = runtime.makeHandle(
          PseudoHandle<StringPrimitive>::vmcast(std::move(*tagRes)));
      SafeUInt32 tagLen(tag->getStringLength());
      tagLen.add(9);
      CallResult<StringBuilder> builder =
          StringBuilder::createStringBuilder(runtime, tagLen);
      if (LLVM_UNLIKELY(builder == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
                                                                  
                                  
      builder->appendASCIIRef(ASCIIRef{"[object ", 8});
      builder->appendStringPrim(tag);
      builder->appendCharacter(']');
      return builder->getStringPrimitive().getHermesValue();
    }

                                                             
    CallResult<bool> isArrayRes = isArray(runtime, *O);
    if (LLVM_UNLIKELY(isArrayRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (*isArrayRes) {
                                                          
      str = runtime.getPredefinedString(Predefined::squareObject_JSArray);
    } else if (vmisa<JSString>(O.getHermesValue())) {
                                                                              
      str = runtime.getPredefinedString(Predefined::squareObject_JSString);
    } else if (vmisa<Arguments>(O.getHermesValue())) {
                                                                               
                     
      str = runtime.getPredefinedString(Predefined::squareObject_Arguments);
    } else if (vmisa<Callable>(O.getHermesValue())) {
                                                                        
                    
      str = runtime.getPredefinedString(Predefined::squareObject_JSFunction);
    } else if (vmisa<JSError>(O.getHermesValue())) {
                                                                             
                 
      str = runtime.getPredefinedString(Predefined::squareObject_JSError);
    } else if (vmisa<JSBoolean>(O.getHermesValue())) {
                                                                              
                   
      str = runtime.getPredefinedString(Predefined::squareObject_JSBoolean);
    } else if (vmisa<JSNumber>(O.getHermesValue())) {
                                                                             
                  
      str = runtime.getPredefinedString(Predefined::squareObject_JSNumber);
    } else if (vmisa<JSDate>(O.getHermesValue())) {
                                                                            
                
      str = runtime.getPredefinedString(Predefined::squareObject_JSDate);
    } else if (vmisa<JSRegExp>(O.getHermesValue())) {
                                                                                
                  
      str = runtime.getPredefinedString(Predefined::squareObject_JSRegExp);
    } else {
      str = runtime.getPredefinedString(Predefined::squareObject_JSObject);
    }
  }

  return HermesValue::encodeStringValue(str);
}

CallResult<HermesValue>
objectPrototypeToString(void *, Runtime &runtime, NativeArgs args) {
  return directObjectPrototypeToString(runtime, args.getThisHandle());
}

CallResult<HermesValue>
objectPrototypeToLocaleString(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto selfHandle = runtime.makeHandle<JSObject>(objRes.getValue());
  auto propRes = JSObject::getNamed_RJS(
      selfHandle, runtime, Predefined::getSymbolID(Predefined::toString));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if (auto func = Handle<Callable>::dyn_vmcast(
          runtime.makeHandle(std::move(*propRes)))) {
    return Callable::executeCall0(func, runtime, selfHandle)
        .toCallResultHermesValue();
  }
  return runtime.raiseTypeError("toString must be callable");
}

CallResult<HermesValue>
objectPrototypeValueOf(void *, Runtime &runtime, NativeArgs args) {
  auto res = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return res;
}

static CallResult<HermesValue>
objectHasOwnHelper(Runtime &runtime, Handle<JSObject> O, Handle<> P) {
  ComputedPropertyDescriptor desc;
  MutableHandle<SymbolID> tmpPropNameStorage{runtime};
  CallResult<bool> hasProp = JSObject::getOwnComputedDescriptor(
      O, runtime, P, tmpPropNameStorage, desc);
  if (LLVM_UNLIKELY(hasProp == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if (*hasProp) {
    return HermesValue::encodeBoolValue(true);
  }
                                                                            
                                                               
                                                                     
                                                                        
                                                                              
                                            
                             
                                                  
               
         
  if (LLVM_UNLIKELY(O->isHostObject())) {
    return HermesValue::encodeBoolValue(true);
  }
  return HermesValue::encodeBoolValue(false);
}

                   
CallResult<HermesValue>
objectPrototypeHasOwnProperty(void *, Runtime &runtime, NativeArgs args) {
                                     
  auto PRes = toPropertyKey(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(PRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

                                         
  auto ORes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(ORes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
                                       
  Handle<JSObject> O = runtime.makeHandle<JSObject>(ORes.getValue());
  return objectHasOwnHelper(runtime, O, *PRes);
}

CallResult<HermesValue>
objectHasOwn(void *, Runtime &runtime, NativeArgs args) {
                                
  auto ORes = toObject(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(ORes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<JSObject> O = runtime.makeHandle<JSObject>(ORes.getValue());

                                     
  auto PRes = toPropertyKey(runtime, args.getArgHandle(1));
  if (LLVM_UNLIKELY(PRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
                                       
  return objectHasOwnHelper(runtime, O, *PRes);
}

CallResult<HermesValue>
objectPrototypeIsPrototypeOf(void *, Runtime &runtime, NativeArgs args) {
  if (LLVM_UNLIKELY(!args.getArg(0).isObject())) {
                                                
    return HermesValue::encodeBoolValue(false);
  }
  auto res = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<JSObject> objHandle = runtime.makeHandle<JSObject>(*res);
  PseudoHandle<JSObject> parent =
      createPseudoHandle(vmcast<JSObject>(args.getArg(0)));
  while (true) {
    CallResult<PseudoHandle<JSObject>> protoRes =
        JSObject::getPrototypeOf(std::move(parent), runtime);
    if (LLVM_UNLIKELY(protoRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (!*protoRes) {
      break;
    }
    parent = std::move(*protoRes);
    if (parent.get() == objHandle.get()) {
      return HermesValue::encodeBoolValue(true);
    }
  }
  return HermesValue::encodeBoolValue(false);
}

CallResult<HermesValue>
objectPrototypePropertyIsEnumerable(void *, Runtime &runtime, NativeArgs args) {
  MutableHandle<SymbolID> tmpPropNameStorage{runtime};
  auto res = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  ComputedPropertyDescriptor desc;
  auto status = JSObject::getOwnComputedDescriptor(
      runtime.makeHandle<JSObject>(res.getValue()),
      runtime,
      args.getArgHandle(0),
      tmpPropNameStorage,
      desc);
  if (LLVM_UNLIKELY(status == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return HermesValue::encodeBoolValue(
      status.getValue() && desc.flags.enumerable);
}

CallResult<HermesValue>
objectPrototypeProto_getter(void *, Runtime &runtime, NativeArgs args) {
  CallResult<HermesValue> res = toObject(runtime, args.getThisHandle());
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  return getPrototypeOf(runtime, runtime.makeHandle(vmcast<JSObject>(*res)));
}

CallResult<HermesValue>
objectPrototypeProto_setter(void *, Runtime &runtime, NativeArgs args) {
                                         
  if (args.getThisArg().isNull() || args.getThisArg().isUndefined()) {
    return runtime.raiseTypeError("'this' is not coercible to JSObject");
  }
                                                  
  if (!args.getThisArg().isObject()) {
    return HermesValue::encodeUndefinedValue();
  }

  HermesValue proto = args.getArg(0);
  JSObject *protoPtr;
  if (proto.isObject())
    protoPtr = vmcast<JSObject>(proto);
  else if (proto.isNull())
    protoPtr = nullptr;
  else
    return HermesValue::encodeUndefinedValue();

  if (LLVM_UNLIKELY(
          JSObject::setParent(
              vmcast<JSObject>(args.getThisArg()),
              runtime,
              protoPtr,
              PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION))
    return ExecutionStatus::EXCEPTION;
  return HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue>
objectPrototypeDefineGetter(void *, Runtime &runtime, NativeArgs args) {
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(objRes.getValue());

  auto getter = args.dyncastArg<Callable>(1);
  if (!getter) {
    return runtime.raiseTypeError("__defineGetter__ getter not callable");
  }

  HermesValue crtRes = PropertyAccessor::create(
      runtime, getter, Runtime::makeNullHandle<Callable>());
  auto accessor = runtime.makeHandle<PropertyAccessor>(crtRes);

  DefinePropertyFlags dpf;
  dpf.setEnumerable = 1;
  dpf.enumerable = 1;
  dpf.setConfigurable = 1;
  dpf.configurable = 1;
  dpf.setGetter = 1;

  auto res = JSObject::defineOwnComputed(
      O,
      runtime,
      args.getArgHandle(0),
      dpf,
      accessor,
      PropOpFlags().plusThrowOnError());
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }

  return HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue>
objectPrototypeDefineSetter(void *, Runtime &runtime, NativeArgs args) {
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(objRes.getValue());

  auto setter = args.dyncastArg<Callable>(1);
  if (!setter) {
    return runtime.raiseTypeError("__defineSetter__ setter not callable");
  }

  HermesValue crtRes = PropertyAccessor::create(
      runtime, Runtime::makeNullHandle<Callable>(), setter);
  auto accessor = runtime.makeHandle<PropertyAccessor>(crtRes);

  DefinePropertyFlags dpf;
  dpf.setEnumerable = 1;
  dpf.enumerable = 1;
  dpf.setConfigurable = 1;
  dpf.configurable = 1;
  dpf.setSetter = 1;

  auto res = JSObject::defineOwnComputed(
      O,
      runtime,
      args.getArgHandle(0),
      dpf,
      accessor,
      PropOpFlags().plusThrowOnError());
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }

  return HermesValue::encodeUndefinedValue();
}

namespace {

                                                                     
                                                               
                                                                      
                                                               
                                                                      
                                                                  
               
CallResult<PropertyAccessor *> lookupAccessor(
    Runtime &runtime,
    NativeArgs args) {
  CallResult<HermesValue> res = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  MutableHandle<JSObject> O = runtime.makeMutableHandle(vmcast<JSObject>(*res));
  Handle<> key = args.getArgHandle(0);
  MutableHandle<> valueOrAccessor{runtime};
  MutableHandle<SymbolID> tmpPropNameStorage{runtime};
  do {
    ComputedPropertyDescriptor desc;
    CallResult<bool> definedRes = JSObject::getOwnComputedDescriptor(
        O, runtime, key, tmpPropNameStorage, desc, valueOrAccessor);
    if (LLVM_UNLIKELY(definedRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (*definedRes) {
      if (!desc.flags.accessor) {
        break;
      }
      return vmcast<PropertyAccessor>(valueOrAccessor.get());
    }
    CallResult<PseudoHandle<JSObject>> protoRes =
        JSObject::getPrototypeOf(O, runtime);
    if (LLVM_UNLIKELY(protoRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    O = protoRes->get();
  } while (O);
  return nullptr;
}

}             

CallResult<HermesValue>
objectPrototypeLookupGetter(void *, Runtime &runtime, NativeArgs args) {
  CallResult<PropertyAccessor *> accessorRes = lookupAccessor(runtime, args);
  if (LLVM_UNLIKELY(accessorRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return (*accessorRes && (*accessorRes)->getter)
      ? HermesValue::encodeObjectValue(
            (*accessorRes)->getter.getNonNull(runtime))
      : HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue>
objectPrototypeLookupSetter(void *, Runtime &runtime, NativeArgs args) {
  CallResult<PropertyAccessor *> accessorRes = lookupAccessor(runtime, args);
  if (LLVM_UNLIKELY(accessorRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return (*accessorRes && (*accessorRes)->setter)
      ? HermesValue::encodeObjectValue(
            (*accessorRes)->setter.getNonNull(runtime))
      : HermesValue::encodeUndefinedValue();
}

}                
}                    

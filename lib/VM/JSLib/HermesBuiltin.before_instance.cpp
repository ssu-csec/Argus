#include "hermes/VM/PropertyAccessor.h"
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "JSLibInternal.h"
#include "hermes/VM/ArrayLike.h"

#include "hermes/FrontEndDefs/Builtins.h"
#include "hermes/FrontEndDefs/NativeErrorTypes.h"
#include "hermes/Support/Base64vlq.h"
#include "hermes/VM/Callable.h"
#include "hermes/VM/CodeBlock.h"
#include "hermes/VM/JSArray.h"
#include "hermes/VM/JSArrayBuffer.h"
#include "hermes/VM/JSLib.h"
#include "hermes/VM/JSRegExp.h"
#include "hermes/VM/JSWeakMapImpl.h"
#include "hermes/VM/Operations.h"
#include "hermes/VM/PrimitiveBox.h"
#include "hermes/VM/StackFrame-inline.h"
#include "hermes/VM/StringView.h"

#include <random>

namespace hermes {
namespace vm {

                                                              
CallResult<HermesValue>
silentObjectSetPrototypeOf(void *, Runtime &runtime, NativeArgs args) {
  JSObject *O = dyn_vmcast<JSObject>(args.getArg(0));
  if (!O)
    return HermesValue::encodeUndefinedValue();

  JSObject *parent;
  HermesValue V = args.getArg(1);
  if (V.isNull())
    parent = nullptr;
  else if (V.isObject())
    parent = vmcast<JSObject>(V);
  else
    return HermesValue::encodeUndefinedValue();

  (void)JSObject::setParent(O, runtime, parent);

                       
  runtime.clearThrownValue();

  return HermesValue::encodeUndefinedValue();
}

                                                                           
                                                                            
                                                                       
                                                                     
                                                                       
                                                                       
                                                                             
                                                                                
                                                                        
                                        
CallResult<HermesValue>
hermesBuiltinGetTemplateObject(void *, Runtime &runtime, NativeArgs args) {
  if (LLVM_UNLIKELY(args.getArgCount() < 3)) {
    return runtime.raiseTypeError("At least three arguments expected");
  }
  if (LLVM_UNLIKELY(!args.getArg(0).isNumber())) {
    return runtime.raiseTypeError("First argument should be a number");
  }
  if (LLVM_UNLIKELY(!args.getArg(1).isBool())) {
    return runtime.raiseTypeError("Second argument should be a bool");
  }

  GCScope gcScope{runtime};

                                                                  
  uint32_t templateObjID = args.getArg(0).getNumberAs<uint32_t>();
  auto savedCB = runtime.getStackFrames().begin()->getSavedCodeBlock();
  if (LLVM_UNLIKELY(!savedCB)) {
    return runtime.raiseTypeError("Cannot be called from native code");
  }
  RuntimeModule *runtimeModule = savedCB->getRuntimeModule();
  JSObject *cachedTemplateObj =
      runtimeModule->findCachedTemplateObject(templateObjID);
  if (cachedTemplateObj) {
    return HermesValue::encodeObjectValue(cachedTemplateObj);
  }

  bool dup = args.getArg(1).getBool();
  if (LLVM_UNLIKELY(!dup && args.getArgCount() % 2 == 1)) {
    return runtime.raiseTypeError(
        "There must be the same number of raw and cooked strings.");
  }
  uint32_t count = dup ? args.getArgCount() - 2 : args.getArgCount() / 2 - 1;

                                           
  auto arrRes = JSArray::create(runtime, count, 0);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto rawObj = Handle<JSObject>::vmcast(*arrRes);
  auto arrRes2 = JSArray::create(runtime, count, 0);
  if (LLVM_UNLIKELY(arrRes2 == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto templateObj = Handle<JSObject>::vmcast(*arrRes2);

                                                                              
                  
  DefinePropertyFlags dpf = DefinePropertyFlags::getDefaultNewPropertyFlags();
  dpf.writable = 0;
  dpf.configurable = 0;
  MutableHandle<> idx{runtime};
  MutableHandle<> rawValue{runtime};
  MutableHandle<> cookedValue{runtime};
  uint32_t cookedBegin = dup ? 2 : 2 + count;
  auto marker = gcScope.createMarker();
  for (uint32_t i = 0; i < count; ++i) {
    idx = HermesValue::encodeUntrustedNumberValue(i);

    cookedValue = args.getArg(cookedBegin + i);
    auto putRes = JSObject::defineOwnComputedPrimitive(
        templateObj, runtime, idx, dpf, cookedValue);
    assert(
        putRes != ExecutionStatus::EXCEPTION && *putRes &&
        "Failed to set cooked value to template object.");

    rawValue = args.getArg(2 + i);
    putRes = JSObject::defineOwnComputedPrimitive(
        rawObj, runtime, idx, dpf, rawValue);
    assert(
        putRes != ExecutionStatus::EXCEPTION && *putRes &&
        "Failed to set raw value to raw object.");

    gcScope.flushToMarker(marker);
  }
                                                        
  DefinePropertyFlags readOnlyDPF{};
  readOnlyDPF.setWritable = 1;
  readOnlyDPF.setConfigurable = 1;
  readOnlyDPF.writable = 0;
  readOnlyDPF.configurable = 0;
  auto readOnlyRes = JSObject::defineOwnProperty(
      rawObj,
      runtime,
      Predefined::getSymbolID(Predefined::length),
      readOnlyDPF,
      Runtime::getUndefinedValue(),
      PropOpFlags().plusThrowOnError());
  if (LLVM_UNLIKELY(readOnlyRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if (LLVM_UNLIKELY(!*readOnlyRes)) {
    return runtime.raiseTypeError(
        "Failed to set 'length' property on the raw object read-only.");
  }
  JSObject::preventExtensions(rawObj.get());

                                                                          
            
  PropertyFlags constantPF{};
  constantPF.writable = 0;
  constantPF.configurable = 0;
  constantPF.enumerable = 0;
  auto putNewRes = JSObject::defineNewOwnProperty(
      templateObj,
      runtime,
      Predefined::getSymbolID(Predefined::raw),
      constantPF,
      rawObj);
  if (LLVM_UNLIKELY(putNewRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
                                                             
  readOnlyRes = JSObject::defineOwnProperty(
      templateObj,
      runtime,
      Predefined::getSymbolID(Predefined::length),
      readOnlyDPF,
      Runtime::getUndefinedValue(),
      PropOpFlags().plusThrowOnError());
  if (LLVM_UNLIKELY(readOnlyRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if (LLVM_UNLIKELY(!*readOnlyRes)) {
    return runtime.raiseTypeError(
        "Failed to set 'length' property on the raw object read-only.");
  }
  JSObject::preventExtensions(templateObj.get());

                               
  runtimeModule->cacheTemplateObject(templateObjID, templateObj);

  return templateObj.getHermesValue();
}

                                                                              
                          
   
         
                                                                      
            
CallResult<HermesValue>
hermesBuiltinEnsureObject(void *, Runtime &runtime, NativeArgs args) {
  if (LLVM_LIKELY(args.getArg(0).isObject()))
    return HermesValue::encodeUndefinedValue();

  return runtime.raiseTypeError(args.getArgHandle(1));
}

                                               
   
         
                                                                
            
CallResult<HermesValue>
hermesBuiltinGetMethod(void *, Runtime &runtime, NativeArgs args) {
  return getMethod(runtime, args.getArgHandle(0), args.getArgHandle(1))
      .toCallResultHermesValue();
}

                                                      
   
         
                                                                 
            
CallResult<HermesValue>
hermesBuiltinThrowTypeError(void *, Runtime &runtime, NativeArgs args) {
  return runtime.raiseTypeError(args.getArgHandle(0));
}

                                                                      
                  
                                                                 
                       
CallResult<HermesValue>
hermesBuiltinGeneratorSetDelegated(void *, Runtime &runtime, NativeArgs args) {
  auto *gen = dyn_vmcast<GeneratorInnerFunction>(
      runtime.getCurrentFrame().getPreviousFrame().getCalleeClosureOrCBRef());
  if (!gen) {
    return runtime.raiseTypeError(
        "generatorSetDelegated can only be called as part of yield*");
  }
  gen->setIsDelegated(true);
  return HermesValue::encodeUndefinedValue();
}

namespace {

CallResult<HermesValue> copyDataPropertiesSlowPath_RJS(
    Runtime &runtime,
    Handle<JSObject> target,
    Handle<JSObject> from,
    Handle<JSObject> excludedItems) {
                                                 
  auto cr = JSObject::getOwnPropertyKeys(
      from,
      runtime,
      OwnKeysFlags()
          .plusIncludeSymbols()
          .plusIncludeNonSymbols()
          .plusIncludeNonEnumerable());
  if (LLVM_UNLIKELY(cr == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto keys = *cr;

  MutableHandle<> nextKeyHandle{runtime};
  MutableHandle<> propValueHandle{runtime};
  MutableHandle<SymbolID> tmpSymbolStorage{runtime};
  GCScopeMarkerRAII marker{runtime};
                                                          
  for (uint32_t nextKeyIdx = 0, endIdx = keys->getEndIndex();
       nextKeyIdx < endIdx;
       ++nextKeyIdx) {
    marker.flush();
    nextKeyHandle = keys->at(runtime, nextKeyIdx).unboxToHV(runtime);
    if (nextKeyHandle->isNumber()) {
      CallResult<PseudoHandle<StringPrimitive>> strRes =
          toString_RJS(runtime, nextKeyHandle);
      if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      nextKeyHandle = strRes->getHermesValue();
    }

                                                               
                                                  
                                   
    if (excludedItems) {
      assert(
          !excludedItems->isProxyObject() &&
          "internal excludedItems object is a proxy");
      ComputedPropertyDescriptor desc;
      CallResult<bool> cr = JSObject::getOwnComputedPrimitiveDescriptor(
          excludedItems,
          runtime,
          nextKeyHandle,
          JSObject::IgnoreProxy::Yes,
          tmpSymbolStorage,
          desc);
      if (LLVM_UNLIKELY(cr == ExecutionStatus::EXCEPTION))
        return ExecutionStatus::EXCEPTION;
      if (*cr)
        continue;
    }

                                                           
    ComputedPropertyDescriptor desc;
    CallResult<bool> crb = JSObject::getOwnComputedDescriptor(
        from, runtime, nextKeyHandle, tmpSymbolStorage, desc);
    if (LLVM_UNLIKELY(crb == ExecutionStatus::EXCEPTION))
      return ExecutionStatus::EXCEPTION;
                                                                           
                                                                            
                                
    if ((*crb && desc.flags.enumerable) || from->isHostObject()) {
                                                      
      CallResult<PseudoHandle<>> crv =
          JSObject::getComputed_RJS(from, runtime, nextKeyHandle);
      if (LLVM_UNLIKELY(crv == ExecutionStatus::EXCEPTION))
        return ExecutionStatus::EXCEPTION;
      propValueHandle = std::move(*crv);
                                                                         
      crb = JSObject::defineOwnComputed(
          target,
          runtime,
          nextKeyHandle,
          DefinePropertyFlags::getDefaultNewPropertyFlags(),
          propValueHandle);
      assert(
          crb != ExecutionStatus::EXCEPTION && *crb &&
          "CreateDataProperty failed");
    }
  }
  return target.getHermesValue();
}

}             

         
                                        
                                                       
            
   
                                                                             
                                                                                
                                                                         
                
CallResult<HermesValue>
hermesBuiltinCopyDataProperties(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};

                                       
  Handle<JSObject> target = args.dyncastArg<JSObject>(0);
                                    
  if (!target)
    return HermesValue::encodeUndefinedValue();

                                                      
  Handle<> untypedSource = args.getArgHandle(1);
  if (untypedSource->isNull() || untypedSource->isUndefined())
    return target.getHermesValue();

                                       
  Handle<JSObject> source = untypedSource->isObject()
      ? Handle<JSObject>::vmcast(untypedSource)
      : Handle<JSObject>::vmcast(
            runtime.makeHandle(*toObject(runtime, untypedSource)));

                                                         
                                                                      
                                                                  
                 
  Handle<JSObject> excludedItems = args.dyncastArg<JSObject>(2);
  assert(
      (!excludedItems || !excludedItems->isProxyObject()) &&
      "excludedItems internal List is a Proxy");

                                                                               
                                                                          
                                                                           
                                                                               
                                                                           
  if (source->isProxyObject() || source->isHostObject() ||
      source->getClass(runtime)->getMayHaveAccessor()) {
    return copyDataPropertiesSlowPath_RJS(
        runtime, target, source, excludedItems);
  }

  MutableHandle<> nameHandle{runtime};
  MutableHandle<> valueHandle{runtime};
  MutableHandle<SymbolID> tmpSymbolStorage{runtime};

                                          
  bool success = JSObject::forEachOwnPropertyWhile(
      source,
      runtime,
                   
      [&source,
       &target,
       &excludedItems,
       &nameHandle,
       &valueHandle,
       &tmpSymbolStorage](
          Runtime &runtime, uint32_t index, ComputedPropertyDescriptor desc) {
        if (!desc.flags.enumerable)
          return true;

        nameHandle = HermesValue::encodeUntrustedNumberValue(index);

        if (excludedItems) {
          assert(
              !excludedItems->isProxyObject() &&
              "internal excludedItems object is a proxy");
          ComputedPropertyDescriptor xdesc;
          auto cr = JSObject::getOwnComputedPrimitiveDescriptor(
              excludedItems,
              runtime,
              nameHandle,
              JSObject::IgnoreProxy::Yes,
              tmpSymbolStorage,
              xdesc);
          if (LLVM_UNLIKELY(cr == ExecutionStatus::EXCEPTION))
            return false;
          if (*cr)
            return true;
        }

        valueHandle = JSObject::getOwnIndexed(
            createPseudoHandle(source.get()), runtime, index);

        if (LLVM_UNLIKELY(
                JSObject::defineOwnComputedPrimitive(
                    target,
                    runtime,
                    nameHandle,
                    DefinePropertyFlags::getDefaultNewPropertyFlags(),
                    valueHandle) == ExecutionStatus::EXCEPTION)) {
          return false;
        }

        return true;
      },
                 
      [&source, &target, &excludedItems, &valueHandle](
          Runtime &runtime, SymbolID sym, NamedPropertyDescriptor desc) {
        if (!desc.flags.enumerable)
          return true;
        if (InternalProperty::isInternal(sym))
          return true;

                               
        if (excludedItems) {
          auto cr = JSObject::hasNamedOrIndexed(excludedItems, runtime, sym);
          assert(
              cr != ExecutionStatus::EXCEPTION &&
              "hasNamedOrIndex failed, which can only happen with a proxy, "
              "but excludedItems should never be a proxy");
          if (*cr)
            return true;
        }

        SmallHermesValue shv =
            JSObject::getNamedSlotValueUnsafe(*source, runtime, desc);
        valueHandle = runtime.makeHandle(shv.unboxToHV(runtime));

                                                                                
                                     
        if (LLVM_UNLIKELY(
                JSObject::defineOwnPropertyInternal(
                    target,
                    runtime,
                    sym,
                    DefinePropertyFlags::getDefaultNewPropertyFlags(),
                    valueHandle) == ExecutionStatus::EXCEPTION)) {
          return false;
        }

        return true;
      });

  if (LLVM_UNLIKELY(!success))
    return ExecutionStatus::EXCEPTION;

  return target.getHermesValue();
}

         
                                                     
            
                                                                            
                                         
CallResult<HermesValue>
hermesBuiltinCopyRestArgs(void *, Runtime &runtime, NativeArgs args) {
  GCScopeMarkerRAII marker{runtime};

                                     
  auto frames = runtime.getStackFrames();
  auto it = frames.begin();
  ++it;
                                                                          
  if (LLVM_UNLIKELY(it == frames.end()))
    return HermesValue::encodeUndefinedValue();

                               
  if (!args.getArg(0).isNumber())
    return HermesValue::encodeUndefinedValue();
  uint32_t from = truncateToUInt32(args.getArg(0).getNumber());

  uint32_t argCount = it->getArgCount();
  uint32_t length = from <= argCount ? argCount - from : 0;

  auto cr = JSArray::create(runtime, length, length);
  if (LLVM_UNLIKELY(cr == ExecutionStatus::EXCEPTION))
    return ExecutionStatus::EXCEPTION;
  auto array = *cr;
  JSArray::setStorageEndIndex(array, runtime, length);

  for (uint32_t i = 0; i != length; ++i) {
    const auto shv =
        SmallHermesValue::encodeHermesValue(it->getArgRef(from), runtime);
    JSArray::unsafeSetExistingElementAt(*array, runtime, i, shv);
    ++from;
  }

  return array.getHermesValue();
}

         
                                                                        
            
                  
                                                                               
                                                                     
                                                                               
CallResult<HermesValue>
hermesBuiltinArraySpread(void *, Runtime &runtime, NativeArgs args) {
  GCScopeMarkerRAII topMarker{runtime};
  Handle<JSArray> target = args.dyncastArg<JSArray>(0);
                                      
  if (!target) {
    return runtime.raiseTypeError(
        "HermesBuiltin.arraySpread requires an array target");
  }

  MutableHandle<> nextValue{runtime};

  Handle<JSArray> arr = args.dyncastArg<JSArray>(1);
  if (arr) {
                                                            
                                                              
    NamedPropertyDescriptor desc;
    PseudoHandle<JSObject> propObj = createPseudoHandle(
        JSObject::getNamedDescriptorPredefined(
            arr, runtime, Predefined::SymbolIterator, desc));
    if (LLVM_LIKELY(propObj) && LLVM_LIKELY(!desc.flags.proxyObject)) {
      PseudoHandle<> slotValue = createPseudoHandle(
          JSObject::getNamedSlotValueUnsafe(propObj.get(), runtime, desc)
              .unboxToHV(runtime));
      propObj.invalidate();
      if (LLVM_LIKELY(
              slotValue->getRaw() == runtime.arrayPrototypeValues.getRaw())) {
        slotValue.invalidate();
        auto nextIndex = args.getArg(2).getNumberAs<JSArray::size_type>();
        MutableHandle<> idxHandle{runtime};
        GCScopeMarkerRAII marker{runtime};
        for (JSArray::size_type i = 0; i < JSArray::getLength(*arr, runtime);
             ++i) {
          marker.flush();
                                                                
          nextValue = arr->at(runtime, i).unboxToHV(runtime);
          if (LLVM_UNLIKELY(nextValue->isEmpty())) {
                                                                 
                                                                              
            idxHandle = HermesValue::encodeUntrustedNumberValue(i);
            CallResult<PseudoHandle<>> valueRes =
                JSObject::getComputed_RJS(arr, runtime, idxHandle);
            if (LLVM_UNLIKELY(valueRes == ExecutionStatus::EXCEPTION)) {
              return ExecutionStatus::EXCEPTION;
            }
            nextValue = std::move(*valueRes);
          }
                                                                      
                                                                         
                                                             
                                                                         
                                                                              
                                                                             
                         
          JSArray::setElementAt(target, runtime, nextIndex, nextValue);
          ++nextIndex;
        }

        if (LLVM_UNLIKELY(
                JSArray::setLengthProperty(target, runtime, nextIndex) ==
                ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }

        return HermesValue::encodeUntrustedNumberValue(nextIndex);
      }
    }
  }

                                                       
  auto iteratorRecordRes = getIterator(runtime, args.getArgHandle(1));
  if (LLVM_UNLIKELY(iteratorRecordRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  IteratorRecord iteratorRecord = *iteratorRecordRes;

  MutableHandle<> nextIndex{runtime, args.getArg(2)};

               
  for (GCScopeMarkerRAII marker{runtime};              ; marker.flush()) {
                                                     
    auto nextRes = iteratorStep(runtime, iteratorRecord);
    if (LLVM_UNLIKELY(nextRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    Handle<JSObject> next = *nextRes;

                                             
    if (!next) {
      return nextIndex.getHermesValue();
    }
                                                 
    auto nextItemRes = JSObject::getNamed_RJS(
        next, runtime, Predefined::getSymbolID(Predefined::value));
    if (LLVM_UNLIKELY(nextItemRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    nextValue = std::move(*nextItemRes);

                                                 
                                                    
                                 
    if (LLVM_UNLIKELY(
            JSArray::defineOwnComputed(
                target,
                runtime,
                nextIndex,
                DefinePropertyFlags::getDefaultNewPropertyFlags(),
                nextValue) == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }

                                         
    nextIndex =
        HermesValue::encodeUntrustedNumberValue(nextIndex->getNumber() + 1);
  }

  return nextIndex.getHermesValue();
}

         
                                                                   
            
                                                                            
             
                                                 
                                                                     
                                                                              
                          
CallResult<HermesValue>
hermesBuiltinApply(void *, Runtime &runtime, NativeArgs args) {
  GCScopeMarkerRAII marker{runtime};

  Handle<Callable> fn = args.dyncastArg<Callable>(0);
  if (LLVM_UNLIKELY(!fn)) {
    return runtime.raiseTypeErrorForValue(
        args.getArgHandle(0), " is not a function");
  }

  Handle<JSArray> argArray = args.dyncastArg<JSArray>(1);
  if (LLVM_UNLIKELY(!argArray)) {
    return runtime.raiseTypeError("args must be an array");
  }

  uint32_t len = JSArray::getLength(*argArray, runtime);

  bool isConstructor = args.getArgCount() == 2;

  MutableHandle<> thisVal{runtime};
  if (isConstructor) {
    auto thisValRes = Callable::createThisForConstruct_RJS(fn, runtime);
    if (LLVM_UNLIKELY(thisValRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    thisVal = thisValRes->getHermesValue();
  } else {
    thisVal = args.getArg(2);
  }

  ScopedNativeCallFrame newFrame{
      runtime, len, *fn, isConstructor, thisVal.getHermesValue()};
  if (LLVM_UNLIKELY(newFrame.overflowed()))
    return runtime.raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);

  for (uint32_t i = 0; i < len; ++i) {
    assert(!argArray->at(runtime, i).isEmpty() && "arg array must be dense");
    HermesValue arg = argArray->at(runtime, i).unboxToHV(runtime);
    newFrame->getArgRef(i) = LLVM_UNLIKELY(arg.isEmpty())
        ? HermesValue::encodeUndefinedValue()
        : arg;
  }
  if (isConstructor) {
    auto res = Callable::construct(fn, runtime, thisVal);
    if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    return res->getHermesValue();
  }
  auto res = Callable::call(fn, runtime);
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return res->getHermesValue();
}

                                                                     
                                                                        
                     
                                                                   
                                                 
CallResult<HermesValue>
hermesBuiltinExportAll(void *, Runtime &runtime, NativeArgs args) {
  Handle<JSObject> exports = args.dyncastArg<JSObject>(0);
  if (LLVM_UNLIKELY(!exports)) {
    return runtime.raiseTypeError(
        "exportAll() exports argument must be object");
  }

  Handle<JSObject> source = args.dyncastArg<JSObject>(1);
  if (LLVM_UNLIKELY(!source) || LLVM_UNLIKELY(source->isProxyObject())) {
    return runtime.raiseTypeError(
        "exportAll() source argument must be non-Proxy object");
  }

  MutableHandle<> propertyHandle{runtime};

  auto dpf = DefinePropertyFlags::getDefaultNewPropertyFlags();
  dpf.configurable = 0;

  CallResult<bool> defineRes{ExecutionStatus::EXCEPTION};

                                                                    
  bool result = HiddenClass::forEachPropertyWhile(
      runtime.makeHandle(source->getClass(runtime)),
      runtime,
      [&source, &exports, &propertyHandle, &dpf, &defineRes](
          Runtime &runtime, SymbolID id, NamedPropertyDescriptor desc) {
        if (!desc.flags.enumerable)
          return true;

        if (id == Predefined::getSymbolID(Predefined::defaultExport)) {
          return true;
        }

        propertyHandle =
            JSObject::getNamedSlotValueUnsafe(*source, runtime, desc)
                .unboxToHV(runtime);
        defineRes = JSObject::defineOwnProperty(
            exports, runtime, id, dpf, propertyHandle);
        if (LLVM_UNLIKELY(defineRes == ExecutionStatus::EXCEPTION)) {
          return false;
        }

        return true;
      });
  if (LLVM_UNLIKELY(!result)) {
    return ExecutionStatus::EXCEPTION;
  }
  return HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue>
hermesBuiltinExponentiate(void *ctx, Runtime &runtime, NativeArgs args) {
  CallResult<HermesValue> res = toNumeric_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if (LLVM_LIKELY(!res->isBigInt())) {
    double left = res->getNumber();
                                                                               
              
    CallResult<HermesValue> res = toNumber_RJS(runtime, args.getArgHandle(1));
    if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    return HermesValue::encodeUntrustedNumberValue(
        expOp(left, res->getNumber()));
  }

  Handle<BigIntPrimitive> lhs = runtime.makeHandle(res->getBigInt());

                                                                        
  res = toNumeric_RJS(runtime, args.getArgHandle(1));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  if (!res->isBigInt()) {
    return runtime.raiseTypeErrorForValue(
        "Cannot convert ", args.getArgHandle(1), " to BigInt");
  }

  return BigIntPrimitive::exponentiate(
      runtime, std::move(lhs), runtime.makeHandle(res->getBigInt()));
}

CallResult<HermesValue> hermesBuiltinInitRegexNamedGroups(
    void *ctx,
    Runtime &runtime,
    NativeArgs args) {
  auto *regexp = dyn_vmcast<JSRegExp>(args.getArg(0));
  auto *groupsObj = dyn_vmcast<JSObject>(args.getArg(1));
  regexp->setGroupNameMappings(runtime, groupsObj);
  return HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue> hermesBuiltinGetOriginalNativeErrorConstructor(
    void *ctx,
    Runtime &runtime,
    NativeArgs args) {
  CallResult<HermesValue> res = toInt32_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  uint32_t errorId = res->getNumberAs<uint32_t>();
  switch (static_cast<NativeErrorTypes>(errorId)) {
    default:
      return runtime.raiseRangeError(
          "Invalid error ID passed to getOriginalNativeErrorConstructor");

    case NativeErrorTypes::Error:
      return runtime.errorConstructor;

#define NATIVE_ERROR_TYPE(name) \
  case NativeErrorTypes::name:  \
    return runtime.name##Constructor;
#include "hermes/FrontEndDefs/NativeErrorTypes.def"
  }
}

                                                                         
                                                                           
                                                                               
                                                                              
CallResult<HermesValue>
hermesBuiltinPrivateNameCreate(void *, Runtime &runtime, NativeArgs) {
  GCScope gcScope{runtime};
  auto result = JSWeakMap::create(runtime, Runtime::makeNullHandle<JSObject>());
  if (LLVM_UNLIKELY(result == ExecutionStatus::EXCEPTION))
    return ExecutionStatus::EXCEPTION;
  return result->getHermesValue();
}

CallResult<HermesValue>
hermesBuiltinPrivateFieldInit(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};
  auto receiver = args.dyncastArg<JSObject>(0);
  auto token = args.dyncastArg<JSWeakMap>(1);
  if (LLVM_UNLIKELY(!receiver || !token))
    return runtime.raiseTypeError("Invalid native private field initialization");
  if (LLVM_UNLIKELY(JSWeakMap::hasValue(token, runtime, receiver)))
    return runtime.raiseTypeError("Cannot initialize the same private field twice");
  if (LLVM_UNLIKELY(JSWeakMap::setValue(
          token, runtime, receiver, args.getArgHandle(2)) ==
      ExecutionStatus::EXCEPTION))
    return ExecutionStatus::EXCEPTION;
  return HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue>
hermesBuiltinPrivateFieldGet(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};
  auto receiver = args.dyncastArg<JSObject>(0);
  auto token = args.dyncastArg<JSWeakMap>(1);
  if (LLVM_UNLIKELY(!receiver || !token ||
          !JSWeakMap::hasValue(token, runtime, receiver)))
    return runtime.raiseTypeError("Private field is not present on this object");
  return JSWeakMap::getValue(token, runtime, receiver);
}

CallResult<HermesValue>
hermesBuiltinPrivateFieldSet(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};
  auto receiver = args.dyncastArg<JSObject>(0);
  auto token = args.dyncastArg<JSWeakMap>(1);
  if (LLVM_UNLIKELY(!receiver || !token ||
          !JSWeakMap::hasValue(token, runtime, receiver)))
    return runtime.raiseTypeError("Private field is not present on this object");
  if (LLVM_UNLIKELY(JSWeakMap::setValue(
          token, runtime, receiver, args.getArgHandle(2)) ==
      ExecutionStatus::EXCEPTION))
    return ExecutionStatus::EXCEPTION;
                                                                            
  return args.getArg(2);
}

                                                                           
                                                                           
                                                                        
static CallResult<Handle<JSObject>> nativeBaseClassPrototype(
    Runtime &runtime,
    Handle<JSFunction> ctor,
    bool initializing) {
  auto *block = ctor->getCodeBlock(runtime);
  if (LLVM_UNLIKELY(!block->getHeaderFlags().isCallProhibited(false) ||
                   block->getHeaderFlags().isCallProhibited(true) ||
                   !block->isStrictMode()))
    return runtime.raiseTypeError("Invalid native base class constructor");
  if (ctor->isLazy())
    JSObject::initializeLazyObject(runtime, ctor);
  NamedPropertyDescriptor descriptor;
  if (LLVM_UNLIKELY(!JSObject::getOwnNamedDescriptor(
          ctor, runtime, Predefined::getSymbolID(Predefined::prototype), descriptor) ||
      descriptor.flags.accessor || descriptor.flags.enumerable ||
      descriptor.flags.configurable ||
      descriptor.flags.writable != initializing))
    return runtime.raiseTypeError("Invalid native base class prototype descriptor");
  auto prototypeValue = runtime.makeHandle(
      JSObject::getNamedSlotValueUnsafe(*ctor, runtime, descriptor).unboxToHV(runtime));
  auto prototype = Handle<JSObject>::dyn_vmcast(prototypeValue);
  if (LLVM_UNLIKELY(!prototype || prototype->isProxyObject() ||
                   prototype->isHostObject()))
    return runtime.raiseTypeError("Invalid native base class prototype object");
  if (initializing) {
                                                                              
                                                                            
                                                                          
    auto objectPrototype = Handle<JSObject>::vmcast(&runtime.objectPrototype);
    auto functionPrototype = Handle<JSObject>::vmcast(&runtime.functionPrototype);
    NamedPropertyDescriptor backlink;
    if (LLVM_UNLIKELY(prototype->getParent(runtime) != *objectPrototype ||
                     ctor->getParent(runtime) != *functionPrototype ||
        !JSObject::getOwnNamedDescriptor(prototype, runtime,
            Predefined::getSymbolID(Predefined::constructor), backlink) ||
        backlink.flags.accessor || backlink.flags.enumerable ||
        !backlink.flags.writable || !backlink.flags.configurable))
      return runtime.raiseTypeError("Invalid fresh native class prototype");
    auto owner = JSObject::getNamedSlotValueUnsafe(*prototype, runtime, backlink)
                     .unboxToHV(runtime);
    if (LLVM_UNLIKELY(!owner.isObject() || owner.getObject(runtime) != *ctor))
      return runtime.raiseTypeError("Invalid native class constructor identity");
  }
  return prototype;
}

CallResult<HermesValue>
hermesBuiltinInitBaseClass(void *, Runtime &runtime, NativeArgs args) {
  GCScope scope{runtime};
  auto ctor = args.dyncastArg<JSFunction>(0);
  if (LLVM_UNLIKELY(!ctor))
    return runtime.raiseTypeError("Native class initialization needs a JS constructor");
  auto prototype = nativeBaseClassPrototype(runtime, ctor, true);
  if (LLVM_UNLIKELY(prototype == ExecutionStatus::EXCEPTION))
    return ExecutionStatus::EXCEPTION;
  DefinePropertyFlags flags;
  flags.setWritable = 1;
  flags.writable = 0;
  auto result = JSObject::defineOwnProperty(ctor, runtime,
      Predefined::getSymbolID(Predefined::prototype), flags,
      runtime.getUndefinedValue(), PropOpFlags().plusThrowOnError());
  if (LLVM_UNLIKELY(result == ExecutionStatus::EXCEPTION))
    return ExecutionStatus::EXCEPTION;
  if (LLVM_UNLIKELY(!*result))
    return runtime.raiseTypeError("Cannot finalize native class prototype");
  return HermesValue::encodeUndefinedValue();
}


CallResult<HermesValue>
hermesBuiltinClassHeritagePrototype(void *, Runtime &runtime, NativeArgs args) {
  GCScope scope{runtime}; auto parent=args.getArgHandle(0);
  if(parent->isNull()) return HermesValue::encodeNullValue();
  auto fn=Handle<Callable>::dyn_vmcast(parent);
  if(!fn) return runtime.raiseTypeError("Class heritage is not a constructor");
  auto valid=isConstructor(runtime,*fn);
  if(valid==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
  if(!*valid)return runtime.raiseTypeError("Class heritage is not a constructor");
  auto proto=JSObject::getNamed_RJS(fn,runtime,Predefined::getSymbolID(Predefined::prototype));
  if(proto==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
  if(!proto->get().isObject() && !proto->get().isNull())
    return runtime.raiseTypeError("Class heritage prototype must be object or null");
  return proto->get();
}

CallResult<HermesValue>
hermesBuiltinInitDerivedClass(void *, Runtime &runtime, NativeArgs args) {
  GCScope scope{runtime};auto ctor=args.dyncastArg<JSFunction>(0);
  if(!ctor || !ctor->getCodeBlock(runtime)->getHeaderFlags().derivedConstructor)
    return runtime.raiseTypeError("Invalid derived constructor");
  auto prototype=nativeBaseClassPrototype(runtime,ctor,true);
  if(prototype==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
  auto parent=args.getArgHandle(1), proto=args.getArgHandle(2);
  if((!parent->isObject() && !parent->isNull()) ||
      (!proto->isObject() && !proto->isNull()))
    return runtime.raiseTypeError("Invalid captured class heritage");
  auto parentObject=parent->isNull()
      ? Handle<JSObject>::vmcast(&runtime.functionPrototype)
      : Handle<JSObject>::vmcast(parent);
  auto protoObject=proto->isNull() ? runtime.makeHandle<JSObject>(nullptr)
      : Handle<JSObject>::vmcast(proto);
  auto a=JSObject::setParent(*ctor,runtime,*parentObject,PropOpFlags().plusThrowOnError());
  if(a==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
  auto b=JSObject::setParent(**prototype,runtime,*protoObject,PropOpFlags().plusThrowOnError());
  if(b==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
  DefinePropertyFlags flags;flags.setWritable=1;flags.writable=0;
  auto result=JSObject::defineOwnProperty(ctor,runtime,
      Predefined::getSymbolID(Predefined::prototype),flags,
      runtime.getUndefinedValue(),PropOpFlags().plusThrowOnError());
  if(result==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
  return HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue>
hermesBuiltinSuperPropertyGet(void *, Runtime &runtime, NativeArgs args) {
  auto home=args.dyncastArg<JSObject>(0);
  if(!home)return runtime.raiseTypeError("Invalid super home object");
  auto *parent=home->getParent(runtime);
  if(!parent)return runtime.raiseTypeError("Cannot read super property from null");
  auto base=runtime.makeHandle(parent);
                                                                        
                                                                          
  if(args.getArgCount()==4){
    auto status=JSObject::putComputedWithReceiver_RJS(base,runtime,args.getArgHandle(1),args.getArgHandle(3),args.getArgHandle(2));
    if(status==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
    if(!*status)return runtime.raiseTypeError("super property assignment failed");
    return args.getArg(3);
  }
  if(args.getArgCount()!=3)return runtime.raiseTypeError("Invalid super property operation arity");
  return JSObject::getComputedWithReceiver_RJS(
      base,runtime,args.getArgHandle(1),args.getArgHandle(2)).toCallResultHermesValue();
}

CallResult<HermesValue>
hermesBuiltinGetSuperConstructor(void *, Runtime &runtime, NativeArgs args) {
  auto ctor=args.dyncastArg<JSFunction>(0);
  if(!ctor || !ctor->getCodeBlock(runtime)->getHeaderFlags().derivedConstructor)
    return runtime.raiseTypeError("Invalid active derived constructor");
  auto *parent=ctor->getParent(runtime);
  return parent ? HermesValue::encodeObjectValue(parent) : HermesValue::encodeNullValue();
}
CallResult<HermesValue>
hermesBuiltinAssertDerivedThis(void *, Runtime &runtime, NativeArgs args) {
  if(!args.getArg(0).isObject())return runtime.raiseReferenceError("this is uninitialized before super()");
  return args.getArg(0);
}
CallResult<HermesValue>
hermesBuiltinAssertDerivedUninitialized(void *, Runtime &runtime, NativeArgs args) {
  if(!args.getArg(0).isUndefined())return runtime.raiseReferenceError("super() already initialized this");
  return HermesValue::encodeUndefinedValue();
}
CallResult<HermesValue>
hermesBuiltinDerivedConstructorReturn(void *, Runtime &runtime, NativeArgs args) {
  auto value=args.getArg(1);
  if(value.isObject())return value;
  if(!value.isUndefined())return runtime.raiseTypeError("Derived constructor returned a non-object");
  if(!args.getArg(0).isObject())return runtime.raiseReferenceError("Derived constructor did not initialize this");
  return args.getArg(0);
}
CallResult<HermesValue>
hermesBuiltinConstructWithNewTarget(void *, Runtime &runtime, NativeArgs args) {
  GCScope scope{runtime};auto fn=args.dyncastArg<Callable>(0);
  auto list=args.dyncastArg<JSObject>(1);auto target=args.dyncastArg<Callable>(2);
  if(!fn || !target || !list)return runtime.raiseTypeError("Invalid super construction operands");
  auto count=getArrayLikeLength_RJS(list,runtime);
  if(count==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
  if(*count>UINT32_MAX)return runtime.raiseRangeError("Too many super arguments");
  uint32_t n=static_cast<uint32_t>(*count);
  ScopedNativeCallFrame frame{runtime,n,fn.getHermesValue(),target.getHermesValue(),
      HermesValue::encodeUndefinedValue()};
  if(frame.overflowed())return runtime.raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  frame.fillArguments(n,HermesValue::encodeUndefinedValue());
  if(createListFromArrayLike_RJS(list,runtime,n,
      [&frame](Runtime &,uint64_t i,PseudoHandle<> v){
        frame->getArgRef(i)=v.getHermesValue();return ExecutionStatus::RETURNED;
      })==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
  auto prepared=Callable::prepareThisForConstruct_RJS(fn,runtime,target);
  if(prepared==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
  auto receiver=runtime.makeHandle(std::move(*prepared));
  frame->getThisArgRef()=receiver.getHermesValue();
  auto result=Callable::call(fn,runtime);
  if(result==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
  return result->get().isObject() ? result->get() : receiver.getHermesValue();
}

                                                                            
static CallResult<Handle<>> nativeClassFunctionName(Runtime &runtime, Handle<> key) {
  if(!key->isSymbol()) {
    auto name=toString_RJS(runtime,key);
    if(name==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
    return runtime.makeHandle(name->getHermesValue());
  }
  if(runtime.getIdentifierTable().symbolDescriptionUndefined(key->getSymbol()))
    return runtime.makeHandle(HermesValue::encodeStringValue(runtime.getPredefinedString(Predefined::emptyString)));
  auto desc=runtime.makeHandle(runtime.getStringPrimFromSymbolID(key->getSymbol()));
  auto left=StringPrimitive::createEfficient(runtime,llvh::StringRef("["));
  if(left==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
  auto joined=StringPrimitive::concat(runtime,Handle<StringPrimitive>::vmcast(runtime.makeHandle(*left)),desc);
  if(joined==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
  auto part=Handle<StringPrimitive>::vmcast(runtime.makeHandle(*joined));
  auto right=StringPrimitive::createEfficient(runtime,llvh::StringRef("]"));
  if(right==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
  auto result=StringPrimitive::concat(runtime,part,Handle<StringPrimitive>::vmcast(runtime.makeHandle(*right)));
  if(result==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
  return runtime.makeHandle(*result);
}

CallResult<HermesValue>
hermesBuiltinClassElementKey(void *, Runtime &runtime, NativeArgs args) {
  GCScope scope{runtime};auto result=toPropertyKey(runtime,args.getArgHandle(0));
  if(result==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
  return **result;
}

CallResult<HermesValue>
hermesBuiltinNamePublicFieldFunction(void *, Runtime &runtime, NativeArgs args) {
  GCScope scope{runtime};auto key=args.getArgHandle(0);auto fn=args.dyncastArg<JSFunction>(1);
  if(!fn||(!key->isString()&&!key->isSymbol()))return runtime.raiseTypeError("Invalid cached field function name");
  auto name=nativeClassFunctionName(runtime,key);if(name==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
  DefinePropertyFlags flags;flags.setValue=flags.setWritable=flags.setEnumerable=flags.setConfigurable=1;
  flags.writable=flags.enumerable=0;flags.configurable=1;
  auto result=JSObject::defineOwnProperty(fn,runtime,Predefined::getSymbolID(Predefined::name),flags,*name,PropOpFlags().plusThrowOnError());
  if(result==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
  if(!*result)return runtime.raiseTypeError("Cannot name public field function");
  return fn.getHermesValue();
}

static CallResult<HermesValue> nativeDefineClassMethod(
    Runtime &runtime, NativeArgs args, bool isStatic, unsigned accessorKind = 0) {
  GCScope scope{runtime};
  auto ctor = args.dyncastArg<JSFunction>(0);
  auto method = args.dyncastArg<JSFunction>(2);
  auto key = args.getArgHandle(1);
  if (LLVM_UNLIKELY(!ctor || !method ||
                   !(key->isString() || key->isNumber() || key->isSymbol())))
    return runtime.raiseTypeError("Invalid native instance method operands");
  auto *methodBlock = method->getCodeBlock(runtime);
  if (LLVM_UNLIKELY(!methodBlock->getHeaderFlags().isCallProhibited(true) ||
                   methodBlock->getHeaderFlags().isCallProhibited(false) ||
                   !methodBlock->isStrictMode()))
    return runtime.raiseTypeError("Invalid native instance method flags");
  auto prototypeResult = nativeBaseClassPrototype(runtime, ctor, false);
  if (LLVM_UNLIKELY(prototypeResult == ExecutionStatus::EXCEPTION))
    return ExecutionStatus::EXCEPTION;
  auto prototype = *prototypeResult;
  auto keyResult=toPropertyKey(runtime,key);
  if(keyResult==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
  auto normalizedKey=*keyResult;
  if (method->isLazy())
    JSObject::initializeLazyObject(runtime, method);
  NamedPropertyDescriptor forbiddenPrototype;
                                                                              
                                                                          
                                                                                
  const bool generatorMethod = isStatic && accessorKind == 0 &&
      vmisa<JSGeneratorFunction>(*method);
  if (LLVM_UNLIKELY(!generatorMethod && JSObject::getOwnNamedDescriptor(method, runtime,
      Predefined::getSymbolID(Predefined::prototype), forbiddenPrototype)))
    return runtime.raiseTypeError("Native method must not have a prototype property");

  auto nameResult=nativeClassFunctionName(runtime,normalizedKey);
  if(nameResult==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
  auto functionName = *nameResult;
  if (accessorKind) {
    auto prefixResult = StringPrimitive::createEfficient(runtime,
        llvh::StringRef(accessorKind == 1 ? "get " : "set "));
    if (LLVM_UNLIKELY(prefixResult == ExecutionStatus::EXCEPTION))
      return ExecutionStatus::EXCEPTION;
    auto joined = StringPrimitive::concat(runtime, Handle<StringPrimitive>::vmcast(runtime.makeHandle(*prefixResult)),
        Handle<StringPrimitive>::vmcast(functionName));
    if (LLVM_UNLIKELY(joined == ExecutionStatus::EXCEPTION))
      return ExecutionStatus::EXCEPTION;
    functionName = runtime.makeHandle(*joined);
  }
  DefinePropertyFlags nameFlags;
  nameFlags.setValue = 1;
  nameFlags.setWritable = 1;
  nameFlags.writable = 0;
  nameFlags.setEnumerable = 1;
  nameFlags.enumerable = 0;
  nameFlags.setConfigurable = 1;
  nameFlags.configurable = 1;
  auto named = JSObject::defineOwnProperty(method, runtime,
      Predefined::getSymbolID(Predefined::name), nameFlags, functionName,
      PropOpFlags().plusThrowOnError());
  if (LLVM_UNLIKELY(named == ExecutionStatus::EXCEPTION))
    return ExecutionStatus::EXCEPTION;
  if (LLVM_UNLIKELY(!*named))
    return runtime.raiseTypeError("Cannot name native class method");
                                                                        
                                                                          
  auto target = isStatic ? Handle<JSObject>::vmcast(ctor) : prototype;
  DefinePropertyFlags propertyFlags = DefinePropertyFlags::getNewNonEnumerableFlags();
  auto propertyValue = Handle<>(method);
  if (accessorKind) {
    propertyFlags = DefinePropertyFlags{};
    propertyFlags.setEnumerable = 1;
    propertyFlags.enumerable = 0;
    propertyFlags.setConfigurable = 1;
    propertyFlags.configurable = 1;
    propertyFlags.setGetter = accessorKind == 1;
    propertyFlags.setSetter = accessorKind == 2;
    auto empty = Runtime::makeNullHandle<Callable>();
    auto callable = Handle<Callable>::vmcast(method);
    propertyValue = runtime.makeHandle(PropertyAccessor::create(runtime,
        accessorKind == 1 ? callable : empty, accessorKind == 2 ? callable : empty));
  }
                                                                             
                                                                                
  auto defined = JSObject::defineOwnComputedPrimitive(target, runtime,
      normalizedKey, propertyFlags, propertyValue, PropOpFlags().plusThrowOnError());
  if (LLVM_UNLIKELY(defined == ExecutionStatus::EXCEPTION))
    return ExecutionStatus::EXCEPTION;
  if (LLVM_UNLIKELY(!*defined))
    return runtime.raiseTypeError("Cannot define native class method");
  return HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue>
hermesBuiltinDefineInstanceClassMethod(void *, Runtime &runtime, NativeArgs args) {
  return nativeDefineClassMethod(runtime, args, false);
}

CallResult<HermesValue>
hermesBuiltinDefineStaticClassMethod(void *, Runtime &runtime, NativeArgs args) {
  return nativeDefineClassMethod(runtime, args, true);
}

CallResult<HermesValue>
hermesBuiltinDefineInstanceClassGetter(void *, Runtime &runtime, NativeArgs args) {
  return nativeDefineClassMethod(runtime, args, false, 1);
}

CallResult<HermesValue>
hermesBuiltinDefineInstanceClassSetter(void *, Runtime &runtime, NativeArgs args) {
  return nativeDefineClassMethod(runtime, args, false, 2);
}

CallResult<HermesValue>
hermesBuiltinDefineStaticClassGetter(void *, Runtime &runtime, NativeArgs args) {
  return nativeDefineClassMethod(runtime, args, true, 1);
}

CallResult<HermesValue>
hermesBuiltinDefineStaticClassSetter(void *, Runtime &runtime, NativeArgs args) {
  return nativeDefineClassMethod(runtime, args, true, 2);
}

                                                                         
                                                                              
CallResult<HermesValue>
hermesBuiltinDefinePublicClassField(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};
  auto receiver = args.dyncastArg<JSFunction>(0);
  const HermesValue key = args.getArg(1);
  if (LLVM_UNLIKELY(!receiver || (!key.isString() && !key.isNumber() && !key.isSymbol())))
    return runtime.raiseTypeError("Invalid native public class field definition");
  auto *block = receiver->getCodeBlock(runtime);
  if (LLVM_UNLIKELY(!block->getHeaderFlags().isCallProhibited(false) ||
                   block->getHeaderFlags().isCallProhibited(true) ||
                   !block->isStrictMode()))
    return runtime.raiseTypeError("Invalid native public class constructor flags");
  auto result = JSObject::defineOwnComputedPrimitive(
      receiver, runtime, args.getArgHandle(1),
      DefinePropertyFlags::getDefaultNewPropertyFlags(), args.getArgHandle(2),
      PropOpFlags().plusThrowOnError());
  if (LLVM_UNLIKELY(result == ExecutionStatus::EXCEPTION))
    return ExecutionStatus::EXCEPTION;
  if (LLVM_UNLIKELY(!*result))
    return runtime.raiseTypeError("Cannot define native public class field");
  return HermesValue::encodeUndefinedValue();
}

                                                                          
                                                                             
CallResult<HermesValue>
hermesBuiltinDefinePublicInstanceClassField(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};
  auto receiver=args.dyncastArg<JSObject>(0);
  const HermesValue key=args.getArg(1);
  if (LLVM_UNLIKELY(!receiver || (!key.isString() && !key.isNumber() && !key.isSymbol())))
    return runtime.raiseTypeError("Invalid native public instance field definition");
  auto result=JSObject::defineOwnComputedPrimitive(receiver,runtime,args.getArgHandle(1),
      DefinePropertyFlags::getDefaultNewPropertyFlags(),args.getArgHandle(2),
      PropOpFlags().plusThrowOnError());
  if (LLVM_UNLIKELY(result==ExecutionStatus::EXCEPTION)) return ExecutionStatus::EXCEPTION;
  if (LLVM_UNLIKELY(!*result))
    return runtime.raiseTypeError("Cannot define native public instance field");
  return HermesValue::encodeUndefinedValue();
}

void createHermesBuiltins(
    Runtime &runtime,
    llvh::MutableArrayRef<Callable *> builtins) {
  auto defineInternMethod = [&](BuiltinMethod::Enum builtinIndex,
                                Predefined::Str symID,
                                NativeFunctionPtr func,
                                uint8_t count = 0) {
    auto method = NativeFunction::create(
        runtime,
        Handle<JSObject>::vmcast(&runtime.functionPrototype),
        nullptr              ,
        func,
        Predefined::getSymbolID(symID),
        count,
        Runtime::makeNullHandle<JSObject>());

    assert(builtins[builtinIndex] == nullptr && "builtin already defined");
    builtins[builtinIndex] = *method;
  };

                                      
  namespace P = Predefined;
  namespace B = BuiltinMethod;
  defineInternMethod(
      B::HermesBuiltin_silentSetPrototypeOf,
      P::silentSetPrototypeOf,
      silentObjectSetPrototypeOf,
      2);
  defineInternMethod(
      B::HermesBuiltin_getTemplateObject,
      P::getTemplateObject,
      hermesBuiltinGetTemplateObject);
  defineInternMethod(
      B::HermesBuiltin_ensureObject,
      P::ensureObject,
      hermesBuiltinEnsureObject,
      2);
  defineInternMethod(
      B::HermesBuiltin_getMethod, P::getMethod, hermesBuiltinGetMethod, 2);
  defineInternMethod(
      B::HermesBuiltin_throwTypeError,
      P::throwTypeError,
      hermesBuiltinThrowTypeError,
      1);
  defineInternMethod(
      B::HermesBuiltin_generatorSetDelegated,
      P::generatorSetDelegated,
      hermesBuiltinGeneratorSetDelegated,
      1);
  defineInternMethod(
      B::HermesBuiltin_copyDataProperties,
      P::copyDataProperties,
      hermesBuiltinCopyDataProperties,
      3);
  defineInternMethod(
      B::HermesBuiltin_copyRestArgs,
      P::copyRestArgs,
      hermesBuiltinCopyRestArgs,
      1);
  defineInternMethod(
      B::HermesBuiltin_arraySpread,
      P::arraySpread,
      hermesBuiltinArraySpread,
      2);
  defineInternMethod(B::HermesBuiltin_apply, P::apply, hermesBuiltinApply, 2);
  defineInternMethod(
      B::HermesBuiltin_exportAll, P::exportAll, hermesBuiltinExportAll);
  defineInternMethod(
      B::HermesBuiltin_exponentiationOperator,
      P::exponentiationOperator,
      hermesBuiltinExponentiate);
  defineInternMethod(
      B::HermesBuiltin_initRegexNamedGroups,
      P::initRegexNamedGroups,
      hermesBuiltinInitRegexNamedGroups);

  defineInternMethod(
      B::HermesBuiltin_getOriginalNativeErrorConstructor,
      P::getOriginalNativeErrorConstructor,
      hermesBuiltinGetOriginalNativeErrorConstructor);

  defineInternMethod(B::HermesBuiltin_privateNameCreate,
      P::privateNameCreate, hermesBuiltinPrivateNameCreate, 0);
  defineInternMethod(B::HermesBuiltin_privateFieldInit,
      P::privateFieldInit, hermesBuiltinPrivateFieldInit, 3);
  defineInternMethod(B::HermesBuiltin_privateFieldGet,
      P::privateFieldGet, hermesBuiltinPrivateFieldGet, 2);
  defineInternMethod(B::HermesBuiltin_privateFieldSet,
      P::privateFieldSet, hermesBuiltinPrivateFieldSet, 3);
  defineInternMethod(B::HermesBuiltin_classHeritagePrototype, P::classHeritagePrototype, hermesBuiltinClassHeritagePrototype, 1);
  defineInternMethod(B::HermesBuiltin_initDerivedClass, P::initDerivedClass, hermesBuiltinInitDerivedClass, 3);
  defineInternMethod(B::HermesBuiltin_getSuperConstructor, P::getSuperConstructor, hermesBuiltinGetSuperConstructor, 1);
  defineInternMethod(B::HermesBuiltin_superPropertyGet, P::superPropertyGet, hermesBuiltinSuperPropertyGet, 3);
  defineInternMethod(B::HermesBuiltin_assertDerivedThis, P::assertDerivedThis, hermesBuiltinAssertDerivedThis, 1);
  defineInternMethod(B::HermesBuiltin_assertDerivedUninitialized, P::assertDerivedUninitialized, hermesBuiltinAssertDerivedUninitialized, 1);
  defineInternMethod(B::HermesBuiltin_derivedConstructorReturn, P::derivedConstructorReturn, hermesBuiltinDerivedConstructorReturn, 2);
  defineInternMethod(B::HermesBuiltin_constructWithNewTarget, P::constructWithNewTarget, hermesBuiltinConstructWithNewTarget, 3);
  defineInternMethod(B::HermesBuiltin_initBaseClass,
      P::initBaseClass, hermesBuiltinInitBaseClass, 1);
  defineInternMethod(B::HermesBuiltin_defineInstanceClassMethod,
      P::defineInstanceClassMethod, hermesBuiltinDefineInstanceClassMethod, 3);

  defineInternMethod(B::HermesBuiltin_classElementKey,
      P::classElementKey, hermesBuiltinClassElementKey, 1);
  defineInternMethod(B::HermesBuiltin_namePublicFieldFunction,
      P::namePublicFieldFunction, hermesBuiltinNamePublicFieldFunction, 2);
  defineInternMethod(B::HermesBuiltin_definePublicClassField,
      P::definePublicClassField, hermesBuiltinDefinePublicClassField, 3);
  defineInternMethod(B::HermesBuiltin_definePublicInstanceClassField,
      P::definePublicInstanceClassField, hermesBuiltinDefinePublicInstanceClassField, 3);
  defineInternMethod(B::HermesBuiltin_defineStaticClassMethod,
      P::defineStaticClassMethod, hermesBuiltinDefineStaticClassMethod, 3);
  defineInternMethod(B::HermesBuiltin_defineInstanceClassGetter,
      P::defineInstanceClassGetter, hermesBuiltinDefineInstanceClassGetter, 3);
  defineInternMethod(B::HermesBuiltin_defineInstanceClassSetter,
      P::defineInstanceClassSetter, hermesBuiltinDefineInstanceClassSetter, 3);
  defineInternMethod(B::HermesBuiltin_defineStaticClassGetter,
      P::defineStaticClassGetter, hermesBuiltinDefineStaticClassGetter, 3);
  defineInternMethod(B::HermesBuiltin_defineStaticClassSetter,
      P::defineStaticClassSetter, hermesBuiltinDefineStaticClassSetter, 3);

                                                                      
  defineInternMethod(
      B::HermesBuiltin_requireFast, P::requireFast, requireFast, 1);
}

}                
}                    

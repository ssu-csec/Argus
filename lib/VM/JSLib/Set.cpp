/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                                              
                                                                                

#include "JSLibInternal.h"

#include "hermes/VM/StringPrimitive.h"

namespace hermes {
namespace vm {

Handle<JSObject> createSetConstructor(Runtime &runtime) {
  auto setPrototype = Handle<JSObject>::vmcast(&runtime.setPrototype);

                               
  defineMethod(
      runtime,
      setPrototype,
      Predefined::getSymbolID(Predefined::add),
      nullptr,
      setPrototypeAdd,
      1);

  defineMethod(
      runtime,
      setPrototype,
      Predefined::getSymbolID(Predefined::clear),
      nullptr,
      setPrototypeClear,
      0);

  defineMethod(
      runtime,
      setPrototype,
      Predefined::getSymbolID(Predefined::deleteStr),
      nullptr,
      setPrototypeDelete,
      1);

  defineMethod(
      runtime,
      setPrototype,
      Predefined::getSymbolID(Predefined::entries),
      nullptr,
      setPrototypeEntries,
      0);

  defineMethod(
      runtime,
      setPrototype,
      Predefined::getSymbolID(Predefined::forEach),
      nullptr,
      setPrototypeForEach,
      1);

  defineMethod(
      runtime,
      setPrototype,
      Predefined::getSymbolID(Predefined::has),
      nullptr,
      setPrototypeHas,
      1);

  defineAccessor(
      runtime,
      setPrototype,
      Predefined::getSymbolID(Predefined::size),
      nullptr,
      setPrototypeSizeGetter,
      nullptr,
      false,
      true);

  defineMethod(
      runtime,
      setPrototype,
      Predefined::getSymbolID(Predefined::values),
      nullptr,
      setPrototypeValues,
      0);

  DefinePropertyFlags dpf = DefinePropertyFlags::getNewNonEnumerableFlags();

                                                            
  Handle<NativeFunction> propValue = Handle<NativeFunction>::vmcast(
      runtime.makeHandle(runtime.ignoreAllocationFailure(
          JSObject::getNamed_RJS(
              setPrototype,
              runtime,
              Predefined::getSymbolID(Predefined::values)))));
  runtime.ignoreAllocationFailure(
      JSObject::defineOwnProperty(
          setPrototype,
          runtime,
          Predefined::getSymbolID(Predefined::keys),
          dpf,
          propValue));
  runtime.ignoreAllocationFailure(
      JSObject::defineOwnProperty(
          setPrototype,
          runtime,
          Predefined::getSymbolID(Predefined::SymbolIterator),
          dpf,
          propValue));

  dpf = DefinePropertyFlags::getDefaultNewPropertyFlags();
  dpf.writable = 0;
  dpf.enumerable = 0;
  defineProperty(
      runtime,
      setPrototype,
      Predefined::getSymbolID(Predefined::SymbolToStringTag),
      runtime.getPredefinedStringHandle(Predefined::Set),
      dpf);

  auto cons = defineSystemConstructor<JSSet>(
      runtime,
      Predefined::getSymbolID(Predefined::Set),
      setConstructor,
      setPrototype,
      0,
      CellKind::JSSetKind);

  return cons;
}

CallResult<HermesValue>
setConstructor(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};
  if (LLVM_UNLIKELY(!args.isConstructorCall())) {
    return runtime.raiseTypeError("Constructor Set requires 'new'");
  }
  auto selfHandle = args.dyncastThis<JSSet>();
  if (LLVM_UNLIKELY(!selfHandle)) {
    return runtime.raiseTypeError("Set Constructor only applies to Set object");
  }

  JSSet::initializeStorage(selfHandle, runtime);

  if (args.getArgCount() == 0 || args.getArg(0).isUndefined() ||
      args.getArg(0).isNull()) {
    return selfHandle.getHermesValue();
  }

  auto propRes = JSObject::getNamed_RJS(
      selfHandle, runtime, Predefined::getSymbolID(Predefined::add));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

                                                                     
  auto adder =
      Handle<Callable>::dyn_vmcast(runtime.makeHandle(std::move(*propRes)));
  if (!adder) {
    return runtime.raiseTypeError("Property 'add' for Set is not callable");
  }

  auto iterRes = getIterator(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(iterRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto iteratorRecord = *iterRes;

                                             
  MutableHandle<JSObject> tmpHandle{runtime};
  auto marker = gcScope.createMarker();

                                                         
                                                                              
  for (;;) {
    gcScope.flushToMarker(marker);
    CallResult<Handle<JSObject>> nextRes =
        iteratorStep(runtime, iteratorRecord);
    if (LLVM_UNLIKELY(nextRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (!*nextRes) {
                             
      return selfHandle.getHermesValue();
    }
    tmpHandle = vmcast<JSObject>(nextRes->getHermesValue());
    auto nextValueRes = JSObject::getNamed_RJS(
        tmpHandle, runtime, Predefined::getSymbolID(Predefined::value));
    if (LLVM_UNLIKELY(nextValueRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }

    if (LLVM_UNLIKELY(
            Callable::executeCall1(
                adder, runtime, selfHandle, nextValueRes->get()) ==
            ExecutionStatus::EXCEPTION)) {
      return iteratorCloseAndRethrow(runtime, iteratorRecord.iterator);
    }
  }

  return selfHandle.getHermesValue();
}

                                            
CallResult<HermesValue>
setPrototypeAdd(void *, Runtime &runtime, NativeArgs args) {
  auto selfHandle = args.dyncastThis<JSSet>();
  if (LLVM_UNLIKELY(!selfHandle)) {
    return runtime.raiseTypeError("Non-Set object called on Set.prototype.add");
  }
  auto valueHandle = args.getArgHandle(0);
                                        
                                                                                
                                                                        
  auto value = valueHandle->isNumber() && valueHandle->getNumber() == 0
      ? HandleRootOwner::getZeroValue()
      : valueHandle;
  JSSet::addValue(selfHandle, runtime, value, value);
  return selfHandle.getHermesValue();
}

CallResult<HermesValue>
setPrototypeClear(void *, Runtime &runtime, NativeArgs args) {
  auto selfHandle = args.dyncastThis<JSSet>();
  if (LLVM_UNLIKELY(!selfHandle)) {
    return runtime.raiseTypeError(
        "Non-Set object called on Set.prototype.clear");
  }
  JSSet::clear(selfHandle, runtime);
  return HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue>
setPrototypeDelete(void *, Runtime &runtime, NativeArgs args) {
  auto selfHandle = args.dyncastThis<JSSet>();
  if (LLVM_UNLIKELY(!selfHandle)) {
    return runtime.raiseTypeError(
        "Non-Set object called on Set.prototype.delete");
  }
  return HermesValue::encodeBoolValue(
      JSSet::deleteKey(selfHandle, runtime, args.getArgHandle(0)));
}

CallResult<HermesValue>
setPrototypeEntries(void *, Runtime &runtime, NativeArgs args) {
  auto selfHandle = args.dyncastThis<JSSet>();
  if (LLVM_UNLIKELY(!selfHandle)) {
    return runtime.raiseTypeError(
        "Non-Set object called on Set.prototype.entries");
  }
  auto iterator = runtime.makeHandle(
      JSSetIterator::create(
          runtime, Handle<JSObject>::vmcast(&runtime.setIteratorPrototype)));
  iterator->initializeIterator(runtime, selfHandle, IterationKind::Entry);
  return iterator.getHermesValue();
}

CallResult<HermesValue>
setPrototypeForEach(void *, Runtime &runtime, NativeArgs args) {
  auto selfHandle = args.dyncastThis<JSSet>();
  if (LLVM_UNLIKELY(!selfHandle)) {
    return runtime.raiseTypeError(
        "Non-Set object called on Set.prototype.forEach");
  }
  auto callbackfn = args.dyncastArg<Callable>(0);
  if (LLVM_UNLIKELY(!callbackfn)) {
    return runtime.raiseTypeError(
        "callbackfn must be Callable inSet.prototype.forEach");
  }
  auto thisArg = args.getArgHandle(1);
  if (LLVM_UNLIKELY(
          JSSet::forEach(selfHandle, runtime, callbackfn, thisArg) ==
          ExecutionStatus::EXCEPTION))
    return ExecutionStatus::EXCEPTION;
  return HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue>
setPrototypeHas(void *, Runtime &runtime, NativeArgs args) {
  auto selfHandle = args.dyncastThis<JSSet>();
  if (LLVM_UNLIKELY(!selfHandle)) {
    return runtime.raiseTypeError("Non-Set object called on Set.prototype.has");
  }
  return HermesValue::encodeBoolValue(
      JSSet::hasKey(selfHandle, runtime, args.getArgHandle(0)));
}

CallResult<HermesValue>
setPrototypeSizeGetter(void *, Runtime &runtime, NativeArgs args) {
  auto self = dyn_vmcast<JSSet>(args.getThisArg());
  if (LLVM_UNLIKELY(!self)) {
    return runtime.raiseTypeError(
        "Non-Set object called on Set.prototype.size");
  }
  return HermesValue::encodeUntrustedNumberValue(JSSet::getSize(self, runtime));
}

CallResult<HermesValue>
setPrototypeValues(void *, Runtime &runtime, NativeArgs args) {
  auto selfHandle = args.dyncastThis<JSSet>();
  if (LLVM_UNLIKELY(!selfHandle)) {
    return runtime.raiseTypeError(
        "Non-Set object called on Set.prototype.values");
  }
  auto iterator = runtime.makeHandle(
      JSSetIterator::create(
          runtime, Handle<JSObject>::vmcast(&runtime.setIteratorPrototype)));
  iterator->initializeIterator(runtime, selfHandle, IterationKind::Value);
  return iterator.getHermesValue();
}

Handle<JSObject> createSetIteratorPrototype(Runtime &runtime) {
  auto parentHandle = runtime.makeHandle(
      JSObject::create(
          runtime, Handle<JSObject>::vmcast(&runtime.iteratorPrototype)));
  defineMethod(
      runtime,
      parentHandle,
      Predefined::getSymbolID(Predefined::next),
      nullptr,
      setIteratorPrototypeNext,
      0);

  auto dpf = DefinePropertyFlags::getDefaultNewPropertyFlags();
  dpf.writable = 0;
  dpf.enumerable = 0;
  defineProperty(
      runtime,
      parentHandle,
      Predefined::getSymbolID(Predefined::SymbolToStringTag),
      runtime.getPredefinedStringHandle(Predefined::SetIterator),
      dpf);

  return parentHandle;
}

CallResult<HermesValue>
setIteratorPrototypeNext(void *, Runtime &runtime, NativeArgs args) {
  auto selfHandle = args.dyncastThis<JSSetIterator>();
  if (LLVM_UNLIKELY(!selfHandle)) {
    return runtime.raiseTypeError(
        "Non-SetIterator object called on SetIterator.prototype.next");
  }
  auto cr = JSSetIterator::nextElement(selfHandle, runtime);
  if (cr == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  return *cr;
}
}                
}                    

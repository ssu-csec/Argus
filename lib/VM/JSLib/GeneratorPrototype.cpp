/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                                                
                                                                                
#include "JSLibInternal.h"
#include "hermes/FrontEndDefs/Builtins.h"

#include "hermes/VM/JSGenerator.h"
#include "hermes/VM/Operations.h"
#include "hermes/VM/Runtime.h"

namespace hermes {
namespace vm {

void populateGeneratorPrototype(Runtime &runtime) {
  auto proto = Handle<JSObject>::vmcast(&runtime.generatorPrototype);

  defineMethod(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::next),
      nullptr,
      generatorPrototypeNext,
      1);

  defineMethod(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::returnStr),
                    (void *)false,
      generatorPrototypeReturnOrThrow,
      1);
  defineMethod(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::throwStr),
                    (void *)true,
      generatorPrototypeReturnOrThrow,
      1);

  auto dpf = DefinePropertyFlags::getDefaultNewPropertyFlags();
  dpf.writable = 0;
  dpf.enumerable = 0;

                                                                        
                                                                         
  defineProperty(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::constructor),
      Handle<>(&runtime.generatorFunctionPrototype),
      dpf);

  defineProperty(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::SymbolToStringTag),
      runtime.getPredefinedStringHandle(Predefined::Generator),
      dpf);
}

static CallResult<HermesValue> asyncIteratorSelf(void *, Runtime &, NativeArgs args) { return args.getThisArg(); }
static CallResult<HermesValue> asyncGeneratorRequest(void *ctx, Runtime &runtime, NativeArgs args) {
  auto result = Callable::executeCall1(runtime.makeHandle(runtime.getBuiltinCallable(
      static_cast<unsigned>(reinterpret_cast<uintptr_t>(ctx)))), runtime,
      args.getThisHandle(), args.getArg(0));
  if (result == ExecutionStatus::EXCEPTION) return ExecutionStatus::EXCEPTION;
  return result->get();
}
void populateAsyncGeneratorPrototype(Runtime &runtime) {
  auto proto = Handle<JSObject>::vmcast(&runtime.asyncGeneratorPrototype);
  auto flags = DefinePropertyFlags::getNewNonEnumerableFlags();
  defineMethod(runtime, proto, Predefined::getSymbolID(Predefined::next), reinterpret_cast<void *>(static_cast<uintptr_t>(BuiltinMethod::HermesBuiltin_asyncGeneratorNext)), asyncGeneratorRequest, 1);
  defineMethod(runtime, proto, Predefined::getSymbolID(Predefined::returnStr), reinterpret_cast<void *>(static_cast<uintptr_t>(BuiltinMethod::HermesBuiltin_asyncGeneratorReturn)), asyncGeneratorRequest, 1);
  defineMethod(runtime, proto, Predefined::getSymbolID(Predefined::throwStr), reinterpret_cast<void *>(static_cast<uintptr_t>(BuiltinMethod::HermesBuiltin_asyncGeneratorThrow)), asyncGeneratorRequest, 1);
  flags.writable = 0;
  defineProperty(runtime, proto, Predefined::getSymbolID(Predefined::constructor), Handle<>(&runtime.asyncGeneratorFunctionPrototype), flags);
  defineProperty(runtime, proto, Predefined::getSymbolID(Predefined::SymbolToStringTag), runtime.getPredefinedStringHandle(Predefined::AsyncGenerator), flags);
  defineMethod(runtime, Handle<JSObject>::vmcast(&runtime.asyncIteratorPrototype), Predefined::getSymbolID(Predefined::SymbolAsyncIterator), nullptr, asyncIteratorSelf, 0);
}

                  
static CallResult<Handle<JSGenerator>> generatorValidate(
    Runtime &runtime,
    Handle<> value) {
  auto generator = Handle<JSGenerator>::dyn_vmcast(value);
  if (!generator) {
    return runtime.raiseTypeError(
        "Generator functions must be called on generators");
  }

  if (JSGenerator::getInnerFunction(runtime, *generator)->getState() ==
      GeneratorInnerFunction::State::Executing) {
    return runtime.raiseTypeError(
        "Generator functions may not be called on executing generators");
  }

  return generator;
}

                  
                                                                                
                          
static CallResult<Handle<JSObject>> generatorResume(
    Runtime &runtime,
    Handle<GeneratorInnerFunction> generator,
    Handle<> value) {
  if (generator->getState() == GeneratorInnerFunction::State::Completed) {
    return createIterResultObject(runtime, Runtime::getUndefinedValue(), true);
  }
  auto valueRes = GeneratorInnerFunction::callInnerFunction(
      generator, runtime, value, GeneratorInnerFunction::Action::Next);
  if (LLVM_UNLIKELY(valueRes == ExecutionStatus::EXCEPTION)) {
    generator->setState(GeneratorInnerFunction::State::Completed);
    return ExecutionStatus::EXCEPTION;
  }
  if (LLVM_UNLIKELY(generator->isDelegated())) {
    generator->setIsDelegated(false);
    return runtime.makeHandle<JSObject>(std::move(*valueRes));
  }
  return createIterResultObject(
      runtime,
      runtime.makeHandle(std::move(*valueRes)),
      generator->getState() == GeneratorInnerFunction::State::Completed);
}

CallResult<HermesValue>
generatorPrototypeNext(void *, Runtime &runtime, NativeArgs args) {
  auto generatorRes = generatorValidate(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(generatorRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  auto result = generatorResume(
      runtime,
      runtime.makeHandle(
          JSGenerator::getInnerFunction(runtime, generatorRes->get())),
      args.getArgHandle(0));
  if (LLVM_UNLIKELY(result == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return result->getHermesValue();
}

                  
                                                                         
                                          
static CallResult<Handle<JSObject>> generatorResumeAbrupt(
    Runtime &runtime,
    Handle<GeneratorInnerFunction> generator,
    Handle<> value,
    bool isThrow) {
  if (generator->getState() == GeneratorInnerFunction::State::SuspendedStart) {
                                         
                                                                       
    generator->setState(GeneratorInnerFunction::State::Completed);
  }

  if (generator->getState() == GeneratorInnerFunction::State::Completed) {
    if (!isThrow) {
                                             
      return createIterResultObject(runtime, value, true);
    }
    runtime.setThrownValue(*value);
    return ExecutionStatus::EXCEPTION;
  }

                                       
  assert(
      generator->getState() == GeneratorInnerFunction::State::SuspendedYield);

  auto action = isThrow ? GeneratorInnerFunction::Action::Throw
                        : GeneratorInnerFunction::Action::Return;
  auto valueRes = GeneratorInnerFunction::callInnerFunction(
      generator, runtime, value, action);
  if (LLVM_UNLIKELY(valueRes == ExecutionStatus::EXCEPTION)) {
    generator->setState(GeneratorInnerFunction::State::Completed);
    return ExecutionStatus::EXCEPTION;
  }
  if (LLVM_UNLIKELY(generator->isDelegated())) {
    generator->setIsDelegated(false);
    return runtime.makeHandle<JSObject>(std::move(*valueRes));
  }
  return createIterResultObject(
      runtime,
      runtime.makeHandle(std::move(*valueRes)),
      generator->getState() == GeneratorInnerFunction::State::Completed);
}

CallResult<HermesValue>
generatorPrototypeReturnOrThrow(void *ctx, Runtime &runtime, NativeArgs args) {
  bool isThrow = static_cast<bool>(ctx);

  auto generatorRes = generatorValidate(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(generatorRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  auto result = generatorResumeAbrupt(
      runtime,
      runtime.makeHandle(
          JSGenerator::getInnerFunction(runtime, generatorRes->get())),
      args.getArgHandle(0),
      isThrow);
  if (result == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  return result->getHermesValue();
}

}                
}                    

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                                                   
                                                                                
#include "JSLibInternal.h"

namespace hermes {
namespace vm {

Handle<JSObject> createGeneratorFunctionConstructor(Runtime &runtime) {
  auto proto = Handle<JSObject>::vmcast(&runtime.generatorFunctionPrototype);

  auto cons = runtime.makeHandle(
      NativeConstructor::create(
          runtime,
          Handle<JSObject>::vmcast(&runtime.functionConstructor),
          nullptr,
          generatorFunctionConstructor,
          1,
          NativeConstructor::creatorFunction<JSGeneratorFunction>,
          CellKind::JSGeneratorFunctionKind));

  auto st = Callable::defineNameLengthAndPrototype(
      cons,
      runtime,
      Predefined::getSymbolID(Predefined::GeneratorFunction),
      1,
      proto,
      Callable::WritablePrototype::No,
      false);
  (void)st;
  assert(
      st != ExecutionStatus::EXCEPTION && "defineLengthAndPrototype() failed");

  auto dpf = DefinePropertyFlags::getDefaultNewPropertyFlags();
  dpf.writable = 0;
  dpf.enumerable = 0;

                                                                        
                                          
  defineProperty(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::constructor),
      cons,
      dpf);

                                                              
                                           
  defineProperty(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::prototype),
      Handle<>(&runtime.generatorPrototype),
      dpf);

  defineProperty(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::SymbolToStringTag),
      runtime.getPredefinedStringHandle(Predefined::GeneratorFunction),
      dpf);

  return cons;
}

CallResult<HermesValue>
generatorFunctionConstructor(void *, Runtime &runtime, NativeArgs args) {
  return createDynamicFunction(runtime, args, DynamicFunctionKind::Generator);
}

CallResult<HermesValue>
asyncGeneratorFunctionConstructor(void *, Runtime &runtime, NativeArgs args) {
  return createDynamicFunction(runtime, args, DynamicFunctionKind::AsyncGenerator);
}

Handle<JSObject> createAsyncGeneratorFunctionConstructor(Runtime &runtime) {
  auto proto = Handle<JSObject>::vmcast(&runtime.asyncGeneratorFunctionPrototype);

  auto cons = runtime.makeHandle(
      NativeConstructor::create(
          runtime,
          Handle<JSObject>::vmcast(&runtime.functionConstructor),
          nullptr,
          asyncGeneratorFunctionConstructor,
          1,
          NativeConstructor::creatorFunction<JSGeneratorFunction>,
          CellKind::JSGeneratorFunctionKind));

  auto st = Callable::defineNameLengthAndPrototype(
      cons,
      runtime,
      Predefined::getSymbolID(Predefined::AsyncGeneratorFunction),
      1,
      proto,
      Callable::WritablePrototype::No,
      false);
  (void)st;
  assert(
      st != ExecutionStatus::EXCEPTION && "defineLengthAndPrototype() failed");

  auto dpf = DefinePropertyFlags::getDefaultNewPropertyFlags();
  dpf.writable = 0;
  dpf.enumerable = 0;

                                                                        
                                          
  defineProperty(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::constructor),
      cons,
      dpf);

                                                              
                                           
  defineProperty(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::prototype),
      Handle<>(&runtime.asyncGeneratorPrototype),
      dpf);

  defineProperty(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::SymbolToStringTag),
      runtime.getPredefinedStringHandle(Predefined::AsyncGeneratorFunction),
      dpf);

  return cons;
}

}                
}                    

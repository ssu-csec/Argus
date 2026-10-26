/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                                              
                                                                                
#include "JSLibInternal.h"

namespace hermes {
namespace vm {

                                                   
CallResult<HermesValue>
asyncFunctionConstructor(void *, Runtime &runtime, NativeArgs args) {
                                                                 
  return createDynamicFunction(runtime, args, DynamicFunctionKind::Async);
}

Handle<JSObject> createAsyncFunctionConstructor(Runtime &runtime) {
  auto proto = Handle<JSObject>::vmcast(&runtime.asyncFunctionPrototype);

                                                        
                                                                  
  auto cons = runtime.makeHandle(
      NativeConstructor::create(
          runtime,
          Handle<JSObject>::vmcast(&runtime.functionConstructor),
          nullptr,
          asyncFunctionConstructor,
          1,
          NativeConstructor::creatorFunction<JSAsyncFunction>,
          CellKind::JSAsyncFunctionKind));

                                                           
                                   
                                      
  auto st = Callable::defineNameLengthAndPrototype(
      cons,
      runtime,
      Predefined::getSymbolID(Predefined::AsyncFunction),
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
      Predefined::getSymbolID(Predefined::SymbolToStringTag),
      runtime.getPredefinedStringHandle(Predefined::AsyncFunction),
      dpf);

  return cons;
}

}                
}                    

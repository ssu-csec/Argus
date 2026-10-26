/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                                                
                                                                                

#include "JSLibInternal.h"
#include "hermes/VM/JSNativeFunctions.h"
#include "hermes/VM/JSWeakRef.h"
#include "hermes/VM/Runtime.h"

namespace hermes {
namespace vm {

                                                                                

Handle<JSObject> createWeakRefConstructor(Runtime &runtime) {
  auto weakRefPrototype = Handle<JSObject>::vmcast(&runtime.weakRefPrototype);

  auto cons = defineSystemConstructor<JSWeakRef>(
      runtime,
      Predefined::getSymbolID(Predefined::WeakRef),
      weakRefConstructor,
      weakRefPrototype,
      1,
      CellKind::JSWeakRefKind);

  DefinePropertyFlags dpf = DefinePropertyFlags::getDefaultNewPropertyFlags();
  dpf.writable = 0;
  dpf.enumerable = 0;
  dpf.configurable = 1;

                                                  
                                                      
                                      
                                                                            
  defineProperty(
      runtime,
      weakRefPrototype,
      Predefined::getSymbolID(Predefined::SymbolToStringTag),
      runtime.getPredefinedStringHandle(Predefined::WeakRef),
      dpf);

                                   
  defineMethod(
      runtime,
      weakRefPrototype,
      Predefined::getSymbolID(Predefined::deref),
      nullptr,
      weakRefPrototypeDeref,
      0);

  return cons;
}

                  
CallResult<HermesValue>
weakRefConstructor(void *, Runtime &runtime, NativeArgs args) {
                                                               
  if (!args.isConstructorCall()) {
    return runtime.raiseTypeError(
        "WeakRef() called in function context instead of constructor");
  }

  auto target = args.dyncastArg<JSObject>(0);
                                                                   
  if (LLVM_UNLIKELY(!target)) {
    return runtime.raiseTypeError("target argument is not an object");
  }

                                             
                                         
  runtime.addToKeptObjects(target);

                                                
  auto self = args.vmcastThis<JSWeakRef>();
  self->setTarget(runtime, target);

                       
  return self.getHermesValue();
}

                  
CallResult<HermesValue>
weakRefPrototypeDeref(void *, Runtime &runtime, NativeArgs args) {
  auto selfHandle = args.dyncastThis<JSWeakRef>();
  if (LLVM_UNLIKELY(!selfHandle)) {
    return runtime.raiseTypeError(
        "WeakRef.prototype.deref() called on non-WeakRef object");
  }

  auto val = selfHandle->deref(runtime);
  if (val.isUndefined())
    return val;

  Handle<JSObject> targetHandle = runtime.makeHandle<JSObject>(val);
                                     
                                 
  runtime.addToKeptObjects(targetHandle);
  return targetHandle.getHermesValue();
}

}                
}                    

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                                              
                                                                                
#include "JSLibInternal.h"

#include "hermes/VM/JSRegExpStringIterator.h"
#include "hermes/VM/Runtime.h"

namespace hermes {
namespace vm {

void populateRegExpStringIteratorPrototype(Runtime &runtime) {
  auto proto = Handle<JSObject>::vmcast(&runtime.regExpStringIteratorPrototype);

  defineMethod(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::next),
      nullptr,
      regExpStringIteratorPrototypeNext,
      0);

                                                                      
  auto dpf = DefinePropertyFlags::getDefaultNewPropertyFlags();
  dpf.writable = 0;
  dpf.enumerable = 0;
  defineProperty(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::SymbolToStringTag),
      runtime.getPredefinedStringHandle(Predefined::RegExpStringIterator),
      dpf);
}

                                                                
CallResult<HermesValue>
regExpStringIteratorPrototypeNext(void *, Runtime &runtime, NativeArgs args) {
                                
                                                              
                                                                                
                                                                 
  auto O = args.dyncastThis<JSRegExpStringIterator>();
  if (LLVM_UNLIKELY(!O)) {
    return runtime.raiseTypeError(
        "RegExpStringIteratorPrototype.next requires 'this' is a RegExp String Iterator");
  }
  return JSRegExpStringIterator::nextElement(O, runtime);
}

}                
}                    

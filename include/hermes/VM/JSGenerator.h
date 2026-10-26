/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_JSGENERATOR_H
#define HERMES_VM_JSGENERATOR_H

#include "hermes/VM/Callable.h"
#include "hermes/VM/JSObject.h"

namespace hermes {
namespace vm {

                                 
                                                                    
                                                                        
                                                                             
                                                                 
                                                                              
                                                                           
                  
class JSGenerator final : public JSObject {
  using Super = JSObject;
  friend void JSGeneratorBuildMeta(const GCCell *cell, Metadata::Builder &mb);

  const static ObjectVTable vt;

 public:
  static constexpr CellKind getCellKind() {
    return CellKind::JSGeneratorKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::JSGeneratorKind;
  }

  static CallResult<PseudoHandle<JSGenerator>> create(
      Runtime &runtime,
      Handle<GeneratorInnerFunction> innerFunction,
      Handle<JSObject> parentHandle);

                                 
  static PseudoHandle<GeneratorInnerFunction> getInnerFunction(
      Runtime &runtime,
      JSGenerator *self) {
    return createPseudoHandle(self->innerFunction_.get(runtime));
  }

 public:
  JSGenerator(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz)
      : JSObject(runtime, *parent, *clazz) {}

 private:
                                                                                
  GCPointer<GeneratorInnerFunction> innerFunction_;
};

}                
}                    

#endif

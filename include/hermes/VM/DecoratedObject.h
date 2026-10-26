/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_DECORATEDOBJECT_H
#define HERMES_VM_DECORATEDOBJECT_H

#include "hermes/VM/JSObject.h"

#include <memory>

namespace hermes {
namespace vm {

                                                                         
                                                                           
                                                                             
                                                                   
                                 
class DecoratedObject : public JSObject {
 public:
  struct Decoration {
                                                                        
                                                                             
    virtual ~Decoration() = default;

                                                                           
                                                                          
    virtual size_t getMallocSize() const;
  };

                                                                         

                                                                     
                                                                     
                                                                               
                                        
                                                  
  static PseudoHandle<DecoratedObject> create(
      Runtime &runtime,
      Handle<JSObject> parentHandle,
      std::unique_ptr<Decoration> decoration,
      unsigned int additionalSlotCount = 0);

                            
  Decoration *getDecoration() {
    return decoration_.get();
  }

                            
  const Decoration *getDecoration() const {
    return decoration_.get();
  }

                                                 
  void setDecoration(std::unique_ptr<Decoration> val) {
    decoration_ = std::move(val);
  }

                                              
                                                                         
                        
  static SmallHermesValue getAdditionalSlotValue(
      DecoratedObject *self,
      Runtime &runtime,
      unsigned index) {
    return JSObject::getInternalProperty(
        self, runtime, numOverlapSlots<DecoratedObject>() + index);
  }

                                          
                                                                         
                        
  static void setAdditionalSlotValue(
      DecoratedObject *self,
      Runtime &runtime,
      unsigned index,
      SmallHermesValue value) {
    JSObject::setInternalProperty(
        self, runtime, numOverlapSlots<DecoratedObject>() + index, value);
  }

  using Super = JSObject;
  static const ObjectVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::DecoratedObjectKind;
  }
  static bool classof(const GCCell *cell) {
    return kindInRange(
        cell->getKind(),
        CellKind::DecoratedObjectKind_first,
        CellKind::DecoratedObjectKind_last);
  }

 public:
  ~DecoratedObject() = default;

  DecoratedObject(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz,
      std::unique_ptr<Decoration> decoration)
      : JSObject(runtime, *parent, *clazz),
        decoration_(std::move(decoration)) {}

 protected:
  static void _finalizeImpl(GCCell *cell, GC &);
  static size_t _mallocSizeImpl(GCCell *cell);

 private:
  std::unique_ptr<Decoration> decoration_;
};

}                
}                    
#endif

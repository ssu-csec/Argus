/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_HOST_MODEL_H
#define HERMES_VM_HOST_MODEL_H

#include "hermes/VM/Callable.h"
#include "hermes/VM/DecoratedObject.h"

namespace hermes {
namespace vm {

                                                                
typedef void (*FinalizeNativeFunctionPtr)(void *context);

                                                                   
                                                                     
                                                                         
              
class FinalizableNativeFunction final : public NativeFunction {
  FinalizeNativeFunctionPtr finalizePtr_;

 public:
  static const CallableVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::FinalizableNativeFunctionKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::FinalizableNativeFunctionKind;
  }

                                                      
                                          
                                               
                                                               
  static CallResult<HermesValue> createWithoutPrototype(
      Runtime &runtime,
      void *context,
      NativeFunctionPtr functionPtr,
      FinalizeNativeFunctionPtr finalizePtr,
      SymbolID name,
      unsigned paramCount);

  void *getContext() {
    return context_;
  }

  FinalizableNativeFunction(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz,
      void *context,
      NativeFunctionPtr functionPtr,
      FinalizeNativeFunctionPtr finalizePtr)
      : NativeFunction(runtime, parent, clazz, context, functionPtr),
        finalizePtr_(finalizePtr) {}

 protected:
  ~FinalizableNativeFunction() {
    finalizePtr_(context_);
  }

  static void _finalizeImpl(GCCell *cell, GC &) {
    auto *self = vmcast<FinalizableNativeFunction>(cell);
                           
    self->~FinalizableNativeFunction();
  }
};

                                                                  
                                              
class HostObjectProxy : public DecoratedObject::Decoration {
 public:
                                                 
  virtual ~HostObjectProxy();

                                                      
  virtual CallResult<HermesValue> get(SymbolID) = 0;

                                                                    
                                                                           
  virtual CallResult<bool> set(SymbolID, HermesValue) = 0;

                                                                             
                                                                             
                    
  virtual CallResult<Handle<JSArray>> getHostPropertyNames() = 0;
};

class HostObject final : public DecoratedObject {
 public:
  static const ObjectVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::HostObjectKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::HostObjectKind;
  }

                                                         
  static CallResult<HermesValue> createWithoutPrototype(
      Runtime &runtime,
      std::unique_ptr<HostObjectProxy> proxy);

  CallResult<HermesValue> get(SymbolID name) {
    return getProxy()->get(name);
  }

  CallResult<bool> set(SymbolID name, HermesValue value) {
    return getProxy()->set(name, value);
  }

  CallResult<Handle<JSArray>> getHostPropertyNames() {
    return getProxy()->getHostPropertyNames();
  }

  HostObjectProxy *getProxy() {
    return static_cast<HostObjectProxy *>(this->getDecoration());
  }

  const HostObjectProxy *getProxy() const {
    return static_cast<const HostObjectProxy *>(this->getDecoration());
  }

  HostObject(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz,
      std::unique_ptr<HostObjectProxy> proxy)
      : DecoratedObject(runtime, parent, clazz, std::move(proxy)) {}
};

}                
}                    

#endif

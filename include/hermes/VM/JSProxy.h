/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_JSPROXY_H
#define HERMES_VM_JSPROXY_H

#include "hermes/VM/JSObject.h"

namespace hermes {
namespace vm {

namespace detail {

                                                                    
                                                                  
                                                          
                                                               
                                                          
struct ProxySlots {
  GCPointer<JSObject> target;
  GCPointer<JSObject> handler;
};

                                                                
                   

detail::ProxySlots &slots(JSObject *selfHandle);

CallResult<Handle<Callable>>
findTrap(Handle<JSObject> selfHandle, Runtime &runtime, Predefined::Str name);

}                    

                                                                       
                                                                
                                                                    
                                                                
                                                                       
                                                                    
                                                                      
                                                                       
                                                                   
                                                               
                                                                  
                                 
class JSProxy : public JSObject {
 public:
  friend void JSProxyBuildMeta(const GCCell *cell, Metadata::Builder &mb);
  friend detail::ProxySlots &detail::slots(JSObject *selfHandle);

  static const ObjectVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::JSProxyKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::JSProxyKind;
  }

  static PseudoHandle<JSProxy> create(Runtime &runtime);

  static PseudoHandle<JSProxy> create(
      Runtime &runtime,
      Handle<JSObject>                ) {
    return create(runtime);
  }

  static void setTargetAndHandler(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<JSObject> target,
      Handle<JSObject> handler);

  static PseudoHandle<JSObject> getTarget(JSObject *proxy, PointerBase &base) {
    return createPseudoHandle(detail::slots(proxy).target.get(base));
  }

  static PseudoHandle<JSObject> getHandler(JSObject *proxy, PointerBase &base) {
    return createPseudoHandle(detail::slots(proxy).handler.get(base));
  }

                                                                      
                                        
  static bool isRevoked(JSObject *proxy, PointerBase &base) {
    return !getHandler(proxy, base);
  }

                                   

  static CallResult<PseudoHandle<JSObject>> getPrototypeOf(
      Handle<JSObject> selfHandle,
      Runtime &runtime);

  static CallResult<bool> setPrototypeOf(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<JSObject> parent);

  static CallResult<bool> isExtensible(
      Handle<JSObject> selfHandle,
      Runtime &runtime);

  static CallResult<bool> preventExtensions(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      PropOpFlags opFlags = PropOpFlags());

  static CallResult<bool> getOwnProperty(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<> nameValHandle,
      ComputedPropertyDescriptor &desc,
      MutableHandle<> *valueOrAccessor);

  static CallResult<bool> defineOwnProperty(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<> nameValHandle,
      DefinePropertyFlags dpFlags,
      Handle<> valueOrAccessor,
      PropOpFlags opFlags);

  static CallResult<bool>
  hasNamed(Handle<JSObject> selfHandle, Runtime &runtime, SymbolID name);

  static CallResult<bool> hasComputed(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<> nameValHandle);

  static CallResult<PseudoHandle<>> getNamed(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      Handle<> receiver);

  static CallResult<PseudoHandle<>> getComputed(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<> nameValHandle,
      Handle<> receiver);

  static CallResult<bool> setNamed(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      Handle<> valueHandle,
      Handle<> receiver);

  static CallResult<bool> setComputed(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<> nameValHandle,
      Handle<> valueHandle,
      Handle<> receiver);

  static CallResult<bool>
  deleteNamed(Handle<JSObject> selfHandle, Runtime &runtime, SymbolID name);

  static CallResult<bool> deleteComputed(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<> nameValHandle);

                                                                         
                                                                       
                                                                        
                         
  static CallResult<PseudoHandle<JSArray>> ownPropertyKeys(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      OwnKeysFlags okFlags);

 public:
  JSProxy(Runtime &runtime, Handle<JSObject> parent, Handle<HiddenClass> clazz)
      : JSObject(runtime, *parent, *clazz) {}

 private:
  detail::ProxySlots slots_;
};

}                
}                    

#endif                       

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                          
                                                                                

#include "JSLibInternal.h"

#include "hermes/VM/JSCallableProxy.h"
#include "hermes/VM/StackFrame-inline.h"

namespace hermes {
namespace vm {

namespace {

                                                                    
                                                     
enum ProxySlotIndexes { revocableProxy, COUNT };

SmallHermesValue getRevocableProxySlot(
    NativeFunction *revoker,
    Runtime &runtime) {
  return NativeFunction::getAdditionalSlotValue(
      revoker, runtime, ProxySlotIndexes::revocableProxy);
}

void setRevocableProxySlot(
    NativeFunction *revoker,
    Runtime &runtime,
    SmallHermesValue value) {
  NativeFunction::setAdditionalSlotValue(
      revoker, runtime, ProxySlotIndexes::revocableProxy, value);
}

                                                                   
                           
                                                                   
                                  
CallResult<Handle<JSObject>> proxyCreate(
    Runtime &runtime,
    Handle<JSObject> target,
    Handle<JSObject> handler,
    Handle<JSObject> proxy) {
                                                                   
  if (!target) {
    return runtime.raiseTypeError("new Proxy target must be an Object");
  }
                                                                    
  if (!handler) {
    return runtime.raiseTypeError("new Proxy handler must be an Object");
  }
                                        
                                                                   
                                                        
                                           
  if (vmisa<Callable>(*target)) {
                                                  
                                                  
                                                         
                                                                        
                                                                     
                                                                         
    proxy = runtime.makeHandle(JSCallableProxy::create(runtime));
  }

                                                             
                                                               

  JSProxy::setTargetAndHandler(proxy, runtime, target, handler);

              
  return proxy;
}

}             

CallResult<HermesValue>
proxyConstructor(void *, Runtime &runtime, NativeArgs args) {
                                                               
  if (!args.isConstructorCall()) {
    return runtime.raiseTypeError(
        "Proxy() called in function context instead of constructor");
  }
                                              
  auto proxyRes = proxyCreate(
      runtime,
      args.dyncastArg<JSObject>(0),
      args.dyncastArg<JSObject>(1),
      args.vmcastThis<JSProxy>());
  if (proxyRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  return proxyRes->getHermesValue();
}

CallResult<HermesValue>
proxyRevocationSteps(void *, Runtime &runtime, NativeArgs args) {
                                      
  auto revoker = vmcast<NativeFunction>(
      runtime.getCurrentFrame()->getCalleeClosureUnsafe());
  SmallHermesValue proxyVal = getRevocableProxySlot(revoker, runtime);
                                       
  if (proxyVal.isNull()) {
    return HermesValue::encodeUndefinedValue();
  }
                                         
  setRevocableProxySlot(revoker, runtime, SmallHermesValue::encodeNullValue());
                                    
  JSObject *proxy = vmcast<JSObject>(proxyVal.getObject(runtime));
  assert(proxy->isProxyObject() && "[[RevocableProxy]] is not a Proxy");
                                      
                                       
  JSProxy::setTargetAndHandler(
      runtime.makeHandle(proxy),
      runtime,
      runtime.makeNullHandle<JSObject>(),
      runtime.makeNullHandle<JSObject>());
                         
  return HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue>
proxyRevocable(void *, Runtime &runtime, NativeArgs args) {
                                                
  CallResult<Handle<JSObject>> proxyRes = proxyCreate(
      runtime,
      args.dyncastArg<JSObject>(0),
      args.dyncastArg<JSObject>(1),
      runtime.makeHandle(vm::JSProxy::create(runtime)));
  if (proxyRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                                                               
                                                                            
  Handle<NativeFunction> revoker = NativeFunction::createWithoutPrototype(
      runtime,
      nullptr,
      proxyRevocationSteps,
      Predefined::getSymbolID(Predefined::emptyString),
      0,
      ProxySlotIndexes::COUNT);
                                            
  auto shv =
      SmallHermesValue::encodeHermesValue(proxyRes->getHermesValue(), runtime);
  setRevocableProxySlot(*revoker, runtime, shv);
                                                      
  Handle<JSObject> result = runtime.makeHandle(JSObject::create(runtime));
                                                       
  auto res1 = JSObject::putNamed_RJS(
      result, runtime, Predefined::getSymbolID(Predefined::proxy), *proxyRes);
  if (res1 == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  assert(*res1 && "Failed to set proxy on Proxy.revocable return");
                                                              
  auto res2 = JSObject::putNamed_RJS(
      result, runtime, Predefined::getSymbolID(Predefined::revoke), revoker);
  if (res2 == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  assert(*res2 && "Failed to set revoke on Proxy.revocable return");
                      
  return result.getHermesValue();
}

Handle<JSObject> createProxyConstructor(Runtime &runtime) {
  Handle<NativeConstructor> cons = defineSystemConstructor<JSProxy>(
      runtime,
      Predefined::getSymbolID(Predefined::Proxy),
      proxyConstructor,
      runtime.makeNullHandle<JSObject>(),
      2,
      CellKind::JSProxyKind);

  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::revocable),
      nullptr,
      proxyRevocable,
      2);

  return cons;
}

}                
}                    

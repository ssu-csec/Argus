/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_JSLIB_JSLIBINTERNAL_H
#define HERMES_VM_JSLIB_JSLIBINTERNAL_H

#include "hermes/Support/ScopeChain.h"
#include "hermes/VM/Callable.h"
#include "hermes/VM/JSDate.h"
#include "hermes/VM/JSError.h"
#include "hermes/VM/JSMapImpl.h"
#include "hermes/VM/JSNativeFunctions.h"
#include "hermes/VM/JSProxy.h"
#include "hermes/VM/JSRegExp.h"
#include "hermes/VM/JSWeakRef.h"

namespace hermes {
namespace vm {

                                                                              
                                                                            
                                                                             
                                                   
                                                                              
                       
                                                                             
                                 
                                                                   
                     
   
                                                                             
                                                                              
                                                                              
                                  
                                                                   
                                                     
                                                                    
                          
                                             
Handle<NativeConstructor> defineSystemConstructor(
    Runtime &runtime,
    SymbolID name,
    NativeFunctionPtr nativeFunctionPtr,
    Handle<JSObject> prototypeObjectHandle,
    Handle<JSObject> constructorProtoObjectHandle,
    unsigned paramCount,
    NativeConstructor::CreatorFunction *creator,
    CellKind targetKind);

Handle<NativeConstructor> defineSystemConstructor(
    Runtime &runtime,
    SymbolID name,
    NativeFunctionPtr nativeFunctionPtr,
    Handle<JSObject> prototypeObjectHandle,
    unsigned paramCount,
    NativeConstructor::CreatorFunction *creator,
    CellKind targetKind);

template <class NativeClass>
Handle<NativeConstructor> defineSystemConstructor(
    Runtime &runtime,
    SymbolID name,
    NativeFunctionPtr nativeFunctionPtr,
    Handle<JSObject> prototypeObjectHandle,
    unsigned paramCount,
    CellKind targetKind) {
  return defineSystemConstructor(
      runtime,
      name,
      nativeFunctionPtr,
      prototypeObjectHandle,
      paramCount,
      NativeConstructor::creatorFunction<NativeClass>,
      targetKind);
}

                                          
                                                                        
                                                                             
                     
                                                                 
                                                                        
                                                              
                                                              
                                                                         
                                                              
                                                              
                                   
CallResult<HermesValue> defineMethod(
    Runtime &runtime,
    Handle<JSObject> objectHandle,
    SymbolID propertyName,
    SymbolID methodName,
    void *context,
    NativeFunctionPtr nativeFunctionPtr,
    unsigned paramCount,
    DefinePropertyFlags dpf);

                                          
                                                                        
                                                                             
                     
                                                                 
                                                                
                                                              
                                                                         
                                                              
                                                              
                                   
inline CallResult<HermesValue> defineMethod(
    Runtime &runtime,
    Handle<JSObject> objectHandle,
    SymbolID name,
    void *context,
    NativeFunctionPtr nativeFunctionPtr,
    unsigned paramCount,
    DefinePropertyFlags dpf) {
  return defineMethod(
      runtime,
      objectHandle,
      name,
      name,
      context,
      nativeFunctionPtr,
      paramCount,
      dpf);
}

                                          
                                                                 
                                       
                                                              
                                                                         
                                                              
void defineMethod(
    Runtime &runtime,
    Handle<JSObject> objectHandle,
    SymbolID name,
    void *context,
    NativeFunctionPtr nativeFunctionPtr,
    unsigned paramCount);

                                             
                                                                   
                                                                              
                                               
                                                               
                                                                  
                                                                  
void defineAccessor(
    Runtime &runtime,
    Handle<JSObject> objectHandle,
    SymbolID propertyName,
    SymbolID methodName,
    void *context,
    NativeFunctionPtr getterFunc,
    NativeFunctionPtr setterFunc,
    bool enumerable,
    bool configurable);

                                             
                                                                   
                                         
                                                               
                                                                  
                                                                  
inline void defineAccessor(
    Runtime &runtime,
    Handle<JSObject> objectHandle,
    SymbolID name,
    void *context,
    NativeFunctionPtr getterFunc,
    NativeFunctionPtr setterFunc,
    bool enumerable,
    bool configurable) {
  defineAccessor(
      runtime,
      objectHandle,
      name,
      name,
      context,
      getterFunc,
      setterFunc,
      enumerable,
      configurable);
}

                                            
                                                               
                                                                   
                                         
                                                  
void defineProperty(
    Runtime &runtime,
    Handle<JSObject> objectHandle,
    SymbolID name,
    Handle<> value);

                                            
                                                                   
                                         
                                                  
                                                              
void defineProperty(
    Runtime &runtime,
    Handle<JSObject> objectHandle,
    SymbolID name,
    Handle<> value,
    DefinePropertyFlags dpf);

                                                                         
                                                                    
                                      
ExecutionStatus iteratorCloseAndRethrow(
    Runtime &runtime,
    Handle<JSObject> iterator);

                                                                             
                                   
                                          
Handle<JSObject> createObjectConstructor(Runtime &runtime);

                                       
CallResult<HermesValue> directObjectPrototypeToString(
    Runtime &runtime,
    Handle<> arg);

                                                                      
                                                                               
#define ALL_ERROR_TYPE(name) \
  Handle<JSObject> create##name##Constructor(Runtime &runtime);
#include "hermes/FrontEndDefs/NativeErrorTypes.def"

                                             
void populateCallSitePrototype(Runtime &runtime);

                                                                             
                                   
                                          
Handle<JSObject> createStringConstructor(Runtime &runtime);

                                                                             
                                   
                                          
Handle<JSObject> createBigIntConstructor(Runtime &runtime);

                                                                               
                                       
                                            
Handle<JSObject> createFunctionConstructor(Runtime &runtime);

                                                                             
                                   
                                          
Handle<JSObject> createNumberConstructor(Runtime &runtime);

                                                                              
                                     
                                           
Handle<JSObject> createBooleanConstructor(Runtime &runtime);

                                                                           
                               
                                        
Handle<JSObject> createDateConstructor(Runtime &runtime);

                                                                      
                            
Handle<JSObject> createMathObject(Runtime &runtime);

                                                                               
                                         
Handle<JSObject> createProxyConstructor(Runtime &runtime);

                       
class JSLibFlags;

                                                                           
                                  
Handle<JSObject> createHermesInternalObject(
    Runtime &runtime,
    const JSLibFlags &jsLibFlags);

#ifdef HERMES_ENABLE_DEBUGGER

                                                                             
                                  
Handle<JSObject> createDebuggerInternalObject(Runtime &runtime);

#endif                          

                                                                      
                            
Handle<JSObject> createJSONObject(Runtime &runtime);

                                                                         
                            
Handle<JSObject> createReflectObject(Runtime &runtime);

                                                                             
                                   
                                          
Handle<JSObject> createRegExpConstructor(Runtime &runtime);

                                                             
                                                                    
CallResult<Handle<JSRegExp>>
regExpCreate(Runtime &runtime, Handle<> P, Handle<> F);

                    
                             
CallResult<HermesValue>
regExpExec(Runtime &runtime, Handle<JSObject> R, Handle<StringPrimitive> S);

                                                               
                                                           
                                                                             
CallResult<Handle<JSArray>> directRegExpExec(
    Handle<JSRegExp> regexp,
    Runtime &runtime,
    Handle<StringPrimitive> S);

                     
                             
                                                                          
                                      
CallResult<HermesValue> getSubstitution(
    Runtime &runtime,
    Handle<StringPrimitive> matched,
    Handle<StringPrimitive> str,
    uint32_t position,
    Handle<ArrayStorageSmall> captures,
    Handle<JSObject> namedCaptures,
    Handle<StringPrimitive> replacement);

                                                                             
                                         
CallResult<HermesValue> splitInternal(
    Runtime &runtime,
    Handle<> string,
    Handle<> limit,
    Handle<> separator);

                                                      
inline ExecutionStatus
setLastIndex(Handle<JSObject> regexp, Runtime &runtime, SmallHermesValue shv) {
  return runtime.putNamedThrowOnError(
      regexp, PropCacheID::RegExpLastIndex, shv);
}

                                                        
inline ExecutionStatus
setLastIndex(Handle<JSObject> regexp, Runtime &runtime, double value) {
  auto shv = SmallHermesValue::encodeNumberValue(value, runtime);
  return setLastIndex(regexp, runtime, shv);
}

                    
                                                                              
                                                                   
                                              
uint64_t
advanceStringIndex(const StringPrimitive *S, uint64_t index, bool unicode);

                                                                            
                                 
                                         
Handle<JSObject> createArrayConstructor(Runtime &runtime);

Handle<JSObject> createArrayBufferConstructor(Runtime &runtime);

Handle<JSObject> createDataViewConstructor(Runtime &runtime);

Handle<JSObject> createTypedArrayBaseConstructor(Runtime &runtime);

#define TYPED_ARRAY(name, type) \
  Handle<JSObject> create##name##ArrayConstructor(Runtime &runtime);
#include "hermes/VM/TypedArrays.def"
#undef TYPED_ARRAY

                                                                          
                     
Handle<JSObject> createSetConstructor(Runtime &runtime);

                                                      
Handle<JSObject> createSetIteratorPrototype(Runtime &runtime);

                                                                          
                     
Handle<JSObject> createMapConstructor(Runtime &runtime);

                                                      
Handle<JSObject> createMapIteratorPrototype(Runtime &runtime);

                                                        
Handle<JSObject> createWeakMapConstructor(Runtime &runtime);

                                                        
Handle<JSObject> createWeakSetConstructor(Runtime &runtime);

                                                        
Handle<JSObject> createWeakRefConstructor(Runtime &runtime);

                                                       
Handle<JSObject> createSymbolConstructor(Runtime &runtime);

                                                                  
Handle<JSObject> createGeneratorFunctionConstructor(Runtime &runtime);
Handle<JSObject> createAsyncGeneratorFunctionConstructor(Runtime &runtime);

                                                              
Handle<JSObject> createAsyncFunctionConstructor(Runtime &runtime);

                                                            
Handle<JSObject> createTextEncoderConstructor(Runtime &runtime);

                                 
void populateIteratorPrototype(Runtime &runtime);

                                       
void populateArrayIteratorPrototype(Runtime &runtime);

                                        
void populateStringIteratorPrototype(Runtime &runtime);

                                              
void populateRegExpStringIteratorPrototype(Runtime &runtime);

                                    
void populateGeneratorPrototype(Runtime &runtime);

                                                                              
enum class DynamicFunctionKind { Normal, Generator, Async, AsyncGenerator };

                                                     
                                                                            
CallResult<HermesValue> createDynamicFunction(
    Runtime &runtime,
    NativeArgs args,
    DynamicFunctionKind kind);

                                                  
CallResult<HermesValue> directEval(
    Runtime &runtime,
    Handle<StringPrimitive> str,
    const ScopeChain &scopeChain,
    bool isStrict,
    bool singleFunction);

                                        
                                                                     
                                                        
                                                                  
                                      
                                                                             
                                                                              
template <typename AdderCB>
CallResult<HermesValue> addEntriesFromIterable(
    Runtime &runtime,
    Handle<JSObject> target,
    Handle<> iterable,
    AdderCB adder) {
  GCScope gcScope{runtime};
                                                                       
  assert(
      !iterable->isUndefined() && !iterable->isNull() &&
      "iterable cannot be undefined or null");
                                                      
  CallResult<IteratorRecord> iterRes = getIterator(runtime, iterable);
  if (LLVM_UNLIKELY(iterRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto iteratorRecord = *iterRes;

  MutableHandle<JSObject> nextItem{runtime};
  MutableHandle<> key{runtime};
  MutableHandle<> value{runtime};
  Handle<> zero = HandleRootOwner::getZeroValue();
  Handle<> one = HandleRootOwner::getOneValue();
  auto marker = gcScope.createMarker();

               
  for (;; gcScope.flushToMarker(marker)) {
                                                     
    auto nextRes = iteratorStep(runtime, iteratorRecord);
    if (LLVM_UNLIKELY(nextRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (!*nextRes) {
                                            
      return target.getHermesValue();
    }
                                                
    nextItem = vmcast<JSObject>(nextRes->getHermesValue());
    auto nextItemRes = JSObject::getNamed_RJS(
        nextItem, runtime, Predefined::getSymbolID(Predefined::value));
    if (LLVM_UNLIKELY(nextItemRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (!vmisa<JSObject>(nextItemRes->get())) {
                                                 
                                                                               
                                                               
      (void)runtime.raiseTypeError("Iterator value must be an object");
      return iteratorCloseAndRethrow(runtime, iteratorRecord.iterator);
    }
    nextItem = PseudoHandle<JSObject>::vmcast(std::move(*nextItemRes));

                                      
    auto keyRes = JSObject::getComputed_RJS(nextItem, runtime, zero);
    if (LLVM_UNLIKELY(keyRes == ExecutionStatus::EXCEPTION)) {
                                         
                                                      
      return iteratorCloseAndRethrow(runtime, iteratorRecord.iterator);
    }
    key = std::move(*keyRes);

                                      
    auto valueRes = JSObject::getComputed_RJS(nextItem, runtime, one);
    if (LLVM_UNLIKELY(valueRes == ExecutionStatus::EXCEPTION)) {
                                         
                                                      
      return iteratorCloseAndRethrow(runtime, iteratorRecord.iterator);
    }
    value = std::move(*valueRes);

                                                                          
    if (LLVM_UNLIKELY(
            adder(runtime, key, value) == ExecutionStatus::EXCEPTION)) {
                                              
                                                           
      return iteratorCloseAndRethrow(runtime, iteratorRecord.iterator);
    }
  }

  llvm_unreachable(
      "loop must terminate with 'return' when iteration is complete");
}

#ifdef HERMES_ENABLE_IR_INSTRUMENTATION
                                                          
Handle<JSObject> createInstrumentObject(Runtime &runtime);
#endif

}                

#ifdef HERMES_ENABLE_INTL
namespace intl {

                                                                        
vm::Handle<vm::JSObject> createIntlObject(vm::Runtime &runtime);

}                  
#endif

}                    

#endif                                   

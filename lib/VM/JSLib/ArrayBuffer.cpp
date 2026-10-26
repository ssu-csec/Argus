/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                        
                                                                                

#include "JSLibInternal.h"

#include "hermes/VM/JSArrayBuffer.h"
#include "hermes/VM/JSDataView.h"
#include "hermes/VM/JSTypedArray.h"
#include "hermes/VM/Operations.h"
#include "hermes/VM/StringPrimitive.h"
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

using std::max;
using std::min;

                        
      

Handle<JSObject> createArrayBufferConstructor(Runtime &runtime) {
  auto arrayBufferPrototype =
      Handle<JSObject>::vmcast(&runtime.arrayBufferPrototype);
  auto cons = defineSystemConstructor<JSArrayBuffer>(
      runtime,
      Predefined::getSymbolID(Predefined::ArrayBuffer),
      arrayBufferConstructor,
      arrayBufferPrototype,
      1,
      CellKind::JSArrayBufferKind);

                                         
  defineAccessor(
      runtime,
      arrayBufferPrototype,
      Predefined::getSymbolID(Predefined::byteLength),
      nullptr,
      arrayBufferPrototypeByteLength,
      nullptr,
      false,
      true);
  defineMethod(
      runtime,
      arrayBufferPrototype,
      Predefined::getSymbolID(Predefined::slice),
      nullptr,
      arrayBufferPrototypeSlice,
      2);

  auto dpf = DefinePropertyFlags::getDefaultNewPropertyFlags();
  dpf.writable = 0;
  dpf.enumerable = 0;
  defineProperty(
      runtime,
      arrayBufferPrototype,
      Predefined::getSymbolID(Predefined::SymbolToStringTag),
      runtime.getPredefinedStringHandle(Predefined::ArrayBuffer),
      dpf);

                               
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::isView),
      nullptr,
      arrayBufferIsView,
      1);

  return cons;
}

CallResult<HermesValue>
arrayBufferConstructor(void *, Runtime &runtime, NativeArgs args) {
                                                               
  if (!args.isConstructorCall()) {
    return runtime.raiseTypeError(
        "ArrayBuffer() called in function context instead of constructor");
  }
  auto self = args.vmcastThis<JSArrayBuffer>();
  auto length = args.getArgHandle(0);

                                          
  auto res = toIndex(runtime, length);
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  uint64_t byteLength = res->getNumberAs<uint64_t>();

                                                          
                                                                          
  assert(
      !self->attached() &&
      "A new array buffer should not have an existing buffer");
  if (byteLength > std::numeric_limits<JSArrayBuffer::size_type>::max()) {
                                                                        
                                         
    return runtime.raiseRangeError("Too large of a byteLength requested");
  }
  if (JSArrayBuffer::createDataBlock(runtime, self, byteLength) ==
      ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  return self.getHermesValue();
}

CallResult<HermesValue>
arrayBufferIsView(void *, Runtime &runtime, NativeArgs args) {
                                                 
                                                                      
                     
  return HermesValue::encodeBoolValue(
      vmisa<JSTypedArrayBase>(args.getArg(0)) ||
      vmisa<JSDataView>(args.getArg(0)));
}

CallResult<HermesValue>
arrayBufferPrototypeByteLength(void *, Runtime &runtime, NativeArgs args) {
  auto self = args.dyncastThis<JSArrayBuffer>();
  if (!self) {
    return runtime.raiseTypeError(
        "byteLength called on a non ArrayBuffer object");
  }
  return HermesValue::encodeUntrustedNumberValue(self->size());
}

CallResult<HermesValue>
arrayBufferPrototypeSlice(void *, Runtime &runtime, NativeArgs args) {
  auto start = args.getArgHandle(0);
  auto end = args.getArgHandle(1);
                                
  auto self = args.dyncastThis<JSArrayBuffer>();
                                                              
                                                                        
                                                                              
               
  if (!self) {
    return runtime.raiseTypeError(
        "Called ArrayBuffer.prototype.slice on a non-ArrayBuffer");
  }

                                                                            
  double len = self->size();
                                                        
  auto intRes = toIntegerOrInfinity(runtime, start);
  if (intRes == ExecutionStatus::EXCEPTION) {
                                        
    return ExecutionStatus::EXCEPTION;
  }
  double relativeStart = intRes->getNumber();
                                                                             
                                          
  double first = relativeStart < 0 ? max(len + relativeStart, 0.0)
                                   : min(relativeStart, len);
                                                                            
                              
  double relativeEnd;
  if (end->isUndefined()) {
    relativeEnd = len;
  } else {
    intRes = toIntegerOrInfinity(runtime, end);
    if (intRes == ExecutionStatus::EXCEPTION) {
                                         
      return ExecutionStatus::EXCEPTION;
    }
    relativeEnd = intRes->getNumber();
  }
                                                                              
                                    
                             
  double finale =
      relativeEnd < 0 ? max(len + relativeEnd, 0.0) : min(relativeEnd, len);
                                          
  double newLen = max(finale - first, 0.0);
                                                             
  JSArrayBuffer::size_type first_int = first;
  JSArrayBuffer::size_type newLen_int = newLen;
                                                          
                              
                                              
                             

  auto newBuf = runtime.makeHandle(
      JSArrayBuffer::create(
          runtime, Handle<JSObject>::vmcast(&runtime.arrayBufferPrototype)));

  if (JSArrayBuffer::createDataBlock(runtime, newBuf, newLen_int) ==
      ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                                                           
                         
                                                                       
                                                                   
                                                                 
                                                
                                                                   
                                                                     
  if (!self->attached() || !newBuf->attached()) {
    return runtime.raiseTypeError("Cannot split with detached ArrayBuffers");
  }

                                                                           
                                                                           
                                                                      
  JSArrayBuffer::copyDataBlockBytes(
      runtime, *newBuf, 0, *self, first_int, newLen_int);
                    
  return newBuf.getHermesValue();
}
      
}                
}                    

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "JSLibInternal.h"

#include "hermes/VM/BigIntPrimitive.h"
#include "hermes/VM/JSDataView.h"
#include "hermes/VM/JSTypedArray.h"
#include "hermes/VM/StringPrimitive.h"
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

                            
      

               
CallResult<HermesValue>
dataViewPrototypeBuffer(void *, Runtime &runtime, NativeArgs args) {
  auto self = args.dyncastThis<JSDataView>();
  if (!self) {
    return runtime.raiseTypeError(
        "DataView.prototype.buffer called on a non DataView object");
  }
  return self->getBuffer(runtime).getHermesValue();
}

               
CallResult<HermesValue>
dataViewPrototypeByteLength(void *, Runtime &runtime, NativeArgs args) {
  auto self = args.dyncastThis<JSDataView>();
  if (!self) {
    return runtime.raiseTypeError(
        "DataView.prototype.byteLength called on a non DataView object");
  }
  return HermesValue::encodeUntrustedNumberValue(self->byteLength());
}

               
CallResult<HermesValue>
dataViewPrototypeByteOffset(void *, Runtime &runtime, NativeArgs args) {
  auto self = args.dyncastThis<JSDataView>();
  if (!self) {
    return runtime.raiseTypeError(
        "DataView.prototype.byteOffset called on a non DataView object");
  }
  return HermesValue::encodeUntrustedNumberValue(self->byteOffset());
}

                                               
namespace {
template <typename T>
CallResult<HermesValue> dataViewPrototypeGetEncoder(Runtime &, T value) {
  return HermesValue::encodeUntrustedNumberValue(value);
}

CallResult<HermesValue> dataViewPrototypeGetEncoder(
    Runtime &runtime,
    int64_t value) {
  return BigIntPrimitive::fromSigned(runtime, value);
}

CallResult<HermesValue> dataViewPrototypeGetEncoder(
    Runtime &runtime,
    uint64_t value) {
  return BigIntPrimitive::fromUnsigned(runtime, value);
}

template <typename T>
CallResult<HermesValue>
dataViewPrototypeGet(void *, Runtime &runtime, NativeArgs args) {
  auto self = args.dyncastThis<JSDataView>();
  if (!self) {
    return runtime.raiseTypeError(
        "DataView.prototype.get<Type>() called on a non DataView object");
  }
  auto res = toIndex(runtime, args.getArgHandle(0));
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto byteOffset = res->getNumberAs<uint64_t>();
  auto littleEndian = toBoolean(args.getArg(1));
  if (!self->attached(runtime)) {
    return runtime.raiseTypeError(
        "DataView.prototype.get<Type>() called on a detached ArrayBuffer");
  }
  if (byteOffset + sizeof(T) > self->byteLength()) {
    return runtime.raiseRangeError(
        "DataView.prototype.get<Type>(): Cannot "
        "read that many bytes");
  }
  return dataViewPrototypeGetEncoder(
      runtime, self->get<T>(runtime, byteOffset, littleEndian));
}

template <CellKind C>
constexpr bool isBigIntCellKind() {
  return C == CellKind::BigInt64ArrayKind || C == CellKind::BigUint64ArrayKind;
}

template <typename T, CellKind C>
CallResult<HermesValue>
dataViewPrototypeSet(void *, Runtime &runtime, NativeArgs args) {
  auto self = args.dyncastThis<JSDataView>();
  if (!self) {
    return runtime.raiseTypeError(
        "DataView.prototype.set<Type>() called on a non DataView object");
  }
  auto res = toIndex(runtime, args.getArgHandle(0));
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto byteOffset = res->getNumberAs<uint64_t>();
  auto littleEndian = toBoolean(args.getArg(2));
  if constexpr (isBigIntCellKind<C>()) {
    res = toBigInt_RJS(runtime, args.getArgHandle(1));
  } else {
    res = toNumber_RJS(runtime, args.getArgHandle(1));
  }
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  if (!self->attached(runtime)) {
    return runtime.raiseTypeError(
        "DataView.prototype.set<Type> called on a detached ArrayBuffer");
  }
  T value = JSTypedArray<T, C>::toDestType(*res);
  if (byteOffset + sizeof(T) > self->byteLength()) {
    return runtime.raiseRangeError(
        "DataView.prototype.set<Type>(): Cannot "
        "write that many bytes");
  }
  self->set<T>(runtime, byteOffset, value, littleEndian);
  return HermesValue::encodeUndefinedValue();
}
}             

#define TYPED_ARRAY(name, type)                                   \
  CallResult<HermesValue> dataViewPrototypeGet##name(             \
      void *ctx, Runtime &rt, NativeArgs args) {                  \
    return dataViewPrototypeGet<type>(ctx, rt, args);             \
  }                                                               \
  CallResult<HermesValue> dataViewPrototypeSet##name(             \
      void *ctx, Runtime &rt, NativeArgs args) {                  \
    return dataViewPrototypeSet<type, CellKind::name##ArrayKind>( \
        ctx, rt, args);                                           \
  }
#define TYPED_ARRAY_NO_CLAMP
#include "hermes/VM/TypedArrays.def"
#undef TYPED_ARRAY_NO_CLAMP
#undef TYPED_ARRAY

      

                   
CallResult<HermesValue>
dataViewConstructor(void *, Runtime &runtime, NativeArgs args) {
                                                               
  if (!args.isConstructorCall()) {
    return runtime.raiseTypeError(
        "DataView() called in function context instead of constructor");
  }
  auto self = args.vmcastThis<JSDataView>();
  auto buffer = args.dyncastArg<JSArrayBuffer>(0);
  auto byteLength = args.getArgHandle(2);
                                                                  
                                                                             
                         
  if (!buffer) {
    return runtime.raiseTypeError(
        "new DataView(buffer, [byteOffset], [byteLength]): "
        "buffer must be an ArrayBuffer");
  }

                                          
  auto res = toIndex(runtime, args.getArgHandle(1));
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto offset = res->getNumberAs<uint64_t>();
                                                                 
  auto bufferByteLength = buffer->size();
                                                                   
  if (offset > bufferByteLength) {
    return runtime.raiseRangeError(
        "new DataView(buffer, [byteOffset], "
        "[byteLength]): byteOffset must be <= the "
        "buffer's byte length");
  }
  double viewByteLength = 0;
                                                              
  if (byteLength->isUndefined()) {
                                                           
    viewByteLength = bufferByteLength - offset;
  } else {
                                                       
    auto res2 = toIndex(runtime, byteLength);
    if (res2 == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    viewByteLength = res2->getNumber();
                                                                          
                 
    if (offset + viewByteLength > bufferByteLength) {
      return runtime.raiseRangeError(
          "new DataView(buffer, [byteOffset], "
          "[byteLength]): byteOffset + byteLength must be "
          "<= the length of the buffer");
    }
  }
  self->setBuffer(runtime, *buffer, offset, viewByteLength);
  return self.getHermesValue();
}

Handle<JSObject> createDataViewConstructor(Runtime &runtime) {
  auto proto = Handle<JSObject>::vmcast(&runtime.dataViewPrototype);
  auto cons = defineSystemConstructor<JSDataView>(
      runtime,
      Predefined::getSymbolID(Predefined::DataView),
      dataViewConstructor,
      proto,
      1,
      CellKind::JSDataViewKind);

                                      
  defineAccessor(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::buffer),
      nullptr,
      dataViewPrototypeBuffer,
      nullptr,
      false,
      true);
  defineAccessor(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::byteLength),
      nullptr,
      dataViewPrototypeByteLength,
      nullptr,
      false,
      true);
  defineAccessor(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::byteOffset),
      nullptr,
      dataViewPrototypeByteOffset,
      nullptr,
      false,
      true);

#define TYPED_ARRAY(name, type)                       \
  defineMethod(                                       \
      runtime,                                        \
      proto,                                          \
      Predefined::getSymbolID(Predefined::get##name), \
      nullptr,                                        \
      dataViewPrototypeGet##name,                     \
      1);                                             \
  defineMethod(                                       \
      runtime,                                        \
      proto,                                          \
      Predefined::getSymbolID(Predefined::set##name), \
      nullptr,                                        \
      dataViewPrototypeSet##name,                     \
      2);
#define TYPED_ARRAY_NO_CLAMP
#include "hermes/VM/TypedArrays.def"

  auto dpf = DefinePropertyFlags::getDefaultNewPropertyFlags();
  dpf.writable = 0;
  dpf.enumerable = 0;
  defineProperty(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::SymbolToStringTag),
      runtime.getPredefinedStringHandle(Predefined::DataView),
      dpf);

                            

  return cons;
}

}                
}                    

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                                                                             
                                                                                
#include "JSLibInternal.h"

#include "hermes/VM/BigIntPrimitive.h"
#include "hermes/VM/Operations.h"
#include "hermes/VM/PrimitiveBox.h"

namespace hermes {
namespace vm {

Handle<JSObject> createBigIntConstructor(Runtime &runtime) {
  auto bigintPrototype = Handle<JSObject>::vmcast(&runtime.bigintPrototype);

  auto cons = defineSystemConstructor<JSBigInt>(
      runtime,
      Predefined::getSymbolID(Predefined::BigInt),
      bigintConstructor,
      bigintPrototype,
      1,
      CellKind::JSBigIntKind);

                                  
                                                                           
  void *ctx = nullptr;
  defineMethod(
      runtime,
      bigintPrototype,
      Predefined::getSymbolID(Predefined::toString),
      ctx,
      bigintPrototypeToString,
      0);
  defineMethod(
      runtime,
      bigintPrototype,
      Predefined::getSymbolID(Predefined::valueOf),
      ctx,
      bigintPrototypeValueOf,
      0);
  defineMethod(
      runtime,
      bigintPrototype,
      Predefined::getSymbolID(Predefined::toLocaleString),
      ctx,
      bigintPrototypeToLocaleString,
      1);

                          
                                                                      
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::asIntN),
      reinterpret_cast<void *>(&BigIntPrimitive::asIntN),
      bigintTruncate,
      2);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::asUintN),
      reinterpret_cast<void *>(&BigIntPrimitive::asUintN),
      bigintTruncate,
      2);

                          
  auto dpf = DefinePropertyFlags::getDefaultNewPropertyFlags();
  dpf.writable = 0;
  dpf.enumerable = 0;
  defineProperty(
      runtime,
      bigintPrototype,
      Predefined::getSymbolID(Predefined::SymbolToStringTag),
      runtime.getPredefinedStringHandle(Predefined::BigInt),
      dpf);

  return cons;
}

CallResult<HermesValue>
bigintConstructor(void *, Runtime &runtime, NativeArgs args) {
                                                             
                                                               
  if (args.isConstructorCall()) {
    return runtime.raiseTypeError("BigInt is not a constructor");
  }

  auto hArg0 = runtime.makeHandle(args.getArg(0));
  auto prim = toPrimitive_RJS(runtime, hArg0, PreferredType::NUMBER);
  if (LLVM_UNLIKELY(prim == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  if (prim->isNumber()) {
    return numberToBigInt(runtime, prim->getNumber());
  }

  return toBigInt_RJS(runtime, hArg0);
}

CallResult<HermesValue>
bigintPrototypeToLocaleString(void *ctx, Runtime &runtime, NativeArgs args) {
  auto bigint = thisBigIntValue(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(bigint == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

                                
                                                         
  auto res = toString_RJS(runtime, runtime.makeHandle(*bigint));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  return res->getHermesValue();
}

CallResult<HermesValue>
bigintPrototypeToString(void *, Runtime &runtime, NativeArgs args) {
                                               
  auto x = thisBigIntValue(runtime, args.getThisHandle());

  if (LLVM_UNLIKELY(x == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  Handle<BigIntPrimitive> xHandle = runtime.makeHandle(x->getBigInt());

                                                 
  uint32_t radixMV = 10;

                                                          
  auto radixArg = args.getArgHandle(0);
  if (!radixArg->isUndefined()) {
    auto r = toIntegerOrInfinity(runtime, radixArg);
    if (LLVM_UNLIKELY(r == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    assert(r->isNumber());
                                                                       
    if (r->getNumber() < 2 || r->getNumber() > 36) {
      return runtime.raiseRangeError(
          "radix out-of-range in BigInt.prototype.toString");
    }

    radixMV = r->getNumber();
  }

                                              
                                              
  return BigIntPrimitive::toString(runtime, xHandle, radixMV);
}

CallResult<HermesValue>
bigintPrototypeValueOf(void *, Runtime &runtime, NativeArgs args) {
  return thisBigIntValue(runtime, args.getThisHandle());
}

using TruncateOp =
    CallResult<HermesValue> (*)(Runtime &, uint64_t, Handle<BigIntPrimitive>);

CallResult<HermesValue>
bigintTruncate(void *ctx, Runtime &runtime, NativeArgs args) {
  auto bitsRes = toIndex(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(bitsRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  uint64_t bits = bitsRes->getNumberAs<uint64_t>();

  auto bigint = toBigInt_RJS(runtime, args.getArgHandle(1));
  if (LLVM_UNLIKELY(bigint == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  auto op = reinterpret_cast<TruncateOp>(ctx);
  return (*op)(runtime, bits, runtime.makeHandle(bigint->getBigInt()));
}

}                
}                    

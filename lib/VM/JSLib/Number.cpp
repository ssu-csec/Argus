/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                                                 
                                                                                

#include "JSLibInternal.h"

#include "hermes/VM/Operations.h"
#include "hermes/VM/PrimitiveBox.h"
#include "hermes/VM/SmallXString.h"
#include "hermes/VM/StringPrimitive.h"

#include "dtoa/dtoa.h"

#include "llvh/ADT/SmallString.h"
#include "llvh/Support/Format.h"
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

Handle<JSObject> createNumberConstructor(Runtime &runtime) {
  auto numberPrototype = Handle<JSNumber>::vmcast(&runtime.numberPrototype);

  auto cons = defineSystemConstructor<JSNumber>(
      runtime,
      Predefined::getSymbolID(Predefined::Number),
      numberConstructor,
      numberPrototype,
      1,
      CellKind::JSNumberKind);

  defineMethod(
      runtime,
      numberPrototype,
      Predefined::getSymbolID(Predefined::valueOf),
      nullptr,
      numberPrototypeValueOf,
      0);
  defineMethod(
      runtime,
      numberPrototype,
      Predefined::getSymbolID(Predefined::toString),
      nullptr,
      numberPrototypeToString,
      1);
  defineMethod(
      runtime,
      numberPrototype,
      Predefined::getSymbolID(Predefined::toLocaleString),
      nullptr,
      numberPrototypeToLocaleString,
      0);
  defineMethod(
      runtime,
      numberPrototype,
      Predefined::getSymbolID(Predefined::toFixed),
      nullptr,
      numberPrototypeToFixed,
      1);
  defineMethod(
      runtime,
      numberPrototype,
      Predefined::getSymbolID(Predefined::toExponential),
      nullptr,
      numberPrototypeToExponential,
      1);
  defineMethod(
      runtime,
      numberPrototype,
      Predefined::getSymbolID(Predefined::toPrecision),
      nullptr,
      numberPrototypeToPrecision,
      1);

  DefinePropertyFlags constantDPF =
      DefinePropertyFlags::getDefaultNewPropertyFlags();
  constantDPF.enumerable = 0;
  constantDPF.writable = 0;
  constantDPF.configurable = 0;

  MutableHandle<> numberValueHandle{runtime};
  auto setNumberValueProperty = [&](SymbolID name, double value) {
    numberValueHandle = HermesValue::encodeUntrustedNumberValue(value);
    auto result = JSObject::defineOwnProperty(
        cons, runtime, name, constantDPF, numberValueHandle);
    assert(
        result != ExecutionStatus::EXCEPTION &&
        "defineOwnProperty() failed on a new object");
    (void)result;
  };

  setNumberValueProperty(
      Predefined::getSymbolID(Predefined::MAX_VALUE),
      std::numeric_limits<double>::max());
  setNumberValueProperty(
      Predefined::getSymbolID(Predefined::MIN_VALUE),
      std::numeric_limits<double>::denorm_min());
  setNumberValueProperty(
      Predefined::getSymbolID(Predefined::NaN),
      std::numeric_limits<double>::quiet_NaN());
  setNumberValueProperty(
      Predefined::getSymbolID(Predefined::NEGATIVE_INFINITY),
      -std::numeric_limits<double>::infinity());
  setNumberValueProperty(
      Predefined::getSymbolID(Predefined::POSITIVE_INFINITY),
      std::numeric_limits<double>::infinity());
                   
  setNumberValueProperty(
      Predefined::getSymbolID(Predefined::EPSILON),
      std::numeric_limits<double>::epsilon());
                   
  constexpr double kMaxSafeInteger = 9007199254740991;
  setNumberValueProperty(
      Predefined::getSymbolID(Predefined::MAX_SAFE_INTEGER), kMaxSafeInteger);
                   
  setNumberValueProperty(
      Predefined::getSymbolID(Predefined::MIN_SAFE_INTEGER), -kMaxSafeInteger);

  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::isFinite),
      nullptr,
      numberIsFinite,
      1);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::isInteger),
      nullptr,
      numberIsInteger,
      1);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::isNaN),
      nullptr,
      numberIsNaN,
      1);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::isSafeInteger),
      nullptr,
      numberIsSafeInteger,
      1);
  defineProperty(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::parseInt),
      Handle<>(&runtime.parseIntFunction));
  defineProperty(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::parseFloat),
      Handle<>(&runtime.parseFloatFunction));
  return cons;
}

CallResult<HermesValue>
numberConstructor(void *, Runtime &runtime, NativeArgs args) {
  double value = +0.0;

  if (args.getArgCount() > 0) {
    CallResult<HermesValue> res = toNumeric_RJS(runtime, args.getArgHandle(0));
    if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (!res->isBigInt()) {
      value = res->getNumber();
    } else {
      CallResult<double> val = res->getBigInt()->toDouble(runtime);
      if (LLVM_UNLIKELY(val == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      value = *val;
    }
  }

  if (args.isConstructorCall()) {
    auto *self = vmcast<JSNumber>(args.getThisArg());
    self->setPrimitiveNumber(value);
    return args.getThisArg();
  }

  return HermesValue::encodeUntrustedNumberValue(value);
}

CallResult<HermesValue>
numberIsFinite(void *, Runtime &runtime, NativeArgs args) {
  if (!args.getArg(0).isNumber()) {
                                                   
    return HermesValue::encodeBoolValue(false);
  }
  double number = args.getArg(0).getNumber();
                                               
                            
  return HermesValue::encodeBoolValue(std::isfinite(number));
}

CallResult<HermesValue>
numberIsInteger(void *, Runtime &runtime, NativeArgs args) {
  if (!args.getArg(0).isNumber()) {
                                                   
    return HermesValue::encodeBoolValue(false);
  }
  double number = args.getArg(0).getNumber();

  if (!std::isfinite(number)) {
                                                 
    return HermesValue::encodeBoolValue(false);
  }
                                                
  assert(!std::isnan(number) && "number must not be NaN after the check");
                                                                    
  double integer = std::trunc(number);

                                                     
                            
  return HermesValue::encodeBoolValue(integer == number);
}

CallResult<HermesValue> numberIsNaN(void *, Runtime &runtime, NativeArgs args) {
  if (!args.getArg(0).isNumber()) {
                                                   
    return HermesValue::encodeBoolValue(false);
  }
  double number = args.getArg(0).getNumber();
                                   
                             
  return HermesValue::encodeBoolValue(std::isnan(number));
}

CallResult<HermesValue>
numberIsSafeInteger(void *, Runtime &runtime, NativeArgs args) {
  if (!args.getArg(0).isNumber()) {
                                                   
    return HermesValue::encodeBoolValue(false);
  }
  double number = args.getArg(0).getNumber();

  if (!std::isfinite(number)) {
                                                 
    return HermesValue::encodeBoolValue(false);
  }

                                                
  assert(!std::isnan(number) && "number must not be NaN after the check");
                                                                    
  double integer = std::trunc(number);

  if (integer != number) {
                                                       
    return HermesValue::encodeBoolValue(false);
  }

                                           
                             
  return HermesValue::encodeBoolValue(
      std::abs(integer) <= ((double)((uint64_t)1 << 53)) - 1);
}

CallResult<HermesValue>
numberPrototypeValueOf(void *, Runtime &runtime, NativeArgs args) {
  if (args.getThisArg().isNumber()) {
    return args.getThisArg();
  }
  auto *numPtr = dyn_vmcast<JSNumber>(args.getThisArg());
  if (!numPtr) {
    return runtime.raiseTypeError(
        "Number.prototype.valueOf() can only be used on Number");
  }
  return HermesValue::encodeUntrustedNumberValue(numPtr->getPrimitiveNumber());
}

CallResult<HermesValue>
numberPrototypeToString(void *, Runtime &runtime, NativeArgs args) {
  const size_t MIN_RADIX = 2;
  const size_t MAX_RADIX = 36;

  unsigned radix;
  double number;

                                  
  if (args.getThisArg().isNumber()) {
    number = args.getThisArg().getNumber();
  } else {
    auto *numPtr = dyn_vmcast<JSNumber>(args.getThisArg());
    if (!numPtr) {
      return runtime.raiseTypeError(
          "Number.prototype.toString() can only be used on Number");
    }
    number = numPtr->getPrimitiveNumber();
  }

  if (args.getArg(0).isUndefined())
    radix = 10;
  else {
                                 
    auto intRes = toIntegerOrInfinity(runtime, args.getArgHandle(0));
    if (intRes == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    auto d = intRes->getNumber();
    if (d < MIN_RADIX || d > MAX_RADIX) {
      return runtime.raiseRangeError("Invalid radix value");
    }
    radix = (unsigned)d;
  }

                                                          
                                                                           
                                                                                
                                         
  if (radix != 10 && std::isfinite(number)) {
    return numberToStringWithRadix(runtime, number, radix).getHermesValue();
  }

                                                         
  auto resultRes = toString_RJS(
      runtime,
      runtime.makeHandle(HermesValue::encodeUntrustedNumberValue(number)));
  if (LLVM_UNLIKELY(resultRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return resultRes->getHermesValue();
}

CallResult<HermesValue>
numberPrototypeToLocaleString(void *ctx, Runtime &runtime, NativeArgs args) {
#ifdef HERMES_ENABLE_INTL
  return intlNumberPrototypeToLocaleString(             ctx, runtime, args);
#else

  double number;

                                  
  if (args.getThisArg().isNumber()) {
    number = args.getThisArg().getNumber();
  } else {
    auto *numPtr = dyn_vmcast<JSNumber>(args.getThisArg());
    if (!numPtr) {
      return runtime.raiseTypeError(
          "Number.prototype.toLocaleString() can only be used on Number");
    }
    number = numPtr->getPrimitiveNumber();
  }

                                
                                             
  auto res = toString_RJS(
      runtime,
      runtime.makeHandle(HermesValue::encodeUntrustedNumberValue(number)));
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }

  return res->getHermesValue();
#endif
}

CallResult<HermesValue>
numberPrototypeToFixed(void *, Runtime &runtime, NativeArgs args) {
  auto intRes = toIntegerOrInfinity(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double fDouble = intRes->getNumber();

                                                          
  if (LLVM_UNLIKELY(fDouble < 0 || fDouble > 100)) {
    return runtime.raiseRangeError(
        "toFixed argument must be between 0 and 100");
  }
                                               
                                       
                                                    
  int32_t f = static_cast<int32_t>(fDouble);

                                         
  double x;
  if (args.getThisArg().isNumber()) {
    x = args.getThisArg().getNumber();
  } else {
    auto numPtr = Handle<JSNumber>::dyn_vmcast(args.getThisHandle());
    if (LLVM_UNLIKELY(!numPtr)) {
      return runtime.raiseTypeError(
          "Number.prototype.toFixed() can only be used on Number");
    }
    x = numPtr->getPrimitiveNumber();
  }

  if (std::isnan(x)) {
    return HermesValue::encodeStringValue(
        runtime.getPredefinedString(Predefined::NaN));
  }

                                    
  if (std::abs(x) >= 1e21) {
                                      
    auto resultRes = toString_RJS(
        runtime,
        runtime.makeHandle(HermesValue::encodeUntrustedNumberValue(x)));
    if (LLVM_UNLIKELY(resultRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    return resultRes->getHermesValue();
  }

                                                                          
  bool negative = false;
  if (x < 0) {
    negative = true;
    x = -x;
  }

                         
  int decPt;

                           
  int sign;

                                                            
  char *sEnd;

                        
                                                              
                                                               
                                                                         
  llvh::SmallString<32> n;
  {
    DtoaAllocator<> dalloc{};
    char *s = ::dtoa_fixedpoint(dalloc, x, 3, f, &decPt, &sign, &sEnd);
    n.append(s, sEnd);
    ::g_freedtoa(dalloc, s);
  }

                                                                           
  size_t minNLen = decPt + f;

                                                               
  while (n.size() < minNLen) {
    n.push_back('0');
  }

                  
  llvh::SmallString<32> m{};

                                                               
  bool isZero = n.find_first_not_of('0') == llvh::StringRef::npos;

  if (isZero) {
                                              
    m.push_back('0');
  } else {
                                           
    m.append(n);
  }

  if (f != 0) {
    int32_t k = m.size();
    if (k <= f) {
                                                                           
                                        
                                                                         
      for (int32_t i = 0; i < f + 1 - k; ++i) {
        m.insert(m.begin(), '0');
      }
                                  
      k = f + 1;
    }
                                                                   
                                                         
    m.insert(m.begin() + (k - f), '.');
  }

  if (negative) {
    m.insert(m.begin(), '-');
  }

  return StringPrimitive::create(runtime, m);
}

CallResult<HermesValue>
numberPrototypeToExponential(void *, Runtime &runtime, NativeArgs args) {
                                               
  double x;
  if (args.getThisArg().isNumber()) {
    x = args.getThisArg().getNumber();
  } else {
    auto numPtr = Handle<JSNumber>::dyn_vmcast(args.getThisHandle());
    if (LLVM_UNLIKELY(!numPtr)) {
      return runtime.raiseTypeError(
          "Number.prototype.toExponential() can only be used on Number");
    }
    x = numPtr->getPrimitiveNumber();
  }

  auto res = toIntegerOrInfinity(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double fDouble = res->getNumber();

  if (std::isnan(x)) {
    return HermesValue::encodeStringValue(
        runtime.getPredefinedString(Predefined::NaN));
  }
  if (x == std::numeric_limits<double>::infinity()) {
    return HermesValue::encodeStringValue(
        runtime.getPredefinedString(Predefined::Infinity));
  }
  if (x == -std::numeric_limits<double>::infinity()) {
    return HermesValue::encodeStringValue(
        runtime.getPredefinedString(Predefined::NegativeInfinity));
  }

                                                          
  if (LLVM_UNLIKELY(
          !args.getArg(0).isUndefined() && (fDouble < 0 || fDouble > 100))) {
    return runtime.raiseRangeError(
        "toExponential argument must be between 0 and 100");
  }
                                               
                                       
                                                    
  int f = static_cast<int>(fDouble);

                                                                          
  bool negative = false;
  if (x < 0) {
    negative = true;
    x = -x;
  }

                  
  llvh::SmallString<32> n{};

                                  
  int e;
  if (x == 0) {
                                                                         
                                                                            
                        

                                                     
                                               
    for (int i = 0; i < f + 1; ++i) {
      n.push_back('0');
    }
    e = 0;
  } else {
             
                           
    int decPt;
                             
    int sign;
                                                              
    char *sEnd;

    DtoaAllocator<> dalloc{};
    if (!args.getArg(0).isUndefined()) {
                                                                   
                                                                         
                                                                             
      char *s = ::dtoa_fixedpoint(dalloc, x, 2, f + 1, &decPt, &sign, &sEnd);
      n.append(s, sEnd);
      ::g_freedtoa(dalloc, s);

                                                                     
                                                                 
      size_t minNLen = f + 1;
      while (n.size() < minNLen) {
        n.push_back('0');
      }
    } else {
                                                                   
                                                                           
                                                         
      char *s = ::g_dtoa(dalloc, x, 0, 0, &decPt, &sign, &sEnd);
      n.append(s, sEnd);
      ::g_freedtoa(dalloc, s);

                                                                      
      f = n.size() - 1;
    }
                                                                          
                                                                  
    e = decPt - 1;
  }

  if (f != 0) {
                                                                            
                     
    n.insert(n.begin() + 1, '.');
  }

                                                             
  if (e == 0) {
    n.append("e+0");
  } else {
    llvh::raw_svector_ostream os{n};
    os << llvh::format("e%+d", e);
  }

  if (negative) {
    n.insert(n.begin(), '-');
  }
  return runtime.ignoreAllocationFailure(StringPrimitive::create(runtime, n));
}

CallResult<HermesValue>
numberPrototypeToPrecision(void *, Runtime &runtime, NativeArgs args) {
                                             
  double x;
  if (args.getThisArg().isNumber()) {
    x = args.getThisArg().getNumber();
  } else {
    auto numPtr = Handle<JSNumber>::dyn_vmcast(args.getThisHandle());
    if (LLVM_UNLIKELY(!numPtr)) {
      return runtime.raiseTypeError(
          "Number.prototype.toPrecision() can only be used on Number");
    }
    x = numPtr->getPrimitiveNumber();
  }

  if (args.getArg(0).isUndefined()) {
    auto xHandle =
        runtime.makeHandle(HermesValue::encodeUntrustedNumberValue(x));
    auto resultRes = toString_RJS(runtime, xHandle);
    if (LLVM_UNLIKELY(resultRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    return resultRes->getHermesValue();
  }

  auto intRes = toIntegerOrInfinity(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double pDouble = intRes->getNumber();

  if (std::isnan(x)) {
    return HermesValue::encodeStringValue(
        runtime.getPredefinedString(Predefined::NaN));
  }
  if (x == std::numeric_limits<double>::infinity()) {
    return HermesValue::encodeStringValue(
        runtime.getPredefinedString(Predefined::Infinity));
  }
  if (x == -std::numeric_limits<double>::infinity()) {
    return HermesValue::encodeStringValue(
        runtime.getPredefinedString(Predefined::NegativeInfinity));
  }

                                                          
  if (pDouble < 1 || pDouble > 100) {
    return runtime.raiseRangeError(
        "toPrecision argument must be between 1 and 100");
  }
                                                 
                                       
                                                    
  int p = static_cast<int>(pDouble);

                                                                          
  bool negative = false;
  if (x < 0) {
    negative = true;
    x = -x;
  }

                                                          
  llvh::SmallString<32> n{};

                                  
  int e;
  if (x == 0) {
                                                     
    for (int i = 0; i < p; ++i) {
      n.push_back('0');
    }
    e = 0;
  } else {
             
                           
    int decPt;
                             
    int sign;
                                                              
    char *sEnd;

                                                                 
                                                                     
    {
      DtoaAllocator<> dalloc{};
      char *s = ::dtoa_fixedpoint(dalloc, x, 2, p, &decPt, &sign, &sEnd);
      n.append(s, sEnd);
      ::g_freedtoa(dalloc, s);
    }

                                                                   
                            
    size_t minNLen = p;
    while (n.size() < minNLen) {
      n.push_back('0');
    }

                                                                          
                                                                  
    e = decPt - 1;

    if (e < -6 || e >= p) {
                                                                     
      if (n.size() > 1) {
                                                                      
        n.insert(n.begin() + 1, '.');
      }

                         
      if (e == 0) {
        n.append("e+0");
      } else {
        llvh::raw_svector_ostream os{n};
        os << llvh::format("e%+d", e);
      }

                                                            
                                                                            
                                                                     
                                              

      if (negative) {
        n.insert(n.begin(), '-');
      }
      return runtime.ignoreAllocationFailure(
          StringPrimitive::create(runtime, n));
    }
  }

                                                              

  if (e == p - 1) {
    if (negative) {
      n.insert(n.begin(), '-');
    }
    return runtime.ignoreAllocationFailure(StringPrimitive::create(runtime, n));
  }

                                                                           
                   
  if (e >= 0) {
    n.insert(n.begin() + (e + 1), '.');
    if (negative) {
      n.insert(n.begin(), '-');
    }
    return runtime.ignoreAllocationFailure(StringPrimitive::create(runtime, n));
  } else {
                                                                                
                    
    llvh::SmallString<32> m{"0."};
    m.reserve(2 + -(e + 1) + n.size());
    for (int i = 0; i < -(e + 1); ++i) {
      m.push_back('0');
    }
    m.append(n);
    if (negative) {
      m.insert(m.begin(), '-');
    }
    return runtime.ignoreAllocationFailure(StringPrimitive::create(runtime, m));
  }
}

}                
}                    

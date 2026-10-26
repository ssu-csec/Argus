/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                                        
                                                                                

#include "JSLibInternal.h"

#include "hermes/VM/JSLib/JSLibStorage.h"
#include "hermes/VM/Operations.h"
#include "hermes/VM/SingleObject.h"
#include "hermes/VM/StringPrimitive.h"

#ifndef _USE_MATH_DEFINES
#define _USE_MATH_DEFINES
#endif
#include <float.h>
#include <math.h>
#include <random>
#include "hermes/Support/Math.h"
#include "hermes/Support/OSCompat.h"

#include "llvh/Support/MathExtras.h"
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

              
      

      

                                                                                
         
                                                             
                                                                           
                                                                        
            
                                                                    
                 
                                                   
                                                                      
                                                         
                                                                              
                                                   
                                                                    
static double roundHalfwaysTowardsInfinity(double x) {
                                                                
                                                                       
  static constexpr double integer_threshold = 1LLU << (DBL_MANT_DIG - 1);
  double absf = std::fabs(x);
  if (absf >= integer_threshold) {
                                         
    return x;
  } else if (absf < 0.5) {
                                                                     
    return std::copysign(0, x);
  } else {
                                                                         
                                                  
    return std::copysign(std::floor(x + 0.5), x);
  }
}

                                                                        
                                                                           
                                                                              
                                 
enum class MathKind {
#define MATHFUNC_1ARG(name, func) name,
#include "MathStdFunctions.def"
#undef MATHFUNC_1ARG
  Num1ArgKinds,
#define MATHFUNC_2ARG(name, func) name,
#include "MathStdFunctions.def"
#undef MATHFUNC_2ARG
  Num2ArgKinds
};
                                                         
                                                      
                                                 

CallResult<HermesValue>
runContextFunc1Arg(void *ctx, Runtime &runtime, NativeArgs args) {
  typedef double (*Math1ArgFuncPtr)(double);
  static Math1ArgFuncPtr math1ArgFuncs[] = {
#define MATHFUNC_1ARG(name, func) func,
#include "MathStdFunctions.def"
#undef MATHFUNC_1ARG
  };
  assert(
      (uint64_t)ctx < (uint64_t)MathKind::Num1ArgKinds &&
      "runContextFunc1Arg with wrong kind");
  Math1ArgFuncPtr func = math1ArgFuncs[(uint64_t)ctx];
  auto res = toNumber_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double arg = res->getNumber();
  return HermesValue::encodeUntrustedNumberValue(func(arg));
}

                                                            
                                                                 
                                        
CallResult<HermesValue>
runContextFunc2Arg(void *ctx, Runtime &runtime, NativeArgs args) {
  typedef double (*Math2ArgFuncPtr)(double, double);
  static Math2ArgFuncPtr math2ArgFuncs[] = {
#define MATHFUNC_2ARG(name, func) func,
#include "MathStdFunctions.def"
#undef MATHFUNC_2ARG
  };
  assert(
      (uint64_t)ctx > (uint64_t)MathKind::Num1ArgKinds &&
      (uint64_t)ctx < (uint64_t)MathKind::Num2ArgKinds &&
      "runContextFunc1Arg with wrong kind");
  Math2ArgFuncPtr func =
      math2ArgFuncs[(uint64_t)ctx - (uint64_t)MathKind::Num1ArgKinds - 1];
  auto res = toNumber_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double arg0 = res->getNumber();

  res = toNumber_RJS(runtime, args.getArgHandle(1));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double arg1 = res->getNumber();

  return HermesValue::encodeUntrustedNumberValue(func(arg0, arg1));
}

                  
CallResult<HermesValue> mathMax(void *, Runtime &runtime, NativeArgs args) {
  double result = -std::numeric_limits<double>::infinity();
  GCScopeMarkerRAII marker{runtime};
  for (const Handle<> sarg : args.handles()) {
    marker.flush();
    auto res = toNumber_RJS(runtime, sarg);
    if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    double arg = res->getNumber();
    if (std::isnan(result)) {
      continue;
    } else if (std::isnan(arg)) {
      result = std::numeric_limits<double>::quiet_NaN();
    } else if (arg > result || std::signbit(arg) < std::signbit(result)) {
                                                                                
      result = arg;
    }
  }
  return HermesValue::encodeUntrustedNumberValue(result);
}

                  
CallResult<HermesValue> mathMin(void *, Runtime &runtime, NativeArgs args) {
  double result = std::numeric_limits<double>::infinity();
  GCScopeMarkerRAII marker{runtime};
  for (const Handle<> sarg : args.handles()) {
    marker.flush();
    auto res = toNumber_RJS(runtime, sarg);
    if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    double arg = res->getNumber();
    if (std::isnan(result)) {
      continue;
    } else if (std::isnan(arg)) {
      result = std::numeric_limits<double>::quiet_NaN();
    } else if (arg < result || std::signbit(arg) > std::signbit(result)) {
                                                                                
      result = arg;
    }
  }
  return HermesValue::encodeUntrustedNumberValue(result);
}

                  
CallResult<HermesValue> mathPow(void *, Runtime &runtime, NativeArgs args) {
  auto res = toNumber_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  const double x = res->getNumber();

  res = toNumber_RJS(runtime, args.getArgHandle(1));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  const double y = res->getNumber();

  return HermesValue::encodeUntrustedNumberValue(expOp(x, y));
}

                  
                                                                             
CallResult<HermesValue> mathRandom(void *, Runtime &runtime, NativeArgs) {
  JSLibStorage *storage = runtime.getJSLibStorage();
  if (!storage->randomEngineSeeded_) {
    std::random_device randDevice;

    auto randValue = randDevice();
    static_assert(
        sizeof(randValue) == 4, "expecting 32 bits from std::random_device()");

                                                            
    uint64_t seed =
        (uint64_t(randValue) << (8 * sizeof(randValue))) | randDevice();
    static_assert(
        sizeof(decltype(storage->randomEngine_)::result_type) >= 8,
        "expecting at least 64-bit result_type for PRNG");

    storage->randomEngine_.seed(seed);
    storage->randomEngineSeeded_ = true;
  }
  std::uniform_real_distribution<> dist(0.0, 1.0);
  return HermesValue::encodeUntrustedNumberValue(dist(storage->randomEngine_));
}

CallResult<HermesValue> mathFround(void *, Runtime &runtime, NativeArgs args)
    LLVM_NO_SANITIZE("float-cast-overflow");

CallResult<HermesValue> mathFround(void *, Runtime &runtime, NativeArgs args) {
  auto res = toNumber_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double x = res->getNumber();

                                           
                                                            
                                                                             
                           
                                                                               
                   
  return HermesValue::encodeUntrustedNumberValue(
      static_cast<double>(static_cast<float>(x)));
}

                   
CallResult<HermesValue> mathHypot(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};
                                        
  llvh::SmallVector<double, 4> coerced{};
  coerced.reserve(args.getArgCount());

                                                                         
                                                                       
                                         
  double max = 0;

  bool hasNaN = false, hasInf = false;
  auto marker = gcScope.createMarker();
                                        
  for (const Handle<> arg : args.handles()) {
    gcScope.flushToMarker(marker);
                                   
    auto res = toNumber_RJS(runtime, arg);
    if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    double value = res->getNumber();
    hasInf = std::isinf(value) || hasInf;
    hasNaN = std::isnan(value) || hasNaN;
                              
    coerced.push_back(value);
    max = std::max(std::fabs(value), max);
  }
                                              
                                                        
  if (hasInf)
    return HermesValue::encodeUntrustedNumberValue(
        std::numeric_limits<double>::infinity());
                                              
                                       
  if (hasNaN)
    return HermesValue::encodeNaNValue();

  assert(!(max < 0) && "max must not be negative (max(abs(value))");
                                        
  if (max == 0) {
    return HermesValue::encodeUntrustedNumberValue(+0);
  }

                                                                           
                                                                        
                         

                                                                   
                                                                              
                                                             
                                                              
                                                                              
  double sum = 0;
  double c = 0;
  for (const double value : coerced) {
    double addend = (value / max) * (value / max);
                                                                                
    double y = addend - c;
    double t = sum + y;
    c = (t - sum) - y;
    sum = t;
  }
  double result = std::sqrt(sum) * max;

  return HermesValue::encodeUntrustedNumberValue(result);
}

                  
                          
CallResult<HermesValue> mathImul(void *, Runtime &runtime, NativeArgs args) {
  auto res = toUInt32_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  uint32_t a = res->getNumber();
  res = toUInt32_RJS(runtime, args.getArgHandle(1));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  uint32_t b = res->getNumber();

                            
  uint32_t product = a * b;

                                                                    
  return HermesValue::encodeUntrustedNumberValue(static_cast<int32_t>(product));
}

                  
                                            
CallResult<HermesValue> mathClz32(void *, Runtime &runtime, NativeArgs args) {
  auto res = toUInt32_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  uint32_t n = res->getNumberAs<uint32_t>();
  uint32_t p = llvh::countLeadingZeros(n);
  return HermesValue::encodeUntrustedNumberValue(p);
}

                  
                             
CallResult<HermesValue> mathSign(void *, Runtime &runtime, NativeArgs args) {
  auto res = toNumber_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double x = res->getNumber();

  if (std::isnan(x)) {
    return HermesValue::encodeNaNValue();
  }
  if (x == 0) {
                                                                   
    return HermesValue::encodeUntrustedNumberValue(x);
  }

  return HermesValue::encodeUntrustedNumberValue(std::signbit(x) ? -1 : +1);
}

Handle<JSObject> createMathObject(Runtime &runtime) {
  auto objRes = JSMath::create(
      runtime, Handle<JSObject>::vmcast(&runtime.objectPrototype));
  assert(objRes != ExecutionStatus::EXCEPTION && "unable to define Math");
  auto math = runtime.makeHandle<JSMath>(*objRes);

  DefinePropertyFlags constantDPF =
      DefinePropertyFlags::getDefaultNewPropertyFlags();
  constantDPF.enumerable = 0;
  constantDPF.writable = 0;
  constantDPF.configurable = 0;

  MutableHandle<> numberHandle{runtime};

                                        
  auto setMathValueProperty = [&](SymbolID name, double value) {
    numberHandle = HermesValue::encodeUntrustedNumberValue(value);
    auto result = JSObject::defineOwnProperty(
        math, runtime, name, constantDPF, numberHandle);
    assert(
        result != ExecutionStatus::EXCEPTION &&
        "defineOwnProperty() failed on a new object");
    (void)result;
  };
  setMathValueProperty(Predefined::getSymbolID(Predefined::E), M_E);
  setMathValueProperty(Predefined::getSymbolID(Predefined::LN10), M_LN10);
  setMathValueProperty(Predefined::getSymbolID(Predefined::LN2), M_LN2);
  setMathValueProperty(Predefined::getSymbolID(Predefined::LOG2E), M_LOG2E);
  setMathValueProperty(Predefined::getSymbolID(Predefined::LOG10E), M_LOG10E);
  setMathValueProperty(Predefined::getSymbolID(Predefined::PI), M_PI);
  setMathValueProperty(Predefined::getSymbolID(Predefined::SQRT1_2), M_SQRT1_2);
  setMathValueProperty(Predefined::getSymbolID(Predefined::SQRT2), M_SQRT2);

                                           
  auto setMathFunctionProperty1Arg = [&runtime, math](
                                         SymbolID name, MathKind kind) {
    defineMethod(runtime, math, name, (void *)kind, runContextFunc1Arg, 1);
  };

  auto setMathFunctionProperty2Arg = [&runtime, math](
                                         SymbolID name, MathKind kind) {
    defineMethod(runtime, math, name, (void *)kind, runContextFunc2Arg, 2);
  };

                                                                   
                                                                   
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::abs), MathKind::abs);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::acos), MathKind::acos);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::acosh), MathKind::acosh);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::asin), MathKind::asin);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::asinh), MathKind::asinh);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::atan), MathKind::atan);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::atanh), MathKind::atanh);
  setMathFunctionProperty2Arg(
      Predefined::getSymbolID(Predefined::atan2), MathKind::atan2);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::cbrt), MathKind::cbrt);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::ceil), MathKind::ceil);
  defineMethod(
      runtime,
      math,
      Predefined::getSymbolID(Predefined::clz32),
      nullptr,
      mathClz32,
      1);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::cos), MathKind::cos);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::cosh), MathKind::cosh);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::exp), MathKind::exp);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::expm1), MathKind::expm1);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::floor), MathKind::floor);
  defineMethod(
      runtime,
      math,
      Predefined::getSymbolID(Predefined::fround),
      nullptr,
      mathFround,
      1);
  defineMethod(
      runtime,
      math,
      Predefined::getSymbolID(Predefined::hypot),
      nullptr,
      mathHypot,
      2);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::log), MathKind::log);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::log10), MathKind::log10);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::log1p), MathKind::log1p);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::log2), MathKind::log2);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::trunc), MathKind::trunc);
  defineMethod(
      runtime,
      math,
      Predefined::getSymbolID(Predefined::max),
      nullptr,
      mathMax,
      2);
  defineMethod(
      runtime,
      math,
      Predefined::getSymbolID(Predefined::min),
      nullptr,
      mathMin,
      2);
  defineMethod(
      runtime,
      math,
      Predefined::getSymbolID(Predefined::imul),
      nullptr,
      mathImul,
      2);
  defineMethod(
      runtime,
      math,
      Predefined::getSymbolID(Predefined::pow),
      nullptr,
      mathPow,
      2);
  defineMethod(
      runtime,
      math,
      Predefined::getSymbolID(Predefined::random),
      nullptr,
      mathRandom,
      0);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::round), MathKind::round);
  defineMethod(
      runtime,
      math,
      Predefined::getSymbolID(Predefined::sign),
      nullptr,
      mathSign,
      1);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::sin), MathKind::sin);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::sinh), MathKind::sinh);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::sqrt), MathKind::sqrt);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::tan), MathKind::tan);
  setMathFunctionProperty1Arg(
      Predefined::getSymbolID(Predefined::tanh), MathKind::tanh);

  auto dpf = DefinePropertyFlags::getDefaultNewPropertyFlags();
  dpf.writable = 0;
  dpf.enumerable = 0;
  defineProperty(
      runtime,
      math,
      Predefined::getSymbolID(Predefined::SymbolToStringTag),
      runtime.getPredefinedStringHandle(Predefined::Math),
      dpf);

  return math;
}

}                
}                    

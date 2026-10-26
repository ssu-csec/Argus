/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                                           
                                                                                
#include "hermes/Platform/Intl/PlatformIntl.h"
#include "hermes/VM/JSArrayBuffer.h"
#include "hermes/VM/JSDataView.h"
#include "hermes/VM/JSLib.h"
#include "hermes/VM/JSTypedArray.h"
#include "hermes/VM/Operations.h"
#include "hermes/VM/PrimitiveBox.h"
#include "hermes/VM/PropertyAccessor.h"
#include "hermes/VM/StringView.h"

#include "dtoa/dtoa.h"

#include "JSLibInternal.h"

namespace hermes {
namespace vm {

                  
CallResult<HermesValue> isNaN(void *, Runtime &runtime, NativeArgs args) {
  auto res = toNumber_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return HermesValue::encodeBoolValue(std::isnan(res->getNumber()));
}

                  
CallResult<HermesValue> isFinite(void *, Runtime &runtime, NativeArgs args) {
  auto res = toNumber_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto value = res->getDouble();
  return HermesValue::encodeBoolValue(std::isfinite(value));
}

                                           
CallResult<HermesValue> emptyFunction(void *, Runtime &, NativeArgs) {
  return HermesValue::encodeUndefinedValue();
}

                                                                   
static bool isValidRadixChar(char16_t c, int radix) {
               
  if (c >= '0' && c <= '9') {
    return (radix >= 10 || c < '0' + radix);
  }
  c = letterToLower(c);
  return (radix > 10 && c >= 'a' && c < 'a' + radix - 10);
}

                                          
CallResult<HermesValue> parseInt(void *, Runtime &runtime, NativeArgs args) {
                    
  auto strRes = toString_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto str = runtime.makeHandle(std::move(*strRes));

  int radix = 10;
  bool stripPrefix = true;
                                                                     
  if (args.getArgCount() > 1 && !args.getArg(1).isUndefined()) {
    auto intRes = toInt32_RJS(runtime, args.getArgHandle(1));
    if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    radix = static_cast<int>(intRes->getNumber());
    if (radix == 0) {
      radix = 10;
    } else if (radix < 2 || radix > 36) {
      return HermesValue::encodeNaNValue();
    } else if (radix != 16) {
      stripPrefix = false;
    }
  }

  auto strView = StringPrimitive::createStringView(runtime, str);
  auto begin = strView.begin();
  auto end = strView.end();

                                
  while (begin != end &&
         (isWhiteSpaceChar(*begin) || isLineTerminatorChar(*begin))) {
    ++begin;
  }

                  
  int sign = 1;
  if (begin != end && (*begin == u'+' || *begin == u'-')) {
    if (*begin == u'-') {
      sign = -1;
    }
    ++begin;
  }

                                        
  if (stripPrefix && begin != end) {
    if (*begin == u'0') {
      ++begin;
      if (begin != end && letterToLower(*begin) == u'x') {
        ++begin;
        radix = 16;
      } else {
        --begin;
      }
    }
  }

                                                      
  auto realEnd = begin;
  for (; realEnd != end && isValidRadixChar(*realEnd, radix); ++realEnd) {
  }
  if (realEnd == begin) {
                                          
    return HermesValue::encodeNaNValue();
  }

  return HermesValue::encodeUntrustedNumberValue(
      sign * parseIntWithRadix(strView.slice(begin, realEnd), radix));
}

                                     
static bool isPrefix(StringView str1, StringView str2) {
  if (str1.length() > str2.length()) {
    return false;
  }
  for (auto first1 = str1.begin(), last1 = str1.end(), first2 = str2.begin();
       first1 != last1;
       ++first1, ++first2) {
    if (*first1 != *first2) {
      return false;
    }
  }
  return true;
}

                                     
CallResult<HermesValue> parseFloat(void *, Runtime &runtime, NativeArgs args) {
                    
  auto res = toString_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  auto strHandle = runtime.makeHandle(std::move(*res));
  auto origStr = StringPrimitive::createStringView(runtime, strHandle);

  auto &idTable = runtime.getIdentifierTable();

                              
  auto begin = origStr.begin();
  auto end = origStr.end();

  while (begin != end &&
         (isWhiteSpaceChar(*begin) || isLineTerminatorChar(*begin))) {
    ++begin;
  }
  StringView str16 = origStr.slice(begin, end);

                              
                                                                    
               
  if (LLVM_UNLIKELY(isPrefix(
          idTable.getStringView(
              runtime, Predefined::getSymbolID(Predefined::Infinity)),
          str16))) {
    return HermesValue::encodeUntrustedNumberValue(
        std::numeric_limits<double>::infinity());
  }
  if (LLVM_UNLIKELY(isPrefix(
          idTable.getStringView(
              runtime, Predefined::getSymbolID(Predefined::PositiveInfinity)),
          str16))) {
    return HermesValue::encodeUntrustedNumberValue(
        std::numeric_limits<double>::infinity());
  }
  if (LLVM_UNLIKELY(isPrefix(
          idTable.getStringView(
              runtime, Predefined::getSymbolID(Predefined::NegativeInfinity)),
          str16))) {
    return HermesValue::encodeUntrustedNumberValue(
        -std::numeric_limits<double>::infinity());
  }
  if (LLVM_UNLIKELY(isPrefix(
          idTable.getStringView(
              runtime, Predefined::getSymbolID(Predefined::NaN)),
          str16))) {
    return HermesValue::encodeNaNValue();
  }

                                                                   
                                            
  auto len = str16.length();
  llvh::SmallVector<char, 32> str8(len + 1);
  uint32_t i = 0;
  for (auto c : str16) {
    if ((c >= u'0' && c <= u'9') || c == '.' || letterToLower(c) == 'e' ||
        c == '+' || c == '-') {
      str8[i] = static_cast<char>(c);
    } else {
      break;
    }
    ++i;
  }
  if (i == 0) {
                    
    return HermesValue::encodeNaNValue();
  }
                                                                             
                                                                            
                                                                              
                     
  len = i;
  str8[len] = '\0';
  char *endPtr;
  ::hermes_g_strtod(str8.data(), &endPtr);
  if (endPtr == str8.data()) {
                    
    return HermesValue::encodeNaNValue();
  }
                                                         
  *endPtr = '\0';
  return HermesValue::encodeUntrustedNumberValue(
      ::hermes_g_strtod(str8.data(), &endPtr));
}

                                                         
CallResult<HermesValue> gc(void *, Runtime &runtime, NativeArgs) {
  runtime.collect("forced");
  return HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue>
throwTypeError(void *ctx, Runtime &runtime, NativeArgs) {
  static const char *TypeErrorMessage[] = {
      "Restricted in strict mode",
      "Dynamic requires are not allowed after static resolution",
  };

  uint64_t kind = (uint64_t)ctx;
  assert(
      kind < (uint64_t)TypeErrorKind::NumKinds &&
      "[[ThrowTypeError]] wrong error kind passed as context");
  return runtime.raiseTypeError(TypeErrorMessage[kind]);
}

                                                                   
                 
void initGlobalObject(Runtime &runtime, const JSLibFlags &jsLibFlags) {
  GCScope gcScope{runtime, "initGlobalObject", 350};

                                                    
  DefinePropertyFlags constantDPF =
      DefinePropertyFlags::getDefaultNewPropertyFlags();
  constantDPF.enumerable = 0;
  constantDPF.writable = 0;
  constantDPF.configurable = 0;

                                                   
  DefinePropertyFlags normalDPF =
      DefinePropertyFlags::getNewNonEnumerableFlags();

                                                   
  DefinePropertyFlags configurableOnlyPDF =
      DefinePropertyFlags::getDefaultNewPropertyFlags();
  configurableOnlyPDF.enumerable = 0;
  configurableOnlyPDF.writable = 0;

                                  
  DefinePropertyFlags clearConfigurableDPF{};
  clearConfigurableDPF.setConfigurable = 1;
  clearConfigurableDPF.configurable = 0;

                                                              
                                                               
  auto defineGlobalFunc =
      [&](SymbolID name, NativeFunctionPtr functionPtr, unsigned paramCount) {
        gcScope.clearAllHandles();

        auto func = NativeFunction::createWithoutPrototype(
            runtime, nullptr, functionPtr, name, paramCount);
        runtime.ignoreAllocationFailure(
            JSObject::defineOwnProperty(
                runtime.getGlobal(), runtime, name, normalDPF, func));
        return func;
      };

                  
  runtime.ignoreAllocationFailure(
      JSObject::defineOwnProperty(
          runtime.getGlobal(),
          runtime,
          Predefined::getSymbolID(Predefined::NaN),
          constantDPF,
          runtime.makeHandle(HermesValue::encodeNaNValue())));

                       
  runtime.ignoreAllocationFailure(
      JSObject::defineOwnProperty(
          runtime.getGlobal(),
          runtime,
          Predefined::getSymbolID(Predefined::Infinity),
          constantDPF,
          runtime.makeHandle(
              HermesValue::encodeUntrustedNumberValue(
                  std::numeric_limits<double>::infinity()))));

                        
  runtime.ignoreAllocationFailure(
      JSObject::defineOwnProperty(
          runtime.getGlobal(),
          runtime,
          Predefined::getSymbolID(Predefined::undefined),
          constantDPF,
          runtime.makeHandle(HermesValue::encodeUndefinedValue())));

                                                                                
           

  runtime.objectPrototype =
      JSObject::create(runtime, Runtime::makeNullHandle<JSObject>())
          .getHermesValue();
  runtime.objectPrototypeRawPtr = vmcast<JSObject>(runtime.objectPrototype);

                                                                               
           
  runtime.ErrorPrototype = JSObject::create(runtime).getHermesValue();

                                                                       
                                      
#define NATIVE_ERROR_TYPE(name)                                       \
  runtime.name##Prototype =                                           \
      JSObject::create(                                               \
          runtime, Handle<JSObject>::vmcast(&runtime.ErrorPrototype)) \
          .getHermesValue();
#define AGGREGATE_ERROR_TYPE(name) NATIVE_ERROR_TYPE(name)
#include "hermes/FrontEndDefs/NativeErrorTypes.def"

                                                                             
                             
  runtime.callSitePrototype =
      JSObject::create(
          runtime, Handle<JSObject>::vmcast(&runtime.objectPrototype))
          .getHermesValue();

                                                                        
                     
  Handle<NativeFunction> funcRes = NativeFunction::create(
      runtime,
      Handle<JSObject>::vmcast(&runtime.objectPrototype),
      nullptr,
      emptyFunction,
      Predefined::getSymbolID(Predefined::emptyString),
      0,
      Runtime::makeNullHandle<JSObject>());
  runtime.functionPrototype = funcRes.getHermesValue();
  runtime.functionPrototypeRawPtr = funcRes.get();
  runtime.ignoreAllocationFailure(
      JSObject::defineOwnProperty(
          Handle<JSObject>::vmcast(&runtime.functionPrototype),
          runtime,
          Predefined::getSymbolID(Predefined::length),
          configurableOnlyPDF,
          Runtime::getZeroValue()));

                        
  auto throwTypeErrorFunction = NativeFunction::create(
      runtime,
      Handle<JSObject>::vmcast(&runtime.functionPrototype),
      (void *)TypeErrorKind::NonStrictOnly,
      throwTypeError,
      Predefined::getSymbolID(Predefined::emptyString),
      0,
      Runtime::makeNullHandle<JSObject>());
  runtime.ignoreAllocationFailure(
      JSObject::defineOwnProperty(
          throwTypeErrorFunction,
          runtime,
          Predefined::getSymbolID(Predefined::length),
          clearConfigurableDPF,
          Runtime::getUndefinedValue()));
  runtime.throwTypeErrorAccessor = PropertyAccessor::create(
      runtime, throwTypeErrorFunction, throwTypeErrorFunction);

                                    
  runtime.parseIntFunction =
      defineGlobalFunc(
          Predefined::getSymbolID(Predefined::parseInt), parseInt, 2)
          .getHermesValue();

                                      
  runtime.parseFloatFunction =
      defineGlobalFunc(
          Predefined::getSymbolID(Predefined::parseFloat), parseFloat, 1)
          .getHermesValue();

                                                                      
                     
  runtime.stringPrototype =
      runtime
          .ignoreAllocationFailure(
              JSString::create(
                  runtime,
                  runtime.getPredefinedStringHandle(Predefined::emptyString),
                  Handle<JSObject>::vmcast(&runtime.objectPrototype)))
          .getHermesValue();

                                                                      
                     
  runtime.bigintPrototype = JSObject::create(runtime).getHermesValue();

                                                                      
                     
  runtime.numberPrototype =
      JSNumber::create(
          runtime, +0.0, Handle<JSObject>::vmcast(&runtime.objectPrototype))
          .getHermesValue();

                                                                       
                     
  runtime.booleanPrototype =
      JSBoolean::create(
          runtime, false, Handle<JSObject>::vmcast(&runtime.objectPrototype))
          .getHermesValue();

                                                                      
                     
  runtime.symbolPrototype = JSObject::create(runtime).getHermesValue();

                                                                    
                     
  runtime.datePrototype =
      JSObject::create(
          runtime, Handle<JSObject>::vmcast(&runtime.objectPrototype))
          .getHermesValue();

                                                  
  runtime.iteratorPrototype = JSObject::create(runtime).getHermesValue();

                                                                     
                     
  runtime.arrayPrototype =
      runtime
          .ignoreAllocationFailure(
              JSArray::createNoAllocPropStorage(
                  runtime,
                  Handle<JSObject>::vmcast(&runtime.objectPrototype),
                  JSArray::createClass(
                      runtime,
                      Handle<JSObject>::vmcast(&runtime.objectPrototype)),
                  0,
                  0))
          .getHermesValue();

                             
  runtime.arrayClass =
      JSArray::createClass(
          runtime, Handle<JSObject>::vmcast(&runtime.arrayPrototype))
          .getHermesValue();

                                           
  runtime.regExpMatchClass =
      JSRegExp::createMatchClass(
          runtime, Handle<HiddenClass>::vmcast(&runtime.arrayClass))
          .getHermesValue();

                                                                           
                     
  runtime.arrayBufferPrototype =
      JSObject::create(
          runtime, Handle<JSObject>::vmcast(&runtime.objectPrototype))
          .getHermesValue();

                                                                        
                     
  runtime.dataViewPrototype =
      JSObject::create(
          runtime, Handle<JSObject>::vmcast(&runtime.objectPrototype))
          .getHermesValue();

                                                                              
                     
  runtime.typedArrayBasePrototype = JSObject::create(runtime).getHermesValue();

               
                                                                       
#define TYPED_ARRAY(name, type)                                                \
  runtime.name##ArrayPrototype =                                               \
      JSObject::create(                                                        \
          runtime, Handle<JSObject>::vmcast(&runtime.typedArrayBasePrototype)) \
          .getHermesValue();
#include "hermes/VM/TypedArrays.def"

                                                                   
                     
  runtime.setPrototype = JSObject::create(runtime).getHermesValue();

  runtime.setIteratorPrototype =
      createSetIteratorPrototype(runtime).getHermesValue();

                                                                   
                     
  runtime.mapPrototype = JSObject::create(runtime).getHermesValue();

  runtime.mapIteratorPrototype =
      createMapIteratorPrototype(runtime).getHermesValue();

                                               
                                                                                
                        
  runtime.regExpPrototype =
      JSObject::create(
          runtime, Handle<JSObject>::vmcast(&runtime.objectPrototype))
          .getHermesValue();

                                                
  runtime.weakMapPrototype = JSObject::create(runtime).getHermesValue();

                                                
  runtime.weakSetPrototype = JSObject::create(runtime).getHermesValue();

                                                      
  if (LLVM_UNLIKELY(runtime.hasMicrotaskQueue())) {
                                                  
    runtime.weakRefPrototype = JSObject::create(runtime).getHermesValue();
  }

                                                       
  runtime.arrayIteratorPrototype =
      JSObject::create(
          runtime, Handle<JSObject>::vmcast(&runtime.iteratorPrototype))
          .getHermesValue();

                                                        
  runtime.stringIteratorPrototype =
      JSObject::create(
          runtime, Handle<JSObject>::vmcast(&runtime.iteratorPrototype))
          .getHermesValue();

                                                              
  runtime.regExpStringIteratorPrototype =
      JSObject::create(
          runtime, Handle<JSObject>::vmcast(&runtime.iteratorPrototype))
          .getHermesValue();

                                                          
  runtime.generatorPrototype =
      JSObject::create(
          runtime, Handle<JSObject>::vmcast(&runtime.iteratorPrototype))
          .getHermesValue();

  runtime.asyncIteratorPrototype = JSObject::create(runtime, Handle<JSObject>::vmcast(&runtime.objectPrototype)).getHermesValue();
  runtime.asyncGeneratorPrototype = JSObject::create(runtime, Handle<JSObject>::vmcast(&runtime.asyncIteratorPrototype)).getHermesValue();
  runtime.asyncGeneratorFunctionPrototype = JSObject::create(runtime, Handle<JSObject>::vmcast(&runtime.functionPrototype)).getHermesValue();

                                                           
  runtime.generatorFunctionPrototype =
      JSObject::create(
          runtime, Handle<JSObject>::vmcast(&runtime.functionPrototype))
          .getHermesValue();

                                                       
  runtime.asyncFunctionPrototype =
      JSObject::create(
          runtime, Handle<JSObject>::vmcast(&runtime.functionPrototype))
          .getHermesValue();

                                                    
  runtime.textEncoderPrototype = JSObject::create(runtime).getHermesValue();

                        
  runtime.objectConstructor = createObjectConstructor(runtime).getHermesValue();

                         
  runtime.errorConstructor = createErrorConstructor(runtime).getHermesValue();

                                 
#define NATIVE_ERROR_TYPE(name)                            \
  runtime.name##Constructor =                              \
      create##name##Constructor(runtime).getHermesValue(); \
  gcScope.clearAllHandles();
#define AGGREGATE_ERROR_TYPE(name) NATIVE_ERROR_TYPE(name)
#include "hermes/FrontEndDefs/NativeErrorTypes.def"

                                              
  populateCallSitePrototype(runtime);

                        
  createStringConstructor(runtime);

                        
  createBigIntConstructor(runtime);

                          
  runtime.functionConstructor =
      createFunctionConstructor(runtime).getHermesValue();

                        
  createNumberConstructor(runtime);

                         
  createBooleanConstructor(runtime);

                      
  createDateConstructor(runtime);

                       
  createRegExpConstructor(runtime);
  runtime.regExpLastInput = HermesValue::encodeUndefinedValue();
  runtime.regExpLastRegExp = HermesValue::encodeUndefinedValue();

                       
  createArrayConstructor(runtime);

  if (runtime.hasArrayBuffer()) {
                               
    createArrayBufferConstructor(runtime);

                            
    createDataViewConstructor(runtime);

                                  
    runtime.typedArrayBaseConstructor =
        createTypedArrayBaseConstructor(runtime).getHermesValue();

#define TYPED_ARRAY(name, type)                                 \
  runtime.name##ArrayConstructor =                              \
      create##name##ArrayConstructor(runtime).getHermesValue(); \
  gcScope.clearAllHandles();
#include "hermes/VM/TypedArrays.def"
  } else {
    gcScope.clearAllHandles();
  }                  

                     
  createSetConstructor(runtime);

                     
  createMapConstructor(runtime);

                         
  createWeakMapConstructor(runtime);

                         
  createWeakSetConstructor(runtime);

                                                                  
  if (LLVM_UNLIKELY(runtime.hasMicrotaskQueue())) {
                           
    createWeakRefConstructor(runtime);
  }

                        
  createSymbolConstructor(runtime);

                          
  populateIteratorPrototype(runtime);

                     
  populateArrayIteratorPrototype(runtime);

                      
  populateStringIteratorPrototype(runtime);

                             
  populateRegExpStringIteratorPrototype(runtime);

                                                                               
  createGeneratorFunctionConstructor(runtime);
  createAsyncGeneratorFunctionConstructor(runtime);

                                                                           
  createAsyncFunctionConstructor(runtime);

                             
  createTextEncoderConstructor(runtime);

                          
  populateGeneratorPrototype(runtime);

                       
  if (LLVM_UNLIKELY(runtime.hasES6Proxy())) {
    createProxyConstructor(runtime);
  }

                                  
  runtime.ignoreAllocationFailure(
      JSObject::defineOwnProperty(
          runtime.getGlobal(),
          runtime,
          Predefined::getSymbolID(Predefined::Math),
          normalDPF,
          createMathObject(runtime)));

                                  
  runtime.ignoreAllocationFailure(
      JSObject::defineOwnProperty(
          runtime.getGlobal(),
          runtime,
          Predefined::getSymbolID(Predefined::JSON),
          normalDPF,
          createJSONObject(runtime)));

  if (LLVM_UNLIKELY(runtime.hasES6Proxy())) {
                                       
    runtime.ignoreAllocationFailure(
        JSObject::defineOwnProperty(
            runtime.getGlobal(),
            runtime,
            Predefined::getSymbolID(Predefined::Reflect),
            normalDPF,
            createReflectObject(runtime)));
  }

                                              
  runtime.ignoreAllocationFailure(
      JSObject::defineOwnProperty(
          runtime.getGlobal(),
          runtime,
          Predefined::getSymbolID(Predefined::HermesInternal),
          constantDPF,
          createHermesInternalObject(runtime, jsLibFlags)));

#ifdef HERMES_ENABLE_DEBUGGER

                                                
  runtime.ignoreAllocationFailure(
      JSObject::defineOwnProperty(
          runtime.getGlobal(),
          runtime,
          runtime.getIdentifierTable().registerLazyIdentifier(
              createASCIIRef("DebuggerInternal")),
          constantDPF,
          createDebuggerInternalObject(runtime)));

#endif                          

                                 
  defineGlobalFunc(Predefined::getSymbolID(Predefined::print), print, 1);

                                
  defineGlobalFunc(Predefined::getSymbolID(Predefined::eval), eval, 1);

                                 
  defineGlobalFunc(Predefined::getSymbolID(Predefined::isNaN), isNaN, 1);

                                    
  defineGlobalFunc(Predefined::getSymbolID(Predefined::isFinite), isFinite, 1);

                                  
  defineGlobalFunc(Predefined::getSymbolID(Predefined::escape), escape, 1);

                                    
  defineGlobalFunc(Predefined::getSymbolID(Predefined::unescape), unescape, 1);

                                
  defineGlobalFunc(Predefined::getSymbolID(Predefined::atob), atob, 1);

                                
  defineGlobalFunc(Predefined::getSymbolID(Predefined::btoa), btoa, 1);

                                     
  defineGlobalFunc(
      Predefined::getSymbolID(Predefined::decodeURI), decodeURI, 1);

                                              
  defineGlobalFunc(
      Predefined::getSymbolID(Predefined::decodeURIComponent),
      decodeURIComponent,
      1);

                                     
  defineGlobalFunc(
      Predefined::getSymbolID(Predefined::encodeURI), encodeURI, 1);

                                              
  defineGlobalFunc(
      Predefined::getSymbolID(Predefined::encodeURIComponent),
      encodeURIComponent,
      1);

                                      
  runtime.ignoreAllocationFailure(
      JSObject::defineOwnProperty(
          runtime.getGlobal(),
          runtime,
          Predefined::getSymbolID(Predefined::globalThis),
          normalDPF,
          runtime.getGlobal()));

                                   
  runtime.requireFunction =
      NativeFunction::create(
          runtime,
          Handle<JSObject>::vmcast(&runtime.functionPrototype),
          nullptr,
          require,
          Predefined::getSymbolID(Predefined::require),
          1,
          Runtime::makeNullHandle<JSObject>())
          .getHermesValue();

  if (jsLibFlags.enableHermesInternal) {
                                
    defineGlobalFunc(Predefined::getSymbolID(Predefined::gc), gc, 0);
  }

#ifdef HERMES_ENABLE_IR_INSTRUMENTATION
                                          
  runtime.ignoreAllocationFailure(
      JSObject::defineOwnProperty(
          runtime.getGlobal(),
          runtime,
          runtime.getIdentifierTable().registerLazyIdentifier(
              createASCIIRef("__instrument")),
          normalDPF,
          createInstrumentObject(runtime)));
#endif

#ifdef HERMES_ENABLE_INTL
                                  
                                                                          
  if (runtime.hasIntl()) {
    runtime.ignoreAllocationFailure(
        JSObject::defineOwnProperty(
            runtime.getGlobal(),
            runtime,
            Predefined::getSymbolID(Predefined::Intl),
            normalDPF,
            intl::createIntlObject(runtime)));
  }
#endif
}

}                
}                    

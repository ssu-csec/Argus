/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                                                 
                                                                                

#include "JSLibInternal.h"

#include "hermes/Platform/Unicode/PlatformUnicode.h"
#include "hermes/VM/Operations.h"
#include "hermes/VM/PrimitiveBox.h"
#include "hermes/VM/SmallXString.h"
#include "hermes/VM/StringBuilder.h"
#include "hermes/VM/StringView.h"

#if defined(__ANDROID__)
#include "hermes/Platform/Unicode/PlatformUnicode.h"
#endif

#ifdef __APPLE__
#include <CoreFoundation/CFString.h>
#endif

#include <locale>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

                                                                                
           

Handle<JSObject> createStringConstructor(Runtime &runtime) {
  auto stringPrototype = Handle<JSString>::vmcast(&runtime.stringPrototype);

  auto cons = defineSystemConstructor<JSString>(
      runtime,
      Predefined::getSymbolID(Predefined::String),
      stringConstructor,
      stringPrototype,
      1,
      CellKind::JSStringKind);

                                  
  void *ctx = nullptr;
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::toString),
      ctx,
      stringPrototypeToString,
      0);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::at),
      ctx,
      stringPrototypeAt,
      1);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::valueOf),
      ctx,
      stringPrototypeToString,
      0);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::charCodeAt),
      ctx,
      stringPrototypeCharCodeAt,
      1);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::codePointAt),
      ctx,
      stringPrototypeCodePointAt,
      1);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::concat),
      ctx,
      stringPrototypeConcat,
      1);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::substring),
      ctx,
      stringPrototypeSubstring,
      2);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::toLowerCase),
      ctx,
      stringPrototypeToLowerCase,
      0);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::toLocaleLowerCase),
      ctx,
      stringPrototypeToLocaleLowerCase,
      0);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::toUpperCase),
      ctx,
      stringPrototypeToUpperCase,
      0);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::toLocaleUpperCase),
      ctx,
      stringPrototypeToLocaleUpperCase,
      0);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::substr),
      ctx,
      stringPrototypeSubstr,
      2);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::trim),
      ctx,
      stringPrototypeTrim,
      0);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::localeCompare),
      ctx,
      stringPrototypeLocaleCompare,
      1);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::normalize),
      ctx,
      stringPrototypeNormalize,
      0);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::repeat),
      ctx,
      stringPrototypeRepeat,
      1);

  DefinePropertyFlags dpf = DefinePropertyFlags::getNewNonEnumerableFlags();
  auto trimStartRes =
      runtime.makeHandle<Callable>(runtime.ignoreAllocationFailure(defineMethod(
          runtime,
          stringPrototype,
          Predefined::getSymbolID(Predefined::trimStart),
          ctx,
          stringPrototypeTrimStart,
          0,
          dpf)));
  auto trimEndRes =
      runtime.makeHandle<Callable>(runtime.ignoreAllocationFailure(defineMethod(
          runtime,
          stringPrototype,
          Predefined::getSymbolID(Predefined::trimEnd),
          ctx,
          stringPrototypeTrimEnd,
          0,
          dpf)));

  defineProperty(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::trimLeft),
      trimStartRes);
  defineProperty(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::trimRight),
      trimEndRes);

  (void)defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::SymbolIterator),
      Predefined::getSymbolID(Predefined::squareSymbolIterator),
      ctx,
      stringPrototypeSymbolIterator,
      0,
      dpf);

                          
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::fromCharCode),
      ctx,
      stringFromCharCode,
      1);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::fromCodePoint),
      ctx,
      stringFromCodePoint,
      1);
  defineMethod(
      runtime,
      cons,
      Predefined::getSymbolID(Predefined::raw),
      ctx,
      stringRaw,
      1);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::matchAll),
      ctx,
      stringPrototypeMatchAll,
      1);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::replaceAll),
      ctx,
      stringPrototypeReplaceAll,
      2);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::match),
      ctx,
      stringPrototypeMatch,
      1);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::padEnd),
      (void *)false,
      stringPrototypePad,
      1);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::padStart),
      (void *)true,
      stringPrototypePad,
      1);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::replace),
      ctx,
      stringPrototypeReplace,
      2);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::search),
      ctx,
      stringPrototypeSearch,
      1);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::charAt),
      ctx,
      stringPrototypeCharAt,
      1);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::endsWith),
      ctx,
      stringPrototypeEndsWith,
      1);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::slice),
      ctx,
      stringPrototypeSlice,
      2);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::split),
      ctx,
      stringPrototypeSplit,
      2);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::includes),
      (void *)false,
      stringPrototypeIncludesOrStartsWith,
      1);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::indexOf),
      ctx,
      stringPrototypeIndexOf,
      1);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::lastIndexOf),
      ctx,
      stringPrototypeLastIndexOf,
      1);
  defineMethod(
      runtime,
      stringPrototype,
      Predefined::getSymbolID(Predefined::startsWith),
      (void *)true,
      stringPrototypeIncludesOrStartsWith,
      1);

  return cons;
}

CallResult<HermesValue>
stringConstructor(void *, Runtime &runtime, NativeArgs args) {
  if (args.getArgCount() == 0) {
    return HermesValue::encodeStringValue(
        runtime.getPredefinedString(Predefined::emptyString));
  }

  if (!args.isConstructorCall() && args.getArg(0).isSymbol()) {
    auto str = symbolDescriptiveString(
        runtime, Handle<SymbolID>::vmcast(args.getArgHandle(0)));
    if (LLVM_UNLIKELY(str == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    return str->getHermesValue();
  }

  auto sRes = toString_RJS(runtime, args.getArgHandle(0));
  if (sRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto s = runtime.makeHandle(std::move(*sRes));

  if (!args.isConstructorCall()) {
                                                            
    return s.getHermesValue();
  }

                                               
  auto self = args.vmcastThis<JSString>();
  JSString::setPrimitiveString(self, runtime, s);

  return self.getHermesValue();
}

CallResult<HermesValue>
stringFromCharCode(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
  uint32_t n = args.getArgCount();
  if (LLVM_LIKELY(n == 1)) {
                                                        
    auto res = toUInt16(runtime, args.getArgHandle(0));
    if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    char16_t ch = res->getNumber();
    return runtime.getCharacterString(ch).getHermesValue();
  }
  auto builder = StringBuilder::createStringBuilder(runtime, SafeUInt32{n});
  if (builder == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  for (unsigned i = 0; i < n; ++i) {
                                                                 
    auto res = toUInt16(runtime, args.getArgHandle(i));
    if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    char16_t ch = res->getNumber();
    builder->appendCharacter(ch);
  }
  return HermesValue::encodeStringValue(*builder->getStringPrimitive());
}

CallResult<HermesValue>
stringFromCodePoint(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};

                                                                        
              
                                                           
  uint32_t length = args.getArgCount();
                                   
  llvh::SmallVector<char16_t, 32> elements{};
                           
  uint32_t nextIndex = 0;

  MutableHandle<> next{runtime};
  MutableHandle<> nextCP{runtime};

  GCScopeMarkerRAII marker{gcScope};
                                       
  for (; nextIndex < length; marker.flush()) {
    marker.flush();
                                             
    next = args.getArg(nextIndex);
                                            
    auto nextCPRes = toNumber_RJS(runtime, next);
    if (LLVM_UNLIKELY(nextCPRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    nextCP = *nextCPRes;

                                                                            
                              
    auto nextCPInt = toIntegerOrInfinity(runtime, nextCP);
    if (LLVM_UNLIKELY(nextCPInt == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (!isSameValue(*nextCP, *nextCPInt)) {
      return runtime.raiseRangeError(
          TwineChar16("Code point must be an integer: ") + nextCP->getNumber());
    }

                                                                            
    if (nextCP->getNumber() < 0 || nextCP->getNumber() > 0x10FFFF) {
      return runtime.raiseRangeError(
          TwineChar16("Code point out of bounds: ") + nextCP->getNumber());
    }

                                                                             
                       
                                                                          
    utf16Encoding(nextCP->getNumberAs<uint32_t>(), elements);

                                          
    ++nextIndex;
  }

                                                                             
                                                                     
  return StringPrimitive::createEfficient(runtime, elements);
}

                                                             
CallResult<HermesValue> stringRaw(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};

                                                                                
                                                      
                                                                
                                                                             
  uint32_t numberOfSubstitutions =
      args.getArgCount() < 2 ? 0 : args.getArgCount() - 1;

                                         
  auto cookedRes = toObject(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(cookedRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto cooked = runtime.makeHandle<JSObject>(*cookedRes);

                                                
  auto getRes = JSObject::getNamed_RJS(
      cooked, runtime, Predefined::getSymbolID(Predefined::raw));
  if (LLVM_UNLIKELY(getRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto rawRes = toObject(runtime, runtime.makeHandle(std::move(*getRes)));
  if (LLVM_UNLIKELY(rawRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto raw = runtime.makeHandle<JSObject>(*rawRes);

                                                           
  auto lengthRes = JSObject::getNamed_RJS(
      raw, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(lengthRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto literalSegmentsRes =
      toLength(runtime, runtime.makeHandle(std::move(*lengthRes)));
  if (LLVM_UNLIKELY(literalSegmentsRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  int64_t literalSegments = literalSegmentsRes->getNumberAs<int64_t>();
                                                        
  if (literalSegments <= 0) {
    return HermesValue::encodeStringValue(
        runtime.getPredefinedString(Predefined::emptyString));
  }

                                          
  llvh::SmallVector<char16_t, 32> stringElements{};

                            
  MutableHandle<> nextIndex{
      runtime, HermesValue::encodeUntrustedNumberValue(0)};

  MutableHandle<> tmpHandle{runtime};
  MutableHandle<StringPrimitive> nextSeg{runtime};
  MutableHandle<> next{runtime};
  MutableHandle<StringPrimitive> nextSub{runtime};

               
  GCScopeMarkerRAII marker{gcScope};
  for (;; marker.flush()) {
                                                 
                                                         
    auto nextSegPropRes = JSObject::getComputed_RJS(raw, runtime, nextIndex);
    if (LLVM_UNLIKELY(nextSegPropRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    tmpHandle = std::move(*nextSegPropRes);
    auto nextSegRes = toString_RJS(runtime, tmpHandle);
    if (LLVM_UNLIKELY(nextSegRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    nextSeg = nextSegRes->get();

                                                                             
                      
    nextSeg->appendUTF16String(stringElements);

                                                      
    if (nextIndex->getNumberAs<int64_t>() + 1 == literalSegments) {
                                                                           
                                                                                
                                      
      return StringPrimitive::createEfficient(runtime, stringElements);
    }

    if (nextIndex->getNumberAs<int64_t>() < numberOfSubstitutions) {
                                                                 
                                  
                                                            
      next = args.getArg(nextIndex->getNumberAs<int64_t>() + 1);
                                              
      auto nextSubRes = toString_RJS(runtime, next);
      if (LLVM_UNLIKELY(nextSubRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      nextSub = nextSubRes->get();
                                                                               
                        
      nextSub->appendUTF16String(stringElements);
    }

                                                 
                                       

                                             
    nextIndex = HermesValue::encodeUntrustedNumberValue(
        nextIndex->getNumberAs<int64_t>() + 1);
  }
}

                                                                                
                     

            
CallResult<HermesValue>
stringPrototypeAt(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
                                                    
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, args.getThisHandle()) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

                             
  auto strRes = toString_RJS(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*strRes));

                                   
  double len = S->getStringLength();

                                                          
  auto idx = args.getArgHandle(0);
  auto relativeIndexRes = toIntegerOrInfinity(runtime, idx);
  if (LLVM_UNLIKELY(relativeIndexRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  const double relativeIndex = relativeIndexRes->getNumber();

  double k;
                                  
  if (relativeIndex >= 0) {
                                 
    k = relativeIndex;
  } else {
               
                                       
    k = len + relativeIndex;
  }

                                              
  if (k < 0 || k >= len) {
    return HermesValue::encodeUndefinedValue();
  }

                                                  
  auto sliceRes = StringPrimitive::slice(runtime, S, k, 1);
  if (LLVM_UNLIKELY(sliceRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return sliceRes;
}

CallResult<HermesValue>
stringPrototypeToString(void *, Runtime &runtime, NativeArgs args) {
  if (args.getThisArg().isString()) {
    return args.getThisArg();
  }

                                                 
  auto *strPtr = dyn_vmcast<JSString>(args.getThisArg());
  if (strPtr) {
                                                           
    return HermesValue::encodeStringValue(
        JSString::getPrimitiveString(strPtr, runtime));
  }
  return runtime.raiseTypeError(
      "String.prototype.toString() called on non-string object");
}

CallResult<HermesValue>
stringPrototypeCharCodeAt(void *, Runtime &runtime, NativeArgs args) {
  Handle<> thisValue{&args.getThisArg()};
                                                               
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, thisValue) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto strRes = toString_RJS(runtime, thisValue);
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*strRes));
  auto intRes =
      toIntegerOrInfinity(runtime, runtime.makeHandle(args.getArg(0)));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto position = intRes->getNumber();
  auto size = S->getStringLength();
  if (position < 0 || position >= size) {
    return HermesValue::encodeNaNValue();
  }
  return HermesValue::encodeTrustedNumberValue(
      StringPrimitive::createStringView(runtime, S)[position]);
}

CallResult<HermesValue>
stringPrototypeCodePointAt(void *, Runtime &runtime, NativeArgs args) {
                                                    
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, args.getThisHandle()) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

                             
  auto strRes = toString_RJS(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*strRes));

                                                 
  auto positionRes = toIntegerOrInfinity(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(positionRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double position = positionRes->getNumber();

                                                
  double size = S->getStringLength();

                                                             
  if (position < 0 || position >= size) {
    return HermesValue::encodeUndefinedValue();
  }

  auto strView = StringPrimitive::createStringView(runtime, S);

                                                                                
              
  char16_t first = strView[position];

                                                                               
  if (first < 0xD800 || first > 0xDBFF || position + 1 == size) {
    return HermesValue::encodeUntrustedNumberValue(first);
  }

                                                                                
                  
                                                                
  char16_t second = strView[position + 1];

                                                             
  if (second < 0xDC00 || second > 0xDFFF) {
    return HermesValue::encodeUntrustedNumberValue(first);
  }

                                           
  return HermesValue::encodeUntrustedNumberValue(utf16Decode(first, second));
}

CallResult<HermesValue>
stringPrototypeConcat(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);

  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, args.getThisHandle()) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto strRes = toString_RJS(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*strRes));
                                              
  SafeUInt32 size(S->getStringLength());
  uint32_t argCount = args.getArgCount();

                                                               
  auto arrRes = ArrayStorageSmall::create(runtime, argCount, argCount);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto strings = runtime.makeHandle<ArrayStorageSmall>(*arrRes);

                                                                
  auto marker = gcScope.createMarker();
  for (uint32_t i = 0; i < argCount; ++i) {
    auto strRes = toString_RJS(runtime, args.getArgHandle(i));
    if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }

                                           
                                                           
    strings->set(
        i,
        SmallHermesValue::encodeStringValue(strRes->get(), runtime),
        runtime.getHeap());
    uint32_t strLength = strRes->get()->getStringLength();

    size.add(strLength);
    if (LLVM_UNLIKELY(size.isOverflowed())) {
      return runtime.raiseRangeError("resulting string length exceeds limit");
    }

    gcScope.flushToMarker(marker);
  }

                                  
  auto builder = StringBuilder::createStringBuilder(runtime, size);
  if (builder == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }

                                
  builder->appendStringPrim(S);
  MutableHandle<StringPrimitive> element{runtime};

                                  
  for (uint32_t i = 0; i < argCount; i++) {
    element = strings->at(i).getString(runtime);
    builder->appendStringPrim(element);
  }
  return builder->getStringPrimitive().getHermesValue();
}

CallResult<HermesValue>
stringPrototypeSubstring(void *, Runtime &runtime, NativeArgs args) {
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, args.getThisHandle()) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto strRes = toString_RJS(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*strRes));
  double len = S->getStringLength();

  auto intRes = toIntegerOrInfinity(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double intStart = intRes->getNumber();

  double intEnd;
  if (args.getArg(1).isUndefined()) {
    intEnd = len;
  } else {
    if (LLVM_UNLIKELY(
            (intRes = toIntegerOrInfinity(runtime, args.getArgHandle(1))) ==
            ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    intEnd = intRes->getNumber();
  }

  size_t finalStart = std::min(std::max(intStart, 0.0), len);
  size_t finalEnd = std::min(std::max(intEnd, 0.0), len);
  size_t from = std::min(finalStart, finalEnd);
  size_t to = std::max(finalStart, finalEnd);

  return StringPrimitive::slice(runtime, S, from, to > from ? to - from : 0);
}

static CallResult<HermesValue> convertCase(
    Runtime &runtime,
    Handle<StringPrimitive> S,
    const bool upperCase,
    const bool useCurrentLocale) {
                                                             
  SmallU16String<32> buff;
                                                                              
                                                        
  S->appendUTF16String(buff);
  UTF16Ref str = buff.arrayRef();

  if (!useCurrentLocale) {
                                         
                                                                          
    char16_t mask = 0;
                                                                          
    bool noop = true;
    if (upperCase) {
      for (const auto c : str) {
        mask |= c;
                                                                      
        noop &= !('a' <= c && c <= 'z');
      }
    } else {
      for (const auto c : str) {
        mask |= c;
                                                                       
        noop &= !('A' <= c && c <= 'Z');
      }
    }
    if (mask <= 127) {
      if (noop) {
                                              
        return S.getHermesValue();
      }

      if (str.size() == 1) {
                                                                              
        char16_t c = str[0];
        if (upperCase) {
          char16_t isLower = 'a' <= c && c <= 'z';
          return runtime.getCharacterString(c & ~(isLower << 5))
              .getHermesValue();
        } else {
          char16_t isUpper = 'A' <= c && c <= 'Z';
          return runtime.getCharacterString(c | (isUpper << 5))
              .getHermesValue();
        }
      }

      SafeUInt32 len(S->getStringLength());
      auto builder = StringBuilder::createStringBuilder(runtime, len);
      if (builder == ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
      char16_t ch;
      if (upperCase) {
        for (const char16_t c : str) {
                                                                     
          char16_t isLower = 'a' <= c && c <= 'z';
          ch = c & ~(isLower << 5);
          builder->appendCharacter(ch);
        }
      } else {
        for (const char16_t c : str) {
                                                                   
          char16_t isUpper = 'A' <= c && c <= 'Z';
          ch = c | (isUpper << 5);
          builder->appendCharacter(ch);
        }
      }
      return HermesValue::encodeStringValue(*builder->getStringPrimitive());
    }
  }
  platform_unicode::convertToCase(
      buff,
      upperCase ? platform_unicode::CaseConversion::ToUpper
                : platform_unicode::CaseConversion::ToLower,
      useCurrentLocale);
  return StringPrimitive::create(runtime, buff);
}

CallResult<HermesValue>
stringPrototypeToLowerCase(void *, Runtime &runtime, NativeArgs args) {
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, args.getThisHandle()) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto res = toString_RJS(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return convertCase(
      runtime, runtime.makeHandle(std::move(*res)), false, false);
}

CallResult<HermesValue>
stringPrototypeToLocaleLowerCase(void *ctx, Runtime &runtime, NativeArgs args) {
#ifdef HERMES_ENABLE_INTL
  return intlStringPrototypeToLocaleLowerCase(             ctx, runtime, args);
#else
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, args.getThisHandle()) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto res = toString_RJS(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return convertCase(runtime, runtime.makeHandle(std::move(*res)), false, true);
#endif
}

CallResult<HermesValue>
stringPrototypeToUpperCase(void *, Runtime &runtime, NativeArgs args) {
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, args.getThisHandle()) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto res = toString_RJS(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return convertCase(runtime, runtime.makeHandle(std::move(*res)), true, false);
}

CallResult<HermesValue>
stringPrototypeToLocaleUpperCase(void *ctx, Runtime &runtime, NativeArgs args) {
#ifdef HERMES_ENABLE_INTL
  return intlStringPrototypeToLocaleUpperCase(             ctx, runtime, args);
#else
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, args.getThisHandle()) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto res = toString_RJS(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return convertCase(runtime, runtime.makeHandle(std::move(*res)), true, true);
#endif
}

CallResult<HermesValue>
stringPrototypeSubstr(void *, Runtime &runtime, NativeArgs args) {
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, args.getThisHandle()) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto strRes = toString_RJS(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*strRes));
  double stringLen = S->getStringLength();

  auto intRes = toIntegerOrInfinity(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double start = intRes->getNumber();

  double length;
  if (args.getArg(1).isUndefined()) {
    length = stringLen;
  } else {
    if (LLVM_UNLIKELY(
            (intRes = toIntegerOrInfinity(runtime, args.getArgHandle(1))) ==
            ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    length = intRes->getNumber();
  }

  if (start < 0) {
    start = std::max(stringLen + start, 0.0);
  }
  double adjustedLength = std::min(std::max(length, 0.0), stringLen - start);
  if (adjustedLength <= 0) {
    return HermesValue::encodeStringValue(
        runtime.getPredefinedString(Predefined::emptyString));
  } else {
    return StringPrimitive::slice(
        runtime,
        S,
        static_cast<size_t>(start),
        static_cast<size_t>(adjustedLength));
  }
}

                                                                     
static size_t trimStart(
    StringView::const_iterator begin,
    StringView::const_iterator end) {
  size_t toTrim = 0;
  while (begin != end &&
         (isWhiteSpaceChar(*begin) || isLineTerminatorChar(*begin))) {
    ++begin;
    ++toTrim;
  }
  return toTrim;
}

                                                                   
static size_t trimEnd(
    StringView::const_iterator begin,
    StringView::const_iterator end) {
  size_t toTrim = 0;
  while (begin != end &&
         (isWhiteSpaceChar(*(end - 1)) || isLineTerminatorChar(*(end - 1)))) {
    --end;
    ++toTrim;
  }
  return toTrim;
}

CallResult<HermesValue>
stringPrototypeTrim(void *, Runtime &runtime, NativeArgs args) {
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, args.getThisHandle()) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto res = toString_RJS(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*res));

                                                                            
  size_t beginIdx = 0, endIdx = S->getStringLength();
  {
    auto str = StringPrimitive::createStringView(runtime, S);
    auto begin = str.begin();
    auto end = str.end();
    beginIdx = trimStart(begin, end);
    begin += beginIdx;
    endIdx -= trimEnd(begin, end);
  }

  return StringPrimitive::slice(runtime, S, beginIdx, endIdx - beginIdx);
}

CallResult<HermesValue>
stringPrototypeTrimStart(void *, Runtime &runtime, NativeArgs args) {
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, args.getThisHandle()) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto res = toString_RJS(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*res));

                                                                            
  size_t beginIdx = 0;
  {
    auto str = StringPrimitive::createStringView(runtime, S);
    auto begin = str.begin();
    auto end = str.end();
    beginIdx = trimStart(begin, end);
  }

  return StringPrimitive::slice(
      runtime, S, beginIdx, S->getStringLength() - beginIdx);
}

CallResult<HermesValue>
stringPrototypeTrimEnd(void *, Runtime &runtime, NativeArgs args) {
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, args.getThisHandle()) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto res = toString_RJS(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*res));

                                                                            
  size_t endIdx = S->getStringLength();
  {
    auto str = StringPrimitive::createStringView(runtime, S);
    auto begin = str.begin();
    auto end = str.end();
    endIdx -= trimEnd(begin, end);
  }

  return StringPrimitive::slice(runtime, S, 0, endIdx);
}

CallResult<HermesValue>
stringPrototypeLocaleCompare(void *ctx, Runtime &runtime, NativeArgs args) {
#ifdef HERMES_ENABLE_INTL
  return intlStringPrototypeLocaleCompare(             ctx, runtime, args);
#else
  auto thisValue = args.getThisHandle();
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, thisValue) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto sRes = toString_RJS(runtime, thisValue);
  if (LLVM_UNLIKELY(sRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*sRes));

  auto tRes = toString_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(tRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
                   
  auto T = runtime.makeHandle(std::move(*tRes));

  llvh::SmallVector<char16_t, 32> left;
  llvh::SmallVector<char16_t, 32> right;

  StringPrimitive::createStringView(runtime, S).appendUTF16String(left);
  StringPrimitive::createStringView(runtime, T).appendUTF16String(right);
  int comparisonResult = platform_unicode::localeCompare(left, right);
  assert(comparisonResult >= -1 && comparisonResult <= 1);
  return HermesValue::encodeUntrustedNumberValue(comparisonResult);
#endif
}

CallResult<HermesValue>
stringPrototypeNormalize(void *, Runtime &runtime, NativeArgs args) {
  using platform_unicode::NormalizationForm;

                                                    
  auto O = args.getThisHandle();
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, O) == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
                             
  auto sRes = toString_RJS(runtime, O);
  if (LLVM_UNLIKELY(sRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*sRes));

  NormalizationForm form;

                                                                        
  if (args.getArg(0).isUndefined()) {
    form = NormalizationForm::C;
  } else {
                                  
    auto fRes = toString_RJS(runtime, args.getArgHandle(0));
    if (LLVM_UNLIKELY(fRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    auto f = runtime.makeHandle(std::move(*fRes));

                                                                                
                 
    auto sv = StringPrimitive::createStringView(runtime, f);
    if (sv.equals(ASCIIRef{"NFC", 3})) {
      form = NormalizationForm::C;
    } else if (sv.equals(ASCIIRef{"NFD", 3})) {
      form = NormalizationForm::D;
    } else if (sv.equals(ASCIIRef{"NFKC", 4})) {
      form = NormalizationForm::KC;
    } else if (sv.equals(ASCIIRef{"NFKD", 4})) {
      form = NormalizationForm::KD;
    } else {
      return runtime.raiseRangeError(
          TwineChar16("Invalid normalization form: ") + *f);
    }
  }

                                                                               
                                                  
                                                      
  llvh::SmallVector<char16_t, 32> ns;
  S->appendUTF16String(ns);
  platform_unicode::normalize(ns, form);

                  
  return StringPrimitive::createEfficient(runtime, ns);
}

CallResult<HermesValue>
stringPrototypeRepeat(void *, Runtime &runtime, NativeArgs args) {
                                                    
  auto O = args.getThisHandle();
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, O) == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
                             
                          
  auto sRes = toString_RJS(runtime, O);
  if (LLVM_UNLIKELY(sRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*sRes));

                                            
                          
  auto nRes = toIntegerOrInfinity(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(nRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double n = nRes->getNumber();

                                               
                                                        
  if (n < 0 || n == std::numeric_limits<double>::infinity()) {
    return runtime.raiseRangeError(
        "String.prototype.repeat count must be finite and non-negative");
  }

                                                                        
                                                
  double strLen = S->getStringLength();

  if (n == 0 || strLen == 0) {
    return HermesValue::encodeStringValue(
        runtime.getPredefinedString(Predefined::emptyString));
  }

  if (n > std::numeric_limits<uint32_t>::max() ||
      S->getStringLength() > (double)StringPrimitive::MAX_STRING_LENGTH / n) {
                          
    return runtime.raiseRangeError(
        "String.prototype.repeat result exceeds limit");
  }

                                                               
  SafeUInt32 finalLen(strLen * n);

  auto builderRes = StringBuilder::createStringBuilder(runtime, finalLen);
  if (LLVM_UNLIKELY(builderRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

                                                                    
  for (uint32_t i = 0; i < n; ++i) {
    builderRes->appendStringPrim(S);
  }

                 
  return builderRes->getStringPrimitive().getHermesValue();
}

                                                      
CallResult<HermesValue>
stringPrototypeSymbolIterator(void *, Runtime &runtime, NativeArgs args) {
                                                    
  auto thisValue = args.getThisHandle();
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, thisValue) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
                             
                          
  auto strRes = toString_RJS(runtime, thisValue);
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto string = runtime.makeHandle(std::move(*strRes));

                                       
  return JSStringIterator::create(runtime, string).getHermesValue();
}

CallResult<HermesValue>
stringPrototypeMatchAll(void *, Runtime &runtime, NativeArgs args) {
                                                      
  auto O = args.getThisHandle();
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, O) == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

                                                     
  auto regexp = args.getArgHandle(0);
  if (!regexp->isUndefined() && !regexp->isNull()) {
                                             
    auto isRegExpRes = isRegExp(runtime, regexp);
    if (LLVM_UNLIKELY(isRegExpRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
                                   
    if (*isRegExpRes) {
                                                                              
      Handle<JSObject> regexpObj = Handle<JSObject>::vmcast(regexp);
      bool isGlobal = false;
                                                
      auto flagsPropRes = JSObject::getNamed_RJS(
          regexpObj, runtime, Predefined::getSymbolID(Predefined::flags));
      if (LLVM_UNLIKELY(flagsPropRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      auto flags = runtime.makeHandle(std::move(*flagsPropRes));
                                                     
      if (LLVM_UNLIKELY(
              checkObjectCoercible(runtime, flags) ==
              ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
                                                                          
                   
      auto strRes = toString_RJS(runtime, flags);
      if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      auto strView = StringPrimitive::createStringView(
          runtime, runtime.makeHandle(std::move(*strRes)));
      for (char16_t c : strView)
        if (c == u'g')
          isGlobal = true;
      if (!isGlobal)
        return runtime.raiseTypeError(
            "String.prototype.matchAll called with a non-global RegExp argument");
    }
                                                         
    auto matcherRes = getMethod(
        runtime,
        regexp,
        runtime.makeHandle(
            Predefined::getSymbolID(Predefined::SymbolMatchAll)));
    if (LLVM_UNLIKELY(matcherRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
                                           
    if (!matcherRes->getHermesValue().isUndefined()) {
      auto matcher = runtime.makeHandle<Callable>(std::move(*matcherRes));
                                                
      return Callable::executeCall1(
                 matcher, runtime, regexp, O.getHermesValue())
          .toCallResultHermesValue();
    }
  }

                               
  auto strRes = toString_RJS(runtime, O);
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*strRes));

                                              
  auto regRes = regExpCreate(runtime, regexp, runtime.getCharacterString('g'));
  if (regRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<JSRegExp> rx = regRes.getValue();

                                             
  auto propRes = JSObject::getNamed_RJS(
      rx, runtime, Predefined::getSymbolID(Predefined::SymbolMatchAll));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto func =
      Handle<Callable>::dyn_vmcast(runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(!func)) {
    return runtime.raiseTypeError(
        "RegExp.prototype[@@matchAll] must be callable.");
  }
  return Callable::executeCall1(func, runtime, rx, S.getHermesValue())
      .toCallResultHermesValue();
}

                                                                        
                                                                               
                              
                                                                     
                             
                                                                         
                        
   
                                                                              
                                                                           
                                                                          
                            
   
                                                             
                                                                      
                                                         
                                                                    
                                                                                
                                                                     
                                                                          
                                                                                
                                                                          
                                                                             
                                                                          
static CallResult<HermesValue> stringDirectedIndexOf(
    Runtime &runtime,
    Handle<> string,
    Handle<> searchString,
    Handle<> position,
    bool reverse,
    bool clampPosition = true) {
                                                      
                                                               
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, string) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
                               
  auto strRes = toString_RJS(runtime, string);
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*strRes));

                                                  
  auto searchStrRes = toString_RJS(runtime, searchString);
  if (searchStrRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto searchStr = runtime.makeHandle(std::move(*searchStrRes));

  double pos;
  if (reverse) {
                  
                                             
    auto intRes = toNumber_RJS(runtime, position);
    if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    Handle<> numPos = runtime.makeHandle(intRes.getValue());
                                                                  
                                   
    if (std::isnan(numPos->getNumber())) {
      pos = std::numeric_limits<double>::infinity();
    } else {
      if (LLVM_UNLIKELY(
              (intRes = toIntegerOrInfinity(runtime, numPos)) ==
              ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      pos = intRes->getNumber();
    }
  } else {
              
                                                     
    auto intRes = toIntegerOrInfinity(runtime, position);
    if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    pos = intRes->getNumber();
  }

                                
  double len = S->getStringLength();

                                                                                
                                                                               
                                                                
                                                                       
                                                                          
                                                                          
                                                                 
  if (!clampPosition && pos > len) {
    return HermesValue::encodeUntrustedNumberValue(-1);
  }

                                        
  uint32_t start = static_cast<uint32_t>(std::min(std::max(pos, 0.), len));

                                                                    
                                                        
  auto SView = StringPrimitive::createStringView(runtime, S);
  auto searchStrView = StringPrimitive::createStringView(runtime, searchStr);
  double ret = -1;
  if (reverse) {
                  
    uint32_t lastPossibleMatchEnd =
        std::min(SView.length(), start + searchStrView.length());
    auto foundIter = std::search(
        SView.rbegin() + (SView.length() - lastPossibleMatchEnd),
        SView.rend(),
        searchStrView.rbegin(),
        searchStrView.rend());
    if (foundIter != SView.rend() || searchStrView.empty()) {
      ret = SView.rend() - foundIter - searchStrView.length();
    }
  } else {
              
    auto foundIter = std::search(
        SView.begin() + start,
        SView.end(),
        searchStrView.begin(),
        searchStrView.end());
    if (foundIter != SView.end() || searchStrView.empty()) {
      ret = foundIter - SView.begin();
    }
  }
  return HermesValue::encodeUntrustedNumberValue(ret);
}

                                                                        
               
                                                                        
                                                                                
                                                    
static CallResult<HermesValue> stringIndexOf(
    Runtime &runtime,
    Handle<StringPrimitive> string,
    Handle<StringPrimitive> searchValue,
    uint32_t fromIndex) {
                                       
                                            
                                                          
  return stringDirectedIndexOf(
      runtime,
      string,
      searchValue,
      runtime.makeHandle(HermesValue::encodeUntrustedNumberValue(fromIndex)),
      false,
      false);
}

                                                                            
CallResult<HermesValue>
stringPrototypeReplaceAll(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};

                                                      
  auto O = args.getThisHandle();
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, O) == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  auto searchValue = args.getArgHandle(0);
  auto replaceValue = args.getArgHandle(1);
                                                          
  if (!searchValue->isUndefined() && !searchValue->isNull()) {
                                                  
    auto isRegExpRes = isRegExp(runtime, searchValue);
    if (LLVM_UNLIKELY(isRegExpRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
                                   
    if (*isRegExpRes) {
      Handle<JSObject> regexpObj = Handle<JSObject>::vmcast(searchValue);
                                                     
      auto flagsPropRes = JSObject::getNamed_RJS(
          regexpObj, runtime, Predefined::getSymbolID(Predefined::flags));
      if (LLVM_UNLIKELY(flagsPropRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      auto flags = runtime.makeHandle(std::move(*flagsPropRes));
                                                     
      if (LLVM_UNLIKELY(
              checkObjectCoercible(runtime, flags) ==
              ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
                                                                          
                   
      auto strRes = toString_RJS(runtime, flags);
      if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      auto strView = StringPrimitive::createStringView(
          runtime, runtime.makeHandle(std::move(*strRes)));
      bool isGlobal = false;
      for (char16_t c : strView)
        if (c == u'g')
          isGlobal = true;
      if (!isGlobal)
        return runtime.raiseTypeError(
            "String.prototype.replaceAll called with a non-global RegExp argument");
    }
                                                              
    auto replacerRes = getMethod(
        runtime,
        searchValue,
        runtime.makeHandle(Predefined::getSymbolID(Predefined::SymbolReplace)));
    if (LLVM_UNLIKELY(replacerRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
                                            
    if (!replacerRes->getHermesValue().isUndefined()) {
      auto replacer = runtime.makeHandle<Callable>(std::move(*replacerRes));
                                                                     
      return Callable::executeCall2(
                 replacer,
                 runtime,
                 searchValue,
                 O.getHermesValue(),
                 replaceValue.getHermesValue())
          .toCallResultHermesValue();
    }
  }

                                    
  auto strRes = toString_RJS(runtime, O);
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto string = runtime.makeHandle(std::move(*strRes));

                                                    
  auto searchStrRes = toString_RJS(runtime, searchValue);
  if (LLVM_UNLIKELY(searchStrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto searchString = runtime.makeHandle(std::move(*searchStrRes));

                                                          
  auto replaceFn = Handle<Callable>::dyn_vmcast(replaceValue);
  bool functionalReplace = !!replaceFn;

                                                               
  MutableHandle<StringPrimitive> replaceValueStr{runtime};
                                           
  if (!functionalReplace) {
                                                       
    auto replaceValueStrRes = toString_RJS(runtime, replaceValue);
    if (LLVM_UNLIKELY(replaceValueStrRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    replaceValueStr = std::move(*replaceValueStrRes);
  }

                                                       
  uint32_t searchLength = searchString->getStringLength();
                                              
  uint32_t advanceBy = std::max(1u, searchLength);

                                               
  llvh::SmallVector<int32_t, 8> matchPositions{};

                                                                  
  auto positionRes = stringIndexOf(runtime, string, searchString, 0);
  int32_t position = positionRes->getNumberAs<int32_t>();

                                          
  while (position != -1) {
    GCScopeMarkerRAII marker{runtime};
                                                       
    matchPositions.push_back(position);
                                                                          
                  
    positionRes =
        stringIndexOf(runtime, string, searchString, position + advanceBy);
    assert(
        positionRes == ExecutionStatus::RETURNED &&
        "StringIndexOf cannot fail");
    position = positionRes->getNumberAs<int32_t>();
  }

                                 
  uint32_t endOfLastMatch = 0;
                                              
  SmallU16String<32> result{};

                                                
  auto stringView = StringPrimitive::createStringView(runtime, string);
  MutableHandle<StringPrimitive> replacement{runtime};
  MutableHandle<> replacementCallRes{runtime};
  for (uint32_t i = 0, size = matchPositions.size(); i < size; ++i) {
    GCScopeMarkerRAII marker{runtime};
    uint32_t position = matchPositions[i];
                                                                         
                
                                                                     
    auto preserved =
        stringView.slice(endOfLastMatch, position - endOfLastMatch);
                                            
    if (functionalReplace) {
                                           
                                                                              
      auto callRes = Callable::executeCall3(
                         replaceFn,
                         runtime,
                         Runtime::getUndefinedValue(),
                         searchString.getHermesValue(),
                         HermesValue::encodeUntrustedNumberValue(position),
                         string.getHermesValue())
                         .toCallResultHermesValue();
      if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      replacementCallRes = *callRes;
      auto replacementStrRes = toString_RJS(runtime, replacementCallRes);
      if (LLVM_UNLIKELY(replacementStrRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      replacement = std::move(*replacementStrRes);
    } else {
                 
                                                 
                                              
      auto captures = Runtime::makeNullHandle<ArrayStorageSmall>();
      auto namedCaptures = Runtime::makeNullHandle<JSObject>();
                                                                        
                                                      
      auto callRes = getSubstitution(
          runtime,
          searchString,
          string,
          (double)position,
          captures,
          namedCaptures,
          replaceValueStr);
      if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      replacement = vmcast<StringPrimitive>(*callRes);
    }

                                                                          
                   
    preserved.appendUTF16String(result);
    StringPrimitive::createStringView(runtime, replacement)
        .appendUTF16String(result);
                                                        
    endOfLastMatch = position + searchLength;
  }

                                                       
  if (endOfLastMatch < string->getStringLength()) {
                                                                               
                                  
    stringView.slice(endOfLastMatch).appendUTF16String(result);
  }
                       
  return StringPrimitive::create(runtime, result);
}

CallResult<HermesValue>
stringPrototypeMatch(void *, Runtime &runtime, NativeArgs args) {
                                                    
                          
  auto O = args.getThisHandle();
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, O) == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
                                                     
  auto regexp = args.getArgHandle(0);
  if (!regexp->isUndefined() && !regexp->isNull()) {
                                                    
    auto methodRes = getMethod(
        runtime,
        regexp,
        runtime.makeHandle(Predefined::getSymbolID(Predefined::SymbolMatch)));
                                  
    if (LLVM_UNLIKELY(methodRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
                                           
                                               
    if (!methodRes->getHermesValue().isUndefined()) {
      auto matcher = runtime.makeHandle<Callable>(std::move(*methodRes));
      return Callable::executeCall1(
                 matcher, runtime, regexp, O.getHermesValue())
          .toCallResultHermesValue();
    }
  }
                             
  auto strRes = toString_RJS(runtime, O);
                          
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*strRes));

                                                                   
                           
  auto regRes = regExpCreate(runtime, regexp, Runtime::getUndefinedValue());
  if (regRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<JSRegExp> rx = regRes.getValue();

                                         
  auto propRes = JSObject::getNamed_RJS(
      rx, runtime, Predefined::getSymbolID(Predefined::SymbolMatch));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto func =
      Handle<Callable>::dyn_vmcast(runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(!func)) {
    return runtime.raiseTypeError(
        "RegExp.prototype[@@match] must be callable.");
  }
  return Callable::executeCall1(func, runtime, rx, S.getHermesValue())
      .toCallResultHermesValue();
}

CallResult<HermesValue>
stringPrototypePad(void *ctx, Runtime &runtime, NativeArgs args) {
  bool padStart = (bool)ctx;

                                                      
  auto O = args.getThisHandle();
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, O) == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

                               
  auto sRes = toString_RJS(runtime, O);
  if (LLVM_UNLIKELY(sRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*sRes));

                                                  
  auto intMaxLengthRes = toLength(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(intMaxLengthRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  const uint64_t intMaxLength = intMaxLengthRes->getNumberAs<int64_t>();

                                                        
  const uint32_t stringLength = S->getStringLength();
  SafeUInt32 size{stringLength};

                                                                   
  if (intMaxLength <= stringLength) {
    return S.getHermesValue();
  }

  MutableHandle<StringPrimitive> filler{runtime};

  if (args.getArg(1).isUndefined()) {
                                                                              
                                       
    filler = runtime.getPredefinedString(Predefined::space);
  } else {
                                                     
    auto fillerRes = toString_RJS(runtime, args.getArgHandle(1));
    if (LLVM_UNLIKELY(fillerRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    filler = fillerRes->get();
  }

                                                
  if (filler->getStringLength() == 0) {
    return S.getHermesValue();
  }

                                                   
  const uint64_t fillLen = intMaxLength - stringLength;

                                                                                
                                                  
  if (fillLen > StringPrimitive::MAX_STRING_LENGTH) {
    return runtime.raiseRangeError("String pad result exceeds limit");
  }

  size.add((uint32_t)fillLen);

  if (size.isZero()) {
    return HermesValue::encodeStringValue(
        runtime.getPredefinedString(Predefined::emptyString));
  }

  auto builderRes = StringBuilder::createStringBuilder(runtime, size);
  if (LLVM_UNLIKELY(builderRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  uint32_t resultLen = size.get();

                                                                         
                
  auto addFiller = [&filler, resultLen, stringLength](StringBuilder &builder) {
    uint32_t remaining = resultLen - stringLength;
    const uint32_t fillerLen = filler->getStringLength();
    while (remaining != 0) {
      uint32_t length = std::min(remaining, fillerLen);
      builder.appendStringPrim(filler, length);
      remaining -= length;
    }
  };

  if (padStart) {
                                                                        
                                                                     
                                                                     
                                   
    addFiller(*builderRes);
    builderRes->appendStringPrim(S);
  } else {
                                                                        
                                                                     
                                                                           
                             
    builderRes->appendStringPrim(S);
    addFiller(*builderRes);
  }

  return builderRes->getStringPrimitive().getHermesValue();
}

CallResult<HermesValue>
stringPrototypeReplace(void *, Runtime &runtime, NativeArgs args) {
                                                    
                          
  auto O = args.getThisHandle();
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, O) == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
                                                          
  auto searchValue = args.getArgHandle(0);
  auto replaceValue = args.getArgHandle(1);
  if (!searchValue->isUndefined() && !searchValue->isNull()) {
                                                            
    auto methodRes = getMethod(
        runtime,
        searchValue,
        runtime.makeHandle(Predefined::getSymbolID(Predefined::SymbolReplace)));
                                   
    if (LLVM_UNLIKELY(methodRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
                                            
                                                                   
    if (!methodRes->getHermesValue().isUndefined()) {
                                                                             
      Handle<Callable> replacer =
          Handle<Callable>::vmcast(runtime, methodRes->getHermesValue());
      return Callable::executeCall2(
                 replacer,
                 runtime,
                 searchValue,
                 O.getHermesValue(),
                 replaceValue.getHermesValue())
          .toCallResultHermesValue();
    }
  }
                                  
                               
  auto stringRes = toString_RJS(runtime, O);
  if (LLVM_UNLIKELY(stringRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto string = runtime.makeHandle(std::move(*stringRes));
                                                  
  auto searchStringRes = toString_RJS(runtime, searchValue);
                                     
  if (LLVM_UNLIKELY(searchStringRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto searchString = runtime.makeHandle(std::move(*searchStringRes));
                                                          
  auto replaceFn = Handle<Callable>::dyn_vmcast(replaceValue);
  MutableHandle<StringPrimitive> replaceValueStr{runtime};
  bool functionalReplace = !!replaceFn;
                                           
  if (!functionalReplace) {
                                                     
                                       
    auto replaceValueStrRes = toString_RJS(runtime, replaceValue);
    if (LLVM_UNLIKELY(replaceValueStrRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    replaceValueStr = std::move(*replaceValueStrRes);
  }
                                                                              
                                                                                
                                                                               
                   
                                                                         
  uint32_t pos = 0;
  auto strView = StringPrimitive::createStringView(runtime, string);
  if (!strView.empty()) {
    auto searchView = StringPrimitive::createStringView(runtime, searchString);
    auto searchResult = std::search(
        strView.begin(), strView.end(), searchView.begin(), searchView.end());

    if (searchResult != strView.end()) {
      pos = searchResult - strView.begin();
    } else {
      return string.getHermesValue();
    }
  } else if (searchString->getStringLength() != 0) {
                                                                     
    return string.getHermesValue();
  }
  MutableHandle<StringPrimitive> replStr{runtime};
                                           
  if (functionalReplace) {
                                                                           
                
    auto callRes = Callable::executeCall3(
        replaceFn,
        runtime,
        Runtime::getUndefinedValue(),
        searchString.getHermesValue(),
        HermesValue::encodeUntrustedNumberValue(pos),
        string.getHermesValue());
    if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
                                             
    auto replStrRes =
        toString_RJS(runtime, runtime.makeHandle(std::move(*callRes)));
                                  
    if (LLVM_UNLIKELY(replStrRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    replStr = replStrRes->get();
  } else {
                
                                        
    auto nullHandle = Runtime::makeNullHandle<ArrayStorageSmall>();
    auto namedCaptures = Runtime::makeNullHandle<JSObject>();
                                                                        
                     
    auto callRes = getSubstitution(
        runtime,
        searchString,
        string,
        pos,
        nullHandle,
        namedCaptures,
        replaceValueStr);
    if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    replStr = vmcast<StringPrimitive>(callRes.getValue());
  }
                                                                  
  uint32_t tailPos = pos + searchString->getStringLength();
                                                                               
                                                                               
                                                                               
                      
  SmallU16String<32> newString{};
  strView.slice(0, pos).appendUTF16String(newString);
  StringPrimitive::createStringView(runtime, replStr)
      .appendUTF16String(newString);
  strView.slice(tailPos).appendUTF16String(newString);
                          
  return StringPrimitive::create(runtime, newString);
}

CallResult<HermesValue>
stringPrototypeSearch(void *, Runtime &runtime, NativeArgs args) {
                                                    
                          
  auto O = args.getThisHandle();
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, O) == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
                                                     
  auto regexp = args.getArgHandle(0);
  if (!regexp->isUndefined() && !regexp->isNull()) {
                                                      
    auto methodRes = getMethod(
        runtime,
        regexp,
        runtime.makeHandle(Predefined::getSymbolID(Predefined::SymbolSearch)));
                                   
    if (LLVM_UNLIKELY(methodRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
                                            
                                                
    if (!methodRes->getHermesValue().isUndefined()) {
                                                                             
      Handle<Callable> searcher =
          Handle<Callable>::vmcast(runtime, methodRes->getHermesValue());
      return Callable::executeCall1(
                 searcher, runtime, regexp, O.getHermesValue())
          .toCallResultHermesValue();
    }
  }
                                  
                               
  auto strRes = toString_RJS(runtime, O);
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto string = runtime.makeHandle(std::move(*strRes));

                                                                   
                           
  auto regRes = regExpCreate(runtime, regexp, Runtime::getUndefinedValue());
  if (regRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<JSRegExp> rx = *regRes;

                                              
  auto propRes = JSObject::getNamed_RJS(
      rx, runtime, Predefined::getSymbolID(Predefined::SymbolSearch));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if (LLVM_UNLIKELY(!vmisa<Callable>(propRes->get()))) {
    return runtime.raiseTypeError(
        "RegExp.prototype[@@search] must be callable.");
  }
  auto func = Handle<Callable>::vmcast(runtime.makeHandle(std::move(*propRes)));
  return Callable::executeCall1(func, runtime, rx, string.getHermesValue())
      .toCallResultHermesValue();
}

CallResult<HermesValue>
stringPrototypeCharAt(void *, Runtime &runtime, NativeArgs args) {
  Handle<> thisValue{&args.getThisArg()};
                                                               
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, thisValue) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto strRes = toString_RJS(runtime, thisValue);
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*strRes));

  auto intRes =
      toIntegerOrInfinity(runtime, runtime.makeHandle(args.getArg(0)));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto position = intRes->getNumber();
  auto size = S->getStringLength();
  if (position < 0 || position >= size) {
    return HermesValue::encodeStringValue(
        runtime.getPredefinedString(Predefined::emptyString));
  }
  auto result = runtime.getCharacterString(
      StringPrimitive::createStringView(runtime, S)[position]);
  return HermesValue::encodeStringValue(result.get());
}

CallResult<HermesValue>
stringPrototypeSlice(void *, Runtime &runtime, NativeArgs args) {
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, args.getThisHandle()) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto strRes = toString_RJS(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*strRes));
  double len = S->getStringLength();

  auto intRes = toIntegerOrInfinity(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double intStart = intRes->getNumber();

  double intEnd;
  if (args.getArg(1).isUndefined()) {
    intEnd = len;
  } else {
    if (LLVM_UNLIKELY(
            (intRes = toIntegerOrInfinity(runtime, args.getArgHandle(1))) ==
            ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    intEnd = intRes->getNumber();
  }

  size_t from =
      intStart < 0 ? std::max(len + intStart, 0.0) : std::min(intStart, len);
  size_t to = intEnd < 0 ? std::max(len + intEnd, 0.0) : std::min(intEnd, len);
  size_t span = to > from ? to - from : 0;
  assert(from + span <= len && "invalid index computed in slice");

  return StringPrimitive::slice(runtime, S, from, span);
}

CallResult<HermesValue>
stringPrototypeEndsWith(void *, Runtime &runtime, NativeArgs args) {
                                                    
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, args.getThisHandle()) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

                             
  auto strRes = toString_RJS(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*strRes));

                                               
  auto isRegExpRes = isRegExp(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(isRegExpRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

                                                         
  if (LLVM_UNLIKELY(*isRegExpRes)) {
    return runtime.raiseTypeError(
        "First argument to endsWith must not be a RegExp");
  }

                                                
  auto searchStrRes = toString_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(searchStrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto searchStr = runtime.makeHandle(std::move(*searchStrRes));

                                               
  double len = S->getStringLength();

                                                                     
                                      
  double pos;
  if (args.getArg(1).isUndefined()) {
    pos = len;
  } else {
    auto posRes = toIntegerOrInfinity(runtime, args.getArgHandle(1));
    if (LLVM_UNLIKELY(posRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    pos = posRes->getNumberAs<double>();
  }

                                          
  double end = std::min(std::max(pos, 0.0), len);

                                                                 
  double searchLength = searchStr->getStringLength();

                                         
  double start = end - searchLength;

                                               
  if (start < 0) {
    return HermesValue::encodeBoolValue(false);
  }
                                                                     
                                                                               
          
                                 
  return HermesValue::encodeBoolValue(
      S->sliceEquals(start, searchLength, *searchStr));
}

                    
                                                                         
                                                                           
                                                            
                                                                      
                      
                                                                          
static OptValue<uint32_t> splitMatch(
    Runtime &runtime,
    Handle<StringPrimitive> S,
    uint32_t q,
    Handle<StringPrimitive> R) {
                                               
  auto r = R->getStringLength();
                                               
  auto s = S->getStringLength();
                                 
  if (q + r > s) {
    return llvh::None;
  }

                                                                              
                                                                              
                  
  if (q == s) {
    return q;
  }

  auto SStr = StringPrimitive::createStringView(runtime, S);
  auto RStr = StringPrimitive::createStringView(runtime, R);

  auto sliced = SStr.slice(q);
  auto searchResult =
      std::search(sliced.begin(), sliced.end(), RStr.begin(), RStr.end());

  if (searchResult != sliced.end()) {
    return q + (searchResult - sliced.begin()) + r;
  }
  return llvh::None;
}

                                                             
CallResult<HermesValue>
stringPrototypeSplit(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};

                                                      
  auto O = args.getThisHandle();
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, O) == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
                                                        
  auto separator = args.getArgHandle(0);
  if (!separator->isUndefined() && !separator->isNull()) {
                                                          
    auto methodRes = getMethod(
        runtime,
        separator,
        runtime.makeHandle(Predefined::getSymbolID(Predefined::SymbolSplit)));
    if (LLVM_UNLIKELY(methodRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
                                            
                                                          
    if (!methodRes->getHermesValue().isUndefined()) {
      Handle<Callable> splitter =
          Handle<Callable>::vmcast(runtime, methodRes->getHermesValue());
      return Callable::executeCall2(
                 splitter,
                 runtime,
                 separator,
                 O.getHermesValue(),
                 args.getArg(1))
          .toCallResultHermesValue();
    }
  }

                               
  auto strRes = toString_RJS(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*strRes));

                                  
  auto arrRes = JSArray::create(runtime, 0, 0);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto A = *arrRes;
                         
  uint32_t lengthA = 0;

                                                                    
                     
  auto limit = args.getArgHandle(1);
  uint32_t lim;
  if (limit->isUndefined()) {
                                      
    lim = 0xffffffff;              
  } else {
    auto intRes = toUInt32_RJS(runtime, limit);
    if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    lim = intRes->getNumber();
  }

                                 
  uint32_t s = S->getStringLength();
                   
                           
  uint32_t p = 0;

                                       
                                              
  auto sepRes = toString_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(sepRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<StringPrimitive> R = runtime.makeHandle(std::move(sepRes.getValue()));

                              
  if (lim == 0) {
                                              
    return A.getHermesValue();
  }

                                        
  if (LLVM_UNLIKELY(separator->isUndefined())) {
                                                         
    (void)JSArray::setElementAt(A, runtime, 0, S);
    if (LLVM_UNLIKELY(
            JSArray::setLengthProperty(A, runtime, 1) ==
            ExecutionStatus::EXCEPTION))
      return ExecutionStatus::EXCEPTION;
                   
    return A.getHermesValue();
  }

                       
  if (s == 0) {
                             
                                       
    auto matchResult = splitMatch(runtime, S, 0, R);
                                      
    if (matchResult) {
      return A.getHermesValue();
    }
                                                         
    (void)JSArray::setElementAt(A, runtime, 0, S);
    if (LLVM_UNLIKELY(
            JSArray::setLengthProperty(A, runtime, 1) ==
            ExecutionStatus::EXCEPTION))
      return ExecutionStatus::EXCEPTION;
                   
    return A.getHermesValue();
  }

                    
                                                  
  uint32_t q = p;

  MutableHandle<> tmpHandle{runtime};
  auto marker = gcScope.createMarker();

                            
                                                                   
  while (q != s) {
    gcScope.flushToMarker(marker);

                                       
                                     

                                                     
                                                                          
                                                                                
                                             
    auto matchResult = splitMatch(runtime, S, q, R);
                                                                         
    if (matchResult) {
      q = *matchResult - R->getStringLength();
    }
    if (!matchResult || q >= s) {
                                                                               
                                                                  
                                                                                
                                                                               
                    
      break;
    }
               
                                                                                
             
    uint32_t e = *matchResult;
                                   
    if (e == p) {
                                                                        
                                             
                                                                        
                                                                               
      q++;
    }
                
    else {
                                        
                                                                    
                                                                         
                                                         

                                                                               
                                                                       
      auto strRes = StringPrimitive::slice(runtime, S, p, q - p);
      if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      tmpHandle = *strRes;
                                                                          
      JSArray::setElementAt(A, runtime, lengthA, tmpHandle);
                                       
      ++lengthA;

                                       
      if (lengthA == lim) {
                                           
        if (LLVM_UNLIKELY(
                JSArray::setLengthProperty(A, runtime, lengthA) ==
                ExecutionStatus::EXCEPTION))
          return ExecutionStatus::EXCEPTION;
        return A.getHermesValue();
      }
                       
                                                                    
                                                                           
      p = e;
                       
                                                                               
      q = p;
    }
  }

                                                                                
                                                               
                                                            
  auto elementStrRes = StringPrimitive::slice(runtime, S, p, s - p);
  if (LLVM_UNLIKELY(elementStrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  tmpHandle = *elementStrRes;
                                                                        
  JSArray::setElementAt(A, runtime, lengthA, tmpHandle);
  ++lengthA;

  if (LLVM_UNLIKELY(
          JSArray::setLengthProperty(A, runtime, lengthA) ==
          ExecutionStatus::EXCEPTION))
    return ExecutionStatus::EXCEPTION;

                  
  return A.getHermesValue();
}

CallResult<HermesValue> stringPrototypeIncludesOrStartsWith(
    void *ctx,
    Runtime &runtime,
    NativeArgs args) {
                                               
                                                
  bool startsWith = static_cast<bool>(ctx);

                                                    
  if (LLVM_UNLIKELY(
          checkObjectCoercible(runtime, args.getThisHandle()) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

                             
  auto strRes = toString_RJS(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*strRes));

                                               
                                                         
  auto isRegExpRes = isRegExp(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(isRegExpRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  if (LLVM_UNLIKELY(*isRegExpRes)) {
    return runtime.raiseTypeError(
        "First argument to startsWith and includes must not be a RegExp");
  }

                                                
  auto searchStrRes = toString_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(searchStrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto searchStr = runtime.makeHandle(std::move(*searchStrRes));

                                                 
                                                                
  auto posRes = toIntegerOrInfinity(runtime, args.getArgHandle(1));
  if (LLVM_UNLIKELY(posRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double pos = posRes->getNumber();

                                                
  double len = S->getStringLength();

                                            
  double start = std::min(std::max(pos, 0.0), len);

                                                                 
  double searchLength = searchStr->getStringLength();

  if (startsWith) {
                                                            
                                                                   
    if (searchLength + start > len) {
      return HermesValue::encodeBoolValue(false);
    }
                                                                       
                                                                          
                   
                                   
    return HermesValue::encodeBoolValue(
        S->sliceEquals(start, searchLength, *searchStr));
  }

                                                                           
                                                                               
                                                                            
                                                                               
                     
  auto SView = StringPrimitive::createStringView(runtime, S);
  auto searchStrView = StringPrimitive::createStringView(runtime, searchStr);
  auto foundIter = std::search(
      SView.begin() + start,
      SView.end(),
      searchStrView.begin(),
      searchStrView.end());
                                                                            
                                             
  return HermesValue::encodeBoolValue(
      foundIter != SView.end() || searchStrView.empty());
}

CallResult<HermesValue>
stringPrototypeIndexOf(void *, Runtime &runtime, NativeArgs args) {
  auto searchString = args.getArgHandle(0);
  auto position = args.getArgHandle(1);
  return stringDirectedIndexOf(
      runtime, args.getThisHandle(), searchString, position, false);
}

CallResult<HermesValue>
stringPrototypeLastIndexOf(void *, Runtime &runtime, NativeArgs args) {
  auto searchString = args.getArgHandle(0);
  auto position = args.getArgHandle(1);
  return stringDirectedIndexOf(
      runtime, args.getThisHandle(), searchString, position, true);
}

}                
}                    

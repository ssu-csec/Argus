/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                                                     
                                                                                

#include "JSLibInternal.h"

#include "hermes/VM/JSObject.h"
#include "hermes/VM/JSRegExpStringIterator.h"
#include "hermes/VM/Operations.h"
#include "hermes/VM/SmallXString.h"
#include "hermes/VM/StringPrimitive.h"
#include "hermes/VM/StringView.h"
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

                    
      

                                                           
static CallResult<HermesValue> regExpAlloc(
    Runtime &runtime,
    PseudoHandle<>                );

                                                                          
static CallResult<Handle<JSRegExp>> regExpInitialize(
    Runtime &runtime,
    Handle<> obj,
    Handle<> pattern,
    Handle<> flags);

                    
static CallResult<HermesValue> regExpBuiltinExec(
    Runtime &runtime,
    Handle<JSRegExp> R,
    Handle<StringPrimitive> S);

      

                                                                               
                                                                            
static inline bool thisIsRegExpProto(Runtime &runtime, NativeArgs args) {
  return args.dyncastThis<JSObject>().get() ==
      vmcast<JSObject>(runtime.regExpPrototype);
}

Handle<JSObject> createRegExpConstructor(Runtime &runtime) {
  auto proto = Handle<JSObject>::vmcast(&runtime.regExpPrototype);

  auto cons = defineSystemConstructor<JSRegExp>(
      runtime,
      Predefined::getSymbolID(Predefined::RegExp),
      regExpConstructor,
      proto,
      2,
      CellKind::JSRegExpKind);

  defineMethod(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::exec),
      nullptr,
      regExpPrototypeExec,
      1);

  defineMethod(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::test),
      nullptr,
      regExpPrototypeTest,
      1);

  DefinePropertyFlags dpf = DefinePropertyFlags::getNewNonEnumerableFlags();

  (void)defineMethod(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::SymbolMatchAll),
      Predefined::getSymbolID(Predefined::squareSymbolMatchAll),
      nullptr,
      regExpPrototypeSymbolMatchAll,
      1,
      dpf);

                                                                               
                                                                         
                                        
  auto defineGetter = [&](Handle<JSObject> obj,
                          Predefined::Str sym,
                          NativeFunctionPtr getter,
                          intptr_t ctx = 0) {
    defineAccessor(
        runtime,
        obj,
        Predefined::getSymbolID(sym),
        ctx ? reinterpret_cast<void *>(ctx) : nullptr,
        getter,
        nullptr,
        false,
        true);
  };

  defineGetter(proto, Predefined::source, regExpSourceGetter);
  defineGetter(proto, Predefined::multiline, regExpFlagPropertyGetter, 'm');
  defineGetter(proto, Predefined::ignoreCase, regExpFlagPropertyGetter, 'i');
  defineGetter(proto, Predefined::global, regExpFlagPropertyGetter, 'g');
  defineGetter(proto, Predefined::unicode, regExpFlagPropertyGetter, 'u');
  defineGetter(proto, Predefined::sticky, regExpFlagPropertyGetter, 'y');
  defineGetter(proto, Predefined::dotAll, regExpFlagPropertyGetter, 's');
  defineGetter(proto, Predefined::hasIndices, regExpFlagPropertyGetter, 'd');

  defineGetter(cons, Predefined::dollar1, regExpDollarNumberGetter, 1);
  defineGetter(cons, Predefined::dollar2, regExpDollarNumberGetter, 2);
  defineGetter(cons, Predefined::dollar3, regExpDollarNumberGetter, 3);
  defineGetter(cons, Predefined::dollar4, regExpDollarNumberGetter, 4);
  defineGetter(cons, Predefined::dollar5, regExpDollarNumberGetter, 5);
  defineGetter(cons, Predefined::dollar6, regExpDollarNumberGetter, 6);
  defineGetter(cons, Predefined::dollar7, regExpDollarNumberGetter, 7);
  defineGetter(cons, Predefined::dollar8, regExpDollarNumberGetter, 8);
  defineGetter(cons, Predefined::dollar9, regExpDollarNumberGetter, 9);
  defineGetter(cons, Predefined::leftContext, regExpLeftContextGetter);
  defineGetter(cons, Predefined::dollarBacktick, regExpLeftContextGetter);
  defineGetter(cons, Predefined::rightContext, regExpRightContextGetter);
  defineGetter(cons, Predefined::dollarApostrophe, regExpRightContextGetter);
  defineGetter(cons, Predefined::dollarUnderscore, regExpInputGetter);
  defineGetter(cons, Predefined::input, regExpInputGetter);
  defineGetter(cons, Predefined::dollarAmpersand, regExpLastMatchGetter);
  defineGetter(cons, Predefined::lastMatch, regExpLastMatchGetter);
  defineGetter(cons, Predefined::dollarPlus, regExpLastParenGetter);
  defineGetter(cons, Predefined::lastParen, regExpLastParenGetter);

  defineMethod(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::toString),
      nullptr,
      regExpPrototypeToString,
      0);
  (void)defineMethod(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::SymbolMatch),
      Predefined::getSymbolID(Predefined::squareSymbolMatch),
      nullptr,
      regExpPrototypeSymbolMatch,
      1,
      dpf);
  (void)defineMethod(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::SymbolSearch),
      Predefined::getSymbolID(Predefined::squareSymbolSearch),
      nullptr,
      regExpPrototypeSymbolSearch,
      1,
      dpf);
  (void)defineMethod(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::SymbolReplace),
      Predefined::getSymbolID(Predefined::squareSymbolReplace),
      nullptr,
      regExpPrototypeSymbolReplace,
      2,
      dpf);
  (void)defineMethod(
      runtime,
      proto,
      Predefined::getSymbolID(Predefined::SymbolSplit),
      Predefined::getSymbolID(Predefined::squareSymbolSplit),
      nullptr,
      regExpPrototypeSymbolSplit,
      2,
      dpf);

  defineGetter(proto, Predefined::flags, regExpFlagsGetter);

  return cons;
}

                                             
static uint32_t getStringIndex(Handle<StringPrimitive> S, uint32_t e) {
                                                                             
                                                                               
                                                                                
          
                                                                        
                                         
  if (e > 0 && e < S->getStringLength()) {
    if (isHighSurrogate(S->at(e - 1)) && isLowSurrogate(S->at(e))) {
      e -= 1;
    }
  }
  return e;
}

                                                           
                                                                                
                                                                     
                                                                               
                              
static CallResult<HermesValue> regExpAlloc(
    Runtime &runtime,
    PseudoHandle<>                ) {
  return JSRegExp::create(runtime).getHermesValue();
}

                                                                
static CallResult<Handle<JSRegExp>> regExpInitialize(
    Runtime &runtime,
    Handle<> obj,
    Handle<> pattern,
    Handle<> flags) {
  auto regExpObj = Handle<JSRegExp>::dyn_vmcast(obj);
  if (LLVM_UNLIKELY(!regExpObj)) {
    return ExecutionStatus::EXCEPTION;
  }
                                                           
                                           
  MutableHandle<StringPrimitive> P = runtime.makeMutableHandle(
      runtime.getPredefinedString(Predefined::emptyString));
  if (!pattern->isUndefined()) {
    auto strRes = toString_RJS(runtime, pattern);
    if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    P = strRes->get();
  }
                                                         
                                         
  MutableHandle<StringPrimitive> F = runtime.makeMutableHandle(
      runtime.getPredefinedString(Predefined::emptyString));
  if (!flags->isUndefined()) {
    auto strRes = toString_RJS(runtime, flags);
    if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    F = strRes->get();
  }
  if (JSRegExp::initialize(regExpObj, runtime, P, F) ==
      ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  return regExpObj;
}

                                                             
CallResult<Handle<JSRegExp>>
regExpCreate(Runtime &runtime, Handle<> P, Handle<> F) {
  auto objRes =
      regExpAlloc(runtime, createPseudoHandle(runtime.regExpPrototype));
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return regExpInitialize(runtime, runtime.makeHandle(objRes.getValue()), P, F);
}

                                          
                                                                                
                                                                     
                                                              
                                                                           
                                                                             
                                                             
static CallResult<Handle<JSObject>> regExpConstructorInternal(
    Runtime &runtime,
    Handle<> pattern,
    Handle<> flags,
    bool isConstructorCall) {
                                                 
                                        
  auto callRes = isRegExp(runtime, pattern);
  if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  bool patternIsRegExp = callRes.getValue();
                                                                  
                                                                           
                                                                             
                                                                            
                   
  auto propRes = JSObject::getNamed_RJS(
      runtime.getGlobal(),
      runtime,
      Predefined::getSymbolID(Predefined::RegExp));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<> newTarget = runtime.makeHandle(std::move(*propRes));
             
                                    
  if (!isConstructorCall) {
                                                      
                                                                       
                                                                 
    if (patternIsRegExp && flags->isUndefined()) {
                                                                  
                                                
      auto patternObj = Handle<JSObject>::vmcast(pattern);
      auto patternConstructor = JSObject::getNamed_RJS(
          patternObj,
          runtime,
          Predefined::getSymbolID(Predefined::constructor));
      if (LLVM_UNLIKELY(patternConstructor == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
                                                                         
                 
      if (isSameValue(newTarget.getHermesValue(), patternConstructor->get())) {
                                                                              
                                                                
                                                                              
        return patternObj;
      }
    }
  }

  MutableHandle<> P{runtime};
  MutableHandle<> F{runtime};
                                                                               
               
  if (auto patternAsRegExp = Handle<JSRegExp>::dyn_vmcast(pattern)) {
                                                                           
    P = JSRegExp::getPattern(patternAsRegExp.get(), runtime).getHermesValue();
                                                                
                                       
    if (flags->isUndefined()) {
      auto flagsStr =
          JSRegExp::getSyntaxFlags(patternAsRegExp.get()).toString();
      auto strRes = StringPrimitive::create(runtime, flagsStr);
      if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      F = strRes.getValue();
    } else {
                                 
      F = flags.getHermesValue();
    }
  } else if (patternIsRegExp) {
                                               
                                            
                              
    Handle<JSObject> patternObj = Handle<JSObject>::vmcast(pattern);
    propRes = JSObject::getNamed_RJS(
        patternObj, runtime, Predefined::getSymbolID(Predefined::source));
    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    P = std::move(propRes.getValue());
                                       
    if (flags->isUndefined()) {
                                             
                                 
      propRes = JSObject::getNamed_RJS(
          patternObj, runtime, Predefined::getSymbolID(Predefined::flags));
      if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      F = std::move(propRes.getValue());
    } else {
                                   
      F = flags.getHermesValue();
    }
  } else {
               
                             
    P = pattern.getHermesValue();
                           
    F = flags.getHermesValue();
  }
                                        
                          
  auto objRes = regExpAlloc(runtime, newTarget);
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
                                          
  auto regExpRes =
      regExpInitialize(runtime, runtime.makeHandle(objRes.getValue()), P, F);
  if (LLVM_UNLIKELY(regExpRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return Handle<JSObject>::vmcast(*regExpRes);
}

                                          
                                                                             
CallResult<HermesValue>
regExpConstructor(void *, Runtime &runtime, NativeArgs args) {
  Handle<> pattern = args.getArgHandle(0);
  Handle<> flags = args.getArgHandle(1);
  auto regExpRes = regExpConstructorInternal(
      runtime, pattern, flags, args.isConstructorCall());
  if (LLVM_UNLIKELY(regExpRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return regExpRes->getHermesValue();
}

                                                                      
                                                                            
                                                                              
             
static CallResult<Handle<JSRegExp>> regExpConstructorFastCopy(
    Runtime &runtime,
    Handle<> pattern,
    Handle<StringPrimitive> flags) {
  if (auto R = Handle<JSRegExp>::dyn_vmcast(pattern)) {
    auto newRegexp = runtime.makeHandle(JSRegExp::create(runtime));
    if (LLVM_UNLIKELY(
            JSRegExp::initialize(newRegexp, runtime, R, flags) ==
            ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    return newRegexp;
  }
  auto newRegexpRes = regExpConstructorInternal(runtime, pattern, flags, true);
  if (LLVM_UNLIKELY(newRegexpRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return Handle<JSRegExp>::vmcast(*newRegexpRes);
}

static void createGroupsObject(
    Runtime &runtime,
    Handle<JSArray> matchObj,
    Handle<JSObject> mappingObj) {
                                                                       
              
  NamedPropertyDescriptor groupsDesc;
  auto pos = JSObject::getOwnNamedDescriptor(
      matchObj,
      runtime,
      Predefined::getSymbolID(Predefined::groups),
      groupsDesc);
  assert(pos && "match object is missing .groups property");
  (void)pos;

                                                                  
  if (!mappingObj) {
    auto shv = SmallHermesValue::encodeUndefinedValue();
    JSObject::setNamedSlotValueUnsafe(matchObj.get(), runtime, groupsDesc, shv);
    return;
  }

                                                                  
                                                                          
                                                                          
  auto clazzHandle = runtime.makeHandle(mappingObj->getClass(runtime));
  auto groupsObjRes = JSObject::create(
      runtime, Runtime::makeNullHandle<JSObject>(), clazzHandle);
  auto groupsObj = runtime.makeHandle(groupsObjRes.get());

  HiddenClass::forEachProperty(
      clazzHandle, runtime, [&](SymbolID id, NamedPropertyDescriptor desc) {
        auto groupIdx =
            JSObject::getNamedSlotValueUnsafe(*mappingObj, runtime, desc.slot)
                .getNumber(runtime);
        JSObject::setNamedSlotValueUnsafe(
            *groupsObj, runtime, desc.slot, matchObj->at(runtime, groupIdx));
      });

  auto shv = SmallHermesValue::encodeObjectValue(*groupsObj, runtime);
  JSObject::setNamedSlotValueUnsafe(matchObj.get(), runtime, groupsDesc, shv);
}

                                                  
static CallResult<Handle<JSArray>> makeMatchIndicesIndexPairArray(
    Runtime &runtime,
    Handle<StringPrimitive> S,
    RegExpMatch indices,
    Handle<JSObject> mappingObj,
    bool hasGroups) {
                                                   
  size_t n = indices.size();
                                                                     
                    
                                  
  auto arrRes = JSArray::create(runtime, n, n);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<JSArray> A = runtime.makeHandle<JSArray>(*arrRes);
  JSArray::setStorageEndIndex(A, runtime, indices.size());

                                                                           
                                                                               
                          

  MutableHandle<> matchIndexPair{runtime};
                                                                      
  for (size_t i = 0; i < n; i++) {
                                        
    auto matchIndices = indices[i];
                                                
    if (matchIndices) {
                                                                     
      auto matchIndexPairRes = JSArray::create(runtime, 2, 2);
      if (LLVM_UNLIKELY(matchIndexPairRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      auto pair = runtime.makeHandle<JSArray>(*matchIndexPairRes);
      JSArray::setStorageEndIndex(pair, runtime, 2);
      auto firstIdx =
          SmallHermesValue::encodeNumberValue(matchIndices->location, runtime);
      JSArray::unsafeSetExistingElementAt(*pair, runtime, 0, firstIdx);
      auto secondIdx = SmallHermesValue::encodeNumberValue(
          matchIndices->location + matchIndices->length, runtime);
      JSArray::unsafeSetExistingElementAt(*pair, runtime, 1, secondIdx);
      matchIndexPair = pair.getHermesValue();
    } else {
                 
                                            
      matchIndexPair = Runtime::getUndefinedValue();
    }
                                                                  
                       
    auto shv = SmallHermesValue::encodeHermesValue(*matchIndexPair, runtime);
    JSArray::unsafeSetExistingElementAt(*A, runtime, i, shv);
  }

                                               
                                  
  MutableHandle<> groups{runtime};
  if (hasGroups) {
                                                   
    auto mappingObjClazz = runtime.makeHandle(mappingObj->getClass(runtime));
    auto groupsRes = JSObject::create(
        runtime, Runtime::makeNullHandle<JSObject>(), mappingObjClazz);
    auto groupsObj = runtime.makeHandle(groupsRes.get());
    HiddenClass::forEachProperty(
        mappingObjClazz,
        runtime,
        [&](SymbolID id, NamedPropertyDescriptor desc) {
          auto groupIdx =
              JSObject::getNamedSlotValueUnsafe(*mappingObj, runtime, desc.slot)
                  .getNumber(runtime);
                                                                       
                                                                             
                             
          JSObject::setNamedSlotValueUnsafe(
              *groupsObj, runtime, desc.slot, A->at(runtime, groupIdx));
        });
    groups = groupsObj.getHermesValue();
  } else {
               
                                  
    groups = Runtime::getUndefinedValue();
  }

                                                                 
  if (LLVM_UNLIKELY(
          JSObject::defineOwnProperty(
              A,
              runtime,
              Predefined::getSymbolID(Predefined::groups),
              DefinePropertyFlags::getDefaultNewPropertyFlags(),
              groups) == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

                  
  return A;
}

                 
CallResult<Handle<JSArray>> directRegExpExec(
    Handle<JSRegExp> regexp,
    Runtime &runtime,
    Handle<StringPrimitive> S) {
  MutableHandle<JSArray> A{runtime};
  GCScope gcScope{runtime};

                                                 
  const uint32_t length = S->getStringLength();

                                                        
  auto propRes = runtime.getNamed(regexp, PropCacheID::RegExpLastIndex);
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto lengthRes =
      toLengthU64(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(lengthRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  uint64_t lastIndex = *lengthRes;

                                     
  const regex::SyntaxFlags flags = JSRegExp::getSyntaxFlags(regexp.get());

                                                                        
                                                                         
                                                                          
           
                                                                            
           
  const bool global = flags.global;
  const bool sticky = flags.sticky;
  const bool hasIndices = flags.hasIndices;
  const bool fullUnicode = flags.unicode;

                                                                
  if (!global && !sticky) {
    lastIndex = 0;
  }

                                                                         
                                                                   
                                                                              
                            
  CallResult<RegExpMatch> matchResult = RegExpMatch{};
  if (lastIndex <= length) {
    assert(
        lastIndex <= UINT32_MAX &&
        "lastIndex should fit in u32 because it is <= a string length");
    uint32_t searchStartOffset = static_cast<uint32_t>(lastIndex);
    matchResult = JSRegExp::search(regexp, runtime, S, searchStartOffset);
  }

  if (LLVM_UNLIKELY(matchResult == ExecutionStatus::EXCEPTION))
    return ExecutionStatus::EXCEPTION;
  RegExpMatch &match = *matchResult;
  if (match.empty()) {
                                               
                                    
                                                    
                                                             
                                        
                      
                
                              
                                  
                                                           
                                      
                      
    if (global || sticky) {
      if (LLVM_UNLIKELY(
              setLastIndex(regexp, runtime, 0) == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
    }
    return Runtime::makeNullHandle<JSArray>();
  }

                     
                                                                               
               
                                            
  assert(!match.empty() && "Match should not be empty");

                                                                      
               
  if (fullUnicode) {
    for (auto &mg : match) {
      if (!mg)
        continue;
      auto captureStart = getStringIndex(S, mg->location);
      auto captureEnd = getStringIndex(S, mg->location + mg->length);
      mg = RegExpMatchRange{captureStart, captureEnd - captureStart};
    }
  }

  if (global || sticky) {
    auto totalMatch = *match.front();
    uint32_t e = totalMatch.location + totalMatch.length;
    if (LLVM_UNLIKELY(
            setLastIndex(regexp, runtime, e) == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
  }

  auto arrRes = JSArray::createAndAllocPropStorage(
      runtime,
      Handle<JSObject>::vmcast(&runtime.arrayPrototype),
      Handle<HiddenClass>::vmcast(&runtime.regExpMatchClass),
      match.size(),
      match.size());
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  A = arrRes->get();

                                      
  NamedPropertyDescriptor indexDesc;
  bool res = JSObject::getOwnNamedDescriptor(
      A, runtime, Predefined::getSymbolID(Predefined::index), indexDesc);
  assert(res && "match object is missing .index property");
  (void)res;
  auto indexSHV =
      SmallHermesValue::encodeNumberValue(match.front()->location, runtime);
  JSObject::setNamedSlotValueUnsafe(*A, runtime, indexDesc, indexSHV);

  NamedPropertyDescriptor inputDesc;
  res = JSObject::getOwnNamedDescriptor(
      A, runtime, Predefined::getSymbolID(Predefined::input), inputDesc);
  assert(res && "match object is missing .input property");
  (void)res;
  auto inputSHV = SmallHermesValue::encodeStringValue(*S, runtime);
  JSObject::setNamedSlotValueUnsafe(*A, runtime, inputDesc, inputSHV);

                                                             
  Handle<JSObject> groupNames = regexp->getGroupNameMappings(runtime);
  bool hasGroups = (bool)groupNames;

                                                          
  size_t idx = 0;
  auto marker = gcScope.createMarker();
  for (const auto &mg : match) {
    gcScope.flushToMarker(marker);
    if (!mg) {
                                                                   
      JSArray::setElementAt(A, runtime, idx, Runtime::getUndefinedValue());
    } else {
      assert(
          mg->location + mg->length >= mg->location &&
          mg->location + mg->length <= S->getStringLength() &&
          "Capture group range unexpectedly out of bounds");
      auto strRes =
          StringPrimitive::slice(runtime, S, mg->location, mg->length);
      if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      JSArray::setElementAt(
          A, runtime, idx, runtime.makeHandle<StringPrimitive>(*strRes));
    }
    idx++;
  }

                                
  if (hasIndices) {
                                                                     
                              
    auto indicesArray = makeMatchIndicesIndexPairArray(
        runtime, S, match, groupNames, hasGroups);
    if (LLVM_UNLIKELY(indicesArray == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }

                                                                       
    if (LLVM_UNLIKELY(
            JSObject::defineOwnProperty(
                A,
                runtime,
                Predefined::getSymbolID(Predefined::indices),
                DefinePropertyFlags::getDefaultNewPropertyFlags(),
                *indicesArray) == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
  }

  createGroupsObject(runtime, A, groupNames);
  return A;
}

                                                                  
                                                                           
                                                                           
                                                                       
                                        
static CallResult<HermesValue> regExpBuiltinExec(
    Runtime &runtime,
    Handle<JSRegExp> R,
    Handle<StringPrimitive> S) {
  CallResult<Handle<JSArray>> result = directRegExpExec(R, runtime, S);
  if (LLVM_UNLIKELY(result == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
                                                                     
                                                                             
                                                 
  if (!result.getValue())
    return HermesValue::encodeNullValue();
  return result->getHermesValue();
}

                    
uint64_t
advanceStringIndex(const StringPrimitive *S, uint64_t index, bool unicode) {
  if (unicode && index + 1 < S->getStringLength() &&
      isHighSurrogate(S->at(index)) && isLowSurrogate(S->at(index + 1))) {
    return index + 2;
  }
  return index + 1;
}

                                                           
CallResult<HermesValue>
regExpExec(Runtime &runtime, Handle<JSObject> R, Handle<StringPrimitive> S) {
                                   
                             
  auto propRes = JSObject::getNamed_RJS(
      R, runtime, Predefined::getSymbolID(Predefined::exec));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto exec = runtime.makeHandle(std::move(propRes.getValue()));
                                         
  if (auto execCallable = Handle<Callable>::dyn_vmcast(exec)) {
                                           
                                 
    auto callRes =
        Callable::executeCall1(execCallable, runtime, R, S.getHermesValue());
    if (callRes == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
                                                                      
                 
    if (!(*callRes)->isObject() && !(*callRes)->isNull()) {
      return runtime.raiseTypeError(
          "The result of exec can only be object or null.");
    }
                        
    return callRes.toCallResultHermesValue();
  }
                                                                               
               
                                                                       
                                                   
  auto regExpObj = Handle<JSRegExp>::dyn_vmcast(R);
  if (LLVM_UNLIKELY(!regExpObj)) {
    return runtime.raiseTypeError(
        "Failed to execute an invalid regular expression object.");
  }
                                       
  return regExpBuiltinExec(runtime, regExpObj, S);
}

                                           
                                                                   
CallResult<HermesValue>
regExpPrototypeExec(void *, Runtime &runtime, NativeArgs args) {
  Handle<JSRegExp> regexp = args.dyncastThis<JSRegExp>();
  if (!regexp) {
    return runtime.raiseTypeError(
        "RegExp function called on non-RegExp object");
  }

  auto strRes = toString_RJS(runtime, args.getArgHandle(0));
  if (strRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<StringPrimitive> S = runtime.makeHandle(std::move(*strRes));
  CallResult<Handle<JSArray>> result = directRegExpExec(regexp, runtime, S);
  if (LLVM_UNLIKELY(result.getStatus() == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

                                                                     
                                                                             
                                                 
  if (!result.getValue())
    return HermesValue::encodeNullValue();
  return result.getValue().getHermesValue();
}

                                           
                                                     
                                                                            
                      
CallResult<HermesValue>
regExpPrototypeTest(void *context, Runtime &runtime, NativeArgs args) {
  CallResult<HermesValue> res = regExpPrototypeExec(context, runtime, args);
  if (res == ExecutionStatus::EXCEPTION)
    return ExecutionStatus::EXCEPTION;

  return HermesValue::encodeBoolValue(
      !runtime.makeHandle(res.getValue())->isNull());
}

                                                                            
                                                 
CallResult<HermesValue>
regExpDollarNumberGetter(void *ctx, Runtime &runtime, NativeArgs args) {
  size_t i = reinterpret_cast<size_t>(ctx);

  auto match = runtime.regExpLastMatch;
  if (match.size() >= i + 1 &&
      vmisa<StringPrimitive>(runtime.regExpLastInput)) {
    const auto &cap = match[i];
    if (cap.hasValue()) {
      auto S = Handle<StringPrimitive>::vmcast(&runtime.regExpLastInput);
      auto strRes =
          StringPrimitive::slice(runtime, S, cap->location, cap->length);
      if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      return *strRes;
    }
  }

  return HermesValue::encodeStringValue(
      runtime.getPredefinedString(Predefined::emptyString));
}

                
CallResult<HermesValue>
regExpSourceGetter(void *ctx, Runtime &runtime, NativeArgs args) {
                                                            
  if (!args.dyncastThis<JSObject>()) {
    return runtime.raiseTypeError(
        "RegExp.prototype.source getter called on non-RegExp");
  }

  Handle<JSRegExp> R = args.dyncastThis<JSRegExp>();
  if (!R) {
                                                                             
                                   
    if (LLVM_UNLIKELY(thisIsRegExpProto(runtime, args))) {
                                                                          
                                    
      const char *emptyPattern = "(?:)";
      return StringPrimitive::create(
          runtime, ASCIIRef{emptyPattern, strlen(emptyPattern)});
    }
    return runtime.raiseTypeError(
        "RegExp.prototype.source getter called on non-RegExp");
  }

                                                                    
                                                                     
                                              
                                                                              
                                                                             
                                                                         
  return JSRegExp::escapePattern(
      runtime.makeHandle(JSRegExp::getPattern(R.get(), runtime)), runtime);
}

                                   
CallResult<HermesValue>
regExpFlagPropertyGetter(void *ctx, Runtime &runtime, NativeArgs args) {
                                                                                
                                                                      

                               
                                                             
                                                                              
                                                                       
  Handle<JSRegExp> R = args.dyncastThis<JSRegExp>();
  if (!R) {
                                                                                
                                   
    if (thisIsRegExpProto(runtime, args)) {
      return HermesValue::encodeUndefinedValue();
    }
    return runtime.raiseTypeError("RegExp getter called on non-RegExp");
  }

                                                                     
                                                            
                    
  auto syntaxFlags = JSRegExp::getSyntaxFlags(R.get());
  switch ((intptr_t)ctx) {
    case 'i':
      return HermesValue::encodeBoolValue(syntaxFlags.ignoreCase);
    case 'm':
      return HermesValue::encodeBoolValue(syntaxFlags.multiline);
    case 'g':
      return HermesValue::encodeBoolValue(syntaxFlags.global);
    case 'u':
      return HermesValue::encodeBoolValue(syntaxFlags.unicode);
    case 'y':
      return HermesValue::encodeBoolValue(syntaxFlags.sticky);
    case 's':
      return HermesValue::encodeBoolValue(syntaxFlags.dotAll);
    case 'd':
      return HermesValue::encodeBoolValue(syntaxFlags.hasIndices);
    default:
      llvm_unreachable("Invalid flag passed to regExpFlagPropertyGetter");
      return HermesValue::encodeEmptyValue();
  }
}

CallResult<HermesValue>
regExpLeftContextGetter(void *ctx, Runtime &runtime, NativeArgs args) {
  auto match = runtime.regExpLastMatch;
  if (match.size() >= 1 && vmisa<StringPrimitive>(runtime.regExpLastInput)) {
    auto S = Handle<StringPrimitive>::vmcast(&runtime.regExpLastInput);
    auto strRes = StringPrimitive::slice(runtime, S, 0, match[0]->location);
    if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    return *strRes;
  }

  return HermesValue::encodeStringValue(
      runtime.getPredefinedString(Predefined::emptyString));
}

CallResult<HermesValue>
regExpRightContextGetter(void *ctx, Runtime &runtime, NativeArgs args) {
  auto match = runtime.regExpLastMatch;
  if (match.size() >= 1 && vmisa<StringPrimitive>(runtime.regExpLastInput)) {
    auto S = Handle<StringPrimitive>::vmcast(&runtime.regExpLastInput);
    if (match[0]->location + match[0]->length < S->getStringLength()) {
      auto startIdx = match[0]->location + match[0]->length;
      auto strRes = StringPrimitive::slice(
          runtime, S, startIdx, S->getStringLength() - startIdx);
      if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      return *strRes;
    }
  }

  return HermesValue::encodeStringValue(
      runtime.getPredefinedString(Predefined::emptyString));
}

CallResult<HermesValue>
regExpInputGetter(void *ctx, Runtime &runtime, NativeArgs args) {
  if (vmisa<StringPrimitive>(runtime.regExpLastInput)) {
    return runtime.regExpLastInput;
  }

  return HermesValue::encodeStringValue(
      runtime.getPredefinedString(Predefined::emptyString));
}

CallResult<HermesValue>
regExpLastMatchGetter(void *ctx, Runtime &runtime, NativeArgs args) {
  auto match = runtime.regExpLastMatch;
  if (match.size() >= 1 && vmisa<StringPrimitive>(runtime.regExpLastInput)) {
    auto S = Handle<StringPrimitive>::vmcast(&runtime.regExpLastInput);
    auto strRes = StringPrimitive::slice(
        runtime, S, match[0]->location, match[0]->length);
    if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    return *strRes;
  }

  return HermesValue::encodeStringValue(
      runtime.getPredefinedString(Predefined::emptyString));
}

CallResult<HermesValue>
regExpLastParenGetter(void *ctx, Runtime &runtime, NativeArgs args) {
  auto match = runtime.regExpLastMatch;
  if (match.size() >= 2 && vmisa<StringPrimitive>(runtime.regExpLastInput)) {
    auto S = Handle<StringPrimitive>::vmcast(&runtime.regExpLastInput);
    const auto &cap = match.back();
    if (cap.hasValue()) {
      auto strRes =
          StringPrimitive::slice(runtime, S, cap->location, cap->length);
      if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      return *strRes;
    }
  }

  return HermesValue::encodeStringValue(
      runtime.getPredefinedString(Predefined::emptyString));
}

                     
                                                                          
                                      
CallResult<HermesValue> getSubstitution(
    Runtime &runtime,
    Handle<StringPrimitive> matched,
    Handle<StringPrimitive> str,
    uint32_t position,
    Handle<ArrayStorageSmall> captures,
    Handle<JSObject> namedCaptures,
    Handle<StringPrimitive> replacement) {
                                        
                                                               
  uint32_t matchLength = matched->getStringLength();
                                    
                                                            
  uint32_t stringLength = str->getStringLength();
                                                  
                                        
  assert(
      position <= stringLength &&
      "The matched position should be within the string length.");
                                                             
                                           
                                              
  uint32_t tailPos = position + matchLength;
                                                     
  size_t m = captures ? captures->size() : 0;

                                                                              
                                                                              
                                                                              
                                                                          
                                     
  auto replacementView =
      StringPrimitive::createStringView(runtime, replacement);
  auto stringView = StringPrimitive::createStringView(runtime, str);
  auto matchedStrView = StringPrimitive::createStringView(runtime, matched);
  SmallU16String<32> result{};

                                                                          
                                                   
  for (size_t i = 0, e = replacementView.length(); i < e;) {
                                                                       
    char16_t c0 = replacementView[i];
    if (c0 != u'$' || i + 1 == e) {
                                                                  
      result.append(c0);
      ++i;
      continue;
    }

                                                                        
    char16_t c1 = replacementView[i + 1];
    if (c1 == u'$') {
      result.append(u'$');
      i += 2;
    } else if (c1 == u'&') {
                               
      matchedStrView.appendUTF16String(result);
      i += 2;
    } else if (c1 == u'`') {
                                                        
      stringView.slice(0, position).appendUTF16String(result);
      i += 2;
    } else if (c1 == u'\'') {
                                                       
      if (tailPos < stringLength) {
        stringView.slice(position + matchLength).appendUTF16String(result);
      }
      i += 2;
    } else if (u'0' <= c1 && c1 <= u'9') {
                  
                                                             
                                                        
                                                    

                                                                     
                                             
      auto submatchOrEmpty = [&](size_t idx) -> StringView {
        assert(
            captures && idx < captures->size() &&
            "Index into captures is out of bound.");
        if (captures->at(idx).isUndefined()) {
                                 
          return stringView.slice(str->getStringLength());
        }
        return StringPrimitive::createStringView(
            runtime,
            runtime.makeHandle<StringPrimitive>(
                captures->at(idx).getString(runtime)));
      };

      uint32_t n = c1 - u'0';
      if (i + 2 < e) {
                                                                     
        char16_t c2 = replacementView[i + 2];
                     
        uint32_t nn = (c1 - u'0') * 10 + (c2 - u'0');
        if ((u'0' <= c2 && c2 <= u'9') && (1 <= nn && nn <= m)) {
                            
          auto view = submatchOrEmpty(nn - 1);
          result.insert(result.end(), view.begin(), view.end());
          i += 3;
        } else if (1 <= n && n <= m) {
                                       
          auto view = submatchOrEmpty(n - 1);
          result.insert(result.end(), view.begin(), view.end());
          i += 2;
        } else {
                                                                    
                     
          result.append({c0, c1});
          i += 2;
        }
      } else if (1 <= n && n <= m) {
        auto view = submatchOrEmpty(n - 1);
        result.insert(result.end(), view.begin(), view.end());
        i += 2;
      } else {
                          
        result.append({c0, c1});
        i += 2;
      }
    } else if (c1 == u'<' && namedCaptures) {
                                                                 
      size_t gtPos = 0;
      for (size_t innerI = i + 2; innerI < e; innerI++) {
        if (replacementView[innerI] == u'>') {
          gtPos = innerI;
          break;
        }
      }
                                            
      if (gtPos == 0) {
        result.append({c0, c1});
        i += 2;
      } else {
        llvh::SmallVector<char16_t, 32> storage;
                                                                           
                 
        auto identifier =
            replacementView.slice(i + 2, gtPos - (i + 2)).getUTF16Ref(storage);
        auto symbolRes =
            runtime.getIdentifierTable().getSymbolHandle(runtime, identifier);
        if (LLVM_UNLIKELY(symbolRes == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }
        auto captureRes =
            JSObject::getNamed_RJS(namedCaptures, runtime, symbolRes->get());
        if (LLVM_UNLIKELY(captureRes == ExecutionStatus::EXCEPTION))
          return ExecutionStatus::EXCEPTION;
                                           
                                                     
                   
        if (!(*captureRes)->isUndefined()) {
                                                          
          auto toStrRes =
              toString_RJS(runtime, runtime.makeHandle(std::move(*captureRes)));
          if (toStrRes == ExecutionStatus::EXCEPTION) {
            return ExecutionStatus::EXCEPTION;
          }
          (*toStrRes)->appendUTF16String(result);
        }
                                                       
        i = gtPos + 1;
      }
    } else {
                                                                    
      result.append({c0, c1});
      i += 2;
    }
  }
                       
  return StringPrimitive::create(runtime, result);
}

                 
                                                                             
CallResult<HermesValue>
regExpPrototypeSymbolMatchAll(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};

                                
  auto R = args.dyncastThis<JSObject>();

                                                              
  if (LLVM_UNLIKELY(!R)) {
    return runtime.raiseTypeError(
        "RegExp.prototype[@@matchAll] should be called on a js object");
  }

                                    
  auto strRes = toString_RJS(runtime, args.getArgHandle(0));
  if (strRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*strRes));

                                                   
                                                                       

                                                   
  auto flagsPropRes = JSObject::getNamed_RJS(
      R, runtime, Predefined::getSymbolID(Predefined::flags));
  if (LLVM_UNLIKELY(flagsPropRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto flagsStrRes =
      toString_RJS(runtime, runtime.makeHandle(std::move(*flagsPropRes)));
  if (LLVM_UNLIKELY(flagsStrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto flags = runtime.makeHandle(std::move(*flagsStrRes));

                                                    
                                                     
                                                                        
                                                                            
  auto newRegExpRes = regExpConstructorFastCopy(runtime, R, flags);
  if (newRegExpRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto matcher = *newRegExpRes;

                                                           
  auto propRes = JSObject::getNamed_RJS(
      R, runtime, Predefined::getSymbolID(Predefined::lastIndex));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto lenRes = toLength(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(lenRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double lastIndex = lenRes->getNumber();
                                                             
  if (setLastIndex(matcher, runtime, lastIndex) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }

                                                  
                                   
                                                        
                                        
  bool global = false;
  bool fullUnicode = false;
  auto strView = StringPrimitive::createStringView(runtime, flags);
  for (auto it = strView.begin(); it < strView.end(); it++) {
    if (*it == 'g')
      global = true;
    if (*it == 'u')
      fullUnicode = true;
  }

                                                                              
  return JSRegExpStringIterator::create(
             runtime, matcher, S, global, fullUnicode)
      .getHermesValue();
}

                
                                                               
CallResult<HermesValue>
regExpPrototypeToString(void *, Runtime &runtime, NativeArgs args) {
  Handle<JSObject> regexp = args.dyncastThis<JSObject>();
  if (!regexp) {
    return runtime.raiseTypeError(
        "RegExp.prototype.toString() called on non-object");
  }

                                              
  auto source = JSObject::getNamed_RJS(
      regexp, runtime, Predefined::getSymbolID(Predefined::source));
  if (LLVM_UNLIKELY(source == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto patternRes =
      toString_RJS(runtime, runtime.makeHandle(std::move(*source)));
  if (LLVM_UNLIKELY(patternRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<StringPrimitive> pattern = runtime.makeHandle(std::move(*patternRes));

                                           
  auto flagsObj = JSObject::getNamed_RJS(
      regexp, runtime, Predefined::getSymbolID(Predefined::flags));
  if (LLVM_UNLIKELY(flagsObj == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto flagsRes =
      toString_RJS(runtime, runtime.makeHandle(std::move(*flagsObj)));
  if (LLVM_UNLIKELY(flagsRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<StringPrimitive> flags = runtime.makeHandle(std::move(*flagsRes));

                                                                              
                                                               
  SmallU16String<32> result;
  result.reserve(pattern->getStringLength() + 2 + 5);

  result.push_back(u'/');
  pattern->appendUTF16String(result);
  result.push_back(u'/');
  flags->appendUTF16String(result);
  return StringPrimitive::create(runtime, result);
}

                                     
                  
CallResult<HermesValue>
regExpPrototypeSymbolMatch(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};

                                 
  Handle<JSObject> rx = args.dyncastThis<JSObject>();

                                                               
  if (LLVM_UNLIKELY(!rx)) {
    return runtime.raiseTypeError(
        "RegExp.prototype[@@match] should be called on a js object");
  }
                                 
                          
  auto strRes = toString_RJS(runtime, args.getArgHandle(0));
  if (strRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*strRes));
                                                   
                               
  auto propRes = JSObject::getNamed_RJS(
      rx, runtime, Predefined::getSymbolID(Predefined::global));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto global = toBoolean(propRes->get());
                                
                                   
  if (!global) {
    return regExpExec(runtime, rx, S);
  }
                            
                                                        
                                   
  auto unicodePropRes = JSObject::getNamed_RJS(
      rx, runtime, Predefined::getSymbolID(Predefined::unicode));
  if (LLVM_UNLIKELY(unicodePropRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  bool fullUnicode = toBoolean(unicodePropRes->get());

                                                       
                                  
  if (setLastIndex(rx, runtime, 0) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                
  auto arrRes = JSArray::create(runtime, 0, 0);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto A = *arrRes;
                   
  uint32_t n = 0;

               
  MutableHandle<> propValue{runtime};
  MutableHandle<> result{runtime};
  MutableHandle<StringPrimitive> matchStr{runtime};
  auto marker = gcScope.createMarker();
  while (true) {
    gcScope.flushToMarker(marker);
                                          
    auto callRes = regExpExec(runtime, rx, S);
                                  
    if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    result = callRes.getValue();
                                   
    if (result->isNull()) {
      if (n == 0) {
        return HermesValue::encodeNullValue();
      } else {
        if (LLVM_UNLIKELY(
                JSArray::setLengthProperty(A, runtime, n) ==
                ExecutionStatus::EXCEPTION))
          return ExecutionStatus::EXCEPTION;
        return A.getHermesValue();
      }
    }
                                   
    auto resultObj = Handle<JSObject>::vmcast(result);
                                                     
                                   
    auto propRes2 = JSObject::getComputed_RJS(
        resultObj, runtime, HandleRootOwner::getZeroValue());
    if (propRes2 == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    propValue = std::move(propRes2.getValue());
    auto strRes2 = toString_RJS(runtime, propValue);
    if (strRes2 == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    matchStr = strRes2->get();
                                                                     
                                 
    JSArray::setElementAt(A, runtime, n, matchStr);
                                               
    if (matchStr->getStringLength() == 0) {
                                                            
                                      
      if ((propRes = runtime.getNamed(rx, PropCacheID::RegExpLastIndex)) ==
          ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
      propValue = std::move(propRes.getValue());
      auto thisIndex = toLength(runtime, propValue);
      if (thisIndex == ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
                                                                           
      double nextIndex = advanceStringIndex(
          S.get(), thisIndex->getNumberAs<uint64_t>(), fullUnicode);
                                                                   
      auto setStatus = setLastIndex(rx, runtime, nextIndex);
                                      
      if (setStatus == ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
    }
                      
    n++;
  }
  llvm_unreachable(
      "RegExp.prototype[@@match] must stop when all matched results are returned.");
}

                  
CallResult<HermesValue>
regExpPrototypeSymbolSearch(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};

                                 
                                                               
  Handle<JSObject> rx = args.dyncastThis<JSObject>();
  if (!rx) {
    return runtime.raiseTypeError(
        "Calling regExp.prototype[@@search] on a non-object.");
  }
                                  
                          
  auto strRes = toString_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*strRes));
                                                      
                                          
  auto propRes = runtime.getNamed(rx, PropCacheID::RegExpLastIndex);
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<> previousLastIndex =
      runtime.makeHandle(std::move(propRes.getValue()));
                                                    
  auto status = setLastIndex(rx, runtime, 0);
                               
  if (LLVM_UNLIKELY(status == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
                                        
                                
  auto execRes = regExpExec(runtime, rx, S);
  if (LLVM_UNLIKELY(execRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<> result = runtime.makeHandle(execRes.getValue());
                                                                     
  auto previousLastIndexSHV =
      SmallHermesValue::encodeHermesValue(*previousLastIndex, runtime);
  status = setLastIndex(rx, runtime, previousLastIndexSHV);
                                
  if (LLVM_UNLIKELY(status == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
                                      
  if (result->isNull()) {
    return HermesValue::encodeUntrustedNumberValue(-1);
  }
                                     
  auto resultObj = Handle<JSObject>::dyn_vmcast(result);
  if (LLVM_UNLIKELY(!resultObj)) {
    return ExecutionStatus::EXCEPTION;
  }
  return JSObject::getNamed_RJS(
             resultObj, runtime, Predefined::getSymbolID(Predefined::index))
      .toCallResultHermesValue();
}

                  
CallResult<HermesValue>
regExpPrototypeSymbolReplace(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};

                                 
                                                               
  Handle<JSObject> rx = args.dyncastThis<JSObject>();
  if (LLVM_UNLIKELY(!rx)) {
    return runtime.raiseTypeError(
        "RegExp.prototype[@@replace] called on a non-object.");
  }
                                  
                          
  auto strRes = toString_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*strRes));
                                                             
  uint32_t lengthS = S->getStringLength();
                                                          
  Handle<> replaceValue = args.getArgHandle(1);
  MutableHandle<StringPrimitive> replaceValueStr{runtime};
  auto replaceFn = Handle<Callable>::dyn_vmcast(replaceValue);
                                           
  if (!replaceFn) {
                                                       
                                         
    auto strRes = toString_RJS(runtime, replaceValue);
    if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    replaceValueStr = strRes->get();
  }
                                                   
                               
  auto propRes = JSObject::getNamed_RJS(
      rx, runtime, Predefined::getSymbolID(Predefined::global));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  bool global = toBoolean(propRes->get());

                                                     
  bool fullUnicode = false;

                                
  if (global) {
                                                             
                                        
    auto unicodePropRes = JSObject::getNamed_RJS(
        rx, runtime, Predefined::getSymbolID(Predefined::unicode));
    if (LLVM_UNLIKELY(unicodePropRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    fullUnicode = toBoolean(unicodePropRes->get());

                                                           
    auto setStatus = setLastIndex(rx, runtime, 0);
                                      
    if (LLVM_UNLIKELY(setStatus == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
  }
                                         
  auto arrRes = ArrayStorageSmall::create(runtime, 16               );
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  MutableHandle<ArrayStorageSmall> resultsHandle{
      runtime, vmcast<ArrayStorageSmall>(arrRes.getValue())};

                           
  bool done = false;

                                    
  MutableHandle<> propValue{runtime};
  MutableHandle<StringPrimitive> matchStr{runtime};
  MutableHandle<JSObject> result{runtime};
  auto stringView = StringPrimitive::createStringView(runtime, S);
  while (!done) {
    GCScopeMarkerRAII marker{runtime};
                                          
                                 
    auto execRes = regExpExec(runtime, rx, S);
    if (LLVM_UNLIKELY(execRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
                                              
    if (execRes->isNull()) {
      done = true;
      break;
    }
                                  
                                                   
    result = vmcast<JSObject>(execRes.getValue());
                                              
    if (LLVM_UNLIKELY(
            resultsHandle->size() == ArrayStorageSmall::maxElements())) {
      return runtime.raiseRangeError("Out of memory for regexp results.");
    }
    if (LLVM_UNLIKELY(
            ArrayStorageSmall::push_back(resultsHandle, runtime, result) ==
            ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
                                                
    if (!global) {
      done = true;
    } else {
                   
                                                       
                                     
      propRes = JSObject::getComputed_RJS(
          result, runtime, HandleRootOwner::getZeroValue());
      if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      propValue = propRes->get();
      auto strRes = toString_RJS(runtime, propValue);
      if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      matchStr = strRes->get();
                                                 
      if (matchStr->getStringLength() == 0) {
                                                              
                                        
        if ((propRes = runtime.getNamed(rx, PropCacheID::RegExpLastIndex)) ==
            ExecutionStatus::EXCEPTION) {
          return ExecutionStatus::EXCEPTION;
        }
        propValue = std::move(propRes.getValue());
        auto thisIndex = toLength(runtime, propValue);
        if (thisIndex == ExecutionStatus::EXCEPTION) {
          return ExecutionStatus::EXCEPTION;
        }
                                                                             
        double nextIndex = advanceStringIndex(
            S.get(), thisIndex->getNumberAs<uint64_t>(), fullUnicode);
                                                                     
        auto setStatus = setLastIndex(rx, runtime, nextIndex);
                                        
        if (setStatus == ExecutionStatus::EXCEPTION) {
          return ExecutionStatus::EXCEPTION;
        }
      }
    }
  }

                                                         
  SmallU16String<32> accumulatedResult{};
                                     
  uint32_t nextSourcePosition = 0;
                                            
  MutableHandle<> valueHandle{runtime};
  MutableHandle<> nHandle{runtime};
  for (uint32_t i = 0, size = resultsHandle->size(); i < size; ++i) {
    GCScopeMarkerRAII marker1{runtime};
    result = vmcast<JSObject>(resultsHandle->at(i).getObject(runtime));
                                                           
                                    
    propRes = JSObject::getNamed_RJS(
        result, runtime, Predefined::getSymbolID(Predefined::length));
    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    valueHandle = std::move(propRes.getValue());
    auto lengthRes = toLength(runtime, valueHandle);
    if (LLVM_UNLIKELY(lengthRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
                                                         
    uint64_t nCaptures = lengthRes->getNumberAs<uint64_t>();
                                                 
    nCaptures = nCaptures > 0 ? nCaptures - 1 : 0;
                                                    
                                  
    propRes = JSObject::getComputed_RJS(
        result, runtime, HandleRootOwner::getZeroValue());
    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    auto strRes = toString_RJS(
        runtime, runtime.makeHandle(std::move(propRes.getValue())));
    if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    auto matched = runtime.makeHandle(std::move(*strRes));
                                                                 
    uint32_t matchLength = matched->getStringLength();
                                                                    
                                   
    propRes = JSObject::getNamed_RJS(
        result, runtime, Predefined::getSymbolID(Predefined::index));
    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    auto intRes = toIntegerOrInfinity(
        runtime, runtime.makeHandle(std::move(propRes.getValue())));
    if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
                                                                              
    double positionDouble = intRes->getNumber();
                                                         
                                                                
                                   
    uint32_t position = (int64_t)std::fmax(
        std::fmin(positionDouble, (double)lengthS), (double)0);
                     
                                   
    uint64_t n = 1;
                                        
    if (LLVM_UNLIKELY(nCaptures > ArrayStorageSmall::maxElements())) {
      return runtime.raiseRangeError("Out of memory for capture groups.");
    }
    arrRes = ArrayStorageSmall::create(runtime, nCaptures);
    if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    MutableHandle<ArrayStorageSmall> capturesHandle{
        runtime, vmcast<ArrayStorageSmall>(arrRes.getValue())};
    MutableHandle<> capN{runtime};
                                    
    while (n <= nCaptures) {
      GCScopeMarkerRAII marker2{runtime};
                                                 
                                  
      nHandle = HermesValue::encodeUntrustedNumberValue(n);
      propRes = JSObject::getComputed_RJS(result, runtime, nHandle);
      if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      capN = std::move(propRes.getValue());
                                            
      if (!capN->isUndefined()) {
                                         
                                   
        auto strRes = toString_RJS(runtime, capN);
        if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }
        capN = strRes->getHermesValue();
      }
                                                         
      if (LLVM_UNLIKELY(
              ArrayStorageSmall::push_back(capturesHandle, runtime, capN) ==
              ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
                        
      n++;
    }

                                                       
    MutableHandle<HermesValue> namedCaptures{runtime};
    bool hasNamedCaptures = false;
    auto namedCapturesRes = JSObject::getNamed_RJS(
        result, runtime, Predefined::getSymbolID(Predefined::groups));
    if (LLVM_UNLIKELY(namedCapturesRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (!(*namedCapturesRes)->isUndefined()) {
      namedCaptures.set(namedCapturesRes->get());
      hasNamedCaptures = true;
    }

                                            
    MutableHandle<StringPrimitive> replacement{runtime};
    if (replaceFn) {
      CallResult<PseudoHandle<>> callRes{ExecutionStatus::EXCEPTION};
      {
                                            
                                                                
        size_t replacerArgsCount = 1 + nCaptures + 2 + hasNamedCaptures;
        if (LLVM_UNLIKELY(replacerArgsCount >= UINT32_MAX))
          return runtime.raiseStackOverflow(
              Runtime::StackOverflowKind::JSRegisterStack);
        ScopedNativeCallFrame newFrame{
            runtime,
            static_cast<uint32_t>(replacerArgsCount),
            *replaceFn,
            false,
            HermesValue::encodeUndefinedValue()};
        if (LLVM_UNLIKELY(newFrame.overflowed()))
          return runtime.raiseStackOverflow(
              Runtime::StackOverflowKind::NativeStack);

        uint32_t argIdx = 0;
        newFrame->getArgRef(argIdx++) = matched.getHermesValue();
                                                                              
                             
        for (; argIdx <= capturesHandle->size(); ++argIdx) {
          newFrame->getArgRef(argIdx) =
              capturesHandle->at(argIdx - 1).unboxToHV(runtime);
        }
                                      
        newFrame->getArgRef(argIdx++) =
            HermesValue::encodeUntrustedNumberValue(position);
        newFrame->getArgRef(argIdx++) = S.getHermesValue();
                                                      
        if (hasNamedCaptures) {
          newFrame->getArgRef(argIdx++) = *namedCaptures;
        }
                                                                           
        callRes = Callable::call(replaceFn, runtime);
        if (callRes == ExecutionStatus::EXCEPTION) {
          return ExecutionStatus::EXCEPTION;
        }
      }
                                                    
      auto strRes = toString_RJS(
          runtime, runtime.makeHandle(std::move(callRes.getValue())));
      if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      replacement = strRes->get();
    } else {
                 
                                                   
      if (hasNamedCaptures) {
        auto objRes = toObject(runtime, namedCaptures);
        if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }
                                                             
        namedCaptures.set(*objRes);
      }

                                                                               
                       
      auto callRes = getSubstitution(
          runtime,
          matched,
          S,
          position,
          capturesHandle,
          hasNamedCaptures ? Handle<JSObject>::vmcast(namedCaptures)
                           : Runtime::makeNullHandle<JSObject>(),
          replaceValueStr);
      if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      replacement = vmcast<StringPrimitive>(callRes.getValue());
    }
                                      
                                                
    if (position >= nextSourcePosition) {
                                                                               
                                                                             
                                                                 
                                                                                
                 
                                                          
                                                                               
                                                                  
                                                                               
                                   
      stringView.slice(nextSourcePosition, position - nextSourcePosition)
          .appendUTF16String(accumulatedResult);
      replacement->appendUTF16String(accumulatedResult);
                                                               
      nextSourcePosition = position + matchLength;
    }
  }

                                                                   
  if (nextSourcePosition >= lengthS) {
    return StringPrimitive::createEfficient(runtime, accumulatedResult);
  }
                                                                    
                                                                                
                                                                       
                 
  stringView.slice(nextSourcePosition).appendUTF16String(accumulatedResult);
  return StringPrimitive::createEfficient(runtime, accumulatedResult);
}

                    
                                                                               
                                                
                                                                                
CallResult<HermesValue>
regExpPrototypeSymbolSplit(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};

                                                               
  if (LLVM_UNLIKELY(!vmisa<JSObject>(args.getThisArg()))) {
    return runtime.raiseTypeError(
        "Cannot call RegExp.protoype[Symbol.split] on a non-object.");
  }
                                  
  auto strRes = toString_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto S = runtime.makeHandle(std::move(*strRes));

                                                    
  auto regexp = Handle<JSObject>::vmcast(args.getThisHandle());
  CallResult<PseudoHandle<>> flagsRes = JSObject::getNamed_RJS(
      regexp, runtime, Predefined::getSymbolID(Predefined::flags));
  if (LLVM_UNLIKELY(flagsRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  CallResult<PseudoHandle<StringPrimitive>> flagsStrRes =
      toString_RJS(runtime, runtime.makeHandle(std::move(flagsRes.getValue())));
  if (LLVM_UNLIKELY(flagsStrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<StringPrimitive> flags =
      runtime.makeHandle(std::move(flagsStrRes.getValue()));

                                                     
                                                                               
         
                                                                                
                                                            
                                                      
  auto splitterRes = regExpConstructorFastCopy(runtime, regexp, flags);
  if (LLVM_UNLIKELY(splitterRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto splitter = *splitterRes;
                                                                          
                                                                         
                                             
  auto stickyFlags = JSRegExp::getSyntaxFlags(splitter.get());
  auto newFlags = stickyFlags;
  newFlags.sticky = 0;
  JSRegExp::setSyntaxFlags(splitter.get(), newFlags);

                                                           
                                           
  bool unicodeMatching = newFlags.unicode;

                                 
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

                                     
  uint32_t size = S->getStringLength();

                    
                                                               
  uint32_t p = 0;

                              
  if (lim == 0) {
                                              
    return A.getHermesValue();
  }

                          
  if (size == 0) {
                                           
    auto matchResult = JSRegExp::search(splitter, runtime, S, 0);
    if (LLVM_UNLIKELY(matchResult == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
                                     
    else if (!matchResult->empty()) {
                                                              
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

                               
                                                                   
  while (q < size) {
    gcScope.flushToMarker(marker);

                                                        
                                             
                                                                           

                                                        
                                                                  
                                                   
    auto matchResult = JSRegExp::search(splitter, runtime, S, q);
    if (LLVM_UNLIKELY(matchResult == ExecutionStatus::EXCEPTION))
      return ExecutionStatus::EXCEPTION;

    auto match = *matchResult;

    if (match.empty() || match[0]->location >= size) {
                                                                               
                                                                  
                                                                                
                                                                               
                    
      break;
    }

               
                                                     
                                                                                
                                                                                
                
    q = match[0]->location;
                                                            
                                 
                                                                               
                                                 
    uint32_t e = q + match[0]->length;

                                                                         
    if (e == p) {
                                                                        
                                             
                                                                        
                                                                               
      q = advanceStringIndex(S.get(), q, unicodeMatching);
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

                                                           
                                                                 
                       
                                                
                                                                              
      for (uint32_t i = 1, m = match.size(); i < m; ++i) {
        GCScopeMarkerRAII captureMarker{runtime};
                                                         
        const auto &range = match[i];
                                                                         
                        
        if (!range) {
          JSArray::setElementAt(
              A, runtime, lengthA, Runtime::getUndefinedValue());
        } else {
          if (LLVM_UNLIKELY(
                  (strRes = StringPrimitive::slice(
                       runtime, S, range->location, range->length)) ==
                  ExecutionStatus::EXCEPTION)) {
            return ExecutionStatus::EXCEPTION;
          }
          JSArray::setElementAt(
              A,
              runtime,
              lengthA,
              runtime.makeHandle<StringPrimitive>(*strRes));
        }
                                        
        ++lengthA;
                                         
        if (lengthA == lim) {
          if (LLVM_UNLIKELY(
                  JSArray::setLengthProperty(A, runtime, lengthA) ==
                  ExecutionStatus::EXCEPTION))
            return ExecutionStatus::EXCEPTION;
          return A.getHermesValue();
        }
      }
                        
                                                                               
      q = p;
    }
  }

                                                                                
                                                                  
                                                            
  auto elementStrRes = StringPrimitive::slice(runtime, S, p, size - p);
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

                  
                                          
CallResult<HermesValue>
regExpFlagsGetter(void *ctx, Runtime &runtime, NativeArgs args) {
                             
                                                          
  Handle<JSObject> R = args.dyncastThis<JSObject>();
  if (!R) {
    return runtime.raiseTypeError(
        "RegExp.prototype.flags getter called on non-object");
  }

  llvh::SmallString<7> result;
  static const struct FlagProp {
    char flagChar;
    Predefined::Str name;
  } flagProps[] = {
      {'d', Predefined::hasIndices},
      {'g', Predefined::global},
      {'i', Predefined::ignoreCase},
      {'m', Predefined::multiline},
      {'s', Predefined::dotAll},
      {'u', Predefined::unicode},
      {'y', Predefined::sticky},
  };
  for (FlagProp f : flagProps) {
    auto flagVal =
        JSObject::getNamed_RJS(R, runtime, Predefined::getSymbolID(f.name));
    if (LLVM_UNLIKELY(flagVal == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (toBoolean(flagVal->get())) {
      result.push_back(f.flagChar);
    }
  }
  return StringPrimitive::create(runtime, result);
}

}                
}                    

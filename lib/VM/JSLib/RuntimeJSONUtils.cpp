/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/JSLib/RuntimeJSONUtils.h"

#include "Object.h"

#include "hermes/Support/Compiler.h"
#include "hermes/Support/JSON.h"
#include "hermes/Support/UTF16Stream.h"
#include "hermes/VM/ArrayLike.h"
#include "hermes/VM/ArrayStorage.h"
#include "hermes/VM/Callable.h"
#include "hermes/VM/JSArray.h"
#include "hermes/VM/JSProxy.h"
#include "hermes/VM/PrimitiveBox.h"

#include "JSONLexer.h"

#include "llvh/ADT/SmallString.h"
#include "llvh/Support/SaveAndRestore.h"

namespace hermes {
namespace vm {

namespace {

                                                                           
                                                                        
                                     
class RuntimeJSONParser {
 public:
  static constexpr int32_t MAX_RECURSION_DEPTH =
#ifndef HERMES_LIMIT_STACK_DEPTH
      512
#else
      100
#endif
      ;

 private:
                     
  Runtime &runtime_;

                
  JSONLexer lexer_;

                                            
                                     
  Handle<Callable> reviver_;

                                                                            
                                            
  MutableHandle<> tmpHandle_;

                                                         
                                                       
                                                  
                                                                
  int32_t remainingDepth_{MAX_RECURSION_DEPTH};

 public:
  explicit RuntimeJSONParser(
      Runtime &runtime,
      UTF16Stream &&jsonString,
      Handle<Callable> reviver)
      : runtime_(runtime),
        lexer_(runtime, std::move(jsonString)),
        reviver_(reviver),
        tmpHandle_(runtime) {}

                                                                      
                                                                         
                                               
  CallResult<HermesValue> parse();

 private:
                                                          
                                                                   
                                                       
  CallResult<HermesValue> parseValue();

                                                      
                                                                    
  CallResult<HermesValue> parseArray();

                                                       
                                                                    
  CallResult<HermesValue> parseObject();

                                       
  CallResult<HermesValue> revive(Handle<> value);

                                                                              
                                                                          
  CallResult<HermesValue> operationWalk(
      Handle<JSObject> holder,
      Handle<> property);

                                                                           
                                                                            
                            
  ExecutionStatus filter(Handle<JSObject> val, Handle<> key);
};

                                                                      
            
class JSONStringifyer {
                  
  Runtime &runtime_;

                                                                       
                
  MutableHandle<Callable> replacerFunction_;

                                                             
                                                         
                                                                           
                                                                    
                      
  MutableHandle<StringPrimitive> gap_;

                                                                              
  MutableHandle<JSArray> propertyList_;

                                                                        
                              
  MutableHandle<PropStorage> stackValue_;

                                                                           
  MutableHandle<PropStorage> stackJO_;

                                                                            
                
                                                                        
                
  MutableHandle<> tmpHandle_;

                                                            
  MutableHandle<> tmpHandle2_;

                                                     
  MutableHandle<> operationStrValue_;

                                            
  MutableHandle<JSArray> operationJOK_;

                                                 
                                                                     
                                            
  MutableHandle<JSObject> operationStrHolder_;

                                                                        
                                                                             
                                                          
  uint32_t depthCount_{0};

                                                                                
                               
  static constexpr uint32_t MAX_RECURSION_DEPTH{
      RuntimeJSONParser::MAX_RECURSION_DEPTH};

                                                                       
  llvh::SmallVector<char16_t, 32> output_{};

 public:
  explicit JSONStringifyer(Runtime &runtime)
      : runtime_(runtime),
        replacerFunction_(runtime),
        gap_{runtime, nullptr},
        propertyList_(runtime),
        stackValue_(runtime),
        stackJO_(runtime),
        tmpHandle_(runtime),
        tmpHandle2_(runtime),
        operationStrValue_(runtime),
        operationJOK_(runtime),
        operationStrHolder_(runtime) {}

  LLVM_NODISCARD ExecutionStatus init(Handle<> replacer, Handle<> space) {
    auto arrRes = PropStorage::create(runtime_, 4);
    if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    stackValue_ = vmcast<PropStorage>(*arrRes);
    if (LLVM_UNLIKELY(
            (arrRes = PropStorage::create(runtime_, 4)) ==
            ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    stackJO_ = vmcast<PropStorage>(*arrRes);
    auto cr = initializeReplacer(replacer);
    if (LLVM_UNLIKELY(cr == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    return initializeSpace(space);
  }

                         
  CallResult<HermesValue> stringify(Handle<> value);

 private:
                                            
                                                                            
                                           
  LLVM_NODISCARD ExecutionStatus initializeReplacer(Handle<> replacer);

                                                     
                                              
  ExecutionStatus initializeSpace(Handle<> space);

                                                                             
                                                              
                                                             
                                                       
                                                                            
                                                                   
                                                  
  CallResult<bool> operationStr(HermesValue key);

                                                    
                                                                                
  void operationQuote(StringView value);

                                                                         
                                                        
                             
  ExecutionStatus operationJA();

                                                                         
                                                        
                              
  ExecutionStatus operationJO();

                                        
                                                         
  void indent();

                                                                   
                                                                  
                       
                                                         
  CallResult<bool> pushValueToStack(HermesValue value);

                           
  void popValueFromStack();

                                                                
  void appendToOutput(SymbolID identifierID);

                                                       
  void appendToOutput(const StringPrimitive *str);
};
}             

CallResult<HermesValue> RuntimeJSONParser::parse() {
                                                   
  if (LLVM_UNLIKELY(lexer_.advance() == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto parRes = parseValue();
  if (LLVM_UNLIKELY(parRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

                                          
  if (LLVM_UNLIKELY(lexer_.getCurToken()->getKind() != JSONTokenKind::Eof)) {
    return lexer_.errorUnexpectedChar();
  }

  if (reviver_.get()) {
    if ((parRes = revive(runtime_.makeHandle(*parRes))) ==
        ExecutionStatus::EXCEPTION)
      return ExecutionStatus::EXCEPTION;
  }
  return parRes;
}

CallResult<HermesValue> RuntimeJSONParser::parseValue() {
  llvh::SaveAndRestore<decltype(remainingDepth_)> oldDepth{
      remainingDepth_, remainingDepth_ - 1};
  if (remainingDepth_ <= 0) {
    return runtime_.raiseStackOverflow(Runtime::StackOverflowKind::JSONParser);
  }

  MutableHandle<> returnValue{runtime_};
  switch (lexer_.getCurToken()->getKind()) {
    case JSONTokenKind::String:
      returnValue = lexer_.getCurToken()->getStrAsPrim().getHermesValue();
      break;
    case JSONTokenKind::Number:
      returnValue = HermesValue::encodeUntrustedNumberValue(
          lexer_.getCurToken()->getNumber());
      break;
    case JSONTokenKind::LBrace: {
      auto parRes = parseObject();
      if (LLVM_UNLIKELY(parRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      returnValue = *parRes;
      break;
    }
    case JSONTokenKind::LSquare: {
      auto parRes = parseArray();
      if (LLVM_UNLIKELY(parRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      returnValue = *parRes;
      break;
    }
    case JSONTokenKind::True:
      returnValue = HermesValue::encodeBoolValue(true);
      break;
    case JSONTokenKind::False:
      returnValue = HermesValue::encodeBoolValue(false);
      break;
    case JSONTokenKind::Null:
      returnValue = HermesValue::encodeNullValue();
      break;

    default:
      return lexer_.errorUnexpectedChar();
  }

  if (LLVM_UNLIKELY(lexer_.advance() == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  return returnValue.getHermesValue();
}

CallResult<HermesValue> RuntimeJSONParser::parseArray() {
  assert(
      lexer_.getCurToken()->getKind() == JSONTokenKind::LSquare &&
      "Wrong entrance to parseArray");
  auto arrRes = JSArray::create(runtime_, 4, 0);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto array = *arrRes;

  if (LLVM_UNLIKELY(lexer_.advance() == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if (lexer_.getCurToken()->getKind() != JSONTokenKind::RSquare) {
    MutableHandle<> indexValue{runtime_};
    GCScope gcScope{runtime_};
    auto marker = gcScope.createMarker();

    for (uint32_t index = 0;; ++index) {
      gcScope.flushToMarker(marker);

      auto parRes = parseValue();
      if (LLVM_UNLIKELY(parRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }

      indexValue = HermesValue::encodeUntrustedNumberValue(index);
      (void)JSObject::defineOwnComputedPrimitive(
          array,
          runtime_,
          indexValue,
          DefinePropertyFlags::getDefaultNewPropertyFlags(),
          runtime_.makeHandle(*parRes));

      if (lexer_.getCurToken()->getKind() == JSONTokenKind::Comma) {
        if (LLVM_UNLIKELY(lexer_.advance() == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }
        continue;
      } else if (lexer_.getCurToken()->getKind() == JSONTokenKind::RSquare) {
        break;
      } else {
        return lexer_.errorUnexpectedChar();
      }
    }
    assert(
        lexer_.getCurToken()->getKind() == JSONTokenKind::RSquare &&
        "Unexpected break for array parse");
  }

  return array.getHermesValue();
}

CallResult<HermesValue> RuntimeJSONParser::parseObject() {
  assert(
      lexer_.getCurToken()->getKind() == JSONTokenKind::LBrace &&
      "Wrong entrance to parseObject");
  auto object = runtime_.makeHandle(JSObject::create(runtime_));

                                                                              
                                                                  
  if (LLVM_UNLIKELY(
          lexer_.advanceStrAsSymbol() == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if (lexer_.getCurToken()->getKind() == JSONTokenKind::RBrace) {
    return object.getHermesValue();
  }

  MutableHandle<SymbolID> key{runtime_};
  GCScope gcScope{runtime_};
  auto marker = gcScope.createMarker();
  for (;;) {
    gcScope.flushToMarker(marker);

    if (LLVM_UNLIKELY(
            lexer_.getCurToken()->getKind() != JSONTokenKind::String)) {
      return lexer_.error("Expect a string key in JSON object");
    }
    key = lexer_.getCurToken()->getStrAsSymbol().get();

    if (LLVM_UNLIKELY(lexer_.advance() == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }

    if (lexer_.getCurToken()->getKind() != JSONTokenKind::Colon) {
      return lexer_.error("Expect ':' after the key in JSON object");
    }

    if (LLVM_UNLIKELY(lexer_.advance() == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }

    auto parRes = parseValue();
    if (LLVM_UNLIKELY(parRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }

    (void)JSObject::defineOwnComputedPrimitive(
        object,
        runtime_,
        key,
        DefinePropertyFlags::getDefaultNewPropertyFlags(),
        runtime_.makeHandle(*parRes));

    if (lexer_.getCurToken()->getKind() == JSONTokenKind::Comma) {
      if (LLVM_UNLIKELY(
              lexer_.advanceStrAsSymbol() == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      continue;
    } else if (lexer_.getCurToken()->getKind() == JSONTokenKind::RBrace) {
      break;
    } else {
      return lexer_.errorUnexpectedChar();
    }
  }
  assert(
      lexer_.getCurToken()->getKind() == JSONTokenKind::RBrace &&
      "Unexpected stop for object parse");
  return object.getHermesValue();
}

CallResult<HermesValue> RuntimeJSONParser::revive(Handle<> value) {
  auto root = runtime_.makeHandle(JSObject::create(runtime_));
  auto status = JSObject::defineOwnProperty(
      root,
      runtime_,
      Predefined::getSymbolID(Predefined::emptyString),
      DefinePropertyFlags::getDefaultNewPropertyFlags(),
      value);
  (void)status;
  assert(
      status != ExecutionStatus::EXCEPTION && *status &&
      "defineOwnProperty on new object cannot fail");
  return operationWalk(
      root, runtime_.getPredefinedStringHandle(Predefined::emptyString));
}

CallResult<HermesValue> RuntimeJSONParser::operationWalk(
    Handle<JSObject> holder,
    Handle<> property) {
                                                      
  GCScope gcScope(runtime_);

  llvh::SaveAndRestore<decltype(remainingDepth_)> oldDepth{
      remainingDepth_, remainingDepth_ - 1};
  if (remainingDepth_ <= 0) {
    return runtime_.raiseStackOverflow(Runtime::StackOverflowKind::JSONParser);
  }

  auto propRes = JSObject::getComputed_RJS(holder, runtime_, property);
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  MutableHandle<> tmpHandle{runtime_};
  CallResult<bool> isArrayRes =
      isArray(runtime_, dyn_vmcast<JSObject>(propRes->get()));
  if (LLVM_UNLIKELY(isArrayRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto valHandle = runtime_.makeHandle(std::move(*propRes));
  if (*isArrayRes) {
    Handle<JSObject> objHandle = Handle<JSObject>::vmcast(valHandle);
    CallResult<uint64_t> lenRes = getArrayLikeLength_RJS(objHandle, runtime_);
    if (LLVM_UNLIKELY(lenRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }

    GCScopeMarkerRAII marker(runtime_);
    for (uint64_t index = 0, e = *lenRes; index < e; ++index) {
      tmpHandle = HermesValue::encodeUntrustedNumberValue(index);
                                                                 
      if (LLVM_UNLIKELY(
              filter(objHandle, tmpHandle) == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      marker.flush();
    }
  } else if (auto scopedObject = Handle<JSObject>::dyn_vmcast(valHandle)) {
    auto cr = JSObject::getOwnPropertyNames(scopedObject, runtime_, true);
    if (cr == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    auto keys = *cr;
    GCScopeMarkerRAII marker(runtime_);
    for (uint32_t index = 0, e = keys->getEndIndex(); index < e; ++index) {
      tmpHandle = keys->at(runtime_, index).unboxToHV(runtime_);
      if (LLVM_UNLIKELY(
              filter(scopedObject, tmpHandle) == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      marker.flush();
    }
  }
                                                                         
                                                                   
  tmpHandle = *property;
  auto strRes = toString_RJS(runtime_, tmpHandle);
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  tmpHandle = strRes->getHermesValue();

  return Callable::executeCall2(
             reviver_, runtime_, holder, *tmpHandle, *valHandle)
      .toCallResultHermesValue();
}

ExecutionStatus RuntimeJSONParser::filter(Handle<JSObject> val, Handle<> key) {
  auto jsonRes = operationWalk(val, key);
  if (LLVM_UNLIKELY(jsonRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto newElement = runtime_.makeHandle(*jsonRes);
  if (newElement->isUndefined()) {
    if (LLVM_UNLIKELY(
            JSObject::deleteComputed(val, runtime_, key) ==
            ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
  } else {
    if (LLVM_UNLIKELY(
            JSObject::defineOwnComputed(
                val,
                runtime_,
                key,
                DefinePropertyFlags::getDefaultNewPropertyFlags(),
                newElement) == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
  }
  return ExecutionStatus::RETURNED;
}

CallResult<HermesValue> runtimeJSONParse(
    Runtime &runtime,
    Handle<StringPrimitive> jsonString,
    Handle<Callable> reviver) {
                                                                     
                                                                          
  UTF16Ref ref;
  SmallU16String<32> storage;
  if (LLVM_UNLIKELY(jsonString->isExternal() && !jsonString->isASCII())) {
    ref = jsonString->getStringRef<char16_t>();
  } else {
    StringPrimitive::createStringView(runtime, jsonString)
        .appendUTF16String(storage);
    ref = storage;
  }

  RuntimeJSONParser parser{runtime, UTF16Stream(ref), reviver};
  return parser.parse();
}

CallResult<HermesValue> runtimeJSONParseRef(
    Runtime &runtime,
    UTF16Stream &&stream) {
  RuntimeJSONParser parser{
      runtime, std::move(stream), Runtime::makeNullHandle<Callable>()};
  return parser.parse();
}

ExecutionStatus JSONStringifyer::initializeReplacer(Handle<> replacer) {
  if (!vmisa<JSObject>(*replacer))
    return ExecutionStatus::RETURNED;
                           

  if ((replacerFunction_ = dyn_vmcast<Callable>(*replacer)))
    return ExecutionStatus::RETURNED;
                                

  auto replacerArray = Handle<JSObject>::dyn_vmcast(replacer);
  CallResult<bool> isArrayRes =
      isArray(runtime_, dyn_vmcast<JSObject>(*replacerArray));
  if (LLVM_UNLIKELY(isArrayRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if (!*isArrayRes)
    return ExecutionStatus::RETURNED;
                         

  CallResult<uint64_t> lenRes = getArrayLikeLength_RJS(replacerArray, runtime_);
  if (LLVM_UNLIKELY(lenRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if (*lenRes > UINT32_MAX) {
    return runtime_.raiseRangeError("replacer array is too large");
  }
  uint32_t len = static_cast<uint32_t>(*lenRes);
  auto arrRes = JSArray::create(runtime_, len, 0);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  propertyList_ = arrRes->get();

                                                     
  GCScope gcScope{runtime_};
  auto marker = gcScope.createMarker();
  for (uint64_t i = 0, e = *lenRes; i < e; ++i) {
    gcScope.flushToMarker(marker);

                              
    tmpHandle_ = HermesValue::encodeUntrustedNumberValue(i);
    auto propRes =
        JSObject::getComputed_RJS(replacerArray, runtime_, tmpHandle_);
    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    PseudoHandle<> v = std::move(*propRes);
                                                                                
                   
    if (v->isString()) {
      tmpHandle_ = std::move(v);
    } else if (
        v->isNumber() || vmisa<JSNumber>(v.get()) || vmisa<JSString>(v.get())) {
      tmpHandle_ = std::move(v);
      auto strRes = toString_RJS(runtime_, tmpHandle_);
      if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      tmpHandle_ = strRes->getHermesValue();
    } else {
      tmpHandle_ = HermesValue::encodeUndefinedValue();
    }

    if (tmpHandle_->isUndefined())
      continue;
                                                                          
    bool exists = false;
    auto len = propertyList_->getEndIndex();
    for (uint32_t i = 0; i < len; ++i) {
      if (propertyList_->at(runtime_, i)
              .getString(runtime_)
              ->equals(tmpHandle_->getString())) {
        exists = true;
        break;
      }
    }
    if (!exists) {
      JSArray::setElementAt(propertyList_, runtime_, len, tmpHandle_);
    }
  }
  return ExecutionStatus::RETURNED;
}

ExecutionStatus JSONStringifyer::initializeSpace(Handle<> space) {
  tmpHandle_ = *space;
  if (vmisa<JSNumber>(*tmpHandle_)) {
    auto numRes = toNumber_RJS(runtime_, tmpHandle_);
    if (LLVM_UNLIKELY(numRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    tmpHandle_ = *numRes;
  } else if (vmisa<JSString>(*tmpHandle_)) {
    auto strRes = toString_RJS(runtime_, tmpHandle_);
    if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    tmpHandle_ = strRes->getHermesValue();
  }
  if (tmpHandle_->isNumber()) {
    auto intRes = toIntegerOrInfinity(runtime_, tmpHandle_);
    assert(
        intRes != ExecutionStatus::EXCEPTION &&
        "toInteger on a number cannot throw");
                              
    auto spaceCount =
        static_cast<int>(std::max(0.0, std::min(10.0, intRes->getNumber())));
    if (spaceCount > 0) {
                                                   
      llvh::SmallString<32> spaces;
      for (int i = 0; i < spaceCount; ++i) {
        spaces.push_back(' ');
      }
      auto strRes = StringPrimitive::create(runtime_, spaces);
      if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      gap_ = strRes->getString();
    }
  } else if (auto str = Handle<StringPrimitive>::dyn_vmcast(tmpHandle_)) {
    if (str->getStringLength() > 10) {
      auto strRes = StringPrimitive::slice(runtime_, str, 0, 10);
      if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      gap_ = strRes->getString();
    } else if (str->getStringLength() > 0) {
                                                      
      gap_ = str.get();
    }
  }
  return ExecutionStatus::RETURNED;
}

CallResult<bool> JSONStringifyer::operationStr(HermesValue key) {
  GCScopeMarkerRAII marker{runtime_};
  tmpHandle_ = key;

                               
  auto propRes =
      JSObject::getComputed_RJS(operationStrHolder_, runtime_, tmpHandle_);
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  operationStrValue_.set(propRes->get());

                                                    
  MutableHandle<> hValueHV{runtime_, *operationStrValue_};
  if (vmisa<BigIntPrimitive>(*operationStrValue_)) {
    CallResult<HermesValue> hObjRes = toObject(runtime_, hValueHV);
    if (LLVM_UNLIKELY(hObjRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    assert(vmisa<JSBigInt>(*hObjRes) && "if not boxed bigint, then what?!");
    assert(vmisa<JSObject>(*hObjRes) && "if not object, then what?!");
    hValueHV = std::move(*hObjRes);
  }

  if (auto valueObj = Handle<JSObject>::dyn_vmcast(hValueHV)) {
             
                                                
    if (LLVM_UNLIKELY(
            (propRes = JSObject::getNamedWithReceiver_RJS(
                 valueObj,
                 runtime_,
                 Predefined::getSymbolID(Predefined::toJSON),
                 operationStrValue_)) == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
                                              
    if (auto toJSON = Handle<Callable>::dyn_vmcast(
            runtime_.makeHandle(std::move(*propRes)))) {
      if (!tmpHandle_->isString()) {
                                          
        auto status = toString_RJS(runtime_, tmpHandle_);
        assert(
            status != ExecutionStatus::EXCEPTION &&
            "toString on a property cannot fail");
        tmpHandle_ = status->getHermesValue();
      }
                                                         
      auto callRes = Callable::executeCall1(
          toJSON, runtime_, operationStrValue_, *tmpHandle_);
      if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      operationStrValue_ = std::move(*callRes);
    }
  }

           
  if (replacerFunction_) {
               
    if (!tmpHandle_->isString()) {
                                        
      auto status = toString_RJS(runtime_, tmpHandle_);
      assert(
          status != ExecutionStatus::EXCEPTION &&
          "toString on a property cannot fail");
      tmpHandle_ = status->getHermesValue();
    }
                                                                          
                      
    auto callRes = Callable::executeCall2(
        replacerFunction_,
        runtime_,
        operationStrHolder_,
        *tmpHandle_,
        *operationStrValue_);
    if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    operationStrValue_ = std::move(*callRes);
  }

                                     
                                   
  if (vmisa<JSNumber>(*operationStrValue_)) {
                                                         
                                           
    auto numRes = toNumber_RJS(runtime_, operationStrValue_);
    if (LLVM_UNLIKELY(numRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    operationStrValue_ = *numRes;
  } else if (vmisa<JSString>(*operationStrValue_)) {
                                                              
                                           
    auto strRes = toString_RJS(runtime_, operationStrValue_);
    if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    operationStrValue_ = strRes->getHermesValue();
  } else if (auto *jsBool = dyn_vmcast<JSBoolean>(*operationStrValue_)) {
                                                               
                                               
    operationStrValue_ =
        HermesValue::encodeBoolValue(jsBool->getPrimitiveBoolean());
  } else if (auto jsBigInt = dyn_vmcast<JSBigInt>(*operationStrValue_)) {
                                                              
                                             
    BigIntPrimitive *bigintData =
        JSBigInt::getPrimitiveBigInt(jsBigInt, runtime_);
    operationStrValue_ = HermesValue::encodeBigIntValue(bigintData);
  }

           
  if (operationStrValue_->isNull()) {
    appendToOutput(Predefined::getSymbolID(Predefined::null));
    return true;
  }

  if (operationStrValue_->isBool()) {
    if (operationStrValue_->getBool()) {
               
      appendToOutput(Predefined::getSymbolID(Predefined::trueStr));
    } else {
               
      appendToOutput(Predefined::getSymbolID(Predefined::falseStr));
    }
    return true;
  }

           
  if (operationStrValue_->isString()) {
    operationQuote(
        StringPrimitive::createStringView(
            runtime_, Handle<StringPrimitive>::vmcast(operationStrValue_)));
    return true;
  }

           
  if (operationStrValue_->isNumber()) {
    if (std::isfinite(operationStrValue_->getNumber())) {
      auto status = toString_RJS(runtime_, operationStrValue_);
      assert(
          status != ExecutionStatus::EXCEPTION &&
          "toString on a number cannot fail");
      appendToOutput(status->get());
    } else {
      appendToOutput(Predefined::getSymbolID(Predefined::null));
    }
    return true;
  }

           
  if (vmisa<BigIntPrimitive>(*operationStrValue_)) {
    return runtime_.raiseTypeError("Do not know how to serialize a BigInt");
  }

            
  if (vmisa<JSObject>(*operationStrValue_) &&
      !vmisa<Callable>(*operationStrValue_)) {
    auto cr = pushValueToStack(*operationStrValue_);

    if (cr == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    if (LLVM_UNLIKELY(!*cr)) {
      return runtime_.raiseTypeError("cyclical structure in JSON object");
    }
                                                                        
                
    marker.flush();
    CallResult<bool> isArrayRes =
        isArray(runtime_, vmcast<JSObject>(*operationStrValue_));
    if (LLVM_UNLIKELY(isArrayRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    ExecutionStatus status = *isArrayRes ? operationJA() : operationJO();
    popValueFromStack();
    if (LLVM_UNLIKELY(status == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    return true;
  }

            
  return false;
}

void JSONStringifyer::operationQuote(StringView value) {
  if (value.isASCII()) {
    quoteStringForJSON(
        output_, ASCIIRef{value.castToCharPtr(), value.length()});
  } else {
    quoteStringForJSON(
        output_, UTF16Ref{value.castToChar16Ptr(), value.length()});
  }
}

ExecutionStatus JSONStringifyer::operationJA() {
  GCScopeMarkerRAII marker{runtime_};

          
  auto stepBack = depthCount_;
          
  if (depthCount_ + 1 >= MAX_RECURSION_DEPTH) {
    return runtime_.raiseStackOverflow(
        Runtime::StackOverflowKind::JSONStringify);
  }
  depthCount_++;
  output_.push_back(u'[');
  CallResult<uint64_t> lenRes = getArrayLikeLength_RJS(
      runtime_.makeHandle(
          vmcast<JSObject>(
              stackValue_->at(stackValue_->size() - 1).getObject(runtime_))),
      runtime_);
  if (LLVM_UNLIKELY(lenRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if (*lenRes > 0) {
                                                             
    indent();
  }
                   
  for (uint64_t index = 0; index < *lenRes; ++index) {
    if (index > 0) {
               
      output_.push_back(u',');
      indent();
    }
              
    operationStrHolder_ = vmcast<JSObject>(
        stackValue_->at(stackValue_->size() - 1).getObject(runtime_));
                                                                        
    marker.flush();
    auto status = operationStr(HermesValue::encodeUntrustedNumberValue(index));
    if (LLVM_UNLIKELY(status == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (LLVM_UNLIKELY(!status.getValue())) {
                                                                      
      appendToOutput(Predefined::getSymbolID(Predefined::null));
    }
  }
  depthCount_ = stepBack;

  if (*lenRes > 0) {
    indent();
  }
  output_.push_back(u']');
  return ExecutionStatus::RETURNED;
}

ExecutionStatus JSONStringifyer::operationJO() {
  GCScopeMarkerRAII marker{runtime_};

          
  auto stepBack = depthCount_;
          
  if (depthCount_ + 1 >= MAX_RECURSION_DEPTH) {
    return runtime_.raiseStackOverflow(
        Runtime::StackOverflowKind::JSONStringify);
  }
  depthCount_++;
  output_.push_back(u'{');
  auto beginningLoc = output_.size();
  indent();

  if (propertyList_) {
            
    operationJOK_ = propertyList_.get();
  } else {
            
    tmpHandle_ = HermesValue::encodeObjectValue(
        stackValue_->at(stackValue_->size() - 1).getObject(runtime_));
    if (LLVM_LIKELY(!Handle<JSObject>::vmcast(tmpHandle_)->isProxyObject())) {
                                                                   
                                                                   
                                                                      
                                     
      auto cr = JSObject::getOwnPropertyNames(
          Handle<JSObject>::vmcast(tmpHandle_), runtime_, true);
      if (cr == ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
      operationJOK_ = **cr;
    } else {
      CallResult<HermesValue> ownPropRes = enumerableOwnProperties_RJS(
          runtime_,
          Handle<JSObject>::vmcast(tmpHandle_),
          EnumerableOwnPropertiesKind::Key);
      if (ownPropRes == ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
      operationJOK_ = vmcast<JSArray>(*ownPropRes);
    }
  }

  marker.flush();

          
  bool hasElement = false;
  for (uint32_t index = 0, len = operationJOK_->getEndIndex(); index < len;
       ++index) {
              
                                                                           
                                                                        
                                                                    
                   
    auto savedLocation = output_.size();

    if (hasElement) {
               
      output_.push_back(u',');
      indent();
    }

    tmpHandle_ = operationJOK_->at(runtime_, index).unboxToHV(runtime_);
    if (LLVM_UNLIKELY(!tmpHandle_->isString())) {
                                                                               
                                                                      
                                                   
                                                            
      assert(!tmpHandle_->isObject() && "property name is an object");
      auto status = toString_RJS(runtime_, tmpHandle_);
      assert(
          status != ExecutionStatus::EXCEPTION &&
          "toString on a property cannot fail");
      tmpHandle_ = status->getHermesValue();
    }
                                                 
               
    operationQuote(
        StringPrimitive::createStringView(
            runtime_, Handle<StringPrimitive>::vmcast(tmpHandle_)));
                
    output_.push_back(u':');
                 
    if (gap_.get()) {
      output_.push_back(u' ');
    }

              
    operationStrHolder_ = vmcast<JSObject>(
        stackValue_->at(stackValue_->size() - 1).getObject(runtime_));

    tmpHandle2_ = operationJOK_.getHermesValue();
    if (PropStorage::push_back(stackJO_, runtime_, tmpHandle2_) ==
        ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }

                                                                            
    marker.flush();
    auto result = operationStr(*tmpHandle_);

    operationJOK_ =
        vmcast<JSArray>(stackJO_->pop_back(runtime_).getObject(runtime_));

    if (LLVM_UNLIKELY(result == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }

    if (LLVM_UNLIKELY(!result.getValue())) {
                                                     
      output_.resize(savedLocation);
    } else {
      hasElement = true;
    }
  }
                                                                
                                              
  depthCount_ = stepBack;

  if (hasElement) {
    indent();
  } else {
                                                                     
    output_.resize(beginningLoc);
  }
  output_.push_back(u'}');
  return ExecutionStatus::RETURNED;
}

void JSONStringifyer::indent() {
  if (gap_.get()) {
    output_.push_back(u'\n');
    for (uint32_t i = 0; i < depthCount_; ++i) {
      appendToOutput(gap_.get());
    }
  }
}

CallResult<bool> JSONStringifyer::pushValueToStack(HermesValue value) {
  assert(vmisa<JSObject>(value) && "Can only push object to stack");

  for (uint32_t i = 0, len = stackValue_->size(); i < len; ++i) {
    if (stackValue_->at(i).getObject(runtime_) == value.getObject()) {
      return false;
    }
  }

  tmpHandle_ = value;
  if (PropStorage::push_back(stackValue_, runtime_, tmpHandle_) ==
      ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  return true;
}

void JSONStringifyer::popValueFromStack() {
  assert(stackValue_->size() && "Cannot pop from an empty stack");
  stackValue_->pop_back(runtime_);
}

void JSONStringifyer::appendToOutput(SymbolID identifierID) {
  appendToOutput(runtime_.getStringPrimFromSymbolID(identifierID));
}

void JSONStringifyer::appendToOutput(const StringPrimitive *str) {
  str->appendUTF16String(output_);
}

CallResult<HermesValue> JSONStringifyer::stringify(Handle<> value) {
                                                             
                             
  output_.clear();

                                 
  operationStrHolder_ = JSObject::create(runtime_).get();
  auto status = JSObject::defineOwnProperty(
      operationStrHolder_,
      runtime_,
      Predefined::getSymbolID(Predefined::emptyString),
      DefinePropertyFlags::getDefaultNewPropertyFlags(),
      value);
  assert(
      status != ExecutionStatus::EXCEPTION && *status &&
      "defineOwnProperty on a newly created object cannot fail");
  (void)status;

                              
  status = operationStr(
      HermesValue::encodeStringValue(
          runtime_.getPredefinedString(Predefined::emptyString)));
  if (LLVM_UNLIKELY(status == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if (status.getValue()) {
    return StringPrimitive::create(runtime_, output_);
  } else {
    return HermesValue::encodeUndefinedValue();
  }
}

CallResult<HermesValue> runtimeJSONStringify(
    Runtime &runtime,
    Handle<> value,
    Handle<> replacer,
    Handle<> space) {
  GCScope gcScope{runtime, "runtimeJSONStringify"};

  JSONStringifyer stringifyer{runtime};
  if (stringifyer.init(replacer, space) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  return stringifyer.stringify(value);
}

}                
}                    

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_OPERATIONS_H
#define HERMES_VM_OPERATIONS_H

#include "hermes/VM/BigIntPrimitive.h"
#include "hermes/VM/CallResult.h"
#include "hermes/VM/InternalProperty.h"
#include "hermes/VM/Runtime.h"
#include "hermes/VM/StringPrimitive.h"
#include "hermes/VM/SymbolID.h"

#include "llvh/ADT/SmallVector.h"

namespace hermes {
namespace vm {

union DefinePropertyFlags;
class Runtime;

               
                                                                   
enum class PreferredType {
  NONE,
  STRING,
  NUMBER,
};

               
CallResult<HermesValue>
toPrimitive_RJS(Runtime &runtime, Handle<> valueHandle, PreferredType hint);

               
                                                                        
                                            
CallResult<HermesValue> ordinaryToPrimitive(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    PreferredType preferredType);

             
bool toBoolean(HermesValue value);

             
CallResult<HermesValue> toNumber_RJS(Runtime &runtime, Handle<> valueHandle);

                                  
CallResult<HermesValue> toNumeric_RJS(Runtime &runtime, Handle<> valueHandle);

              
CallResult<HermesValue> toLength(Runtime &runtime, Handle<> valueHandle);

                                                 
CallResult<uint64_t> toLengthU64(Runtime &runtime, Handle<> valueHandle);

                  
CallResult<HermesValue> toIndex(Runtime &runtime, Handle<> valueHandle);

                 
CallResult<HermesValue> toIntegerOrInfinity(
    Runtime &runtime,
    Handle<> valueHandle);

             
CallResult<HermesValue> toInt8(Runtime &runtime, Handle<> valueHandle);

             
CallResult<HermesValue> toInt16(Runtime &runtime, Handle<> valueHandle);

             
CallResult<HermesValue> toInt32_RJS(Runtime &runtime, Handle<> valueHandle);

              
CallResult<HermesValue> toUInt8(Runtime &runtime, Handle<> valueHandle);

              
uint8_t toUInt8Clamp(double number);
CallResult<HermesValue> toUInt8Clamp(Runtime &runtime, Handle<> valueHandle);

             
CallResult<HermesValue> toUInt16(Runtime &runtime, Handle<> valueHandle);

             
CallResult<HermesValue> toUInt32_RJS(Runtime &runtime, Handle<> valueHandle);

             
CallResult<PseudoHandle<StringPrimitive>> toString_RJS(
    Runtime &runtime,
    Handle<> valueHandle);

             
inline bool isPropertyKey(Handle<> valueHandle) {
  return valueHandle->isString() || valueHandle->isSymbol();
}

              
inline CallResult<Handle<>> toPropertyKey(
    Runtime &runtime,
    Handle<> valueHandle) {
  CallResult<HermesValue> primRes =
      toPrimitive_RJS(runtime, valueHandle, PreferredType::STRING);
  if (LLVM_UNLIKELY(primRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<> prim = runtime.makeHandle(*primRes);
  if (prim->isSymbol()) {
    return prim;
  }
  CallResult<PseudoHandle<StringPrimitive>> strRes =
      toString_RJS(runtime, prim);
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return Handle<>::vmcast(runtime.makeHandle(std::move(*strRes)));
}

                                                                          
                                                                          
                                                                       
           
                                                                      
                                                                              
inline CallResult<Handle<>> toPropertyKeyIfObject(
    Runtime &runtime,
    Handle<> valueHandle) {
  if (LLVM_UNLIKELY(valueHandle->isObject())) {
    return toPropertyKey(runtime, valueHandle);
  }
  return valueHandle;
}

                                            
CallResult<Handle<JSObject>> getPrimitivePrototype(
    Runtime &runtime,
    Handle<> base);

             
CallResult<HermesValue> toObject(Runtime &runtime, Handle<> valueHandle);

                                                                           
                                                                     
                                                                     
                                                        
                                                                        
                               
                                                          
ExecutionStatus amendPropAccessErrorMsgWithPropName(
    Runtime &runtime,
    Handle<> valueHandle,
    llvh::StringRef operationStr,
    SymbolID id);

                                 
                                                  
inline ExecutionStatus checkObjectCoercible(
    Runtime &runtime,
    Handle<> valueHandle) {
  if (LLVM_UNLIKELY(valueHandle->isUndefined() || valueHandle->isNull())) {
    return runtime.raiseTypeError("Value not coercible to object");
  }
  return ExecutionStatus::RETURNED;
}

                
                                  
bool isSameValue(HermesValue x, HermesValue y);

                                                                  
bool isSameValueZero(HermesValue x, HermesValue y);

                 
CallResult<bool>
lessOp_RJS(Runtime &runtime, Handle<> leftHandle, Handle<> rightHandle);
                 
CallResult<bool>
greaterOp_RJS(Runtime &runtime, Handle<> leftHandle, Handle<> rightHandle);
                 
CallResult<bool>
lessEqualOp_RJS(Runtime &runtime, Handle<> leftHandle, Handle<> rightHandle);
                 
CallResult<bool>
greaterEqualOp_RJS(Runtime &runtime, Handle<> leftHandle, Handle<> rightHandle);

                                            
CallResult<bool>
abstractEqualityTest_RJS(Runtime &runtime, Handle<> xHandle, Handle<> yHandle);

                
bool strictEqualityTest(HermesValue x, HermesValue y);

                                                
CallResult<Handle<SymbolID>> stringToSymbolID(
    Runtime &runtime,
    PseudoHandle<StringPrimitive> strPrim);

                                               
CallResult<Handle<SymbolID>> valueToSymbolID(
    Runtime &runtime,
    Handle<> nameValHnd);

                                                                            
                      
HermesValue typeOf(Runtime &runtime, Handle<> valueHandle);

                                                            
                                                                              
                                                                               
            
OptValue<uint32_t> toArrayIndex(
    Runtime &runtime,
    Handle<StringPrimitive> strPrim);

                                                                            
OptValue<uint32_t> toArrayIndex(StringView str);

                                                                       
                                                                               
                                                        
OptValue<uint32_t> toArrayIndexFastPath(HermesValue value)
    LLVM_NO_SANITIZE("float-cast-overflow");
inline OptValue<uint32_t> toArrayIndexFastPath(HermesValue value) {
  if (value.isNumber()) {
    return hermes::doubleToArrayIndex(value.getNumber());
  }
  return llvh::None;
}

                                                                                
                                                                  
bool isPrimitive(HermesValue val);

                
CallResult<HermesValue>
addOp_RJS(Runtime &runtime, Handle<> xHandle, Handle<> yHandle);

                
inline double expOp(double x, double y) {
  constexpr double nan = std::numeric_limits<double>::quiet_NaN();

                                                            
  if (std::isnan(y)) {
    return nan;
  } else if (y == 0) {
    return 1;
  } else if (std::abs(x) == 1 && std::isinf(y)) {
    return nan;
  }

                                                                      
  return std::pow(x, y);
}

             
inline bool isWhiteSpaceChar(char16_t c) {
  return c == u'\u0009' || c == u'\u000B' || c == u'\u000C' || c == u'\u0020' ||
      c == u'\u00A0' || c == u'\uFEFF' || c == u'\u1680' ||
      (c >= u'\u2000' && c <= u'\u200A') || c == u'\u202F' || c == u'\u205F' ||
      c == u'\u3000';
}

             
inline bool isLineTerminatorChar(char16_t c) {
  return c == u'\u000A' || c == u'\u000D' || c == u'\u2028' || c == u'\u2029';
}

                                                       
inline char16_t letterToLower(char16_t c) {
  return c | 32;
}

                                                                            
                      
                                                         
double parseIntWithRadix(const StringView str, int radix);

                                                                         
                                                                             
                                   
                                                                          
                                                                               
                                        
                                     
Handle<StringPrimitive>
numberToStringWithRadix(Runtime &runtime, double number, unsigned radix);

               
CallResult<PseudoHandle<>>
getMethod(Runtime &runtime, Handle<> O, Handle<> key);

                                           
                                                                          
struct IteratorRecord {
                             
  const Handle<JSObject> iterator;

                                                               
  const Handle<Callable> nextMethod;

  IteratorRecord(Handle<JSObject> iterator, Handle<Callable> nextMethod)
      : iterator(iterator), nextMethod(nextMethod) {}
};

               
                                      
                                                                              
                               
CallResult<IteratorRecord> getIterator(
    Runtime &runtime,
    Handle<> obj,
    llvh::Optional<Handle<Callable>> method = llvh::None);

               
CallResult<PseudoHandle<JSObject>> iteratorNext(
    Runtime &runtime,
    const IteratorRecord &iteratorRecord,
    llvh::Optional<Handle<>> value = llvh::None);

               
                                       
CallResult<PseudoHandle<HermesValue>> iteratorValue(
    Runtime &runtime,
    Handle<JSObject> iterResult);

                
                                                        
CallResult<Handle<JSObject>> iteratorStep(
    Runtime &runtime,
    const IteratorRecord &iteratorRecord);

                        
                                                                                
               
ExecutionStatus
iteratorClose(Runtime &runtime, Handle<JSObject> iterator, Handle<> completion);

                                                                  
                                     
CallResult<Handle<JSArray>> iterableToArray(
    Runtime &runtime,
    Handle<HermesValue> items);

                                                                
                                                                                
                       
                                                                              
          
bool isUncatchableError(HermesValue value);

               
Handle<JSObject>
createIterResultObject(Runtime &runtime, Handle<> value, bool done);

              
CallResult<Handle<Callable>> speciesConstructor(
    Handle<JSObject> O,
    Runtime &runtime,
    Handle<Callable> defaultConstructor);

             
                                                                    
             
CallResult<bool> isConstructor(Runtime &runtime, HermesValue value);

             
                                                                     
                                  
CallResult<bool> isConstructor(Runtime &runtime, Callable *callable);

               
                                                                                
                      
CallResult<bool> isRegExp(Runtime &runtime, Handle<> arg);

                
CallResult<bool>
ordinaryHasInstance(Runtime &runtime, Handle<> constructor, Handle<> object);

                
                                                 
                                                                  
inline void utf16Encoding(
    uint32_t cp,
    llvh::SmallVectorImpl<char16_t> &output) {
                               
  assert(cp <= 0x10FFFF && "Invalid input to UTF16Encoding");
                              
  if (cp <= 65535) {
    output.push_back((char16_t)cp);
    return;
  }
                                                    
                                                      
  char16_t cu1 = (char16_t)(((cp - 65536) / 1024) + 0xD800);
                                                    
  char16_t cu2 = (char16_t)(((cp - 65536) % 1024) + 0xDC00);
                                                                     
  output.push_back(cu1);
  output.push_back(cu2);
}

                
                                                                         
                              
inline uint32_t utf16Decode(char16_t lead, char16_t trail) {
                                                                
  assert(
      0xD800 <= lead && lead <= 0xDBFF && 0xDC00 <= trail && trail <= 0xDFFF &&
      "Invalid input to UTF16Decode");
                                                                   
                              
  uint32_t c1 = lead - 0xD800;
  uint32_t c2 = trail - 0xDC00;
  return c1 * 1024 + c2 + 0x10000;
}

                
CallResult<bool>
instanceOfOperator_RJS(Runtime &runtime, Handle<> object, Handle<> constructor);

                                                                       
                                                   
CallResult<Handle<StringPrimitive>> symbolDescriptiveString(
    Runtime &runtime,
    Handle<SymbolID> sym);

             
CallResult<bool> isArray(Runtime &runtime, JSObject *obj);

                    
CallResult<bool> isConcatSpreadable(Runtime &runtime, Handle<> value);

                                                                          
                    
constexpr bool isSymbolPrimitive(SymbolID id) {
  return id.isNotUniqued() && !InternalProperty::isInternal(id);
}

                                                                          
                  
constexpr bool isPropertyNamePrimitive(SymbolID id) {
  return id.isUniqued();
}

                                                                     
                                                                       
ExecutionStatus toPropertyDescriptor(
    Handle<> obj,
    Runtime &runtime,
    DefinePropertyFlags &flags,
    MutableHandle<> &valueOrAccessor);

                                      
                                                                
                                                                              
                                                                           
                                                                                
                                                                     
                                                                          
                                                                   
CallResult<HermesValue> objectFromPropertyDescriptor(
    Runtime &runtime,
    DefinePropertyFlags dpFlags,
    Handle<> valueOrAccessor);

                                            
CallResult<HermesValue> numberToBigInt(Runtime &runtime, double number);

                                          
bool isIntegralNumber(double number);

                                   
CallResult<HermesValue> toBigInt_RJS(Runtime &runtime, Handle<> value);

                               
CallResult<HermesValue> stringToBigInt(Runtime &runtime, Handle<> value);

                                                                            
CallResult<HermesValue> thisBigIntValue(Runtime &runtime, Handle<> value);

                                                      
                                                                          
                                                                        
                                                                              
                                                                               
                                               
bool hasRestrictedGlobalProperty(Runtime &runtime, SymbolID N);

}                
}                    

#endif                          

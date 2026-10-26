/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_STRINGBUILDER_H
#define HERMES_VM_STRINGBUILDER_H

#include "hermes/ADT/SafeInt.h"
#include "hermes/VM/Casting.h"
#include "hermes/VM/Runtime.h"
#include "hermes/VM/StringPrimitive.h"

namespace hermes {
namespace vm {

                                                                              
                               
                                                               
                                                                         
                                                              
                                                                            
                                                                              
                                                                               
                                                                             
                                                                          
                                             
class StringBuilder {
                                                        
  MutableHandle<StringPrimitive> strPrim_;

                              
  uint32_t index_;

                                                                             
                                                              
  Runtime *runtime_;

 public:
  static CallResult<StringBuilder> createStringBuilder(
      Runtime &runtime,
      SafeUInt32 length,
      bool isASCII = false) {
    if (length.isOverflowed()) {
      return runtime.raiseRangeError("String length exceeds limit");
    }
    auto crtRes = StringPrimitive::create(runtime, *length, isASCII);
    if (LLVM_UNLIKELY(crtRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    return StringBuilder(runtime, crtRes->getString());
  }

                                                                   
  uint32_t currentLength() const {
    return index_;
  }

                                                                                
                  
  uint32_t maxLength() const {
    return strPrim_->getStringLength();
  }

                                                                               
                                                      
  void appendUTF16Ref(UTF16Ref str) {
    assert(
        index_ + str.size() <= strPrim_->getStringLength() &&
        "StringBuilder append out of bound");
    if (LLVM_UNLIKELY((*strPrim_)->isASCII())) {
                                                                            
                                                                  
                                                                         
                                                                              
      auto strRes = runtime_->ignoreAllocationFailure(
          StringPrimitive::create(
              *runtime_, strPrim_->getStringLength(),                   false));
      auto currentPartialString =
          ASCIIRef(strPrim_->castToASCIIPointer(), index_);
      strPrim_ = strRes.getString();
      index_ = 0;
      appendASCIIRef(currentPartialString);
    }
    std::copy(
        str.data(),
        str.data() + str.size(),
        strPrim_->castToUTF16PointerForWrite() + index_);
    index_ += str.size();
  }

  void appendASCIIRef(ASCIIRef ascii) {
    assert(
        index_ + ascii.size() <= strPrim_->getStringLength() &&
        "StringBuilder append out of bound");
    if (LLVM_LIKELY(strPrim_->isASCII())) {
      std::copy(
          ascii.data(),
          ascii.data() + ascii.size(),
          strPrim_->castToASCIIPointerForWrite() + index_);
    } else {
      std::copy(
          ascii.data(),
          ascii.data() + ascii.size(),
          strPrim_->castToUTF16PointerForWrite() + index_);
    }
    index_ += ascii.size();
  }

                                        
  void appendCharacter(char16_t ch) {
    assert(
        index_ + 1 <= strPrim_->getStringLength() &&
        "StringBuilder append out of bound");
    if (strPrim_->isASCII()) {
      if (ch < 128) {
        strPrim_->castToASCIIPointerForWrite()[index_++] = ch;
      } else {
                                                                         
                                         
        appendUTF16Ref(ch);
      }
    } else {
      strPrim_->castToUTF16PointerForWrite()[index_++] = ch;
    }
  }

                                                                          
  void appendStringPrim(Handle<StringPrimitive> other, uint32_t length) {
    assert(
        index_ + length <= strPrim_->getStringLength() &&
        "StringBuilder append out of bound");
    if (other->isASCII()) {
      appendASCIIRef({other->castToASCIIPointer(), length});
    } else if (!strPrim_->isASCII()) {
      appendUTF16Ref({other->castToUTF16Pointer(), length});
    } else {
                                                                             
      auto strRes = runtime_->ignoreAllocationFailure(
          StringPrimitive::create(
              *runtime_, strPrim_->getStringLength(),                   false));
      auto currentPartialString =
          ASCIIRef(strPrim_->castToASCIIPointer(), index_);
                                                  
      strPrim_ = strRes.getString();
      index_ = 0;
                                          
      appendASCIIRef(currentPartialString);
      appendUTF16Ref({other->castToUTF16Pointer(), length});
    }
  }

                                                          
  void appendStringPrim(Handle<StringPrimitive> other) {
    return appendStringPrim(other, other->getStringLength());
  }

                                                           
  Handle<StringPrimitive> getStringPrimitive() const {
    assert(
        index_ == strPrim_->getStringLength() &&
        "String content is not fully filled yet.");
    return Handle<StringPrimitive>::vmcast(strPrim_);
  }

 private:
  StringBuilder(Runtime &runtime, StringPrimitive *strPrim)
      : strPrim_(runtime, strPrim), index_(0), runtime_(&runtime) {}
};

}                
}                    

#endif

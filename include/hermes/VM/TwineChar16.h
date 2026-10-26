/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_TWINECHAR16_H
#define HERMES_SUPPORT_TWINECHAR16_H

#include <cassert>

#include "hermes/Support/Conversions.h"
#include "hermes/VM/StringRefUtils.h"

namespace llvh {
class raw_ostream;
class raw_svector_ostream;
}                  

namespace hermes {
namespace vm {

class StringPrimitive;

                                                                              
                                                                                
                                                                           
   
                                                                               
                                                                          
                                                                             
                                                                       
                                                                             
                                                                                
   
                                                                     
                                                                           
                                                                          
                                                                       
                                                                         
                                                             
                                                             
   
                                                                             
                                                                              
                                                                                
                                                                                
                                                                              
                
   
                                                                           
                              
class TwineChar16 {
 private:
                                             
  enum NodeKind {
                                                                     
    NullKind,
                                      
    EmptyKind,
                      
    TwineKind,
                    
    CharStrKind,
                        
    Char16StrKind,
                                     
    StringPrimitiveKind,
               
    Int32Kind,
                        
    Unsigned32Kind,
                      
    DoubleKind,
  };

                             
  union Node {
    const TwineChar16 *twine;

                         
    const char *charStr;

                                           
    const char16_t *char16Str;

    const StringPrimitive *stringPrimitive;

    int32_t int32;
    uint32_t uint32;
    double flt;
  };

                                            
                                                                       
  Node leftChild_;
  NodeKind leftKind_;

                                             
                                                               
  Node rightChild_;
  NodeKind rightKind_;

                                                      
  size_t leftSize_;
  size_t rightSize_;

 public:
                          
  TwineChar16()
      : leftKind_(EmptyKind),
        rightKind_(EmptyKind),
        leftSize_(0),
        rightSize_(0) {
    assert(isValid());
  }

  TwineChar16(const TwineChar16 &other) = default;

  TwineChar16(const char *str) : TwineChar16(llvh::StringRef(str)) {}

                                                     
  TwineChar16(const llvh::StringRef str)
      : rightKind_(EmptyKind), leftSize_(str.size()), rightSize_(0) {
    if (str.size() == 0) {
      leftKind_ = EmptyKind;
    } else {
      leftChild_.charStr = str.begin();
      leftKind_ = CharStrKind;
    }
    assert(isValid());
  }

                                                     
  TwineChar16(const char16_t *str)
      : rightKind_(EmptyKind),
        leftSize_(utf16_traits::length(str)),
        rightSize_(0) {
    if (leftSize_ == 0) {
      leftKind_ = EmptyKind;
    } else {
      leftChild_.char16Str = str;
      leftKind_ = Char16StrKind;
    }
    assert(isValid());
  }

                                       
  TwineChar16(const UTF16Ref str)
      : leftKind_(Char16StrKind),
        rightKind_(EmptyKind),
        leftSize_(str.size()),
        rightSize_(0) {
    leftChild_.char16Str = str.begin();
    assert(isValid());
  }

                                              
  TwineChar16(const StringPrimitive *str);

                                      
  TwineChar16(const int32_t i)
      : leftKind_(Int32Kind), rightKind_(EmptyKind), rightSize_(0) {
                                                                       
    leftSize_ = ::snprintf(nullptr, 0, "%" PRId32, i);
    leftChild_.int32 = i;
    assert(isValid());
  }

  TwineChar16(const uint32_t i)
      : leftKind_(Unsigned32Kind), rightKind_(EmptyKind), rightSize_(0) {
                                                                       
    leftSize_ = ::snprintf(nullptr, 0, "%" PRIu32, i);
    leftChild_.uint32 = i;
    assert(isValid());
  }

  TwineChar16(const double f)
      : leftKind_(DoubleKind), rightKind_(EmptyKind), rightSize_(0) {
    char buf[NUMBER_TO_STRING_BUF_SIZE];
                                                  
    leftSize_ = numberToString(f, buf, sizeof(buf));
    leftChild_.flt = f;
    assert(isValid());
  }

                                                                           
  TwineChar16(const llvh::StringRef left, const char16_t *right)
      : leftKind_(CharStrKind),
        rightKind_(Char16StrKind),
        leftSize_(left.size()),
        rightSize_(utf16_traits::length(right)) {
    leftChild_.charStr = left.begin();
    rightChild_.char16Str = right;
    assert(isValid());
  }

                                                                           
  TwineChar16(const char16_t *left, const llvh::StringRef right)
      : leftKind_(Char16StrKind),
        rightKind_(CharStrKind),
        leftSize_(utf16_traits::length(left)),
        rightSize_(right.size()) {
    leftChild_.char16Str = left;
    rightChild_.charStr = right.begin();
    assert(isValid());
  }

                                                                           
  TwineChar16(const char16_t *left, const char16_t *right)
      : leftKind_(Char16StrKind),
        rightKind_(Char16StrKind),
        leftSize_(utf16_traits::length(left)),
        rightSize_(utf16_traits::length(right)) {
    leftChild_.char16Str = left;
    rightChild_.char16Str = right;
    assert(isValid());
  }

                                                             
  TwineChar16(const UTF16Ref left, const UTF16Ref right)
      : leftKind_(Char16StrKind),
        rightKind_(Char16StrKind),
        leftSize_(left.size()),
        rightSize_(right.size()) {
    leftChild_.char16Str = left.begin();
    rightChild_.char16Str = right.begin();
    assert(isValid());
  }

                                                                           
  TwineChar16(const UTF16Ref left, const char16_t *right)
      : leftKind_(Char16StrKind),
        rightKind_(Char16StrKind),
        leftSize_(left.size()),
        rightSize_(utf16_traits::length(right)) {
    leftChild_.char16Str = left.begin();
    rightChild_.char16Str = right;
    assert(isValid());
  }

                                                                           
  TwineChar16(const char16_t *left, const UTF16Ref right)
      : leftKind_(Char16StrKind),
        rightKind_(Char16StrKind),
        leftSize_(utf16_traits::length(left)),
        rightSize_(right.size()) {
    leftChild_.char16Str = left;
    rightChild_.char16Str = right.begin();
    assert(isValid());
  }

                                                                         
  TwineChar16(const llvh::StringRef left, const int32_t right)
      : leftKind_(CharStrKind), rightKind_(Int32Kind), leftSize_(left.size()) {
                                                                           
    rightSize_ = ::snprintf(nullptr, 0, "%" PRId32, right);
    leftChild_.charStr = left.begin();
    rightChild_.int32 = right;
    assert(isValid());
  }

                              
  static inline TwineChar16 createNull() {
    return TwineChar16(NullKind);
  }

                                                                      
                                        
  TwineChar16 concat(const TwineChar16 &other) const;

                                                         
  inline size_t size() const {
    assert(isValid());
    return leftSize_ + rightSize_;
  }

                                                              
  inline bool empty() const {
    assert(isValid());
    return size() == 0;
  }

                                                                
                                                                         
                                                  
                                                             
                                              
  size_t toChar16Str(char16_t *out, size_t maxlen) const;

                                                               
                                                                         
  void toVector(llvh::SmallVectorImpl<char16_t> &out) const;

                                                             
  void print(llvh::raw_ostream &os) const;

 private:
                                                        
  TwineChar16(NodeKind kind)
      : leftKind_(kind), rightKind_(EmptyKind), leftSize_(0), rightSize_(0) {
    assert(isNullary());
    assert(isValid());
  }

                          
  TwineChar16(const TwineChar16 &left, const TwineChar16 &right)
      : leftKind_(TwineKind),
        rightKind_(TwineKind),
        leftSize_(left.size()),
        rightSize_(right.size()) {
    leftChild_.twine = &left;
    rightChild_.twine = &right;
    assert(isValid());
  }

                                        
  TwineChar16(
      Node leftChild,
      NodeKind leftKind,
      size_t leftLen,
      Node rightChild,
      NodeKind rightKind,
      size_t rightLen)
      : leftChild_(leftChild),
        leftKind_(leftKind),
        rightChild_(rightChild),
        rightKind_(rightKind),
        leftSize_(leftLen),
        rightSize_(rightLen) {
    assert(isValid());
  }

                                                         
  TwineChar16 &operator=(const TwineChar16 &other) = delete;

                                             
  inline bool isNull() const {
    return leftKind_ == NullKind;
  }

                                              
  inline bool isEmpty() const {
    return leftKind_ == EmptyKind;
  }

                                                    
  inline bool isNullary() const {
    return isNull() || isEmpty();
  }

                                                      
  inline bool isUnary() const {
    return !isNullary() && rightKind_ == EmptyKind;
  }

                                                    
  inline bool isBinary() const {
    return leftKind_ != NullKind && rightKind_ != EmptyKind;
  }

                                                         
  inline bool isValid() const {
                                                               
    if (rightKind_ == NullKind) {
      fprintf(stderr, "null right\n");
      return false;
    }

                                                     
    if (isNullary() && rightKind_ != EmptyKind) {
      fprintf(stderr, "nullary with nonempty right\n");
      return false;
    }

                                                                     
    if (leftKind_ == EmptyKind && rightKind_ != EmptyKind) {
      fprintf(stderr, "left empty, right not\n");
      return false;
    }

                                                               
    if ((leftKind_ == TwineKind && !leftChild_.twine->isBinary()) ||
        (rightKind_ == TwineKind && !rightChild_.twine->isBinary())) {
      fprintf(stderr, "non-binary twine child\n");
      return false;
    }

    return true;
  }
};

inline TwineChar16 TwineChar16::concat(const TwineChar16 &other) const {
  assert(isValid());
  assert(other.isValid());
  if (isNull() || other.isNull()) {
    return TwineChar16::createNull();
  }

                                                               
  if (isEmpty()) {
    return other;
  }
  if (other.isEmpty()) {
    return *this;
  }

                                               
  Node newLeft;
  newLeft.twine = this;
  NodeKind newLeftKind = TwineKind;
  size_t leftLen = size();

  Node newRight;
  newRight.twine = &other;
  NodeKind newRightKind = TwineKind;
  size_t rightLen = other.size();

                                                                      
  if (isUnary()) {
    newLeft = leftChild_;
    newLeftKind = leftKind_;
  }
  if (other.isUnary()) {
    newRight = other.leftChild_;
    newRightKind = other.leftKind_;
  }

  return TwineChar16(
      newLeft, newLeftKind, leftLen, newRight, newRightKind, rightLen);
}

inline TwineChar16 operator+(
    const TwineChar16 &left,
    const TwineChar16 &right) {
  return left.concat(right);
}

inline TwineChar16 operator+(
    const llvh::StringRef left,
    const char16_t *right) {
  return TwineChar16(left, right);
}

inline TwineChar16 operator+(const llvh::StringRef left, const int32_t right) {
  return TwineChar16(left, right);
}

inline llvh::raw_ostream &operator<<(
    llvh::raw_ostream &os,
    const TwineChar16 &other) {
  other.print(os);
  return os;
}

}                
}                    
#endif

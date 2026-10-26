/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_BIGINT_H
#define HERMES_SUPPORT_BIGINT_H

#include "hermes/Support/Compiler.h"

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/Support/MathExtras.h"

#include <deque>
#include <optional>
#include <string>
#include <vector>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace bigint {

enum class ParsedSign {
  Minus = -1,
  None = 0,
  Plus = 1,
};

                                                             
                                           
   
                                                                               
                                                                          
                                                                                
                                                                              
                                             
std::optional<std::string> getStringIntegerLiteralDigitsAndSign(
    llvh::ArrayRef<char> src,
    uint8_t &radix,
    ParsedSign &sign,
    std::string *outError = nullptr);
std::optional<std::string> getStringIntegerLiteralDigitsAndSign(
    llvh::ArrayRef<char16_t> src,
    uint8_t &radix,
    ParsedSign &sign,
    std::string *outError = nullptr);

                                             
                                   
   
                                                                             
                                                                               
                                                                              
                                                     
std::optional<std::string> getNumericValueDigits(
    llvh::StringRef src,
    uint8_t &radix,
    std::string *outError = nullptr);

using SignedBigIntDigitType = int64_t;
using BigIntDigitType = uint64_t;

inline constexpr uint32_t BigIntDigitSizeInBytes =
    static_cast<uint32_t>(sizeof(BigIntDigitType));
inline constexpr uint32_t BigIntDigitSizeInBits = BigIntDigitSizeInBytes * 8;

                                                                
inline constexpr uint32_t BigIntMaxSizeInDigits =
    0x400;                         

                                                               
inline constexpr uint32_t BigIntMaxSizeInBytes =
    BigIntDigitSizeInBytes * BigIntMaxSizeInDigits;

                                                                             
              
inline constexpr bool tooManyDigits(uint32_t numDigits) {
  return BigIntMaxSizeInDigits < numDigits;
}

                                                                         
                                 
inline constexpr bool tooManyBytes(uint32_t numBytes) {
  return BigIntMaxSizeInBytes < numBytes;
}

                                                           
inline uint32_t numDigitsForSizeInBits(uint32_t v) {
  return static_cast<uint32_t>(llvh::alignTo(v, BigIntDigitSizeInBits)) /
      BigIntDigitSizeInBits;
}

                                                            
inline uint32_t numDigitsForSizeInBytes(uint32_t v) {
  return static_cast<uint32_t>(llvh::alignTo(v, BigIntDigitSizeInBytes)) /
      BigIntDigitSizeInBytes;
}

                                                                  
inline uint32_t constexpr maxCharsPerDigitInRadix(uint8_t radix) {
                                                                           
                                                                            
                                                                          
                                                       
  uint32_t minNumBitsPerChar = radix < 4 ? 1
      : radix < 8                        ? 2
      : radix < 16                       ? 3
      : radix < 32                       ? 4
                                         : 5;

                                                                                
                                                                            
                                                                   
  uint32_t numCharsPerDigits = BigIntDigitSizeInBits / (1 << minNumBitsPerChar);

  return numCharsPerDigits;
}

                                                                            
                                                                                
                 
llvh::ArrayRef<uint8_t> dropExtraSignBits(llvh::ArrayRef<uint8_t> src);

                                                                              
                                                                              
                  
template <typename D, typename T, typename UT = std::make_unsigned_t<T>>
inline constexpr std::enable_if_t<std::is_integral_v<T>, D> getSignExtValue(
    const T &value) {
  uint32_t UnsignedTSizeInBits = sizeof(UT) * 8;
  UT unsignedValue = value;

                                                                              
                                                                       
                     
  uint64_t signExtValue = 0ull - (unsignedValue >> (UnsignedTSizeInBits - 1));

                                                                      
  return static_cast<D>(signExtValue);
}

                                                                                
                                      
struct ImmutableBigIntRef {
  const BigIntDigitType *digits;
  uint32_t numDigits;
};

                                                                          
                                                                           
                                                                              
struct MutableBigIntRef {
  BigIntDigitType *digits;
  uint32_t &numDigits;
};

                                                                           
                                                                            
                                                                               
enum class OperationStatus : uint32_t {
  RETURNED,
  DEST_TOO_SMALL,
  TOO_MANY_DIGITS,
  DIVISION_BY_ZERO,
  NEGATIVE_EXPONENT,
} HERMES_ATTRIBUTE_WARN_UNUSED_RESULT_TYPE;

                                                                       
OperationStatus initWithBytes(
    MutableBigIntRef dst,
    llvh::ArrayRef<uint8_t> data);

                                                                     
bool isNegative(ImmutableBigIntRef src);

                                                                
uint32_t fromDoubleResultSize(double src);

                                     
OperationStatus fromDouble(MutableBigIntRef dst, double src);

                                       
OperationStatus toDouble(double &dst, ImmutableBigIntRef src);

                                             
class ParsedBigInt {
  ParsedBigInt(const ParsedBigInt &) = delete;
  ParsedBigInt &operator=(const ParsedBigInt &) = delete;

 public:
  using Storage = std::vector<uint8_t>;

  ParsedBigInt(ParsedBigInt &&) = default;
  ParsedBigInt &operator=(ParsedBigInt &&) = default;

  static std::optional<ParsedBigInt> parsedBigIntFromStringIntegerLiteral(
      llvh::ArrayRef<char> input,
      std::string *outError = nullptr);

  static std::optional<ParsedBigInt> parsedBigIntFromStringIntegerLiteral(
      llvh::ArrayRef<char16_t> input,
      std::string *outError = nullptr);

                                                                              
                                                                               
                                                                               
                                                                            
                
  static std::optional<ParsedBigInt> parsedBigIntFromNumericValue(
      llvh::StringRef input,
      std::string *outError = nullptr);

                                                                            
                                                               
                                 
  llvh::ArrayRef<uint8_t> getBytes() const {
    return dropExtraSignBits(storage_);
  }

  llvh::ArrayRef<uint8_t> getRawDataFull() const {
    return storage_;
  }

 private:
  ParsedBigInt(llvh::ArrayRef<uint8_t> bytes) : storage_(bytes) {}

  Storage storage_;
};

                                                                               
                                                                              
             
class TmpStorage {
  TmpStorage() = delete;
  TmpStorage(const TmpStorage &) = delete;
  TmpStorage(TmpStorage &&) = delete;

  TmpStorage &operator=(const TmpStorage &) = delete;
  TmpStorage &operator=(TmpStorage &&) = delete;

 public:
  explicit TmpStorage(uint32_t sizeInDigits)
      : storage_(sizeInDigits), data_(storage_.begin()) {}

  ~TmpStorage() = default;

                                                                   
  BigIntDigitType *requestNumDigits(uint32_t size) {
    BigIntDigitType *ret = data_;
    data_ += size;
    assert(data_ <= storage_.end() && "too many temporary digits requested.");
    return ret;
  }

 private:
  static constexpr uint32_t MaxStackTmpStorageInDigits = 4;
  llvh::SmallVector<BigIntDigitType, MaxStackTmpStorageInDigits> storage_;

  BigIntDigitType *data_;
};

                                                
std::string toString(ImmutableBigIntRef src, uint8_t radix);

                                                        
OperationStatus
toString(std::string &out, llvh::ArrayRef<uint8_t> bytes, uint8_t radix);

                                                                              
                                
                                                                              
                                                          
OperationStatus
asUintNResultSize(uint64_t n, ImmutableBigIntRef src, uint32_t &resultSize);

                                                 
OperationStatus
asUintN(MutableBigIntRef dst, uint64_t n, ImmutableBigIntRef src);

                                                                    
uint32_t asIntNResultSize(uint64_t n, ImmutableBigIntRef src);

                                                                              
OperationStatus
asIntN(MutableBigIntRef dst, uint64_t n, ImmutableBigIntRef src);

                                                                             
                 
int compare(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs);
int compare(ImmutableBigIntRef lhs, SignedBigIntDigitType rhs);

                                                                  
                                                                          
                                      
bool isSingleDigitTruncationLossless(
    ImmutableBigIntRef src,
    bool signedTruncation);

                                                                  
inline BigIntDigitType truncateToSingleDigit(ImmutableBigIntRef src) {
  return src.numDigits == 0 ? 0 : src.digits[0];
}

                                                       
uint32_t unaryMinusResultSize(ImmutableBigIntRef src);

                             
OperationStatus unaryMinus(MutableBigIntRef dst, ImmutableBigIntRef src);

                                                       
uint32_t unaryNotResultSize(ImmutableBigIntRef src);

                              
OperationStatus unaryNot(MutableBigIntRef dst, ImmutableBigIntRef src);

                                                              
uint32_t addResultSize(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs);

                                    
OperationStatus
add(MutableBigIntRef dst, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs);

                                                               
uint32_t addSignedResultSize(
    ImmutableBigIntRef lhs,
    SignedBigIntDigitType sImm);

                                     
OperationStatus addSigned(
    MutableBigIntRef dst,
    ImmutableBigIntRef lhs,
    SignedBigIntDigitType sImm);

                                                              
uint32_t subtractResultSize(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs);

                                    
OperationStatus
subtract(MutableBigIntRef dst, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs);

                                                               
uint32_t subtractSignedResultSize(
    ImmutableBigIntRef lhs,
    SignedBigIntDigitType sImm);

                                     
OperationStatus subtractSigned(
    MutableBigIntRef dst,
    ImmutableBigIntRef lhs,
    SignedBigIntDigitType sImm);

                                                                        
             
uint32_t multiplyResultSize(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs);

                                                     
OperationStatus
multiply(MutableBigIntRef dst, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs);

                                                              
uint32_t divideResultSize(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs);

                                    
OperationStatus
divide(MutableBigIntRef dst, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs);

                                                              
uint32_t remainderResultSize(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs);

                                    
OperationStatus
remainder(MutableBigIntRef dst, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs);

                                     
                                                                         
                                                                             
                                                                                
                                                  
OperationStatus exponentiate(
    MutableBigIntRef dst,
    ImmutableBigIntRef lhs,
    ImmutableBigIntRef rhs);

                                                              
uint32_t bitwiseANDResultSize(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs);

                           
OperationStatus bitwiseAND(
    MutableBigIntRef dst,
    ImmutableBigIntRef lhs,
    ImmutableBigIntRef rhs);

                                                              
uint32_t bitwiseORResultSize(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs);

                                    
OperationStatus
bitwiseOR(MutableBigIntRef dst, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs);

                                                              
uint32_t bitwiseXORResultSize(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs);

                                    
OperationStatus bitwiseXOR(
    MutableBigIntRef dst,
    ImmutableBigIntRef lhs,
    ImmutableBigIntRef rhs);

                                                               
uint32_t leftShiftResultSize(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs);

                                     
OperationStatus
leftShift(MutableBigIntRef dst, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs);

                                                               
uint32_t signedRightShiftResultSize(
    ImmutableBigIntRef lhs,
    ImmutableBigIntRef rhs);

                                  
OperationStatus signedRightShift(
    MutableBigIntRef dst,
    ImmutableBigIntRef lhs,
    ImmutableBigIntRef rhs);

                                                                          
using BigIntBytes = std::vector<uint8_t>;

                                                                          
                                  
struct BigIntTableEntry {
  uint32_t offset;
  uint32_t length;
};

inline bool operator==(
    const BigIntTableEntry &lhs,
    const BigIntTableEntry &rhs) {
  return lhs.offset == rhs.offset && lhs.length == rhs.length;
}

                                                     
class UniquingBigIntTable {
                                                                          
                                                           
  std::deque<ParsedBigInt> bigints_;

  using KeyType = llvh::ArrayRef<uint8_t>;

                                              
                                                            
  llvh::DenseMap<KeyType, uint32_t> keysToIndex_;

                                              
  UniquingBigIntTable(const UniquingBigIntTable &) = delete;
  void operator=(const UniquingBigIntTable &) = delete;

 public:
  UniquingBigIntTable() = default;

                                                        
                                   
  uint32_t addBigInt(ParsedBigInt bigint) {
    auto iter = keysToIndex_.find(keyFor(bigint));
    if (iter != keysToIndex_.end()) {
      return iter->second;
    }

    const uint32_t index = bigints_.size();
    bigints_.push_back(std::move(bigint));
    keysToIndex_[keyFor(bigints_.back())] = index;
    return index;
  }

                                         
  bool empty() const {
    return bigints_.empty();
  }

                                   
  std::vector<BigIntTableEntry> getEntryList() const;

                                          
  BigIntBytes getDigitsBuffer() const;

 private:
  static KeyType keyFor(const ParsedBigInt &parsedBigInt) {
    return parsedBigInt.getBytes();
  }
};

}                    
}                    
#pragma GCC diagnostic pop

#endif                           

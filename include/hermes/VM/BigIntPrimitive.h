/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_BIGINTPRIMITIVE_H
#define HERMES_VM_BIGINTPRIMITIVE_H

#include "hermes/VM/Runtime.h"

#include "hermes/Support/BigIntSupport.h"
#include "hermes/VM/CallResult.h"
#include "hermes/VM/Handle.h"

#include "llvh/ADT/ArrayRef.h"
#include "llvh/Support/MathExtras.h"
#include "llvh/Support/TrailingObjects.h"
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {
                                                                           
class BigIntPrimitive final
    : public VariableSizeRuntimeCell,
      private llvh::TrailingObjects<BigIntPrimitive, bigint::BigIntDigitType> {
 public:
  using DigitType = bigint::BigIntDigitType;
  static constexpr uint32_t DigitSizeInBytes = bigint::BigIntDigitSizeInBytes;
  static_assert(
      llvh::isPowerOf2_64(DigitSizeInBytes),
      "DigitSizeInBytes is not power of 2.");

 private:
  friend class llvh::TrailingObjects<BigIntPrimitive, DigitType>;

  friend void BigIntPrimitiveBuildMeta(
      const GCCell *cell,
      Metadata::Builder &mb);

                                                           
  uint32_t numDigits;

                                                                        
                       
  uint32_t numTrailingBytes() const {
    return numDigits * DigitSizeInBytes;
  }

  static const VTable vt;

                                                                                
                                                                    
                       
  static uint32_t calcCellSizeInBytes(uint32_t numDigits);

 public:
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::BigIntPrimitiveKind;
  }

  static constexpr CellKind getCellKind() {
    return CellKind::BigIntPrimitiveKind;
  }

                                                                               
                                          
  template <typename T>
  static std::enable_if_t<std::is_signed<T>::value, Handle<BigIntPrimitive>>
  fromSignedNoThrow(Runtime &runtime, T value) {
    return runtime.makeHandle<BigIntPrimitive>(
        runtime.ignoreAllocationFailure(fromSigned(runtime, value)));
  }

                                                                               
               
  template <typename T>
  static std::enable_if_t<std::is_signed<T>::value, CallResult<HermesValue>>
  fromSigned(Runtime &runtime, T value) {
    const auto *ptr = reinterpret_cast<const uint8_t *>(&value);
    const uint32_t size = sizeof(T);

    return fromBytes(runtime, llvh::makeArrayRef(ptr, size));
  }

                                                                         
                        
  template <typename T>
  static std::enable_if_t<std::is_unsigned<T>::value, CallResult<HermesValue>>
  fromUnsigned(Runtime &runtime, T value) {
    static_assert(sizeof(T) <= sizeof(DigitType), "unsigned value truncation");
    DigitType tmp[2] = {static_cast<DigitType>(value), 0};
    const auto *ptr = reinterpret_cast<const uint8_t *>(tmp);
    const uint32_t size = sizeof(tmp);

    return fromBytes(runtime, llvh::makeArrayRef(ptr, size));
  }

                                                                                
  static CallResult<HermesValue> fromDouble(Runtime &runtime, double value);

                                                                          
                                                                                
                
  static Handle<BigIntPrimitive> fromBytesNoThrow(
      Runtime &runtime,
      llvh::ArrayRef<uint8_t> bytes) {
    return runtime.makeHandle<BigIntPrimitive>(
        runtime.ignoreAllocationFailure(fromBytes(runtime, bytes)));
  }

                                                                          
            
  static CallResult<HermesValue> fromBytes(
      Runtime &runtime,
      llvh::ArrayRef<uint8_t> bytes) {
    const uint32_t numDigits = bigint::numDigitsForSizeInBytes(bytes.size());

    auto ret = createUninitializedWithNumDigits(runtime, numDigits);
    if (LLVM_UNLIKELY(ret == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }

    auto res = raiseOnError(
        runtime, bigint::initWithBytes(ret->getMutableRef(runtime), bytes));

    if (LLVM_UNLIKELY(res != ExecutionStatus::RETURNED)) {
      return res;
    }

    return HermesValue::encodeBigIntValue(ret->getBigIntPrimitive());
  }

                                                                         
  llvh::ArrayRef<DigitType> getDigits() const {
    return llvh::makeArrayRef(getTrailingObjects<DigitType>(), numDigits);
  }

                                                                            
                                                                               
  llvh::ArrayRef<uint8_t> getRawDataFull() const {
    auto digits = getDigits();
    const uint8_t *ptr = reinterpret_cast<const uint8_t *>(digits.data());
    const uint32_t size = digits.size() * DigitSizeInBytes;
    return llvh::makeArrayRef(ptr, size);
  }

                                                                            
                                                                      
                                          
  llvh::ArrayRef<uint8_t> getRawDataCompact() const {
    return bigint::dropExtraSignBits(getRawDataFull());
  }

                                                            
  static CallResult<HermesValue>
  toString(Runtime &runtime, PseudoHandle<BigIntPrimitive> self, uint8_t radix);

                                                                                
  static CallResult<HermesValue>
  asIntN(Runtime &runtime, uint64_t n, Handle<BigIntPrimitive> src);

                                                   
  static CallResult<HermesValue>
  asUintN(Runtime &runtime, uint64_t n, Handle<BigIntPrimitive> src);

                                                                       
                                                                              
                                                        
  int32_t compare(const BigIntPrimitive *other) const {
    return bigint::compare(
        this->getImmutableRefUnsafe(), other->getImmutableRefUnsafe());
  }

                                                                             
                                                  
  template <typename T>
  std::enable_if_t<std::is_signed<T>::value, int32_t> compare(T value) const {
    return bigint::compare(this->getImmutableRefUnsafe(), value);
  }

                                                  
  DigitType truncateToSingleDigit() const {
    return bigint::truncateToSingleDigit(this->getImmutableRefUnsafe());
  }

                                                                                
                                                                         
  bool isTruncationToSingleDigitLossless(bool signedTruncation) {
    return bigint::isSingleDigitTruncationLossless(
        this->getImmutableRefUnsafe(), signedTruncation);
  }

                              

                      
  static CallResult<HermesValue> unaryMinus(
      Runtime &runtime,
      Handle<BigIntPrimitive> src);

                      
  static CallResult<HermesValue> unaryNOT(
      Runtime &runtime,
      Handle<BigIntPrimitive> src);

                             
  static CallResult<HermesValue> subtract(
      Runtime &runtime,
      Handle<BigIntPrimitive> lhs,
      Handle<BigIntPrimitive> rhs);

                             
  static CallResult<HermesValue> add(
      Runtime &runtime,
      Handle<BigIntPrimitive> lhs,
      Handle<BigIntPrimitive> rhs);

                             
  static CallResult<HermesValue> multiply(
      Runtime &runtime,
      Handle<BigIntPrimitive> lhs,
      Handle<BigIntPrimitive> rhs);

                             
  static CallResult<HermesValue> divide(
      Runtime &runtime,
      Handle<BigIntPrimitive> lhs,
      Handle<BigIntPrimitive> rhs);

                             
  static CallResult<HermesValue> remainder(
      Runtime &runtime,
      Handle<BigIntPrimitive> lhs,
      Handle<BigIntPrimitive> rhs);

                              
  static CallResult<HermesValue> exponentiate(
      Runtime &runtime,
      Handle<BigIntPrimitive> lhs,
      Handle<BigIntPrimitive> rhs);

                             
  static CallResult<HermesValue> bitwiseAND(
      Runtime &runtime,
      Handle<BigIntPrimitive> lhs,
      Handle<BigIntPrimitive> rhs);

                             
  static CallResult<HermesValue> bitwiseOR(
      Runtime &runtime,
      Handle<BigIntPrimitive> lhs,
      Handle<BigIntPrimitive> rhs);

                             
  static CallResult<HermesValue> bitwiseXOR(
      Runtime &runtime,
      Handle<BigIntPrimitive> lhs,
      Handle<BigIntPrimitive> rhs);

                              
  static CallResult<HermesValue> leftShift(
      Runtime &runtime,
      Handle<BigIntPrimitive> lhs,
      Handle<BigIntPrimitive> rhs);

                                      
  static CallResult<HermesValue> signedRightShift(
      Runtime &runtime,
      Handle<BigIntPrimitive> lhs,
      Handle<BigIntPrimitive> rhs);

                                                                               
  static CallResult<HermesValue> unsignedRightShift(
      Runtime &runtime,
      Handle<BigIntPrimitive> lhs,
      Handle<BigIntPrimitive> rhs);

                        
  static CallResult<HermesValue> inc(
      Runtime &runtime,
      Handle<BigIntPrimitive> src);

                        
  static CallResult<HermesValue> dec(
      Runtime &runtime,
      Handle<BigIntPrimitive> src);

                                                                             
  explicit BigIntPrimitive(uint32_t numDigits);

                                                                         
               
  bool sign() const {
    return bigint::isNegative(getImmutableRefUnsafe());
  }

                         
  CallResult<double> toDouble(Runtime &runtime) const;

 private:
  static ExecutionStatus raiseOnError(
      Runtime &runtime,
      bigint::OperationStatus status) {
    switch (status) {
      case bigint::OperationStatus::RETURNED:
        return ExecutionStatus::RETURNED;
      case bigint::OperationStatus::DEST_TOO_SMALL:
        return runtime.raiseRangeError(
            "BigInt is too small for the operation result");
      case bigint::OperationStatus::TOO_MANY_DIGITS:
        return runtime.raiseRangeError("Maximum BigInt size exceeded");
      case bigint::OperationStatus::DIVISION_BY_ZERO:
        return runtime.raiseRangeError("Division by zero");
      case bigint::OperationStatus::NEGATIVE_EXPONENT:
        return runtime.raiseRangeError("Exponent must be positive");
    }
    llvm_unreachable("No other OperationStatus.");
  }

  template <typename BigIntRefTy>
  struct SafeBigIntRef : public BigIntRefTy {
    SafeBigIntRef() = delete;
    SafeBigIntRef(const SafeBigIntRef &) = delete;
    SafeBigIntRef(SafeBigIntRef &&) = delete;
    SafeBigIntRef &operator=(const SafeBigIntRef &) = delete;
    SafeBigIntRef &operator=(SafeBigIntRef &&) = delete;

    template <typename... Args>
    explicit SafeBigIntRef(Runtime &rt, Args &&...args)
#ifndef HERMES_SLOW_DEBUG
        : BigIntRefTy{std::forward<Args>(args)...} {}
#else                     
        : BigIntRefTy{std::forward<Args>(args)...}, noAlloc(rt) {
    }

    NoAllocScope noAlloc;
#endif                     
  };

  using SafeImmutableBigIntRef = SafeBigIntRef<bigint::ImmutableBigIntRef>;
  using SafeMutableBigIntRef = SafeBigIntRef<bigint::MutableBigIntRef>;

                                                         
                                                          
                                                                              
                                                                                
                                    
  SafeImmutableBigIntRef getImmutableRef(Runtime &rt) const {
    return SafeImmutableBigIntRef(
        rt, getTrailingObjects<DigitType>(), numDigits);
  }

                                                                             
                                                                         
                                                                                
                                                                             
                 
  bigint::ImmutableBigIntRef getImmutableRefUnsafe() const {
    return bigint::ImmutableBigIntRef{
        getTrailingObjects<DigitType>(), numDigits};
  }

                                                                             
                                                                              
                                                                             
                                                                                
                                                                   
  class UninitializedBigIntPrimitive {
   public:
    UninitializedBigIntPrimitive() = delete;
    UninitializedBigIntPrimitive(const UninitializedBigIntPrimitive &) =
        default;
    UninitializedBigIntPrimitive &operator=(
        const UninitializedBigIntPrimitive &) = default;

    explicit UninitializedBigIntPrimitive(BigIntPrimitive *u)
        : uninitialized(u) {}

    SafeMutableBigIntRef getMutableRef(Runtime &rt) {
#ifdef HERMES_SLOW_DEBUG
      possiblyInitialized = true;
#endif                     
      return SafeMutableBigIntRef{
          rt,
          uninitialized->getTrailingObjects<DigitType>(),
          uninitialized->numDigits};
    }

    BigIntPrimitive *getBigIntPrimitive() const {
#ifdef HERMES_SLOW_DEBUG
      assert(
          possiblyInitialized &&
          "UninitializedBigIntPrimitive was never possibly-initialized.");
#endif                     
      return uninitialized;
    }

   private:
    BigIntPrimitive *uninitialized = nullptr;
#ifdef HERMES_SLOW_DEBUG
                                                                           
                                                                            
                                                               
                                                                                
                                        
    bool possiblyInitialized = false;
#endif                     
  };

                                                                           
             
  static CallResult<UninitializedBigIntPrimitive>
  createUninitializedWithNumDigits(Runtime &runtime, uint32_t numDigits) {
    if (bigint::tooManyDigits(numDigits)) {
      return raiseOnError(runtime, bigint::OperationStatus::TOO_MANY_DIGITS);
    }

    const uint32_t cellSizeInBytes = calcCellSizeInBytes(numDigits);

    UninitializedBigIntPrimitive ret{
        runtime.makeAVariable<BigIntPrimitive>(cellSizeInBytes, numDigits)};
    return ret;
  }

  using UnaryOp = bigint::OperationStatus (*)(
      bigint::MutableBigIntRef dst,
      bigint::ImmutableBigIntRef src);
  template <typename UnaryOpT = UnaryOp>
  static CallResult<HermesValue> unaryOp(
      Runtime &runtime,
      UnaryOpT op,
      Handle<BigIntPrimitive> src,
      size_t numDigits);

  using BinaryOp = bigint::OperationStatus (*)(
      bigint::MutableBigIntRef dst,
      bigint::ImmutableBigIntRef lhs,
      bigint::ImmutableBigIntRef src);
  static CallResult<HermesValue> binaryOp(
      Runtime &runtime,
      BinaryOp op,
      Handle<BigIntPrimitive> lhs,
      Handle<BigIntPrimitive> rhs,
      uint32_t numDigitsResult);
};
}                
}                    
#pragma GCC diagnostic pop

#endif                               

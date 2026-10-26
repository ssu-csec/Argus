//===- llvm/Support/ScaledNumber.h - Support for scaled numbers -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains functions (and a class) useful for working with scaled
// numbers -- in particular, pairs of integers where one represents digits and
// another represents a scale.  The functions are helpers and live in the
// namespace ScaledNumbers.  The class ScaledNumber is useful for modelling
// certain cost metrics that need simple, integer-like semantics that are easy
// to reason about.
//
// These might remind you of soft-floats.  If you want one of those, you're in
// the wrong place.  Look at include/llvm/ADT/APFloat.h instead.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_SCALEDNUMBER_H
#define LLVM_SUPPORT_SCALEDNUMBER_H

#include "llvh/Support/MathExtras.h"
#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <tuple>
#include <utility>

namespace llvh {
namespace ScaledNumbers {

                                                           
const int32_t MaxScale = 16383;

                                                           
const int32_t MinScale = -16382;

                              
template <class DigitsT> inline int getWidth() { return sizeof(DigitsT) * 8; }

                                           
   
                                                                         
                                                                        
                       
   
                                                          
template <class DigitsT>
inline std::pair<DigitsT, int16_t> getRounded(DigitsT Digits, int16_t Scale,
                                              bool ShouldRound) {
  static_assert(!std::numeric_limits<DigitsT>::is_signed, "expected unsigned");

  if (ShouldRound)
    if (!++Digits)
                  
      return std::make_pair(DigitsT(1) << (getWidth<DigitsT>() - 1), Scale + 1);
  return std::make_pair(Digits, Scale);
}

                                           
inline std::pair<uint32_t, int16_t> getRounded32(uint32_t Digits, int16_t Scale,
                                                 bool ShouldRound) {
  return getRounded(Digits, Scale, ShouldRound);
}

                                           
inline std::pair<uint64_t, int16_t> getRounded64(uint64_t Digits, int16_t Scale,
                                                 bool ShouldRound) {
  return getRounded(Digits, Scale, ShouldRound);
}

                                                                
   
                                                           
template <class DigitsT>
inline std::pair<DigitsT, int16_t> getAdjusted(uint64_t Digits,
                                               int16_t Scale = 0) {
  static_assert(!std::numeric_limits<DigitsT>::is_signed, "expected unsigned");

  const int Width = getWidth<DigitsT>();
  if (Width == 64 || Digits <= std::numeric_limits<DigitsT>::max())
    return std::make_pair(Digits, Scale);

                           
  int Shift = 64 - Width - countLeadingZeros(Digits);
  return getRounded<DigitsT>(Digits >> Shift, Scale + Shift,
                             Digits & (UINT64_C(1) << (Shift - 1)));
}

                                                
inline std::pair<uint32_t, int16_t> getAdjusted32(uint64_t Digits,
                                                  int16_t Scale = 0) {
  return getAdjusted<uint32_t>(Digits, Scale);
}

                                                
inline std::pair<uint64_t, int16_t> getAdjusted64(uint64_t Digits,
                                                  int16_t Scale = 0) {
  return getAdjusted<uint64_t>(Digits, Scale);
}

                                                                  
   
                                                    
std::pair<uint64_t, int16_t> multiply64(uint64_t LHS, uint64_t RHS);

                                                                  
   
                                                 
template <class DigitsT>
inline std::pair<DigitsT, int16_t> getProduct(DigitsT LHS, DigitsT RHS) {
  static_assert(!std::numeric_limits<DigitsT>::is_signed, "expected unsigned");

  if (getWidth<DigitsT>() <= 32 || (LHS <= UINT32_MAX && RHS <= UINT32_MAX))
    return getAdjusted<DigitsT>(uint64_t(LHS) * RHS);

  return multiply64(LHS, RHS);
}

                                          
inline std::pair<uint32_t, int16_t> getProduct32(uint32_t LHS, uint32_t RHS) {
  return getProduct(LHS, RHS);
}

                                          
inline std::pair<uint64_t, int16_t> getProduct64(uint64_t LHS, uint64_t RHS) {
  return getProduct(LHS, RHS);
}

                                                                
   
                                   
   
                                                 
std::pair<uint64_t, int16_t> divide64(uint64_t Dividend, uint64_t Divisor);

                                                                
   
                                                              
   
                                                 
std::pair<uint32_t, int16_t> divide32(uint32_t Dividend, uint32_t Divisor);

                                                               
   
                                                              
   
                                                                      
template <class DigitsT>
std::pair<DigitsT, int16_t> getQuotient(DigitsT Dividend, DigitsT Divisor) {
  static_assert(!std::numeric_limits<DigitsT>::is_signed, "expected unsigned");
  static_assert(sizeof(DigitsT) == 4 || sizeof(DigitsT) == 8,
                "expected 32-bit or 64-bit digits");

                    
  if (!Dividend)
    return std::make_pair(0, 0);
  if (!Divisor)
    return std::make_pair(std::numeric_limits<DigitsT>::max(), MaxScale);

  if (getWidth<DigitsT>() == 64)
    return divide64(Dividend, Divisor);
  return divide32(Dividend, Divisor);
}

                                           
inline std::pair<uint32_t, int16_t> getQuotient32(uint32_t Dividend,
                                                  uint32_t Divisor) {
  return getQuotient(Dividend, Divisor);
}

                                           
inline std::pair<uint64_t, int16_t> getQuotient64(uint64_t Dividend,
                                                  uint64_t Divisor) {
  return getQuotient(Dividend, Divisor);
}

                                          
   
                                                                             
                                                     
   
                                                
template <class DigitsT>
inline std::pair<int32_t, int> getLgImpl(DigitsT Digits, int16_t Scale) {
  static_assert(!std::numeric_limits<DigitsT>::is_signed, "expected unsigned");

  if (!Digits)
    return std::make_pair(INT32_MIN, 0);

                                       
  int32_t LocalFloor = sizeof(Digits) * 8 - countLeadingZeros(Digits) - 1;

                          
  int32_t Floor = Scale + LocalFloor;
  if (Digits == UINT64_C(1) << LocalFloor)
    return std::make_pair(Floor, 0);

                                   
  assert(LocalFloor >= 1);
  bool Round = Digits & UINT64_C(1) << (LocalFloor - 1);
  return std::make_pair(Floor + Round, Round ? 1 : -1);
}

                                            
   
                                    
   
                                                
template <class DigitsT> int32_t getLg(DigitsT Digits, int16_t Scale) {
  return getLgImpl(Digits, Scale).first;
}

                                        
   
                                                 
   
                                                
template <class DigitsT> int32_t getLgFloor(DigitsT Digits, int16_t Scale) {
  auto Lg = getLgImpl(Digits, Scale);
  return Lg.first - (Lg.second > 0);
}

                                          
   
                                                   
   
                                                
template <class DigitsT> int32_t getLgCeiling(DigitsT Digits, int16_t Scale) {
  auto Lg = getLgImpl(Digits, Scale);
  return Lg.first + (Lg.second < 0);
}

                                                
   
                                                                              
                                                                               
                                                                  
   
                             
int compareImpl(uint64_t L, uint64_t R, int ScaleDiff);

                               
   
                                                                             
                     
template <class DigitsT>
int compare(DigitsT LDigits, int16_t LScale, DigitsT RDigits, int16_t RScale) {
  static_assert(!std::numeric_limits<DigitsT>::is_signed, "expected unsigned");

                    
  if (!LDigits)
    return RDigits ? -1 : 0;
  if (!RDigits)
    return 1;

                                                                              
                             
  int32_t lgL = getLgFloor(LDigits, LScale), lgR = getLgFloor(RDigits, RScale);
  if (lgL != lgR)
    return lgL < lgR ? -1 : 1;

                    
  if (LScale < RScale)
    return compareImpl(LDigits, RDigits, RScale - LScale);

  return -compareImpl(RDigits, LDigits, LScale - RScale);
}

                                
   
                                                                           
                                                                               
                                         
   
                                                                               
                                         
   
                                                                             
                                                                            
                                     
template <class DigitsT>
int16_t matchScales(DigitsT &LDigits, int16_t &LScale, DigitsT &RDigits,
                    int16_t &RScale) {
  static_assert(!std::numeric_limits<DigitsT>::is_signed, "expected unsigned");

  if (LScale < RScale)
                      
    return matchScales(RDigits, RScale, LDigits, LScale);
  if (!LDigits)
    return RScale;
  if (!RDigits || LScale == RScale)
    return LScale;

                                              
  int32_t ScaleDiff = int32_t(LScale) - RScale;
  if (ScaleDiff >= 2 * getWidth<DigitsT>()) {
                                                                   
    RDigits = 0;
    return LScale;
  }

                                                                      
  int32_t ShiftL = std::min<int32_t>(countLeadingZeros(LDigits), ScaleDiff);
  assert(ShiftL < getWidth<DigitsT>() && "can't shift more than width");

  int32_t ShiftR = ScaleDiff - ShiftL;
  if (ShiftR >= getWidth<DigitsT>()) {
                                                                   
    RDigits = 0;
    return LScale;
  }

  LDigits <<= ShiftL;
  RDigits >>= ShiftR;

  LScale -= ShiftL;
  RScale += ShiftR;
  assert(LScale == RScale && "scales should match");
  return LScale;
}

                                      
   
                                                                         
   
                                                                          
template <class DigitsT>
std::pair<DigitsT, int16_t> getSum(DigitsT LDigits, int16_t LScale,
                                   DigitsT RDigits, int16_t RScale) {
  static_assert(!std::numeric_limits<DigitsT>::is_signed, "expected unsigned");

                                                                             
                                         
  assert(LScale < INT16_MAX && "scale too large");
  assert(RScale < INT16_MAX && "scale too large");

                                      
  int16_t Scale = matchScales(LDigits, LScale, RDigits, RScale);

                 
  DigitsT Sum = LDigits + RDigits;
  if (Sum >= RDigits)
    return std::make_pair(Sum, Scale);

                                          
  DigitsT HighBit = DigitsT(1) << (getWidth<DigitsT>() - 1);
  return std::make_pair(HighBit | Sum >> 1, Scale + 1);
}

                                      
inline std::pair<uint32_t, int16_t> getSum32(uint32_t LDigits, int16_t LScale,
                                             uint32_t RDigits, int16_t RScale) {
  return getSum(LDigits, LScale, RDigits, RScale);
}

                                      
inline std::pair<uint64_t, int16_t> getSum64(uint64_t LDigits, int16_t LScale,
                                             uint64_t RDigits, int16_t RScale) {
  return getSum(LDigits, LScale, RDigits, RScale);
}

                                             
   
                                                         
   
                                                        
template <class DigitsT>
std::pair<DigitsT, int16_t> getDifference(DigitsT LDigits, int16_t LScale,
                                          DigitsT RDigits, int16_t RScale) {
  static_assert(!std::numeric_limits<DigitsT>::is_signed, "expected unsigned");

                                      
  const DigitsT SavedRDigits = RDigits;
  const int16_t SavedRScale = RScale;
  matchScales(LDigits, LScale, RDigits, RScale);

                        
  if (LDigits <= RDigits)
    return std::make_pair(0, 0);
  if (RDigits || !SavedRDigits)
    return std::make_pair(LDigits - RDigits, LScale);

                                                                       
    
                                             
  const auto RLgFloor = getLgFloor(SavedRDigits, SavedRScale);
  if (!compare(LDigits, LScale, DigitsT(1), RLgFloor + getWidth<DigitsT>()))
    return std::make_pair(std::numeric_limits<DigitsT>::max(), RLgFloor);

  return std::make_pair(LDigits, LScale);
}

                                             
inline std::pair<uint32_t, int16_t> getDifference32(uint32_t LDigits,
                                                    int16_t LScale,
                                                    uint32_t RDigits,
                                                    int16_t RScale) {
  return getDifference(LDigits, LScale, RDigits, RScale);
}

                                             
inline std::pair<uint64_t, int16_t> getDifference64(uint64_t LDigits,
                                                    int16_t LScale,
                                                    uint64_t RDigits,
                                                    int16_t RScale) {
  return getDifference(LDigits, LScale, RDigits, RScale);
}

}                               
}                      

namespace llvh {

class raw_ostream;
class ScaledNumberBase {
public:
  static const int DefaultPrecision = 10;

  static void dump(uint64_t D, int16_t E, int Width);
  static raw_ostream &print(raw_ostream &OS, uint64_t D, int16_t E, int Width,
                            unsigned Precision);
  static std::string toString(uint64_t D, int16_t E, int Width,
                              unsigned Precision);
  static int countLeadingZeros32(uint32_t N) { return countLeadingZeros(N); }
  static int countLeadingZeros64(uint64_t N) { return countLeadingZeros(N); }
  static uint64_t getHalf(uint64_t N) { return (N >> 1) + (N & 1); }

  static std::pair<uint64_t, bool> splitSigned(int64_t N) {
    if (N >= 0)
      return std::make_pair(N, false);
    uint64_t Unsigned = N == INT64_MIN ? UINT64_C(1) << 63 : uint64_t(-N);
    return std::make_pair(Unsigned, true);
  }
  static int64_t joinSigned(uint64_t U, bool IsNeg) {
    if (U > uint64_t(INT64_MAX))
      return IsNeg ? INT64_MIN : INT64_MAX;
    return IsNeg ? -int64_t(U) : int64_t(U);
  }
};

                                             
   
                                                                               
                                                                              
                                                                      
                                                                               
                                                                               
            
   
                                                                            
                                                                            
                                                                            
                                                                           
   
                                                                              
                               
   
                                                                           
                                                                              
                                                                     
   
                                                                             
                                                              
   
                                                  
                                                  
                                                  
   
                                                                          
                                                                          
                                                                             
                                                                            
                                                            
   
                                                                            
                                                                              
                           
   
                                                                            
                                                                          
                                                  
   
                                                 
   
                                                   
                                                            
                                                           
template <class DigitsT> class ScaledNumber : ScaledNumberBase {
public:
  static_assert(!std::numeric_limits<DigitsT>::is_signed,
                "only unsigned floats supported");

  typedef DigitsT DigitsType;

private:
  typedef std::numeric_limits<DigitsType> DigitsLimits;

  static const int Width = sizeof(DigitsType) * 8;
  static_assert(Width <= 64, "invalid integer width for digits");

private:
  DigitsType Digits = 0;
  int16_t Scale = 0;

public:
  ScaledNumber() = default;

  constexpr ScaledNumber(DigitsType Digits, int16_t Scale)
      : Digits(Digits), Scale(Scale) {}

private:
  ScaledNumber(const std::pair<DigitsT, int16_t> &X)
      : Digits(X.first), Scale(X.second) {}

public:
  static ScaledNumber getZero() { return ScaledNumber(0, 0); }
  static ScaledNumber getOne() { return ScaledNumber(1, 0); }
  static ScaledNumber getLargest() {
    return ScaledNumber(DigitsLimits::max(), ScaledNumbers::MaxScale);
  }
  static ScaledNumber get(uint64_t N) { return adjustToWidth(N, 0); }
  static ScaledNumber getInverse(uint64_t N) {
    return get(N).invert();
  }
  static ScaledNumber getFraction(DigitsType N, DigitsType D) {
    return getQuotient(N, D);
  }

  int16_t getScale() const { return Scale; }
  DigitsType getDigits() const { return Digits; }

                                        
     
                                                                          
                
  template <class IntT> IntT toInt() const;

  bool isZero() const { return !Digits; }
  bool isLargest() const { return *this == getLargest(); }
  bool isOne() const {
    if (Scale > 0 || Scale <= -Width)
      return false;
    return Digits == DigitsType(1) << -Scale;
  }

                              
     
                                                                 
  int32_t lg() const { return ScaledNumbers::getLg(Digits, Scale); }

                                                
     
                                                         
  int32_t lgFloor() const { return ScaledNumbers::getLgFloor(Digits, Scale); }

                                                
     
                                                           
  int32_t lgCeiling() const {
    return ScaledNumbers::getLgCeiling(Digits, Scale);
  }

  bool operator==(const ScaledNumber &X) const { return compare(X) == 0; }
  bool operator<(const ScaledNumber &X) const { return compare(X) < 0; }
  bool operator!=(const ScaledNumber &X) const { return compare(X) != 0; }
  bool operator>(const ScaledNumber &X) const { return compare(X) > 0; }
  bool operator<=(const ScaledNumber &X) const { return compare(X) <= 0; }
  bool operator>=(const ScaledNumber &X) const { return compare(X) >= 0; }

  bool operator!() const { return isZero(); }

                                                      
     
                                                                         
                                                                              
                               
     
                                                                              
                                       
     
                                                                               
                                                                           
                                                                           
                                                              
     
                                              
                                              
                                              
                                               
                                                
  std::string toString(unsigned Precision = DefaultPrecision) {
    return ScaledNumberBase::toString(Digits, Scale, Width, Precision);
  }

                                     
     
                                                      
  raw_ostream &print(raw_ostream &OS,
                     unsigned Precision = DefaultPrecision) const {
    return ScaledNumberBase::print(OS, Digits, Scale, Width, Precision);
  }
  void dump() const { return ScaledNumberBase::dump(Digits, Scale, Width); }

  ScaledNumber &operator+=(const ScaledNumber &X) {
    std::tie(Digits, Scale) =
        ScaledNumbers::getSum(Digits, Scale, X.Digits, X.Scale);
                                        
    if (Scale > ScaledNumbers::MaxScale)
      *this = getLargest();
    return *this;
  }
  ScaledNumber &operator-=(const ScaledNumber &X) {
    std::tie(Digits, Scale) =
        ScaledNumbers::getDifference(Digits, Scale, X.Digits, X.Scale);
    return *this;
  }
  ScaledNumber &operator*=(const ScaledNumber &X);
  ScaledNumber &operator/=(const ScaledNumber &X);
  ScaledNumber &operator<<=(int16_t Shift) {
    shiftLeft(Shift);
    return *this;
  }
  ScaledNumber &operator>>=(int16_t Shift) {
    shiftRight(Shift);
    return *this;
  }

private:
  void shiftLeft(int32_t Shift);
  void shiftRight(int32_t Shift);

                                                   
     
                                                                               
                                                        
     
                                                                              
                  
  ScaledNumber matchScales(ScaledNumber X) {
    ScaledNumbers::matchScales(Digits, Scale, X.Digits, X.Scale);
    return X;
  }

public:
                                      
     
                                                                              
                                                              
  uint64_t scale(uint64_t N) const;
  uint64_t scaleByInverse(uint64_t N) const {
                                                                            
                 
    return inverse().scale(N);
  }
  int64_t scale(int64_t N) const {
    std::pair<uint64_t, bool> Unsigned = splitSigned(N);
    return joinSigned(scale(Unsigned.first), Unsigned.second);
  }
  int64_t scaleByInverse(int64_t N) const {
    std::pair<uint64_t, bool> Unsigned = splitSigned(N);
    return joinSigned(scaleByInverse(Unsigned.first), Unsigned.second);
  }

  int compare(const ScaledNumber &X) const {
    return ScaledNumbers::compare(Digits, Scale, X.Digits, X.Scale);
  }
  int compareTo(uint64_t N) const {
    return ScaledNumbers::compare<uint64_t>(Digits, Scale, N, 0);
  }
  int compareTo(int64_t N) const { return N < 0 ? 1 : compareTo(uint64_t(N)); }

  ScaledNumber &invert() { return *this = ScaledNumber::get(1) / *this; }
  ScaledNumber inverse() const { return ScaledNumber(*this).invert(); }

private:
  static ScaledNumber getProduct(DigitsType LHS, DigitsType RHS) {
    return ScaledNumbers::getProduct(LHS, RHS);
  }
  static ScaledNumber getQuotient(DigitsType Dividend, DigitsType Divisor) {
    return ScaledNumbers::getQuotient(Dividend, Divisor);
  }

  static int countLeadingZerosWidth(DigitsType Digits) {
    if (Width == 64)
      return countLeadingZeros64(Digits);
    if (Width == 32)
      return countLeadingZeros32(Digits);
    return countLeadingZeros32(Digits) + Width - 32;
  }

                                                         
     
                                                       
     
                                                       
  static ScaledNumber adjustToWidth(uint64_t N, int32_t Shift) {
    assert(Shift >= ScaledNumbers::MinScale && "Shift should be close to 0");
    assert(Shift <= ScaledNumbers::MaxScale - 64 &&
           "Shift should be close to 0");
    auto Adjusted = ScaledNumbers::getAdjusted<DigitsT>(N, Shift);
    return Adjusted;
  }

  static ScaledNumber getRounded(ScaledNumber P, bool Round) {
                
    if (P.isLargest())
      return P;

    return ScaledNumbers::getRounded(P.Digits, P.Scale, Round);
  }
};

#define SCALED_NUMBER_BOP(op, base)                                            \
  template <class DigitsT>                                                     \
  ScaledNumber<DigitsT> operator op(const ScaledNumber<DigitsT> &L,            \
                                    const ScaledNumber<DigitsT> &R) {          \
    return ScaledNumber<DigitsT>(L) base R;                                    \
  }
SCALED_NUMBER_BOP(+, += )
SCALED_NUMBER_BOP(-, -= )
SCALED_NUMBER_BOP(*, *= )
SCALED_NUMBER_BOP(/, /= )
#undef SCALED_NUMBER_BOP

template <class DigitsT>
ScaledNumber<DigitsT> operator<<(const ScaledNumber<DigitsT> &L,
                                 int16_t Shift) {
  return ScaledNumber<DigitsT>(L) <<= Shift;
}

template <class DigitsT>
ScaledNumber<DigitsT> operator>>(const ScaledNumber<DigitsT> &L,
                                 int16_t Shift) {
  return ScaledNumber<DigitsT>(L) >>= Shift;
}

template <class DigitsT>
raw_ostream &operator<<(raw_ostream &OS, const ScaledNumber<DigitsT> &X) {
  return X.print(OS, 10);
}

#define SCALED_NUMBER_COMPARE_TO_TYPE(op, T1, T2)                              \
  template <class DigitsT>                                                     \
  bool operator op(const ScaledNumber<DigitsT> &L, T1 R) {                     \
    return L.compareTo(T2(R)) op 0;                                            \
  }                                                                            \
  template <class DigitsT>                                                     \
  bool operator op(T1 L, const ScaledNumber<DigitsT> &R) {                     \
    return 0 op R.compareTo(T2(L));                                            \
  }
#define SCALED_NUMBER_COMPARE_TO(op)                                           \
  SCALED_NUMBER_COMPARE_TO_TYPE(op, uint64_t, uint64_t)                        \
  SCALED_NUMBER_COMPARE_TO_TYPE(op, uint32_t, uint64_t)                        \
  SCALED_NUMBER_COMPARE_TO_TYPE(op, int64_t, int64_t)                          \
  SCALED_NUMBER_COMPARE_TO_TYPE(op, int32_t, int64_t)
SCALED_NUMBER_COMPARE_TO(< )
SCALED_NUMBER_COMPARE_TO(> )
SCALED_NUMBER_COMPARE_TO(== )
SCALED_NUMBER_COMPARE_TO(!= )
SCALED_NUMBER_COMPARE_TO(<= )
SCALED_NUMBER_COMPARE_TO(>= )
#undef SCALED_NUMBER_COMPARE_TO
#undef SCALED_NUMBER_COMPARE_TO_TYPE

template <class DigitsT>
uint64_t ScaledNumber<DigitsT>::scale(uint64_t N) const {
  if (Width == 64 || N <= DigitsLimits::max())
    return (get(N) * *this).template toInt<uint64_t>();

                                 
  return ScaledNumber<uint64_t>(Digits, Scale).scale(N);
}

template <class DigitsT>
template <class IntT>
IntT ScaledNumber<DigitsT>::toInt() const {
  typedef std::numeric_limits<IntT> Limits;
  if (*this < 1)
    return 0;
  if (*this >= Limits::max())
    return Limits::max();

  IntT N = Digits;
  if (Scale > 0) {
    assert(size_t(Scale) < sizeof(IntT) * 8);
    return N << Scale;
  }
  if (Scale < 0) {
    assert(size_t(-Scale) < sizeof(IntT) * 8);
    return N >> -Scale;
  }
  return N;
}

template <class DigitsT>
ScaledNumber<DigitsT> &ScaledNumber<DigitsT>::
operator*=(const ScaledNumber &X) {
  if (isZero())
    return *this;
  if (X.isZero())
    return *this = X;

                        
  int32_t Scales = int32_t(Scale) + int32_t(X.Scale);

                         
  *this = getProduct(Digits, X.Digits);

                            
  return *this <<= Scales;
}
template <class DigitsT>
ScaledNumber<DigitsT> &ScaledNumber<DigitsT>::
operator/=(const ScaledNumber &X) {
  if (isZero())
    return *this;
  if (X.isZero())
    return *this = getLargest();

                        
  int32_t Scales = int32_t(Scale) - int32_t(X.Scale);

                          
  *this = getQuotient(Digits, X.Digits);

                            
  return *this <<= Scales;
}
template <class DigitsT> void ScaledNumber<DigitsT>::shiftLeft(int32_t Shift) {
  if (!Shift || isZero())
    return;
  assert(Shift != INT32_MIN);
  if (Shift < 0) {
    shiftRight(-Shift);
    return;
  }

                                             
  int32_t ScaleShift = std::min(Shift, ScaledNumbers::MaxScale - Scale);
  Scale += ScaleShift;
  if (ScaleShift == Shift)
    return;

                                      
  if (isLargest())
    return;

                                 
  Shift -= ScaleShift;
  if (Shift > countLeadingZerosWidth(Digits)) {
                
    *this = getLargest();
    return;
  }

  Digits <<= Shift;
}

template <class DigitsT> void ScaledNumber<DigitsT>::shiftRight(int32_t Shift) {
  if (!Shift || isZero())
    return;
  assert(Shift != INT32_MIN);
  if (Shift < 0) {
    shiftLeft(-Shift);
    return;
  }

                                             
  int32_t ScaleShift = std::min(Shift, Scale - ScaledNumbers::MinScale);
  Scale -= ScaleShift;
  if (ScaleShift == Shift)
    return;

                                 
  Shift -= ScaleShift;
  if (Shift >= Width) {
                
    *this = getZero();
    return;
  }

  Digits >>= Shift;
}

template <typename T> struct isPodLike;
template <typename T> struct isPodLike<ScaledNumber<T>> {
  static const bool value = true;
};

}                      

#endif                               

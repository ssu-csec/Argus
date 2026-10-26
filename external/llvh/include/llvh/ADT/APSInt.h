//===-- llvm/ADT/APSInt.h - Arbitrary Precision Signed Int -----*- C++ -*--===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the APSInt class, which is a simple class that
// represents an arbitrary sized integer that knows its signedness.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_APSINT_H
#define LLVM_ADT_APSINT_H

#include "llvh/ADT/APInt.h"

namespace llvh {

class LLVM_NODISCARD APSInt : public APInt {
  bool IsUnsigned;

public:
                                                              
  explicit APSInt() : IsUnsigned(false) {}

                                                                         
               
  explicit APSInt(uint32_t BitWidth, bool isUnsigned = true)
   : APInt(BitWidth, 0), IsUnsigned(isUnsigned) {}

  explicit APSInt(APInt I, bool isUnsigned = true)
   : APInt(std::move(I)), IsUnsigned(isUnsigned) {}

                                                       
     
                                                                          
                                                                             
                                                     
     
                                              
  explicit APSInt(StringRef Str);

  APSInt &operator=(APInt RHS) {
                               
    APInt::operator=(std::move(RHS));
    return *this;
  }

  APSInt &operator=(uint64_t RHS) {
                               
    APInt::operator=(RHS);
    return *this;
  }

                            
  bool isSigned() const { return !IsUnsigned; }
  bool isUnsigned() const { return IsUnsigned; }
  void setIsUnsigned(bool Val) { IsUnsigned = Val; }
  void setIsSigned(bool Val) { IsUnsigned = !Val; }

                                                                 
  void toString(SmallVectorImpl<char> &Str, unsigned Radix = 10) const {
    APInt::toString(Str, Radix, isSigned());
  }
                                                                            
                                                                 
  std::string toString(unsigned Radix) const {
    return APInt::toString(Radix, isSigned());
  }
  using APInt::toString;

                                                  
  int64_t getExtValue() const {
    assert(getMinSignedBits() <= 64 && "Too many bits for int64_t");
    return isSigned() ? getSExtValue() : getZExtValue();
  }

  APSInt trunc(uint32_t width) const {
    return APSInt(APInt::trunc(width), IsUnsigned);
  }

  APSInt extend(uint32_t width) const {
    if (IsUnsigned)
      return APSInt(zext(width), IsUnsigned);
    else
      return APSInt(sext(width), IsUnsigned);
  }

  APSInt extOrTrunc(uint32_t width) const {
    if (IsUnsigned)
      return APSInt(zextOrTrunc(width), IsUnsigned);
    else
      return APSInt(sextOrTrunc(width), IsUnsigned);
  }

  const APSInt &operator%=(const APSInt &RHS) {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    if (IsUnsigned)
      *this = urem(RHS);
    else
      *this = srem(RHS);
    return *this;
  }
  const APSInt &operator/=(const APSInt &RHS) {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    if (IsUnsigned)
      *this = udiv(RHS);
    else
      *this = sdiv(RHS);
    return *this;
  }
  APSInt operator%(const APSInt &RHS) const {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    return IsUnsigned ? APSInt(urem(RHS), true) : APSInt(srem(RHS), false);
  }
  APSInt operator/(const APSInt &RHS) const {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    return IsUnsigned ? APSInt(udiv(RHS), true) : APSInt(sdiv(RHS), false);
  }

  APSInt operator>>(unsigned Amt) const {
    return IsUnsigned ? APSInt(lshr(Amt), true) : APSInt(ashr(Amt), false);
  }
  APSInt& operator>>=(unsigned Amt) {
    if (IsUnsigned)
      lshrInPlace(Amt);
    else
      ashrInPlace(Amt);
    return *this;
  }

  inline bool operator<(const APSInt& RHS) const {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    return IsUnsigned ? ult(RHS) : slt(RHS);
  }
  inline bool operator>(const APSInt& RHS) const {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    return IsUnsigned ? ugt(RHS) : sgt(RHS);
  }
  inline bool operator<=(const APSInt& RHS) const {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    return IsUnsigned ? ule(RHS) : sle(RHS);
  }
  inline bool operator>=(const APSInt& RHS) const {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    return IsUnsigned ? uge(RHS) : sge(RHS);
  }
  inline bool operator==(const APSInt& RHS) const {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    return eq(RHS);
  }
  inline bool operator!=(const APSInt& RHS) const {
    return !((*this) == RHS);
  }

  bool operator==(int64_t RHS) const {
    return compareValues(*this, get(RHS)) == 0;
  }
  bool operator!=(int64_t RHS) const {
    return compareValues(*this, get(RHS)) != 0;
  }
  bool operator<=(int64_t RHS) const {
    return compareValues(*this, get(RHS)) <= 0;
  }
  bool operator>=(int64_t RHS) const {
    return compareValues(*this, get(RHS)) >= 0;
  }
  bool operator<(int64_t RHS) const {
    return compareValues(*this, get(RHS)) < 0;
  }
  bool operator>(int64_t RHS) const {
    return compareValues(*this, get(RHS)) > 0;
  }

                                                                         
                            

  APSInt operator<<(unsigned Bits) const {
    return APSInt(static_cast<const APInt&>(*this) << Bits, IsUnsigned);
  }
  APSInt& operator<<=(unsigned Amt) {
    static_cast<APInt&>(*this) <<= Amt;
    return *this;
  }

  APSInt& operator++() {
    ++(static_cast<APInt&>(*this));
    return *this;
  }
  APSInt& operator--() {
    --(static_cast<APInt&>(*this));
    return *this;
  }
  APSInt operator++(int) {
    return APSInt(++static_cast<APInt&>(*this), IsUnsigned);
  }
  APSInt operator--(int) {
    return APSInt(--static_cast<APInt&>(*this), IsUnsigned);
  }
  APSInt operator-() const {
    return APSInt(-static_cast<const APInt&>(*this), IsUnsigned);
  }
  APSInt& operator+=(const APSInt& RHS) {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    static_cast<APInt&>(*this) += RHS;
    return *this;
  }
  APSInt& operator-=(const APSInt& RHS) {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    static_cast<APInt&>(*this) -= RHS;
    return *this;
  }
  APSInt& operator*=(const APSInt& RHS) {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    static_cast<APInt&>(*this) *= RHS;
    return *this;
  }
  APSInt& operator&=(const APSInt& RHS) {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    static_cast<APInt&>(*this) &= RHS;
    return *this;
  }
  APSInt& operator|=(const APSInt& RHS) {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    static_cast<APInt&>(*this) |= RHS;
    return *this;
  }
  APSInt& operator^=(const APSInt& RHS) {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    static_cast<APInt&>(*this) ^= RHS;
    return *this;
  }

  APSInt operator&(const APSInt& RHS) const {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    return APSInt(static_cast<const APInt&>(*this) & RHS, IsUnsigned);
  }

  APSInt operator|(const APSInt& RHS) const {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    return APSInt(static_cast<const APInt&>(*this) | RHS, IsUnsigned);
  }

  APSInt operator^(const APSInt &RHS) const {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    return APSInt(static_cast<const APInt&>(*this) ^ RHS, IsUnsigned);
  }

  APSInt operator*(const APSInt& RHS) const {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    return APSInt(static_cast<const APInt&>(*this) * RHS, IsUnsigned);
  }
  APSInt operator+(const APSInt& RHS) const {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    return APSInt(static_cast<const APInt&>(*this) + RHS, IsUnsigned);
  }
  APSInt operator-(const APSInt& RHS) const {
    assert(IsUnsigned == RHS.IsUnsigned && "Signedness mismatch!");
    return APSInt(static_cast<const APInt&>(*this) - RHS, IsUnsigned);
  }
  APSInt operator~() const {
    return APSInt(~static_cast<const APInt&>(*this), IsUnsigned);
  }

                                                                            
                                               
  static APSInt getMaxValue(uint32_t numBits, bool Unsigned) {
    return APSInt(Unsigned ? APInt::getMaxValue(numBits)
                           : APInt::getSignedMaxValue(numBits), Unsigned);
  }

                                                                            
                                               
  static APSInt getMinValue(uint32_t numBits, bool Unsigned) {
    return APSInt(Unsigned ? APInt::getMinValue(numBits)
                           : APInt::getSignedMinValue(numBits), Unsigned);
  }

                                                            
                               
  static bool isSameValue(const APSInt &I1, const APSInt &I2) {
    return !compareValues(I1, I2);
  }

                                               
  static int compareValues(const APSInt &I1, const APSInt &I2) {
    if (I1.getBitWidth() == I2.getBitWidth() && I1.isSigned() == I2.isSigned())
      return I1.IsUnsigned ? I1.compare(I2) : I1.compareSigned(I2);

                                      
    if (I1.getBitWidth() > I2.getBitWidth())
      return compareValues(I1, I2.extend(I1.getBitWidth()));
    if (I2.getBitWidth() > I1.getBitWidth())
      return compareValues(I1.extend(I2.getBitWidth()), I2);

                                                                         
                                             
    if (I1.isSigned()) {
      assert(!I2.isSigned() && "Expected signed mismatch");
      if (I1.isNegative())
        return -1;
    } else {
      assert(I2.isSigned() && "Expected signed mismatch");
      if (I2.isNegative())
        return 1;
    }

    return I1.compare(I2);
  }

  static APSInt get(int64_t X) { return APSInt(APInt(64, X), false); }
  static APSInt getUnsigned(uint64_t X) { return APSInt(APInt(64, X), true); }

                                                                             
                                 
  void Profile(FoldingSetNodeID& ID) const;
};

inline bool operator==(int64_t V1, const APSInt &V2) { return V2 == V1; }
inline bool operator!=(int64_t V1, const APSInt &V2) { return V2 != V1; }
inline bool operator<=(int64_t V1, const APSInt &V2) { return V2 >= V1; }
inline bool operator>=(int64_t V1, const APSInt &V2) { return V2 <= V1; }
inline bool operator<(int64_t V1, const APSInt &V2) { return V2 > V1; }
inline bool operator>(int64_t V1, const APSInt &V2) { return V2 < V1; }

inline raw_ostream &operator<<(raw_ostream &OS, const APSInt &I) {
  I.print(OS, I.isSigned());
  return OS;
}

}                      

#endif

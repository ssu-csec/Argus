//===-- llvm/ADT/APInt.h - For Arbitrary Precision Integer -----*- C++ -*--===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file implements a class to represent arbitrary precision
/// integral constant values and operations on them.
///
//===----------------------------------------------------------------------===//
#ifndef LLVM_ADT_APINT_H
#define LLVM_ADT_APINT_H

#include "llvh/Support/Compiler.h"
#include "llvh/Support/MathExtras.h"
#include <cassert>
#include <climits>
#include <cstring>
#include <string>

#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif

namespace llvh {
class FoldingSetNodeID;
class StringRef;
class hash_code;
class raw_ostream;

template <typename T> class SmallVectorImpl;
template <typename T> class ArrayRef;
template <typename T> class Optional;

class APInt;

inline APInt operator-(APInt);

                                                                                
                                           
                                                                                

                                           
   
                                                                                
                                                                             
                                                                                
                                                                               
                                                                               
                                                                               
                 
   
                                                  
                                                         
                                                                            
                                             
                                                                              
                                                                         
                                       
                                                                            
                                                                                
                                                                              
                                                                                
                                                                             
            
                                                                                
                                                         
   
class LLVM_NODISCARD APInt {
public:
  typedef uint64_t WordType;

                                                                  
  enum : unsigned {
                            
    APINT_WORD_SIZE = sizeof(WordType),
                       
    APINT_BITS_PER_WORD = APINT_WORD_SIZE * CHAR_BIT
  };

  enum class Rounding {
    DOWN,
    TOWARD_ZERO,
    UP,
  };

  static const WordType WORDTYPE_MAX = ~WordType(0);

private:
                                                             
                                                                   
  union {
    uint64_t VAL;                                                   
    uint64_t *pVal;                                               
  } U;

  unsigned BitWidth;                                       

  friend struct DenseMapAPIntKeyInfo;

  friend class APSInt;

                               
     
                                                                           
                                                                    
  APInt(uint64_t *val, unsigned bits) : BitWidth(bits) {
    U.pVal = val;
  }

                                                               
     
                                                                 
  bool isSingleWord() const { return BitWidth <= APINT_BITS_PER_WORD; }

                                       
     
                                                                
  static unsigned whichWord(unsigned bitPosition) {
    return bitPosition / APINT_BITS_PER_WORD;
  }

                                                
     
                                                                        
                   
  static unsigned whichBit(unsigned bitPosition) {
    return bitPosition % APINT_BITS_PER_WORD;
  }

                            
     
                                                                      
                                                                           
                                                                         
                         
  static uint64_t maskBit(unsigned bitPosition) {
    return 1ULL << whichBit(bitPosition);
  }

                                  
     
                                                                                
                                                                        
                                                                        
                 
  APInt &clearUnusedBits() {
                                                       
    unsigned WordBits = ((BitWidth-1) % APINT_BITS_PER_WORD) + 1;

                              
    uint64_t mask = WORDTYPE_MAX >> (APINT_BITS_PER_WORD - WordBits);
    if (isSingleWord())
      U.VAL &= mask;
    else
      U.pVal[getNumWords() - 1] &= mask;
    return *this;
  }

                                                  
                                                                     
  uint64_t getWord(unsigned bitPosition) const {
    return isSingleWord() ? U.VAL : U.pVal[whichWord(bitPosition)];
  }

                                                                            
                                                                               
                                                                           
  void reallocate(unsigned NewBitWidth);

                                        
     
                                      
                                                                    
                                                                  
                                            
     
                                                                  
     
                                                                   
                                                                 
                               
  void fromString(unsigned numBits, StringRef str, uint8_t radix);

                                                        
     
                                                                           
                                                                               
                                                                              
                                                
  static void divide(const WordType *LHS, unsigned lhsWords,
                     const WordType *RHS, unsigned rhsWords, WordType *Quotient,
                     WordType *Remainder);

                                                  
  void initSlowCase(uint64_t val, bool isSigned);

                                                
  void initFromArray(ArrayRef<uint64_t> array);

                                                       
  void initSlowCase(const APInt &that);

                                   
  void shlSlowCase(unsigned ShiftAmt);

                                     
  void lshrSlowCase(unsigned ShiftAmt);

                                     
  void ashrSlowCase(unsigned ShiftAmt);

                                         
  void AssignSlowCase(const APInt &RHS);

                                          
  bool EqualSlowCase(const APInt &RHS) const LLVM_READONLY;

                                                 
  unsigned countLeadingZerosSlowCase() const LLVM_READONLY;

                                                 
  unsigned countLeadingOnesSlowCase() const LLVM_READONLY;

                                                   
  unsigned countTrailingZerosSlowCase() const LLVM_READONLY;

                                                 
  unsigned countTrailingOnesSlowCase() const LLVM_READONLY;

                                               
  unsigned countPopulationSlowCase() const LLVM_READONLY;

                                           
  bool intersectsSlowCase(const APInt &RHS) const LLVM_READONLY;

                                           
  bool isSubsetOfSlowCase(const APInt &RHS) const LLVM_READONLY;

                                        
  void setBitsSlowCase(unsigned loBit, unsigned hiBit);

                                            
  void flipAllBitsSlowCase();

                                           
  void AndAssignSlowCase(const APInt& RHS);

                                           
  void OrAssignSlowCase(const APInt& RHS);

                                           
  void XorAssignSlowCase(const APInt& RHS);

                                                                                
                              
  int compare(const APInt &RHS) const LLVM_READONLY;

                                                                              
                              
  int compareSigned(const APInt &RHS) const LLVM_READONLY;

public:
                        
        

                                                              
     
                                                                          
                                                                              
                                                                               
                                        
     
                                                           
                                               
                                                    
  APInt(unsigned numBits, uint64_t val, bool isSigned = false)
      : BitWidth(numBits) {
    assert(BitWidth && "bitwidth too small");
    if (isSingleWord()) {
      U.VAL = val;
      clearUnusedBits();
    } else {
      initSlowCase(val, isSigned);
    }
  }

                                                                   
     
                                                                             
                                                        
     
                                                           
                                                                              
  APInt(unsigned numBits, ArrayRef<uint64_t> bigVal);

                                                                             
                                                                        
                                                  
     
                                                                             
                                                                            
                  
  APInt(unsigned numBits, unsigned numWords, const uint64_t bigVal[]);

                                                      
     
                                                                           
                                                                                
                                                                             
                                                                           
                                               
     
                                                           
                                             
                                                      
  APInt(unsigned numBits, StringRef str, uint8_t radix);

                                        
                       
  APInt(const APInt &that) : BitWidth(that.BitWidth) {
    if (isSingleWord())
      U.VAL = that.U.VAL;
    else
      initSlowCase(that);
  }

                       
  APInt(APInt &&that) : BitWidth(that.BitWidth) {
    memcpy(&U, &that.U, sizeof(U));
    that.BitWidth = 0;
  }

                 
  ~APInt() {
    if (needsCleanup())
      delete[] U.pVal;
  }

                                                             
                                      
     
                                                                          
                    
  explicit APInt() : BitWidth(1) { U.VAL = 0; }

                                                     
  bool needsCleanup() const { return !isSingleWord(); }

                                                                               
                   
  void Profile(FoldingSetNodeID &id) const;

        
                       
        

                                   
     
                                                                      
     
                                                              
  bool isNegative() const { return (*this)[BitWidth - 1]; }

                                                          
     
                                                                       
  bool isNonNegative() const { return !isNegative(); }

                                                 
     
                                                                      
     
                                                                        
  bool isSignBitSet() const { return (*this)[BitWidth-1]; }

                                                   
     
                                                                        
     
                                                                          
  bool isSignBitClear() const { return !isSignBitSet(); }

                                                
     
                                                                   
                                     
     
                                              
  bool isStrictlyPositive() const { return isNonNegative() && !isNullValue(); }

                                   
     
                                                                               
  bool isAllOnesValue() const {
    if (isSingleWord())
      return U.VAL == WORDTYPE_MAX >> (APINT_BITS_PER_WORD - BitWidth);
    return countTrailingOnesSlowCase() == BitWidth;
  }

                                     
     
                                                                            
          
  bool isNullValue() const { return !*this; }

                                        
     
                                                           
  bool isOneValue() const {
    if (isSingleWord())
      return U.VAL == 1;
    return countLeadingZerosSlowCase() == BitWidth - 1;
  }

                                                      
     
                                                                           
                                      
  bool isMaxValue() const { return isAllOnesValue(); }

                                                    
     
                                                                         
                                      
  bool isMaxSignedValue() const {
    if (isSingleWord())
      return U.VAL == ((WordType(1) << (BitWidth - 1)) - 1);
    return !isNegative() && countTrailingOnesSlowCase() == BitWidth - 1;
  }

                                                       
     
                                                                           
                                      
  bool isMinValue() const { return isNullValue(); }

                                                     
     
                                                                         
                                      
  bool isMinSignedValue() const {
    if (isSingleWord())
      return U.VAL == (WordType(1) << (BitWidth - 1));
    return isNegative() && countTrailingZerosSlowCase() == BitWidth - 1;
  }

                                                               
  bool isIntN(unsigned N) const {
    assert(N && "N == 0 ???");
    return getActiveBits() <= N;
  }

                                                             
  bool isSignedIntN(unsigned N) const {
    assert(N && "N == 0 ???");
    return getMinSignedBits() <= N;
  }

                                                                      
     
                                                                      
  bool isPowerOf2() const {
    if (isSingleWord())
      return isPowerOf2_64(U.VAL);
    return countPopulationSlowCase() == 1;
  }

                                                            
     
                                                                 
  bool isSignMask() const { return isMinSignedValue(); }

                                       
     
                                                                        
  bool getBoolValue() const { return !!*this; }

                                                                             
                                                                              
  uint64_t getLimitedValue(uint64_t Limit = UINT64_MAX) const {
    return ugt(Limit) ? Limit : getZExtValue();
  }

                                                            
     
                                           
                                                                             
                              
  bool isSplat(unsigned SplatSizeInBits) const;

                                                                            
                                                                    
  bool isMask(unsigned numBits) const {
    assert(numBits != 0 && "numBits must be non-zero");
    assert(numBits <= BitWidth && "numBits out of range");
    if (isSingleWord())
      return U.VAL == (WORDTYPE_MAX >> (APINT_BITS_PER_WORD - numBits));
    unsigned Ones = countTrailingOnesSlowCase();
    return (numBits == Ones) &&
           ((Ones + countLeadingZerosSlowCase()) == BitWidth);
  }

                                                                             
                                                        
                                      
  bool isMask() const {
    if (isSingleWord())
      return isMask_64(U.VAL);
    unsigned Ones = countTrailingOnesSlowCase();
    return (Ones > 0) && ((Ones + countLeadingZerosSlowCase()) == BitWidth);
  }

                                                                      
                         
  bool isShiftedMask() const {
    if (isSingleWord())
      return isShiftedMask_64(U.VAL);
    unsigned Ones = countPopulationSlowCase();
    unsigned LeadZ = countLeadingZerosSlowCase();
    return (Ones + LeadZ + countTrailingZeros()) == BitWidth;
  }

        
                            
        

                                                                  
  static APInt getMaxValue(unsigned numBits) {
    return getAllOnesValue(numBits);
  }

                                                                  
  static APInt getSignedMaxValue(unsigned numBits) {
    APInt API = getAllOnesValue(numBits);
    API.clearBit(numBits - 1);
    return API;
  }

                                                                    
  static APInt getMinValue(unsigned numBits) { return APInt(numBits, 0); }

                                                                  
  static APInt getSignedMinValue(unsigned numBits) {
    APInt API(numBits, 0);
    API.setBit(numBits - 1);
    return API;
  }

                                                
     
                                                                               
                                                 
  static APInt getSignMask(unsigned BitWidth) {
    return getSignedMinValue(BitWidth);
  }

                             
     
                                                                          
  static APInt getAllOnesValue(unsigned numBits) {
    return APInt(numBits, WORDTYPE_MAX, true);
  }

                        
     
                                                                     
  static APInt getNullValue(unsigned numBits) { return APInt(numBits, 0); }

                                                                   
     
                                                                       
                                                                
     
                                                     
  APInt getHiBits(unsigned numBits) const;

                                                                  
     
                                                                       
                    
     
                                                    
  APInt getLoBits(unsigned numBits) const;

                                                             
  static APInt getOneBitSet(unsigned numBits, unsigned BitNo) {
    APInt Res(numBits, 0);
    Res.setBit(BitNo);
    return Res;
  }

                                           
     
                                                                            
                                                                             
                                                                              
                                                                           
                                                                     
     
                                                         
                                                   
                                                    
     
                                                          
  static APInt getBitsSet(unsigned numBits, unsigned loBit, unsigned hiBit) {
    APInt Res(numBits, 0);
    Res.setBits(loBit, hiBit);
    return Res;
  }

                                                        
     
                                                                            
                                                                               
                                                                           
                 
     
                                                         
                                                      
     
                                                          
  static APInt getBitsSetFrom(unsigned numBits, unsigned loBit) {
    APInt Res(numBits, 0);
    Res.setBitsFrom(loBit);
    return Res;
  }

                                    
     
                                                                    
     
                                               
                                                                       
  static APInt getHighBitsSet(unsigned numBits, unsigned hiBitsSet) {
    APInt Res(numBits, 0);
    Res.setHighBits(hiBitsSet);
    return Res;
  }

                                   
     
                                                                       
     
                                               
                                                                      
  static APInt getLowBitsSet(unsigned numBits, unsigned loBitsSet) {
    APInt Res(numBits, 0);
    Res.setLowBits(loBitsSet);
    return Res;
  }

                                                               
  static APInt getSplat(unsigned NewLen, const APInt &V);

                                                                       
                                                                   
  static bool isSameValue(const APInt &I1, const APInt &I2) {
    if (I1.getBitWidth() == I2.getBitWidth())
      return I1 == I2;

    if (I1.getBitWidth() > I2.getBitWidth())
      return I1 == I2.zext(I1.getBitWidth());

    return I1.zext(I2.getBitWidth()) == I2;
  }

                                                         
  friend hash_code hash_value(const APInt &Arg);

                                                                           
                                                                         
                  
  const uint64_t *getRawData() const {
    if (isSingleWord())
      return &U.VAL;
    return &U.pVal[0];
  }

        
                           
        

                                 
     
                            
     
                                                                          
  const APInt operator++(int) {
    APInt API(*this);
    ++(*this);
    return API;
  }

                                
     
                                       
  APInt &operator++();

                                 
     
                            
     
                                                                          
  const APInt operator--(int) {
    APInt API(*this);
    --(*this);
    return API;
  }

                                
     
                                        
  APInt &operator--();

                                
     
                                                        
     
                                                      
  bool operator!() const {
    if (isSingleWord())
      return U.VAL == 0;
    return countLeadingZerosSlowCase() == BitWidth;
  }

        
                                
        

                               
     
                                             
  APInt &operator=(const APInt &RHS) {
                                                                      
    if (isSingleWord() && RHS.isSingleWord()) {
      U.VAL = RHS.U.VAL;
      BitWidth = RHS.BitWidth;
      return clearUnusedBits();
    }

    AssignSlowCase(RHS);
    return *this;
  }

                               
  APInt &operator=(APInt &&that) {
#ifdef _MSC_VER
                                                                       
    if (this == &that)
      return *this;
#endif
    assert(this != &that && "Self-move not supported");
    if (!isSingleWord())
      delete[] U.pVal;

                                                                          
                   
    memcpy(&U, &that.U, sizeof(U));

    BitWidth = that.BitWidth;
    that.BitWidth = 0;

    return *this;
  }

                          
     
                                                                               
                                                                              
                                                                           
     
                                                   
  APInt &operator=(uint64_t RHS) {
    if (isSingleWord()) {
      U.VAL = RHS;
      clearUnusedBits();
    } else {
      U.pVal[0] = RHS;
      memset(U.pVal+1, 0, (getNumWords() - 1) * APINT_WORD_SIZE);
    }
    return *this;
  }

                                      
     
                                                                           
                        
     
                                           
  APInt &operator&=(const APInt &RHS) {
    assert(BitWidth == RHS.BitWidth && "Bit widths must be the same");
    if (isSingleWord())
      U.VAL &= RHS.U.VAL;
    else
      AndAssignSlowCase(RHS);
    return *this;
  }

                                      
     
                                                                    
                                                                    
              
  APInt &operator&=(uint64_t RHS) {
    if (isSingleWord()) {
      U.VAL &= RHS;
      return *this;
    }
    U.pVal[0] &= RHS;
    memset(U.pVal+1, 0, (getNumWords() - 1) * APINT_WORD_SIZE);
    return *this;
  }

                                     
     
                                                                          
                     
     
                                          
  APInt &operator|=(const APInt &RHS) {
    assert(BitWidth == RHS.BitWidth && "Bit widths must be the same");
    if (isSingleWord())
      U.VAL |= RHS.U.VAL;
    else
      OrAssignSlowCase(RHS);
    return *this;
  }

                                     
     
                                                                   
                                                                    
              
  APInt &operator|=(uint64_t RHS) {
    if (isSingleWord()) {
      U.VAL |= RHS;
      clearUnusedBits();
    } else {
      U.pVal[0] |= RHS;
    }
    return *this;
  }

                                      
     
                                                                           
                        
     
                                           
  APInt &operator^=(const APInt &RHS) {
    assert(BitWidth == RHS.BitWidth && "Bit widths must be the same");
    if (isSingleWord())
      U.VAL ^= RHS.U.VAL;
    else
      XorAssignSlowCase(RHS);
    return *this;
  }

                                      
     
                                                                    
                                                                    
              
  APInt &operator^=(uint64_t RHS) {
    if (isSingleWord()) {
      U.VAL ^= RHS;
      clearUnusedBits();
    } else {
      U.pVal[0] ^= RHS;
    }
    return *this;
  }

                                         
     
                                                                   
     
                    
  APInt &operator*=(const APInt &RHS);
  APInt &operator*=(uint64_t RHS);

                                   
     
                                                        
     
                    
  APInt &operator+=(const APInt &RHS);
  APInt &operator+=(uint64_t RHS);

                                      
     
                                                               
     
                    
  APInt &operator-=(const APInt &RHS);
  APInt &operator-=(uint64_t RHS);

                                     
     
                                                                    
     
                                                    
  APInt &operator<<=(unsigned ShiftAmt) {
    assert(ShiftAmt <= BitWidth && "Invalid shift amount");
    if (isSingleWord()) {
      if (ShiftAmt == BitWidth)
        U.VAL = 0;
      else
        U.VAL <<= ShiftAmt;
      return clearUnusedBits();
    }
    shlSlowCase(ShiftAmt);
    return *this;
  }

                                     
     
                                                                    
     
                                                    
  APInt &operator<<=(const APInt &ShiftAmt);

        
                            
        

                              
     
                                                          
  APInt operator*(const APInt &RHS) const;

                                  
     
                                                               
  APInt operator<<(unsigned Bits) const { return shl(Bits); }

                                  
     
                                                               
  APInt operator<<(const APInt &Bits) const { return shl(Bits); }

                                      
     
                                                    
  APInt ashr(unsigned ShiftAmt) const {
    APInt R(*this);
    R.ashrInPlace(ShiftAmt);
    return R;
  }

                                                             
  void ashrInPlace(unsigned ShiftAmt) {
    assert(ShiftAmt <= BitWidth && "Invalid shift amount");
    if (isSingleWord()) {
      int64_t SExtVAL = SignExtend64(U.VAL, BitWidth);
      if (ShiftAmt == BitWidth)
        U.VAL = SExtVAL >> (APINT_BITS_PER_WORD - 1);                       
      else
        U.VAL = SExtVAL >> ShiftAmt;
      clearUnusedBits();
      return;
    }
    ashrSlowCase(ShiftAmt);
  }

                                   
     
                                                 
  APInt lshr(unsigned shiftAmt) const {
    APInt R(*this);
    R.lshrInPlace(shiftAmt);
    return R;
  }

                                                          
  void lshrInPlace(unsigned ShiftAmt) {
    assert(ShiftAmt <= BitWidth && "Invalid shift amount");
    if (isSingleWord()) {
      if (ShiftAmt == BitWidth)
        U.VAL = 0;
      else
        U.VAL >>= ShiftAmt;
      return;
    }
    lshrSlowCase(ShiftAmt);
  }

                          
     
                                        
  APInt shl(unsigned shiftAmt) const {
    APInt R(*this);
    R <<= shiftAmt;
    return R;
  }

                               
  APInt rotl(unsigned rotateAmt) const;

                                
  APInt rotr(unsigned rotateAmt) const;

                                      
     
                                                    
  APInt ashr(const APInt &ShiftAmt) const {
    APInt R(*this);
    R.ashrInPlace(ShiftAmt);
    return R;
  }

                                                             
  void ashrInPlace(const APInt &shiftAmt);

                                   
     
                                                 
  APInt lshr(const APInt &ShiftAmt) const {
    APInt R(*this);
    R.lshrInPlace(ShiftAmt);
    return R;
  }

                                                          
  void lshrInPlace(const APInt &ShiftAmt);

                          
     
                                        
  APInt shl(const APInt &ShiftAmt) const {
    APInt R(*this);
    R <<= ShiftAmt;
    return R;
  }

                               
  APInt rotl(const APInt &rotateAmt) const;

                                
  APInt rotr(const APInt &rotateAmt) const;

                                  
     
                                                                              
                                                                           
     
                                                                                
           
  APInt udiv(const APInt &RHS) const;
  APInt udiv(uint64_t RHS) const;

                                         
     
                                            
     
                                         
  APInt sdiv(const APInt &RHS) const;
  APInt sdiv(int64_t RHS) const;

                                   
     
                                                                              
                                                                                
                                                                               
                                                                              
               
     
                                                                
  APInt urem(const APInt &RHS) const;
  uint64_t urem(uint64_t RHS) const;

                                              
     
                                          
  APInt srem(const APInt &RHS) const;
  int64_t srem(int64_t RHS) const;

                                        
     
                                                                               
                                                                            
                                                                                
                                                                       
                                       
  static void udivrem(const APInt &LHS, const APInt &RHS, APInt &Quotient,
                      APInt &Remainder);
  static void udivrem(const APInt &LHS, uint64_t RHS, APInt &Quotient,
                      uint64_t &Remainder);

  static void sdivrem(const APInt &LHS, const APInt &RHS, APInt &Quotient,
                      APInt &Remainder);
  static void sdivrem(const APInt &LHS, int64_t RHS, APInt &Quotient,
                      int64_t &Remainder);

                                                
  APInt sadd_ov(const APInt &RHS, bool &Overflow) const;
  APInt uadd_ov(const APInt &RHS, bool &Overflow) const;
  APInt ssub_ov(const APInt &RHS, bool &Overflow) const;
  APInt usub_ov(const APInt &RHS, bool &Overflow) const;
  APInt sdiv_ov(const APInt &RHS, bool &Overflow) const;
  APInt smul_ov(const APInt &RHS, bool &Overflow) const;
  APInt umul_ov(const APInt &RHS, bool &Overflow) const;
  APInt sshl_ov(const APInt &Amt, bool &Overflow) const;
  APInt ushl_ov(const APInt &Amt, bool &Overflow) const;

                             
     
                                           
  bool operator[](unsigned bitPosition) const {
    assert(bitPosition < getBitWidth() && "Bit position out of bounds!");
    return (maskBit(bitPosition) & getWord(bitPosition)) != 0;
  }

        
                                
        

                        
     
                                                                   
                   
  bool operator==(const APInt &RHS) const {
    assert(BitWidth == RHS.BitWidth && "Comparison requires equal bit widths");
    if (isSingleWord())
      return U.VAL == RHS.U.VAL;
    return EqualSlowCase(RHS);
  }

                        
     
                                                                          
                   
     
                                   
  bool operator==(uint64_t Val) const {
    return (isSingleWord() || getActiveBits() <= 64) && getZExtValue() == Val;
  }

                          
     
                                                                   
                   
     
                                   
  bool eq(const APInt &RHS) const { return (*this) == RHS; }

                          
     
                                                                     
                   
     
                                   
  bool operator!=(const APInt &RHS) const { return !((*this) == RHS); }

                          
     
                                                                            
                   
     
                                   
  bool operator!=(uint64_t Val) const { return !((*this) == Val); }

                           
     
                                                                     
                   
     
                                   
  bool ne(const APInt &RHS) const { return !((*this) == RHS); }

                                   
     
                                                                             
                                                 
     
                                                                     
  bool ult(const APInt &RHS) const { return compare(RHS) < 0; }

                                   
     
                                                                             
                                                 
     
                                                            
  bool ult(uint64_t RHS) const {
                                                           
    return (isSingleWord() || getActiveBits() <= 64) && getZExtValue() < RHS;
  }

                                 
     
                                                                           
                                             
     
                                                                   
  bool slt(const APInt &RHS) const { return compareSigned(RHS) < 0; }

                                 
     
                                                                          
                                                 
     
                                                          
  bool slt(int64_t RHS) const {
    return (!isSingleWord() && getMinSignedBits() > 64) ? isNegative()
                                                        : getSExtValue() < RHS;
  }

                                       
     
                                                                             
                                                 
     
                                                                      
  bool ule(const APInt &RHS) const { return compare(RHS) <= 0; }

                                       
     
                                                                             
                                                     
     
                                                             
  bool ule(uint64_t RHS) const { return !ugt(RHS); }

                                     
     
                                                                           
                                                 
     
                                                                    
  bool sle(const APInt &RHS) const { return compareSigned(RHS) <= 0; }

                                     
     
                                                                              
                                                 
     
                                                           
  bool sle(uint64_t RHS) const { return !sgt(RHS); }

                                       
     
                                                                             
                                                    
     
                                                                     
  bool ugt(const APInt &RHS) const { return !ule(RHS); }

                                      
     
                                                                             
                                                    
     
                                                            
  bool ugt(uint64_t RHS) const {
                                                           
    return (!isSingleWord() && getActiveBits() > 64) || getZExtValue() > RHS;
  }

                                     
     
                                                                               
                                                
     
                                                                   
  bool sgt(const APInt &RHS) const { return !sle(RHS); }

                                    
     
                                                                          
                                                    
     
                                                          
  bool sgt(int64_t RHS) const {
    return (!isSingleWord() && getMinSignedBits() > 64) ? !isNegative()
                                                        : getSExtValue() > RHS;
  }

                                          
     
                                                                             
                                                    
     
                                                                      
  bool uge(const APInt &RHS) const { return !ult(RHS); }

                                          
     
                                                                             
                                                        
     
                                                             
  bool uge(uint64_t RHS) const { return !ult(RHS); }

                                        
     
                                                                           
                                                    
     
                                                                    
  bool sge(const APInt &RHS) const { return !slt(RHS); }

                                        
     
                                                                          
                                                        
     
                                                           
  bool sge(int64_t RHS) const { return !slt(RHS); }

                                                                       
                                                   
  bool intersects(const APInt &RHS) const {
    assert(BitWidth == RHS.BitWidth && "Bit widths must be the same");
    if (isSingleWord())
      return (U.VAL & RHS.U.VAL) != 0;
    return intersectsSlowCase(RHS);
  }

                                                                                
  bool isSubsetOf(const APInt &RHS) const {
    assert(BitWidth == RHS.BitWidth && "Bit widths must be the same");
    if (isSingleWord())
      return (U.VAL & ~RHS.U.VAL) == 0;
    return isSubsetOfSlowCase(RHS);
  }

        
                              
        

                            
     
                                                                                
                                                         
  APInt trunc(unsigned width) const;

                                 
     
                                                                             
                                                                                
                                                                         
                    
  APInt sext(unsigned width) const;

                                 
     
                                                                               
                                                                             
                                         
  APInt zext(unsigned width) const;

                                      
     
                                                                             
                                                               
  APInt sextOrTrunc(unsigned width) const;

                                      
     
                                                                             
                                                               
  APInt zextOrTrunc(unsigned width) const;

                                      
     
                                                                             
                                                    
  APInt sextOrSelf(unsigned width) const;

                                      
     
                                                                             
                                                    
  APInt zextOrSelf(unsigned width) const;

        
                                      
        

                         
  void setAllBits() {
    if (isSingleWord())
      U.VAL = WORDTYPE_MAX;
    else
                                           
      memset(U.pVal, -1, getNumWords() * APINT_WORD_SIZE);
                            
    clearUnusedBits();
  }

                           
     
                                                                      
  void setBit(unsigned BitPosition) {
    assert(BitPosition <= BitWidth && "BitPosition out of range");
    WordType Mask = maskBit(BitPosition);
    if (isSingleWord())
      U.VAL |= Mask;
    else
      U.pVal[whichWord(BitPosition)] |= Mask;
  }

                            
  void setSignBit() {
    setBit(BitWidth - 1);
  }

                                                                    
  void setBits(unsigned loBit, unsigned hiBit) {
    assert(hiBit <= BitWidth && "hiBit out of range");
    assert(loBit <= BitWidth && "loBit out of range");
    assert(loBit <= hiBit && "loBit greater than hiBit");
    if (loBit == hiBit)
      return;
    if (loBit < APINT_BITS_PER_WORD && hiBit <= APINT_BITS_PER_WORD) {
      uint64_t mask = WORDTYPE_MAX >> (APINT_BITS_PER_WORD - (hiBit - loBit));
      mask <<= loBit;
      if (isSingleWord())
        U.VAL |= mask;
      else
        U.pVal[0] |= mask;
    } else {
      setBitsSlowCase(loBit, hiBit);
    }
  }

                                           
  void setBitsFrom(unsigned loBit) {
    return setBits(loBit, BitWidth);
  }

                                 
  void setLowBits(unsigned loBits) {
    return setBits(0, loBits);
  }

                              
  void setHighBits(unsigned hiBits) {
    return setBits(BitWidth - hiBits, BitWidth);
  }

                         
  void clearAllBits() {
    if (isSingleWord())
      U.VAL = 0;
    else
      memset(U.pVal, 0, getNumWords() * APINT_WORD_SIZE);
  }

                           
     
                                                                      
  void clearBit(unsigned BitPosition) {
    assert(BitPosition <= BitWidth && "BitPosition out of range");
    WordType Mask = ~maskBit(BitPosition);
    if (isSingleWord())
      U.VAL &= Mask;
    else
      U.pVal[whichWord(BitPosition)] &= Mask;
  }

                            
  void clearSignBit() {
    clearBit(BitWidth - 1);
  }

                                             
  void flipAllBits() {
    if (isSingleWord()) {
      U.VAL ^= WORDTYPE_MAX;
      clearUnusedBits();
    } else {
      flipAllBitsSlowCase();
    }
  }

                                                
     
                                                                      
                       
  void flipBit(unsigned bitPosition);

                                 
  void negate() {
    flipAllBits();
    ++(*this);
  }

                                                                   
  void insertBits(const APInt &SubBits, unsigned bitPosition);

                                                                                
  APInt extractBits(unsigned numBits, unsigned bitPosition) const;

        
                                            
        

                                             
  unsigned getBitWidth() const { return BitWidth; }

                              
     
                                                          
     
                                                                           
  unsigned getNumWords() const { return getNumWords(BitWidth); }

                              
     
                                                                 
     
                                                                             
            
  static unsigned getNumWords(unsigned BitWidth) {
    return ((uint64_t)BitWidth + APINT_BITS_PER_WORD - 1) / APINT_BITS_PER_WORD;
  }

                                                    
     
                                                                             
                                                                          
                                                  
  unsigned getActiveBits() const { return BitWidth - countLeadingZeros(); }

                                                                    
     
                                                                                
                
  unsigned getActiveWords() const {
    unsigned numActiveBits = getActiveBits();
    return numActiveBits ? whichWord(numActiveBits - 1) + 1 : 1;
  }

                                                    
     
                                                                                
                                                                              
                                                                         
                                                                             
                                                                              
                                                 
  unsigned getMinSignedBits() const {
    if (isNegative())
      return BitWidth - countLeadingOnes() + 1;
    return getActiveBits() + 1;
  }

                             
     
                                                                               
                                                                         
                                                   
  uint64_t getZExtValue() const {
    if (isSingleWord())
      return U.VAL;
    assert(getActiveBits() <= 64 && "Too many bits for uint64_t");
    return U.pVal[0];
  }

                             
     
                                                                               
                                                                          
                                                  
  int64_t getSExtValue() const {
    if (isSingleWord())
      return SignExtend64(U.VAL, BitWidth);
    assert(getMinSignedBits() <= 64 && "Too many bits for int64_t");
    return int64_t(U.pVal[0]);
  }

                                         
     
                                                                         
                                               
  static unsigned getBitsNeeded(StringRef str, uint8_t radix);

                                                             
                     
     
                                                                              
              
     
                                                                             
                                                                  
  unsigned countLeadingZeros() const {
    if (isSingleWord()) {
      unsigned unusedBits = APINT_BITS_PER_WORD - BitWidth;
      return llvh::countLeadingZeros(U.VAL) - unusedBits;
    }
    return countLeadingZerosSlowCase();
  }

                                           
     
                                                               
                                                                           
                                            
     
                                                                               
                                                      
  unsigned countLeadingOnes() const {
    if (isSingleWord())
      return llvh::countLeadingOnes(U.VAL << (APINT_BITS_PER_WORD - BitWidth));
    return countLeadingOnesSlowCase();
  }

                                                                             
               
  unsigned getNumSignBits() const {
    return isNegative() ? countLeadingOnes() : countLeadingZeros();
  }

                                             
     
                                                                 
                                                                             
                                           
     
                                                                             
                                                                
  unsigned countTrailingZeros() const {
    if (isSingleWord())
      return std::min(unsigned(llvh::countTrailingZeros(U.VAL)), BitWidth);
    return countTrailingZerosSlowCase();
  }

                                            
     
                                                                
                                                                            
                                            
     
                                                                              
                                                                   
  unsigned countTrailingOnes() const {
    if (isSingleWord())
      return llvh::countTrailingOnes(U.VAL);
    return countTrailingOnesSlowCase();
  }

                                   
     
                                                                        
                                                                         
     
                                                                                
  unsigned countPopulation() const {
    if (isSingleWord())
      return llvh::countPopulation(U.VAL);
    return countPopulationSlowCase();
  }

        
                                
        
  void print(raw_ostream &OS, bool isSigned) const;

                                                                            
                  
  void toString(SmallVectorImpl<char> &Str, unsigned Radix, bool Signed,
                bool formatAsCLiteral = false) const;

                                                                             
                                                       
  void toStringUnsigned(SmallVectorImpl<char> &Str, unsigned Radix = 10) const {
    toString(Str, Radix, false, false);
  }

                                                                           
                                                        
  void toStringSigned(SmallVectorImpl<char> &Str, unsigned Radix = 10) const {
    toString(Str, Radix, true, false);
  }

                                        
     
                                                                         
                                                                              
                     
  std::string toString(unsigned Radix, bool Signed) const;

                                                                 
  APInt byteSwap() const;

                                                                           
            
  APInt reverseBits() const;

                                            
  double roundToDouble(bool isSigned) const;

                                                     
  double roundToDouble() const { return roundToDouble(false); }

                                                   
  double signedRoundToDouble() const { return roundToDouble(true); }

                                     
     
                                                                              
                                                                             
                                                        
  double bitsToDouble() const {
    return BitsToDouble(getWord(0));
  }

                                     
     
                                                                             
                                                                            
                                                        
  float bitsToFloat() const {
    return BitsToFloat(getWord(0));
  }

                                      
     
                                                                              
                                           
  static APInt doubleToBits(double V) {
    return APInt(sizeof(double) * CHAR_BIT, DoubleToBits(V));
  }

                                     
     
                                                                             
                                          
  static APInt floatToBits(float V) {
    return APInt(sizeof(float) * CHAR_BIT, FloatToBits(V));
  }

        
                                  
        

                                                  
  unsigned logBase2() const { return getActiveBits() -  1; }

                                                 
  unsigned ceilLogBase2() const {
    APInt temp(*this);
    --temp;
    return temp.getActiveBits();
  }

                                                                   
     
                                                    
     
                            
                   
     
                                                            
                                                     
  unsigned nearestLogBase2() const {
                                                                      
                                                                      
                  
    if (BitWidth == 1)
      return U.VAL - 1;

                            
    if (isNullValue())
      return UINT32_MAX;

                                                 
      
                                                             
      
                                                                
    unsigned lg = logBase2();
    return lg + unsigned((*this)[lg - 1]);
  }

                                                                            
               
  int32_t exactLogBase2() const {
    if (!isPowerOf2())
      return -1;
    return logBase2();
  }

                             
  APInt sqrt() const;

                             
     
                                                            
  APInt abs() const {
    if (isNegative())
      return -(*this);
    return *this;
  }

                                                             
  APInt multiplicativeInverse(const APInt &modulo) const;

        
                                            
        

                                                                   
  struct ms;
  ms magic() const;

                                                                     
  struct mu;
  mu magicu(unsigned LeadingZeros = 0) const;

        
                                                           
        

                                                                             
                                                                       
                                                                              
                                                                               
                                                                 

                                                                                
                       
  static void tcSet(WordType *, WordType, unsigned);

                                   
  static void tcAssign(WordType *, const WordType *, unsigned);

                                                        
  static bool tcIsZero(const WordType *, unsigned);

                                                                     
  static int tcExtractBit(const WordType *, unsigned bit);

                                                                               
                                                                        
                                                                     
                  
  static void tcExtract(WordType *, unsigned dstCount,
                        const WordType *, unsigned srcBits,
                        unsigned srcLSB);

                                                 
  static void tcSetBit(WordType *, unsigned bit);

                                                   
  static void tcClearBit(WordType *, unsigned bit);

                                                                          
                                                                   
  static unsigned tcLSB(const WordType *, unsigned n);
  static unsigned tcMSB(const WordType *parts, unsigned n);

                               
  static void tcNegate(WordType *, unsigned);

                                                                             
  static WordType tcAdd(WordType *, const WordType *,
                        WordType carry, unsigned);
                                          
  static WordType tcAddPart(WordType *, WordType, unsigned);

                                                                            
  static WordType tcSubtract(WordType *, const WordType *,
                             WordType carry, unsigned);
                                          
  static WordType tcSubtractPart(WordType *, WordType, unsigned);

                                                     
                                                      
     
                                                                            
                                               
     
                                                                           
                                                                              
                                                                           
                                                 
  static int tcMultiplyPart(WordType *dst, const WordType *src,
                            WordType multiplier, WordType carry,
                            unsigned srcParts, unsigned dstParts,
                            bool add);

                                                                          
                                                                            
                                                                        
               
  static int tcMultiply(WordType *, const WordType *, const WordType *,
                        unsigned);

                                                                       
                                                                            
  static void tcFullMultiply(WordType *, const WordType *,
                             const WordType *, unsigned, unsigned);

                                                                      
                                                                            
                                                    
     
                                      
     
                                                                                
                                                                                
                                             
  static int tcDivide(WordType *lhs, const WordType *rhs,
                      WordType *remainder, WordType *scratch,
                      unsigned parts);

                                                                            
                            
  static void tcShiftLeft(WordType *, unsigned Words, unsigned Count);

                                                                               
                            
  static void tcShiftRight(WordType *, unsigned Words, unsigned Count);

                                                            
  static void tcAnd(WordType *, const WordType *, unsigned);
  static void tcOr(WordType *, const WordType *, unsigned);
  static void tcXor(WordType *, const WordType *, unsigned);
  static void tcComplement(WordType *, unsigned);

                                           
  static int tcCompare(const WordType *, const WordType *, unsigned);

                                                          
  static WordType tcIncrement(WordType *dst, unsigned parts) {
    return tcAddPart(dst, 1, parts);
  }

                                                           
  static WordType tcDecrement(WordType *dst, unsigned parts) {
    return tcSubtractPart(dst, 1, parts);
  }

                                                        
  static void tcSetLeastSignificantBits(WordType *, unsigned, unsigned bits);

                  
  void dump() const;

        
};

                                                            
struct APInt::ms {
  APInt m;                     
  unsigned s;                  
};

                                                              
struct APInt::mu {
  APInt m;                     
  bool a;                       
  unsigned s;                  
};

inline bool operator==(uint64_t V1, const APInt &V2) { return V2 == V1; }

inline bool operator!=(uint64_t V1, const APInt &V2) { return V2 != V1; }

                                      
   
                                                             
inline APInt operator~(APInt v) {
  v.flipAllBits();
  return v;
}

inline APInt operator&(APInt a, const APInt &b) {
  a &= b;
  return a;
}

inline APInt operator&(const APInt &a, APInt &&b) {
  b &= a;
  return std::move(b);
}

inline APInt operator&(APInt a, uint64_t RHS) {
  a &= RHS;
  return a;
}

inline APInt operator&(uint64_t LHS, APInt b) {
  b &= LHS;
  return b;
}

inline APInt operator|(APInt a, const APInt &b) {
  a |= b;
  return a;
}

inline APInt operator|(const APInt &a, APInt &&b) {
  b |= a;
  return std::move(b);
}

inline APInt operator|(APInt a, uint64_t RHS) {
  a |= RHS;
  return a;
}

inline APInt operator|(uint64_t LHS, APInt b) {
  b |= LHS;
  return b;
}

inline APInt operator^(APInt a, const APInt &b) {
  a ^= b;
  return a;
}

inline APInt operator^(const APInt &a, APInt &&b) {
  b ^= a;
  return std::move(b);
}

inline APInt operator^(APInt a, uint64_t RHS) {
  a ^= RHS;
  return a;
}

inline APInt operator^(uint64_t LHS, APInt b) {
  b ^= LHS;
  return b;
}

inline raw_ostream &operator<<(raw_ostream &OS, const APInt &I) {
  I.print(OS, true);
  return OS;
}

inline APInt operator-(APInt v) {
  v.negate();
  return v;
}

inline APInt operator+(APInt a, const APInt &b) {
  a += b;
  return a;
}

inline APInt operator+(const APInt &a, APInt &&b) {
  b += a;
  return std::move(b);
}

inline APInt operator+(APInt a, uint64_t RHS) {
  a += RHS;
  return a;
}

inline APInt operator+(uint64_t LHS, APInt b) {
  b += LHS;
  return b;
}

inline APInt operator-(APInt a, const APInt &b) {
  a -= b;
  return a;
}

inline APInt operator-(const APInt &a, APInt &&b) {
  b.negate();
  b += a;
  return std::move(b);
}

inline APInt operator-(APInt a, uint64_t RHS) {
  a -= RHS;
  return a;
}

inline APInt operator-(uint64_t LHS, APInt b) {
  b.negate();
  b += LHS;
  return b;
}

inline APInt operator*(APInt a, uint64_t RHS) {
  a *= RHS;
  return a;
}

inline APInt operator*(uint64_t LHS, APInt b) {
  b *= LHS;
  return b;
}


namespace APIntOps {

                                                                
inline const APInt &smin(const APInt &A, const APInt &B) {
  return A.slt(B) ? A : B;
}

                                                               
inline const APInt &smax(const APInt &A, const APInt &B) {
  return A.sgt(B) ? A : B;
}

                                                                
inline const APInt &umin(const APInt &A, const APInt &B) {
  return A.ult(B) ? A : B;
}

                                                                 
inline const APInt &umax(const APInt &A, const APInt &B) {
  return A.ugt(B) ? A : B;
}

                                             
   
                                                                             
                            
   
                                                    
APInt GreatestCommonDivisor(APInt A, APInt B);

                                               
   
                                                                  
inline double RoundAPIntToDouble(const APInt &APIVal) {
  return APIVal.roundToDouble();
}

                                               
   
                                                               
inline double RoundSignedAPIntToDouble(const APInt &APIVal) {
  return APIVal.signedRoundToDouble();
}

                                               
inline float RoundAPIntToFloat(const APInt &APIVal) {
  return float(RoundAPIntToDouble(APIVal));
}

                                              
   
                                                               
inline float RoundSignedAPIntToFloat(const APInt &APIVal) {
  return float(APIVal.signedRoundToDouble());
}

                                                 
   
                                                           
APInt RoundDoubleToAPInt(double Double, unsigned width);

                                        
   
                                               
inline APInt RoundFloatToAPInt(float Float, unsigned width) {
  return RoundDoubleToAPInt(double(Float), width);
}

                                                                     
APInt RoundingUDiv(const APInt &A, const APInt &B, APInt::Rounding RM);

                                                                   
APInt RoundingSDiv(const APInt &A, const APInt &B, APInt::Rounding RM);

                                                                   
                      
                                                        
                               
                                                                    
                                                               
                                            
                                                                     
                                                                     
                                                                     
                                                                      
                                                              
                                                                    
                                                                       
                                                                 
                                                                  
                                                                    
                                             
   
                                                                    
                                                                        
                             
   
                                                                       
                                                                        
                                                                         
                                                                       
                                                                   
                                                                      
                                                           
   
                                                                    
                 
Optional<APInt> SolveQuadraticEquationWrap(APInt A, APInt B, APInt C,
                                           unsigned RangeWidth);
}                             

                                                                           
                                               
hash_code hash_value(const APInt &Arg);
}                         

#pragma GCC diagnostic pop

#endif

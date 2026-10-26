//===-- APInt.cpp - Implement APInt class ---------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements a class to represent arbitrary precision integer
// constant values and provide a variety of arithmetic operations on them.
//
//===----------------------------------------------------------------------===//

#include "llvh/ADT/APInt.h"
#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/FoldingSet.h"
#include "llvh/ADT/Hashing.h"
#include "llvh/ADT/Optional.h"
#include "llvh/ADT/SmallString.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/bit.h"
#include "llvh/Config/llvm-config.h"
#include "llvh/Support/Debug.h"
#include "llvh/Support/ErrorHandling.h"
#include "llvh/Support/MathExtras.h"
#include "llvh/Support/raw_ostream.h"
#include <climits>
#include <cmath>
#include <cstdlib>
#include <cstring>
using namespace llvh;

#define DEBUG_TYPE "apint"

                                                                               
                                         
inline static uint64_t* getClearedMemory(unsigned numWords) {
  uint64_t *result = new uint64_t[numWords];
  memset(result, 0, numWords * sizeof(uint64_t));
  return result;
}

                                                                        
                                        
inline static uint64_t* getMemory(unsigned numWords) {
  return new uint64_t[numWords];
}

                                                            
inline static unsigned getDigit(char cdigit, uint8_t radix) {
  unsigned r;

  if (radix == 16 || radix == 36) {
    r = cdigit - '0';
    if (r <= 9)
      return r;

    r = cdigit - 'A';
    if (r <= radix - 11U)
      return r + 10;

    r = cdigit - 'a';
    if (r <= radix - 11U)
      return r + 10;

    radix = 10;
  }

  r = cdigit - '0';
  if (r < radix)
    return r;

  return -1U;
}


void APInt::initSlowCase(uint64_t val, bool isSigned) {
  U.pVal = getClearedMemory(getNumWords());
  U.pVal[0] = val;
  if (isSigned && int64_t(val) < 0)
    for (unsigned i = 1; i < getNumWords(); ++i)
      U.pVal[i] = WORDTYPE_MAX;
  clearUnusedBits();
}

void APInt::initSlowCase(const APInt& that) {
  U.pVal = getMemory(getNumWords());
  memcpy(U.pVal, that.U.pVal, getNumWords() * APINT_WORD_SIZE);
}

void APInt::initFromArray(ArrayRef<uint64_t> bigVal) {
  assert(BitWidth && "Bitwidth too small");
  assert(bigVal.data() && "Null pointer detected!");
  if (isSingleWord())
    U.VAL = bigVal[0];
  else {
                               
    U.pVal = getClearedMemory(getNumWords());
                                            
    unsigned words = std::min<unsigned>(bigVal.size(), getNumWords());
                                         
    memcpy(U.pVal, bigVal.data(), words * APINT_WORD_SIZE);
  }
                                           
  clearUnusedBits();
}

APInt::APInt(unsigned numBits, ArrayRef<uint64_t> bigVal)
  : BitWidth(numBits) {
  initFromArray(bigVal);
}

APInt::APInt(unsigned numBits, unsigned numWords, const uint64_t bigVal[])
  : BitWidth(numBits) {
  initFromArray(makeArrayRef(bigVal, numWords));
}

APInt::APInt(unsigned numbits, StringRef Str, uint8_t radix)
  : BitWidth(numbits) {
  assert(BitWidth && "Bitwidth too small");
  fromString(numbits, Str, radix);
}

void APInt::reallocate(unsigned NewBitWidth) {
                                                                              
  if (getNumWords() == getNumWords(NewBitWidth)) {
    BitWidth = NewBitWidth;
    return;
  }

                                         
  if (!isSingleWord())
    delete [] U.pVal;

                     
  BitWidth = NewBitWidth;

                                                         
  if (!isSingleWord())
    U.pVal = getMemory(getNumWords());
}

void APInt::AssignSlowCase(const APInt& RHS) {
                                
  if (this == &RHS)
    return;

                                                              
  reallocate(RHS.getBitWidth());

                   
  if (isSingleWord())
    U.VAL = RHS.U.VAL;
  else
    memcpy(U.pVal, RHS.U.pVal, getNumWords() * APINT_WORD_SIZE);
}

                                                            
void APInt::Profile(FoldingSetNodeID& ID) const {
  ID.AddInteger(BitWidth);

  if (isSingleWord()) {
    ID.AddInteger(U.VAL);
    return;
  }

  unsigned NumWords = getNumWords();
  for (unsigned i = 0; i < NumWords; ++i)
    ID.AddInteger(U.pVal[i]);
}

                                                           
APInt& APInt::operator++() {
  if (isSingleWord())
    ++U.VAL;
  else
    tcIncrement(U.pVal, getNumWords());
  return clearUnusedBits();
}

                                                           
APInt& APInt::operator--() {
  if (isSingleWord())
    --U.VAL;
  else
    tcDecrement(U.pVal, getNumWords());
  return clearUnusedBits();
}

                                     
                                         
                                 
APInt& APInt::operator+=(const APInt& RHS) {
  assert(BitWidth == RHS.BitWidth && "Bit widths must be the same");
  if (isSingleWord())
    U.VAL += RHS.U.VAL;
  else
    tcAdd(U.pVal, RHS.U.pVal, 0, getNumWords());
  return clearUnusedBits();
}

APInt& APInt::operator+=(uint64_t RHS) {
  if (isSingleWord())
    U.VAL += RHS;
  else
    tcAddPart(U.pVal, RHS, getNumWords());
  return clearUnusedBits();
}

                                           
                                    
                                    
APInt& APInt::operator-=(const APInt& RHS) {
  assert(BitWidth == RHS.BitWidth && "Bit widths must be the same");
  if (isSingleWord())
    U.VAL -= RHS.U.VAL;
  else
    tcSubtract(U.pVal, RHS.U.pVal, 0, getNumWords());
  return clearUnusedBits();
}

APInt& APInt::operator-=(uint64_t RHS) {
  if (isSingleWord())
    U.VAL -= RHS;
  else
    tcSubtractPart(U.pVal, RHS, getNumWords());
  return clearUnusedBits();
}

APInt APInt::operator*(const APInt& RHS) const {
  assert(BitWidth == RHS.BitWidth && "Bit widths must be the same");
  if (isSingleWord())
    return APInt(BitWidth, U.VAL * RHS.U.VAL);

  APInt Result(getMemory(getNumWords()), getBitWidth());

  tcMultiply(Result.U.pVal, U.pVal, RHS.U.pVal, getNumWords());

  Result.clearUnusedBits();
  return Result;
}

void APInt::AndAssignSlowCase(const APInt& RHS) {
  tcAnd(U.pVal, RHS.U.pVal, getNumWords());
}

void APInt::OrAssignSlowCase(const APInt& RHS) {
  tcOr(U.pVal, RHS.U.pVal, getNumWords());
}

void APInt::XorAssignSlowCase(const APInt& RHS) {
  tcXor(U.pVal, RHS.U.pVal, getNumWords());
}

APInt& APInt::operator*=(const APInt& RHS) {
  assert(BitWidth == RHS.BitWidth && "Bit widths must be the same");
  *this = *this * RHS;
  return *this;
}

APInt& APInt::operator*=(uint64_t RHS) {
  if (isSingleWord()) {
    U.VAL *= RHS;
  } else {
    unsigned NumWords = getNumWords();
    tcMultiplyPart(U.pVal, U.pVal, RHS, 0, NumWords, NumWords, false);
  }
  return clearUnusedBits();
}

bool APInt::EqualSlowCase(const APInt& RHS) const {
  return std::equal(U.pVal, U.pVal + getNumWords(), RHS.U.pVal);
}

int APInt::compare(const APInt& RHS) const {
  assert(BitWidth == RHS.BitWidth && "Bit widths must be same for comparison");
  if (isSingleWord())
    return U.VAL < RHS.U.VAL ? -1 : U.VAL > RHS.U.VAL;

  return tcCompare(U.pVal, RHS.U.pVal, getNumWords());
}

int APInt::compareSigned(const APInt& RHS) const {
  assert(BitWidth == RHS.BitWidth && "Bit widths must be same for comparison");
  if (isSingleWord()) {
    int64_t lhsSext = SignExtend64(U.VAL, BitWidth);
    int64_t rhsSext = SignExtend64(RHS.U.VAL, BitWidth);
    return lhsSext < rhsSext ? -1 : lhsSext > rhsSext;
  }

  bool lhsNeg = isNegative();
  bool rhsNeg = RHS.isNegative();

                                                                      
  if (lhsNeg != rhsNeg)
    return lhsNeg ? -1 : 1;

                                                                            
                                                                          
  return tcCompare(U.pVal, RHS.U.pVal, getNumWords());
}

void APInt::setBitsSlowCase(unsigned loBit, unsigned hiBit) {
  unsigned loWord = whichWord(loBit);
  unsigned hiWord = whichWord(hiBit);

                                                                    
  uint64_t loMask = WORDTYPE_MAX << whichBit(loBit);

                                                  
  unsigned hiShiftAmt = whichBit(hiBit);
  if (hiShiftAmt != 0) {
                                                 
    uint64_t hiMask = WORDTYPE_MAX >> (APINT_BITS_PER_WORD - hiShiftAmt);
                                                                            
                              
    if (hiWord == loWord)
      loMask &= hiMask;
    else
      U.pVal[hiWord] |= hiMask;
  }
                                    
  U.pVal[loWord] |= loMask;

                                                            
  for (unsigned word = loWord + 1; word < hiWord; ++word)
    U.pVal[word] = WORDTYPE_MAX;
}

                                           
void APInt::flipAllBitsSlowCase() {
  tcComplement(U.pVal, getNumWords());
  clearUnusedBits();
}

                                                                    
                     
                                              
void APInt::flipBit(unsigned bitPosition) {
  assert(bitPosition < BitWidth && "Out of the bit-width range!");
  if ((*this)[bitPosition]) clearBit(bitPosition);
  else setBit(bitPosition);
}

void APInt::insertBits(const APInt &subBits, unsigned bitPosition) {
  unsigned subBitWidth = subBits.getBitWidth();
  assert(0 < subBitWidth && (subBitWidth + bitPosition) <= BitWidth &&
         "Illegal bit insertion");

                                
  if (subBitWidth == BitWidth) {
    *this = subBits;
    return;
  }

                                                        
  if (isSingleWord()) {
    uint64_t mask = WORDTYPE_MAX >> (APINT_BITS_PER_WORD - subBitWidth);
    U.VAL &= ~(mask << bitPosition);
    U.VAL |= (subBits.U.VAL << bitPosition);
    return;
  }

  unsigned loBit = whichBit(bitPosition);
  unsigned loWord = whichWord(bitPosition);
  unsigned hi1Word = whichWord(bitPosition + subBitWidth - 1);

                                                                    
  if (loWord == hi1Word) {
    uint64_t mask = WORDTYPE_MAX >> (APINT_BITS_PER_WORD - subBitWidth);
    U.pVal[loWord] &= ~(mask << loBit);
    U.pVal[loWord] |= (subBits.U.VAL << loBit);
    return;
  }

                               
  if (loBit == 0) {
                               
    unsigned numWholeSubWords = subBitWidth / APINT_BITS_PER_WORD;
    memcpy(U.pVal + loWord, subBits.getRawData(),
           numWholeSubWords * APINT_WORD_SIZE);

                                  
    unsigned remainingBits = subBitWidth % APINT_BITS_PER_WORD;
    if (remainingBits != 0) {
      uint64_t mask = WORDTYPE_MAX >> (APINT_BITS_PER_WORD - remainingBits);
      U.pVal[hi1Word] &= ~mask;
      U.pVal[hi1Word] |= subBits.getWord(subBitWidth - 1);
    }
    return;
  }

                                                                  
                                                                             
                                                                
  for (unsigned i = 0; i != subBitWidth; ++i) {
    if (subBits[i])
      setBit(bitPosition + i);
    else
      clearBit(bitPosition + i);
  }
}

APInt APInt::extractBits(unsigned numBits, unsigned bitPosition) const {
  assert(numBits > 0 && "Can't extract zero bits");
  assert(bitPosition < BitWidth && (numBits + bitPosition) <= BitWidth &&
         "Illegal bit extraction");

  if (isSingleWord())
    return APInt(numBits, U.VAL >> bitPosition);

  unsigned loBit = whichBit(bitPosition);
  unsigned loWord = whichWord(bitPosition);
  unsigned hiWord = whichWord(bitPosition + numBits - 1);

                                                                  
  if (loWord == hiWord)
    return APInt(numBits, U.pVal[loWord] >> loBit);

                                                                     
                           
  if (loBit == 0)
    return APInt(numBits, makeArrayRef(U.pVal + loWord, 1 + hiWord - loWord));

                                                                  
  APInt Result(numBits, 0);
  unsigned NumSrcWords = getNumWords();
  unsigned NumDstWords = Result.getNumWords();

  uint64_t *DestPtr = Result.isSingleWord() ? &Result.U.VAL : Result.U.pVal;
  for (unsigned word = 0; word < NumDstWords; ++word) {
    uint64_t w0 = U.pVal[loWord + word];
    uint64_t w1 =
        (loWord + word + 1) < NumSrcWords ? U.pVal[loWord + word + 1] : 0;
    DestPtr[word] = (w0 >> loBit) | (w1 << (APINT_BITS_PER_WORD - loBit));
  }

  return Result.clearUnusedBits();
}

unsigned APInt::getBitsNeeded(StringRef str, uint8_t radix) {
  assert(!str.empty() && "Invalid string length");
  assert((radix == 10 || radix == 8 || radix == 16 || radix == 2 ||
          radix == 36) &&
         "Radix should be 2, 8, 10, 16, or 36!");

  size_t slen = str.size();

                                                           
  StringRef::iterator p = str.begin();
  unsigned isNegative = *p == '-';
  if (*p == '-' || *p == '+') {
    p++;
    slen--;
    assert(slen && "String is only a sign, needs a value.");
  }

                                                                            
                    
  if (radix == 2)
    return slen + isNegative;
  if (radix == 8)
    return slen * 3 + isNegative;
  if (radix == 16)
    return slen * 4 + isNegative;

                   

                                                                             
                                                                             
                                                                        

                                                                              
                                                                     
                                                                              
                       
  unsigned sufficient
    = radix == 10? (slen == 1 ? 4 : slen * 64/18)
                 : (slen == 1 ? 7 : slen * 16/3);

                                        
  APInt tmp(sufficient, StringRef(p, slen), radix);

                                                                               
              
  unsigned log = tmp.logBase2();
  if (log == (unsigned)-1) {
    return isNegative + 1;
  } else {
    return isNegative + log + 1;
  }
}

hash_code llvh::hash_value(const APInt &Arg) {
  if (Arg.isSingleWord())
    return hash_combine(Arg.U.VAL);

  return hash_combine_range(Arg.U.pVal, Arg.U.pVal + Arg.getNumWords());
}

bool APInt::isSplat(unsigned SplatSizeInBits) const {
  assert(getBitWidth() % SplatSizeInBits == 0 &&
         "SplatSizeInBits must divide width!");
                                                                           
                                                                 
  return *this == rotl(SplatSizeInBits);
}

                                                                
APInt APInt::getHiBits(unsigned numBits) const {
  return this->lshr(BitWidth - numBits);
}

                                                               
APInt APInt::getLoBits(unsigned numBits) const {
  APInt Result(getLowBitsSet(BitWidth, numBits));
  Result &= *this;
  return Result;
}

                                                             
APInt APInt::getSplat(unsigned NewLen, const APInt &V) {
  assert(NewLen >= V.getBitWidth() && "Can't splat to smaller bit width!");

  APInt Val = V.zextOrSelf(NewLen);
  for (unsigned I = V.getBitWidth(); I < NewLen; I <<= 1)
    Val |= Val << I;

  return Val;
}

unsigned APInt::countLeadingZerosSlowCase() const {
  unsigned Count = 0;
  for (int i = getNumWords()-1; i >= 0; --i) {
    uint64_t V = U.pVal[i];
    if (V == 0)
      Count += APINT_BITS_PER_WORD;
    else {
      Count += llvh::countLeadingZeros(V);
      break;
    }
  }
                                                                         
  unsigned Mod = BitWidth % APINT_BITS_PER_WORD;
  Count -= Mod > 0 ? APINT_BITS_PER_WORD - Mod : 0;
  return Count;
}

unsigned APInt::countLeadingOnesSlowCase() const {
  unsigned highWordBits = BitWidth % APINT_BITS_PER_WORD;
  unsigned shift;
  if (!highWordBits) {
    highWordBits = APINT_BITS_PER_WORD;
    shift = 0;
  } else {
    shift = APINT_BITS_PER_WORD - highWordBits;
  }
  int i = getNumWords() - 1;
  unsigned Count = llvh::countLeadingOnes(U.pVal[i] << shift);
  if (Count == highWordBits) {
    for (i--; i >= 0; --i) {
      if (U.pVal[i] == WORDTYPE_MAX)
        Count += APINT_BITS_PER_WORD;
      else {
        Count += llvh::countLeadingOnes(U.pVal[i]);
        break;
      }
    }
  }
  return Count;
}

unsigned APInt::countTrailingZerosSlowCase() const {
  unsigned Count = 0;
  unsigned i = 0;
  for (; i < getNumWords() && U.pVal[i] == 0; ++i)
    Count += APINT_BITS_PER_WORD;
  if (i < getNumWords())
    Count += llvh::countTrailingZeros(U.pVal[i]);
  return std::min(Count, BitWidth);
}

unsigned APInt::countTrailingOnesSlowCase() const {
  unsigned Count = 0;
  unsigned i = 0;
  for (; i < getNumWords() && U.pVal[i] == WORDTYPE_MAX; ++i)
    Count += APINT_BITS_PER_WORD;
  if (i < getNumWords())
    Count += llvh::countTrailingOnes(U.pVal[i]);
  assert(Count <= BitWidth);
  return Count;
}

unsigned APInt::countPopulationSlowCase() const {
  unsigned Count = 0;
  for (unsigned i = 0; i < getNumWords(); ++i)
    Count += llvh::countPopulation(U.pVal[i]);
  return Count;
}

bool APInt::intersectsSlowCase(const APInt &RHS) const {
  for (unsigned i = 0, e = getNumWords(); i != e; ++i)
    if ((U.pVal[i] & RHS.U.pVal[i]) != 0)
      return true;

  return false;
}

bool APInt::isSubsetOfSlowCase(const APInt &RHS) const {
  for (unsigned i = 0, e = getNumWords(); i != e; ++i)
    if ((U.pVal[i] & ~RHS.U.pVal[i]) != 0)
      return false;

  return true;
}

APInt APInt::byteSwap() const {
  assert(BitWidth >= 16 && BitWidth % 16 == 0 && "Cannot byteswap!");
  if (BitWidth == 16)
    return APInt(BitWidth, ByteSwap_16(uint16_t(U.VAL)));
  if (BitWidth == 32)
    return APInt(BitWidth, ByteSwap_32(unsigned(U.VAL)));
  if (BitWidth == 48) {
    unsigned Tmp1 = unsigned(U.VAL >> 16);
    Tmp1 = ByteSwap_32(Tmp1);
    uint16_t Tmp2 = uint16_t(U.VAL);
    Tmp2 = ByteSwap_16(Tmp2);
    return APInt(BitWidth, (uint64_t(Tmp2) << 32) | Tmp1);
  }
  if (BitWidth == 64)
    return APInt(BitWidth, ByteSwap_64(U.VAL));

  APInt Result(getNumWords() * APINT_BITS_PER_WORD, 0);
  for (unsigned I = 0, N = getNumWords(); I != N; ++I)
    Result.U.pVal[I] = ByteSwap_64(U.pVal[N - I - 1]);
  if (Result.BitWidth != BitWidth) {
    Result.lshrInPlace(Result.BitWidth - BitWidth);
    Result.BitWidth = BitWidth;
  }
  return Result;
}

APInt APInt::reverseBits() const {
  switch (BitWidth) {
  case 64:
    return APInt(BitWidth, llvh::reverseBits<uint64_t>(U.VAL));
  case 32:
    return APInt(BitWidth, llvh::reverseBits<uint32_t>(U.VAL));
  case 16:
    return APInt(BitWidth, llvh::reverseBits<uint16_t>(U.VAL));
  case 8:
    return APInt(BitWidth, llvh::reverseBits<uint8_t>(U.VAL));
  default:
    break;
  }

  APInt Val(*this);
  APInt Reversed(BitWidth, 0);
  unsigned S = BitWidth;

  for (; Val != 0; Val.lshrInPlace(1)) {
    Reversed <<= 1;
    Reversed |= Val[0];
    --S;
  }

  Reversed <<= S;
  return Reversed;
}

APInt llvh::APIntOps::GreatestCommonDivisor(APInt A, APInt B) {
                             
  if (A == B) return A;

                                                                   
  if (!A) return B;
  if (!B) return A;

                                                               
  unsigned Pow2;
  {
    unsigned Pow2_A = A.countTrailingZeros();
    unsigned Pow2_B = B.countTrailingZeros();
    if (Pow2_A > Pow2_B) {
      A.lshrInPlace(Pow2_A - Pow2_B);
      Pow2 = Pow2_B;
    } else if (Pow2_B > Pow2_A) {
      B.lshrInPlace(Pow2_B - Pow2_A);
      Pow2 = Pow2_A;
    } else {
      Pow2 = Pow2_A;
    }
  }

                                                
    
                                                
    
                                                                         
                                    
  while (A != B) {
    if (A.ugt(B)) {
      A -= B;
      A.lshrInPlace(A.countTrailingZeros() - Pow2);
    } else {
      B -= A;
      B.lshrInPlace(B.countTrailingZeros() - Pow2);
    }
  }

  return A;
}

APInt llvh::APIntOps::RoundDoubleToAPInt(double Double, unsigned width) {
  uint64_t I = bit_cast<uint64_t>(Double);

                                                
  bool isNeg = I >> 63;

                                                             
  int64_t exp = ((I >> 52) & 0x7ff) - 1023;

                                                                    
  if (exp < 0)
    return APInt(width, 0u);

                                                                        
  uint64_t mantissa = (I & (~0ULL >> 12)) | 1ULL << 52;

                                                               
  if (exp < 52)
    return isNeg ? -APInt(width, mantissa >> (52 - exp)) :
                    APInt(width, mantissa >> (52 - exp));

                                                                               
                                                
  if (width <= exp - 52)
    return APInt(width, 0);

                                                                           
  APInt Tmp(width, mantissa);
  Tmp <<= (unsigned)exp - 52;
  return isNeg ? -Tmp : Tmp;
}

                                                  
                                                              
                                           
                                             
                                             
                                             
                                           
double APInt::roundToDouble(bool isSigned) const {

                                                                         
                                                                                  
  if (isSingleWord() || getActiveBits() <= APINT_BITS_PER_WORD) {
    if (isSigned) {
      int64_t sext = SignExtend64(getWord(0), BitWidth);
      return double(sext);
    } else
      return double(getWord(0));
  }

                                        
  bool isNeg = isSigned ? (*this)[BitWidth-1] : false;

                                                    
  APInt Tmp(isNeg ? -(*this) : (*this));

                                          
  unsigned n = Tmp.getActiveBits();

                                                                         
                                                                          
                    
  uint64_t exp = n;

                                          
  if (exp > 1023) {
    if (!isSigned || !isNeg)
      return std::numeric_limits<double>::infinity();
    else
      return -std::numeric_limits<double>::infinity();
  }
  exp += 1023;                           

                                                                            
                                                             
  uint64_t mantissa;
  unsigned hiWord = whichWord(n-1);
  if (hiWord == 0) {
    mantissa = Tmp.U.pVal[0];
    if (n > 52)
      mantissa >>= n - 52;                                        
  } else {
    assert(hiWord > 0 && "huh?");
    uint64_t hibits = Tmp.U.pVal[hiWord] << (52 - n % APINT_BITS_PER_WORD);
    uint64_t lobits = Tmp.U.pVal[hiWord-1] >> (11 + n % APINT_BITS_PER_WORD);
    mantissa = hibits | lobits;
  }

                                                               
  uint64_t sign = isNeg ? (1ULL << (APINT_BITS_PER_WORD - 1)) : 0;
  uint64_t I = sign | (exp << 52) | mantissa;
  return bit_cast<double>(I);
}

                         
APInt APInt::trunc(unsigned width) const {
  assert(width < BitWidth && "Invalid APInt Truncate request");
  assert(width && "Can't truncate to 0 bits");

  if (width <= APINT_BITS_PER_WORD)
    return APInt(width, getRawData()[0]);

  APInt Result(getMemory(getNumWords(width)), width);

                     
  unsigned i;
  for (i = 0; i != width / APINT_BITS_PER_WORD; i++)
    Result.U.pVal[i] = U.pVal[i];

                                        
  unsigned bits = (0 - width) % APINT_BITS_PER_WORD;
  if (bits != 0)
    Result.U.pVal[i] = U.pVal[i] << bits >> bits;

  return Result;
}

                              
APInt APInt::sext(unsigned Width) const {
  assert(Width > BitWidth && "Invalid APInt SignExtend request");

  if (Width <= APINT_BITS_PER_WORD)
    return APInt(Width, SignExtend64(U.VAL, BitWidth));

  APInt Result(getMemory(getNumWords(Width)), Width);

                
  std::memcpy(Result.U.pVal, getRawData(), getNumWords() * APINT_WORD_SIZE);

                                                                           
  Result.U.pVal[getNumWords() - 1] =
      SignExtend64(Result.U.pVal[getNumWords() - 1],
                   ((BitWidth - 1) % APINT_BITS_PER_WORD) + 1);

                         
  std::memset(Result.U.pVal + getNumWords(), isNegative() ? -1 : 0,
              (Result.getNumWords() - getNumWords()) * APINT_WORD_SIZE);
  Result.clearUnusedBits();
  return Result;
}

                               
APInt APInt::zext(unsigned width) const {
  assert(width > BitWidth && "Invalid APInt ZeroExtend request");

  if (width <= APINT_BITS_PER_WORD)
    return APInt(width, U.VAL);

  APInt Result(getMemory(getNumWords(width)), width);

                
  std::memcpy(Result.U.pVal, getRawData(), getNumWords() * APINT_WORD_SIZE);

                          
  std::memset(Result.U.pVal + getNumWords(), 0,
              (Result.getNumWords() - getNumWords()) * APINT_WORD_SIZE);

  return Result;
}

APInt APInt::zextOrTrunc(unsigned width) const {
  if (BitWidth < width)
    return zext(width);
  if (BitWidth > width)
    return trunc(width);
  return *this;
}

APInt APInt::sextOrTrunc(unsigned width) const {
  if (BitWidth < width)
    return sext(width);
  if (BitWidth > width)
    return trunc(width);
  return *this;
}

APInt APInt::zextOrSelf(unsigned width) const {
  if (BitWidth < width)
    return zext(width);
  return *this;
}

APInt APInt::sextOrSelf(unsigned width) const {
  if (BitWidth < width)
    return sext(width);
  return *this;
}

                                                  
                                    
void APInt::ashrInPlace(const APInt &shiftAmt) {
  ashrInPlace((unsigned)shiftAmt.getLimitedValue(BitWidth));
}

                                                  
                                    
void APInt::ashrSlowCase(unsigned ShiftAmt) {
                                           
  if (!ShiftAmt)
    return;

                                          
  bool Negative = isNegative();

                                                                     
  unsigned WordShift = ShiftAmt / APINT_BITS_PER_WORD;
  unsigned BitShift = ShiftAmt % APINT_BITS_PER_WORD;

  unsigned WordsToMove = getNumWords() - WordShift;
  if (WordsToMove != 0) {
                                                            
    U.pVal[getNumWords() - 1] = SignExtend64(
        U.pVal[getNumWords() - 1], ((BitWidth - 1) % APINT_BITS_PER_WORD) + 1);

                                          
    if (BitShift == 0) {
      std::memmove(U.pVal, U.pVal + WordShift, WordsToMove * APINT_WORD_SIZE);
    } else {
                                                    
      for (unsigned i = 0; i != WordsToMove - 1; ++i)
        U.pVal[i] = (U.pVal[i + WordShift] >> BitShift) |
                    (U.pVal[i + WordShift + 1] << (APINT_BITS_PER_WORD - BitShift));

                                                             
      U.pVal[WordsToMove - 1] = U.pVal[WordShift + WordsToMove - 1] >> BitShift;
                                   
      U.pVal[WordsToMove - 1] =
          SignExtend64(U.pVal[WordsToMove - 1], APINT_BITS_PER_WORD - BitShift);
    }
  }

                                                      
  std::memset(U.pVal + WordsToMove, Negative ? -1 : 0,
              WordShift * APINT_WORD_SIZE);
  clearUnusedBits();
}

                                               
                                 
void APInt::lshrInPlace(const APInt &shiftAmt) {
  lshrInPlace((unsigned)shiftAmt.getLimitedValue(BitWidth));
}

                                               
                                 
void APInt::lshrSlowCase(unsigned ShiftAmt) {
  tcShiftRight(U.pVal, getNumWords(), ShiftAmt);
}

                                      
                        
APInt &APInt::operator<<=(const APInt &shiftAmt) {
                                                                  
  *this <<= (unsigned)shiftAmt.getLimitedValue(BitWidth);
  return *this;
}

void APInt::shlSlowCase(unsigned ShiftAmt) {
  tcShiftLeft(U.pVal, getNumWords(), ShiftAmt);
  clearUnusedBits();
}

                                                    
static unsigned rotateModulo(unsigned BitWidth, const APInt &rotateAmt) {
  unsigned rotBitWidth = rotateAmt.getBitWidth();
  APInt rot = rotateAmt;
  if (rotBitWidth < BitWidth) {
                                                                     
                                                
    rot = rotateAmt.zext(BitWidth);
  }
  rot = rot.urem(APInt(rot.getBitWidth(), BitWidth));
  return rot.getLimitedValue(BitWidth);
}

APInt APInt::rotl(const APInt &rotateAmt) const {
  return rotl(rotateModulo(BitWidth, rotateAmt));
}

APInt APInt::rotl(unsigned rotateAmt) const {
  rotateAmt %= BitWidth;
  if (rotateAmt == 0)
    return *this;
  return shl(rotateAmt) | lshr(BitWidth - rotateAmt);
}

APInt APInt::rotr(const APInt &rotateAmt) const {
  return rotr(rotateModulo(BitWidth, rotateAmt));
}

APInt APInt::rotr(unsigned rotateAmt) const {
  rotateAmt %= BitWidth;
  if (rotateAmt == 0)
    return *this;
  return lshr(rotateAmt) | shl(BitWidth - rotateAmt);
}

                                                                            
                                                                           
                                                                           
                                                                            
                                                                             
                                                                          
                                                            
APInt APInt::sqrt() const {

                                          
  unsigned magnitude = getActiveBits();

                                                                       
                                                   
  if (magnitude <= 5) {
    static const uint8_t results[32] = {
                  0,
                  1, 1,
                  2, 2, 2, 2,
                  3, 3, 3, 3, 3, 3,
                  4, 4, 4, 4, 4, 4, 4, 4,
                  5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
                  6
    };
    return APInt(BitWidth, results[ (isSingleWord() ? U.VAL : U.pVal[0]) ]);
  }

                                                                              
                                                                        
                                                                            
                                                    
  if (magnitude < 52) {
    return APInt(BitWidth,
                 uint64_t(::round(::sqrt(double(isSingleWord() ? U.VAL
                                                               : U.pVal[0])))));
  }

                                                                              
                                                                              
                                                                        
                                                           
                                      
  unsigned nbits = BitWidth, i = 4;
  APInt testy(BitWidth, 16);
  APInt x_old(BitWidth, 1);
  APInt x_new(BitWidth, 0);
  APInt two(BitWidth, 2);

                                                          
  for (;; i += 2, testy = testy.shl(2))
    if (i >= nbits || this->ule(testy)) {
      x_old = x_old.shl(i / 2);
      break;
    }

                                                                    
  for (;;) {
    x_new = (this->udiv(x_old) + x_old).udiv(two);
    if (x_old.ule(x_new))
      break;
    x_old = x_new;
  }

                                                  
                                                                        
                                                                                
                                                                         
                                                                             
                                                                  
  APInt square(x_old * x_old);
  APInt nextSquare((x_old + 1) * (x_old +1));
  if (this->ult(square))
    return x_old;
  assert(this->ule(nextSquare) && "Error in APInt::sqrt computation");
  APInt midpoint((nextSquare - square).udiv(two));
  APInt offset(*this - square);
  if (offset.ult(midpoint))
    return x_old;
  return x_old + 1;
}

                                                                             
                                                                           
                                                                             
                                                                               
                                      
APInt APInt::multiplicativeInverse(const APInt& modulo) const {
  assert(ult(modulo) && "This APInt must be smaller than the modulo");

                                                                               
                                                  
                                                                          
                                                                                
                                                                             
                                                                           
               

  APInt r[2] = { modulo, *this };
  APInt t[2] = { APInt(BitWidth, 0), APInt(BitWidth, 1) };
  APInt q(BitWidth, 0);

  unsigned i;
  for (i = 0; r[i^1] != 0; i ^= 1) {
                                                                  
                          
                             
                                 
    udivrem(r[i], r[i^1], q, r[i]);
    t[i] -= t[i^1] * q;
  }

                                                                             
                                                                       
                                                                             
               
  if (r[i] != 1)
    return APInt(BitWidth, 0);

                                                                       
                                                                               
                                                                       
                                                                     
  if (t[i].isNegative())
    t[i] += modulo;

  return std::move(t[i]);
}

                                                                               
                                                                              
                                                                            
                            
APInt::ms APInt::magic() const {
  const APInt& d = *this;
  unsigned p;
  APInt ad, anc, delta, q1, r1, q2, r2, t;
  APInt signedMin = APInt::getSignedMinValue(d.getBitWidth());
  struct ms mag;

  ad = d.abs();
  t = signedMin + (d.lshr(d.getBitWidth() - 1));
  anc = t - 1 - t.urem(ad);                          
  p = d.getBitWidth() - 1;                   
  q1 = signedMin.udiv(anc);                                
  r1 = signedMin - q1*anc;                                      
  q2 = signedMin.udiv(ad);                                
  r2 = signedMin - q2*ad;                                      
  do {
    p = p + 1;
    q1 = q1<<1;                                   
    r1 = r1<<1;                                        
    if (r1.uge(anc)) {                                
      q1 = q1 + 1;
      r1 = r1 - anc;
    }
    q2 = q2<<1;                                  
    r2 = r2<<1;                                       
    if (r2.uge(ad)) {                                 
      q2 = q2 + 1;
      r2 = r2 - ad;
    }
    delta = ad - r2;
  } while (q1.ult(delta) || (q1 == delta && r1 == 0));

  mag.m = q2 + 1;
  if (d.isNegative()) mag.m = -mag.m;                            
  mag.s = p - d.getBitWidth();                            
  return mag;
}

                                                                         
                                                                        
                                                                             
                               
                                                                          
                                        
APInt::mu APInt::magicu(unsigned LeadingZeros) const {
  const APInt& d = *this;
  unsigned p;
  APInt nc, delta, q1, r1, q2, r2;
  struct mu magu;
  magu.a = 0;                                            
  APInt allOnes = APInt::getAllOnesValue(d.getBitWidth()).lshr(LeadingZeros);
  APInt signedMin = APInt::getSignedMinValue(d.getBitWidth());
  APInt signedMax = APInt::getSignedMaxValue(d.getBitWidth());

  nc = allOnes - (allOnes - d).urem(d);
  p = d.getBitWidth() - 1;                 
  q1 = signedMin.udiv(nc);                          
  r1 = signedMin - q1*nc;                                
  q2 = signedMax.udiv(d);                              
  r2 = signedMax - q2*d;                                    
  do {
    p = p + 1;
    if (r1.uge(nc - r1)) {
      q1 = q1 + q1 + 1;              
      r1 = r1 + r1 - nc;             
    }
    else {
      q1 = q1+q1;             
      r1 = r1+r1;             
    }
    if ((r2 + 1).uge(d - r2)) {
      if (q2.uge(signedMax)) magu.a = 1;
      q2 = q2+q2 + 1;                 
      r2 = r2+r2 + 1 - d;             
    }
    else {
      if (q2.uge(signedMin)) magu.a = 1;
      q2 = q2+q2;                 
      r2 = r2+r2 + 1;             
    }
    delta = d - 1 - r2;
  } while (p < d.getBitWidth()*2 &&
           (q1.ult(delta) || (q1 == delta && r1 == 0)));
  magu.m = q2 + 1;                          
  magu.s = p - d.getBitWidth();                    
  return magu;
}

                                                                            
                                                                            
                                                                            
                                            
static void KnuthDiv(uint32_t *u, uint32_t *v, uint32_t *q, uint32_t* r,
                     unsigned m, unsigned n) {
  assert(u && "Must provide dividend");
  assert(v && "Must provide divisor");
  assert(q && "Must provide quotient");
  assert(u != v && u != q && v != q && "Must use different memory");
  assert(n>1 && "n must be > 1");

                                                                    
  const uint64_t b = uint64_t(1) << 32;

                                                                          
                                                                   
#ifdef KNUTH_DEBUG
#define DEBUG_KNUTH(X) LLVM_DEBUG(X)
#else
#define DEBUG_KNUTH(X) do {} while(false)
#endif

  DEBUG_KNUTH(dbgs() << "KnuthDiv: m=" << m << " n=" << n << '\n');
  DEBUG_KNUTH(dbgs() << "KnuthDiv: original:");
  DEBUG_KNUTH(for (int i = m + n; i >= 0; i--) dbgs() << " " << u[i]);
  DEBUG_KNUTH(dbgs() << " by");
  DEBUG_KNUTH(for (int i = n; i > 0; i--) dbgs() << " " << v[i - 1]);
  DEBUG_KNUTH(dbgs() << '\n');
                                                                             
                                                                             
                                                                             
                                                                             
                                                                             
                                                                            
                                                                           
                        
  unsigned shift = countLeadingZeros(v[n-1]);
  uint32_t v_carry = 0;
  uint32_t u_carry = 0;
  if (shift) {
    for (unsigned i = 0; i < m+n; ++i) {
      uint32_t u_tmp = u[i] >> (32 - shift);
      u[i] = (u[i] << shift) | u_carry;
      u_carry = u_tmp;
    }
    for (unsigned i = 0; i < n; ++i) {
      uint32_t v_tmp = v[i] >> (32 - shift);
      v[i] = (v[i] << shift) | v_carry;
      v_carry = v_tmp;
    }
  }
  u[m+n] = u_carry;

  DEBUG_KNUTH(dbgs() << "KnuthDiv:   normal:");
  DEBUG_KNUTH(for (int i = m + n; i >= 0; i--) dbgs() << " " << u[i]);
  DEBUG_KNUTH(dbgs() << " by");
  DEBUG_KNUTH(for (int i = n; i > 0; i--) dbgs() << " " << v[i - 1]);
  DEBUG_KNUTH(dbgs() << '\n');

                                                                               
  int j = m;
  do {
    DEBUG_KNUTH(dbgs() << "KnuthDiv: quotient digit #" << j << '\n');
                           
                                                                  
                                                                  
                                                                          
                                                                               
                                                                              
                                                                             
                 
    uint64_t dividend = Make_64(u[j+n], u[j+n-1]);
    DEBUG_KNUTH(dbgs() << "KnuthDiv: dividend == " << dividend << '\n');
    uint64_t qp = dividend / v[n-1];
    uint64_t rp = dividend % v[n-1];
    if (qp == b || qp*v[n-2] > b*rp + u[j+n-2]) {
      qp--;
      rp += v[n-1];
      if (rp < b && (qp == b || qp*v[n-2] > b*rp + u[j+n-2]))
        qp--;
    }
    DEBUG_KNUTH(dbgs() << "KnuthDiv: qp == " << qp << ", rp == " << rp << '\n');

                                                                        
                                                                          
                                                                               
                     
                                                                           
                                                                            
                                                                
                                                                       
    int64_t borrow = 0;
    for (unsigned i = 0; i < n; ++i) {
      uint64_t p = uint64_t(qp) * uint64_t(v[i]);
      int64_t subres = int64_t(u[j+i]) - borrow - Lo_32(p);
      u[j+i] = Lo_32(subres);
      borrow = Hi_32(p) - Hi_32(subres);
      DEBUG_KNUTH(dbgs() << "KnuthDiv: u[j+i] = " << u[j + i]
                        << ", borrow = " << borrow << '\n');
    }
    bool isNeg = u[j+n] < borrow;
    u[j+n] -= Lo_32(borrow);

    DEBUG_KNUTH(dbgs() << "KnuthDiv: after subtraction:");
    DEBUG_KNUTH(for (int i = m + n; i >= 0; i--) dbgs() << " " << u[i]);
    DEBUG_KNUTH(dbgs() << '\n');

                                                                        
                                                           
    q[j] = Lo_32(qp);
    if (isNeg) {
                                                                            
                                                                               
                                             
      q[j]--;
                                                                       
                                                                           
                                                              
      bool carry = false;
      for (unsigned i = 0; i < n; i++) {
        uint32_t limit = std::min(u[j+i],v[i]);
        u[j+i] += v[i] + carry;
        carry = u[j+i] < limit || (carry && u[j+i] == limit);
      }
      u[j+n] += carry;
    }
    DEBUG_KNUTH(dbgs() << "KnuthDiv: after correction:");
    DEBUG_KNUTH(for (int i = m + n; i >= 0; i--) dbgs() << " " << u[i]);
    DEBUG_KNUTH(dbgs() << "\nKnuthDiv: digit result = " << q[j] << '\n');

                                                                         
  } while (--j >= 0);

  DEBUG_KNUTH(dbgs() << "KnuthDiv: quotient:");
  DEBUG_KNUTH(for (int i = m; i >= 0; i--) dbgs() << " " << q[i]);
  DEBUG_KNUTH(dbgs() << '\n');

                                                                           
                                                                           
                                            
  if (r) {
                                                                           
                                                                          
                        
    if (shift) {
      uint32_t carry = 0;
      DEBUG_KNUTH(dbgs() << "KnuthDiv: remainder:");
      for (int i = n-1; i >= 0; i--) {
        r[i] = (u[i] >> shift) | carry;
        carry = u[i] << (32 - shift);
        DEBUG_KNUTH(dbgs() << " " << r[i]);
      }
    } else {
      for (int i = n-1; i >= 0; i--) {
        r[i] = u[i];
        DEBUG_KNUTH(dbgs() << " " << r[i]);
      }
    }
    DEBUG_KNUTH(dbgs() << '\n');
  }
  DEBUG_KNUTH(dbgs() << '\n');
}

void APInt::divide(const WordType *LHS, unsigned lhsWords, const WordType *RHS,
                   unsigned rhsWords, WordType *Quotient, WordType *Remainder) {
  assert(lhsWords >= rhsWords && "Fractional result");

                                                                       
                                                                             
                                                                          
                                                                            
                                                                           
                                                                            
                                   
  unsigned n = rhsWords * 2;
  unsigned m = (lhsWords * 2) - n;

                                                                            
                                             
  uint32_t SPACE[128];
  uint32_t *U = nullptr;
  uint32_t *V = nullptr;
  uint32_t *Q = nullptr;
  uint32_t *R = nullptr;
  if ((Remainder?4:3)*n+2*m+1 <= 128) {
    U = &SPACE[0];
    V = &SPACE[m+n+1];
    Q = &SPACE[(m+n+1) + n];
    if (Remainder)
      R = &SPACE[(m+n+1) + n + (m+n)];
  } else {
    U = new uint32_t[m + n + 1];
    V = new uint32_t[n];
    Q = new uint32_t[m+n];
    if (Remainder)
      R = new uint32_t[n];
  }

                            
  memset(U, 0, (m+n+1)*sizeof(uint32_t));
  for (unsigned i = 0; i < lhsWords; ++i) {
    uint64_t tmp = LHS[i];
    U[i * 2] = Lo_32(tmp);
    U[i * 2 + 1] = Hi_32(tmp);
  }
  U[m+n] = 0;                                                          

                           
  memset(V, 0, (n)*sizeof(uint32_t));
  for (unsigned i = 0; i < rhsWords; ++i) {
    uint64_t tmp = RHS[i];
    V[i * 2] = Lo_32(tmp);
    V[i * 2 + 1] = Hi_32(tmp);
  }

                                          
  memset(Q, 0, (m+n) * sizeof(uint32_t));
  if (Remainder)
    memset(R, 0, n * sizeof(uint32_t));

                                                                            
                                                                            
                                                                           
                                                         
  for (unsigned i = n; i > 0 && V[i-1] == 0; i--) {
    n--;
    m++;
  }
  for (unsigned i = m+n; i > 0 && U[i-1] == 0; i--)
    m--;

                                                                              
                                                                            
                                                                           
                                                                          
                                                                             
                                            
  assert(n != 0 && "Divide by zero?");
  if (n == 1) {
    uint32_t divisor = V[0];
    uint32_t remainder = 0;
    for (int i = m; i >= 0; i--) {
      uint64_t partial_dividend = Make_64(remainder, U[i]);
      if (partial_dividend == 0) {
        Q[i] = 0;
        remainder = 0;
      } else if (partial_dividend < divisor) {
        Q[i] = 0;
        remainder = Lo_32(partial_dividend);
      } else if (partial_dividend == divisor) {
        Q[i] = 1;
        remainder = 0;
      } else {
        Q[i] = Lo_32(partial_dividend / divisor);
        remainder = Lo_32(partial_dividend - (Q[i] * divisor));
      }
    }
    if (R)
      R[0] = remainder;
  } else {
                                                                              
                  
    KnuthDiv(U, V, Q, R, m, n);
  }

                                     
  if (Quotient) {
    for (unsigned i = 0; i < lhsWords; ++i)
      Quotient[i] = Make_64(Q[i*2+1], Q[i*2]);
  }

                                      
  if (Remainder) {
    for (unsigned i = 0; i < rhsWords; ++i)
      Remainder[i] = Make_64(R[i*2+1], R[i*2]);
  }

                                      
  if (U != &SPACE[0]) {
    delete [] U;
    delete [] V;
    delete [] Q;
    delete [] R;
  }
}

APInt APInt::udiv(const APInt &RHS) const {
  assert(BitWidth == RHS.BitWidth && "Bit widths must be the same");

                                   
  if (isSingleWord()) {
    assert(RHS.U.VAL != 0 && "Divide by zero?");
    return APInt(BitWidth, U.VAL / RHS.U.VAL);
  }

                                                                  
  unsigned lhsWords = getNumWords(getActiveBits());
  unsigned rhsBits  = RHS.getActiveBits();
  unsigned rhsWords = getNumWords(rhsBits);
  assert(rhsWords && "Divided by zero???");

                                    
  if (!lhsWords)
                   
    return APInt(BitWidth, 0);
  if (rhsBits == 1)
                   
    return *this;
  if (lhsWords < rhsWords || this->ult(RHS))
                              
    return APInt(BitWidth, 0);
  if (*this == RHS)
                   
    return APInt(BitWidth, 1);
  if (lhsWords == 1)                                   
                                                      
    return APInt(BitWidth, this->U.pVal[0] / RHS.U.pVal[0]);

                                                                           
  APInt Quotient(BitWidth, 0);                   
  divide(U.pVal, lhsWords, RHS.U.pVal, rhsWords, Quotient.U.pVal, nullptr);
  return Quotient;
}

APInt APInt::udiv(uint64_t RHS) const {
  assert(RHS != 0 && "Divide by zero?");

                                   
  if (isSingleWord())
    return APInt(BitWidth, U.VAL / RHS);

                                        
  unsigned lhsWords = getNumWords(getActiveBits());

                                    
  if (!lhsWords)
                   
    return APInt(BitWidth, 0);
  if (RHS == 1)
                   
    return *this;
  if (this->ult(RHS))
                              
    return APInt(BitWidth, 0);
  if (*this == RHS)
                   
    return APInt(BitWidth, 1);
  if (lhsWords == 1)                                   
                                                      
    return APInt(BitWidth, this->U.pVal[0] / RHS);

                                                                           
  APInt Quotient(BitWidth, 0);                   
  divide(U.pVal, lhsWords, &RHS, 1, Quotient.U.pVal, nullptr);
  return Quotient;
}

APInt APInt::sdiv(const APInt &RHS) const {
  if (isNegative()) {
    if (RHS.isNegative())
      return (-(*this)).udiv(-RHS);
    return -((-(*this)).udiv(RHS));
  }
  if (RHS.isNegative())
    return -(this->udiv(-RHS));
  return this->udiv(RHS);
}

APInt APInt::sdiv(int64_t RHS) const {
  if (isNegative()) {
    if (RHS < 0)
      return (-(*this)).udiv(-RHS);
    return -((-(*this)).udiv(RHS));
  }
  if (RHS < 0)
    return -(this->udiv(-RHS));
  return this->udiv(RHS);
}

APInt APInt::urem(const APInt &RHS) const {
  assert(BitWidth == RHS.BitWidth && "Bit widths must be the same");
  if (isSingleWord()) {
    assert(RHS.U.VAL != 0 && "Remainder by zero?");
    return APInt(BitWidth, U.VAL % RHS.U.VAL);
  }

                                 
  unsigned lhsWords = getNumWords(getActiveBits());

                                 
  unsigned rhsBits = RHS.getActiveBits();
  unsigned rhsWords = getNumWords(rhsBits);
  assert(rhsWords && "Performing remainder operation by zero ???");

                               
  if (lhsWords == 0)
                   
    return APInt(BitWidth, 0);
  if (rhsBits == 1)
                   
    return APInt(BitWidth, 0);
  if (lhsWords < rhsWords || this->ult(RHS))
                              
    return *this;
  if (*this == RHS)
                  
    return APInt(BitWidth, 0);
  if (lhsWords == 1)
                                                         
    return APInt(BitWidth, U.pVal[0] % RHS.U.pVal[0]);

                                                                           
  APInt Remainder(BitWidth, 0);
  divide(U.pVal, lhsWords, RHS.U.pVal, rhsWords, nullptr, Remainder.U.pVal);
  return Remainder;
}

uint64_t APInt::urem(uint64_t RHS) const {
  assert(RHS != 0 && "Remainder by zero?");

  if (isSingleWord())
    return U.VAL % RHS;

                                 
  unsigned lhsWords = getNumWords(getActiveBits());

                               
  if (lhsWords == 0)
                   
    return 0;
  if (RHS == 1)
                   
    return 0;
  if (this->ult(RHS))
                              
    return getZExtValue();
  if (*this == RHS)
                  
    return 0;
  if (lhsWords == 1)
                                                         
    return U.pVal[0] % RHS;

                                                                           
  uint64_t Remainder;
  divide(U.pVal, lhsWords, &RHS, 1, nullptr, &Remainder);
  return Remainder;
}

APInt APInt::srem(const APInt &RHS) const {
  if (isNegative()) {
    if (RHS.isNegative())
      return -((-(*this)).urem(-RHS));
    return -((-(*this)).urem(RHS));
  }
  if (RHS.isNegative())
    return this->urem(-RHS);
  return this->urem(RHS);
}

int64_t APInt::srem(int64_t RHS) const {
  if (isNegative()) {
    if (RHS < 0)
      return -((-(*this)).urem(-RHS));
    return -((-(*this)).urem(RHS));
  }
  if (RHS < 0)
    return this->urem(-RHS);
  return this->urem(RHS);
}

void APInt::udivrem(const APInt &LHS, const APInt &RHS,
                    APInt &Quotient, APInt &Remainder) {
  assert(LHS.BitWidth == RHS.BitWidth && "Bit widths must be the same");
  unsigned BitWidth = LHS.BitWidth;

                                   
  if (LHS.isSingleWord()) {
    assert(RHS.U.VAL != 0 && "Divide by zero?");
    uint64_t QuotVal = LHS.U.VAL / RHS.U.VAL;
    uint64_t RemVal = LHS.U.VAL % RHS.U.VAL;
    Quotient = APInt(BitWidth, QuotVal);
    Remainder = APInt(BitWidth, RemVal);
    return;
  }

                                                       
  unsigned lhsWords = getNumWords(LHS.getActiveBits());
  unsigned rhsBits  = RHS.getActiveBits();
  unsigned rhsWords = getNumWords(rhsBits);
  assert(rhsWords && "Performing divrem operation by zero ???");

                               
  if (lhsWords == 0) {
    Quotient = APInt(BitWidth, 0);                   
    Remainder = APInt(BitWidth, 0);                  
    return;
  }

  if (rhsBits == 1) {
    Quotient = LHS;                                  
    Remainder = APInt(BitWidth, 0);                  
  }

  if (lhsWords < rhsWords || LHS.ult(RHS)) {
    Remainder = LHS;                                            
    Quotient = APInt(BitWidth, 0);                              
    return;
  }

  if (LHS == RHS) {
    Quotient  = APInt(BitWidth, 1);                  
    Remainder = APInt(BitWidth, 0);                   
    return;
  }

                                                         
                                                                           
                                                                           
                     
  Quotient.reallocate(BitWidth);
  Remainder.reallocate(BitWidth);

  if (lhsWords == 1) {                                   
                                                                     
    uint64_t lhsValue = LHS.U.pVal[0];
    uint64_t rhsValue = RHS.U.pVal[0];
    Quotient = lhsValue / rhsValue;
    Remainder = lhsValue % rhsValue;
    return;
  }

                                  
  divide(LHS.U.pVal, lhsWords, RHS.U.pVal, rhsWords, Quotient.U.pVal,
         Remainder.U.pVal);
                                                  
  std::memset(Quotient.U.pVal + lhsWords, 0,
              (getNumWords(BitWidth) - lhsWords) * APINT_WORD_SIZE);
  std::memset(Remainder.U.pVal + rhsWords, 0,
              (getNumWords(BitWidth) - rhsWords) * APINT_WORD_SIZE);
}

void APInt::udivrem(const APInt &LHS, uint64_t RHS, APInt &Quotient,
                    uint64_t &Remainder) {
  assert(RHS != 0 && "Divide by zero?");
  unsigned BitWidth = LHS.BitWidth;

                                   
  if (LHS.isSingleWord()) {
    uint64_t QuotVal = LHS.U.VAL / RHS;
    Remainder = LHS.U.VAL % RHS;
    Quotient = APInt(BitWidth, QuotVal);
    return;
  }

                                                       
  unsigned lhsWords = getNumWords(LHS.getActiveBits());

                               
  if (lhsWords == 0) {
    Quotient = APInt(BitWidth, 0);                   
    Remainder = 0;                                   
    return;
  }

  if (RHS == 1) {
    Quotient = LHS;                                  
    Remainder = 0;                                   
    return;
  }

  if (LHS.ult(RHS)) {
    Remainder = LHS.getZExtValue();                             
    Quotient = APInt(BitWidth, 0);                              
    return;
  }

  if (LHS == RHS) {
    Quotient  = APInt(BitWidth, 1);                  
    Remainder = 0;                                    
    return;
  }

                                                         
                                                                           
                                                                        
  Quotient.reallocate(BitWidth);

  if (lhsWords == 1) {                                   
                                                                     
    uint64_t lhsValue = LHS.U.pVal[0];
    Quotient = lhsValue / RHS;
    Remainder = lhsValue % RHS;
    return;
  }

                                  
  divide(LHS.U.pVal, lhsWords, &RHS, 1, Quotient.U.pVal, &Remainder);
                                    
  std::memset(Quotient.U.pVal + lhsWords, 0,
              (getNumWords(BitWidth) - lhsWords) * APINT_WORD_SIZE);
}

void APInt::sdivrem(const APInt &LHS, const APInt &RHS,
                    APInt &Quotient, APInt &Remainder) {
  if (LHS.isNegative()) {
    if (RHS.isNegative())
      APInt::udivrem(-LHS, -RHS, Quotient, Remainder);
    else {
      APInt::udivrem(-LHS, RHS, Quotient, Remainder);
      Quotient.negate();
    }
    Remainder.negate();
  } else if (RHS.isNegative()) {
    APInt::udivrem(LHS, -RHS, Quotient, Remainder);
    Quotient.negate();
  } else {
    APInt::udivrem(LHS, RHS, Quotient, Remainder);
  }
}

void APInt::sdivrem(const APInt &LHS, int64_t RHS,
                    APInt &Quotient, int64_t &Remainder) {
  uint64_t R = Remainder;
  if (LHS.isNegative()) {
    if (RHS < 0)
      APInt::udivrem(-LHS, -RHS, Quotient, R);
    else {
      APInt::udivrem(-LHS, RHS, Quotient, R);
      Quotient.negate();
    }
    R = -R;
  } else if (RHS < 0) {
    APInt::udivrem(LHS, -RHS, Quotient, R);
    Quotient.negate();
  } else {
    APInt::udivrem(LHS, RHS, Quotient, R);
  }
  Remainder = R;
}

APInt APInt::sadd_ov(const APInt &RHS, bool &Overflow) const {
  APInt Res = *this+RHS;
  Overflow = isNonNegative() == RHS.isNonNegative() &&
             Res.isNonNegative() != isNonNegative();
  return Res;
}

APInt APInt::uadd_ov(const APInt &RHS, bool &Overflow) const {
  APInt Res = *this+RHS;
  Overflow = Res.ult(RHS);
  return Res;
}

APInt APInt::ssub_ov(const APInt &RHS, bool &Overflow) const {
  APInt Res = *this - RHS;
  Overflow = isNonNegative() != RHS.isNonNegative() &&
             Res.isNonNegative() != isNonNegative();
  return Res;
}

APInt APInt::usub_ov(const APInt &RHS, bool &Overflow) const {
  APInt Res = *this-RHS;
  Overflow = Res.ugt(*this);
  return Res;
}

APInt APInt::sdiv_ov(const APInt &RHS, bool &Overflow) const {
                              
  Overflow = isMinSignedValue() && RHS.isAllOnesValue();
  return sdiv(RHS);
}

APInt APInt::smul_ov(const APInt &RHS, bool &Overflow) const {
  APInt Res = *this * RHS;

  if (*this != 0 && RHS != 0)
    Overflow = Res.sdiv(RHS) != *this || Res.sdiv(*this) != RHS;
  else
    Overflow = false;
  return Res;
}

APInt APInt::umul_ov(const APInt &RHS, bool &Overflow) const {
  APInt Res = *this * RHS;

  if (*this != 0 && RHS != 0)
    Overflow = Res.udiv(RHS) != *this || Res.udiv(*this) != RHS;
  else
    Overflow = false;
  return Res;
}

APInt APInt::sshl_ov(const APInt &ShAmt, bool &Overflow) const {
  Overflow = ShAmt.uge(getBitWidth());
  if (Overflow)
    return APInt(BitWidth, 0);

  if (isNonNegative())                            
    Overflow = ShAmt.uge(countLeadingZeros());
  else
    Overflow = ShAmt.uge(countLeadingOnes());

  return *this << ShAmt;
}

APInt APInt::ushl_ov(const APInt &ShAmt, bool &Overflow) const {
  Overflow = ShAmt.uge(getBitWidth());
  if (Overflow)
    return APInt(BitWidth, 0);

  Overflow = ShAmt.ugt(countLeadingZeros());

  return *this << ShAmt;
}




void APInt::fromString(unsigned numbits, StringRef str, uint8_t radix) {
                               
  assert(!str.empty() && "Invalid string length");
  assert((radix == 10 || radix == 8 || radix == 16 || radix == 2 ||
          radix == 36) &&
         "Radix should be 2, 8, 10, 16, or 36!");

  StringRef::iterator p = str.begin();
  size_t slen = str.size();
  bool isNeg = *p == '-';
  if (*p == '-' || *p == '+') {
    p++;
    slen--;
    assert(slen && "String is only a sign, needs a value.");
  }
  assert((slen <= numbits || radix != 2) && "Insufficient bit width");
  assert(((slen-1)*3 <= numbits || radix != 8) && "Insufficient bit width");
  assert(((slen-1)*4 <= numbits || radix != 16) && "Insufficient bit width");
  assert((((slen-1)*64)/22 <= numbits || radix != 10) &&
         "Insufficient bit width");

                              
  if (isSingleWord())
    U.VAL = 0;
  else
    U.pVal = getClearedMemory(getNumWords());

                                                   
  unsigned shift = (radix == 16 ? 4 : radix == 8 ? 3 : radix == 2 ? 1 : 0);

                               
  for (StringRef::iterator e = str.end(); p != e; ++p) {
    unsigned digit = getDigit(*p, radix);
    assert(digit < radix && "Invalid character in digit string");

                                               
    if (slen > 1) {
      if (shift)
        *this <<= shift;
      else
        *this *= radix;
    }

                                           
    *this += digit;
  }
                                                     
  if (isNeg)
    this->negate();
}

void APInt::toString(SmallVectorImpl<char> &Str, unsigned Radix,
                     bool Signed, bool formatAsCLiteral) const {
  assert((Radix == 10 || Radix == 8 || Radix == 16 || Radix == 2 ||
          Radix == 36) &&
         "Radix should be 2, 8, 10, 16, or 36!");

  const char *Prefix = "";
  if (formatAsCLiteral) {
    switch (Radix) {
      case 2:
                                                                         
                                                                            
        Prefix = "0b";
        break;
      case 8:
        Prefix = "0";
        break;
      case 10:
        break;             
      case 16:
        Prefix = "0x";
        break;
      default:
        llvm_unreachable("Invalid radix!");
    }
  }

                                                                          
  if (*this == 0) {
    while (*Prefix) {
      Str.push_back(*Prefix);
      ++Prefix;
    };
    Str.push_back('0');
    return;
  }

  static const char Digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  if (isSingleWord()) {
    char Buffer[65];
    char *BufPtr = std::end(Buffer);

    uint64_t N;
    if (!Signed) {
      N = getZExtValue();
    } else {
      int64_t I = getSExtValue();
      if (I >= 0) {
        N = I;
      } else {
        Str.push_back('-');
        N = -(uint64_t)I;
      }
    }

    while (*Prefix) {
      Str.push_back(*Prefix);
      ++Prefix;
    };

    while (N) {
      *--BufPtr = Digits[N % Radix];
      N /= Radix;
    }
    Str.append(BufPtr, std::end(Buffer));
    return;
  }

  APInt Tmp(*this);

  if (Signed && isNegative()) {
                                                                       
                                                                        
                                         
    Tmp.negate();
    Str.push_back('-');
  }

  while (*Prefix) {
    Str.push_back(*Prefix);
    ++Prefix;
  };

                                                                             
  unsigned StartDig = Str.size();

                                                                       
                                                                           
                                                     
  if (Radix == 2 || Radix == 8 || Radix == 16) {
                                                                      
    unsigned ShiftAmt = (Radix == 16 ? 4 : (Radix == 8 ? 3 : 1));
    unsigned MaskAmt = Radix - 1;

    while (Tmp.getBoolValue()) {
      unsigned Digit = unsigned(Tmp.getRawData()[0]) & MaskAmt;
      Str.push_back(Digits[Digit]);
      Tmp.lshrInPlace(ShiftAmt);
    }
  } else {
    while (Tmp.getBoolValue()) {
      uint64_t Digit;
      udivrem(Tmp, Radix, Tmp, Digit);
      assert(Digit < Radix && "divide failed");
      Str.push_back(Digits[Digit]);
    }
  }

                                         
  std::reverse(Str.begin()+StartDig, Str.end());
}

                                                                                
                                                                           
std::string APInt::toString(unsigned Radix = 10, bool Signed = true) const {
  SmallString<40> S;
  toString(S, Radix, Signed,                         false);
  return S.str();
}

#if !defined(NDEBUG) || defined(LLVM_ENABLE_DUMP)
LLVM_DUMP_METHOD void APInt::dump() const {
  SmallString<40> S, U;
  this->toStringUnsigned(U);
  this->toStringSigned(S);
  dbgs() << "APInt(" << BitWidth << "b, "
         << U << "u " << S << "s)\n";
}
#endif

void APInt::print(raw_ostream &OS, bool isSigned) const {
  SmallString<40> S;
  this->toString(S, 10, isSigned,                         false);
  OS << S;
}

                                                                 
                                                                

                                                                    
                                
static_assert(APInt::APINT_BITS_PER_WORD % 2 == 0,
              "Part width must be divisible by 2!");

                                               

                                                                
                           
static inline APInt::WordType lowBitMask(unsigned bits) {
  assert(bits != 0 && bits <= APInt::APINT_BITS_PER_WORD);

  return ~(APInt::WordType) 0 >> (APInt::APINT_BITS_PER_WORD - bits);
}

                                                   
static inline APInt::WordType lowHalf(APInt::WordType part) {
  return part & lowBitMask(APInt::APINT_BITS_PER_WORD / 2);
}

                                                   
static inline APInt::WordType highHalf(APInt::WordType part) {
  return part >> (APInt::APINT_BITS_PER_WORD / 2);
}

                                                                    
                                                           
static unsigned partMSB(APInt::WordType value) {
  return findLastSet(value, ZB_Max);
}

                                                               
                                                                  
static unsigned partLSB(APInt::WordType value) {
  return findFirstSet(value, ZB_Max);
}

                                                                      
                               
void APInt::tcSet(WordType *dst, WordType part, unsigned parts) {
  assert(parts > 0);

  dst[0] = part;
  for (unsigned i = 1; i < parts; i++)
    dst[i] = 0;
}

                                    
void APInt::tcAssign(WordType *dst, const WordType *src, unsigned parts) {
  for (unsigned i = 0; i < parts; i++)
    dst[i] = src[i];
}

                                                         
bool APInt::tcIsZero(const WordType *src, unsigned parts) {
  for (unsigned i = 0; i < parts; i++)
    if (src[i])
      return false;

  return true;
}

                                                         
int APInt::tcExtractBit(const WordType *parts, unsigned bit) {
  return (parts[whichWord(bit)] & maskBit(bit)) != 0;
}

                                    
void APInt::tcSetBit(WordType *parts, unsigned bit) {
  parts[whichWord(bit)] |= maskBit(bit);
}

                                       
void APInt::tcClearBit(WordType *parts, unsigned bit) {
  parts[whichWord(bit)] &= ~maskBit(bit);
}

                                                               
                                                                    
unsigned APInt::tcLSB(const WordType *parts, unsigned n) {
  for (unsigned i = 0; i < n; i++) {
    if (parts[i] != 0) {
      unsigned lsb = partLSB(parts[i]);

      return lsb + i * APINT_BITS_PER_WORD;
    }
  }

  return -1U;
}

                                                                      
                                                           
unsigned APInt::tcMSB(const WordType *parts, unsigned n) {
  do {
    --n;

    if (parts[n] != 0) {
      unsigned msb = partMSB(parts[n]);

      return msb + n * APINT_BITS_PER_WORD;
    }
  } while (n);

  return -1U;
}

                                                                 
                                                                      
                                                                    
                           
void
APInt::tcExtract(WordType *dst, unsigned dstCount, const WordType *src,
                 unsigned srcBits, unsigned srcLSB) {
  unsigned dstParts = (srcBits + APINT_BITS_PER_WORD - 1) / APINT_BITS_PER_WORD;
  assert(dstParts <= dstCount);

  unsigned firstSrcPart = srcLSB / APINT_BITS_PER_WORD;
  tcAssign (dst, src + firstSrcPart, dstParts);

  unsigned shift = srcLSB % APINT_BITS_PER_WORD;
  tcShiftRight (dst, dstParts, shift);

                                                                       
                                                                 
                             
  unsigned n = dstParts * APINT_BITS_PER_WORD - shift;
  if (n < srcBits) {
    WordType mask = lowBitMask (srcBits - n);
    dst[dstParts - 1] |= ((src[firstSrcPart + dstParts] & mask)
                          << n % APINT_BITS_PER_WORD);
  } else if (n > srcBits) {
    if (srcBits % APINT_BITS_PER_WORD)
      dst[dstParts - 1] &= lowBitMask (srcBits % APINT_BITS_PER_WORD);
  }

                          
  while (dstParts < dstCount)
    dst[dstParts++] = 0;
}

                                                                      
APInt::WordType APInt::tcAdd(WordType *dst, const WordType *rhs,
                             WordType c, unsigned parts) {
  assert(c <= 1);

  for (unsigned i = 0; i < parts; i++) {
    WordType l = dst[i];
    if (c) {
      dst[i] += rhs[i] + 1;
      c = (dst[i] <= l);
    } else {
      dst[i] += rhs[i];
      c = (dst[i] < l);
    }
  }

  return c;
}

                                                                    
                                                                              
                                                                   
                                       
APInt::WordType APInt::tcAddPart(WordType *dst, WordType src,
                                 unsigned parts) {
  for (unsigned i = 0; i < parts; ++i) {
    dst[i] += src;
    if (dst[i] >= src)
      return 0;                                   
    src = 1;                            
  }

  return 1;
}

                                                                      
APInt::WordType APInt::tcSubtract(WordType *dst, const WordType *rhs,
                                  WordType c, unsigned parts) {
  assert(c <= 1);

  for (unsigned i = 0; i < parts; i++) {
    WordType l = dst[i];
    if (c) {
      dst[i] -= rhs[i] + 1;
      c = (dst[i] >= l);
    } else {
      dst[i] -= rhs[i];
      c = (dst[i] > l);
    }
  }

  return c;
}

                                                                    
                                                                               
                                                                                
                                                                        
                                                                         
                
                                              
APInt::WordType APInt::tcSubtractPart(WordType *dst, WordType src,
                                      unsigned parts) {
  for (unsigned i = 0; i < parts; ++i) {
    WordType Dst = dst[i];
    dst[i] -= src;
    if (src <= Dst)
      return 0;                                    
    src = 1;                                          
  }

  return 1;
}

                                
void APInt::tcNegate(WordType *dst, unsigned parts) {
  tcComplement(dst, parts);
  tcIncrement(dst, parts);
}

                                                    
                                                     

                                                                
                                                       

                                                              
                                                                 
                                                                  
                                                                
                   
int APInt::tcMultiplyPart(WordType *dst, const WordType *src,
                          WordType multiplier, WordType carry,
                          unsigned srcParts, unsigned dstParts,
                          bool add) {
                                                                 
  assert(dst <= src || dst >= src + srcParts);
  assert(dstParts <= srcParts + 1);

                                                   
  unsigned n = std::min(dstParts, srcParts);

  for (unsigned i = 0; i < n; i++) {
    WordType low, mid, high, srcPart;

                                                              

                                      

                                                          

                                    

    srcPart = src[i];

    if (multiplier == 0 || srcPart == 0) {
      low = carry;
      high = 0;
    } else {
      low = lowHalf(srcPart) * lowHalf(multiplier);
      high = highHalf(srcPart) * highHalf(multiplier);

      mid = lowHalf(srcPart) * highHalf(multiplier);
      high += highHalf(mid);
      mid <<= APINT_BITS_PER_WORD / 2;
      if (low + mid < low)
        high++;
      low += mid;

      mid = highHalf(srcPart) * lowHalf(multiplier);
      high += highHalf(mid);
      mid <<= APINT_BITS_PER_WORD / 2;
      if (low + mid < low)
        high++;
      low += mid;

                           
      if (low + carry < low)
        high++;
      low += carry;
    }

    if (add) {
                                                              
      if (low + dst[i] < low)
        high++;
      dst[i] += low;
    } else
      dst[i] = low;

    carry = high;
  }

  if (srcParts < dstParts) {
                                                     
    assert(srcParts + 1 == dstParts);
    dst[srcParts] = carry;
    return 0;
  }

                                         
  if (carry)
    return 1;

                                                                  
                                                                    
                                        
  if (multiplier)
    for (unsigned i = dstParts; i < srcParts; i++)
      if (src[i])
        return 1;

                                             
  return 0;
}

                                                                    
                                                                     
                                                                  
                          
int APInt::tcMultiply(WordType *dst, const WordType *lhs,
                      const WordType *rhs, unsigned parts) {
  assert(dst != lhs && dst != rhs);

  int overflow = 0;
  tcSet(dst, 0, parts);

  for (unsigned i = 0; i < parts; i++)
    overflow |= tcMultiplyPart(&dst[i], lhs, rhs[i], 0, parts,
                               parts - i, true);

  return overflow;
}

                                                                     
                                                                          
void APInt::tcFullMultiply(WordType *dst, const WordType *lhs,
                           const WordType *rhs, unsigned lhsParts,
                           unsigned rhsParts) {
                                                                 
  if (lhsParts > rhsParts)
    return tcFullMultiply (dst, rhs, lhs, rhsParts, lhsParts);

  assert(dst != lhs && dst != rhs);

  tcSet(dst, 0, rhsParts);

  for (unsigned i = 0; i < lhsParts; i++)
    tcMultiplyPart(&dst[i], rhs, lhs[i], 0, rhsParts, rhsParts + 1, true);
}

                                                                   
                                                                     
                                                     

                                  

                                                                      
                                                                   
                                                           
  
int APInt::tcDivide(WordType *lhs, const WordType *rhs,
                    WordType *remainder, WordType *srhs,
                    unsigned parts) {
  assert(lhs != remainder && lhs != srhs && remainder != srhs);

  unsigned shiftCount = tcMSB(rhs, parts) + 1;
  if (shiftCount == 0)
    return true;

  shiftCount = parts * APINT_BITS_PER_WORD - shiftCount;
  unsigned n = shiftCount / APINT_BITS_PER_WORD;
  WordType mask = (WordType) 1 << (shiftCount % APINT_BITS_PER_WORD);

  tcAssign(srhs, rhs, parts);
  tcShiftLeft(srhs, parts, shiftCount);
  tcAssign(remainder, lhs, parts);
  tcSet(lhs, 0, parts);

                                                                      
                   
  for (;;) {
    int compare = tcCompare(remainder, srhs, parts);
    if (compare >= 0) {
      tcSubtract(remainder, srhs, 0, parts);
      lhs[n] |= mask;
    }

    if (shiftCount == 0)
      break;
    shiftCount--;
    tcShiftRight(srhs, parts, 1);
    if ((mask >>= 1) == 0) {
      mask = (WordType) 1 << (APINT_BITS_PER_WORD - 1);
      n--;
    }
  }

  return false;
}

                                                                                
                             
void APInt::tcShiftLeft(WordType *Dst, unsigned Words, unsigned Count) {
                                           
  if (!Count)
    return;

                                                                         
  unsigned WordShift = std::min(Count / APINT_BITS_PER_WORD, Words);
  unsigned BitShift = Count % APINT_BITS_PER_WORD;

                                        
  if (BitShift == 0) {
    std::memmove(Dst + WordShift, Dst, (Words - WordShift) * APINT_WORD_SIZE);
  } else {
    while (Words-- > WordShift) {
      Dst[Words] = Dst[Words - WordShift] << BitShift;
      if (Words > WordShift)
        Dst[Words] |=
          Dst[Words - WordShift - 1] >> (APINT_BITS_PER_WORD - BitShift);
    }
  }

                                   
  std::memset(Dst, 0, WordShift * APINT_WORD_SIZE);
}

                                                                             
                                 
void APInt::tcShiftRight(WordType *Dst, unsigned Words, unsigned Count) {
                                           
  if (!Count)
    return;

                                                                         
  unsigned WordShift = std::min(Count / APINT_BITS_PER_WORD, Words);
  unsigned BitShift = Count % APINT_BITS_PER_WORD;

  unsigned WordsToMove = Words - WordShift;
                                        
  if (BitShift == 0) {
    std::memmove(Dst, Dst + WordShift, WordsToMove * APINT_WORD_SIZE);
  } else {
    for (unsigned i = 0; i != WordsToMove; ++i) {
      Dst[i] = Dst[i + WordShift] >> BitShift;
      if (i + 1 != WordsToMove)
        Dst[i] |= Dst[i + WordShift + 1] << (APINT_BITS_PER_WORD - BitShift);
    }
  }

                                   
  std::memset(Dst + WordsToMove, 0, WordShift * APINT_WORD_SIZE);
}

                                  
void APInt::tcAnd(WordType *dst, const WordType *rhs, unsigned parts) {
  for (unsigned i = 0; i < parts; i++)
    dst[i] &= rhs[i];
}

                                           
void APInt::tcOr(WordType *dst, const WordType *rhs, unsigned parts) {
  for (unsigned i = 0; i < parts; i++)
    dst[i] |= rhs[i];
}

                                           
void APInt::tcXor(WordType *dst, const WordType *rhs, unsigned parts) {
  for (unsigned i = 0; i < parts; i++)
    dst[i] ^= rhs[i];
}

                                    
void APInt::tcComplement(WordType *dst, unsigned parts) {
  for (unsigned i = 0; i < parts; i++)
    dst[i] = ~dst[i];
}

                                            
int APInt::tcCompare(const WordType *lhs, const WordType *rhs,
                     unsigned parts) {
  while (parts) {
    parts--;
    if (lhs[parts] != rhs[parts])
      return (lhs[parts] > rhs[parts]) ? 1 : -1;
  }

  return 0;
}

                                                             
            
void APInt::tcSetLeastSignificantBits(WordType *dst, unsigned parts,
                                      unsigned bits) {
  unsigned i = 0;
  while (bits > APINT_BITS_PER_WORD) {
    dst[i++] = ~(WordType) 0;
    bits -= APINT_BITS_PER_WORD;
  }

  if (bits)
    dst[i++] = ~(WordType) 0 >> (APINT_BITS_PER_WORD - bits);

  while (i < parts)
    dst[i++] = 0;
}

APInt llvh::APIntOps::RoundingUDiv(const APInt &A, const APInt &B,
                                   APInt::Rounding RM) {
                                          
  switch (RM) {
  case APInt::Rounding::DOWN:
  case APInt::Rounding::TOWARD_ZERO:
    return A.udiv(B);
  case APInt::Rounding::UP: {
    APInt Quo, Rem;
    APInt::udivrem(A, B, Quo, Rem);
    if (Rem == 0)
      return Quo;
    return Quo + 1;
  }
  }
  llvm_unreachable("Unknown APInt::Rounding enum");
}

APInt llvh::APIntOps::RoundingSDiv(const APInt &A, const APInt &B,
                                   APInt::Rounding RM) {
  switch (RM) {
  case APInt::Rounding::DOWN:
  case APInt::Rounding::UP: {
    APInt Quo, Rem;
    APInt::sdivrem(A, B, Quo, Rem);
    if (Rem == 0)
      return Quo;
                                                                         
                                                                              
                                                                                
                                                                              
                            
    if (RM == APInt::Rounding::DOWN) {
      if (Rem.isNegative() != B.isNegative())
        return Quo - 1;
      return Quo;
    }
    if (Rem.isNegative() != B.isNegative())
      return Quo;
    return Quo + 1;
  }
                                       
  case APInt::Rounding::TOWARD_ZERO:
    return A.sdiv(B);
  }
  llvm_unreachable("Unknown APInt::Rounding enum");
}

Optional<APInt>
llvh::APIntOps::SolveQuadraticEquationWrap(APInt A, APInt B, APInt C,
                                           unsigned RangeWidth) {
  unsigned CoeffWidth = A.getBitWidth();
  assert(CoeffWidth == B.getBitWidth() && CoeffWidth == C.getBitWidth());
  assert(RangeWidth <= CoeffWidth &&
         "Value range width should be less than coefficient width");
  assert(RangeWidth > 1 && "Value range bit width should be > 1");

  LLVM_DEBUG(dbgs() << __func__ << ": solving " << A << "x^2 + " << B
                    << "x + " << C << ", rw:" << RangeWidth << '\n');

                                               
  if (C.sextOrTrunc(RangeWidth).isNullValue() ) {
    LLVM_DEBUG(dbgs() << __func__ << ": zero solution\n");
    return APInt(CoeffWidth, 0);
  }

                                                                           
                                                                             
                                           
                                                                          
                                                                          
                                                                             
                            
    
                                                                            
                                                                             
                                                                          
                                                                         
                                                                           
                    
  CoeffWidth *= 3;
  A = A.sext(CoeffWidth);
  B = B.sext(CoeffWidth);
  C = C.sext(CoeffWidth);

                                                                            
                                 
  if (A.isNegative()) {
    A.negate();
    B.negate();
    C.negate();
  }

                                                                         
                                                                         
                        
                                                                         
                                                                          
                                                                      
                                                        
    
                                                                        
                                                                       
                                                                         
                                                  
                                                         
    
                                                                      
                                                                         
                                                                      
    
                                                                         
                                                      
                                                                   
                
  APInt R = APInt::getOneBitSet(CoeffWidth, RangeWidth);
  APInt TwoA = 2 * A;
  APInt SqrB = B * B;
  bool PickLow;

  auto RoundUp = [] (const APInt &V, const APInt &A) -> APInt {
    assert(A.isStrictlyPositive());
    APInt T = V.abs().urem(A);
    if (T.isNullValue())
      return V;
    return V.isNegative() ? V+T : V+(A-T);
  };

                                                                           
                       
  if (B.isNonNegative()) {
                                                                       
                                                                         
                                                                      
                                                                     
    C = C.srem(R);
    if (C.isStrictlyPositive())
      C -= R;
                                 
    PickLow = false;
  } else {
                                                                       
                                                                       
                                                                     
                                                    
    APInt LowkR = C - SqrB.udiv(2*TwoA);                                
                                                       
    LowkR = RoundUp(LowkR, R);

                                                                   
                                                                    
                                                                      
                                                                   
                                                                
    if (C.sgt(LowkR)) {
                                                                   
                                         
      C -= -RoundUp(-C, R);                                
                                   
      PickLow = true;
    } else {
                                                                      
                                                                         
                                                                   
                                                                       
                                                                           
                                                 
                                                                    
      C -= LowkR;
                                   
      PickLow = false;
    }
  }

  LLVM_DEBUG(dbgs() << __func__ << ": updated coefficients " << A << "x^2 + "
                    << B << "x + " << C << ", rw:" << RangeWidth << '\n');

  APInt D = SqrB - 4*A*C;
  assert(D.isNonNegative() && "Negative discriminant");
  APInt SQ = D.sqrt();

  APInt Q = SQ * SQ;
  bool InexactSQ = Q != D;
                                                                           
                                                                            
  if (Q.sgt(D))
    SQ -= 1;

  APInt X;
  APInt Rem;

                                                                        
                                                                       
                                                                         
                                                                        
                                                                        
            
  if (PickLow)
    APInt::sdivrem(-B - (SQ+InexactSQ), TwoA, X, Rem);
  else
    APInt::sdivrem(-B + SQ, TwoA, X, Rem);

                                                                         
                                                                        
                                      
  assert(X.isNonNegative() && "Solution should be non-negative");

  if (!InexactSQ && Rem.isNullValue()) {
    LLVM_DEBUG(dbgs() << __func__ << ": solution (root): " << X << '\n');
    return X;
  }

  assert((SQ*SQ).sle(D) && "SQ = |_sqrt(D)_|, so SQ*SQ <= D");
                                                                           
                                                                           
                                                
    
                                                                       
                                                                     
                                             

  APInt VX = (A*X + B)*X + C;
  APInt VY = VX + TwoA*X + A + B;
  bool SignChange = VX.isNegative() != VY.isNegative() ||
                    VX.isNullValue() != VY.isNullValue();
                                                                             
                                                                          
                                                                     
  if (!SignChange) {
    LLVM_DEBUG(dbgs() << __func__ << ": no valid solution\n");
    return None;
  }

  X += 1;
  LLVM_DEBUG(dbgs() << __func__ << ": solution (wrap): " << X << '\n');
  return X;
}

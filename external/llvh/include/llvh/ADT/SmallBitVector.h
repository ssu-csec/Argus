//===- llvm/ADT/SmallBitVector.h - 'Normally small' bit vectors -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the SmallBitVector class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_SMALLBITVECTOR_H
#define LLVM_ADT_SMALLBITVECTOR_H

#include "llvh/ADT/BitVector.h"
#include "llvh/ADT/iterator_range.h"
#include "llvh/Support/MathExtras.h"
#include <algorithm>
#include <cassert>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <utility>

namespace llvh {

                                                                             
                                                                                
                                                                         
                                                                               
                                                                        
class SmallBitVector {
                                                                           
                                                                          
                                                                               
  uintptr_t X = 1;

  enum {
                                        
    NumBaseBits = sizeof(uintptr_t) * CHAR_BIT,

                                                                        
                                                                 
    SmallNumRawBits = NumBaseBits - 1,

                                                                               
                                                                            
                                        
    SmallNumSizeBits = (NumBaseBits == 32 ? 5 :
                        NumBaseBits == 64 ? 6 :
                        SmallNumRawBits),

                                                                         
    SmallNumDataBits = SmallNumRawBits - SmallNumSizeBits
  };

  static_assert(NumBaseBits == 64 || NumBaseBits == 32,
                "Unsupported word size");

public:
  using size_type = unsigned;

                                   
  class reference {
    SmallBitVector &TheVector;
    unsigned BitPos;

  public:
    reference(SmallBitVector &b, unsigned Idx) : TheVector(b), BitPos(Idx) {}

    reference(const reference&) = default;

    reference& operator=(reference t) {
      *this = bool(t);
      return *this;
    }

    reference& operator=(bool t) {
      if (t)
        TheVector.set(BitPos);
      else
        TheVector.reset(BitPos);
      return *this;
    }

    operator bool() const {
      return const_cast<const SmallBitVector &>(TheVector).operator[](BitPos);
    }
  };

private:
  bool isSmall() const {
    return X & uintptr_t(1);
  }

  BitVector *getPointer() const {
    assert(!isSmall());
    return reinterpret_cast<BitVector *>(X);
  }

  void switchToSmall(uintptr_t NewSmallBits, size_t NewSize) {
    X = 1;
    setSmallSize(NewSize);
    setSmallBits(NewSmallBits);
  }

  void switchToLarge(BitVector *BV) {
    X = reinterpret_cast<uintptr_t>(BV);
    assert(!isSmall() && "Tried to use an unaligned pointer");
  }

                                                                           
                                                   
  uintptr_t getSmallRawBits() const {
    assert(isSmall());
    return X >> 1;
  }

  void setSmallRawBits(uintptr_t NewRawBits) {
    assert(isSmall());
    X = (NewRawBits << 1) | uintptr_t(1);
  }

                     
  size_t getSmallSize() const { return getSmallRawBits() >> SmallNumDataBits; }

  void setSmallSize(size_t Size) {
    setSmallRawBits(getSmallBits() | (Size << SmallNumDataBits));
  }

                             
  uintptr_t getSmallBits() const {
    return getSmallRawBits() & ~(~uintptr_t(0) << getSmallSize());
  }

  void setSmallBits(uintptr_t NewBits) {
    setSmallRawBits((NewBits & ~(~uintptr_t(0) << getSmallSize())) |
                    (getSmallSize() << SmallNumDataBits));
  }

public:
                                 
  SmallBitVector() = default;

                                                                               
                             
  explicit SmallBitVector(unsigned s, bool t = false) {
    if (s <= SmallNumDataBits)
      switchToSmall(t ? ~uintptr_t(0) : 0, s);
    else
      switchToLarge(new BitVector(s, t));
  }

                               
  SmallBitVector(const SmallBitVector &RHS) {
    if (RHS.isSmall())
      X = RHS.X;
    else
      switchToLarge(new BitVector(*RHS.getPointer()));
  }

  SmallBitVector(SmallBitVector &&RHS) : X(RHS.X) {
    RHS.X = 1;
  }

  ~SmallBitVector() {
    if (!isSmall())
      delete getPointer();
  }

  using const_set_bits_iterator = const_set_bits_iterator_impl<SmallBitVector>;
  using set_iterator = const_set_bits_iterator;

  const_set_bits_iterator set_bits_begin() const {
    return const_set_bits_iterator(*this);
  }

  const_set_bits_iterator set_bits_end() const {
    return const_set_bits_iterator(*this, -1);
  }

  iterator_range<const_set_bits_iterator> set_bits() const {
    return make_range(set_bits_begin(), set_bits_end());
  }

                                                        
  bool empty() const {
    return isSmall() ? getSmallSize() == 0 : getPointer()->empty();
  }

                                                   
  size_t size() const {
    return isSmall() ? getSmallSize() : getPointer()->size();
  }

                                               
  size_type count() const {
    if (isSmall()) {
      uintptr_t Bits = getSmallBits();
      return countPopulation(Bits);
    }
    return getPointer()->count();
  }

                                     
  bool any() const {
    if (isSmall())
      return getSmallBits() != 0;
    return getPointer()->any();
  }

                                       
  bool all() const {
    if (isSmall())
      return getSmallBits() == (uintptr_t(1) << getSmallSize()) - 1;
    return getPointer()->all();
  }

                                               
  bool none() const {
    if (isSmall())
      return getSmallBits() == 0;
    return getPointer()->none();
  }

                                                                             
  int find_first() const {
    if (isSmall()) {
      uintptr_t Bits = getSmallBits();
      if (Bits == 0)
        return -1;
      return countTrailingZeros(Bits);
    }
    return getPointer()->find_first();
  }

  int find_last() const {
    if (isSmall()) {
      uintptr_t Bits = getSmallBits();
      if (Bits == 0)
        return -1;
      return NumBaseBits - countLeadingZeros(Bits);
    }
    return getPointer()->find_last();
  }

                                                                              
  int find_first_unset() const {
    if (isSmall()) {
      if (count() == getSmallSize())
        return -1;

      uintptr_t Bits = getSmallBits();
      return countTrailingOnes(Bits);
    }
    return getPointer()->find_first_unset();
  }

  int find_last_unset() const {
    if (isSmall()) {
      if (count() == getSmallSize())
        return -1;

      uintptr_t Bits = getSmallBits();
      return NumBaseBits - countLeadingOnes(Bits);
    }
    return getPointer()->find_last_unset();
  }

                                                                     
                                                  
  int find_next(unsigned Prev) const {
    if (isSmall()) {
      uintptr_t Bits = getSmallBits();
                                
      Bits &= ~uintptr_t(0) << (Prev + 1);
      if (Bits == 0 || Prev + 1 >= getSmallSize())
        return -1;
      return countTrailingZeros(Bits);
    }
    return getPointer()->find_next(Prev);
  }

                                                                       
                                                    
  int find_next_unset(unsigned Prev) const {
    if (isSmall()) {
      ++Prev;
      uintptr_t Bits = getSmallBits();
                               
      uintptr_t Mask = (1 << Prev) - 1;
      Bits |= Mask;

      if (Bits == ~uintptr_t(0) || Prev + 1 >= getSmallSize())
        return -1;
      return countTrailingOnes(Bits);
    }
    return getPointer()->find_next_unset(Prev);
  }

                                                                          
                                                                        
  int find_prev(unsigned PriorTo) const {
    if (isSmall()) {
      if (PriorTo == 0)
        return -1;

      --PriorTo;
      uintptr_t Bits = getSmallBits();
      Bits &= maskTrailingOnes<uintptr_t>(PriorTo + 1);
      if (Bits == 0)
        return -1;

      return NumBaseBits - countLeadingZeros(Bits) - 1;
    }
    return getPointer()->find_prev(PriorTo);
  }

                     
  void clear() {
    if (!isSmall())
      delete getPointer();
    switchToSmall(0, 0);
  }

                                   
  void resize(unsigned N, bool t = false) {
    if (!isSmall()) {
      getPointer()->resize(N, t);
    } else if (SmallNumDataBits >= N) {
      uintptr_t NewBits = t ? ~uintptr_t(0) << getSmallSize() : 0;
      setSmallSize(N);
      setSmallBits(NewBits | getSmallBits());
    } else {
      BitVector *BV = new BitVector(N, t);
      uintptr_t OldBits = getSmallBits();
      for (size_t i = 0, e = getSmallSize(); i != e; ++i)
        (*BV)[i] = (OldBits >> i) & 1;
      switchToLarge(BV);
    }
  }

  void reserve(unsigned N) {
    if (isSmall()) {
      if (N > SmallNumDataBits) {
        uintptr_t OldBits = getSmallRawBits();
        size_t SmallSize = getSmallSize();
        BitVector *BV = new BitVector(SmallSize);
        for (size_t i = 0; i < SmallSize; ++i)
          if ((OldBits >> i) & 1)
            BV->set(i);
        BV->reserve(N);
        switchToLarge(BV);
      }
    } else {
      getPointer()->reserve(N);
    }
  }

                     
  SmallBitVector &set() {
    if (isSmall())
      setSmallBits(~uintptr_t(0));
    else
      getPointer()->set();
    return *this;
  }

  SmallBitVector &set(unsigned Idx) {
    if (isSmall()) {
      assert(Idx <= static_cast<unsigned>(
                        std::numeric_limits<uintptr_t>::digits) &&
             "undefined behavior");
      setSmallBits(getSmallBits() | (uintptr_t(1) << Idx));
    }
    else
      getPointer()->set(Idx);
    return *this;
  }

                                               
  SmallBitVector &set(unsigned I, unsigned E) {
    assert(I <= E && "Attempted to set backwards range!");
    assert(E <= size() && "Attempted to set out-of-bounds range!");
    if (I == E) return *this;
    if (isSmall()) {
      uintptr_t EMask = ((uintptr_t)1) << E;
      uintptr_t IMask = ((uintptr_t)1) << I;
      uintptr_t Mask = EMask - IMask;
      setSmallBits(getSmallBits() | Mask);
    } else
      getPointer()->set(I, E);
    return *this;
  }

  SmallBitVector &reset() {
    if (isSmall())
      setSmallBits(0);
    else
      getPointer()->reset();
    return *this;
  }

  SmallBitVector &reset(unsigned Idx) {
    if (isSmall())
      setSmallBits(getSmallBits() & ~(uintptr_t(1) << Idx));
    else
      getPointer()->reset(Idx);
    return *this;
  }

                                                 
  SmallBitVector &reset(unsigned I, unsigned E) {
    assert(I <= E && "Attempted to reset backwards range!");
    assert(E <= size() && "Attempted to reset out-of-bounds range!");
    if (I == E) return *this;
    if (isSmall()) {
      uintptr_t EMask = ((uintptr_t)1) << E;
      uintptr_t IMask = ((uintptr_t)1) << I;
      uintptr_t Mask = EMask - IMask;
      setSmallBits(getSmallBits() & ~Mask);
    } else
      getPointer()->reset(I, E);
    return *this;
  }

  SmallBitVector &flip() {
    if (isSmall())
      setSmallBits(~getSmallBits());
    else
      getPointer()->flip();
    return *this;
  }

  SmallBitVector &flip(unsigned Idx) {
    if (isSmall())
      setSmallBits(getSmallBits() ^ (uintptr_t(1) << Idx));
    else
      getPointer()->flip(Idx);
    return *this;
  }

                      
  SmallBitVector operator~() const {
    return SmallBitVector(*this).flip();
  }

              
  reference operator[](unsigned Idx) {
    assert(Idx < size() && "Out-of-bounds Bit access.");
    return reference(*this, Idx);
  }

  bool operator[](unsigned Idx) const {
    assert(Idx < size() && "Out-of-bounds Bit access.");
    if (isSmall())
      return ((getSmallBits() >> Idx) & 1) != 0;
    return getPointer()->operator[](Idx);
  }

  bool test(unsigned Idx) const {
    return (*this)[Idx];
  }

                                      
  void push_back(bool Val) {
    resize(size() + 1, Val);
  }

                                      
  bool anyCommon(const SmallBitVector &RHS) const {
    if (isSmall() && RHS.isSmall())
      return (getSmallBits() & RHS.getSmallBits()) != 0;
    if (!isSmall() && !RHS.isSmall())
      return getPointer()->anyCommon(*RHS.getPointer());

    for (unsigned i = 0, e = std::min(size(), RHS.size()); i != e; ++i)
      if (test(i) && RHS.test(i))
        return true;
    return false;
  }

                          
  bool operator==(const SmallBitVector &RHS) const {
    if (size() != RHS.size())
      return false;
    if (isSmall())
      return getSmallBits() == RHS.getSmallBits();
    else
      return *getPointer() == *RHS.getPointer();
  }

  bool operator!=(const SmallBitVector &RHS) const {
    return !(*this == RHS);
  }

                                         
  SmallBitVector &operator&=(const SmallBitVector &RHS) {
    resize(std::max(size(), RHS.size()));
    if (isSmall())
      setSmallBits(getSmallBits() & RHS.getSmallBits());
    else if (!RHS.isSmall())
      getPointer()->operator&=(*RHS.getPointer());
    else {
      SmallBitVector Copy = RHS;
      Copy.resize(size());
      getPointer()->operator&=(*Copy.getPointer());
    }
    return *this;
  }

                                                            
  SmallBitVector &reset(const SmallBitVector &RHS) {
    if (isSmall() && RHS.isSmall())
      setSmallBits(getSmallBits() & ~RHS.getSmallBits());
    else if (!isSmall() && !RHS.isSmall())
      getPointer()->reset(*RHS.getPointer());
    else
      for (unsigned i = 0, e = std::min(size(), RHS.size()); i != e; ++i)
        if (RHS.test(i))
          reset(i);

    return *this;
  }

                                                                              
  bool test(const SmallBitVector &RHS) const {
    if (isSmall() && RHS.isSmall())
      return (getSmallBits() & ~RHS.getSmallBits()) != 0;
    if (!isSmall() && !RHS.isSmall())
      return getPointer()->test(*RHS.getPointer());

    unsigned i, e;
    for (i = 0, e = std::min(size(), RHS.size()); i != e; ++i)
      if (test(i) && !RHS.test(i))
        return true;

    for (e = size(); i != e; ++i)
      if (test(i))
        return true;

    return false;
  }

  SmallBitVector &operator|=(const SmallBitVector &RHS) {
    resize(std::max(size(), RHS.size()));
    if (isSmall())
      setSmallBits(getSmallBits() | RHS.getSmallBits());
    else if (!RHS.isSmall())
      getPointer()->operator|=(*RHS.getPointer());
    else {
      SmallBitVector Copy = RHS;
      Copy.resize(size());
      getPointer()->operator|=(*Copy.getPointer());
    }
    return *this;
  }

  SmallBitVector &operator^=(const SmallBitVector &RHS) {
    resize(std::max(size(), RHS.size()));
    if (isSmall())
      setSmallBits(getSmallBits() ^ RHS.getSmallBits());
    else if (!RHS.isSmall())
      getPointer()->operator^=(*RHS.getPointer());
    else {
      SmallBitVector Copy = RHS;
      Copy.resize(size());
      getPointer()->operator^=(*Copy.getPointer());
    }
    return *this;
  }

  SmallBitVector &operator<<=(unsigned N) {
    if (isSmall())
      setSmallBits(getSmallBits() << N);
    else
      getPointer()->operator<<=(N);
    return *this;
  }

  SmallBitVector &operator>>=(unsigned N) {
    if (isSmall())
      setSmallBits(getSmallBits() >> N);
    else
      getPointer()->operator>>=(N);
    return *this;
  }

                         
  const SmallBitVector &operator=(const SmallBitVector &RHS) {
    if (isSmall()) {
      if (RHS.isSmall())
        X = RHS.X;
      else
        switchToLarge(new BitVector(*RHS.getPointer()));
    } else {
      if (!RHS.isSmall())
        *getPointer() = *RHS.getPointer();
      else {
        delete getPointer();
        X = RHS.X;
      }
    }
    return *this;
  }

  const SmallBitVector &operator=(SmallBitVector &&RHS) {
    if (this != &RHS) {
      clear();
      swap(RHS);
    }
    return *this;
  }

  void swap(SmallBitVector &RHS) {
    std::swap(X, RHS.X);
  }

                                                          
                                    
  void setBitsInMask(const uint32_t *Mask, unsigned MaskWords = ~0u) {
    if (isSmall())
      applyMask<true, false>(Mask, MaskWords);
    else
      getPointer()->setBitsInMask(Mask, MaskWords);
  }

                                                                       
                                     
  void clearBitsInMask(const uint32_t *Mask, unsigned MaskWords = ~0u) {
    if (isSmall())
      applyMask<false, false>(Mask, MaskWords);
    else
      getPointer()->clearBitsInMask(Mask, MaskWords);
  }

                                                                       
                                     
  void setBitsNotInMask(const uint32_t *Mask, unsigned MaskWords = ~0u) {
    if (isSmall())
      applyMask<true, true>(Mask, MaskWords);
    else
      getPointer()->setBitsNotInMask(Mask, MaskWords);
  }

                                                                         
                                    
  void clearBitsNotInMask(const uint32_t *Mask, unsigned MaskWords = ~0u) {
    if (isSmall())
      applyMask<false, true>(Mask, MaskWords);
    else
      getPointer()->clearBitsNotInMask(Mask, MaskWords);
  }

private:
  template <bool AddBits, bool InvertMask>
  void applyMask(const uint32_t *Mask, unsigned MaskWords) {
    assert(MaskWords <= sizeof(uintptr_t) && "Mask is larger than base!");
    uintptr_t M = Mask[0];
    if (NumBaseBits == 64)
      M |= uint64_t(Mask[1]) << 32;
    if (InvertMask)
      M = ~M;
    if (AddBits)
      setSmallBits(getSmallBits() | M);
    else
      setSmallBits(getSmallBits() & ~M);
  }
};

inline SmallBitVector
operator&(const SmallBitVector &LHS, const SmallBitVector &RHS) {
  SmallBitVector Result(LHS);
  Result &= RHS;
  return Result;
}

inline SmallBitVector
operator|(const SmallBitVector &LHS, const SmallBitVector &RHS) {
  SmallBitVector Result(LHS);
  Result |= RHS;
  return Result;
}

inline SmallBitVector
operator^(const SmallBitVector &LHS, const SmallBitVector &RHS) {
  SmallBitVector Result(LHS);
  Result ^= RHS;
  return Result;
}

}                      

namespace std {

                                                   
inline void
swap(llvh::SmallBitVector &LHS, llvh::SmallBitVector &RHS) {
  LHS.swap(RHS);
}

}                     

#endif                             

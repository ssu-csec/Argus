//===- llvm/ADT/PackedVector.h - Packed values vector -----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the PackedVector class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_PACKEDVECTOR_H
#define LLVM_ADT_PACKEDVECTOR_H

#include "llvh/ADT/BitVector.h"
#include <cassert>
#include <limits>

namespace llvh {

template <typename T, unsigned BitNum, typename BitVectorTy, bool isSigned>
class PackedVectorBase;

                                                                            
                       
template <typename T, unsigned BitNum, typename BitVectorTy>
class PackedVectorBase<T, BitNum, BitVectorTy, false> {
protected:
  static T getValue(const BitVectorTy &Bits, unsigned Idx) {
    T val = T();
    for (unsigned i = 0; i != BitNum; ++i)
      val = T(val | ((Bits[(Idx << (BitNum-1)) + i] ? 1UL : 0UL) << i));
    return val;
  }

  static void setValue(BitVectorTy &Bits, unsigned Idx, T val) {
    assert((val >> BitNum) == 0 && "value is too big");
    for (unsigned i = 0; i != BitNum; ++i)
      Bits[(Idx << (BitNum-1)) + i] = val & (T(1) << i);
  }
};

template <typename T, unsigned BitNum, typename BitVectorTy>
class PackedVectorBase<T, BitNum, BitVectorTy, true> {
protected:
  static T getValue(const BitVectorTy &Bits, unsigned Idx) {
    T val = T();
    for (unsigned i = 0; i != BitNum-1; ++i)
      val = T(val | ((Bits[(Idx << (BitNum-1)) + i] ? 1UL : 0UL) << i));
    if (Bits[(Idx << (BitNum-1)) + BitNum-1])
      val = ~val;
    return val;
  }

  static void setValue(BitVectorTy &Bits, unsigned Idx, T val) {
    if (val < 0) {
      val = ~val;
      Bits.set((Idx << (BitNum-1)) + BitNum-1);
    }
    assert((val >> (BitNum-1)) == 0 && "value is too big");
    for (unsigned i = 0; i != BitNum-1; ++i)
      Bits[(Idx << (BitNum-1)) + i] = val & (T(1) << i);
  }
};

                                                                     
                                                          
         
                                  
            
                                                                                
                 
template <typename T, unsigned BitNum, typename BitVectorTy = BitVector>
class PackedVector : public PackedVectorBase<T, BitNum, BitVectorTy,
                                            std::numeric_limits<T>::is_signed> {
  BitVectorTy Bits;
  using base = PackedVectorBase<T, BitNum, BitVectorTy,
                                std::numeric_limits<T>::is_signed>;

public:
  class reference {
    PackedVector &Vec;
    const unsigned Idx;

  public:
    reference() = delete;
    reference(PackedVector &vec, unsigned idx) : Vec(vec), Idx(idx) {}

    reference &operator=(T val) {
      Vec.setValue(Vec.Bits, Idx, val);
      return *this;
    }

    operator T() const {
      return Vec.getValue(Vec.Bits, Idx);
    }
  };

  PackedVector() = default;
  explicit PackedVector(unsigned size) : Bits(size << (BitNum-1)) {}

  bool empty() const { return Bits.empty(); }

  unsigned size() const { return Bits.size() >> (BitNum - 1); }

  void clear() { Bits.clear(); }

  void resize(unsigned N) { Bits.resize(N << (BitNum - 1)); }

  void reserve(unsigned N) { Bits.reserve(N << (BitNum-1)); }

  PackedVector &reset() {
    Bits.reset();
    return *this;
  }

  void push_back(T val) {
    resize(size()+1);
    (*this)[size()-1] = val;
  }

  reference operator[](unsigned Idx) {
    return reference(*this, Idx);
  }

  T operator[](unsigned Idx) const {
    return base::getValue(Bits, Idx);
  }

  bool operator==(const PackedVector &RHS) const {
    return Bits == RHS.Bits;
  }

  bool operator!=(const PackedVector &RHS) const {
    return Bits != RHS.Bits;
  }

  PackedVector &operator|=(const PackedVector &RHS) {
    Bits |= RHS.Bits;
    return *this;
  }
};

                            
template <typename T> class PackedVector<T, 0>;

}                      

#endif                           

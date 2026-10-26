//===- llvm/ADT/PointerIntPair.h - Pair for pointer and int -----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the PointerIntPair class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_POINTERINTPAIR_H
#define LLVM_ADT_POINTERINTPAIR_H

#include "llvh/Support/PointerLikeTypeTraits.h"
#include <cassert>
#include <cstdint>
#include <limits>

namespace llvh {

template <typename T> struct DenseMapInfo;
template <typename PointerT, unsigned IntBits, typename PtrTraits>
struct PointerIntPairInfo;

                                                                        
                                                                           
                                                                              
                                                                               
                                                                              
         
   
                                                                            
                                                                               
                                                                              
                                                  
                                                             
                                                      
template <typename PointerTy, unsigned IntBits, typename IntType = unsigned,
          typename PtrTraits = PointerLikeTypeTraits<PointerTy>,
          typename Info = PointerIntPairInfo<PointerTy, IntBits, PtrTraits>>
class PointerIntPair {
  intptr_t Value = 0;

public:
  constexpr PointerIntPair() = default;

  PointerIntPair(PointerTy PtrVal, IntType IntVal) {
    setPointerAndInt(PtrVal, IntVal);
  }

  explicit PointerIntPair(PointerTy PtrVal) { initWithPointer(PtrVal); }

  PointerTy getPointer() const { return Info::getPointer(Value); }

  IntType getInt() const { return (IntType)Info::getInt(Value); }

  void setPointer(PointerTy PtrVal) {
    Value = Info::updatePointer(Value, PtrVal);
  }

  void setInt(IntType IntVal) {
    Value = Info::updateInt(Value, static_cast<intptr_t>(IntVal));
  }

  void initWithPointer(PointerTy PtrVal) {
    Value = Info::updatePointer(0, PtrVal);
  }

  void setPointerAndInt(PointerTy PtrVal, IntType IntVal) {
    Value = Info::updateInt(Info::updatePointer(0, PtrVal),
                            static_cast<intptr_t>(IntVal));
  }

  PointerTy const *getAddrOfPointer() const {
    return const_cast<PointerIntPair *>(this)->getAddrOfPointer();
  }

  PointerTy *getAddrOfPointer() {
    assert(Value == reinterpret_cast<intptr_t>(getPointer()) &&
           "Can only return the address if IntBits is cleared and "
           "PtrTraits doesn't change the pointer");
    return reinterpret_cast<PointerTy *>(&Value);
  }

  void *getOpaqueValue() const { return reinterpret_cast<void *>(Value); }

  void setFromOpaqueValue(void *Val) {
    Value = reinterpret_cast<intptr_t>(Val);
  }

  static PointerIntPair getFromOpaqueValue(void *V) {
    PointerIntPair P;
    P.setFromOpaqueValue(V);
    return P;
  }

                                                                             
                                                       
  static PointerIntPair getFromOpaqueValue(const void *V) {
    (void)PtrTraits::getFromVoidPointer(V);
    return getFromOpaqueValue(const_cast<void *>(V));
  }

  bool operator==(const PointerIntPair &RHS) const {
    return Value == RHS.Value;
  }

  bool operator!=(const PointerIntPair &RHS) const {
    return Value != RHS.Value;
  }

  bool operator<(const PointerIntPair &RHS) const { return Value < RHS.Value; }
  bool operator>(const PointerIntPair &RHS) const { return Value > RHS.Value; }

  bool operator<=(const PointerIntPair &RHS) const {
    return Value <= RHS.Value;
  }

  bool operator>=(const PointerIntPair &RHS) const {
    return Value >= RHS.Value;
  }
};

template <typename PointerT, unsigned IntBits, typename PtrTraits>
struct PointerIntPairInfo {
  static_assert(PtrTraits::NumLowBitsAvailable <
                    std::numeric_limits<uintptr_t>::digits,
                "cannot use a pointer type that has all bits free");
  static_assert(IntBits <= PtrTraits::NumLowBitsAvailable,
                "PointerIntPair with integer size too large for pointer");
  enum : uintptr_t {
                                                             
    PointerBitMask =
        ~(uintptr_t)(((intptr_t)1 << PtrTraits::NumLowBitsAvailable) - 1),

                                                                             
                  
    IntShift = (uintptr_t)PtrTraits::NumLowBitsAvailable - IntBits,

                                                                            
    IntMask = (uintptr_t)(((intptr_t)1 << IntBits) - 1),

                                                                          
    ShiftedIntMask = (uintptr_t)(IntMask << IntShift)
  };

  static PointerT getPointer(intptr_t Value) {
    return PtrTraits::getFromVoidPointer(
        reinterpret_cast<void *>(Value & PointerBitMask));
  }

  static intptr_t getInt(intptr_t Value) {
    return (Value >> IntShift) & IntMask;
  }

  static intptr_t updatePointer(intptr_t OrigValue, PointerT Ptr) {
    intptr_t PtrWord =
        reinterpret_cast<intptr_t>(PtrTraits::getAsVoidPointer(Ptr));
    assert((PtrWord & ~PointerBitMask) == 0 &&
           "Pointer is not sufficiently aligned");
                                                      
    return PtrWord | (OrigValue & ~PointerBitMask);
  }

  static intptr_t updateInt(intptr_t OrigValue, intptr_t Int) {
    intptr_t IntWord = static_cast<intptr_t>(Int);
    assert((IntWord & ~IntMask) == 0 && "Integer too large for field");

                                                             
    return (OrigValue & ~ShiftedIntMask) | IntWord << IntShift;
  }
};

template <typename T> struct isPodLike;
template <typename PointerTy, unsigned IntBits, typename IntType>
struct isPodLike<PointerIntPair<PointerTy, IntBits, IntType>> {
  static const bool value = true;
};

                                                             
template <typename PointerTy, unsigned IntBits, typename IntType>
struct DenseMapInfo<PointerIntPair<PointerTy, IntBits, IntType>> {
  using Ty = PointerIntPair<PointerTy, IntBits, IntType>;

  static Ty getEmptyKey() {
    uintptr_t Val = static_cast<uintptr_t>(-1);
    Val <<= PointerLikeTypeTraits<Ty>::NumLowBitsAvailable;
    return Ty::getFromOpaqueValue(reinterpret_cast<void *>(Val));
  }

  static Ty getTombstoneKey() {
    uintptr_t Val = static_cast<uintptr_t>(-2);
    Val <<= PointerLikeTypeTraits<PointerTy>::NumLowBitsAvailable;
    return Ty::getFromOpaqueValue(reinterpret_cast<void *>(Val));
  }

  static unsigned getHashValue(Ty V) {
    uintptr_t IV = reinterpret_cast<uintptr_t>(V.getOpaqueValue());
    return unsigned(IV) ^ unsigned(IV >> 9);
  }

  static bool isEqual(const Ty &LHS, const Ty &RHS) { return LHS == RHS; }
};

                                                                  
template <typename PointerTy, unsigned IntBits, typename IntType,
          typename PtrTraits>
struct PointerLikeTypeTraits<
    PointerIntPair<PointerTy, IntBits, IntType, PtrTraits>> {
  static inline void *
  getAsVoidPointer(const PointerIntPair<PointerTy, IntBits, IntType> &P) {
    return P.getOpaqueValue();
  }

  static inline PointerIntPair<PointerTy, IntBits, IntType>
  getFromVoidPointer(void *P) {
    return PointerIntPair<PointerTy, IntBits, IntType>::getFromOpaqueValue(P);
  }

  static inline PointerIntPair<PointerTy, IntBits, IntType>
  getFromVoidPointer(const void *P) {
    return PointerIntPair<PointerTy, IntBits, IntType>::getFromOpaqueValue(P);
  }

  enum { NumLowBitsAvailable = PtrTraits::NumLowBitsAvailable - IntBits };
};

}                      

#endif                             

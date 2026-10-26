//===- llvm/ADT/PointerEmbeddedInt.h ----------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_POINTEREMBEDDEDINT_H
#define LLVM_ADT_POINTEREMBEDDEDINT_H

#include "llvh/ADT/DenseMapInfo.h"
#include "llvh/Support/MathExtras.h"
#include "llvh/Support/PointerLikeTypeTraits.h"
#include <cassert>
#include <climits>
#include <cstdint>
#include <type_traits>

namespace llvh {

                                                                              
                                                                           
                                                                             
                                                                         
                                      
   
                                                                              
                                                                               
                                                                           
                                                                     
template <typename IntT, int Bits = sizeof(IntT) * CHAR_BIT>
class PointerEmbeddedInt {
  uintptr_t Value = 0;

                                                                      
                                     
  static_assert(Bits < sizeof(uintptr_t) * CHAR_BIT,
                "Cannot embed more bits than we have in a pointer!");

  enum : uintptr_t {
                                                                           
                                              
    Shift = sizeof(uintptr_t) * CHAR_BIT - Bits,

                                                                          
    Mask = static_cast<uintptr_t>(-1) << Bits
  };

  struct RawValueTag {
    explicit RawValueTag() = default;
  };

  friend struct PointerLikeTypeTraits<PointerEmbeddedInt>;

  explicit PointerEmbeddedInt(uintptr_t Value, RawValueTag) : Value(Value) {}

public:
  PointerEmbeddedInt() = default;

  PointerEmbeddedInt(IntT I) { *this = I; }

  PointerEmbeddedInt &operator=(IntT I) {
    assert((std::is_signed<IntT>::value ? isInt<Bits>(I) : isUInt<Bits>(I)) &&
           "Integer has bits outside those preserved!");
    Value = static_cast<uintptr_t>(I) << Shift;
    return *this;
  }

                                                                            
                                                     
  operator IntT() const {
    if (std::is_signed<IntT>::value)
      return static_cast<IntT>(static_cast<intptr_t>(Value) >> Shift);
    return static_cast<IntT>(Value >> Shift);
  }
};

                                                                         
         
template <typename IntT, int Bits>
struct PointerLikeTypeTraits<PointerEmbeddedInt<IntT, Bits>> {
  using T = PointerEmbeddedInt<IntT, Bits>;

  static inline void *getAsVoidPointer(const T &P) {
    return reinterpret_cast<void *>(P.Value);
  }

  static inline T getFromVoidPointer(void *P) {
    return T(reinterpret_cast<uintptr_t>(P), typename T::RawValueTag());
  }

  static inline T getFromVoidPointer(const void *P) {
    return T(reinterpret_cast<uintptr_t>(P), typename T::RawValueTag());
  }

  enum { NumLowBitsAvailable = T::Shift };
};

                                                                               
                       
template <typename IntT, int Bits>
struct DenseMapInfo<PointerEmbeddedInt<IntT, Bits>> {
  using T = PointerEmbeddedInt<IntT, Bits>;
  using IntInfo = DenseMapInfo<IntT>;

  static inline T getEmptyKey() { return IntInfo::getEmptyKey(); }
  static inline T getTombstoneKey() { return IntInfo::getTombstoneKey(); }

  static unsigned getHashValue(const T &Arg) {
    return IntInfo::getHashValue(Arg);
  }

  static bool isEqual(const T &LHS, const T &RHS) { return LHS == RHS; }
};

}                      

#endif                                 

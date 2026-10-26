//===-- llvm/ADT/BitmaskEnum.h ----------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_BITMASKENUM_H
#define LLVM_ADT_BITMASKENUM_H

#include <cassert>
#include <type_traits>
#include <utility>

#include "llvh/Support/MathExtras.h"

                                                                                
                                                                            
   
         
                   
                                       
                                                          
        
   
                  
                                                                     
       
            
   
                                                                              
                                                                              
                                                                         
                                                                         
   
                                                                               
                       
   
                                                  
#define LLVM_MARK_AS_BITMASK_ENUM(LargestValue)                                \
  LLVM_BITMASK_LARGEST_ENUMERATOR = LargestValue

                                                                              
                                                            
   
                                                            
                                                     
                                                                              
                                                                                
           
   
                                                                               
                 
#define LLVM_ENABLE_BITMASK_ENUMS_IN_NAMESPACE()                               \
  using ::llvh::BitmaskEnumDetail::operator~;                                  \
  using ::llvh::BitmaskEnumDetail::operator|;                                  \
  using ::llvh::BitmaskEnumDetail::operator&;                                  \
  using ::llvh::BitmaskEnumDetail::operator^;                                  \
  using ::llvh::BitmaskEnumDetail::operator|=;                                 \
  using ::llvh::BitmaskEnumDetail::operator&=;                                 \
                                                                               \
  using ::llvh::BitmaskEnumDetail::operator^=

namespace llvh {

                                                   
                                               
template <typename E, typename Enable = void>
struct is_bitmask_enum : std::false_type {};

template <typename E>
struct is_bitmask_enum<
    E, typename std::enable_if<sizeof(E::LLVM_BITMASK_LARGEST_ENUMERATOR) >=
                               0>::type> : std::true_type {};
namespace BitmaskEnumDetail {

                                                                               
          
template <typename E> typename std::underlying_type<E>::type Mask() {
                                                                      
                                                                     
  return NextPowerOf2(static_cast<typename std::underlying_type<E>::type>(
             E::LLVM_BITMASK_LARGEST_ENUMERATOR)) -
         1;
}

                                                                           
         
template <typename E> typename std::underlying_type<E>::type Underlying(E Val) {
  auto U = static_cast<typename std::underlying_type<E>::type>(Val);
  assert(U >= 0 && "Negative enum values are not allowed.");
  assert(U <= Mask<E>() && "Enum value too large (or largest val too small?)");
  return U;
}

template <typename E,
          typename = typename std::enable_if<is_bitmask_enum<E>::value>::type>
E operator~(E Val) {
  return static_cast<E>(~Underlying(Val) & Mask<E>());
}

template <typename E,
          typename = typename std::enable_if<is_bitmask_enum<E>::value>::type>
E operator|(E LHS, E RHS) {
  return static_cast<E>(Underlying(LHS) | Underlying(RHS));
}

template <typename E,
          typename = typename std::enable_if<is_bitmask_enum<E>::value>::type>
E operator&(E LHS, E RHS) {
  return static_cast<E>(Underlying(LHS) & Underlying(RHS));
}

template <typename E,
          typename = typename std::enable_if<is_bitmask_enum<E>::value>::type>
E operator^(E LHS, E RHS) {
  return static_cast<E>(Underlying(LHS) ^ Underlying(RHS));
}

                                                                         
                              

template <typename E,
          typename = typename std::enable_if<is_bitmask_enum<E>::value>::type>
E &operator|=(E &LHS, E RHS) {
  LHS = LHS | RHS;
  return LHS;
}

template <typename E,
          typename = typename std::enable_if<is_bitmask_enum<E>::value>::type>
E &operator&=(E &LHS, E RHS) {
  LHS = LHS & RHS;
  return LHS;
}

template <typename E,
          typename = typename std::enable_if<is_bitmask_enum<E>::value>::type>
E &operator^=(E &LHS, E RHS) {
  LHS = LHS ^ RHS;
  return LHS;
}

}                               

                                                                      
LLVM_ENABLE_BITMASK_ENUMS_IN_NAMESPACE();

}                  

#endif

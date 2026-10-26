//===- llvm/ADT/PointerSumType.h --------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_POINTERSUMTYPE_H
#define LLVM_ADT_POINTERSUMTYPE_H

#include "llvh/ADT/bit.h"
#include "llvh/ADT/DenseMapInfo.h"
#include "llvh/Support/PointerLikeTypeTraits.h"
#include <cassert>
#include <cstdint>
#include <type_traits>

namespace llvh {

                                                                            
                                                                           
                                                                            
               
template <uintptr_t N, typename PointerArgT,
          typename TraitsArgT = PointerLikeTypeTraits<PointerArgT>>
struct PointerSumTypeMember {
  enum { Tag = N };
  using PointerT = PointerArgT;
  using TraitsT = TraitsArgT;
};

namespace detail {

template <typename TagT, typename... MemberTs> struct PointerSumTypeHelper;

}                        

                                       
   
                                                                             
                                          
   
                                                            
                                                                             
                                                                            
                                                                         
                                                                             
                                                                             
                                                             
   
                                                                            
                                                                         
                                                                     
   
                                                                               
                                                                            
                                                                            
                      
   
                                                                            
                                                                         
                                                                            
                                                                             
                                                                                
                                                        
   
                                                                           
                                                                              
template <typename TagT, typename... MemberTs> class PointerSumType {
  using HelperT = detail::PointerSumTypeHelper<TagT, MemberTs...>;

                                                                                
                                                                                
                                                                         
                                                                                
                                                                              
                                                                          
                                                                            
                                                                                
                                             
  union StorageT {
                                                                            
                                                                               
                   
    StorageT() : Value(0) {}

    uintptr_t Value;

    typename HelperT::template Lookup<HelperT::MinTag>::PointerT MinTagPointer;
  };

  StorageT Storage;

public:
  constexpr PointerSumType() = default;

                                                              
  template <TagT N>
  void set(typename HelperT::template Lookup<N>::PointerT Pointer) {
    void *V = HelperT::template Lookup<N>::TraitsT::getAsVoidPointer(Pointer);
    assert((reinterpret_cast<uintptr_t>(V) & HelperT::TagMask) == 0 &&
           "Pointer is insufficiently aligned to store the discriminant!");
    Storage.Value = reinterpret_cast<uintptr_t>(V) | N;
  }

                                                                       
  template <TagT N>
  static PointerSumType
  create(typename HelperT::template Lookup<N>::PointerT Pointer) {
    PointerSumType Result;
    Result.set<N>(Pointer);
    return Result;
  }

                                                    
  void clear() { set<HelperT::MinTag>(nullptr); }

  TagT getTag() const {
    return static_cast<TagT>(getOpaqueValue() & HelperT::TagMask);
  }

  template <TagT N> bool is() const { return N == getTag(); }

  template <TagT N> typename HelperT::template Lookup<N>::PointerT get() const {
    void *P = is<N>() ? getVoidPtr() : nullptr;
    return HelperT::template Lookup<N>::TraitsT::getFromVoidPointer(P);
  }

  template <TagT N>
  typename HelperT::template Lookup<N>::PointerT cast() const {
    assert(is<N>() && "This instance has a different active member.");
    return HelperT::template Lookup<N>::TraitsT::getFromVoidPointer(
        getVoidPtr());
  }

                                                                         
                                                                               
                   
  typename HelperT::template Lookup<HelperT::MinTag>::PointerT const *
  getAddrOfZeroTagPointer() const {
    return const_cast<PointerSumType *>(this)->getAddrOfZeroTagPointer();
  }

                                                                         
                                                                               
                   
  typename HelperT::template Lookup<HelperT::MinTag>::PointerT *
  getAddrOfZeroTagPointer() {
    static_assert(HelperT::MinTag == 0, "Non-zero minimum tag value!");
    assert(is<HelperT::MinTag>() && "The active tag is not zero!");
                                                                           
    auto InitialPtr = get<HelperT::MinTag>();
                                                                               
                                                                             
             
    Storage.MinTagPointer = InitialPtr;
                                                                             
                                                           
    assert(InitialPtr == get<HelperT::MinTag>() &&
           "Switching to typed storage changed the pointer returned!");
                                                               
    return &Storage.MinTagPointer;
  }

  explicit operator bool() const {
    return getOpaqueValue() & HelperT::PointerMask;
  }
  bool operator==(const PointerSumType &R) const {
    return getOpaqueValue() == R.getOpaqueValue();
  }
  bool operator!=(const PointerSumType &R) const {
    return getOpaqueValue() != R.getOpaqueValue();
  }
  bool operator<(const PointerSumType &R) const {
    return getOpaqueValue() < R.getOpaqueValue();
  }
  bool operator>(const PointerSumType &R) const {
    return getOpaqueValue() > R.getOpaqueValue();
  }
  bool operator<=(const PointerSumType &R) const {
    return getOpaqueValue() <= R.getOpaqueValue();
  }
  bool operator>=(const PointerSumType &R) const {
    return getOpaqueValue() >= R.getOpaqueValue();
  }

  uintptr_t getOpaqueValue() const {
                                                                         
              
    return bit_cast<uintptr_t>(Storage);
  }

protected:
  void *getVoidPtr() const {
    return reinterpret_cast<void *>(getOpaqueValue() & HelperT::PointerMask);
  }
};

namespace detail {

                                                                          
                                                                             
                                                               
template <typename TagT, typename... MemberTs>
struct PointerSumTypeHelper : MemberTs... {
                                                                       
                                                                           
                                                                               
                                                                       
                
  template <TagT N, typename PointerT, typename TraitsT>
  static PointerSumTypeMember<N, PointerT, TraitsT>
  LookupOverload(PointerSumTypeMember<N, PointerT, TraitsT> *);
  template <TagT N> static void LookupOverload(...);
  template <TagT N> struct Lookup {
                                                                                
    using MemberT = decltype(
        LookupOverload<N>(static_cast<PointerSumTypeHelper *>(nullptr)));

                                      
    using PointerT = typename MemberT::PointerT;

                                     
    using TraitsT = typename MemberT::TraitsT;
  };

                                                                              
                                                                          
                                                           
  template <uintptr_t V, uintptr_t... Vs>
  struct Min : std::integral_constant<
                   uintptr_t, (V < Min<Vs...>::value ? V : Min<Vs...>::value)> {
  };
  template <uintptr_t V>
  struct Min<V> : std::integral_constant<uintptr_t, V> {};
  enum { NumTagBits = Min<MemberTs::TraitsT::NumLowBitsAvailable...>::value };

                                                                              
  constexpr static TagT MinTag =
      static_cast<TagT>(Min<MemberTs::Tag...>::value);
  enum : uint64_t {
    PointerMask = static_cast<uint64_t>(-1) << NumTagBits,
    TagMask = ~PointerMask
  };

                                                                     
            
  template <typename MemberT, typename... InnerMemberTs>
  struct Checker : Checker<InnerMemberTs...> {
    static_assert(MemberT::Tag < (1 << NumTagBits),
                  "This discriminant value requires too many bits!");
  };
  template <typename MemberT> struct Checker<MemberT> : std::true_type {
    static_assert(MemberT::Tag < (1 << NumTagBits),
                  "This discriminant value requires too many bits!");
  };
  static_assert(Checker<MemberTs...>::value,
                "Each member must pass the checker.");
};

}                        

                                                     
template <typename TagT, typename... MemberTs>
struct DenseMapInfo<PointerSumType<TagT, MemberTs...>> {
  using SumType = PointerSumType<TagT, MemberTs...>;
  using HelperT = detail::PointerSumTypeHelper<TagT, MemberTs...>;
  enum { SomeTag = HelperT::MinTag };
  using SomePointerT =
      typename HelperT::template Lookup<HelperT::MinTag>::PointerT;
  using SomePointerInfo = DenseMapInfo<SomePointerT>;

  static inline SumType getEmptyKey() {
    return SumType::create<SomeTag>(SomePointerInfo::getEmptyKey());
  }

  static inline SumType getTombstoneKey() {
    return SumType::create<SomeTag>(SomePointerInfo::getTombstoneKey());
  }

  static unsigned getHashValue(const SumType &Arg) {
    uintptr_t OpaqueValue = Arg.getOpaqueValue();
    return DenseMapInfo<uintptr_t>::getHashValue(OpaqueValue);
  }

  static bool isEqual(const SumType &LHS, const SumType &RHS) {
    return LHS == RHS;
  }
};

}                      

#endif                             

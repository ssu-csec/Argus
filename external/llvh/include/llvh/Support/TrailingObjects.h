//===--- TrailingObjects.h - Variable-length classes ------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This header defines support for implementing classes that have
/// some trailing object (or arrays of objects) appended to them. The
/// main purpose is to make it obvious where this idiom is being used,
/// and to make the usage more idiomatic and more difficult to get
/// wrong.
///
/// The TrailingObject template abstracts away the reinterpret_cast,
/// pointer arithmetic, and size calculations used for the allocation
/// and access of appended arrays of objects, and takes care that they
/// are all allocated at their required alignment. Additionally, it
/// ensures that the base type is final -- deriving from a class that
/// expects data appended immediately after it is typically not safe.
///
/// Users are expected to derive from this template, and provide
/// numTrailingObjects implementations for each trailing type except
/// the last, e.g. like this sample:
///
/// \code
/// class VarLengthObj : private TrailingObjects<VarLengthObj, int, double> {
///   friend TrailingObjects;
///
///   unsigned NumInts, NumDoubles;
///   size_t numTrailingObjects(OverloadToken<int>) const { return NumInts; }
///  };
/// \endcode
///
/// You can access the appended arrays via 'getTrailingObjects', and
/// determine the size needed for allocation via
/// 'additionalSizeToAlloc' and 'totalSizeToAlloc'.
///
/// All the methods implemented by this class are are intended for use
/// by the implementation of the class, not as part of its interface
/// (thus, private inheritance is suggested).
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_TRAILINGOBJECTS_H
#define LLVM_SUPPORT_TRAILINGOBJECTS_H

#include "llvh/Support/AlignOf.h"
#include "llvh/Support/Compiler.h"
#include "llvh/Support/MathExtras.h"
#include "llvh/Support/type_traits.h"
#include <new>
#include <type_traits>

namespace llvh {

namespace trailing_objects_internal {
                                                                           
            
template <typename First, typename... Rest> class AlignmentCalcHelper {
private:
  enum {
    FirstAlignment = alignof(First),
    RestAlignment = AlignmentCalcHelper<Rest...>::Alignment,
  };

public:
  enum {
    Alignment = FirstAlignment > RestAlignment ? FirstAlignment : RestAlignment
  };
};

template <typename First> class AlignmentCalcHelper<First> {
public:
  enum { Alignment = alignof(First) };
};

                                                
class TrailingObjectsBase {
protected:
                                                                       
                                                               
                                                                     
                                                          
                      
  template <typename T> struct OverloadToken {};
};

                                                                
                                                             
                                                                 
                                                                   
                  
template <int Align>
class TrailingObjectsAligner : public TrailingObjectsBase {};
template <>
class alignas(1) TrailingObjectsAligner<1> : public TrailingObjectsBase {};
template <>
class alignas(2) TrailingObjectsAligner<2> : public TrailingObjectsBase {};
template <>
class alignas(4) TrailingObjectsAligner<4> : public TrailingObjectsBase {};
template <>
class alignas(8) TrailingObjectsAligner<8> : public TrailingObjectsBase {};
template <>
class alignas(16) TrailingObjectsAligner<16> : public TrailingObjectsBase {
};
template <>
class alignas(32) TrailingObjectsAligner<32> : public TrailingObjectsBase {
};

                                                                  
                                    
                                         
template <typename Ty1, typename Ty2> struct ExtractSecondType {
  typedef Ty2 type;
};

                                                               
                                                                   
                                                                      
                                                        
                                                                      
                                                                 
                        

template <int Align, typename BaseTy, typename TopTrailingObj, typename PrevTy,
          typename... MoreTys>
class TrailingObjectsImpl {
                                                          
                                             
};

template <int Align, typename BaseTy, typename TopTrailingObj, typename PrevTy,
          typename NextTy, typename... MoreTys>
class TrailingObjectsImpl<Align, BaseTy, TopTrailingObj, PrevTy, NextTy,
                          MoreTys...>
    : public TrailingObjectsImpl<Align, BaseTy, TopTrailingObj, NextTy,
                                 MoreTys...> {

  typedef TrailingObjectsImpl<Align, BaseTy, TopTrailingObj, NextTy, MoreTys...>
      ParentType;

  struct RequiresRealignment {
    static const bool value = alignof(PrevTy) < alignof(NextTy);
  };

  static constexpr bool requiresRealignment() {
    return RequiresRealignment::value;
  }

protected:
                                                               
  using ParentType::getTrailingObjectsImpl;

                                                 
                                                                     
                                                                      
                                                          
                                                            
                                                                   
                                          
                                                                   
                                                          
  static const NextTy *
  getTrailingObjectsImpl(const BaseTy *Obj,
                         TrailingObjectsBase::OverloadToken<NextTy>) {
    auto *Ptr = TopTrailingObj::getTrailingObjectsImpl(
                    Obj, TrailingObjectsBase::OverloadToken<PrevTy>()) +
                TopTrailingObj::callNumTrailingObjects(
                    Obj, TrailingObjectsBase::OverloadToken<PrevTy>());

    if (requiresRealignment())
      return reinterpret_cast<const NextTy *>(
          llvh::alignAddr(Ptr, alignof(NextTy)));
    else
      return reinterpret_cast<const NextTy *>(Ptr);
  }

  static NextTy *
  getTrailingObjectsImpl(BaseTy *Obj,
                         TrailingObjectsBase::OverloadToken<NextTy>) {
    auto *Ptr = TopTrailingObj::getTrailingObjectsImpl(
                    Obj, TrailingObjectsBase::OverloadToken<PrevTy>()) +
                TopTrailingObj::callNumTrailingObjects(
                    Obj, TrailingObjectsBase::OverloadToken<PrevTy>());

    if (requiresRealignment())
      return reinterpret_cast<NextTy *>(llvh::alignAddr(Ptr, alignof(NextTy)));
    else
      return reinterpret_cast<NextTy *>(Ptr);
  }

                                                                     
                                                                  
                                                  
  static constexpr size_t additionalSizeToAllocImpl(
      size_t SizeSoFar, size_t Count1,
      typename ExtractSecondType<MoreTys, size_t>::type... MoreCounts) {
    return ParentType::additionalSizeToAllocImpl(
        (requiresRealignment() ? llvh::alignTo<alignof(NextTy)>(SizeSoFar)
                               : SizeSoFar) +
            sizeof(NextTy) * Count1,
        MoreCounts...);
  }
};

                                                                  
                                       
template <int Align, typename BaseTy, typename TopTrailingObj, typename PrevTy>
class TrailingObjectsImpl<Align, BaseTy, TopTrailingObj, PrevTy>
    : public TrailingObjectsAligner<Align> {
protected:
                                                                     
                                                                      
                                            
  static void getTrailingObjectsImpl();

  static constexpr size_t additionalSizeToAllocImpl(size_t SizeSoFar) {
    return SizeSoFar;
  }

  template <bool CheckAlignment> static void verifyTrailingObjectsAlignment() {}
};

}                                           

                                                                             

                                                        
                         
template <typename BaseTy, typename... TrailingTys>
class TrailingObjects : private trailing_objects_internal::TrailingObjectsImpl<
                            trailing_objects_internal::AlignmentCalcHelper<
                                TrailingTys...>::Alignment,
                            BaseTy, TrailingObjects<BaseTy, TrailingTys...>,
                            BaseTy, TrailingTys...> {

  template <int A, typename B, typename T, typename P, typename... M>
  friend class trailing_objects_internal::TrailingObjectsImpl;

  template <typename... Tys> class Foo {};

  typedef trailing_objects_internal::TrailingObjectsImpl<
      trailing_objects_internal::AlignmentCalcHelper<TrailingTys...>::Alignment,
      BaseTy, TrailingObjects<BaseTy, TrailingTys...>, BaseTy, TrailingTys...>
      ParentType;
  using TrailingObjectsBase = trailing_objects_internal::TrailingObjectsBase;

  using ParentType::getTrailingObjectsImpl;

                                                                     
                                                                
                                                                   
                                                       
  static void verifyTrailingObjectsAssertions() {
#ifdef LLVM_IS_FINAL
    static_assert(LLVM_IS_FINAL(BaseTy), "BaseTy must be final.");
#endif
  }

                                                                     
  static const BaseTy *
  getTrailingObjectsImpl(const BaseTy *Obj,
                         TrailingObjectsBase::OverloadToken<BaseTy>) {
    return Obj;
  }

  static BaseTy *
  getTrailingObjectsImpl(BaseTy *Obj,
                         TrailingObjectsBase::OverloadToken<BaseTy>) {
    return Obj;
  }

                                                                  
                                                                 
                                                                      
                                                                   
                                                     
                                                                    
                                  
  static size_t
  callNumTrailingObjects(const BaseTy *Obj,
                         TrailingObjectsBase::OverloadToken<BaseTy>) {
    return 1;
  }

  template <typename T>
  static size_t callNumTrailingObjects(const BaseTy *Obj,
                                       TrailingObjectsBase::OverloadToken<T>) {
    return Obj->numTrailingObjects(TrailingObjectsBase::OverloadToken<T>());
  }

public:
                                                   
#ifndef _MSC_VER
  using ParentType::OverloadToken;
#else
                                                                     
                 
  template <typename T>
  using OverloadToken = typename ParentType::template OverloadToken<T>;
#endif

                                                                      
                                                                       
                                                 
  template <typename T> const T *getTrailingObjects() const {
    verifyTrailingObjectsAssertions();
                                                                
                                               
    return this->getTrailingObjectsImpl(
        static_cast<const BaseTy *>(this),
        TrailingObjectsBase::OverloadToken<T>());
  }

                                                                      
                                                                       
                                                 
  template <typename T> T *getTrailingObjects() {
    verifyTrailingObjectsAssertions();
                                                                
                                               
    return this->getTrailingObjectsImpl(
        static_cast<BaseTy *>(this), TrailingObjectsBase::OverloadToken<T>());
  }

                                                              
                                                                       
                                                                       
                                                                    
                                                                   
                                                              
  template <typename... Tys>
  static constexpr typename std::enable_if<
      std::is_same<Foo<TrailingTys...>, Foo<Tys...>>::value, size_t>::type
  additionalSizeToAlloc(typename trailing_objects_internal::ExtractSecondType<
                        TrailingTys, size_t>::type... Counts) {
    return ParentType::additionalSizeToAllocImpl(0, Counts...);
  }

                                                                       
                                                       
                                                                          
             
  template <typename... Tys>
  static constexpr typename std::enable_if<
      std::is_same<Foo<TrailingTys...>, Foo<Tys...>>::value, size_t>::type
  totalSizeToAlloc(typename trailing_objects_internal::ExtractSecondType<
                   TrailingTys, size_t>::type... Counts) {
    return sizeof(BaseTy) + ParentType::additionalSizeToAllocImpl(0, Counts...);
  }

                                                                        
                                                                            
                                                                         
                               
     
                                           
     
                 
     
                                                                               
                                  
                                                                  
                                                         
     
              
  template <typename... Tys> struct FixedSizeStorage {
    template <size_t... Counts> struct with_counts {
      enum { Size = totalSizeToAlloc<Tys...>(Counts...) };
      typedef llvh::AlignedCharArray<alignof(BaseTy), Size> type;
    };
  };

                                                                            
  class FixedSizeStorageOwner {
  public:
    FixedSizeStorageOwner(BaseTy *p) : p(p) {}
    ~FixedSizeStorageOwner() {
      assert(p && "FixedSizeStorageOwner owns null?");
      p->~BaseTy();
    }

    BaseTy *get() { return p; }
    const BaseTy *get() const { return p; }

  private:
    FixedSizeStorageOwner(const FixedSizeStorageOwner &) = delete;
    FixedSizeStorageOwner(FixedSizeStorageOwner &&) = delete;
    FixedSizeStorageOwner &operator=(const FixedSizeStorageOwner &) = delete;
    FixedSizeStorageOwner &operator=(FixedSizeStorageOwner &&) = delete;

    BaseTy *const p;
  };
};

}                      

#endif

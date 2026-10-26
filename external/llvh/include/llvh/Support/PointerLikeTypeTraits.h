//===- llvm/Support/PointerLikeTypeTraits.h - Pointer Traits ----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the PointerLikeTypeTraits class.  This allows data
// structures to reason about pointers and other things that are pointer sized.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_POINTERLIKETYPETRAITS_H
#define LLVM_SUPPORT_POINTERLIKETYPETRAITS_H

#include "llvh/Support/DataTypes.h"
#include <assert.h>
#include <type_traits>

namespace llvh {

                                                                               
                                              
template <typename T> struct PointerLikeTypeTraits;

namespace detail {
                                                                        
template <size_t N>
struct ConstantLog2
    : std::integral_constant<size_t, ConstantLog2<N / 2>::value + 1> {};
template <> struct ConstantLog2<1> : std::integral_constant<size_t, 0> {};

                                                 
template <typename T, typename U = void> struct HasPointerLikeTypeTraits {
  static const bool value = false;
};

                                            
template <typename T> struct HasPointerLikeTypeTraits<
  T, decltype((sizeof(PointerLikeTypeTraits<T>) + sizeof(T)), void())> {
  static const bool value = true;
};

template <typename T> struct IsPointerLike {
  static const bool value = HasPointerLikeTypeTraits<T>::value;
};

template <typename T> struct IsPointerLike<T *> {
  static const bool value = true;
};
}                    

                                                      
template <typename T> struct PointerLikeTypeTraits<T *> {
  static inline void *getAsVoidPointer(T *P) { return P; }
  static inline T *getFromVoidPointer(void *P) { return static_cast<T *>(P); }

  enum { NumLowBitsAvailable = detail::ConstantLog2<alignof(T)>::value };
};

template <> struct PointerLikeTypeTraits<void *> {
  static inline void *getAsVoidPointer(void *P) { return P; }
  static inline void *getFromVoidPointer(void *P) { return P; }

                                                                            
                                                                               
                                                                               
                                                                     
     
                                                                             
                            
  enum { NumLowBitsAvailable = 2 };
};

                                                  
template <typename T> struct PointerLikeTypeTraits<const T> {
  typedef PointerLikeTypeTraits<T> NonConst;

  static inline const void *getAsVoidPointer(const T P) {
    return NonConst::getAsVoidPointer(P);
  }
  static inline const T getFromVoidPointer(const void *P) {
    return NonConst::getFromVoidPointer(const_cast<void *>(P));
  }
  enum { NumLowBitsAvailable = NonConst::NumLowBitsAvailable };
};

                                                    
template <typename T> struct PointerLikeTypeTraits<const T *> {
  typedef PointerLikeTypeTraits<T *> NonConst;

  static inline const void *getAsVoidPointer(const T *P) {
    return NonConst::getAsVoidPointer(const_cast<T *>(P));
  }
  static inline const T *getFromVoidPointer(const void *P) {
    return NonConst::getFromVoidPointer(const_cast<void *>(P));
  }
  enum { NumLowBitsAvailable = NonConst::NumLowBitsAvailable };
};

                                               
template <> struct PointerLikeTypeTraits<uintptr_t> {
  static inline void *getAsVoidPointer(uintptr_t P) {
    return reinterpret_cast<void *>(P);
  }
  static inline uintptr_t getFromVoidPointer(void *P) {
    return reinterpret_cast<uintptr_t>(P);
  }
                           
  enum { NumLowBitsAvailable = 0 };
};

                                                                
   
                                                                             
                                                                               
   
                                                                        
                                                                          
                                                                      
template <int Alignment, typename FunctionPointerT>
struct FunctionPointerLikeTypeTraits {
  enum { NumLowBitsAvailable = detail::ConstantLog2<Alignment>::value };
  static inline void *getAsVoidPointer(FunctionPointerT P) {
    assert((reinterpret_cast<uintptr_t>(P) &
            ~((uintptr_t)-1 << NumLowBitsAvailable)) == 0 &&
           "Alignment not satisfied for an actual function pointer!");
    return reinterpret_cast<void *>(P);
  }
  static inline FunctionPointerT getFromVoidPointer(void *P) {
    return reinterpret_cast<FunctionPointerT>(P);
  }
};

                                                                              
              
   
                                                                           
                                                                                
                                                                                
                                        
template <typename ReturnT, typename... ParamTs>
struct PointerLikeTypeTraits<ReturnT (*)(ParamTs...)>
    : FunctionPointerLikeTypeTraits<4, ReturnT (*)(ParamTs...)> {};

}                      

#endif

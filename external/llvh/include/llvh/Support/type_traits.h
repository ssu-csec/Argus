//===- llvm/Support/type_traits.h - Simplfied type traits -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides useful additions to the standard type_traits library.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_TYPE_TRAITS_H
#define LLVM_SUPPORT_TYPE_TRAITS_H

#include "llvh/Support/Compiler.h"
#include <type_traits>
#include <utility>

#ifndef __has_feature
#define LLVM_DEFINED_HAS_FEATURE
#define __has_feature(x) 0
#endif

namespace llvh {

                                                                              
                                                                       
template <typename T>
struct isPodLike {
                                                                            
                           
#if (__has_feature(is_trivially_copyable) && defined(_LIBCPP_VERSION)) ||      \
    (defined(__GNUC__) && __GNUC__ >= 5)
                                                                           
                                                 
  static const bool value = std::is_trivially_copyable<T>::value;
#elif __has_feature(is_trivially_copyable)
                                                                                
                                                                           
                                             
  static const bool value = __is_trivially_copyable(T);
#else
                                                                                
                    
  static const bool value = !std::is_class<T>::value;
#endif
};

                                                  
template<typename T, typename U>
struct isPodLike<std::pair<T, U>> {
  static const bool value = isPodLike<T>::value && isPodLike<U>::value;
};

                                                                    
                                                                 
   
                                                                           
                                                                            
                                                                                
                                                                              
template <typename T> class is_integral_or_enum {
  using UnderlyingT = typename std::remove_reference<T>::type;

public:
  static const bool value =
      !std::is_class<UnderlyingT>::value &&                                
      !std::is_pointer<UnderlyingT>::value &&
      !std::is_floating_point<UnderlyingT>::value &&
      (std::is_enum<UnderlyingT>::value ||
       std::is_convertible<UnderlyingT, unsigned long long>::value);
};

                                                               
template<typename T, typename Enable = void>
struct add_lvalue_reference_if_not_pointer { using type = T &; };

template <typename T>
struct add_lvalue_reference_if_not_pointer<
    T, typename std::enable_if<std::is_pointer<T>::value>::type> {
  using type = T;
};

                                                                      
                   
template<typename T, typename Enable = void>
struct add_const_past_pointer { using type = const T; };

template <typename T>
struct add_const_past_pointer<
    T, typename std::enable_if<std::is_pointer<T>::value>::type> {
  using type = const typename std::remove_pointer<T>::type *;
};

template <typename T, typename Enable = void>
struct const_pointer_or_const_ref {
  using type = const T &;
};
template <typename T>
struct const_pointer_or_const_ref<
    T, typename std::enable_if<std::is_pointer<T>::value>::type> {
  using type = typename add_const_past_pointer<T>::type;
};

namespace detail {
                                                         
template<typename T> union copy_construction_triviality_helper {
    T t;
    copy_construction_triviality_helper() = default;
    copy_construction_triviality_helper(const copy_construction_triviality_helper&) = default;
    ~copy_construction_triviality_helper() = default;
};
                                                         
template<typename T> union move_construction_triviality_helper {
    T t;
    move_construction_triviality_helper() = default;
    move_construction_triviality_helper(move_construction_triviality_helper&&) = default;
    ~move_construction_triviality_helper() = default;
};
}                        

                                                                             
                                              
template <typename T>
struct is_trivially_copy_constructible
    : std::is_copy_constructible<
          ::llvh::detail::copy_construction_triviality_helper<T>> {};
template <typename T>
struct is_trivially_copy_constructible<T &> : std::true_type {};
template <typename T>
struct is_trivially_copy_constructible<T &&> : std::false_type {};

                                                                             
                                              
template <typename T>
struct is_trivially_move_constructible
    : std::is_move_constructible<
          ::llvh::detail::move_construction_triviality_helper<T>> {};
template <typename T>
struct is_trivially_move_constructible<T &> : std::true_type {};
template <typename T>
struct is_trivially_move_constructible<T &&> : std::true_type {};

}                      

                                                                      
                                                                 
                                
#if __cplusplus >= 201402L || defined(_MSC_VER)
#define LLVM_IS_FINAL(Ty) std::is_final<Ty>()
#elif __has_feature(is_final) || LLVM_GNUC_PREREQ(4, 7, 0)
#define LLVM_IS_FINAL(Ty) __is_final(Ty)
#endif

#ifdef LLVM_DEFINED_HAS_FEATURE
#undef __has_feature
#endif

#endif                              

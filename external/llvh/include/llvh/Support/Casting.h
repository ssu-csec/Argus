//===- llvm/Support/Casting.h - Allow flexible, checked, casts --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the isa<X>(), cast<X>(), dyn_cast<X>(), cast_or_null<X>(),
// and dyn_cast_or_null<X>() templates.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_CASTING_H
#define LLVM_SUPPORT_CASTING_H

#include "llvh/Support/Compiler.h"
#include "llvh/Support/type_traits.h"
#include <cassert>
#include <memory>
#include <type_traits>

namespace llvh {

                                                                                
                                                    
                                                                                

                                                                             
                                                                               
                                                                       
  
template<typename From> struct simplify_type {
  using SimpleType = From;                                    

                                         
  static SimpleType &getSimplifiedValue(From &Val) { return Val; }
};

template<typename From> struct simplify_type<const From> {
  using NonConstSimpleType = typename simplify_type<From>::SimpleType;
  using SimpleType =
      typename add_const_past_pointer<NonConstSimpleType>::type;
  using RetType =
      typename add_lvalue_reference_if_not_pointer<SimpleType>::type;

  static RetType getSimplifiedValue(const From& Val) {
    return simplify_type<From>::getSimplifiedValue(const_cast<From&>(Val));
  }
};

                                                                          
                                                                           
                                                             
template <typename To, typename From, typename Enabler = void>
struct isa_impl {
  static inline bool doit(const From &Val) {
    return To::classof(&Val);
  }
};

                                                                
template <typename To, typename From>
struct isa_impl<
    To, From, typename std::enable_if<std::is_base_of<To, From>::value>::type> {
  static inline bool doit(const From &) { return true; }
};

template <typename To, typename From> struct isa_impl_cl {
  static inline bool doit(const From &Val) {
    return isa_impl<To, From>::doit(Val);
  }
};

template <typename To, typename From> struct isa_impl_cl<To, const From> {
  static inline bool doit(const From &Val) {
    return isa_impl<To, From>::doit(Val);
  }
};

template <typename To, typename From>
struct isa_impl_cl<To, const std::unique_ptr<From>> {
  static inline bool doit(const std::unique_ptr<From> &Val) {
    assert(Val && "isa<> used on a null pointer");
    return isa_impl_cl<To, From>::doit(*Val);
  }
};

template <typename To, typename From> struct isa_impl_cl<To, From*> {
  static inline bool doit(const From *Val) {
    assert(Val && "isa<> used on a null pointer");
    return isa_impl<To, From>::doit(*Val);
  }
};

template <typename To, typename From> struct isa_impl_cl<To, From*const> {
  static inline bool doit(const From *Val) {
    assert(Val && "isa<> used on a null pointer");
    return isa_impl<To, From>::doit(*Val);
  }
};

template <typename To, typename From> struct isa_impl_cl<To, const From*> {
  static inline bool doit(const From *Val) {
    assert(Val && "isa<> used on a null pointer");
    return isa_impl<To, From>::doit(*Val);
  }
};

template <typename To, typename From> struct isa_impl_cl<To, const From*const> {
  static inline bool doit(const From *Val) {
    assert(Val && "isa<> used on a null pointer");
    return isa_impl<To, From>::doit(*Val);
  }
};

template<typename To, typename From, typename SimpleFrom>
struct isa_impl_wrap {
                                                                             
                                
  static bool doit(const From &Val) {
    return isa_impl_wrap<To, SimpleFrom,
      typename simplify_type<SimpleFrom>::SimpleType>::doit(
                          simplify_type<const From>::getSimplifiedValue(Val));
  }
};

template<typename To, typename FromTy>
struct isa_impl_wrap<To, FromTy, FromTy> {
                                                                      
  static bool doit(const FromTy &Val) {
    return isa_impl_cl<To,FromTy>::doit(Val);
  }
};

                                                                              
                                           
  
                                 
  
template <class X, class Y> LLVM_NODISCARD inline bool isa(const Y &Val) {
  return isa_impl_wrap<X, const Y,
                       typename simplify_type<const Y>::SimpleType>::doit(Val);
}

                                                                                
                                                     
                                                                                

template<class To, class From> struct cast_retty;

                                                                              
                                        
template<class To, class From> struct cast_retty_impl {
  using ret_type = To &;                                 
};
template<class To, class From> struct cast_retty_impl<To, const From> {
  using ret_type = const To &;                           
};

template<class To, class From> struct cast_retty_impl<To, From*> {
  using ret_type = To *;                                      
};

template<class To, class From> struct cast_retty_impl<To, const From*> {
  using ret_type = const To *;                                               
};

template<class To, class From> struct cast_retty_impl<To, const From*const> {
  using ret_type = const To *;                                               
};

template <class To, class From>
struct cast_retty_impl<To, std::unique_ptr<From>> {
private:
  using PointerType = typename cast_retty_impl<To, From *>::ret_type;
  using ResultType = typename std::remove_pointer<PointerType>::type;

public:
  using ret_type = std::unique_ptr<ResultType>;
};

template<class To, class From, class SimpleFrom>
struct cast_retty_wrap {
                                                                              
                                                                         
                    
  using ret_type = typename cast_retty<To, SimpleFrom>::ret_type;
};

template<class To, class FromTy>
struct cast_retty_wrap<To, FromTy, FromTy> {
                                                                         
  using ret_type = typename cast_retty_impl<To,FromTy>::ret_type;
};

template<class To, class From>
struct cast_retty {
  using ret_type = typename cast_retty_wrap<
      To, From, typename simplify_type<From>::SimpleType>::ret_type;
};

                                                                              
                                               
  
template<class To, class From, class SimpleFrom> struct cast_convert_val {
                                                                  
  static typename cast_retty<To, From>::ret_type doit(From &Val) {
    return cast_convert_val<To, SimpleFrom,
      typename simplify_type<SimpleFrom>::SimpleType>::doit(
                          simplify_type<From>::getSimplifiedValue(Val));
  }
};

template<class To, class FromTy> struct cast_convert_val<To,FromTy,FromTy> {
                                           
  static typename cast_retty<To, FromTy>::ret_type doit(const FromTy &Val) {
    typename cast_retty<To, FromTy>::ret_type Res2
     = (typename cast_retty<To, FromTy>::ret_type)const_cast<FromTy&>(Val);
    return Res2;
  }
};

template <class X> struct is_simple_type {
  static const bool value =
      std::is_same<X, typename simplify_type<X>::SimpleType>::value;
};

                                                                            
                                                                                
                                                                              
                                  
  
                                         
  
template <class X, class Y>
inline typename std::enable_if<!is_simple_type<Y>::value,
                               typename cast_retty<X, const Y>::ret_type>::type
cast(const Y &Val) {
  assert(isa<X>(Val) && "cast<Ty>() argument of incompatible type!");
  return cast_convert_val<
      X, const Y, typename simplify_type<const Y>::SimpleType>::doit(Val);
}

template <class X, class Y>
inline typename cast_retty<X, Y>::ret_type cast(Y &Val) {
  assert(isa<X>(Val) && "cast<Ty>() argument of incompatible type!");
  return cast_convert_val<X, Y,
                          typename simplify_type<Y>::SimpleType>::doit(Val);
}

template <class X, class Y>
inline typename cast_retty<X, Y *>::ret_type cast(Y *Val) {
  assert(isa<X>(Val) && "cast<Ty>() argument of incompatible type!");
  return cast_convert_val<X, Y*,
                          typename simplify_type<Y*>::SimpleType>::doit(Val);
}

template <class X, class Y>
inline typename cast_retty<X, std::unique_ptr<Y>>::ret_type
cast(std::unique_ptr<Y> &&Val) {
  assert(isa<X>(Val.get()) && "cast<Ty>() argument of incompatible type!");
  using ret_type = typename cast_retty<X, std::unique_ptr<Y>>::ret_type;
  return ret_type(
      cast_convert_val<X, Y *, typename simplify_type<Y *>::SimpleType>::doit(
          Val.release()));
}

                                                                                
            
  
template <class X, class Y>
LLVM_NODISCARD inline
    typename std::enable_if<!is_simple_type<Y>::value,
                            typename cast_retty<X, const Y>::ret_type>::type
    cast_or_null(const Y &Val) {
  if (!Val)
    return nullptr;
  assert(isa<X>(Val) && "cast_or_null<Ty>() argument of incompatible type!");
  return cast<X>(Val);
}

template <class X, class Y>
LLVM_NODISCARD inline
    typename std::enable_if<!is_simple_type<Y>::value,
                            typename cast_retty<X, Y>::ret_type>::type
    cast_or_null(Y &Val) {
  if (!Val)
    return nullptr;
  assert(isa<X>(Val) && "cast_or_null<Ty>() argument of incompatible type!");
  return cast<X>(Val);
}

template <class X, class Y>
LLVM_NODISCARD inline typename cast_retty<X, Y *>::ret_type
cast_or_null(Y *Val) {
  if (!Val) return nullptr;
  assert(isa<X>(Val) && "cast_or_null<Ty>() argument of incompatible type!");
  return cast<X>(Val);
}

template <class X, class Y>
inline typename cast_retty<X, std::unique_ptr<Y>>::ret_type
cast_or_null(std::unique_ptr<Y> &&Val) {
  if (!Val)
    return nullptr;
  return cast<X>(std::move(Val));
}

                                                                                
                                                                                
                                                                            
                                                    
  
                                                                    
  

template <class X, class Y>
LLVM_NODISCARD inline
    typename std::enable_if<!is_simple_type<Y>::value,
                            typename cast_retty<X, const Y>::ret_type>::type
    dyn_cast(const Y &Val) {
  return isa<X>(Val) ? cast<X>(Val) : nullptr;
}

template <class X, class Y>
LLVM_NODISCARD inline typename cast_retty<X, Y>::ret_type dyn_cast(Y &Val) {
  return isa<X>(Val) ? cast<X>(Val) : nullptr;
}

template <class X, class Y>
LLVM_NODISCARD inline typename cast_retty<X, Y *>::ret_type dyn_cast(Y *Val) {
  return isa<X>(Val) ? cast<X>(Val) : nullptr;
}

                                                                               
                     
  
template <class X, class Y>
LLVM_NODISCARD inline
    typename std::enable_if<!is_simple_type<Y>::value,
                            typename cast_retty<X, const Y>::ret_type>::type
    dyn_cast_or_null(const Y &Val) {
  return (Val && isa<X>(Val)) ? cast<X>(Val) : nullptr;
}

template <class X, class Y>
LLVM_NODISCARD inline
    typename std::enable_if<!is_simple_type<Y>::value,
                            typename cast_retty<X, Y>::ret_type>::type
    dyn_cast_or_null(Y &Val) {
  return (Val && isa<X>(Val)) ? cast<X>(Val) : nullptr;
}

template <class X, class Y>
LLVM_NODISCARD inline typename cast_retty<X, Y *>::ret_type
dyn_cast_or_null(Y *Val) {
  return (Val && isa<X>(Val)) ? cast<X>(Val) : nullptr;
}

                                                                             
                                                                         
                                                                          
                                                                          
                         
template <class X, class Y>
LLVM_NODISCARD inline auto unique_dyn_cast(std::unique_ptr<Y> &Val)
    -> decltype(cast<X>(Val)) {
  if (!isa<X>(Val))
    return nullptr;
  return cast<X>(std::move(Val));
}

template <class X, class Y>
LLVM_NODISCARD inline auto unique_dyn_cast(std::unique_ptr<Y> &&Val)
    -> decltype(cast<X>(Val)) {
  return unique_dyn_cast<X, Y>(Val);
}

                                                                               
                            
template <class X, class Y>
LLVM_NODISCARD inline auto unique_dyn_cast_or_null(std::unique_ptr<Y> &Val)
    -> decltype(cast<X>(Val)) {
  if (!Val)
    return nullptr;
  return unique_dyn_cast<X, Y>(Val);
}

template <class X, class Y>
LLVM_NODISCARD inline auto unique_dyn_cast_or_null(std::unique_ptr<Y> &&Val)
    -> decltype(cast<X>(Val)) {
  return unique_dyn_cast_or_null<X, Y>(Val);
}

}                      

#endif                          

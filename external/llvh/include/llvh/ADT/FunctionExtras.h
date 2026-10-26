//===- FunctionExtras.h - Function type erasure utilities -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
/// \file
/// This file provides a collection of function (or more generally, callable)
/// type erasure utilities supplementing those provided by the standard library
/// in `<function>`.
///
/// It provides `unique_function`, which works like `std::function` but supports
/// move-only callable objects.
///
/// Future plans:
/// - Add a `function` that provides const, volatile, and ref-qualified support,
///   which doesn't work with `std::function`.
/// - Provide support for specifying multiple signatures to type erase callable
///   objects with an overload set, such as those produced by generic lambdas.
/// - Expand to include a copyable utility that directly replaces std::function
///   but brings the above improvements.
///
/// Note that LLVM's utilities are greatly simplified by not supporting
/// allocators.
///
/// If the standard library ever begins to provide comparable facilities we can
/// consider switching to those.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_FUNCTION_EXTRAS_H
#define LLVM_ADT_FUNCTION_EXTRAS_H

#include "llvh/ADT/PointerIntPair.h"
#include "llvh/ADT/PointerUnion.h"
#include "llvh/Support/type_traits.h"
#include <memory>

namespace llvh {

template <typename FunctionT> class unique_function;

template <typename ReturnT, typename... ParamTs>
class unique_function<ReturnT(ParamTs...)> {
  static constexpr size_t InlineStorageSize = sizeof(void *) * 3;

                                                                       
                                                                             
                                                           
  template <typename T> struct IsSizeLessThanThresholdT {
    static constexpr bool value = sizeof(T) <= (2 * sizeof(void *));
  };

                                                                              
                                                                             
                                                                               
                                                                              
                                                           
    
                                                                              
                                                                         
                                                                          
  template <typename T>
  using AdjustedParamT = typename std::conditional<
      !std::is_reference<T>::value &&
          llvh::is_trivially_copy_constructible<T>::value &&
          llvh::is_trivially_move_constructible<T>::value &&
          IsSizeLessThanThresholdT<T>::value,
      T, T &>::type;

                                                                                
                                                                
  using CallPtrT = ReturnT (*)(void *CallableAddr,
                               AdjustedParamT<ParamTs>... Params);
  using MovePtrT = void (*)(void *LHSCallableAddr, void *RHSCallableAddr);
  using DestroyPtrT = void (*)(void *CallableAddr);

                                                                              
                     
  struct alignas(8) TrivialCallback {
    CallPtrT CallPtr;
  };

                                                                           
                 
  struct alignas(8) NonTrivialCallbacks {
    CallPtrT CallPtr;
    MovePtrT MovePtr;
    DestroyPtrT DestroyPtr;
  };

                                                                             
                                                                               
                      
  using CallbackPointerUnionT =
      PointerUnion<TrivialCallback *, NonTrivialCallbacks *>;

                                                                            
                                                      
  union StorageUnionT {
                                                                              
                                                         
    struct OutOfLineStorageT {
      void *StoragePtr;
      size_t Size;
      size_t Alignment;
    } OutOfLineStorage;
    static_assert(
        sizeof(OutOfLineStorageT) <= InlineStorageSize,
        "Should always use all of the out-of-line storage for inline storage!");

                                                                           
                                                    
    typename std::aligned_storage<InlineStorageSize, alignof(void *)>::type
        InlineStorage;
  } StorageUnion;

                                                                            
                                                                          
                          
  PointerIntPair<CallbackPointerUnionT, 1, bool> CallbackAndInlineFlag;

  bool isInlineStorage() const { return CallbackAndInlineFlag.getInt(); }

  bool isTrivialCallback() const {
    return CallbackAndInlineFlag.getPointer().template is<TrivialCallback *>();
  }

  CallPtrT getTrivialCallback() const {
    return CallbackAndInlineFlag.getPointer().template get<TrivialCallback *>()->CallPtr;
  }

  NonTrivialCallbacks *getNonTrivialCallbacks() const {
    return CallbackAndInlineFlag.getPointer()
        .template get<NonTrivialCallbacks *>();
  }

  void *getInlineStorage() { return &StorageUnion.InlineStorage; }

  void *getOutOfLineStorage() {
    return StorageUnion.OutOfLineStorage.StoragePtr;
  }
  size_t getOutOfLineStorageSize() const {
    return StorageUnion.OutOfLineStorage.Size;
  }
  size_t getOutOfLineStorageAlignment() const {
    return StorageUnion.OutOfLineStorage.Alignment;
  }

  void setOutOfLineStorage(void *Ptr, size_t Size, size_t Alignment) {
    StorageUnion.OutOfLineStorage = {Ptr, Size, Alignment};
  }

  template <typename CallableT>
  static ReturnT CallImpl(void *CallableAddr, AdjustedParamT<ParamTs>... Params) {
    return (*reinterpret_cast<CallableT *>(CallableAddr))(
        std::forward<ParamTs>(Params)...);
  }

  template <typename CallableT>
  static void MoveImpl(void *LHSCallableAddr, void *RHSCallableAddr) noexcept {
    new (LHSCallableAddr)
        CallableT(std::move(*reinterpret_cast<CallableT *>(RHSCallableAddr)));
  }

  template <typename CallableT>
  static void DestroyImpl(void *CallableAddr) noexcept {
    reinterpret_cast<CallableT *>(CallableAddr)->~CallableT();
  }

public:
  unique_function() = default;
  unique_function(std::nullptr_t                  ) {}

  ~unique_function() {
    if (!CallbackAndInlineFlag.getPointer())
      return;

                                                                             
    bool IsInlineStorage = isInlineStorage();

    if (!isTrivialCallback())
      getNonTrivialCallbacks()->DestroyPtr(
          IsInlineStorage ? getInlineStorage() : getOutOfLineStorage());

    if (!IsInlineStorage)
      deallocate_buffer(getOutOfLineStorage(), getOutOfLineStorageSize(),
                        getOutOfLineStorageAlignment());
  }

  unique_function(unique_function &&RHS) noexcept {
                                         
    CallbackAndInlineFlag = RHS.CallbackAndInlineFlag;

                                                                 
    if (!RHS)
      return;

    if (!isInlineStorage()) {
                                                 
      StorageUnion.OutOfLineStorage = RHS.StorageUnion.OutOfLineStorage;
    } else if (isTrivialCallback()) {
                                                       
      memcpy(getInlineStorage(), RHS.getInlineStorage(), InlineStorageSize);
    } else {
                                                                       
      getNonTrivialCallbacks()->MovePtr(getInlineStorage(),
                                        RHS.getInlineStorage());
    }

                                                                        
    RHS.CallbackAndInlineFlag = {};

#ifndef NDEBUG
                                                                        
    memset(RHS.getInlineStorage(), 0xAD, InlineStorageSize);
#endif
  }

  unique_function &operator=(unique_function &&RHS) noexcept {
    if (this == &RHS)
      return *this;

                                                                             
                                                                            
                                                        
    this->~unique_function();
    new (this) unique_function(std::move(RHS));
    return *this;
  }

  template <typename CallableT> unique_function(CallableT Callable) {
    bool IsInlineStorage = true;
    void *CallableAddr = getInlineStorage();
    if (sizeof(CallableT) > InlineStorageSize ||
        alignof(CallableT) > alignof(decltype(StorageUnion.InlineStorage))) {
      IsInlineStorage = false;
                                                                       
                                 
      auto Size = sizeof(CallableT);
      auto Alignment = alignof(CallableT);
      CallableAddr = allocate_buffer(Size, Alignment);
      setOutOfLineStorage(CallableAddr, Size, Alignment);
    }

                                 
    new (CallableAddr) CallableT(std::move(Callable));

                                                                          
                                                                             
                                                  
      
                                                                              
                                                                               
                                         
    if (llvh::is_trivially_move_constructible<CallableT>::value &&
        std::is_trivially_destructible<CallableT>::value) {
                                                                            
                                                 
      static TrivialCallback Callback = { &CallImpl<CallableT> };

      CallbackAndInlineFlag = {&Callback, IsInlineStorage};
      return;
    }

                                                                               
                                                                                
                                           
    static NonTrivialCallbacks Callbacks = {
        &CallImpl<CallableT>, &MoveImpl<CallableT>, &DestroyImpl<CallableT>};

    CallbackAndInlineFlag = {&Callbacks, IsInlineStorage};
  }

  ReturnT operator()(ParamTs... Params) {
    void *CallableAddr =
        isInlineStorage() ? getInlineStorage() : getOutOfLineStorage();

    return (isTrivialCallback()
                ? getTrivialCallback()
                : getNonTrivialCallbacks()->CallPtr)(CallableAddr, Params...);
  }

  explicit operator bool() const {
    return (bool)CallbackAndInlineFlag.getPointer();
  }
};

}                      

#endif                       

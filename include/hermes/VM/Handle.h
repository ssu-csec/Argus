/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_HANDLE_H
#define HERMES_VM_HANDLE_H

#include "hermes/VM/Casting.h"
#include "hermes/VM/GCBase.h"
#include "hermes/VM/GCDecl.h"
#include "hermes/VM/GCPointer.h"
#include "hermes/VM/HermesValueTraits.h"
#include "llvh/Support/type_traits.h"

#include <algorithm>

namespace hermes {
namespace vm {

                        
class GCScope;
class HandleRootOwner;
template <typename T = HermesValue>
class Handle;
template <typename T = HermesValue>
class MutableHandle;
template <typename T>
class Handle;
template <typename T>
class MutableHandle;

                                                                              
                                                                               
                                                                         
                                                                               
                
   
                
         
                                                               
                              
                      
                                                            
                                                  
      
            
template <typename T = HermesValue>
class PseudoHandle {
  using traits_type = HermesValueTraits<T>;

 public:
  using value_type = typename traits_type::value_type;
  using arrow_type = typename traits_type::arrow_type;

 private:
  template <class U>
  friend class PseudoHandle;

  value_type value_;
#ifndef NDEBUG
  bool valid_{true};
#endif

  explicit PseudoHandle(value_type value) : value_(value) {}

 public:
  PseudoHandle(const PseudoHandle &) = delete;
  PseudoHandle &operator=(const PseudoHandle &) = delete;

#ifndef NDEBUG
  PseudoHandle(PseudoHandle &&hnd) : value_(hnd.value_), valid_(hnd.valid_) {
    hnd.valid_ = false;
  }
  PseudoHandle &operator=(PseudoHandle &&hnd) {
    value_ = std::move(hnd.value_);
    valid_ = hnd.valid_;
    hnd.valid_ = false;
    return *this;
  }
#else
  PseudoHandle(PseudoHandle &&) = default;
  PseudoHandle &operator=(PseudoHandle &&) = default;
#endif

  ~PseudoHandle() = default;

  constexpr PseudoHandle() : value_(traits_type::defaultValue()) {}
  PseudoHandle(Handle<T> handle) : value_(*handle) {}

                                                                               
              
  explicit PseudoHandle(PinnedHermesValue *pvalue) : value_(*pvalue) {
    static_assert(
        std::is_same<value_type, HermesValue>::value,
        "This constructor can only be used for PseudoHandle<HermesValue>");
  }

  PseudoHandle &operator=(Handle<T> handle) {
    value_ = *handle;
#ifndef NDEBUG
    valid_ = true;
#endif
    return *this;
  }

                                                    
  template <
      typename U,
      typename = typename std::enable_if<std::is_convertible<
          typename PseudoHandle<U>::value_type,
          typename PseudoHandle<T>::value_type>::value>::type>
                 PseudoHandle(PseudoHandle<U> &&other)
      : value_(static_cast<value_type>(other.get())) {
    other.invalidate();
  }

  void invalidate() {
#ifndef NDEBUG
    valid_ = false;
#endif
  }

  value_type get() const {
    assert(valid_ && "Pseudo handle has been invalidated");
    return value_;
  }

  arrow_type operator->() const {
    assert(valid_ && "Pseudo handle has been invalidated");
    return traits_type::arrow(value_);
  }

  explicit operator bool() const {
    assert(valid_ && "Pseudo handle has been invalidated");
    return value_ != nullptr;
  }

                                              
  HermesValue getHermesValue() const {
    assert(valid_ && "Pseudo handle has been invalidated");
    return traits_type::encode(value_);
  }

                                                                
                                                    
                                                                           
  value_type unsafeGetValue() const {
    return value_;
  }

                                            
  static PseudoHandle<T> create(value_type value) {
    return PseudoHandle<T>(value);
  }

  template <typename U>
  static inline PseudoHandle vmcast(PseudoHandle<U> &&other);

  template <typename U>
  static inline PseudoHandle dyn_vmcast(PseudoHandle<U> &&other);
};

                                                                              
                                                                            
                                             
                                                                           
                                                                          
                              
                                                                            
             
class HandleBase {
#ifndef NDEBUG
                                                                             
                                            
  GCScope *gcScope_;
#endif

                                                                             
                                                                     
  PinnedHermesValue *handle_;

 protected:
#ifndef NDEBUG
  HandleBase &operator=(const HandleBase &other);
#else
  HandleBase &operator=(const HandleBase &other) = default;
#endif

  PinnedHermesValue *&handleRef() {
#ifdef HERMES_SLOW_DEBUG
    assert(!handle_->isInvalid() && "Reading from flushed handle");
#endif
    return handle_;
  }
  const PinnedHermesValue *handleRef() const {
#ifdef HERMES_SLOW_DEBUG
    assert(!handle_->isInvalid() && "Reading from flushed handle");
#endif
    return handle_;
  }

 public:
                                                  
  explicit HandleBase(
      HandleRootOwner &runtime,
      HermesValue value = HermesValue::encodeUndefinedValue());

                                                                
                          
  explicit HandleBase(const PinnedHermesValue *valueAddr)
      : handle_(const_cast<PinnedHermesValue *>(valueAddr)) {
#ifndef NDEBUG
    gcScope_ = nullptr;
#endif
  }

                       
#ifndef NDEBUG
  HandleBase(const HandleBase &sc);
#else
  HandleBase(const HandleBase &sc) = default;
#endif

#ifndef NDEBUG
                       
  HandleBase(HandleBase &&sc) : handle_(sc.handle_) {
    gcScope_ = sc.gcScope_;
    sc.gcScope_ = nullptr;
  }
#endif

#ifndef NDEBUG
  ~HandleBase();
#else
  ~HandleBase() = default;
#endif

  const PinnedHermesValue *operator->() {
    return handleRef();
  }
  HermesValue operator*() {
    return *handleRef();
  }

  HermesValue getHermesValue() const {
    return *handleRef();
  }

                                                              
                                                                
                                                              
                                                    
  const PinnedHermesValue *unsafeGetPinnedHermesValue() const {
                                                                            
    return handle_;
  }
} HERMES_ATTRIBUTE_WARN_UNUSED_VARIABLES;

#ifdef NDEBUG
static_assert(
    std::is_trivially_copyable<HandleBase>::value &&
        sizeof(HandleBase) == sizeof(void *),
    "Handle must fit in a register and be trivially copyable");
#endif

                                                                       
             
template <typename T, bool isCell = HermesValueTraits<T>::is_cell>
struct HermesValueCast {
                                                                           
                  
  static void assertValid(HermesValue x) {
#ifndef NDEBUG
    (void)vmcast<T>(x);
#endif
  }
};

template <typename T>
struct HermesValueCast<T, false> {
                                                                           
                  
  static void assertValid(HermesValue x) {
#ifndef NDEBUG
    (void)HermesValueTraits<T>::decode(x);
#endif
  }
};

                                                                              
                                                                            
                                             
                                                                           
                                                                          
                              
template <typename T>
class Handle : public HandleBase {
 protected:
                                                                
                          
  explicit Handle(const PinnedHermesValue *valueAddr, bool)
      : HandleBase(const_cast<PinnedHermesValue *>(valueAddr)) {}

  explicit Handle(const HandleBase &hb, bool) : HandleBase(hb) {}

  explicit Handle(HandleRootOwner &runtime, HermesValue hermesValue, bool)
      : HandleBase(runtime, hermesValue) {}

 public:
  using value_type = typename HermesValueTraits<T>::value_type;

                                                  
  explicit Handle(HandleRootOwner &runtime, value_type value)
      : HandleBase(runtime, HermesValueTraits<T>::encode(value)) {};
  explicit Handle(GCScope *inScope, value_type value)
      : HandleBase(inScope, HermesValueTraits<T>::encode(value)) {};

                                                                
                          
  explicit Handle(const PinnedHermesValue *valueAddr)
      : HandleBase(const_cast<PinnedHermesValue *>(valueAddr)) {
    static_assert(
        std::is_same<value_type, HermesValue>::value,
        "This constructor can only be used for Handle<HermesValue>");
  }

                                       
  template <
      typename U,
      typename =
          typename std::enable_if<IsHermesValueConvertible<U, T>::value>::type>
  Handle(const Handle<U> &other) : HandleBase(other) {}

  Handle(const Handle<T> &) = default;
  Handle(Handle<T> &&) = default;

  template <
      typename U,
      typename =
          typename std::enable_if<IsHermesValueConvertible<U, T>::value>::type>
  Handle<T> &operator=(const Handle<U> &other) {
    HandleBase::operator=(other);
    return *this;
  }

#ifndef NDEBUG
  Handle<T> &operator=(const Handle<T> &other) {
    HandleBase::operator=(other);
    return *this;
  }
#else
  Handle<T> &operator=(const Handle<T> &other) = default;
#endif

  value_type get() const {
    return HermesValueTraits<T>::decode(getHermesValue());
  }

                                                     
                                                                      
  explicit operator bool() const {
    return handleRef()->isPointer() && handleRef()->getPointer();
  }

  typename HermesValueTraits<T>::arrow_type operator->() const {
    return HermesValueTraits<T>::arrow(*handleRef());
  }

  value_type operator*() const {
    return get();
  }

  bool operator==(const Handle &value) const {
    return get() == value.get();
  }

                                                             
                                             
  static Handle<T> vmcast(HandleRootOwner &runtime, HermesValue hermesValue) {
    HermesValueCast<T>::assertValid(hermesValue);
    return Handle<T>(runtime, hermesValue, true);
  }

                                                                            
                                 
  static Handle<T> vmcast(const PinnedHermesValue *valueAddr) {
    HermesValueCast<T>::assertValid(*valueAddr);
    return Handle<T>(valueAddr, true);
  }

                                                                            
                                 
  static Handle<T> vmcast_or_null(const PinnedHermesValue *valueAddr) {
    (void)hermes::vm::vmcast_or_null<T>(*valueAddr);
    return Handle<T>(valueAddr, true);
  }

                                                                             
                   
  static Handle<T> vmcast(const HandleBase &other) {
    HermesValueCast<T>::assertValid(other.getHermesValue());
    return Handle<T>(other, true);
  }

                                                                             
                   
  static Handle<T> vmcast_or_null(const HandleBase &other) {
    (void)hermes::vm::vmcast_or_null<T>(other.getHermesValue());
    return Handle<T>(other, true);
  }

  static Handle<T> dyn_vmcast(const HandleBase &other);

                                                             
                                                                   
  static Handle<T> unsafeCreate(const PinnedHermesValue *valueAddr) {
    return Handle<T>(valueAddr, true);
  }
} HERMES_ATTRIBUTE_WARN_UNUSED_VARIABLES;

#ifdef NDEBUG
static_assert(
    std::is_trivially_copyable<Handle<>>::value &&
        sizeof(Handle<>) == sizeof(void *),
    "Handle must fit in a register and be trivially copyable");
#endif

                                                                          
                                                                             
                                             
template <typename T>
class MutableHandle : public Handle<T> {
  MutableHandle(const MutableHandle &) = delete;
  void operator=(const MutableHandle &) = delete;

                                                                              
  explicit MutableHandle(PinnedHermesValue *valueAddr, bool dummy)
      : Handle<T>(valueAddr, dummy) {}

 public:
  using value_type = typename Handle<T>::value_type;

                                                  
  explicit MutableHandle(
      HandleRootOwner &runtime,
      value_type value = HermesValueTraits<T>::defaultValue())
      : Handle<T>(runtime, value) {}

                         
  MutableHandle(MutableHandle &&sc) : Handle<T>(std::move(sc)) {}

  MutableHandle &operator=(MutableHandle &&sc) {
    *HandleBase::handleRef() = *sc.handleRef();
    return *this;
  }

  MutableHandle &operator=(PseudoHandle<T> &&other) {
    set(other.get());
    other.invalidate();
    return *this;
  }

  MutableHandle &operator=(value_type value) {
    set(value);
    return *this;
  }
                                                                            
  void clear() {
    set(HermesValueTraits<T>::defaultValue());
  }

  void set(value_type value) {
    *HandleBase::handleRef() = HermesValueTraits<T>::encode(value);
  }

                                                                                
                           
  static MutableHandle<T> vmcast(PinnedHermesValue *valueAddr) {
    HermesValueCast<T>::assertValid(*valueAddr);
    return MutableHandle<T>(valueAddr, true);
  }

                                                                             
                                                                            
                                                                      
  static MutableHandle<T> aliasForOutput(PinnedHermesValue *valueAddr) {
#ifdef HERMES_SLOW_DEBUG
    *valueAddr = HermesValue::encodeInvalidValue();
#endif
    return MutableHandle<T>(valueAddr, true);
  }
} HERMES_ATTRIBUTE_WARN_UNUSED_VARIABLES;

static_assert(
    sizeof(MutableHandle<>) == sizeof(HandleBase),
    "MutableHandle must be a thin wrapper on top of Handle");

                                            
template <typename T>
inline PseudoHandle<T> createPseudoHandle(T *ptr) {
  return PseudoHandle<T>::create(ptr);
}

                                                
inline PseudoHandle<> createPseudoHandle(HermesValue value) {
  return PseudoHandle<>::create(value);
}

}                
}                    

namespace std {
                                                                             
                                                                            
template <typename T>
void swap(hermes::vm::MutableHandle<T> &a, hermes::vm::MutableHandle<T> &b) {
  typename hermes::vm::MutableHandle<T>::value_type tmp = a.get();
  a.set(b.get());
  b.set(tmp);
}
}                 
                                                                       
                                                                
                                                                     
                                                                     
                                                                           
                                                                       
                                                                        
                     
                                                                     
                    
namespace llvh {

                                                                           
                                                                           
                                                                            
template <typename T>
struct isPodLike<hermes::vm::PseudoHandle<T>> {
  static const bool value = false;
};
}                  

#endif                      

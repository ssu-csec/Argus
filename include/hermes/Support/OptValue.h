/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                                                                               
                                                                          
                       
                                                                                

#ifndef HERMES_SUPPORT_OPTVALUE_H
#define HERMES_SUPPORT_OPTVALUE_H

#include "hermes/Support/Compiler.h"

#include "llvh/ADT/None.h"

#include <cassert>
#include <type_traits>

namespace hermes {

                                                                           
                                                                               
                                                                               
                              
template <typename T>
class OptValue {
  static_assert(
      std::is_trivially_copyable<T>::value,
      "OptValue<> can only be used with trivially copyable types");
  T value_{};
  bool hasValue_;

 public:
  typedef T value_type;

  OptValue(llvh::NoneType) : hasValue_(false) {}
  explicit OptValue() : hasValue_(false) {}
  OptValue(const T &v) : value_(v), hasValue_(true) {}

  OptValue(const OptValue &) = default;
  OptValue &operator=(const OptValue &) = default;
  ~OptValue() = default;

  bool hasValue() const {
    return hasValue_;
  }
  explicit operator bool() const {
    return hasValue_;
  }

  const T &getValue() const {
    assert(hasValue());
    return value_;
  }
  const T &operator*() const {
    return getValue();
  }

  const T *operator->() const {
    return &getValue();
  }
};
static_assert(
    std::is_trivially_copyable<OptValue<int>>::value,
    "OptValue<int> must be trivially copyable");

                                                                         
template <>
class OptValue<bool> {
                                   
  int value_;

 public:
  typedef bool value_type;
  OptValue(llvh::NoneType) : value_(-1) {}
  explicit OptValue() : value_(-1) {}
  OptValue(bool v) : value_(v ? 1 : 0) {}

  OptValue(const OptValue &) = default;
  OptValue &operator=(const OptValue &) = default;
  ~OptValue() = default;

  bool hasValue() const {
    return value_ >= 0;
  }
  explicit operator bool() const {
    return hasValue();
  }

  bool getValue() const {
    assert(hasValue());
    return value_ > 0;
  }

  bool operator*() const {
    return getValue();
  }
};
static_assert(
    std::is_trivially_copyable<OptValue<bool>>::value,
    "OptValue<bool> must be trivially copyable");

template <typename T, typename U>
bool operator==(const OptValue<T> &a, const OptValue<U> &b) {
  if (a && b)
    return *a == *b;
  return a.hasValue() == b.hasValue();
}

template <typename T, typename U>
bool operator!=(const OptValue<T> &a, const OptValue<U> &b) {
  return !(a == b);
}
}                    

namespace llvh {
template <typename T>
struct isPodLike;
template <typename T>
struct isPodLike<hermes::OptValue<T>> {
                                        
  static const bool value = isPodLike<T>::value;
};
}                  

#endif                             

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_ADT_PTRORINT_H
#define HERMES_ADT_PTRORINT_H

#include <cassert>
#include <cstdint>

namespace hermes {

                                                                            
                                                                         
                                                                              
                                                                             
            
template <class T>
class PtrOrInt {
  static_assert(
      sizeof(int) <= sizeof(intptr_t),
      "int must not be larger than intptr_t");
  T *data_;

                                                                         
                                            
  intptr_t intbits() const {
    return reinterpret_cast<intptr_t>(data_);
  }

                                                              
  static T *encodeInt(int x) {
    return reinterpret_cast<T *>(((intptr_t)x << 1) + 1);
  }

                                      
  static int decodeInt(intptr_t x) {
    return (int)(x >> 1);
  }

 public:
  PtrOrInt(T *ptr) : data_(ptr) {}

  explicit PtrOrInt(int index) : data_(encodeInt(index)) {}

  bool isPointer() const {
    return (intbits() & 1) == 0;
  }

  bool isInt() const {
    return (intbits() & 1) != 0;
  }

  T *getPointer() const {
    assert(isPointer() && "value is not a pointer");
    return data_;
  }

  int getInt() const {
    assert(isInt() && "value is not an index");
    return decodeInt(intbits());
  }

  T *operator->() const {
    return getPointer();
  }

  T &operator*() const {
    return *getPointer();
  }

                                                                          
                     
  T *&getPointerRef() {
    assert(isPointer() && "value is not a pointer");
    return data_;
  }

                              
  PtrOrInt<T> &operator=(int x) {
    data_ = encodeInt(x);
    return *this;
  }

                             
  PtrOrInt<T> &operator=(T *ptr) {
    data_ = ptr;
    return *this;
  }
};

}                    
#endif                         

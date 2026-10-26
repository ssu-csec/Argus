/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_COPYABLEVECTOR_H
#define HERMES_SUPPORT_COPYABLEVECTOR_H

#include "hermes/Support/Algorithms.h"
#include "hermes/Support/CheckedMalloc.h"
#include "hermes/VM/GC.h"

#include "llvh/Support/Compiler.h"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <memory>

namespace hermes {
namespace vm {

                                                                          
                                                                              
             
   
                                                                              
                                                                           
   
                                                                              
                                                                              
                                                         
   
                                            
                                                                 
                                                                              
                                             
   
                                                                        
                                          
template <typename T>
class CopyableVector {
 public:
  using size_type = size_t;

 private:
                                                                   
  T *start_;

                                                  
  size_type size_;

                                            
  size_type capacity_;

 public:
                                      
                                             
  static constexpr size_type kMaxCapacity =
      std::numeric_limits<size_type>::max() / sizeof(T);

                              
                                           
                                            
  explicit CopyableVector(size_type capacity = 0)
      : size_(0), capacity_(capacity) {
    assert(capacity_ <= kMaxCapacity && "capacity overflow for CopyableVector");
    if (capacity_ == 0) {
      start_ = nullptr;
    } else {
      start_ = static_cast<T *>(checkedMalloc2(sizeof(T), capacity_));
    }
  }

                                                                
  ~CopyableVector() {
    for (auto &v : *this) {
      v.~T();
    }
    free(start_);
  }

                                                                          
                                                                    
  CopyableVector(const CopyableVector &) = delete;
  CopyableVector(CopyableVector &&) = delete;
  CopyableVector &operator=(const CopyableVector &) = delete;
  CopyableVector &operator=(CopyableVector &&) = delete;

                                                     
                                                                         
                                                                      
                    
  void operator=(llvh::ArrayRef<T> arr) {
    assert(
        (arr.data() < this->begin() || arr.data() >= this->end()) &&
        "Cannot assign a subarray of self");
    reserve(arr.size());
                                                                           
                                         
    for (auto &v : *this) {
      v.~T();
    }
    hermes::uninitializedCopyN(arr.data(), arr.size(), this->begin());
    size_ = arr.size();
  }

                                                    
  size_type size() const {
    return size_;
  }

                                                      
  bool empty() const {
    return size_ == 0;
  }

                                                                       
  size_type capacity() const {
    return capacity_;
  }

                                                            
  size_type capacity_in_bytes() const {
    return capacity_ * sizeof(T);
  }

                                   
  const T &operator[](size_type i) const {
    assert(i < size_ && "Out of bounds access in CopyableVector");
    return start_[i];
  }

                                   
  T &operator[](size_type i) {
    assert(i < size_ && "Out of bounds access in CopyableVector");
    return start_[i];
  }

                                             
  const T *begin() const {
    return start_;
  }

                                             
  T *begin() {
    return start_;
  }

                                                     
  const T *end() const {
    return start_ + size_;
  }

                                                     
  T *end() {
    return start_ + size_;
  }

                                       
                                                                           
                       
  void push_back(const T &elem, GC &gc) {
    if (LLVM_UNLIKELY(size_ == capacity_)) {
      grow(gc);
    }
    new (start_ + size_) T(elem);
    ++size_;
  }

                                       
                                                                           
                       
  void push_back(T &&elem, GC &gc) {
    if (LLVM_UNLIKELY(size_ == capacity_)) {
      grow(gc);
    }
    new (start_ + size_) T(std::move(elem));
    ++size_;
  }

                                          
                                   
  void pop_back() {
    assert(!empty() && "Cannot pop from empty vector");
    start_[size_ - 1].~T();
    --size_;
  }

                                                                               
  void reserve(size_type capacity) {
    if (capacity > capacity_) {
      setCapacity(capacity);
    }
  }

                                
                 operator llvh::ArrayRef<T>() const {
    return llvh::makeArrayRef(begin(), size());
  }

 private:
                                                               
                                       
  void grow(GC &gc) {
                                            
    size_t desired = capacity_ + (capacity_ - capacity_ / 2u);
    if (desired < capacity_ || desired > kMaxCapacity) {
                  
      gc.oom(make_error_code(OOMError::CopyableVectorCapacityIntegerOverflow));
    }
    setCapacity(std::max<size_type>(1u, desired));
  }

                                                              
                                                                  
  void setCapacity(size_type newCapacity) {
    assert(newCapacity > capacity_ && "setCapacity() must grow the vector");
    T *newStart = static_cast<T *>(checkedMalloc2(sizeof(T), newCapacity));
    for (T *src = start_, *end = start_ + size_, *target = newStart; src < end;
         ++src, ++target) {
      new (target) T(std::move(*src));
      src->~T();
    }
    free(start_);
    start_ = newStart;
    capacity_ = newCapacity;
  }
};

}                
}                    

#endif

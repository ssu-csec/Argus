/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_HBC_STREAMVECTOR_H
#define HERMES_BCGEN_HBC_STREAMVECTOR_H

#include "llvh/ADT/ArrayRef.h"

namespace hermes {
namespace hbc {

                                                                             
                           
                                                                         
                                                                     
                                          
                                                                          
                                                                           
                          
template <typename T>
class StreamVector {
  StreamVector(const StreamVector &) = delete;
  void operator=(const StreamVector &) = delete;

                                                                   
  std::vector<T> vec_{};

                                                               
                                          
  llvh::ArrayRef<T> ref_{vec_};

 public:
                                                        
  explicit StreamVector(StreamVector &&SV) = default;

                                  
  explicit StreamVector(const T *data, size_t size)
      : StreamVector(llvh::ArrayRef<T>(data, size)) {}

                                  
  explicit StreamVector(llvh::ArrayRef<T> ref) : ref_(ref) {}

                                
  explicit StreamVector(std::vector<T> &&data)
      : vec_(std::move(data)), ref_(vec_) {}

  explicit StreamVector() {}

  StreamVector &operator=(StreamVector &&that) = default;

  const llvh::ArrayRef<T> &getData() const {
    return ref_;
  }

  size_t size() const {
    return ref_.size();
  }

  const T &operator[](std::size_t index) const {
    assert(index < ref_.size() && "StreamVector access out of bound.");
    return ref_[index];
  }
};

}                 
}                    
#endif                                   

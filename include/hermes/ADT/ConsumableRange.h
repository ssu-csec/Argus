/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_CONSUMABLERANGE_H
#define HERMES_SUPPORT_CONSUMABLERANGE_H

#include <cassert>
#include <iterator>

namespace hermes {

                                                                
template <typename T>
class ConsumableRange {
  T cur_;
  const T end_;

 public:
  ConsumableRange(T begin, T end) : cur_(begin), end_(end) {}

  ConsumableRange(const ConsumableRange &other) = default;
  ConsumableRange &operator=(const ConsumableRange &other) = delete;

  ConsumableRange(ConsumableRange &&other) = default;
  ConsumableRange &operator=(ConsumableRange &&other) = default;

                                                                
  bool hasNext() const {
    return cur_ != end_;
  }

                                          
  decltype(*cur_) next() {
    assert(hasNext());
    return *cur_++;
  }

                                       
  decltype(*cur_) peek() const {
    assert(hasNext());
    return *cur_;
  }

                                                 
  size_t size() const {
    using std::distance;
    return distance(cur_, end_);
  }
};

}                    

#endif                                    

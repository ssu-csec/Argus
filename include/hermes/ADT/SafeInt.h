/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_ADT_SAFEINT_H
#define HERMES_ADT_SAFEINT_H

#include <cassert>
#include <cstdint>
#include <limits>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {

                                                                    
                                                          
                                                                               
                         
class SafeUInt32 {
                                                                       
  uint64_t value_;
                                                                  
  uint32_t ors_;

 public:
  explicit SafeUInt32(uint32_t value = 0) : value_(value), ors_(0) {}

                                                        
  bool isOverflowed() const {
    return ors_ != 0;
  }

                                      
  bool isZero() const {
    return value_ == 0 && ors_ == 0;
  }

                                       
                                              
  uint32_t get() const {
    assert(
        !isOverflowed() &&
        "attempt to retrieve value of overflowed SafeUInt32");
    return value_;
  };

                                               
  void add(uint32_t n) {
    value_ += n;
    ors_ |= (value_ >> 32);
  };

  uint32_t operator*() const {
    return get();
  }
};

}                    

#pragma GCC diagnostic pop
#endif

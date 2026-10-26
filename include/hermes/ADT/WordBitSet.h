/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_ADT_WORDBITSET_H
#define HERMES_ADT_WORDBITSET_H

#include "llvh/Support/MathExtras.h"

#include <cassert>
#include <climits>
#include <cstdint>

namespace hermes {

                                                                            
template <typename T = uint32_t>
class WordBitSet {
  T value_{};

  enum { NUM_BITS = sizeof(T) * CHAR_BIT };

 public:
  WordBitSet() = default;
  WordBitSet(const WordBitSet &) = default;
  WordBitSet &operator=(const WordBitSet &) = default;
  ~WordBitSet() = default;

                                      
  bool empty() const {
    return value_ == 0;
  }

                                      
  WordBitSet &set(unsigned pos) {
    value_ |= (T)1 << pos;
    return *this;
  }

                                      
  WordBitSet &clear(unsigned pos) {
    value_ &= ~((T)1 << pos);
    return *this;
  }

                                    
  bool at(unsigned pos) const {
    assert(pos < NUM_BITS && "Invalid index");
    return (value_ & ((T)1 << pos));
  }

                                    
  bool operator[](unsigned pos) const {
    assert(pos < NUM_BITS && "Invalid index");
    return (value_ & ((T)1 << pos));
  }

                                                                     
  int findFirst() const {
    return !value_ ? -1 : llvh::countTrailingZeros(value_, llvh::ZB_Undefined);
  }

                                                                                
                           
  int findNext(int prev) const {
    assert(prev >= 0 && prev < NUM_BITS && "Invalid index");
                                                                
    T tmp = value_ >> prev;
    tmp >>= 1;
    return !tmp ? -1
                : llvh::countTrailingZeros(tmp, llvh::ZB_Undefined) + prev + 1;
  }

  class const_iterator {
    friend class WordBitSet;
    T value_;
    int pos_;

    const_iterator(T value) : value_(value) {
      if (value) {
        unsigned tmp = llvh::countTrailingZeros(value_, llvh::ZB_Undefined);
        value_ >>= tmp;
        pos_ = tmp;
      } else {
        pos_ = -1;
      }
    }

   public:
    bool operator==(const_iterator it) const {
      return pos_ == it.pos_;
    }
    bool operator!=(const_iterator it) const {
      return pos_ != it.pos_;
    }
    unsigned operator*() const {
      assert(pos_ >= 0 && "Can't dereference end() iterator");
      return (unsigned)pos_;
    }
    const_iterator &operator++() {
      assert(pos_ >= 0 && "Can't increment end() iterator");
      value_ >>= 1;
      if (value_) {
        unsigned tmp = llvh::countTrailingZeros(value_, llvh::ZB_Undefined);
        value_ >>= tmp;
        pos_ += tmp + 1;
      } else {
        pos_ = -1;
      }
      return *this;
    }
  };

  const_iterator begin() const {
    return const_iterator{value_};
  }
  const_iterator end() const {
    return const_iterator{0};
  }
};

}                    

#endif                           

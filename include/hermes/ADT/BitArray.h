/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_ADT_BITARRAY_H
#define HERMES_ADT_BITARRAY_H

#include "llvh/Support/MathExtras.h"

#include <array>
#include <bitset>

#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif

namespace hermes {

                                                                              
                                                                        
                                         
                                              
                                                               
template <size_t N, size_t A = sizeof(uintptr_t)>
class BitArray {
 private:
  static_assert(
      A && A % sizeof(uintptr_t) == 0,
      "Bit set alignment must be a non-zero multiple of word size!");
  static constexpr size_t kBitsPerWord = 8 * sizeof(uintptr_t);
  static constexpr size_t kNumWords =
      llvh::alignTo<kBitsPerWord>(N) / kBitsPerWord;
  static constexpr size_t kPaddedWords =
      llvh::alignTo<A / sizeof(uintptr_t)>(kNumWords);
  std::array<uintptr_t, kPaddedWords> allBits_;

                                                            
  template <bool V>
  size_t findNextBitImpl(size_t idx) const {
    assert(
        idx <= N &&
        "precondition: idx is less than or equal to number of bits");
                                                                        
                                                                              
    if (N % kBitsPerWord == 0 && idx == N) {
      return N;
    }
    size_t wordIdx = idx / kBitsPerWord;
    size_t offset = idx % kBitsPerWord;
                                                                                
                                             
    uintptr_t currentWord = V ? allBits_[wordIdx] : ~allBits_[wordIdx];
                                                                        
    currentWord &= (std::numeric_limits<uintptr_t>::max() << offset);

                                                                               
                                                                      
    constexpr bool noBoundsCheck = kNumWords < kPaddedWords && V;
                                                                                
                                                                                
                                                                                
    ++wordIdx;
    while (!currentWord && (noBoundsCheck || wordIdx < kNumWords)) {
      currentWord = V ? allBits_[wordIdx] : ~allBits_[wordIdx];
      ++wordIdx;
    }
    idx = (wordIdx - 1) * kBitsPerWord + llvh::countTrailingZeros(currentWord);
                                                                           
                                                                      
                                      
    if (N % kBitsPerWord) {
      idx = std::min(idx, N);
    }
    return idx;
  }

                                                                
                                                                               
                
  template <bool V>
  size_t findPrevBitImpl(size_t idx) const {
    assert(
        idx <= N &&
        "precondition: idx is less than or equal to number of bits");
    if (!idx) {
      return N;
    }
                                
    idx--;
    size_t wordIdx = idx / kBitsPerWord;
    size_t offset = idx % kBitsPerWord;
                                                                                
                                             
    uintptr_t currentWord = V ? allBits_[wordIdx] : ~allBits_[wordIdx];
                                                                       
    currentWord &= llvh::maskTrailingOnes<uintptr_t>(offset + 1);

                                                                                
                                                                         
                                                                            
                  
    while (wordIdx-- > 0 && !currentWord) {
      currentWord = V ? allBits_[wordIdx] : ~allBits_[wordIdx];
    }
                
                                                                           
                                                                                
                                                                
    idx = (wordIdx + 1) * kBitsPerWord +
        (kBitsPerWord - llvh::countLeadingZeros(currentWord) - 1);
    return std::min(idx, N);
  }

 public:
  BitArray() {
    std::fill_n(allBits_.begin(), kNumWords, 0);
                                                                             
                
    std::fill_n(
        allBits_.begin() + kNumWords,
        kPaddedWords - kNumWords,
        std::numeric_limits<uintptr_t>::max());
  }

                        
  inline void set() {
    std::fill_n(
        allBits_.begin(), kNumWords, std::numeric_limits<uintptr_t>::max());
  }

  inline void set(size_t idx, bool val) {
    const uintptr_t mask = 1ULL << (idx % kBitsPerWord);
    const size_t wordIdx = idx / kBitsPerWord;
    if (val)
      allBits_[wordIdx] |= mask;
    else
      allBits_[wordIdx] &= ~mask;
  }

                        
  inline void reset() {
    std::fill_n(allBits_.begin(), kNumWords, 0);
  }

                                                     
  inline bool at(size_t idx) const {
    assert(idx < N && "Index must be within the bitset");
    const uintptr_t mask = 1ULL << (idx % kBitsPerWord);
    const auto wordIdx = idx / kBitsPerWord;
    return allBits_[wordIdx] & mask;
  }

                                                             
  size_t findNextSetBitFrom(size_t idx) const {
    return findNextBitImpl<true>(idx);
  }
                                                               
  size_t findNextZeroBitFrom(size_t idx) const {
    return findNextBitImpl<false>(idx);
  }
                                                              
  size_t findPrevSetBitFrom(size_t idx) const {
    return findPrevBitImpl<true>(idx);
  }
                                                                
  size_t findPrevZeroBitFrom(size_t idx) const {
    return findPrevBitImpl<false>(idx);
  }
};
}                    
#pragma GCC diagnostic pop

#endif                         

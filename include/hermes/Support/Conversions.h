/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_CONVERSIONS_H
#define HERMES_SUPPORT_CONVERSIONS_H

#include "hermes/Support/OptValue.h"

#include "llvh/ADT/StringRef.h"
#include "llvh/Support/MathExtras.h"

#include <cstdint>

namespace hermes {

                                                                        
                                                                            
                     
                                                                           
                                                                               
                                  
                                                                        
                                                                              
int32_t truncateToInt32SlowPath(double d);

                                                                        
                                                                            
                     
                                                                           
                                                                               
                                  
int32_t truncateToInt32(double d) LLVM_NO_SANITIZE("float-cast-overflow");
inline int32_t truncateToInt32(double d) {
                                                                       
                                                                              
                                                                               
                                                                      
                                                                             
                                                                     
                                                                     
                                                                            
                                                                             
                                                                            
                                                           
                                                                             
                                                        
                                                                            
                  

  if constexpr (sizeof(void *) == 8) {
                                                                      
                                                    
#if defined(__GNUC__) || defined(__clang__)
    if (__builtin_constant_p(d)) {
#endif
                                                                       
                                        
      if (d >= (int64_t)(-1ULL << 53) && d <= (1LL << 53)) {
        return (int32_t)(int64_t)d;
      }
#if defined(__GNUC__) || defined(__clang__)
    } else {
      int64_t fast = (int64_t)((uint64_t)d << 1) >> 1;
      if (LLVM_LIKELY(fast == d))
        return (int32_t)fast;
    }
#endif
  } else {
#if defined(__GNUC__) || defined(__clang__)
    if (__builtin_constant_p(d)) {
#endif
                                                                    
                                                           
      if (d >= (int64_t)(-1ULL << 53) && d <= (1LL << 53)) {
        return (int32_t)(int64_t)d;
      }
#if defined(__GNUC__) || defined(__clang__)
    } else {
      int32_t fast = (int32_t)d;
      if (LLVM_LIKELY(fast == d))
        return fast;
    }
#endif
  }
  return truncateToInt32SlowPath(d);
}

inline uint32_t truncateToUInt32(double d) {
  return (uint32_t)truncateToInt32(d);
}

                                                                            
                         
                                                                               
                                                                               
             
                                                                               
                                                                           
                        
                                                                         
                                         
template <typename IT>
OptValue<uint32_t> toArrayIndex(IT first, IT last) {
                              
  if (first == last)
    return llvh::None;

                          
  if (*first == '0') {
    ++first;
                
    if (first == last)
      return 0;
                                      
    return llvh::None;
  }

  uint32_t res = 0;
  do {
    auto ch = *first;
    if (ch < '0' || ch > '9')
      return llvh::None;
    uint64_t tmp = (uint64_t)res * 10 + (ch - '0');
                          
    if (tmp & ((uint64_t)0xFFFFFFFFu << 32))
      return llvh::None;
    res = (uint32_t)tmp;
  } while (++first != last);

                                           
  if (res == 0xFFFFFFFFu)
    return llvh::None;

  return res;
}

                                                           
inline OptValue<uint32_t> toArrayIndex(llvh::StringRef str) {
  return toArrayIndex(str.begin(), str.end());
}

                                                                   
OptValue<uint32_t> doubleToArrayIndex(double d)
    LLVM_NO_SANITIZE("float-cast-overflow");
inline OptValue<uint32_t> doubleToArrayIndex(double d) {
  uint32_t index = (uint32_t)d;
  if (index == d && index != 0xFFFFFFFFu)
    return index;
  return llvh::None;
}

                                                         
const size_t NUMBER_TO_STRING_BUF_SIZE = 32;

                                                             
                                  
                             
                                                                    
                                                                                
size_t numberToString(double m, char *dest, size_t destSize);

                                                       
template <typename T>
inline T charLetterToLower(T ch) {
  return ch | 32;
}

                                                                            
                                                                             
                             
                                                                               
                    
                                                                         
template <bool AllowNumericSeparator, class Iterable, typename Callback>
bool parseIntWithRadixDigits(Iterable str, int radix, Callback digitCallback) {
  assert(
      radix >= 2 && radix <= 36 && "Invalid radix passed to parseIntWithRadix");
  assert(str.begin() != str.end() && "Empty string");
  for (auto it = str.begin(); it != str.end(); ++it) {
    auto c = *it;
    auto cLow = charLetterToLower(c);
    if ('0' <= c && c <= '9' && c < '0' + radix) {
      digitCallback(c - '0');
    } else if ('a' <= cLow && cLow < 'a' + radix - 10) {
      digitCallback(cLow - 'a' + 0xa);
    } else if (AllowNumericSeparator && LLVM_UNLIKELY(c == '_')) {
                                               
                                                    
      if (it == str.begin() || it == str.end() - 1) {
        return false;
      }
                                                                        
                                                               
                                                    
      char next = *(it + 1);
      if (next == '_') {
        return false;
      }
    } else {
      return false;
    }
  }
  return true;
}

                                                                            
                      
                                                                               
                       
                                                                
template <bool AllowNumericSeparator, class Iterable>
OptValue<double> parseIntWithRadix(Iterable str, int radix) {
  double result = 0;
  bool success = parseIntWithRadixDigits<AllowNumericSeparator>(
      str, radix, [&result, radix](uint8_t d) {
        result *= radix;
        result += d;
      });
  if (!success)
    return llvh::None;

                                                                
  const double MAX_MANTISSA = 9007199254740992.0;
  if (result >= MAX_MANTISSA && llvh::isPowerOf2_32(radix)) {
                                                                    
                                    
                                                                           
    result = 0;

                                                              
    enum Mode {
      LEADING_ZERO,                               
      MANTISSA,                                               
      EXP_LOW_BIT,                                                    
      EXP_LEADING_ZERO,                          
      EXPONENT,                                   
    };

    size_t remainingMantissa = 53;
    double expFactor = 0.0;
    size_t curDigit = 0;

    bool lastMantissaBit = false;
    bool lowestExponentBit = false;

    Mode curMode = Mode::LEADING_ZERO;
    auto itr = str.begin();
    auto e = str.end();
    for (size_t bitMask = 0;;) {
      if (bitMask == 0) {
                                                                   
        if (itr == e) {
          break;
        }
                                                          
        char c = (char)*itr;
        if (AllowNumericSeparator && LLVM_UNLIKELY(c == '_')) {
          ++itr;
          continue;
        }
        auto cLow = charLetterToLower(c);
        if ('0' <= c && c <= '9') {
          curDigit = c - '0';
        } else {
                                                                          
          assert('a' <= cLow && cLow < 'a' + radix - 10);
          curDigit = cLow - 'a' + 0xa;
        }
        ++itr;
                                                  
        bitMask = radix >> 1;
      }
      bool curBit = (curDigit & bitMask) != 0;
      bitMask >>= 1;

      switch (curMode) {
        case Mode::LEADING_ZERO:
                                                              
          if (curBit) {
            --remainingMantissa;
            result = 1;
                                     
            curMode = Mode::MANTISSA;
          }
          break;
        case Mode::MANTISSA:
                                                                     
          result *= 2;
          result += curBit;
          --remainingMantissa;
          if (remainingMantissa == 0) {
                                                                        
            lastMantissaBit = curBit;
            curMode = Mode::EXP_LOW_BIT;
          }
          break;
        case Mode::EXP_LOW_BIT:
          lowestExponentBit = curBit;
          expFactor = 2.0;
          curMode = Mode::EXP_LEADING_ZERO;
          break;
        case Mode::EXP_LEADING_ZERO:
          if (curBit) {
            curMode = Mode::EXPONENT;
          }
          expFactor *= 2.0;
          break;
        case Mode::EXPONENT:
          expFactor *= 2.0;
          break;
      }
    }
    switch (curMode) {
      case Mode::LEADING_ZERO:
      case Mode::MANTISSA:
      case Mode::EXP_LOW_BIT:
                                                     
        break;
      case Mode::EXP_LEADING_ZERO:
                       
        result += lowestExponentBit && lastMantissaBit;
        result *= expFactor;
        break;
      case Mode::EXPONENT:
                       
        result += lowestExponentBit;
        result *= expFactor;
        break;
    }
  }
  return result;
}

}                    

extern "C" {
size_t hermes_numberToString(double m, char *dest, size_t destSize);
}

#endif                                

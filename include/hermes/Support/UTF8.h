/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_UTF8_H
#define HERMES_SUPPORT_UTF8_H

#include "hermes/Platform/Unicode/CharacterProperties.h"
#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/Twine.h"
#include "llvh/Support/Compiler.h"

#include <cstddef>

namespace hermes {

                                                      
constexpr size_t UTF8CodepointMaxBytes = 6;

                                                             
void encodeUTF8(char *&dst, uint32_t cp);

                                                                    
                                             
inline bool isUTF8Start(char ch) {
  return (ch & 0x80) != 0;
}

                                                 
inline bool isUTF8LeadingByte(char ch) {
  return (ch & 0xC0) == 0xC0;
}

                                                                              
                                                   
inline static bool isUTF8ContinuationByte(char ch) {
  return (ch & 0xC0) == 0x80;
}

                                                    
                             
template <typename Char>
bool isASCII(Char c) {
                                                                            
                                                                             
                                              
  constexpr uint32_t asciiMask = 0x7f;
  return (c & static_cast<Char>(~asciiMask)) == 0;
}

                                                       
template <typename Iter>
inline bool isAllASCII(Iter begin, Iter end) {
  while (begin < end) {
    if (!isASCII(*begin))
      return false;
    ++begin;
  }
  return true;
}

                                    
bool isAllASCII(const uint8_t *start, const uint8_t *end);

inline bool isAllASCII(const char *start, const char *end) {
  return isAllASCII((const uint8_t *)start, (const uint8_t *)end);
}

                                                                                
                                   
                                                                         
                          
template <bool allowSurrogates, typename F>
uint32_t _decodeUTF8SlowPath(const char *&from, F error) {
  uint32_t ch = (uint32_t)from[0];
  uint32_t result;

  assert(isUTF8Start(ch));

  if (LLVM_LIKELY((ch & 0xE0) == 0xC0)) {
    uint32_t ch1 = (uint32_t)from[1];
    if (LLVM_UNLIKELY((ch1 & 0xC0) != 0x80)) {
      from += 1;
      error("Invalid UTF-8 continuation byte");
      return UNICODE_REPLACEMENT_CHARACTER;
    }

    from += 2;
    result = ((ch & 0x1F) << 6) | (ch1 & 0x3F);
    if (LLVM_UNLIKELY(result <= 0x7F)) {
      error("Non-canonical UTF-8 encoding");
      return UNICODE_REPLACEMENT_CHARACTER;
    }

  } else if (LLVM_LIKELY((ch & 0xF0) == 0xE0)) {
    uint32_t ch1 = (uint32_t)from[1];
    if (LLVM_UNLIKELY((ch1 & 0x40) != 0 || (ch1 & 0x80) == 0)) {
      from += 1;
      error("Invalid UTF-8 continuation byte");
      return UNICODE_REPLACEMENT_CHARACTER;
    }
    uint32_t ch2 = (uint32_t)from[2];
    if (LLVM_UNLIKELY((ch2 & 0x40) != 0 || (ch2 & 0x80) == 0)) {
      from += 2;
      error("Invalid UTF-8 continuation byte");
      return UNICODE_REPLACEMENT_CHARACTER;
    }
    from += 3;
    result = ((ch & 0x0F) << 12) | ((ch1 & 0x3F) << 6) | (ch2 & 0x3F);
    if (LLVM_UNLIKELY(result <= 0x7FF)) {
      error("Non-canonical UTF-8 encoding");
      return UNICODE_REPLACEMENT_CHARACTER;
    }
    if (LLVM_UNLIKELY(
            result >= UNICODE_SURROGATE_FIRST &&
            result <= UNICODE_SURROGATE_LAST && !allowSurrogates)) {
      error("Invalid UTF-8 code point 0x" + llvh::Twine::utohexstr(result));
      return UNICODE_REPLACEMENT_CHARACTER;
    }

  } else if ((ch & 0xF8) == 0xF0) {
    uint32_t ch1 = (uint32_t)from[1];
    if (LLVM_UNLIKELY((ch1 & 0x40) != 0 || (ch1 & 0x80) == 0)) {
      from += 1;
      error("Invalid UTF-8 continuation byte");
      return UNICODE_REPLACEMENT_CHARACTER;
    }
    uint32_t ch2 = (uint32_t)from[2];
    if (LLVM_UNLIKELY((ch2 & 0x40) != 0 || (ch2 & 0x80) == 0)) {
      from += 2;
      error("Invalid UTF-8 continuation byte");
      return UNICODE_REPLACEMENT_CHARACTER;
    }
    uint32_t ch3 = (uint32_t)from[3];
    if (LLVM_UNLIKELY((ch3 & 0x40) != 0 || (ch3 & 0x80) == 0)) {
      from += 3;
      error("Invalid UTF-8 continuation byte");
      return UNICODE_REPLACEMENT_CHARACTER;
    }
    from += 4;
    result = ((ch & 0x07) << 18) | ((ch1 & 0x3F) << 12) | ((ch2 & 0x3F) << 6) |
        (ch3 & 0x3F);
    if (LLVM_UNLIKELY(result <= 0xFFFF)) {
      error("Non-canonical UTF-8 encoding");
      return UNICODE_REPLACEMENT_CHARACTER;
    }
    if (LLVM_UNLIKELY(result > UNICODE_MAX_VALUE)) {
      error("Invalid UTF-8 code point 0x" + llvh::Twine::utohexstr(result));
      return UNICODE_REPLACEMENT_CHARACTER;
    }

  } else {
    from += 1;
    error("Invalid UTF-8 lead byte 0x" + llvh::Twine::utohexstr((uint8_t)ch));
    return UNICODE_REPLACEMENT_CHARACTER;
  }

  return result;
}

                                                                           
                                                                    
                                                                             
                                                  
inline const char *previousUTF8Start(const char *ptr) {
  --ptr;
                                                     
  if (!(*ptr & 0x80))
    return ptr;
                                                           
  while ((*ptr & 0xC0) != 0xC0)
    --ptr;
  return ptr;
}

                                                                     
                                                                        
                                                                      
   
                                                                         
                          
                                                       
                         
template <bool allowSurrogates, typename F>
inline uint32_t decodeUTF8(const char *&from, F error) {
  if (LLVM_LIKELY((*from & 0x80) == 0))                   
    return *from++;

  return _decodeUTF8SlowPath<allowSurrogates>(from, error);
}

                                                                            
                                               
template <typename OutIt>
inline void encodeUTF16(OutIt &dest, uint32_t cp) {
  if (LLVM_LIKELY(cp < 0x10000)) {
    *dest = (uint16_t)cp;
    ++dest;                                                  
  } else {
    assert(cp <= UNICODE_MAX_VALUE && "invalid Unicode value");
    cp -= 0x10000;
    *dest = UTF16_HIGH_SURROGATE + ((cp >> 10) & 0x3FF);
    ++dest;
    *dest = UTF16_LOW_SURROGATE + (cp & 0x3FF);
    ++dest;
  }
}

                                                                           
                                                                       
                                            
template <typename OutIt>
inline OutIt convertUTF8WithSurrogatesToUTF16(
    OutIt dest,
    const char *begin8,
    const char *end8) {
  while (begin8 < end8)
    encodeUTF16(dest, decodeUTF8<true>(begin8, [](const llvh::Twine &) {
                  llvm_unreachable("invalid UTF-8");
                }));
  return dest;
}

                                                                        
                                                           
                                                                     
                                                                       
                                                                             
             
void convertUTF16ToUTF8WithSingleSurrogates(
    std::string &dest,
    llvh::ArrayRef<char16_t> input);

                                                                        
                                                                                
                                                                         
              
                                                                           
                               
bool convertUTF16ToUTF8WithReplacements(
    std::string &dest,
    llvh::ArrayRef<char16_t> input,
    size_t maxCharacters = 0);

                                                                            
                                                                            
                                                  
                                                                         
                                                                            
                        
std::pair<uint32_t, uint32_t> convertUTF16ToUTF8BufferWithReplacements(
    llvh::MutableArrayRef<uint8_t> outBuffer,
    llvh::ArrayRef<char16_t> input);

                                                                            
                                                                                
                              
void convertUTF8WithSurrogatesToUTF8WithReplacements(
    std::string &output,
    llvh::StringRef input);

}                    

#endif                         

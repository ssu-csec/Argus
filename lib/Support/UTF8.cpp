/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Support/UTF8.h"

namespace hermes {

void encodeUTF8(char *&dst, uint32_t cp) {
  char *d = dst;
  if (cp <= 0x7F) {
    *d = (char)cp;
    ++d;
  } else if (cp <= 0x7FF) {
    d[1] = (cp & 0x3F) | 0x80;
    cp >>= 6;
    d[0] = (cp & 0x1F) | 0xC0;
    d += 2;
  } else if (cp <= 0xFFFF) {
    d[2] = (cp & 0x3F) | 0x80;
    cp >>= 6;
    d[1] = (cp & 0x3F) | 0x80;
    cp >>= 6;
    d[0] = (cp & 0x0F) | 0xE0;
    d += 3;
  } else if (cp <= 0x1FFFFF) {
    d[3] = (cp & 0x3F) | 0x80;
    cp >>= 6;
    d[2] = (cp & 0x3F) | 0x80;
    cp >>= 6;
    d[1] = (cp & 0x3F) | 0x80;
    cp >>= 6;
    d[0] = (cp & 0x07) | 0xF0;
    d += 4;
  } else if (cp <= 0x3FFFFFF) {
    d[4] = (cp & 0x3F) | 0x80;
    cp >>= 6;
    d[3] = (cp & 0x3F) | 0x80;
    cp >>= 6;
    d[2] = (cp & 0x3F) | 0x80;
    cp >>= 6;
    d[1] = (cp & 0x3F) | 0x80;
    cp >>= 6;
    d[0] = (cp & 0x03) | 0xF8;
    d += 5;
  } else {
    d[5] = (cp & 0x3F) | 0x80;
    cp >>= 6;
    d[4] = (cp & 0x3F) | 0x80;
    cp >>= 6;
    d[3] = (cp & 0x3F) | 0x80;
    cp >>= 6;
    d[2] = (cp & 0x3F) | 0x80;
    cp >>= 6;
    d[1] = (cp & 0x3F) | 0x80;
    cp >>= 6;
    d[0] = (cp & 0x01) | 0xFC;
    d += 6;
  }
  dst = d;
}

                                                                         
                                                                          
                                                                         
                                                                            
                                                                             
                                                                            
                                                             
                                                         
                                                         
                                                                              
                                                                
static std::pair<char32_t, size_t> convertToCodePointAt(
    llvh::ArrayRef<char16_t>::iterator cur,
    llvh::ArrayRef<char16_t>::iterator end) {
  char16_t c = cur[0];
  if (isLowSurrogate(c)) {
                              
    return {UNICODE_REPLACEMENT_CHARACTER, 1};
  } else if (isHighSurrogate(c)) {
                                                                            
    if (cur + 1 == end || !isLowSurrogate(cur[1])) {
                                             
      return {UNICODE_REPLACEMENT_CHARACTER, 1};
    } else {
                                                                            
      return {utf16SurrogatePairToCodePoint(c, cur[1]), 2};
    }
  } else {
                       
    return {c, 1};
  }
}

bool convertUTF16ToUTF8WithReplacements(
    std::string &out,
    llvh::ArrayRef<char16_t> input,
    size_t maxCharacters) {
  out.clear();
  out.reserve(input.size());
                                                                             
  size_t currNumCharacters = 0;
  if (!maxCharacters) {
                                                                          
    maxCharacters = std::numeric_limits<size_t>::max();
  }
  auto cur = input.begin(), end = input.end();
  for (; cur < end && currNumCharacters < maxCharacters;
       ++cur, ++currNumCharacters) {
    char16_t c = cur[0];
                       
    if (LLVM_LIKELY(c <= 0x7F)) {
      out.push_back(static_cast<char>(c));
      continue;
    }

    auto [c32, inputConsumed] = convertToCodePointAt(cur, end);
    cur += (inputConsumed - 1);

                                                                            
                                                                            
               
    std::array<char, UTF8CodepointMaxBytes> buff;
    char *ptr = buff.data();
    encodeUTF8(ptr, c32);
    out.insert(out.end(), buff.data(), ptr);
  }
  return cur == end;
}

std::pair<uint32_t, uint32_t> convertUTF16ToUTF8BufferWithReplacements(
    llvh::MutableArrayRef<uint8_t> outBuffer,
    llvh::ArrayRef<char16_t> input) {
  uint32_t numRead = 0;
  uint32_t numWritten = 0;
  uint8_t *writtenPtr = outBuffer.begin();
  auto end = input.end();
  for (auto cur = input.begin(); cur < end; ++cur) {
    char16_t c = cur[0];
                       
    if (LLVM_LIKELY(c <= 0x7F)) {
      if (numWritten + 1 > outBuffer.size()) {
        break;
      }
      *writtenPtr = static_cast<char>(c);
      writtenPtr++;
      numWritten++;
      numRead++;
      continue;
    }

    auto [c32, inputConsumed] = convertToCodePointAt(cur, end);
    cur += (inputConsumed - 1);

                                                                            
                                                                            
               
    std::array<char, UTF8CodepointMaxBytes> buff;
    char *ptr = buff.data();
    encodeUTF8(ptr, c32);

    size_t convertedLength = ptr - buff.data();
    if (numWritten + convertedLength > outBuffer.size()) {
      break;
    }
    std::memcpy(writtenPtr, buff.data(), convertedLength);
    writtenPtr += convertedLength;
    numWritten += convertedLength;
    numRead += inputConsumed;
  }

  return {numRead, numWritten};
}

void convertUTF16ToUTF8WithSingleSurrogates(
    std::string &dest,
    llvh::ArrayRef<char16_t> input) {
  dest.clear();
  dest.reserve(input.size());
  for (char16_t c : input) {
                       
    if (LLVM_LIKELY(c <= 0x7F)) {
      dest.push_back(static_cast<char>(c));
      continue;
    }
    char32_t c32 = static_cast<char32_t>(c);
    char buff[UTF8CodepointMaxBytes];
    char *ptr = buff;
    encodeUTF8(ptr, c32);
    dest.insert(dest.end(), buff, ptr);
  }
}

bool isAllASCII(const uint8_t *start, const uint8_t *end) {
  const uint8_t *cursor = start;
  size_t len = end - start;
  static_assert(
      sizeof(uint32_t) == 4 && alignof(uint32_t) <= 4,
      "uint32_t must be 4 bytes and cannot be more than 4 byte aligned");

  if (len >= 4) {
                                             
    uint8_t mask = 0;
    while ((uintptr_t)cursor % alignof(uint32_t)) {
      mask |= *cursor++;
      len -= 1;
    }
    if (mask & 0x80u) {
      return false;
    }

                                           
    while (len >= 4) {
      uint32_t val = *(const uint32_t *)cursor;
      if (val & 0x80808080u) {
        return false;
      }
      cursor += 4;
      len -= 4;
    }
  }
  assert(len < 4 && "Length should now be less than 4");
  uint8_t mask = 0;
  while (len--) {
    mask |= *cursor++;
  }
  if (mask & 0x80u)
    return false;
  return true;
}

void convertUTF8WithSurrogatesToUTF8WithReplacements(
    std::string &output,
    llvh::StringRef input) {
                                                
  llvh::SmallVector<char16_t, 8> ustr;
                                                                                
                                                      
  ustr.reserve(input.size());
                                                                                
                                                                  
                                                                            
                                                                             
  char16_t *ustrEnd =
      convertUTF8WithSurrogatesToUTF16(ustr.data(), input.begin(), input.end());
                                      
  assert(
      static_cast<uintptr_t>(ustrEnd - ustr.data()) <= ustr.capacity() &&
      "buffer overflow while converting UTF8 surrogates");
                                                             
  convertUTF16ToUTF8WithReplacements(
      output, llvh::makeArrayRef(ustr.data(), ustrEnd));
}

}                    

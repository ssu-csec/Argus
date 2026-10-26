/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "JSLibInternal.h"

#include "hermes/Support/UTF8.h"
#include "hermes/VM/Operations.h"
#include "hermes/VM/SmallXString.h"
#include "hermes/VM/StringView.h"

#include "llvh/Support/ConvertUTF.h"
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

using llvh::ConversionResult;
using llvh::UTF32;
using llvh::UTF8;

                                                                     
static inline bool noEscape(char16_t c) {
  return (u'A' <= c && c <= u'Z') || (u'a' <= c && c <= u'z') ||
      (u'0' <= c && c <= u'9') || c == u'@' || c == u'*' || c == u'_' ||
      c == u'+' || c == u'-' || c == u'.' || c == '/';
}

                                                
                                                          
static inline char16_t toHexChar(int x) {
  assert(0 <= x && x <= 15 && "toHexChar argument out of bounds");
  if (0 <= x && x <= 9) {
    return x + u'0';
  }
  return x - 10 + u'A';
}

                                                                   
static inline bool isHexChar(char16_t c) {
                          
  char16_t cLow = c | 32;
  return (u'0' <= c && c <= u'9') || (u'a' <= cLow && cLow <= 'f');
}

                                
                                                                        
static inline int fromHexChar(char16_t c) {
  assert(isHexChar(c) && "fromHexChar argument out of bounds");
  if (u'0' <= c && c <= u'9') {
    return c - u'0';
  }
                          
  c |= 32;
  return c - u'a' + 10;
}

                                                                 
CallResult<HermesValue> escape(void *, Runtime &runtime, NativeArgs args) {
  auto res = toString_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto string = runtime.makeHandle(std::move(*res));
  auto len = string->getStringLength();
  SmallU16String<32> R{};
  R.reserve(len);

  for (char16_t c : StringPrimitive::createStringView(runtime, string)) {
    if (noEscape(c)) {
                     
      R.push_back(c);
    } else if (c < 256) {
                                                 
      R.push_back(u'%');
      R.push_back(toHexChar((c >> 4) & 0xf));
      R.push_back(toHexChar(c & 0xf));
    } else {
                                                      
      R.append(u"%u");
      R.push_back(toHexChar((c >> 12) & 0xf));
      R.push_back(toHexChar((c >> 8) & 0xf));
      R.push_back(toHexChar((c >> 4) & 0xf));
      R.push_back(toHexChar(c & 0xf));
    }
  }

  return StringPrimitive::create(runtime, R);
}

                                                                   
CallResult<HermesValue> unescape(void *, Runtime &runtime, NativeArgs args) {
  auto res = toString_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto strPrim = runtime.makeHandle(std::move(*res));
  auto len = strPrim->getStringLength();
  SmallU16String<32> R{};
  R.reserve(len);

  uint32_t k = 0;
  auto str = StringPrimitive::createStringView(runtime, strPrim);
  while (k < len) {
    char16_t c = str[k];
                                     
    char16_t r = c;
    if (c == u'%') {
                                          
      if (k + 6 <= len && str[k + 1] == u'u' &&
          std::all_of(str.begin() + k + 2, str.begin() + k + 6, isHexChar)) {
                           
        r = (fromHexChar(str[k + 2]) << 12) | (fromHexChar(str[k + 3]) << 8) |
            (fromHexChar(str[k + 4]) << 4) | fromHexChar(str[k + 5]);
        k += 5;
      } else if (
          k + 3 <= len && isHexChar(str[k + 1]) && isHexChar(str[k + 2])) {
                         
        r = (fromHexChar(str[k + 1]) << 4) | fromHexChar(str[k + 2]);
        k += 2;
      }
    }
    R.push_back(r);
    ++k;
  }

  return StringPrimitive::create(runtime, R);
}

                                                 
                                                                        
             
static inline UTF16Ref removeNullTerminator(const UTF16Ref str) {
  return str.slice(0, str.size() - 1);
}

                                                                                
using CharSetFn = bool (*)(char16_t c);

                                
static bool uriUnescaped(char16_t c) {
  const UTF16Ref marks = removeNullTerminator(u"-_.!~*'()");
  if (std::find(marks.begin(), marks.end(), c) != marks.end()) {
    return true;
  }
  if (u'0' <= c && c <= u'9') {
    return true;
  }
                                                     
  c |= 32;
  return u'a' <= c && c <= u'z';
}

                               
static bool uriReserved(char16_t c) {
  const UTF16Ref reserved = removeNullTerminator(u";/?:@&=+$,");
  return std::find(reserved.begin(), reserved.end(), c) != reserved.end();
}

                                                                        
static bool unescapedURISet(char16_t c) {
  return uriReserved(c) || uriUnescaped(c) || c == '#';
}

                                        
static bool reservedURISet(char16_t c) {
  return uriReserved(c) || c == '#';
}

                 
                                                              
                                                                             
static CallResult<Handle<StringPrimitive>> encode(
    Runtime &runtime,
    Handle<StringPrimitive> strHandle,
    CharSetFn unescapedSet) {
  auto str = StringPrimitive::createStringView(runtime, strHandle);
  auto strLen = str.length();
  SmallU16String<32> R{};
  R.reserve(strLen);
  for (auto itr = str.begin(), e = str.end(); itr != e;) {
                                                        
    uint32_t C = *itr;
    if (unescapedSet(C)) {
      R.push_back(C);
    } else {
      if (C >= 0xdc00 && C <= 0xdfff) {
        return runtime.raiseURIError("Malformed encodeURI input");
      }
                                       
      uint32_t V;
      if (C < 0xd800 || C > 0xdbff) {
        V = C;
      } else {
        ++itr;
        if (itr == e) {
          return runtime.raiseURIError("Malformed encodeURI input");
        }
        uint32_t kChar = *itr;
        if (kChar < 0xdc00 || kChar > 0xdfff) {
          return runtime.raiseURIError("Malformed encodeURI input");
        }
        V = (C - 0xd800) * 0x400 + (kChar - 0xdc00) + 0x10000;
      }
      char octets[UNI_MAX_UTF8_BYTES_PER_CODE_POINT];
      char *targetStart = octets;
      hermes::encodeUTF8(targetStart, V);
                                    
      uint32_t L = targetStart - octets;
      for (uint32_t j = 0; j < L; ++j) {
        auto jOctet = octets[j];
        R.push_back(u'%');
        R.push_back(toHexChar((jOctet >> 4) & 0xf));
        R.push_back(toHexChar(jOctet & 0xf));
      }
    }
    ++itr;
  }

  auto finalStr = StringPrimitive::create(runtime, R);
  if (LLVM_UNLIKELY(finalStr == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return runtime.makeHandle<StringPrimitive>(*finalStr);
}

CallResult<HermesValue> encodeURI(void *, Runtime &runtime, NativeArgs args) {
  auto strRes = toString_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto res =
      encode(runtime, runtime.makeHandle(std::move(*strRes)), unescapedURISet);
  if (res == ExecutionStatus::EXCEPTION)
    return ExecutionStatus::EXCEPTION;
  return res->getHermesValue();
}

CallResult<HermesValue>
encodeURIComponent(void *, Runtime &runtime, NativeArgs args) {
  auto strRes = toString_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto res =
      encode(runtime, runtime.makeHandle(std::move(*strRes)), uriUnescaped);
  if (res == ExecutionStatus::EXCEPTION)
    return ExecutionStatus::EXCEPTION;
  return res->getHermesValue();
}

                 
                                                              
                                                                            
static CallResult<Handle<StringPrimitive>> decode(
    Runtime &runtime,
    Handle<StringPrimitive> strHandle,
    CharSetFn reservedSet) {
  auto str = StringPrimitive::createStringView(runtime, strHandle);
  auto strLen = str.length();
  SmallU16String<32> R{};
  R.reserve(strLen);
  for (auto itr = str.begin(), e = str.end(); itr != e;) {
    char16_t C = *itr;
    if (C != u'%') {
                                     
      R.push_back(C);
    } else {
      auto start = itr;
      if (itr + 2 >= e || !(isHexChar(*(itr + 1)) && isHexChar(*(itr + 2)))) {
        return runtime.raiseURIError("Malformed decodeURI input");
      }
      uint8_t B = (fromHexChar(*(itr + 1)) << 4) | fromHexChar(*(itr + 2));
      itr += 2;
      if ((B & 0x80) == 0) {
                                          
        C = B;
        if (!reservedSet(C)) {
          R.push_back(C);
        } else {
          R.insert(R.end(), start, itr + 1);
        }
      } else {
                                          
        uint32_t n = 0;
                                                               
                                                     
        for (; n <= 8 && (((B << n) & 0x80) != 0); ++n) {
        }
        if (n == 1 || n > 4) {
          return runtime.raiseURIError("Malformed decodeURI input");
        }
                                              
        UTF8 octets[4]{B};
                                                 
        if ((itr + (3 * (n - 1))) >= e) {
          return runtime.raiseURIError("Malformed decodeURI input");
        }
                           
        for (uint32_t j = 1; j < n; ++j) {
          ++itr;
          if (*itr != u'%' ||
              !(isHexChar(*(itr + 1)) && isHexChar(*(itr + 2)))) {
            return runtime.raiseURIError("Malformed decodeURI input");
          }
          B = (fromHexChar(*(itr + 1)) << 4) | fromHexChar(*(itr + 2));
          if (((B >> 6) & 0x3) != 0x2) {
                                              
            return runtime.raiseURIError("Malformed decodeURI input");
          }
          itr += 2;
          octets[j] = B;
        }
                                              
        uint32_t V;
        const UTF8 *sourceStart = octets;
        const UTF8 *sourceEnd = octets + n;
        UTF32 *targetStart = &V;
        UTF32 *targetEnd = &V + 1;
        ConversionResult cRes = ConvertUTF8toUTF32(
            &sourceStart,
            sourceEnd,
            &targetStart,
            targetEnd,
            llvh::strictConversion);
        if (cRes != ConversionResult::conversionOK) {
          return runtime.raiseURIError("Malformed decodeURI input");
        }
        if (V < 0x10000) {
                          
          C = static_cast<char16_t>(V);
          if (!reservedSet(C)) {
            R.push_back(C);
          } else {
            R.insert(R.end(), start, itr + 1);
          }
        } else {
                         
                                                             
                                                       
          char16_t L = ((V - 0x10000) & 0x3ff) + 0xdc00;
          char16_t H = (((V - 0x10000) >> 10) & 0x3ff) + 0xd800;
          R.push_back(H);
          R.push_back(L);
        }
      }
    }
    ++itr;
  }

  return runtime.makeHandle<StringPrimitive>(
      *StringPrimitive::create(runtime, R));
}

CallResult<HermesValue> decodeURI(void *, Runtime &runtime, NativeArgs args) {
  auto strRes = toString_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto res =
      decode(runtime, runtime.makeHandle(std::move(*strRes)), reservedURISet);
  if (res == ExecutionStatus::EXCEPTION)
    return ExecutionStatus::EXCEPTION;
  return res->getHermesValue();
}

CallResult<HermesValue>
decodeURIComponent(void *, Runtime &runtime, NativeArgs args) {
  auto strRes = toString_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto emptySet = [](char16_t) { return false; };
  auto res = decode(runtime, runtime.makeHandle(std::move(*strRes)), emptySet);
  if (res == ExecutionStatus::EXCEPTION)
    return ExecutionStatus::EXCEPTION;
  return res->getHermesValue();
}

}                
}                    

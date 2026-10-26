/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                                              
                                                                                

#ifndef HERMES_REGEX_TRAITS_H
#define HERMES_REGEX_TRAITS_H

#include "hermes/Platform/Unicode/CharacterProperties.h"
#include "hermes/Platform/Unicode/PlatformUnicode.h"
#include "hermes/Regex/RegexBytecode.h"
#include "hermes/Regex/RegexTypes.h"
#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/Optional.h"

namespace hermes {
namespace regex {

                                                                       
                           
inline bool anyRangeContainsChar(
    llvh::ArrayRef<BracketRange32> ranges,
    uint32_t c) {
  for (const auto &r : ranges) {
    if (r.start <= c && c <= r.end) {
      return true;
    }
  }
  return false;
}

                                               
struct UTF16RegexTraits {
                                                 
  using CodePoint = uint32_t;

                                                                          
  using CodeUnit = char16_t;

 private:
  using CanonicalizeCache = llvh::SmallDenseMap<CodePoint, CodePoint, 16>;
  mutable CanonicalizeCache toUpperCache_;

              
  static bool isWhiteSpaceChar(CodePoint c) {
    return c == u'\u0009' || c == u'\u000B' || c == u'\u000C' ||
        c == u'\u0020' || c == u'\u00A0' || c == u'\uFEFF' || c == u'\u1680' ||
        (c >= u'\u2000' && c <= u'\u200A') || c == u'\u202F' ||
        c == u'\u205F' || c == u'\u3000';
  }

              
  static bool isLineTerminatorChar(CodePoint c) {
    return c == u'\u000A' || c == u'\u000D' || c == u'\u2028' || c == u'\u2029';
  }

 public:
                                                                        
  bool characterHasType(CodePoint c, regex::CharacterClass::Type type) const {
    switch (type) {
      case regex::CharacterClass::Digits:
        return u'0' <= c && c <= u'9';
      case regex::CharacterClass::Spaces:
        return isWhiteSpaceChar(c) || isLineTerminatorChar(c);
      case regex::CharacterClass::Words:
        return (u'a' <= c && c <= u'z') || (u'A' <= c && c <= u'Z') ||
            (u'0' <= c && c <= u'9') || (c == u'_');
    }
    llvm_unreachable("Unknown character type");
  }

                    
                                                                             
                                                    
  static CodePoint canonicalize(CodePoint c, bool unicode) {
    static_assert(
        std::numeric_limits<CodePoint>::min() == 0,
        "CodePoint must be unsigned");
                                                                              
                                                               
    if (LLVM_LIKELY(c <= 127)) {
                         
      if (('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')) {
                                                                         
                   
        c &= ~(1u << 5);             
        c |= ((uint32_t)unicode << 5);                                
      }
      return c;
    }
    return hermes::canonicalize(c, unicode);
  }

                                                                           
                                                                         
                                                         
  bool rangesContain(llvh::ArrayRef<BracketRange32> ranges, CodePoint c) const {
    return anyRangeContainsChar(ranges, c);
  }
};

                                                    
struct ASCIIRegexTraits {
                                                          
  using CodePoint = uint8_t;
  using CodeUnit = char;

  bool characterHasType(CodePoint c, regex::CharacterClass::Type type) const {
    switch (type) {
      case regex::CharacterClass::Digits:
        return '0' <= c && c <= '9';
      case regex::CharacterClass::Spaces:
        switch (c) {
          case ' ':
          case '\t':
          case '\r':
          case '\n':
          case '\v':
          case '\f':
            return true;
          default:
            return false;
        }
      case regex::CharacterClass::Words:
        return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') ||
            ('0' <= c && c <= '9') || (c == '_');
    }
    llvm_unreachable("Unknown character type");
  }

                    
                                                                       
  static CodePoint canonicalize(CodePoint c, bool unicode) {
    if (('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')) {
                                                                                
      c &= ~(1u << 5);             
      c |= ((uint32_t)unicode << 5);                                
    }
    return c;
  }

                                                            
                                                                              
  bool rangesContain(llvh::ArrayRef<BracketRange32> ranges, char16_t c) const {
    return anyRangeContainsChar(ranges, c);
  }
};

}                       
}                        

#endif

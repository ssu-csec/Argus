/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// -*- C++ -*-
//===--------------------------- regex ------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is dual licensed under the MIT and the University of Illinois Open
// Source Licenses. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef HERMES_REGEX_TYPES_H
#define HERMES_REGEX_TYPES_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/SmallString.h"

namespace hermes {

struct UnicodeRangePoolRef;

namespace regex {
namespace constants {

                

enum MatchFlagType {
                            
  matchDefault = 0,

                                                                 
  matchNotBeginningOfLine = 1 << 0,

                                                             
  matchNotEndOfLine = 1 << 1,

                                                                   
  matchInputAllAscii = 1 << 2,

                                                               
  matchOnlyAtStart = 1 << 3,
};

inline constexpr MatchFlagType operator~(MatchFlagType x) {
  return MatchFlagType(~int(x) & 0x0FFF);
}

inline constexpr MatchFlagType operator&(MatchFlagType x, MatchFlagType y) {
  return MatchFlagType(int(x) & int(y));
}

inline constexpr MatchFlagType operator|(MatchFlagType x, MatchFlagType y) {
  return MatchFlagType(int(x) | int(y));
}

inline constexpr MatchFlagType operator^(MatchFlagType x, MatchFlagType y) {
  return MatchFlagType(int(x) ^ int(y));
}

inline MatchFlagType &operator&=(MatchFlagType &x, MatchFlagType y) {
  x = x & y;
  return x;
}

inline MatchFlagType &operator|=(MatchFlagType &x, MatchFlagType y) {
  x = x | y;
  return x;
}

inline MatchFlagType &operator^=(MatchFlagType &x, MatchFlagType y) {
  x = x ^ y;
  return x;
}

enum class ErrorType {
                        
  None,

                                                      
  EscapeOverflow,

                                         
  EscapeIncomplete,

                                              
  EscapeInvalid,

                         
  UnbalancedBracket,

                         
  UnbalancedParenthesis,

                                                                        
  BraceRange,

                                             
  CharacterRange,

                              
  InvalidQuantifierBracket,

                                                                 
  InvalidRepeat,

                                                                                
  PatternExceedsParseLimits,

                                                                     
  InvalidFlags,

                                                      
  InvalidCaptureGroupName,

                                   
  DuplicateCaptureGroupName,

                                                
  InvalidNamedReference,

                                             
  NonexistentNamedCaptureReference,

                                            
  InvalidPropertyName,
};

                                                    
inline const char *messageForError(ErrorType error) {
  switch (error) {
    case ErrorType::EscapeOverflow:
      return "Escaped value too large";
    case ErrorType::EscapeIncomplete:
      return "Incomplete escape";
    case ErrorType::EscapeInvalid:
      return "Invalid escape";
    case ErrorType::UnbalancedBracket:
      return "Character class not closed";
    case ErrorType::UnbalancedParenthesis:
      return "Parenthesized expression not closed";
    case ErrorType::BraceRange:
      return "Quantifier range out of order";
    case ErrorType::CharacterRange:
      return "Character class range out of order";
    case ErrorType::InvalidQuantifierBracket:
      return "Invalid quantifier bracket";
    case ErrorType::InvalidRepeat:
      return "Quantifier has nothing to repeat";
    case ErrorType::PatternExceedsParseLimits:
      return "Pattern exceeds parse limits";
    case ErrorType::InvalidFlags:
      return "Invalid flags";
    case ErrorType::InvalidCaptureGroupName:
      return "Invalid capture group name";
    case ErrorType::DuplicateCaptureGroupName:
      return "Duplicate capture group name";
    case ErrorType::InvalidNamedReference:
      return "Invalid named reference";
    case ErrorType::NonexistentNamedCaptureReference:
      return "Nonexistent named capture reference";
    case ErrorType::InvalidPropertyName:
      return "Invalid property name";
    case ErrorType::None:
      return "No error";
  }
  llvm_unreachable("Unknown error");
  return nullptr;
}

                                               
                                                           
constexpr uint16_t kMaxCaptureGroupCount = 65535;

                                      
constexpr uint16_t kMaxLoopCount = 65535;

}                       

                                                                              
                                                               
                                                                          
enum MatchConstraintFlags : uint8_t {
                                                                           
                          
  MatchConstraintNonASCII = 1 << 0,

                                                                                
                   
  MatchConstraintAnchoredAtStart = 1 << 1,

                                                                       
  MatchConstraintNonEmpty = 1 << 2,
};

                                                
inline bool isASCII(uint32_t c) {
  return c <= 127;
}

                                                     
struct CharacterClass {
  enum Type : uint8_t {
    Digits = 1 << 0,         
    Spaces = 1 << 1,         
    Words = 1 << 2,         
  } type_;

                                                      
  bool inverted_;

  CharacterClass(Type type, bool invert) : type_(type), inverted_(invert) {}
};

                                                    
struct CharacterClassCodepointRanges {
  llvh::ArrayRef<UnicodeRangePoolRef> rangeArray;

                                                      
  bool inverted_;

  CharacterClassCodepointRanges(
      llvh::ArrayRef<UnicodeRangePoolRef> rangeArray,
      bool inverted)
      : rangeArray(rangeArray), inverted_(inverted) {}
};

                                                                           
class SyntaxFlags {
 private:
                                                                              
                     
  enum : uint8_t {
    ICASE = 1 << 0,
    GLOBAL = 1 << 1,
    MULTILINE = 1 << 2,
    UCODE = 1 << 3,
    DOTALL = 1 << 4,
    STICKY = 1 << 5,
    INDICES = 1 << 6,
  };

 public:
                                                                               
                                                                   
                                                                      
  uint8_t ignoreCase : 1;
  uint8_t global : 1;
  uint8_t multiline : 1;
  uint8_t unicode : 1;
  uint8_t dotAll : 1;
  uint8_t sticky : 1;
  uint8_t hasIndices : 1;

                                                                              
                                                                          
  uint8_t toByte() const {
    uint8_t ret = 0;
    if (global)
      ret |= GLOBAL;
    if (ignoreCase)
      ret |= ICASE;
    if (multiline)
      ret |= MULTILINE;
    if (unicode)
      ret |= UCODE;
    if (sticky)
      ret |= STICKY;
    if (dotAll)
      ret |= DOTALL;
    if (hasIndices)
      ret |= INDICES;
    return ret;
  }

                                                                             
                                                                        
               
  static SyntaxFlags fromByte(uint8_t byte) {
    SyntaxFlags ret = {};
    if (byte & GLOBAL)
      ret.global = 1;
    if (byte & ICASE)
      ret.ignoreCase = 1;
    if (byte & MULTILINE)
      ret.multiline = 1;
    if (byte & UCODE)
      ret.unicode = 1;
    if (byte & STICKY)
      ret.sticky = 1;
    if (byte & DOTALL)
      ret.dotAll = 1;
    if (byte & INDICES)
      ret.hasIndices = 1;
    return ret;
  }

                                             
                                                                       
                                                                               
                                                                     
                  
  llvh::SmallString<7> toString() const {
    llvh::SmallString<7> result;
    if (hasIndices)
      result.push_back('d');
    if (global)
      result.push_back('g');
    if (ignoreCase)
      result.push_back('i');
    if (multiline)
      result.push_back('m');
    if (dotAll)
      result.push_back('s');
    if (unicode)
      result.push_back('u');
    if (sticky)
      result.push_back('y');
    return result;
  }

                                                                         
                                                                           
                                                            
  static llvh::Optional<SyntaxFlags> fromString(
      const llvh::ArrayRef<char16_t> flags) {
                                                                            
    auto error = llvh::NoneType::None;
    SyntaxFlags ret = {};
    for (auto c : flags) {
      switch (c) {
        case u'i':
          if (ret.ignoreCase)
            return error;
          ret.ignoreCase = 1;
          break;
        case u'm':
          if (ret.multiline)
            return error;
          ret.multiline = 1;
          break;
        case u'g':
          if (ret.global)
            return error;
          ret.global = 1;
          break;
        case u'u':
          if (ret.unicode)
            return error;
          ret.unicode = 1;
          break;
        case u'y':
          if (ret.sticky)
            return error;
          ret.sticky = 1;
          break;
        case u's':
          if (ret.dotAll)
            return error;
          ret.dotAll = 1;
          break;
        case u'd':
          if (ret.hasIndices)
            return error;
          ret.hasIndices = 1;
          break;
        default:
          return error;
      }
    }
    return ret;
  }
};
}                   
}                    
#endif                        

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PLATFORMUNICODE_CHARACTERPROPERTIES_H
#define HERMES_PLATFORMUNICODE_CHARACTERPROPERTIES_H

#include <cassert>
#include <cstdint>
#include <string>

#include "llvh/ADT/ArrayRef.h"

namespace hermes {

const uint32_t UNICODE_MAX_VALUE = 0x10FFFF;
                                     
const uint32_t UNICODE_SURROGATE_FIRST = 0xD800;
                                                          
const uint32_t UNICODE_SURROGATE_LAST = 0xDFFF;
const uint32_t UTF16_HIGH_SURROGATE = 0xD800;
const uint32_t UTF16_LOW_SURROGATE = 0xDC00;
const uint32_t UNICODE_REPLACEMENT_CHARACTER = 0xFFFD;
                               
const uint32_t UNICODE_LAST_BMP = 0xFFFF;

const uint32_t UNICODE_LINE_SEPARATOR = 0x2028;
const uint32_t UNICODE_PARAGRAPH_SEPARATOR = 0x2029;

const uint32_t UNICODE_ZWNJ = 0x200C;
const uint32_t UNICODE_ZWJ = 0x200D;

                                                                
                                                                                
                                                                              
                                                                         
                                                           
const uint32_t UNICODE_MAX_PRECANONICALIZATIONS = 3;

inline bool isValidCodePoint(uint32_t cp) {
  return !(
      (cp >= UNICODE_SURROGATE_FIRST && cp <= UNICODE_SURROGATE_LAST) ||
      cp > UNICODE_MAX_VALUE);
}

                                                                  
                                                        
inline bool isMemberOfBMP(uint32_t cp) {
  return cp <= UNICODE_LAST_BMP;
}

                                           
inline bool isHighSurrogate(uint32_t cp) {
  return UNICODE_SURROGATE_FIRST <= cp && cp < UTF16_LOW_SURROGATE;
}

                                          
inline bool isLowSurrogate(uint32_t cp) {
  return UTF16_LOW_SURROGATE <= cp && cp <= UNICODE_SURROGATE_LAST;
}

                                                                                
              

                                                                  
inline uint32_t utf16SurrogatePairToCodePoint(uint32_t lead, uint32_t trail) {
  assert(
      isHighSurrogate(lead) && isLowSurrogate(trail) && "Not a surrogate pair");
  return ((lead - UTF16_HIGH_SURROGATE) << 10) + (trail - UTF16_LOW_SURROGATE) +
      0x10000;
}

                                                                       
bool isUnicodeOnlyLetter(uint32_t cp);
                                                                      
bool isUnicodeOnlySpace(uint32_t cp);
                                                               
                                      
bool isUnicodeCombiningMark(uint32_t cp);
                                                                    
bool isUnicodeDigit(uint32_t cp);
                                                                           
bool isUnicodeConnectorPunctuation(uint32_t cp);

                                                                         
inline bool isASCIIIdentifierStart(uint32_t ch) {
  return ch == '_' || ch == '$' || ((ch | 32) >= 'a' && (ch | 32) <= 'z');
}

                                                            
inline bool isUnicodeIDStart(uint32_t cp) {
  return isASCIIIdentifierStart(cp) || isUnicodeOnlyLetter(cp);
}

                                                               
inline bool isUnicodeIDContinue(uint32_t cp) {
                                                   
  return isUnicodeIDStart(cp) || isUnicodeCombiningMark(cp) ||
      isUnicodeDigit(cp) || isUnicodeConnectorPunctuation(cp) ||
      cp == UNICODE_ZWNJ || cp == UNICODE_ZWJ;
}

                                                                     
inline bool isUnicodePropertyName(uint32_t ch) {
  return ch == '_' || ((ch | 32) >= 'a' && (ch | 32) <= 'z');
}

                                                                      
inline bool isUnicodePropertyValue(uint32_t ch) {
  return isUnicodePropertyName(ch) || isUnicodeDigit(ch);
}

                                                                       
uint32_t canonicalize(uint32_t cp, bool unicode);

class CodePointSet;
                                                                               
                                                      
CodePointSet makeCanonicallyEquivalent(const CodePointSet &set, bool unicode);

struct UnicodeRangePoolRef;

                                                                       
                 
llvh::ArrayRef<UnicodeRangePoolRef> unicodePropertyRanges(
    std::string_view propertyName,
    std::string_view propertyValue);

                                                                               
                                          
void addRangeArrayPoolToBracket(
    CodePointSet *receiver,
    const llvh::ArrayRef<UnicodeRangePoolRef> rangeArrayPool,
    bool inverted);

}                    

#endif                                                

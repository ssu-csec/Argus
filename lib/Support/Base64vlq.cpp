/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Support/Base64vlq.h"

namespace hermes {

namespace base64vlq {

static constexpr uint32_t Base64Count = 64;
static constexpr const char Base64Chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                                                                  
static_assert(
    sizeof(Base64Chars) == Base64Count + 1,
    "Base64Chars has unexpected length");

                              
                                                                 
static OptValue<uint32_t> base64Decode(char c) {
                                                                       
  for (const char &bc : Base64Chars) {
    if (c == bc)
      return &bc - &Base64Chars[0];
  }
  return llvh::None;
}

                                                                             
enum {
                                     
  DigitWidth = 5,

                                                          
  DigitMask = (1 << DigitWidth) - 1,

                                        
  ContinuationFlag = 1 << DigitWidth,

                                                                      
  SignBit = 1,
};

llvh::raw_ostream &encode(llvh::raw_ostream &OS, int32_t value) {
                                                                           
                                                               
  int64_t wideVal = value;
  wideVal *= 2;
  if (wideVal < 0)
    wideVal = -wideVal | SignBit;
  assert(wideVal >= 0 && "wideVal should not be negative any more");
  do {
    auto digit = wideVal & DigitMask;
    wideVal >>= DigitWidth;
    if (wideVal > 0)
      digit |= ContinuationFlag;
    assert(digit < Base64Count && "digit cannot exceed Base64 character count");
    OS << Base64Chars[digit];
  } while (wideVal > 0);
  return OS;
}

OptValue<int32_t> decode(const char *&begin, const char *end) {
  int64_t result = 0;
  for (const char *cursor = begin; cursor < end; cursor++) {
    OptValue<uint32_t> word = base64Decode(*cursor);
    int32_t shift = DigitWidth * (cursor - begin);

                                                                               
                                                                            
    if (!word || shift > 32)
      return llvh::None;

                                                                  
    int64_t digit = *word & DigitMask;
    result |= (digit << shift);

                                               
    if (*word & ContinuationFlag)
      continue;

                                                            
                                                                         
    if (result & SignBit) {
      result = -result;
    }
    result /= 2;

                          
    if (result > INT32_MAX || result < INT32_MIN)
      return llvh::None;

                                                                 
    begin = cursor + 1;
    return int32_t(result);
  }
                                                                            
  return llvh::None;
}

}                       

}                    

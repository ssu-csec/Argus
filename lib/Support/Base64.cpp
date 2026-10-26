/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Support/Base64.h"

namespace hermes {

                                                                 
static constexpr unsigned char decMap[128] = {
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 62, 64, 64, 64, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60,
    61, 64, 64, 64, 64, 64, 64, 64, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64,
    64, 64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
    43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64};

llvh::Optional<std::string> base64Decode(llvh::StringRef input) {
  size_t inputLen = input.size();

                               
                                                    
  size_t outputLen = inputLen / 4 * 3;

                                               
  if (inputLen % 4 == 0) {
                                                                            
    if (input[inputLen - 1] == '=')
      outputLen--;
    if (input[inputLen - 2] == '=')
      outputLen--;
  } else {
                                                                      
    switch (inputLen % 4) {
      case 1:
        return llvh::None;
      case 2:
        outputLen++;
        break;
      case 3:
        outputLen += 2;
        break;
    }
  }

                                                   
  std::string output(outputLen, '\0');

                                                                               
                                                                            
                                          
  unsigned buf = 0;
  unsigned bufSize = 0;
  size_t i = 0;
  for (const unsigned char c : input) {
    if (LLVM_UNLIKELY(c > 127))
      return llvh::None;

    if (LLVM_UNLIKELY(c == '=')) {
                                     
      if (i < outputLen) {
        return llvh::None;
      } else {
        break;
      }
    }

    unsigned char sextet = decMap[c];
    if (LLVM_UNLIKELY(sextet >= 64)) {
      return llvh::None;
    } else {
                                         
      buf = (buf << 6) + sextet;
      bufSize += 6;

                                                                          
      if (bufSize >= 8) {
        output[i++] = (char)(buf >> (bufSize - 8));
        bufSize -= 8;
      }
    }
  }

  return output;
}

llvh::Optional<std::string> parseJSONBase64DataURL(llvh::StringRef url) {
          
  if (!url.consume_front("data:"))
    return llvh::None;

                  
                                            
  if (!url.consume_front("application/json"))
    return llvh::None;

               
                                                  
  if (!url.consume_front(";base64,"))
    return llvh::None;

           
  return base64Decode(url);
}

}                    

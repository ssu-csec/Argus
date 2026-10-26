/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "IntlUtils.h"

namespace hermes {
namespace platform_intl {
namespace impl_icu {

static constexpr char REPLACEMENT_CHARACTER = '?';

std::string toUTF8ASCII(std::u16string_view utf16Source) {
                                                                            
                                                                                
  std::string result;
  for (const char16_t codeUnit : utf16Source) {
    if (codeUnit <= 0x7f) {
      result.push_back(static_cast<char>(codeUnit));
    } else {
      result.push_back(REPLACEMENT_CHARACTER);
    }
  }
  return result;
}

std::u16string toUTF16ASCII(std::string_view utf8Source) {
                                                                               
                                                                         
  std::u16string result;
  for (const unsigned char c : utf8Source) {
    if (c <= 0x7f) {
      result.push_back(static_cast<char16_t>(c));
    } else {
      result.push_back(static_cast<char16_t>(REPLACEMENT_CHARACTER));
    }
  }
  return result;
}

bool convertToBool(const std::string &str) {
  return (toLowerASCII(str) == "true");
}

bool convertToBool(std::u16string_view str) {
  return convertToBool(toUTF8ASCII(str));
}

std::string toLowerASCII(std::string str) {
  constexpr std::uint8_t offset = 'a' - 'A';
  for (char &c : str) {
    if (c >= 'A' && c <= 'Z') {
      c += offset;
    }
  }
  return str;
}

}                      
}                           
}                    

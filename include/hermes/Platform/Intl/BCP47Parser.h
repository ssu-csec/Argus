/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCP47_PARSER_H
#define HERMES_BCP47_PARSER_H

#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace hermes {
namespace platform_intl {

bool isUnicodeExtensionType(const std::u16string &);

struct ParsedLocaleIdentifier {
                                                                     
                                     
  static std::optional<ParsedLocaleIdentifier> parse(
      const std::u16string &localeId);
                                                                         
                
  std::u16string canonicalize() const;

  struct ParsedLanguageIdentifier {
    std::u16string languageSubtag;
    std::u16string scriptSubtag;
    std::u16string regionSubtag;
    std::set<std::u16string> variantSubtagList;
  };

  ParsedLanguageIdentifier languageIdentifier;
  std::set<std::u16string> unicodeExtensionAttributes;
  std::map<std::u16string, std::u16string> unicodeExtensionKeywords;
  ParsedLanguageIdentifier transformedLanguageIdentifier;
  std::map<std::u16string, std::u16string> transformedExtensionFields;
  std::map<char16_t, std::u16string> otherExtensionMap;
  std::u16string puExtensions;
};

}                           
}                    

#endif

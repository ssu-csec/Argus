/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_REGEX_REGEXSERIALIZATION_H
#define HERMES_REGEX_REGEXSERIALIZATION_H

#include "hermes/Regex/RegexSupport.h"
#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/Optional.h"
#include "llvh/ADT/StringRef.h"

#include <deque>
#include <memory>
#include <string>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace llvh {
class raw_ostream;
}

                                             
namespace hermes {

                                                                              
             
using RegExpBytecode = std::vector<unsigned char>;

                                                                       
struct RegExpTableEntry {
  uint32_t offset;
  uint32_t length;
};

                                                         
void dumpRegexBytecode(llvh::ArrayRef<uint8_t> bytes, llvh::raw_ostream &OS);

                                                                             
                
class CompiledRegExp {
 public:
  ~CompiledRegExp();
  CompiledRegExp(CompiledRegExp &&);
  CompiledRegExp &operator=(CompiledRegExp &&);

                                                                           
                                                                              
                                                                             
                             
  static llvh::Optional<CompiledRegExp> tryCompile(
      llvh::StringRef pattern,
      llvh::StringRef flags,
      llvh::StringRef *outError = nullptr);

  llvh::StringRef getPattern() const {
    return pattern_;
  }

  llvh::StringRef getFlags() const {
    return flags_;
  }

  regex::ParsedGroupNamesMapping &getMapping() {
    return mapping_;
  }

  std::deque<llvh::SmallVector<char16_t, 5>> &getOrderedGroupNames() {
    return orderedGroupNames_;
  }

                                                        
  llvh::ArrayRef<uint8_t> getBytecode() const;

 private:
  std::vector<uint8_t> bytecode_;
  std::string pattern_;
  std::string flags_;
  std::deque<llvh::SmallVector<char16_t, 5>> orderedGroupNames_;
  regex::ParsedGroupNamesMapping mapping_;
  CompiledRegExp(
      std::vector<uint8_t> bytecode,
      std::string pattern,
      std::string flags,
      std::deque<llvh::SmallVector<char16_t, 5>> &&orderedGroupNames,
      regex::ParsedGroupNamesMapping &&mapping_);
  CompiledRegExp(const CompiledRegExp &) = delete;
  void operator=(const CompiledRegExp &) = delete;
};

                                                     
class UniquingRegExpTable {
                                           
  std::vector<CompiledRegExp *> regexps_;

                                                                           
                                                                               
                                                                          
                                                                        
  using KeyType = std::pair<llvh::StringRef, llvh::StringRef>;

                                                                       
                                                            
  llvh::DenseMap<KeyType, uint32_t> keysToIndex_;

                                              
  UniquingRegExpTable(const UniquingRegExpTable &) = delete;
  void operator=(const UniquingRegExpTable &) = delete;

 public:
  UniquingRegExpTable() = default;

                                                        
                                   
  uint32_t addRegExp(CompiledRegExp *regexp) {
    auto iter = keysToIndex_.find(keyFor(*regexp));
    if (iter != keysToIndex_.end())
      return iter->second;

    uint32_t index = regexps_.size();
    regexps_.push_back(regexp);
    keysToIndex_[keyFor(*regexps_.back())] = index;
    return index;
  }

                                         
  bool empty() const {
    return regexps_.empty();
  }

                                   
  std::vector<RegExpTableEntry> getEntryList() const;

                                          
  RegExpBytecode getBytecodeBuffer() const;

                                                                                
  void disassemble(llvh::raw_ostream &OS) const;

 private:
  KeyType keyFor(const CompiledRegExp &re) const {
    return {re.getPattern(), re.getFlags()};
  }
};

}                    
#pragma GCC diagnostic pop

#endif

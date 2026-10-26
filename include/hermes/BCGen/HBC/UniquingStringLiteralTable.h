/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_HBC_UNIQUINGSTRINGLITERALTABLE_H
#define HERMES_BCGEN_HBC_UNIQUINGSTRINGLITERALTABLE_H

#include "hermes/BCGen/HBC/ConsecutiveStringStorage.h"
#include "hermes/BCGen/HBC/StringKind.h"

namespace hermes {
namespace hbc {

                                                                             
                                                                             
                                          
struct StringLiteralIDMapping {
                                                   
  inline size_t count() const;

                                                                
  inline bool empty() const;

  StringLiteralIDMapping() = default;

                                                                              
                                                                                
                                                                               
                                                        
  explicit StringLiteralIDMapping(
      ConsecutiveStringStorage storage,
      std::vector<bool> isIdentifier);

 protected:
                                                        
  ConsecutiveStringStorage storage_;

                                      
  StringSetVector strings_;

                                                                               
                                                       
  std::vector<bool> isIdentifier_;
};

                                                                                
                                                                                
                              
struct StringLiteralTable final : public StringLiteralIDMapping {
  StringLiteralTable() = default;
  using StringLiteralIDMapping::StringLiteralIDMapping;

                                                              
  inline uint32_t getStringID(llvh::StringRef str) const;

                                                                             
                              
  inline uint32_t getIdentifierID(llvh::StringRef str) const;

                                                                               
  inline std::vector<StringTableEntry> acquireStringTable();
  inline std::vector<unsigned char> acquireStringStorage();

                                                                      
                                                            
  std::vector<uint32_t> getIdentifierHashes() const;

                                                                              
                                                                            
                                                                              
                                                                            
                        
  std::vector<StringKind::Entry> getStringKinds() const;
};

                                                                         
                                                                              
                                                                               
             
class UniquingStringLiteralAccumulator final : public StringLiteralIDMapping {
                                                                                
                                                                           
                                                                               
                                                                        
                                                         
  std::vector<size_t> numIdentifierRefs_;

 public:
  UniquingStringLiteralAccumulator() = default;
  using StringLiteralIDMapping::StringLiteralIDMapping;

                                                                               
                                                                     
                 
  inline void addString(llvh::StringRef str, bool isIdentifier);

                                                                           
                                                                        
                                                                            
                                                                            
  static StringLiteralTable toTable(
      UniquingStringLiteralAccumulator strings,
      bool optimize = false);
};

inline size_t StringLiteralIDMapping::count() const {
  return strings_.size();
}

inline bool StringLiteralIDMapping::empty() const {
  return strings_.size() == 0;
}

inline uint32_t StringLiteralTable::getStringID(llvh::StringRef str) const {
  auto iter = strings_.find(str);
  assert(
      iter != strings_.end() &&
      "The requested string is not in the mapping.  Is the part of the IR that "
      "introduces it being traversed by one of the functions in "
      "TraverseLiteralStrings.h ?");
  return std::distance(strings_.begin(), iter);
}

inline uint32_t StringLiteralTable::getIdentifierID(llvh::StringRef str) const {
  auto idx = getStringID(str);
  assert(
      isIdentifier_[idx] &&
      "The requested string exists in the mapping but was not marked as an "
      "identifier.  When it was added to the mapping during a call to one "
      "of the traversal functions in TraverseLiteralStrings.h, was the usage "
      "of the string as an identifier correctly traversed?");
  return idx;
}

inline std::vector<StringTableEntry> StringLiteralTable::acquireStringTable() {
  return storage_.acquireStringTable();
}

inline std::vector<unsigned char> StringLiteralTable::acquireStringStorage() {
  return storage_.acquireStringStorage();
}

inline void UniquingStringLiteralAccumulator::addString(
    llvh::StringRef str,
    bool isIdentifier) {
  assert(strings_.size() == isIdentifier_.size());
  const auto fresh = strings_.size();
  auto id = strings_.insert(str);
  if (id == fresh) {
    isIdentifier_.push_back(false);
    numIdentifierRefs_.push_back(0);
  }

  if (isIdentifier) {
    isIdentifier_[id] = true;
    if (id >= storage_.count()) {
                                                                          
                    
      numIdentifierRefs_[id - storage_.count()]++;
    }
  }
}

}                 
}                    

#endif                                                 

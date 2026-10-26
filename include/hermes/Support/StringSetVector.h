/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_STRINGSETVECTOR_H
#define HERMES_SUPPORT_STRINGSETVECTOR_H

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/StringRef.h"

#include <deque>
#include <limits>
#include <string>

namespace hermes {

                                                                           
                                                                       
                                                           
struct StringSetVector final {
  using iterator = std::deque<std::string>::iterator;
  using const_iterator = std::deque<std::string>::const_iterator;
  using size_type = std::deque<std::string>::size_type;

  StringSetVector() = default;

                     
  StringSetVector(StringSetVector &&) = default;
  StringSetVector &operator=(StringSetVector &&) = default;

                          
  StringSetVector(const StringSetVector &) = delete;
  StringSetVector &operator=(const StringSetVector &) = delete;

                                                                       
                                                    
  inline size_type insert(llvh::StringRef str);

                                                                              
                         
  inline iterator find(llvh::StringRef str);
  inline const_iterator find(llvh::StringRef str) const;

                                                                             
                              
  inline const std::string &operator[](size_type i) const;

  inline size_type size() const;
  inline bool empty() const;

  inline iterator begin();
  inline const_iterator begin() const;

  inline iterator end();
  inline const_iterator end() const;

 private:
                                                                               
                                                                              
                                                                              
                                                                               
                                   
  std::deque<std::string> stringsStorage_;

                                                                             
                                                                       
  using index_type = uint32_t;
  llvh::DenseMap<llvh::StringRef, index_type> stringsToIndex_;
};

inline StringSetVector::size_type StringSetVector::insert(llvh::StringRef str) {
  assert(stringsToIndex_.size() == stringsStorage_.size());
  auto it = stringsToIndex_.find(str);
  if (it != stringsToIndex_.end()) {
    return it->second;
  }

  size_type storageSize = stringsStorage_.size();
  assert(
      storageSize < std::numeric_limits<index_type>::max() &&
      "StringSetVector cannot store that many elements");
  auto newIdx = static_cast<index_type>(storageSize);
  assert(storageSize == newIdx && "casted value unexpectedly different");
  stringsStorage_.emplace_back(str.begin(), str.end());
  auto inserted = stringsToIndex_.insert({stringsStorage_.back(), newIdx});
  assert(inserted.second && "String already exists as key in mapping.");
  (void)inserted;

  return storageSize;
}

inline StringSetVector::iterator StringSetVector::find(llvh::StringRef str) {
  auto it = stringsToIndex_.find(str);
  if (it == stringsToIndex_.end()) {
    return end();
  }

  return stringsStorage_.begin() + it->second;
}

inline StringSetVector::const_iterator StringSetVector::find(
    llvh::StringRef str) const {
  return const_cast<StringSetVector *>(this)->find(str);
}

inline const std::string &StringSetVector::operator[](size_t i) const {
  return stringsStorage_[i];
}

inline size_t StringSetVector::size() const {
  return stringsStorage_.size();
}

inline bool StringSetVector::empty() const {
  return size() == 0;
}

inline StringSetVector::iterator StringSetVector::begin() {
  return stringsStorage_.begin();
}

inline StringSetVector::const_iterator StringSetVector::begin() const {
  return stringsStorage_.begin();
}

inline StringSetVector::iterator StringSetVector::end() {
  return stringsStorage_.end();
}

inline StringSetVector::const_iterator StringSetVector::end() const {
  return stringsStorage_.end();
}

}                    

#endif                                    

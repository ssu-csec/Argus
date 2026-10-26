/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_STRINGTABLE_H
#define HERMES_SUPPORT_STRINGTABLE_H

#include "hermes/Support/Allocator.h"

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/StringRef.h"

namespace llvh {
class raw_ostream;
}                  

namespace hermes {

                                                             
template <class Allocator>
llvh::StringRef zeroTerminate(Allocator &allocator, llvh::StringRef str) {
                                                                       
  auto *s = allocator.template Allocate<char>(str.size() + 1);
  auto end = std::copy(str.begin(), str.end(), s);
  *end = 0;                          

                                       
  return llvh::StringRef(s, str.size());
}

class UniqueString {
  const llvh::StringRef str_;

  UniqueString(const UniqueString &) = delete;
  UniqueString &operator=(const UniqueString &) = delete;

 public:
  explicit UniqueString(llvh::StringRef str) : str_(str) {};

  const llvh::StringRef &str() const {
    return str_;
  }
  const char *c_str() const {
    return str_.begin();
  }

  explicit operator llvh::StringRef() const {
    return str_;
  }
};

                                                                             
                                                                               
                           
class Identifier {
 public:
  using PtrType = UniqueString *;

  explicit Identifier() = default;

 private:
  PtrType ptr_{nullptr};

  explicit Identifier(PtrType ptr) : ptr_(ptr) {}

 public:
  bool isValid() const {
    return ptr_ != nullptr;
  }

                                                                               
                                                 
  PtrType getUnderlyingPointer() const {
    return ptr_;
  }

  static Identifier getFromPointer(UniqueString *ptr) {
    return Identifier(ptr);
  }

  bool operator==(Identifier RHS) const {
    return ptr_ == RHS.ptr_;
  }
  bool operator!=(Identifier RHS) const {
    return !(*this == RHS);
  }

  const llvh::StringRef &str() const {
    return ptr_->str();
  }
  const char *c_str() const {
    return ptr_->c_str();
  }
};

llvh::raw_ostream &operator<<(llvh::raw_ostream &os, Identifier id);

                                                                  
                                                                             
                                
class StringTable {
  using Allocator = hermes::BumpPtrAllocator;
  Allocator &allocator_;

  llvh::DenseMap<llvh::StringRef, UniqueString *> strMap_{};

  StringTable(const StringTable &) = delete;
  StringTable &operator=(const StringTable &_) = delete;

 public:
  explicit StringTable(Allocator &allocator) : allocator_(allocator) {};

                                                                          
  UniqueString *getString(llvh::StringRef name) {
                          
    auto it = strMap_.find(name);
    if (it != strMap_.end())
      return it->second;

                                                    
    auto *str = new (allocator_.Allocate<UniqueString>())
        UniqueString(zeroTerminate(allocator_, name));
    strMap_.insert({str->str(), str});
    return str;
  }

                                                          
  Identifier getIdentifier(llvh::StringRef name) {
    return Identifier::getFromPointer(getString(name));
  }
};

}                    

                                       
namespace llvh {

template <>
struct DenseMapInfo<hermes::Identifier> {
  static inline hermes::Identifier getEmptyKey() {
    return hermes::Identifier::getFromPointer(
        DenseMapInfo<hermes::UniqueString *>::getEmptyKey());
  }
  static inline hermes::Identifier getTombstoneKey() {
    return hermes::Identifier::getFromPointer(
        DenseMapInfo<hermes::UniqueString *>::getTombstoneKey());
  }
  static inline unsigned getHashValue(hermes::Identifier id) {
    return DenseMapInfo<hermes::UniqueString *>::getHashValue(
        id.getUnderlyingPointer());
  }
  static inline bool isEqual(hermes::Identifier a, hermes::Identifier b) {
    return a == b;
  }
};

}                  

#endif                                

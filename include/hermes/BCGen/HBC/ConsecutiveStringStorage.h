/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_STRINGSTORAGE_H
#define HERMES_SUPPORT_STRINGSTORAGE_H

#include "hermes/Support/OptValue.h"
#include "hermes/Support/StringSetVector.h"
#include "hermes/Support/StringTableEntry.h"

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/DenseSet.h"
#include "llvh/ADT/StringRef.h"

#include <cstdint>
#include <deque>
#include <iterator>
#include <string>
#include <vector>

namespace hermes {
namespace hbc {

                                                                            
                                                              
                                          
                                      
llvh::StringRef getStringFromEntry(
    const StringTableEntry &entry,
    llvh::ArrayRef<unsigned char> storage,
    std::string &utf8ConversionStorage);

                                                              
class ConsecutiveStringStorage {
  ConsecutiveStringStorage &operator=(const ConsecutiveStringStorage &_) =
      delete;

  ConsecutiveStringStorage(const ConsecutiveStringStorage &) = delete;

 public:
  using StringTableRefTy = StringTableEntry::StringTableRefTy;
  using MutStringTableRefTy = StringTableEntry::MutStringTableRefTy;
  using StringStorageRefTy = StringTableEntry::StringStorageRefTy;

 private:
                                                                  
  std::vector<StringTableEntry> strTable_{};

                                              
  std::vector<unsigned char> storage_{};

                                                     
  bool isTableValid_{true};

                                                       
  bool isStorageValid_{true};

  inline void ensureTableValid() const {
    assert(isTableValid_ && "String Table no longer valid");
  }
  inline void ensureStorageValid() const {
    assert(isStorageValid_ && "String Storage no longer valid");
  }

 public:
  ConsecutiveStringStorage() = default;
  ConsecutiveStringStorage(ConsecutiveStringStorage &&) = default;
  ConsecutiveStringStorage &operator=(ConsecutiveStringStorage &&) = default;

                                                                      
                                                              
                                                                         
                                                                       
                                                      
  template <typename I, typename Force8Bit>
  ConsecutiveStringStorage(I begin, I end, Force8Bit, bool optimize);

                                              
  explicit ConsecutiveStringStorage(
      llvh::ArrayRef<llvh::StringRef> strings,
      bool optimize = false)
      : ConsecutiveStringStorage(
            strings.begin(),
            strings.end(),
            std::false_type{},
            optimize) {}

                                         
  ConsecutiveStringStorage(
      std::vector<StringTableEntry> &&table,
      std::vector<unsigned char> &&storage)
      : strTable_(std::move(table)), storage_(std::move(storage)) {}

                                           
  StringTableRefTy getStringTableView() const {
    ensureTableValid();
    return strTable_;
  }

  MutStringTableRefTy getStringTableView() {
    ensureTableValid();
    return strTable_;
  }

                                                               
  size_t count() const {
    ensureTableValid();
    return strTable_.size();
  }

                                                                            
                                                                         
                                                       
  std::vector<StringTableEntry> acquireStringTable() {
    ensureTableValid();
    isTableValid_ = false;
    return std::move(strTable_);
  };

                                                                              
                                                                         
                                                       
  std::vector<unsigned char> acquireStringStorage() {
    ensureStorageValid();
    isStorageValid_ = false;
    return std::move(storage_);
  }

                                                                            
                                      
  uint32_t getEntryHash(size_t i) const;

                              
  void appendStorage(ConsecutiveStringStorage &&rhs);

                                                                           
                                                          
                                                                       
                 
  llvh::StringRef getStringAtIndex(
      uint32_t idx,
      std::string &utf8ConversionStorage) const;
};

}                 
}                    

#endif                                  

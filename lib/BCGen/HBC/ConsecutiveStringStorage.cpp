/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "stringstorage"
#include "hermes/BCGen/HBC/ConsecutiveStringStorage.h"

#include "hermes/BCGen/HBC/BytecodeDataProvider.h"
#include "hermes/Support/HashString.h"
#include "hermes/Support/JenkinsHash.h"
#include "hermes/Support/Statistic.h"
#include "hermes/Support/Timer.h"
#include "hermes/Support/UTF8.h"

#include "llvh/ADT/DenseMap.h"
#include "llvh/Support/Endian.h"

#include <algorithm>
#include <climits>
#include <deque>

using namespace hermes;
using llvh::ArrayRef;
using llvh::MutableArrayRef;

STATISTIC(StringTableSize, "Size of the packed String table");
STATISTIC(
    StringTableSavings,
    "Byte savings in length of String table versus naive packing");

namespace {

                                       
constexpr const char *const StringTableTimersName = "StringTableBuilder Timers";

constexpr size_t npos = ~size_t(0);

                                              
constexpr size_t kMaximumPackableStringLength = 24 * 1024;

                                                                               
                                                                              
                                                       
template <typename CharT>
class StringPacker {
  StringPacker() = default;

 public:
                                              
  struct StringEntry {
                                                  
    uint32_t stringID_;

                           
    ArrayRef<CharT> chars_;

                                                     
                                  
    size_t offsetInStorage_ = npos;

                                                                   

                                                                         
                                     
    StringEntry *parent_ = nullptr;
    size_t offsetInParent_ = npos;

                                                   
    StringEntry *next_ = nullptr;

                                                    
    StringEntry *prev_ = nullptr;

                                                               
    size_t overlapAmount_ = 0;

                                                                              
                
    llvh::DenseSet<const StringEntry *> potentialCycles_;

    StringEntry(uint32_t stringID, ArrayRef<CharT> chars)
        : stringID_(stringID), chars_(chars) {}
  };

                                                   
                                                                          
                                                                     
  using Trigram =
      typename std::conditional<sizeof(CharT) == 1, uint32_t, uint64_t>::type;

  static constexpr size_t TrigramCharCount = 3;

                                                                            
  static inline Trigram makeTrigram(const CharT chars[TrigramCharCount]) {
    unsigned shift = CHAR_BIT * sizeof(CharT);
    return (Trigram(chars[0]) << (2 * shift)) |
        (Trigram(chars[1]) << (1 * shift)) | (Trigram(chars[2]) << (0 * shift));
  }

                                                                              
  static llvh::DenseSet<Trigram> buildPrefixTrigramSet(
      ArrayRef<StringEntry> strings) {
                                                                               
    llvh::DenseSet<Trigram> result(strings.size() / 8);
    for (const StringEntry &entry : strings) {
      ArrayRef<CharT> chars = entry.chars_;
      if (chars.size() >= TrigramCharCount) {
        result.insert(makeTrigram(chars.data()));
      }
    }
    return result;
  }

                                                                         
                                                                               
                                                                               
                                                          
  struct HashedSuffix {
                                        
    ArrayRef<CharT> chars_;

                                 
    JenkinsHash hash_;

                                                                             
    static HashedSuffix getEmptyKey() {
      return {llvh::DenseMapInfo<ArrayRef<CharT>>::getEmptyKey(), 0};
    }

                                                                       
                 
    static HashedSuffix getTombstoneKey() {
      return {llvh::DenseMapInfo<ArrayRef<CharT>>::getTombstoneKey(), 0};
    }

                                                                       
    static unsigned getHashValue(const HashedSuffix &s) {
      return s.hash_;
    }

                                                                       
    static bool isEqual(const HashedSuffix &lhs, const HashedSuffix &rhs) {
      return lhs.hash_ == rhs.hash_ && lhs.chars_ == rhs.chars_;
    }
  };

                                                        
  struct SuffixArrayEntry {
                                             
    ArrayRef<CharT> suffix_;

                                                        
    std::vector<StringEntry *> entries_;

                                                      
                                                                         
    SuffixArrayEntry(std::pair<HashedSuffix, std::vector<StringEntry *>> &&kv)
        : suffix_(std::move(kv.first.chars_)), entries_(std::move(kv.second)) {}

                                                                       
    int extCharAt(size_t pos) const {
      return pos >= suffix_.size() ? -1 : suffix_[pos];
    }
  };

                                                                                
                                                                  
  static void radixQuicksort(
      SuffixArrayEntry *begin,
      SuffixArrayEntry *end,
      size_t charIdx) {
    for (;;) {
      if (end - begin <= 1) {
                          
        return;
      }

                                                    
                                
                              
                          
                                 
      int pivotChar = begin->extCharAt(charIdx);
      SuffixArrayEntry *lower = begin;
      SuffixArrayEntry *upper = end;
      for (SuffixArrayEntry *cursor = begin + 1; cursor < upper;) {
        int testChar = cursor->extCharAt(charIdx);
        if (testChar < pivotChar) {
          std::swap(*lower++, *cursor++);
        } else if (testChar > pivotChar) {
          std::swap(*--upper, *cursor);
        } else {
                                  
          cursor++;
        }
      }
                                                                                
                                                                               
                       
      radixQuicksort(begin, lower, charIdx);
      radixQuicksort(upper, end, charIdx);

                                                                        
                                                               
                                              
      if (pivotChar == -1)
        return;

      begin = lower;
      end = upper;
      charIdx += 1;
    }
  }

                                                                   
                                                                               
                                                  
  static std::vector<SuffixArrayEntry> buildSuffixArray(
      MutableArrayRef<StringEntry> strings,
      const llvh::DenseSet<Trigram> &prefixesOfInterest) {
                                                                    
                                                                            
                                                                          
    llvh::DenseMap<HashedSuffix, std::vector<StringEntry *>, HashedSuffix>
        suffixMap(8 * strings.size());
    for (StringEntry &entry : strings) {
      size_t charsSize = entry.chars_.size();
                                       
      if (charsSize > kMaximumPackableStringLength) {
        continue;
      }
      const CharT *chars = entry.chars_.data();
      JenkinsHash hash = JenkinsHashInit;
      size_t i = charsSize;
      while (i--) {
        hash = updateJenkinsHash(hash, chars[i]);
        if (i + TrigramCharCount <= charsSize &&
            !prefixesOfInterest.count(makeTrigram(&chars[i])))
          continue;
        ArrayRef<CharT> suffix(&chars[i], charsSize - i);
        suffixMap[HashedSuffix{suffix, hash}].push_back(&entry);
      }
    }

                                                  
    std::vector<SuffixArrayEntry> result;
    if (!suffixMap.empty()) {
      result.reserve(suffixMap.size());
      std::move(suffixMap.begin(), suffixMap.end(), std::back_inserter(result));
      SuffixArrayEntry *entries = &result[0];
      radixQuicksort(entries, entries + result.size(), 0);
    }
    return result;
  }

                                                                     
                                                                          
                                                                             
                                                                              
                                                                       
                                                                          
                                                                          
  struct Overlap {
    ArrayRef<StringEntry *> srcs_;
    StringEntry *dst_;
  };

                                                           
                                                                        
                       
  using WeightIndexedOverlaps = std::vector<std::vector<Overlap>>;

                                                                              
                                                                               
                                                                            
                                            
  static void computeOverlapsAndParentForEntry(
      StringEntry *rightString,
      ArrayRef<SuffixArrayEntry> suffixArray,
      WeightIndexedOverlaps *overlaps) {
                                                                         
                                                                        
                                                                             
                                                                             
                                                                      
                                                                   
    using std::partition_point;
    ArrayRef<CharT> rightChars = rightString->chars_;
    auto lower = suffixArray.begin();
    auto upper = suffixArray.end();
    for (size_t index = 0, rightCharsLen = rightChars.size();
         index < rightCharsLen;
         index++) {
      CharT testChar = rightChars[index];
                                                                       
                           
      lower = partition_point(lower, upper, [=](const SuffixArrayEntry &ent) {
        return ent.extCharAt(index) < testChar;
      });
      upper = partition_point(lower, upper, [=](const SuffixArrayEntry &ent) {
        return ent.extCharAt(index) == testChar;
      });
      assert(lower <= upper && "Binary search crossed the streams");
      if (lower == upper) {
                                 
        break;
      }

                                                                    
                                             
      size_t overlapAmount = index + 1;
      if (overlapAmount < rightCharsLen) {
                                                                     
                                                                               
                                                                             
                                                                              
                                           
        if (lower->suffix_.size() == overlapAmount) {
                                                   
          if (overlaps->size() <= overlapAmount) {
            overlaps->resize(overlapAmount + 1);
          }
          Overlap ov = {lower->entries_, rightString};
          (*overlaps)[overlapAmount].push_back(ov);
        }
      } else {
                                                                             
                                                                      
                                                                             
                                                                       
                                                                 
                                                                           
        for (auto cursor = lower; cursor < upper; ++cursor) {
          for (StringEntry *parent : cursor->entries_) {
                                      
            if (parent == rightString)
              continue;

                                                                          
                                                                             
                                
            if (rightString->parent_ &&
                rightString->parent_->stringID_ < parent->stringID_)
              continue;

                                 
                                                                  
                                                                               
                                            
                                                                            
                                           
            assert(
                parent->chars_.size() > rightString->chars_.size() &&
                "non-unique strings passed to StringPacker");
            rightString->parent_ = parent;
            rightString->offsetInParent_ =
                parent->chars_.size() - cursor->suffix_.size();
          }
        }
      }
    }
  }

                                                            
                                      
                                                                           
  static WeightIndexedOverlaps computeOverlapsAndParents(
      MutableArrayRef<StringEntry> stringEntries,
      ArrayRef<SuffixArrayEntry> suffixArray) {
    WeightIndexedOverlaps result;
    for (StringEntry &entry : stringEntries) {
      computeOverlapsAndParentForEntry(&entry, suffixArray, &result);
    }
    return result;
  }

                                                                              
                                                                             
                                                            
  static bool canOverlap(const StringEntry *src, const StringEntry *dst) {
                                        
    if (src == dst)
      return false;

                                                               
    if (src->parent_ || dst->parent_)
      return false;

                                                                    
    if (src->next_ || dst->prev_)
      return false;

                                             
    if (src->potentialCycles_.count(dst))
      return false;

                       
    return true;
  }

                                                                             
                                                                        
                                                                    
                                                                              
                                                                   
                                                                  
                                                                              
                                                           
  static void planLayout(const WeightIndexedOverlaps &overlapsByWeight) {
    size_t overlapAmount = overlapsByWeight.size();
    while (overlapAmount--) {
      for (const Overlap &overlap : overlapsByWeight[overlapAmount]) {
        StringEntry *dst = overlap.dst_;
        if (dst->prev_ || dst->parent_) {
                                                                       
          continue;
        }
        for (StringEntry *src : overlap.srcs_) {
          if (canOverlap(src, dst)) {
                                 
            src->next_ = dst;
            dst->prev_ = src;
            dst->overlapAmount_ = overlapAmount;

                                                                                
                                                                              
            StringEntry *end = dst;
            while (end->next_)
              end = end->next_;
            StringEntry *start = src;
            while (start->prev_)
              start = start->prev_;
            end->potentialCycles_.insert(start);

                                                                             
            break;
          }
        }
      }
    }
  }

                                                                              
                                                           
                                                                               
                                                                               
                                                        
  static void layoutIfNeeded(StringEntry *entry, std::vector<CharT> *storage) {
    if (entry->offsetInStorage_ != npos) {
      return;                     
    }

                              
    if (entry->chars_.empty()) {
      entry->offsetInStorage_ = 0;
      return;
    }

                                                                 
    if (entry->parent_) {
      assert(entry->parent_ != entry && "entry cannot parent itself");
      assert(entry->offsetInParent_ != npos && "parent with no offset");
      assert(
          entry->prev_ == nullptr && entry->next_ == nullptr &&
          "Cannot have a parent and be in the path");
      layoutIfNeeded(entry->parent_, storage);
      entry->offsetInStorage_ =
          entry->parent_->offsetInStorage_ + entry->offsetInParent_;
      return;
    }

                                                   
    StringEntry *cursor = entry;
    while (cursor->prev_) {
      cursor = cursor->prev_;
    }
    assert(cursor->overlapAmount_ == 0 && "Cannot have overlap with no prev");
    while (cursor) {
      const auto &str = cursor->chars_;
      assert(
          cursor->offsetInStorage_ == npos &&
          "Cannot have already laid out an entry in this path");
      assert(
          cursor->overlapAmount_ <= str.size() &&
          "overlap cannot be larger than string size");
      assert(
          cursor->overlapAmount_ <= storage->size() &&
          "overlap cannot exceed the storage laid out so far ");
      cursor->offsetInStorage_ = storage->size() - cursor->overlapAmount_;
      storage->insert(
          storage->end(), str.begin() + cursor->overlapAmount_, str.end());
      cursor = cursor->next_;
    }
  }

                                           
                                                                              
                                       
  static std::vector<CharT> optimizingPackStrings(
      MutableArrayRef<StringEntry> strings) {
    auto prefixSet = buildPrefixTrigramSet(strings);
    auto suffixes = buildSuffixArray(strings, prefixSet);
    auto overlaps = computeOverlapsAndParents(strings, suffixes);
    planLayout(overlaps);
    std::vector<CharT> storage;
    for (StringEntry &entry : strings) {
      layoutIfNeeded(&entry, &storage);
    }
    return storage;                  
  }

                                                        
                                                                              
                                       
  static std::vector<CharT> fastPackStrings(
      MutableArrayRef<StringEntry> strings) {
    std::vector<CharT> result;
    for (StringEntry &str : strings) {
      str.offsetInStorage_ = result.size();
      result.insert(result.end(), str.chars_.begin(), str.chars_.end());
    }
                                               
    return result;
  }

#ifndef NDEBUG
                                                                            
                                                            
  static void validateStringPacking(
      ArrayRef<StringEntry> strings,
      ArrayRef<CharT> storage) {
    for (const auto &entry : strings) {
      auto offset = entry.offsetInStorage_;
      auto size = entry.chars_.size();
      assert(
          offset + size >= offset && offset + size <= storage.size() &&
          "Invalid offset or size for string entry");
      assert(
          entry.chars_ == storage.slice(offset, size) &&
          "String does not appear at claimed offset in storage");
    }
  }
#endif
};

                                                                              
                                                                             
                                                                     
                                                                           
                                                          
class StringTableBuilder {
 private:
                                                                                
                                                              
                                                                        
                                                                                
                                                                             
  std::deque<std::vector<char16_t>> u16StringStorage_;

 public:
                                
  std::vector<StringPacker<unsigned char>::StringEntry> asciiStrings_;

                                                
  std::vector<StringPacker<char16_t>::StringEntry> u16Strings_;

                                                                            
                                                                             
                                                                     
                                                                  
  template <typename I, typename Force8Bit>
  StringTableBuilder(I begin, I end, Force8Bit) {
                                                        
                                                                           
                                                   
                                                                             
                      
                                                                           
                                                                      
    uint32_t index = 0;
    for (auto it = begin; it != end; ++it) {
      auto &str = *it;
      static_assert(sizeof(str.data()[0]) == 1, "strings must be UTF8");
      const unsigned char *begin = (const unsigned char *)str.data();
      const unsigned char *end = begin + str.size();
      if (Force8Bit::value || isAllASCII(begin, end)) {
        ArrayRef<unsigned char> astr(begin, end);
        asciiStrings_.emplace_back(index, astr);
      } else {
        u16StringStorage_.emplace_back();
        std::vector<char16_t> &ustr = u16StringStorage_.back();
        convertUTF8WithSurrogatesToUTF16(
            std::back_inserter(ustr), (const char *)begin, (const char *)end);
        u16Strings_.emplace_back(index, ustr);
      }
      index++;
    }
  }

                                                                        
  size_t unpackedSize() const {
    size_t result = 0;
    for (const auto &entry : asciiStrings_) {
      result += sizeof(char) * entry.chars_.size();
    }
    for (const auto &entry : u16Strings_) {
      result += sizeof(char16_t) * entry.chars_.size();
    }
    return result;
  }

                                                                        
                                                                        
                                                                               
                                                                           
                                                                                
                                            
  void packIntoStorage(
      std::vector<unsigned char> *asciiStorage,
      std::vector<char16_t> *u16Storage,
      bool optimize) {
    NamedRegionTimer timer(
        "",
        optimize ? "optimizingPackStrings" : "fastPackStrings",
        "",
        StringTableTimersName,
        AreStatisticsEnabled());
                                                                         
    if (optimize) {
      *asciiStorage =
          StringPacker<unsigned char>::optimizingPackStrings(asciiStrings_);
      *u16Storage = StringPacker<char16_t>::optimizingPackStrings(u16Strings_);
    } else {
      *asciiStorage =
          StringPacker<unsigned char>::fastPackStrings(asciiStrings_);
      *u16Storage = StringPacker<char16_t>::fastPackStrings(u16Strings_);
    }

#ifndef NDEBUG
                                           
    StringPacker<unsigned char>::validateStringPacking(
        asciiStrings_, *asciiStorage);
    StringPacker<char16_t>::validateStringPacking(u16Strings_, *u16Storage);
#endif
  }

                                                                                
                                           
                                                                               
                                                                                
                                                                               
                                                                 
                                                                   
  std::vector<StringTableEntry> generateStringTable(
      ArrayRef<unsigned char> storage,
      size_t u16OffsetAdjust) {
                                                                            
                                                                             
                 
    std::vector<StringTableEntry> table;
    table.resize(asciiStrings_.size() + u16Strings_.size());

    for (const auto &asciiStr : asciiStrings_) {
      table.at(asciiStr.stringID_) = {
          static_cast<uint32_t>(asciiStr.offsetInStorage_),
          static_cast<uint32_t>(asciiStr.chars_.size()),
          false              };
    }
    for (const auto &u16Str : u16Strings_) {
      table.at(u16Str.stringID_) = {
          static_cast<uint32_t>(
              u16Str.offsetInStorage_ * sizeof(char16_t) + u16OffsetAdjust),
          static_cast<uint32_t>(u16Str.chars_.size()),
          true              };
    }
    return table;
  }

                                                              
                                                               
  static size_t appendU16Storage(
      ArrayRef<char16_t> u16Storage,
      std::vector<unsigned char> *output) {
    using namespace llvh::support;
    static_assert(sizeof(char16_t) == 2, "sizeof char16_t unexpectedly not 2");
    if (u16Storage.empty()) {
                                                   
      return 0;
    }

                               
    if (output->size() % sizeof(char16_t)) {
      output->push_back('\0');
    }

                                              
    size_t offset = output->size();
    output->resize(output->size() + sizeof(char16_t) * u16Storage.size());
    unsigned char *cursor = &output->at(offset);
    for (char16_t s : u16Storage) {
      endian::write<char16_t, little, 0>(cursor, s);
      cursor += sizeof(s);
    }
    return offset;
  }
};

}             

namespace hermes {
namespace hbc {

template <typename I, typename Force8Bit>
ConsecutiveStringStorage::ConsecutiveStringStorage(
    I begin,
    I end,
    Force8Bit,
    bool optimize) {
                                       
                                                    
  StringTableBuilder builder(begin, end, Force8Bit{});
  std::vector<unsigned char> asciiStorage;
  std::vector<char16_t> u16Storage;
  builder.packIntoStorage(&asciiStorage, &u16Storage, optimize);

                                                                               
  storage_.insert(storage_.end(), asciiStorage.begin(), asciiStorage.end());
  auto u16Offset = StringTableBuilder::appendU16Storage(u16Storage, &storage_);

                                      
  strTable_ = builder.generateStringTable(storage_, u16Offset);

                       
  size_t unpackedSize = builder.unpackedSize();
  StringTableSize += unpackedSize;
  StringTableSavings += unpackedSize - storage_.size();
}

template ConsecutiveStringStorage::ConsecutiveStringStorage(
    StringSetVector::const_iterator begin,
    StringSetVector::const_iterator end,
    std::false_type,
    bool optimize);

template ConsecutiveStringStorage::ConsecutiveStringStorage(
    StringSetVector::iterator begin,
    StringSetVector::iterator end,
    std::false_type,
    bool optimize);

template ConsecutiveStringStorage::ConsecutiveStringStorage(
    ArrayRef<llvh::StringRef>::const_iterator begin,
    ArrayRef<llvh::StringRef>::const_iterator end,
    std::false_type,
    bool optimize);

template ConsecutiveStringStorage::ConsecutiveStringStorage(
    StringSetVector::const_iterator begin,
    StringSetVector::const_iterator end,
    std::true_type,
    bool optimize);

uint32_t ConsecutiveStringStorage::getEntryHash(size_t i) const {
  ensureTableValid();
  ensureStorageValid();

  auto &entry = strTable_[i];
  uint32_t length = entry.getLength();
  assert(
      entry.getOffset() + (entry.isUTF16() ? length * 2 : length) <=
          storage_.size() &&
      "entry past end");
  const unsigned char *data = storage_.data() + entry.getOffset();
  if (entry.isUTF16()) {
    const char16_t *u16data = reinterpret_cast<const char16_t *>(data);
    return hermes::hashString(ArrayRef<char16_t>{u16data, length});
  } else {
    return hermes::hashString(ArrayRef<char>{(const char *)data, length});
  }
}

void ConsecutiveStringStorage::appendStorage(ConsecutiveStringStorage &&rhs) {
  ensureTableValid();
  ensureStorageValid();
                                                           
  if (strTable_.empty()) {
    *this = std::move(rhs);
    return;
  }
                                                                              
                                                                          
                                                                        
  uint32_t storageDelta = storage_.size();
  strTable_.reserve(strTable_.size() + rhs.strTable_.size());
  for (const StringTableEntry &entry : rhs.strTable_) {
    uint32_t length = entry.getLength();
    uint32_t offset = entry.getOffset() + (length ? storageDelta : 0);
    strTable_.emplace_back(offset, length, entry.isUTF16());
  }
  storage_.insert(storage_.end(), rhs.storage_.begin(), rhs.storage_.end());
}

llvh::StringRef ConsecutiveStringStorage::getStringAtIndex(
    uint32_t idx,
    std::string &utf8ConversionStorage) const {
  ensureTableValid();
  ensureStorageValid();
  assert(idx < strTable_.size() && "getStringAtIndex: invalid index");
  return getStringFromEntry(strTable_[idx], storage_, utf8ConversionStorage);
}

llvh::StringRef getStringFromEntry(
    const StringTableEntry &entry,
    llvh::ArrayRef<unsigned char> storage,
    std::string &utf8ConversionStorage) {
  uint32_t offset = entry.getOffset();
  uint32_t length = entry.getLength();
  assert(
      offset + length <= storage.size() && offset + length >= offset &&
      "Invalid entry");
  if (!entry.isUTF16()) {
    return llvh::StringRef{(const char *)storage.data() + offset, length};
  } else {
    const char16_t *s =
        reinterpret_cast<const char16_t *>(storage.data() + offset);
    llvh::ArrayRef<char16_t> u16String(s, length);
    convertUTF16ToUTF8WithSingleSurrogates(utf8ConversionStorage, u16String);
    return utf8ConversionStorage;
  }
}

}                 
}                    

#undef DEBUG_TYPE

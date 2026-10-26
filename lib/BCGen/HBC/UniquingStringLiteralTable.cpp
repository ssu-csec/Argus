/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/BCGen/HBC/UniquingStringLiteralTable.h"

#include <cassert>

namespace hermes {
namespace hbc {

namespace {

                                                                           
                           
StringKind::Kind kind(llvh::StringRef str, bool isIdentifier) {
  if (isIdentifier) {
    return StringKind::Identifier;
  } else {
    return StringKind::String;
  }
}

}             

StringLiteralIDMapping::StringLiteralIDMapping(
    ConsecutiveStringStorage storage,
    std::vector<bool> isIdentifier)
    : storage_(std::move(storage)), isIdentifier_(std::move(isIdentifier)) {
                                                                  
  std::string utf8Storage;
  uint32_t count = storage_.count();
  assert(isIdentifier_.size() == count);
  for (uint32_t i = 0; i < count; i++) {
    uint32_t j = strings_.insert(storage_.getStringAtIndex(i, utf8Storage));
    assert(i == j && "Duplicate string in storage.");
    (void)j;
  }
}

std::vector<uint32_t> StringLiteralTable::getIdentifierHashes() const {
  std::vector<uint32_t> result;
  assert(strings_.size() == isIdentifier_.size());
  for (size_t i = 0; i < strings_.size(); ++i) {
    if (!isIdentifier_[i]) {
      continue;
    }
    result.push_back(storage_.getEntryHash(i));
  }

  return result;
}

std::vector<StringKind::Entry> StringLiteralTable::getStringKinds() const {
  StringKind::Accumulator acc;

  assert(strings_.size() == isIdentifier_.size());
  for (size_t i = 0; i < strings_.size(); ++i) {
    acc.push_back(kind(strings_[i], isIdentifier_[i]));
  }

  return std::move(acc).entries();
}

             StringLiteralTable UniquingStringLiteralAccumulator::toTable(
    UniquingStringLiteralAccumulator accum,
    bool optimize) {
  auto &storage = accum.storage_;
  auto &strings = accum.strings_;
  auto &isIdentifier = accum.isIdentifier_;
  auto &numIdentifierRefs = accum.numIdentifierRefs_;

  const size_t existingStrings = storage.count();
  const size_t allStrings = strings.size();
  const size_t newStrings = allStrings - existingStrings;
  assert(
      existingStrings <= allStrings &&
      "Cannot have more written strings than strings");

                                                              
  struct Index {
    size_t origIndex;
    llvh::StringRef str;
    StringKind::Kind kind;

    Index(size_t origIndex, llvh::StringRef str, StringKind::Kind kind)
        : origIndex(origIndex), str(str), kind(kind) {}

    using Key = std::tuple<StringKind::Kind, llvh::StringRef>;

    inline Key key() const {
      return std::make_tuple(kind, str);
    }

    inline bool operator<(const Index &that) const {
      return this->key() < that.key();
    }
  };

                                                         
  struct KindedEntry {
    StringKind::Kind kind;
    StringTableEntry entry;

    KindedEntry(StringKind::Kind kind, StringTableEntry entry)
        : kind(kind), entry(entry) {}

   private:
                                                                            
                                                       
    using Key = std::tuple<StringKind::Kind, uint32_t, uint32_t>;
    inline Key key() const {
      return std::make_tuple(kind, entry.getOffset(), entry.getLength());
    }

   public:
    inline bool operator<(const KindedEntry &that) const {
      return this->key() < that.key();
    }
  };

  std::vector<Index> indices;
  indices.reserve(newStrings);

  for (size_t i = existingStrings; i < allStrings; ++i) {
    indices.emplace_back(i, strings[i], kind(strings[i], isIdentifier[i]));
  }

                                                                       
  std::stable_sort(
      indices.begin(),
      indices.end(),
      [&numIdentifierRefs, existingStrings](const Index &a, const Index &b) {
        assert(a.origIndex >= existingStrings && "Sorting an old string");
        assert(b.origIndex >= existingStrings && "Sorting an old string");

        auto ai = a.origIndex - existingStrings;
        auto bi = b.origIndex - existingStrings;

        return numIdentifierRefs[ai] > numIdentifierRefs[bi];
      });

                                                                            
                                               
  const auto remap = [allStrings, existingStrings](size_t ix) {
                                 
    ix = std::max(ix, existingStrings);

                              
    ix = std::min(ix, allStrings);

                                                          
    ix -= existingStrings;

    return ix;
  };

                                                                          
  const auto indicesFrom = [&remap, &indices](size_t ix) {
    return indices.begin() + remap(ix);
  };

  std::sort(indicesFrom(0), indicesFrom(UINT8_MAX));
  std::sort(indicesFrom(UINT8_MAX), indicesFrom(UINT16_MAX));
  std::sort(indicesFrom(UINT16_MAX), indicesFrom(SIZE_MAX));

  {                                       
    std::vector<llvh::StringRef> refs;
    refs.reserve(newStrings);
    for (auto &i : indices) {
      refs.emplace_back(i.str);
    }
    ConsecutiveStringStorage newStrings(refs, optimize);
    storage.appendStorage(std::move(newStrings));
  }

                                                                         
  auto tableView = storage.getStringTableView();
  std::vector<KindedEntry> kindedEntries;
  kindedEntries.reserve(newStrings);

  for (size_t i = 0, j = existingStrings; i < newStrings; ++i, ++j) {
    kindedEntries.emplace_back(indices[i].kind, tableView[j]);
  }

                                                                             
                               
  const auto entriesFrom = [&remap, &kindedEntries](size_t ix) {
    return kindedEntries.begin() + remap(ix);
  };

  std::sort(entriesFrom(0), entriesFrom(UINT8_MAX));
  std::sort(entriesFrom(UINT8_MAX), entriesFrom(UINT16_MAX));
  std::sort(entriesFrom(UINT16_MAX), entriesFrom(SIZE_MAX));

                                                      
  for (size_t i = 0, j = existingStrings; i < newStrings; ++i, ++j) {
    tableView[j] = kindedEntries[i].entry;
    isIdentifier[j] = kindedEntries[i].kind != StringKind::String;
  }

  return StringLiteralTable{std::move(storage), std::move(isIdentifier)};
}

}                 
}                    

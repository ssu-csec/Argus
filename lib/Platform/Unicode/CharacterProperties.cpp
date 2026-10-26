/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Platform/Unicode/CharacterProperties.h"
#include "hermes/Platform/Unicode/CodePointSet.h"

#include <algorithm>
#include <climits>
#include <iterator>
#include <string>
#include <utility>

namespace hermes {

#include "UnicodeData.inc"

namespace {
struct UnicodeRangeComp {
  bool operator()(UnicodeRange p, uint32_t s) const {
    return p.second < s;
  }
  bool operator()(uint32_t s, UnicodeRange p) const {
    return s < p.first;
  }
};
}             

template <typename UnicodeRangeTable>
inline bool lookup(const UnicodeRangeTable &table, const uint32_t cp) {
  return std::binary_search(
      std::begin(table), std::end(table), cp, UnicodeRangeComp());
}

bool isUnicodeOnlyLetter(uint32_t cp) {
                                                                      
                                                                              
                                                   
                                                                   
  if (cp <= 0x7F)
    return false;

  return lookup(UNICODE_LETTERS, cp);
}

                                                        
bool isUnicodeOnlySpace(uint32_t cp) {
                                                               
                   
  if (cp <= 0x7F)
    return false;

  switch (cp) {
    case 0xa0:
    case 0x1680:
    case 0x2000:
    case 0x2001:
    case 0x2002:
    case 0x2003:
    case 0x2004:
    case 0x2005:
    case 0x2006:
    case 0x2007:
    case 0x2008:
    case 0x2009:
    case 0x200a:
    case 0x202f:
    case 0x205f:
    case 0x3000:
      return true;
    default:
      return false;
  }
}

bool isUnicodeCombiningMark(uint32_t cp) {
                                                                        
                                   
  return lookup(UNICODE_COMBINING_MARK, cp);
}

bool isUnicodeDigit(uint32_t cp) {
                                                                  
                            
  return (cp >= '0' && cp <= '9') || lookup(UNICODE_DIGIT, cp);
};

bool isUnicodeConnectorPunctuation(uint32_t cp) {
                                                                        
                          
  return cp == '_' || lookup(UNICODE_CONNECTOR_PUNCTUATION, cp);
}

static uint32_t applyTransform(const UnicodeTransformRange &r, uint32_t cp) {
  assert(
      r.start <= cp && cp < r.start + r.count &&
      "range does not contain this cp");
  assert(cp <= INT32_MAX && "cp is too big");
                                            
  if ((cp - r.start) % r.modulo == 0) {
    int32_t cps = static_cast<int32_t>(cp) + r.delta;
    assert(cps >= 0 && "delta underflowed");
    return static_cast<uint32_t>(cps);
  }
  return cp;
}

                                                                   
                                                                         
           
static bool operator<(const UnicodeTransformRange &m, uint32_t cp) {
  return m.start + m.count <= cp;
}

                                                                                
                                                                   
static void addPrecanonicalCharacters(
    CodePointRange range,
    CodePointSet *receiver,
    bool unicode) {
  if (range.length == 0)
    return;
                                                                           
                                                                               
               
  const auto start =
      unicode ? std::begin(UNICODE_FOLDS) : std::begin(LEGACY_CANONS);
  const auto end = unicode ? std::end(UNICODE_FOLDS) : std::end(LEGACY_CANONS);
  for (auto iter = start; iter != end; ++iter) {
    const UnicodeTransformRange &transform = *iter;
                                                                       
    CodePointRange fromRange{transform.start, transform.count};
    CodePointRange toRange = fromRange;
    toRange.first += transform.delta;

                                                                 
    if (!range.overlaps(toRange))
      continue;

                                     
    for (uint32_t cp = fromRange.first; cp < fromRange.end(); cp++) {
      uint32_t tcp = applyTransform(transform, cp);
      if (tcp != cp && range.first <= tcp && tcp < range.end()) {
        receiver->add(cp);
      }
    }
  }
}

                                                                              
                          
static void
canonicalizeRange(CodePointRange range, CodePointSet *receiver, bool unicode) {
  assert(range.length > 0 && "Range should never be empty");

                                                                       
  const auto start =
      unicode ? std::begin(UNICODE_FOLDS) : std::begin(LEGACY_CANONS);
  const auto end = unicode ? std::end(UNICODE_FOLDS) : std::end(LEGACY_CANONS);
  auto transform = std::lower_bound(start, end, range.first);

  uint32_t curcp = range.first;
  uint32_t endcp = range.end();
  while (curcp < endcp && transform != end) {
    uint32_t transformEnd = transform->start + transform->count;
    assert(transformEnd > curcp && "transform should end after our current cp");
    if (transform->start > curcp) {
                                                                      
                   
      curcp = transform->start;
    } else {
                                                                               
                           
      for (; curcp < transformEnd && curcp < endcp; curcp++) {
        receiver->add(applyTransform(*transform, curcp));
      }
                                                                  
      ++transform;
    }
  }
}

CodePointSet makeCanonicallyEquivalent(const CodePointSet &set, bool unicode) {
                                                                               
                                             
  CodePointSet canonicalized = set;
  for (const auto &range : set.ranges()) {
    canonicalizeRange(range, &canonicalized, unicode);
  }

  CodePointSet result = canonicalized;
  for (const auto &range : canonicalized.ranges()) {
    addPrecanonicalCharacters(range, &result, unicode);
  }
  return result;
}

uint32_t canonicalize(uint32_t cp, bool unicode) {
  const auto start =
      unicode ? std::begin(UNICODE_FOLDS) : std::begin(LEGACY_CANONS);
  const auto end = unicode ? std::end(UNICODE_FOLDS) : std::end(LEGACY_CANONS);
  auto where = std::lower_bound(start, end, cp);
  if (where != end && where->start <= cp && cp < where->start + where->count) {
    return applyTransform(*where, cp);
  } else {
                                                                      
    return cp;
  }
}

#ifdef HERMES_ENABLE_UNICODE_REGEXP_PROPERTY_ESCAPES

                                                                          
                                                                
template <class T>
static const T *findMapEntry(
    const llvh::ArrayRef<T> &arrayRef,
    const std::string_view name) {
  auto it = std::lower_bound(
      std::begin(arrayRef),
      std::end(arrayRef),
      name,
      [](const T &a, std::string_view b) {
        return UNICODE_DATA_STRING_POOL.compare(a.name.offset, a.name.size, b) <
            0;
      });
  if (it == std::end(arrayRef) ||
      UNICODE_DATA_STRING_POOL.compare(it->name.offset, it->name.size, name) !=
          0) {
    return nullptr;
  }
  return it;
}

llvh::ArrayRef<UnicodeRangePoolRef> unicodePropertyRanges(
    std::string_view propertyName,
    std::string_view propertyValue) {
  const NameMapEntry *canonicalNameEntry;
  llvh::ArrayRef<RangeMapEntry> rangeMap;

  if (propertyValue.empty()) {
                                                                               
                                                                      
    if ((canonicalNameEntry = findMapEntry(
             llvh::ArrayRef(canonicalPropertyNameMap_BinaryProperty),
             propertyName))) {
      rangeMap = unicodePropertyRangeMap_BinaryProperty;
    } else if ((canonicalNameEntry = findMapEntry(
                    llvh::ArrayRef(canonicalPropertyNameMap_GeneralCategory),
                    propertyName))) {
      rangeMap = unicodePropertyRangeMap_GeneralCategory;
    }
  } else {
                                                                 
    if ((propertyName == "General_Category" || propertyName == "gc") &&
        (canonicalNameEntry = findMapEntry(
             llvh::ArrayRef(canonicalPropertyNameMap_GeneralCategory),
             propertyValue))) {
      rangeMap = unicodePropertyRangeMap_GeneralCategory;
    } else if (
        (propertyName == "Script" || propertyName == "sc") &&
        (canonicalNameEntry = findMapEntry(
             llvh::ArrayRef(canonicalPropertyNameMap_Script), propertyValue))) {
      rangeMap = unicodePropertyRangeMap_Script;
    } else if (
        (propertyName == "Script_Extensions" || propertyName == "scx") &&
                                                                      
                      
        (canonicalNameEntry = findMapEntry(
             llvh::ArrayRef(canonicalPropertyNameMap_Script), propertyValue))) {
      rangeMap = unicodePropertyRangeMap_ScriptExtensions;
    } else {
      return llvh::ArrayRef<UnicodeRangePoolRef>();
    }
  }

  if (canonicalNameEntry == nullptr) {
    return llvh::ArrayRef<UnicodeRangePoolRef>();
  }

                                               
  auto rangeMapEntry = findMapEntry(
      rangeMap,
      UNICODE_DATA_STRING_POOL.substr(
          canonicalNameEntry->canonical.offset,
          canonicalNameEntry->canonical.size));
  if (rangeMapEntry == nullptr) {
    return llvh::ArrayRef<UnicodeRangePoolRef>();
  }

  return llvh::ArrayRef{
      &UNICODE_RANGE_ARRAY_POOL[rangeMapEntry->rangeArrayPoolOffset],
      rangeMapEntry->rangeArraySize};
}

void addRangeArrayPoolToBracket(
    CodePointSet *receiver,
    const llvh::ArrayRef<UnicodeRangePoolRef> rangeArrayPool,
    bool inverted) {
  for (auto rangePoolRef : rangeArrayPool) {
    auto rangePool = llvh::ArrayRef<UnicodeRange>{
        &UNICODE_RANGE_POOL[rangePoolRef.offset], rangePoolRef.size};

    if (inverted) {
      uint32_t last = 0;
      for (auto range : rangePool) {
        receiver->add(CodePointRange{last, range.first - last});
        last = range.second + 1;
      }
                                                                         
                       
      if (last < UNICODE_MAX_VALUE)
        receiver->add(CodePointRange{last, UNICODE_MAX_VALUE - last});
    } else {
      for (auto range : rangePool) {
        const uint32_t length = range.second - range.first + 1;
        receiver->add(CodePointRange{range.first, length});
      }
    }
  }
}

#else

llvh::ArrayRef<UnicodeRangePoolRef> unicodePropertyRanges(
    std::string_view propertyName,
    std::string_view propertyValue) {
  return llvh::ArrayRef<UnicodeRangePoolRef>();
}

void addRangeArrayPoolToBracket(
    CodePointSet *receiver,
    const llvh::ArrayRef<UnicodeRangePoolRef> rangeArrayPool,
    bool inverted) {}

#endif

}                    

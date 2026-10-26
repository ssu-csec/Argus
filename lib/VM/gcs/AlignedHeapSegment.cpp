/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/AlignedHeapSegment.h"

#include "hermes/Support/OSCompat.h"
#include "hermes/VM/GCBase-inline.h"
#include "hermes/VM/GCBase.h"
#include "hermes/VM/GCCell.h"
#include "hermes/VM/HiddenClass.h"

#include "llvh/Support/MathExtras.h"

#include <algorithm>
#include <cassert>
#include <cstring>

namespace hermes {
namespace vm {

void AlignedHeapSegment::Contents::protectGuardPage(
    oscompat::ProtectMode mode) {
  char *begin = &paddedGuardPage_[kGuardPagePadding];
  size_t size = sizeof(paddedGuardPage_) - kGuardPagePadding;
  size_t PS = oscompat::page_size();
                                                                      
  if (reinterpret_cast<uintptr_t>(begin) % PS == 0 && PS <= size) {
    oscompat::vm_protect(begin, PS, mode);
  }
}

AlignedHeapSegment::AlignedHeapSegment(AlignedStorage storage)
    : storage_(std::move(storage)) {
                                                                       
             
  assert(
      reinterpret_cast<uintptr_t>(hiLim()) % oscompat::page_size() == 0 &&
      "storage end must be page-aligned");
  if (*this) {
    new (contents()) Contents();
    contents()->protectGuardPage(oscompat::ProtectMode::None);
#ifndef NDEBUG
    clear();
#endif
  }
}

AlignedHeapSegment::~AlignedHeapSegment() {
  if (lowLim() == nullptr) {
    return;
  }
  contents()->protectGuardPage(oscompat::ProtectMode::ReadWrite);
  contents()->~Contents();
  __asan_unpoison_memory_region(start(), end() - start());
}

void AlignedHeapSegment::markUnused(char *start, char *end) {
  assert(
      !llvh::alignmentAdjustment(start, oscompat::page_size()) &&
      !llvh::alignmentAdjustment(end, oscompat::page_size()));
                                                                            
                                                                           
                 
  contents()->protectGuardPage(oscompat::ProtectMode::ReadWrite);
  storage_.markUnused(start, end);
  contents()->protectGuardPage(oscompat::ProtectMode::None);
}

template <AdviseUnused MU>
void AlignedHeapSegment::setLevel(char *lvl) {
  assert(dbgContainsLevel(lvl));
  if (lvl < level_) {
#ifndef NDEBUG
    clear(lvl, level_);
#else
    if (MU == AdviseUnused::Yes) {
      const size_t PS = oscompat::page_size();
      auto nextPageAfter = reinterpret_cast<char *>(
          llvh::alignTo(reinterpret_cast<uintptr_t>(lvl), PS));
      auto nextPageBefore = reinterpret_cast<char *>(
          llvh::alignTo(reinterpret_cast<uintptr_t>(level_), PS));

      markUnused(nextPageAfter, nextPageBefore);
    }
#endif
  }
  level_ = lvl;
}

                                                 
template void AlignedHeapSegment::setLevel<AdviseUnused::Yes>(char *lvl);
template void AlignedHeapSegment::setLevel<AdviseUnused::No>(char *lvl);

template <AdviseUnused MU>
void AlignedHeapSegment::resetLevel() {
  setLevel<MU>(start());
}

                                                   
template void AlignedHeapSegment::resetLevel<AdviseUnused::Yes>();
template void AlignedHeapSegment::resetLevel<AdviseUnused::No>();

void AlignedHeapSegment::setEffectiveEnd(char *effectiveEnd) {
  assert(
      start() <= effectiveEnd && effectiveEnd <= end() &&
      "Must be valid end for segment.");
  assert(level() <= effectiveEnd && "Must not set effective end below level");
  effectiveEnd_ = effectiveEnd;
}

void AlignedHeapSegment::clearExternalMemoryCharge() {
  setEffectiveEnd(end());
}

#ifndef NDEBUG
bool AlignedHeapSegment::dbgContainsLevel(const void *lvl) const {
  return contains(lvl) || lvl == hiLim();
}

bool AlignedHeapSegment::validPointer(const void *p) const {
  return start() <= p && p < level() &&
      static_cast<const GCCell *>(p)->isValid();
}

void AlignedHeapSegment::clear() {
  clear(start(), end());
}

             void AlignedHeapSegment::clear(char *start, char *end) {
#if LLVM_ADDRESS_SANITIZER_BUILD
  __asan_poison_memory_region(start, end - start);
#else
  std::memset(start, kInvalidHeapValue, end - start);
#endif
}

             void AlignedHeapSegment::checkUnwritten(char *start, char *end) {
#if !LLVM_ADDRESS_SANITIZER_BUILD && defined(HERMES_SLOW_DEBUG)
                                               
  std::for_each(
      start, end, [](char value) { assert(value == kInvalidHeapValue); });
#endif
}
#endif           

}                
}                    

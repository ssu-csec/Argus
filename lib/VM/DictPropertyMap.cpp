/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "vm"
#include "hermes/VM/DictPropertyMap.h"
#include "hermes/Support/Statistic.h"
#include "hermes/VM/SymbolID-inline.h"

HERMES_SLOW_STATISTIC(NumDictLookups, "Number of dictionary lookups");
HERMES_SLOW_STATISTIC(NumExtraHashProbes, "Number of extra hash probes");

namespace hermes {
namespace vm {

struct DictPropertyMap::detail {
                                                                            
                                                    
                                                                                
                                                                          
                                                                                
                 
  static constexpr uint32_t kSearchUpperBound = GC::maxAllocationSize() / 2;

  static_assert(
      !DictPropertyMap::constWouldFitAllocation(kSearchUpperBound),
      "kSearchUpperBound should not fit into an allocation");

                                                                             
  static constexpr uint32_t kMaxCapacity =
      DictPropertyMap::constFindMaxCapacity(0, kSearchUpperBound);

                                                  
  static_assert(
      DictPropertyMap::constApproxAllocSize64(kMaxCapacity) <=
          GC::maxAllocationSize(),
      "invalid kMaxCapacity");

                                                                              
                                  
  static_assert(
      kMaxCapacity < (1u << 31),
      "kMaxCapacity is unrealistically large");

  static_assert(
      DictPropertyMap::HashPair::canStore(kMaxCapacity),
      "too few bits to store max possible descriptor index");
};

const VTable DictPropertyMap::vt{CellKind::DictPropertyMapKind, 0};

void DictPropertyMapBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  const auto *self = static_cast<const DictPropertyMap *>(cell);
  mb.setVTable(&DictPropertyMap::vt);
  mb.addArray(
      &self->getDescriptorPairs()->first,
      &self->numDescriptors_,
      sizeof(DictPropertyMap::DescriptorPair));
}

DictPropertyMap::size_type DictPropertyMap::getMaxCapacity() {
  return detail::kMaxCapacity;
}

CallResult<PseudoHandle<DictPropertyMap>> DictPropertyMap::create(
    Runtime &runtime,
    size_type capacity) {
  if (LLVM_UNLIKELY(capacity > detail::kMaxCapacity)) {
    return runtime.raiseRangeError(
        TwineChar16("Property storage exceeds ") + detail::kMaxCapacity +
        " properties");
  }
  size_type hashCapacity = calcHashCapacity(capacity);
  auto *cell = runtime.makeAVariable<DictPropertyMap>(
      allocationSize(capacity, hashCapacity), capacity, hashCapacity);
  return createPseudoHandle(cell);
}

std::pair<bool, DictPropertyMap::HashPair *> DictPropertyMap::lookupEntryFor(
    DictPropertyMap *self,
    SymbolID symbolID) {
  ++NumDictLookups;

  size_type const mask = self->hashCapacity_ - 1;
  size_type index = hash(symbolID) & mask;

                  
  size_type step = 1;
                                                                          
  HashPair *const tableStart = self->getHashPairs();
                                      
  HashPair *deleted = nullptr;

  assert(symbolID.isValid() && "looking for an invalid SymbolID");

  for (;;) {
    HashPair *curEntry = tableStart + index;

    if (curEntry->isValid()) {
      if (self->isMatch(curEntry, symbolID))
        return {true, curEntry};
    } else if (curEntry->isEmpty()) {
                                                                         
                                                                          

      return {false, deleted ? deleted : curEntry};
    } else {
      assert(curEntry->isDeleted() && "unexpected HashPair state");
                                                                         
                                            
      if (!deleted)
        deleted = curEntry;
    }

    ++NumExtraHashProbes;
    index = (index + step) & mask;
    ++step;
  }
}

ExecutionStatus DictPropertyMap::grow(
    MutableHandle<DictPropertyMap> &selfHandleRef,
    Runtime &runtime,
    size_type newCapacity) {
  auto res = create(runtime, newCapacity);
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto *newSelf = res->get();
  auto *self = *selfHandleRef;

  selfHandleRef = newSelf;

  auto *dst = newSelf->getDescriptorPairs();
  size_type count = 0;

  for (auto *src = self->getDescriptorPairs(),
            *e = src + self->numDescriptors_.load(std::memory_order_relaxed);
       src != e;
       ++src) {
    if (src->first.isInvalid())
      continue;

    const SymbolID key = src->first;

                                                                           
                                                                           
    new (&dst->first) GCSymbolID(key);
    dst->second = src->second;

    auto result = lookupEntryFor(newSelf, key);
    assert(!result.first && "found duplicate entry while growing");
    result.second->setDescIndex(count, key);

    ++dst;
    ++count;
  }

  assert(
      count == self->numProperties_ && "numProperties mismatch when growing");

  newSelf->numProperties_ = count;

                                                   
  auto deletedIndex = self->deletedListHead_;
  if (deletedIndex != END_OF_LIST) {
    newSelf->deletedListHead_ = count;
    newSelf->deletedListSize_ = self->deletedListSize_;

    do {
      const auto *src = self->getDescriptorPairs() + deletedIndex;
      assert(
          src->first == SymbolID::deleted() &&
          "pair in the deleted list is not marked as deleted");

                                                                             
                                                                             
      new (&dst->first) GCSymbolID(SymbolID::deleted());
      dst->second.slot = src->second.slot;

      deletedIndex = getNextDeletedIndex(src);
      setNextDeletedIndex(
          dst, deletedIndex != END_OF_LIST ? count + 1 : END_OF_LIST);

      ++dst;
      ++count;
    } while (deletedIndex != END_OF_LIST);
  }

  newSelf->numDescriptors_.store(count, std::memory_order_release);
  assert(count <= newSelf->descriptorCapacity_);
  return ExecutionStatus::RETURNED;
}

CallResult<std::pair<NamedPropertyDescriptor *, bool>>
DictPropertyMap::findOrAdd(
    MutableHandle<DictPropertyMap> &selfHandleRef,
    Runtime &runtime,
    SymbolID id) {
  auto *self = *selfHandleRef;
  auto numDescriptors = self->numDescriptors_.load(std::memory_order_relaxed);
  auto found = lookupEntryFor(self, id);
  if (found.first) {
    return std::make_pair(
        &self->getDescriptorPairs()[found.second->getDescIndex()].second,
        false);
  }

                                                                          
                                                                          
                                                                                
                                             

  if (numDescriptors == self->descriptorCapacity_) {
    size_type newCapacity;
    if (self->numProperties_ == self->descriptorCapacity_) {
                                                                            
                                                                          
                                                                            
                     
      newCapacity = self->numProperties_ * 2;
      if (newCapacity > detail::kMaxCapacity)
        newCapacity =
            std::max(toRValue(detail::kMaxCapacity), self->numProperties_ + 1);
    } else {
                                                                       
                                                                            
                                                                           
                            
      newCapacity = self->numProperties_ + 1 + self->deletedListSize_;
    }

    if (LLVM_UNLIKELY(
            grow(selfHandleRef, runtime, newCapacity) ==
            ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }

    self = *selfHandleRef;
    numDescriptors = self->numDescriptors_.load(std::memory_order_relaxed);

    found = lookupEntryFor(self, id);
  }

  ++self->numProperties_;
  if (found.second->isDeleted())
    self->decDeletedHashCount();

  found.second->setDescIndex(numDescriptors, id);

  auto *descPair = self->getDescriptorPairs() + numDescriptors;

  descPair->first.set(id, runtime.getHeap());
  self->numDescriptors_.fetch_add(1, std::memory_order_acq_rel);

  return std::make_pair(&descPair->second, true);
}

void DictPropertyMap::erase(
    DictPropertyMap *self,
    Runtime &runtime,
    PropertyPos pos) {
  auto *hashPair = self->getHashPairs() + pos.hashPairIndex;
  auto descIndex = hashPair->getDescIndex();
  assert(
      descIndex < self->numDescriptors_.load(std::memory_order_relaxed) &&
      "descriptor index out of range");

  auto *descPair = self->getDescriptorPairs() + descIndex;
  assert(
      descPair->first != SymbolID::empty() &&
      "accessing deleted descriptor pair");

  hashPair->setDeleted();
  descPair->first.set(SymbolID::deleted(), runtime.getHeap());
                                            
  setNextDeletedIndex(descPair, self->deletedListHead_);
  self->deletedListHead_ = descIndex;
  ++self->deletedListSize_;

  assert(self->numProperties_ != 0 && "num properties out of sync");
  --self->numProperties_;
  self->incDeletedHashCount();
}

SlotIndex DictPropertyMap::allocatePropertySlot(
    DictPropertyMap *self,
    Runtime &runtime) {
                                                                             
                                    
  if (self->deletedListHead_ == END_OF_LIST)
    return self->numProperties_;

  auto *deletedPair = self->getDescriptorPairs() + self->deletedListHead_;
  assert(
      deletedPair->first == SymbolID::deleted() &&
      "Head of deleted list is not deleted");

                                                    
  self->deletedListHead_ = getNextDeletedIndex(deletedPair);
  --self->deletedListSize_;

                                                     
                                                                             
  new (&deletedPair->first) GCSymbolID(SymbolID::empty());

  return deletedPair->second.slot;
}

void DictPropertyMap::dump() {
  auto &OS = llvh::errs();

  OS << "DictPropertyMap:" << getDebugAllocationId() << "\n";
  OS << "  HashPairs[" << hashCapacity_ << "]:\n";
  for (unsigned i = 0; i < hashCapacity_; ++i) {
    auto *pair = getHashPairs() + i;
    if (pair->isValid()) {
      OS << "    " << pair->getDescIndex() << "\n";
    } else if (pair->isEmpty()) {
      OS << "    (empty)\n";
    } else {
      assert(pair->isDeleted());
      OS << "    (deleted)\n";
    }
  }
  OS << "  Descriptors[" << descriptorCapacity_ << "]:\n";
  for (unsigned i = 0; i < descriptorCapacity_; ++i) {
    auto *pair = getDescriptorPairs() + i;
    OS << "    (" << pair->first << ", " << "(slot=" << pair->second.slot
       << "))\n";
  }
}

}                
}                    

#undef DEBUG_TYPE

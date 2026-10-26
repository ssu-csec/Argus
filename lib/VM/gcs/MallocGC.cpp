/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Support/CheckedMalloc.h"
#include "hermes/Support/ErrorHandling.h"
#include "hermes/Support/SlowAssert.h"
#include "hermes/VM/CheckHeapWellFormedAcceptor.h"
#include "hermes/VM/CompressedPointer.h"
#include "hermes/VM/GC.h"
#include "hermes/VM/GCBase-inline.h"
#include "hermes/VM/HermesValue-inline.h"
#include "hermes/VM/HiddenClass.h"
#include "hermes/VM/JSWeakMapImpl.h"
#include "hermes/VM/RootAndSlotAcceptorDefault.h"
#include "hermes/VM/SmallHermesValue-inline.h"

#include "llvh/Support/Debug.h"

#include <algorithm>

#define DEBUG_TYPE "gc"

namespace hermes {
namespace vm {

static const char *kGCName = "malloc";

struct MallocGC::MarkingAcceptor final : public RootAndSlotAcceptorDefault,
                                         public WeakAcceptorDefault {
  MallocGC &gc;
  std::vector<CellHeader *> worklist_;

                                                                             
                                                                         
                                                                              
                             
  llvh::BitVector markedSymbols_;

  MarkingAcceptor(MallocGC &gc)
      : RootAndSlotAcceptorDefault(gc.getPointerBase()),
        WeakAcceptorDefault(gc.getPointerBase()),
        gc(gc),
        markedSymbols_(gc.gcCallbacks_.getSymbolsEnd()) {}

  using RootAndSlotAcceptorDefault::accept;

  void accept(GCCell *&cell) override {
    if (!cell) {
      return;
    }
    HERMES_SLOW_ASSERT(
        gc.validPointer(cell) &&
        "Marked a pointer that the GC didn't allocate");
    CellHeader *header = CellHeader::from(cell);
#ifdef HERMESVM_SANITIZE_HANDLES
                                                                    
                                                               
                                                                
    if (gc.newPointers_.count(header)) {
      return;
    }
                                                       
    if (header->isMarked()) {
      cell = header->getForwardingPointer()->data();
    } else {
                                             
                                             
      const gcheapsize_t origSize = cell->getAllocatedSize();
      const gcheapsize_t trimmedSize =
          cell->getVT()->getTrimmedSize(cell, origSize);
      auto *newLocation =
          new (checkedMalloc(trimmedSize + sizeof(CellHeader))) CellHeader();
      newLocation->mark();
      memcpy(newLocation->data(), cell, trimmedSize);
      if (origSize != trimmedSize) {
        auto *newVarCell =
            reinterpret_cast<VariableSizeRuntimeCell *>(newLocation->data());
        newVarCell->setSizeFromGC(trimmedSize);
      }
                                                                           
                                                                             
      header->markWithForwardingPointer(newLocation);
      worklist_.push_back(newLocation);
      gc.newPointers_.insert(newLocation);
      if (gc.isTrackingIDs()) {
        gc.moveObject(
            cell, cell->getAllocatedSize(), newLocation->data(), trimmedSize);
      }
      cell = newLocation->data();
    }
#else
    if (!header->isMarked()) {
                                                               
      header->mark();
                                                                            
                                             
      gcheapsize_t origSize = cell->getAllocatedSize();
      gcheapsize_t newSize = cell->getVT()->getTrimmedSize(cell, origSize);
      if (newSize != origSize) {
        static_cast<VariableSizeRuntimeCell *>(cell)->setSizeFromGC(newSize);
      }
      worklist_.push_back(header);
                                                                    
      gc.pointers_.erase(header);
      gc.newPointers_.insert(header);
    }
                                                                            
                                    
#endif
  }

  void acceptWeak(GCCell *&ptr) override {
    if (ptr == nullptr) {
      return;
    }
    CellHeader *header = CellHeader::from(ptr);

                                                
#ifdef HERMESVM_SANITIZE_HANDLES
    ptr = header->isMarked() ? header->getForwardingPointer()->data() : nullptr;
#else
    ptr = header->isMarked() ? ptr : nullptr;
#endif
  }

  void acceptHV(HermesValue &hv) override {
    if (hv.isPointer()) {
      GCCell *ptr = static_cast<GCCell *>(hv.getPointer());
      accept(ptr);
      hv.setInGC(hv.updatePointer(ptr), gc);
    } else if (hv.isSymbol()) {
      acceptSym(hv.getSymbol());
    }
  }

  void acceptSHV(SmallHermesValue &hv) override {
    if (hv.isPointer()) {
      GCCell *ptr = static_cast<GCCell *>(hv.getPointer(pointerBase_));
      accept(ptr);
      hv.setInGC(hv.updatePointer(ptr, pointerBase_), gc);
    } else if (hv.isSymbol()) {
      acceptSym(hv.getSymbol());
    }
  }

  void acceptSym(SymbolID sym) override {
    if (sym.isInvalid()) {
      return;
    }
    assert(
        sym.unsafeGetIndex() < markedSymbols_.size() &&
        "Tried to mark a symbol not in range");
    markedSymbols_.set(sym.unsafeGetIndex());
  }
};

gcheapsize_t MallocGC::Size::storageFootprint() const {
                                                       
  return 0;
}

gcheapsize_t MallocGC::Size::minStorageFootprint() const {
                                                       
  return 0;
}

MallocGC::MallocGC(
    GCCallbacks &gcCallbacks,
    PointerBase &pointerBase,
    const GCConfig &gcConfig,
    std::shared_ptr<CrashManager> crashMgr,
    std::shared_ptr<StorageProvider> provider,
    experiments::VMExperimentFlags vmExperimentFlags)
    : GCBase(
          gcCallbacks,
          pointerBase,
          gcConfig,
          std::move(crashMgr),
          HeapKind::MallocGC),
      pointers_(),
      maxSize_(Size(gcConfig).max()),
      sizeLimit_(gcConfig.getInitHeapSize()) {
  (void)vmExperimentFlags;
  crashMgr_->setCustomData("HermesGC", kGCName);
}

MallocGC::~MallocGC() {
  for (CellHeader *header : pointers_) {
    free(header);
  }
}

void MallocGC::collectBeforeAlloc(std::string cause, uint32_t size) {
  const auto growSizeLimit = [this, size](gcheapsize_t sizeLimit) {
                                                                               
    return std::min(maxSize_, std::max(sizeLimit * 2, size));
  };
  if (size > sizeLimit_) {
    sizeLimit_ = growSizeLimit(sizeLimit_);
  }
  if (size > maxSize_) {
                                                      
    oom(make_error_code(OOMError::MaxHeapReached));
  }
  assert(
      size <= sizeLimit_ &&
      "Should be guaranteed not to be asking for more space than the heap can "
      "provide");
                                                             
                                         
#ifndef HERMESVM_SANITIZE_HANDLES
  if (allocatedBytes_ < sizeLimit_ - size) {
    return;
  }
#endif
                                                                            
                        
  collect(std::move(cause));
                                                            
  while (allocatedBytes_ >= sizeLimit_ - size) {
    if (sizeLimit_ == maxSize_) {
                                           
      oom(make_error_code(OOMError::MaxHeapReached));
    }
    sizeLimit_ = growSizeLimit(sizeLimit_);
  }
}

#ifdef HERMES_SLOW_DEBUG
void MallocGC::checkWellFormed() {
  GCCycle cycle{*this};
  CheckHeapWellFormedAcceptor acceptor(*this);
  DroppingAcceptor<CheckHeapWellFormedAcceptor> nameAcceptor{acceptor};
  markRoots(nameAcceptor, true);
  markWeakRoots(acceptor,                   true);
  for (CellHeader *header : pointers_) {
    GCCell *cell = header->data();
    assert(cell->isValid() && "Invalid cell encountered in heap");
    markCell(cell, acceptor);
  }

  weakMapEntrySlots_.forEach([](WeakMapEntrySlot &slot) {
    if (slot.mappedValue.isEmpty()) {
      assert(
          !slot.key ||
          !slot.owner && "Reachable entry should not have Empty value.");
    }
  });
}

void MallocGC::clearUnmarkedPropertyMaps() {
  for (CellHeader *header : pointers_)
    if (!header->isMarked())
      if (auto hc = dyn_vmcast<HiddenClass>(header->data()))
        hc->clearPropertyMap(*this);
}
#endif

void MallocGC::collect(std::string cause, bool                    ) {
  assert(noAllocLevel_ == 0 && "no GC allowed right now");
  using std::chrono::steady_clock;
  LLVM_DEBUG(llvh::dbgs() << "Beginning collection");
#ifdef HERMES_SLOW_DEBUG
  checkWellFormed();
#endif
  const auto wallStart = steady_clock::now();
  const auto cpuStart = oscompat::thread_cpu_time();
  const auto allocatedBefore = allocatedBytes_;
  const auto externalBefore = externalBytes_;

  resetStats();

                                 
  {
    GCCycle cycle{*this, "GC Full collection"};
    MarkingAcceptor acceptor(*this);
    DroppingAcceptor<MarkingAcceptor> nameAcceptor{acceptor};
    markRoots(nameAcceptor, true);
#ifdef HERMES_SLOW_DEBUG
    clearUnmarkedPropertyMaps();
#endif
    drainMarkStack(acceptor);

    markWeakMapEntrySlots(acceptor);
                                    
    markWeakRoots(acceptor,                   true);

                               
    gcCallbacks_.freeSymbols(acceptor.markedSymbols_);
                                                                               
    for (CellHeader *header : pointers_) {
#ifndef HERMESVM_SANITIZE_HANDLES
                                                                            
      assert(!header->isMarked() && "Live pointer left in dead heap section");
#endif
      GCCell *cell = header->data();
                                                         
      const auto freedSize = cell->getAllocatedSize();
                                                                      
      if (!header->isMarked()) {
        cell->getVT()->finalizeIfExists(cell, *this);
#ifndef NDEBUG
                             
        if (cell->getVT()->finalize_) {
          ++numFinalizedObjects_;
        }
#endif
                                                                               
        if (isTrackingIDs()) {
          untrackObject(cell, freedSize);
        }
      }
#ifndef NDEBUG
                                                              
      std::fill_n(reinterpret_cast<char *>(cell), freedSize, kInvalidHeapValue);
#endif
      free(header);
    }

#ifndef NDEBUG
#ifdef HERMESVM_SANITIZE_HANDLES
                                                                            
                                                                                
                                                                  
    assert(
        pointers_.size() >= newPointers_.size() &&
        "There cannot be more new pointers than there are old pointers");
    numCollectedObjects_ = pointers_.size() - newPointers_.size();
#else
                                                                       
                                                                           
                 
    numCollectedObjects_ = pointers_.size();
#endif
    numReachableObjects_ = newPointers_.size();
    numAllocatedObjects_ = newPointers_.size();
#endif
    pointers_ = std::move(newPointers_);
    assert(
        newPointers_.empty() &&
        "newPointers_ should be empty between collections");
                                            
    for (CellHeader *header : pointers_) {
      assert(header->isMarked() && "Should only be live pointers left");
      header->unmark();
    }
  }

                                                                    
#ifdef HERMES_SLOW_DEBUG
  checkWellFormed();
#endif
                                                                 
  if (allocatedBytes_ >= sizeLimit_ * 3 / 4) {
    sizeLimit_ = std::min(maxSize_, sizeLimit_ * 2);
  }

  const auto cpuEnd = oscompat::thread_cpu_time();
  const auto wallEnd = steady_clock::now();

  GCAnalyticsEvent event{
      getName(),
      kGCName,
      "full",
      std::move(cause),
      std::chrono::duration_cast<std::chrono::milliseconds>(
          wallEnd - wallStart),
      std::chrono::duration_cast<std::chrono::milliseconds>(cpuEnd - cpuStart),
                    BeforeAndAfter{allocatedBefore, allocatedBytes_},
                                                                                
                                                       
               BeforeAndAfter{allocatedBefore, allocatedBytes_},
                                                                            
                                          
                   BeforeAndAfter{externalBefore, externalBytes_},
                       
      allocatedBefore ? (allocatedBytes_ * 1.0) / allocatedBefore : 0,
               {}};

  recordGCStats(event,                 true);
  checkTripwire(allocatedBytes_ + externalBytes_);
}

void MallocGC::drainMarkStack(MarkingAcceptor &acceptor) {
  while (!acceptor.worklist_.empty()) {
    CellHeader *header = acceptor.worklist_.back();
    acceptor.worklist_.pop_back();
    assert(header->isMarked() && "Pointer on the worklist isn't marked");
    GCCell *cell = header->data();
    markCell(cell, acceptor);
    allocatedBytes_ += cell->getAllocatedSize();
  }
}

void MallocGC::markWeakMapEntrySlots(MarkingAcceptor &acceptor) {
  bool newlyMarkedValue;
  do {
    newlyMarkedValue = false;
    weakMapEntrySlots_.forEach([this, &acceptor](WeakMapEntrySlot &slot) {
      if (!slot.key || !slot.owner)
        return;
      GCCell *ownerMapCell = slot.owner.getNoBarrierUnsafe(getPointerBase());
                                                                            
      if (!CellHeader::from(ownerMapCell)->isMarked())
        return;
      GCCell *cell = slot.key.getNoBarrierUnsafe(getPointerBase());
                                                                  
                                                                     
      if (!CellHeader::from(cell)->isMarked())
        return;
      acceptor.accept(slot.mappedValue);
    });
    newlyMarkedValue = !acceptor.worklist_.empty();
    drainMarkStack(acceptor);
  } while (newlyMarkedValue);

                                                                              
  weakMapEntrySlots_.forEach([this](WeakMapEntrySlot &slot) {
    if (!slot.key || !slot.owner) {
      slot.mappedValue = HermesValue::encodeEmptyValue();
      return;
    }
    GCCell *cell = slot.key.getNoBarrierUnsafe(getPointerBase());
    GCCell *ownerMapCell = slot.owner.getNoBarrierUnsafe(getPointerBase());
    if (!CellHeader::from(ownerMapCell)->isMarked() ||
        !CellHeader::from(cell)->isMarked()) {
      slot.mappedValue = HermesValue::encodeEmptyValue();
    }
  });
}

void MallocGC::finalizeAll() {
  for (CellHeader *header : pointers_) {
    GCCell *cell = header->data();
    cell->getVT()->finalizeIfExists(cell, *this);
  }
}

void MallocGC::printStats(JSONEmitter &json) {
  GCBase::printStats(json);
  json.emitKey("specific");
  json.openDict();
  json.emitKeyValue("collector", kGCName);
  json.emitKey("stats");
  json.openDict();
  json.closeDict();
  json.closeDict();
}

std::string MallocGC::getKindAsStr() const {
  return kGCName;
}

void MallocGC::resetStats() {
#ifndef NDEBUG
  numAllocatedObjects_ = 0;
  numReachableObjects_ = 0;
  numCollectedObjects_ = 0;
  numMarkedSymbols_ = 0;
  numHiddenClasses_ = 0;
  numLeafHiddenClasses_ = 0;
#endif
  allocatedBytes_ = 0;
  numFinalizedObjects_ = 0;
}

void MallocGC::getHeapInfo(HeapInfo &info) {
  GCBase::getHeapInfo(info);
  info.allocatedBytes = allocatedBytes_;
                                        
  info.heapSize = 0;
  info.externalBytes = externalBytes_;
}
void MallocGC::getHeapInfoWithMallocSize(HeapInfo &info) {
  getHeapInfo(info);
  GCBase::getHeapInfoWithMallocSize(info);
                                                                    
                                       
  for (CellHeader *header : pointers_) {
    GCCell *cell = header->data();
    info.mallocSizeEstimate += cell->getVT()->getMallocSize(cell);
  }
}

void MallocGC::getCrashManagerHeapInfo(CrashManager::HeapInformation &info) {
  info.used_ = allocatedBytes_;
                                        
  info.size_ = 0;
}

void MallocGC::forAllObjs(const std::function<void(GCCell *)> &callback) {
  for (auto *ptr : pointers_) {
    callback(ptr->data());
  }
}

#ifndef NDEBUG
bool MallocGC::validPointer(const void *p) const {
  return dbgContains(p) && static_cast<const GCCell *>(p)->isValid();
}

bool MallocGC::dbgContains(const void *p) const {
  auto *ptr = reinterpret_cast<GCCell *>(const_cast<void *>(p));
  CellHeader *header = CellHeader::from(ptr);
  bool isValid = pointers_.find(header) != pointers_.end();
  isValid = isValid || newPointers_.find(header) != newPointers_.end();
  return isValid;
}

bool MallocGC::needsWriteBarrier(void *loc, GCCell *value) {
  return false;
}
#endif

#ifdef HERMES_MEMORY_INSTRUMENTATION
void MallocGC::createSnapshot(llvh::raw_ostream &os, bool captureNumericValue) {
  GCCycle cycle{*this};
  GCBase::createSnapshot(*this, os, captureNumericValue);
}
#endif

void MallocGC::creditExternalMemory(GCCell *, uint32_t size) {
  externalBytes_ += size;
}
void MallocGC::debitExternalMemory(GCCell *, uint32_t size) {
  externalBytes_ -= size;
}

                                
      

template void *MallocGC::alloc<              true, HasFinalizer::Yes>(
    uint32_t size);
template void *MallocGC::alloc<              false, HasFinalizer::Yes>(
    uint32_t size);
template void *MallocGC::alloc<              true, HasFinalizer::No>(
    uint32_t size);
template void *MallocGC::alloc<              false, HasFinalizer::No>(
    uint32_t size);
      

}                
}                    
#undef DEBUG_TYPE

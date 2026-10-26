/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/HadesGC.h"

#include "hermes/Support/Compiler.h"
#include "hermes/Support/ErrorHandling.h"
#include "hermes/VM/AllocResult.h"
#include "hermes/VM/CheckHeapWellFormedAcceptor.h"
#include "hermes/VM/FillerCell.h"
#include "hermes/VM/GCBase-inline.h"
#include "hermes/VM/GCPointer.h"
#include "hermes/VM/HermesValue-inline.h"
#include "hermes/VM/RootAndSlotAcceptorDefault.h"
#include "hermes/VM/SmallHermesValue-inline.h"

#include <array>
#include <functional>
#include <stack>

#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif

namespace hermes {
namespace vm {

static const char *kGCName =
    kConcurrentGC ? "hades (concurrent)" : "hades (incremental)";

static const char *kCompacteeNameForCrashMgr = "COMPACT";

                                           
static constexpr size_t kTargetMaxPauseMs = 50;

                                                                            
                                                                          
                                                           
static_assert(HadesGC::HeapSegment::maxSize() <= HadesGC::maxAllocationSize());

                                             
const VTable HadesGC::OldGen::FreelistCell::vt{
    CellKind::FreelistKind,
                     0};

void FreelistBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  mb.setVTable(&HadesGC::OldGen::FreelistCell::vt);
}

GCCell *HadesGC::OldGen::finishAlloc(GCCell *cell, uint32_t sz) {
                                                      
  incrementAllocatedBytes(sz);
                                                                      
  HeapSegment::setCellMarkBit(cell);
                                                                          
            
  return cell;
}

void HadesGC::OldGen::SegmentBucket::addToFreelist(SegmentBucket *dummyHead) {
  auto *oldHead = dummyHead->next;
  if (oldHead)
    oldHead->prev = this;
  prev = dummyHead;
  next = oldHead;
  dummyHead->next = this;
}

void HadesGC::OldGen::SegmentBucket::removeFromFreelist() const {
  if (next)
    next->prev = prev;
  prev->next = next;
}

void HadesGC::OldGen::addCellToFreelist(
    void *addr,
    uint32_t sz,
    SegmentBucket *segBucket) {
  assert(
      sz >= sizeof(FreelistCell) &&
      "Cannot construct a FreelistCell into an allocation in the OG");
  FreelistCell *newFreeCell = constructCell<FreelistCell>(addr, sz);
  HeapSegment::setCellHead(static_cast<GCCell *>(addr), sz);
  addCellToFreelist(newFreeCell, segBucket);
}

void HadesGC::OldGen::addCellToFreelist(
    FreelistCell *cell,
    SegmentBucket *segBucket) {
  const size_t sz = cell->getAllocatedSize();
                                                                       
  CompressedPointer oldHead = segBucket->head;
  cell->next_ = oldHead;
  segBucket->head =
      CompressedPointer::encodeNonNull(cell, gc_.getPointerBase());

                                                                   
  if (!oldHead) {
    uint32_t bucket = getFreelistBucket(sz);
    auto *dummyHead = &buckets_[bucket];
    segBucket->addToFreelist(dummyHead);

                                                                                
    freelistBucketBitArray_.set(bucket, true);
  }

                                                                          
                                                                 
                                                                              
                                                                              
                                                                             
                                                
  __asan_poison_memory_region(cell + 1, sz - sizeof(FreelistCell));
}

void HadesGC::OldGen::addCellToFreelistFromSweep(
    char *freeRangeStart,
    char *freeRangeEnd,
    SegmentBuckets &segBuckets,
    bool setHead) {
  assert(
      gc_.concurrentPhase_ == Phase::Sweep &&
      "addCellToFreelistFromSweep should only be called during sweeping.");
  size_t newCellSize = freeRangeEnd - freeRangeStart;
                                                                             
                     
  if (setHead)
    HeapSegment::setCellHead(
        reinterpret_cast<GCCell *>(freeRangeStart), newCellSize);
  auto *newCell = constructCell<FreelistCell>(freeRangeStart, newCellSize);
                                                  
  const uint32_t bucket = getFreelistBucket(newCellSize);
                                                                       
  auto *segBucket = &segBuckets[bucket];
  newCell->next_ = segBucket->head;
  segBucket->head =
      CompressedPointer::encodeNonNull(newCell, gc_.getPointerBase());
  __asan_poison_memory_region(newCell + 1, newCellSize - sizeof(FreelistCell));
}

HadesGC::OldGen::FreelistCell *HadesGC::OldGen::removeCellFromFreelist(
    size_t bucket,
    SegmentBucket *segBucket) {
  return removeCellFromFreelist(&segBucket->head, bucket, segBucket);
}

HadesGC::OldGen::FreelistCell *HadesGC::OldGen::removeCellFromFreelist(
    AssignableCompressedPointer *prevLoc,
    size_t bucket,
    SegmentBucket *segBucket) {
  FreelistCell *cell =
      vmcast<FreelistCell>(prevLoc->getNonNull(gc_.getPointerBase()));
  assert(cell && "Cannot get a null cell from freelist");

                                                              
  *prevLoc = cell->next_;
                                                              
  if (!segBucket->head) {
    segBucket->removeFromFreelist();

                                                                             
                                       
    freelistBucketBitArray_.set(bucket, buckets_[bucket].next);
  }

                                                        
  __asan_unpoison_memory_region(
      cell + 1, cell->getAllocatedSize() - sizeof(FreelistCell));
  return cell;
}

            
void HadesGC::HeapSegment::setCellHead(
    const GCCell *cellStart,
    const size_t sz) {
  const char *start = reinterpret_cast<const char *>(cellStart);
  const char *end = start + sz;
  CardTable *cards = cardTableCovering(start);
  auto boundary = cards->nextBoundary(start);
                                                                   
                   
  if (boundary.address() < end) {
    cards->updateBoundaries(&boundary, start, end);
  }
}

GCCell *HadesGC::HeapSegment::getFirstCellHead(size_t cardIdx) {
  CardTable &cards = cardTable();
  GCCell *cell = cards.firstObjForCard(cardIdx);
  assert(cell->isValid() && "Object head doesn't point to a valid object");
  return cell;
}

template <typename CallbackFunction>
void HadesGC::HeapSegment::forAllObjs(CallbackFunction callback) {
  for (GCCell *cell : cells()) {
                              
    if (!vmisa<OldGen::FreelistCell>(cell)) {
      callback(cell);
    }
  }
}

template <typename CallbackFunction>
void HadesGC::HeapSegment::forCompactedObjs(
    CallbackFunction callback,
    PointerBase &base) {
  void *const stop = level();
  GCCell *cell = reinterpret_cast<GCCell *>(start());
  while (cell < stop) {
    if (cell->hasMarkedForwardingPointer()) {
                                                  
      cell = reinterpret_cast<GCCell *>(
          reinterpret_cast<char *>(cell) +
          cell->getMarkedForwardingPointer()
              .getNonNull(base)
              ->getAllocatedSize());
    } else {
                                                                    
                                                                             
                                                                             
                           
      callback(cell);
      cell = cell->nextCell();
    }
  }
}

GCCell *HadesGC::OldGen::FreelistCell::carve(uint32_t sz) {
  const auto origSize = getAllocatedSize();
  assert(
      origSize >= sz + minAllocationSize() &&
      "Can't split if it would leave too small of a second cell");
  const auto finalSize = origSize - sz;
  char *newCellAddress = reinterpret_cast<char *>(this) + finalSize;
  GCCell *const newCell = reinterpret_cast<GCCell *>(newCellAddress);
  setSizeFromGC(finalSize);
  HeapSegment::setCellHead(newCell, sz);
  return newCell;
}

class HadesGC::CollectionStats final {
 public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = std::chrono::time_point<Clock>;
  using Duration = std::chrono::microseconds;

  CollectionStats(HadesGC &gc, std::string cause, std::string collectionType)
      : gc_{gc},
        cause_{std::move(cause)},
        collectionType_{std::move(collectionType)} {}
  ~CollectionStats() {
    assert(usedDbg_ && "Stats not submitted.");
  }

  void addCollectionType(std::string collectionType) {
    if (std::find(tags_.begin(), tags_.end(), collectionType) == tags_.end())
      tags_.emplace_back(std::move(collectionType));
  }

                                                                             
             
  void setBeforeSizes(uint64_t allocated, uint64_t external, uint64_t sz) {
    allocatedBefore_ = allocated;
    externalBefore_ = external;
    sizeBefore_ = sz;
  }

                                                             
  void setSweptBytes(uint64_t sweptBytes) {
    sweptBytes_ = sweptBytes;
  }

  void setSweptExternalBytes(uint64_t externalBytes) {
    sweptExternalBytes_ = externalBytes;
  }

  void setAfterSize(uint64_t sz) {
    sizeAfter_ = sz;
  }

                                                      
  void setBeginTime() {
    assert(beginTime_ == Clock::time_point{} && "Begin time already set");
    beginTime_ = Clock::now();
  }

                                                   
  void setEndTime() {
    assert(endTime_ == Clock::time_point{} && "End time already set");
    endTime_ = Clock::now();
  }

  std::chrono::milliseconds getElapsedTime() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - beginTime_);
  }

                                               
                                                                               
                                                     
  void beginCPUTimeSection() {
    assert(
        cpuTimeSectionStart_ == Duration{} &&
        "Must end cpu time section before starting another");
    cpuTimeSectionStart_ = oscompat::thread_cpu_time();
  }
  void endCPUTimeSection() {
    cpuDuration_ += oscompat::thread_cpu_time() - cpuTimeSectionStart_;
    cpuTimeSectionStart_ = {};
  }

  uint64_t beforeAllocatedBytes() const {
    return allocatedBefore_;
  }

                                                                          
                                                                           
                       
  uint64_t afterAllocatedBytes() const {
    assert(sweptBytes_ <= allocatedBefore_);
    return allocatedBefore_ - sweptBytes_;
  }

  uint64_t afterExternalBytes() const {
    assert(sweptExternalBytes_ <= externalBefore_);
    return externalBefore_ - sweptExternalBytes_;
  }

  double survivalRatio() const {
    return allocatedBefore_
        ? static_cast<double>(afterAllocatedBytes()) / allocatedBefore_
        : 0;
  }

  void markUsed() {
    assert(!std::exchange(usedDbg_, true) && "markUsed called twice");
  }

  GCAnalyticsEvent getEvent() && {
    markUsed();
    return GCAnalyticsEvent{
        gc_.getName(),
        gc_.getKindAsStr(),
        collectionType_,
        std::move(cause_),
        std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime_ - beginTime_),
        std::chrono::duration_cast<std::chrono::milliseconds>(cpuDuration_),
                      BeforeAndAfter{allocatedBefore_, afterAllocatedBytes()},
                 BeforeAndAfter{sizeBefore_, sizeAfter_},
                     BeforeAndAfter{externalBefore_, afterExternalBytes()},
                          survivalRatio(),
                 std::move(tags_)};
  }

 private:
  HadesGC &gc_;
  std::string cause_;
  std::string collectionType_;
  std::vector<std::string> tags_;
  TimePoint beginTime_{};
  TimePoint endTime_{};
  Duration cpuTimeSectionStart_{};
  Duration cpuDuration_{};
  uint64_t allocatedBefore_{0};
  uint64_t externalBefore_{0};
  uint64_t sizeBefore_{0};
  uint64_t sizeAfter_{0};
  uint64_t sweptBytes_{0};
  uint64_t sweptExternalBytes_{0};

#ifndef NDEBUG
  bool usedDbg_{false};
#endif
};

template <typename T>
static T convertPtr(PointerBase &, CompressedPointer cp) {
  return cp;
}
template <>
             GCCell *convertPtr(PointerBase &base, CompressedPointer cp) {
  return cp.get(base);
}
template <typename T>
static T convertPtr(PointerBase &, GCCell *p) {
  return p;
}
template <>
             CompressedPointer convertPtr(PointerBase &base, GCCell *a) {
  return CompressedPointer::encodeNonNull(a, base);
}

template <bool CompactionEnabled>
class HadesGC::EvacAcceptor final : public RootAndSlotAcceptor,
                                    public WeakRootAcceptor {
 public:
  EvacAcceptor(HadesGC &gc)
      : gc{gc},
        pointerBase_{gc.getPointerBase()},
        copyListHead_{nullptr},
        isTrackingIDs_{gc.isTrackingIDs()} {}

  ~EvacAcceptor() override {}

                                                                              
                                                                         
                  
  inline bool shouldForward(const void *ptr) const {
    return gc.inYoungGen(ptr) ||
        (CompactionEnabled && gc.compactee_.evacContains(ptr));
  }
  inline bool shouldForward(CompressedPointer ptr) const {
    return gc.inYoungGen(ptr) ||
        (CompactionEnabled && gc.compactee_.evacContains(ptr));
  }

  LLVM_NODISCARD GCCell *acceptRoot(GCCell *ptr) {
    if (shouldForward(ptr))
      return forwardCell<GCCell *>(ptr);
    return ptr;
  }

  LLVM_NODISCARD GCCell *acceptHeap(GCCell *ptr, void *heapLoc) {
    if (shouldForward(ptr)) {
      assert(
          HeapSegment::getCellMarkBit(ptr) &&
          "Should only evacuate marked objects.");
      return forwardCell<GCCell *>(ptr);
    }
    if (CompactionEnabled && gc.compactee_.contains(ptr)) {
                                                                             
                                                         
      HeapSegment::cardTableCovering(heapLoc)->dirtyCardForAddress(heapLoc);
    }
    return ptr;
  }

  LLVM_NODISCARD CompressedPointer
  acceptHeap(CompressedPointer cptr, void *heapLoc) {
    if (shouldForward(cptr)) {
      GCCell *ptr = cptr.getNonNull(pointerBase_);
      assert(
          HeapSegment::getCellMarkBit(ptr) &&
          "Should only evacuate marked objects.");
      return forwardCell<CompressedPointer>(ptr);
    }
    if (CompactionEnabled && gc.compactee_.contains(cptr)) {
                                                                             
                                                         
      HeapSegment::cardTableCovering(heapLoc)->dirtyCardForAddress(heapLoc);
    }
    return cptr;
  }

  template <typename T>
  LLVM_NODISCARD T forwardCell(GCCell *const cell) {
    assert(
        HeapSegment::getCellMarkBit(cell) && "Cannot forward unmarked object");
    if (cell->hasMarkedForwardingPointer()) {
                                                                  
      CompressedPointer forwardedCell = cell->getMarkedForwardingPointer();
      assert(
          forwardedCell.getNonNull(pointerBase_)->isValid() &&
          "Cell was forwarded incorrectly");
      return convertPtr<T>(pointerBase_, forwardedCell);
    }
    assert(cell->isValid() && "Encountered an invalid cell");
    const auto cellSize = cell->getAllocatedSize();
                                                             
    GCCell *const newCell = gc.oldGen_.alloc(cellSize);
    HERMES_SLOW_ASSERT(
        gc.inOldGen(newCell) && "Evacuated cell not in the old gen");
    assert(
        HeapSegment::getCellMarkBit(newCell) &&
        "Cell must be marked when it is allocated into the old gen");
                                                                       
    std::memcpy(newCell, cell, cellSize);
    assert(newCell->isValid() && "Cell was copied incorrectly");
    evacuatedBytes_ += cellSize;
    CopyListCell *const copyCell = static_cast<CopyListCell *>(cell);
                                                 
    copyCell->setMarkedForwardingPointer(
        CompressedPointer::encodeNonNull(newCell, pointerBase_));
    if (isTrackingIDs_) {
      gc.moveObject(cell, cellSize, newCell, cellSize);
    }
                                 
    push(copyCell);
    return convertPtr<T>(pointerBase_, newCell);
  }

  void accept(GCCell *&ptr) override {
    ptr = acceptRoot(ptr);
  }

  void accept(GCPointerBase &ptr) override {
    ptr.setInGC(acceptHeap(ptr, &ptr));
  }

  void accept(PinnedHermesValue &hv) override {
    assert((!hv.isPointer() || hv.getPointer()) && "Value is not nullable.");
    acceptNullable(hv);
  }

  void acceptNullable(PinnedHermesValue &hv) override {
    if (hv.isPointer()) {
      GCCell *forwardedPtr = acceptRoot(static_cast<GCCell *>(hv.getPointer()));
      hv.setInGC(hv.updatePointer(forwardedPtr), gc);
    }
  }

  void accept(GCHermesValue &hv) override {
    if (hv.isPointer()) {
      GCCell *forwardedPtr =
          acceptHeap(static_cast<GCCell *>(hv.getPointer()), &hv);
      hv.setInGC(hv.updatePointer(forwardedPtr), gc);
    }
  }

  void accept(GCSmallHermesValue &hv) override {
    if (hv.isPointer()) {
      CompressedPointer forwardedPtr = acceptHeap(hv.getPointer(), &hv);
      hv.setInGC(hv.updatePointer(forwardedPtr), gc);
    }
  }

  void acceptWeak(WeakRootBase &wr) override {
                                                                                
                                                        
    GCCell *const ptr = wr.getNoBarrierUnsafe(pointerBase_);

    if (!shouldForward(ptr))
      return;

    if (ptr->hasMarkedForwardingPointer()) {
                                                                  
      CompressedPointer forwardedCell = ptr->getMarkedForwardingPointer();
      assert(
          forwardedCell.getNonNull(pointerBase_)->isValid() &&
          "Cell was forwarded incorrectly");
                                                   
      wr = forwardedCell;
    } else {
      wr = nullptr;
    }
  }

  void accept(const RootSymbolID &sym) override {}
  void accept(const GCSymbolID &sym) override {}

  uint64_t evacuatedBytes() const {
    return evacuatedBytes_;
  }

  CopyListCell *pop() {
    if (!copyListHead_) {
      return nullptr;
    } else {
      CopyListCell *const cell =
          static_cast<CopyListCell *>(copyListHead_.getNonNull(pointerBase_));
      assert(HeapSegment::getCellMarkBit(cell) && "Discovered unmarked object");
      copyListHead_ = cell->next_;
      return cell;
    }
  }

 private:
  HadesGC &gc;
  PointerBase &pointerBase_;
                                                                               
  AssignableCompressedPointer copyListHead_;
  const bool isTrackingIDs_;
  uint64_t evacuatedBytes_{0};

  void push(CopyListCell *cell) {
    cell->next_ = copyListHead_;
    copyListHead_ = CompressedPointer::encodeNonNull(cell, pointerBase_);
  }
};

class MarkWorklist {
 private:
                                                                               
                 
  template <typename T, size_t N>
  class FixedCapacityVector {
   public:
    explicit FixedCapacityVector() : FixedCapacityVector(0) {}
    explicit FixedCapacityVector(size_t sz) : size_(sz) {}
    explicit FixedCapacityVector(const FixedCapacityVector &vec)
        : data_(vec.data_), size_(vec.size_) {}

    size_t size() const {
      return size_;
    }

    constexpr size_t capacity() const {
      return N;
    }

    bool empty() const {
      return size_ == 0;
    }

    void push_back(T elem) {
      assert(
          size_ < N && "Trying to push off the end of a FixedCapacityVector");
      data_[size_++] = elem;
    }

    T *data() {
      return data_.data();
    }

    void clear() {
#ifndef NDEBUG
                                                                            
               
      std::memset(data_.data(), kInvalidHeapValue, sizeof(GCCell *) * N);
#endif
      size_ = 0;
    }

   private:
    std::array<T, N> data_;
    size_t size_;
  };

 public:
                                              
  void enqueue(GCCell *cell) {
    pushChunk_.push_back(cell);
    if (pushChunk_.size() == pushChunk_.capacity()) {
                                                                             
      flushPushChunk();
    }
  }

                                           
  llvh::SmallVector<GCCell *, 0> drain() {
    llvh::SmallVector<GCCell *, 0> cells;
                                                                             
                                              
    std::lock_guard<Mutex> lk{mtx_};
    std::swap(cells, worklist_);
    assert(worklist_.empty() && "worklist isn't cleared out");
                                                                 
    worklist_.reserve(cells.size());
    return cells;
  }

                                                                                
                                           
                                                                                
  void flushPushChunk() {
    std::lock_guard<Mutex> lk{mtx_};
    worklist_.insert(
        worklist_.end(),
        pushChunk_.data(),
        pushChunk_.data() + pushChunk_.size());
                                                         
    pushChunk_.clear();
  }

                                                                                
                        
  bool hasPendingWork() {
    std::lock_guard<Mutex> lk{mtx_};
    return !worklist_.empty();
  }

#ifndef NDEBUG
                                                              
  bool empty() {
    std::lock_guard<Mutex> lk{mtx_};
    return pushChunk_.empty() && worklist_.empty();
  }
#endif

 private:
  Mutex mtx_;
  static constexpr size_t kChunkSize = 128;
  using Chunk = FixedCapacityVector<GCCell *, kChunkSize>;
  Chunk pushChunk_;
                                                                      
  llvh::SmallVector<GCCell *, 0> worklist_;
};

class HadesGC::MarkAcceptor final : public RootAndSlotAcceptor {
 public:
  MarkAcceptor(HadesGC &gc)
      : gc{gc},
        pointerBase_{gc.getPointerBase()},
        markedSymbols_{gc.gcCallbacks_.getSymbolsEnd()},
        writeBarrierMarkedSymbols_{gc.gcCallbacks_.getSymbolsEnd()} {}

  void acceptHeap(GCCell *cell, const void *heapLoc) {
    assert(cell && "Cannot pass null pointer to acceptHeap");
    assert(!gc.inYoungGen(heapLoc) && "YG slot found in OG marking");
    if (gc.compactee_.contains(cell) && !gc.compactee_.contains(heapLoc)) {
                                                                             
                            
      HeapSegment::cardTableCovering(heapLoc)->dirtyCardForAddress(heapLoc);
    }
    if (HeapSegment::getCellMarkBit(cell)) {
                                                        
      return;
    }
                                                                               
                                                                      
    assert(cell->isValid() && "Encountered an invalid cell");
    push(cell);
  }

  void acceptRoot(GCCell *cell) {
    assert(cell->isValid() && "Encountered an invalid cell");
    if (!HeapSegment::getCellMarkBit(cell))
      push(cell);
  }

  void accept(GCCell *&ptr) override {
    if (ptr)
      acceptRoot(ptr);
  }

  void accept(GCPointerBase &ptr) override {
    if (auto cp = concurrentRead<CompressedPointer>(ptr))
      acceptHeap(cp.getNonNull(pointerBase_), &ptr);
  }

  void accept(GCHermesValue &hvRef) override {
    HermesValue hv = concurrentRead<HermesValue>(hvRef);
    if (hv.isPointer()) {
      acceptHeap(static_cast<GCCell *>(hv.getPointer()), &hvRef);
    } else if (hv.isSymbol()) {
      acceptSym(hv.getSymbol());
    }
  }

  void accept(PinnedHermesValue &hv) override {
                                                                              
                                              
    if (hv.isPointer()) {
      acceptRoot(static_cast<GCCell *>(hv.getPointer()));
    } else if (hv.isSymbol()) {
      acceptSym(hv.getSymbol());
    }
  }
  void acceptNullable(PinnedHermesValue &hv) override {
    if (hv.isPointer()) {
      if (void *ptr = hv.getPointer())
        acceptRoot(static_cast<GCCell *>(ptr));
    } else if (hv.isSymbol()) {
      acceptSym(hv.getSymbol());
    }
  }

  void accept(GCSmallHermesValue &hvRef) override {
    const SmallHermesValue hv = concurrentRead<SmallHermesValue>(hvRef);
    if (hv.isPointer()) {
      acceptHeap(hv.getPointer(pointerBase_), &hvRef);
    } else if (hv.isSymbol()) {
      acceptSym(hv.getSymbol());
    }
  }

  void acceptSym(SymbolID sym) {
    const uint32_t idx = sym.unsafeGetIndex();
    if (sym.isInvalid() || idx >= markedSymbols_.size()) {
                                                                              
                                   
      return;
    }
    markedSymbols_[idx] = true;
  }

  void accept(const RootSymbolID &sym) override {
    acceptSym(sym);
  }
  void accept(const GCSymbolID &sym) override {
    acceptSym(concurrentRead<SymbolID>(sym));
  }

                                                      
  void markSymbol(SymbolID sym) {
    assert(
        !gc.calledByBackgroundThread() &&
        "Write barrier invoked by background thread.");
    const uint32_t idx = sym.unsafeGetIndex();
    if (sym.isInvalid() || idx >= writeBarrierMarkedSymbols_.size()) {
                                                                              
                                   
      return;
    }
    writeBarrierMarkedSymbols_[idx] = true;
  }

                                                                            
  void setDrainRate(size_t rate) {
    assert(!kConcurrentGC && "Drain rate is only used by incremental GC.");
    byteDrainRate_ = rate;
  }

                                                      
  uint64_t markedBytes() const {
    return markedBytes_;
  }

                                                    
                                                                                
                                        
  void drainAllWork() {
                                                                                
                                                                               
            
    drainSomeWork(std::numeric_limits<size_t>::max());
    assert(localWorklist_.empty() && "Some work left that wasn't completed");
  }

                                                                  
                                              
                                                                        
  bool drainSomeWork() {
                                                                            
                              
    constexpr size_t kConcurrentMarkLimit = 8192;
    return drainSomeWork(kConcurrentGC ? kConcurrentMarkLimit : byteDrainRate_);
  }

                                                    
                                                                     
               
                                                              
                                                                              
                                                                           
                      
                                                                        
  bool drainSomeWork(const size_t markLimit) {
    assert(gc.gcMutex_ && "Must hold the GC lock while accessing mark bits.");
                                                  
    auto cells = globalWorklist_.drain();
    for (GCCell *cell : cells) {
      assert(
          cell->isValid() && "Invalid cell received off the global worklist");
      assert(
          !gc.inYoungGen(cell) &&
          "Shouldn't ever traverse a YG object in this loop");
      HERMES_SLOW_ASSERT(
          gc.dbgContains(cell) && "Non-heap cell found in global worklist");
      if (!HeapSegment::getCellMarkBit(cell)) {
                                        
        push(cell);
      }
    }

    size_t numMarkedBytes = 0;
    assert(markLimit && "markLimit must be non-zero!");
    while (!localWorklist_.empty() && numMarkedBytes < markLimit) {
      GCCell *const cell = localWorklist_.top();
      localWorklist_.pop();
      assert(cell->isValid() && "Invalid cell in marking");
      assert(HeapSegment::getCellMarkBit(cell) && "Discovered unmarked object");
      assert(
          !gc.inYoungGen(cell) &&
          "Shouldn't ever traverse a YG object in this loop");
      HERMES_SLOW_ASSERT(
          gc.dbgContains(cell) && "Non-heap object discovered during marking");
      const auto sz = cell->getAllocatedSize();
      numMarkedBytes += sz;
      gc.markCell(cell, *this);
    }
    markedBytes_ += numMarkedBytes;
    return !localWorklist_.empty();
  }

  bool isLocalWorklistEmpty() const {
    return localWorklist_.empty();
  }

  MarkWorklist &globalWorklist() {
    return globalWorklist_;
  }

                                                                            
                                    
                                                                     
                                                                           
                                     
  llvh::BitVector &markedSymbols() {
    assert(gc.gcMutex_ && "Cannot call markedSymbols without a lock");
    markedSymbols_ |= writeBarrierMarkedSymbols_;
                                                                                
                      
    return markedSymbols_;
  }

 private:
  HadesGC &gc;
  PointerBase &pointerBase_;

                                                                             
                                                                             
                                                                     
  std::stack<GCCell *, std::vector<GCCell *>> localWorklist_;

                                                                          
                                                                          
                                                                              
                    
  MarkWorklist globalWorklist_;

                                                                             
                                                                         
                                                                             
                                                                              
                                                                            
                                                                 
  llvh::BitVector markedSymbols_;

                                                                            
                                                                               
                                                                               
  llvh::BitVector writeBarrierMarkedSymbols_;

                                                                           
                                        
                                           
  size_t byteDrainRate_{0};

                                                       
  uint64_t markedBytes_{0};

  void push(GCCell *cell) {
    assert(
        !HeapSegment::getCellMarkBit(cell) &&
        "A marked object should never be pushed onto a worklist");
    assert(
        !gc.inYoungGen(cell) &&
        "Shouldn't ever push a YG object onto the worklist");
    HeapSegment::setCellMarkBit(cell);
                                                                           
                                                                                
                                                                            
                                                    
    localWorklist_.push(cell);
  }

  template <typename T>
  T concurrentReadImpl(const T &valRef) {
    using Storage =
        typename std::conditional<sizeof(T) == 4, uint32_t, uint64_t>::type;
    static_assert(sizeof(T) == sizeof(Storage), "Sizes must match");
    union {
      Storage storage{};
      T val;
    } ret{};

                                                                           
                                                                          
                                            
                                                                            
                                                                       
                                             
                                                                
                        
                                                                      
                                                       
                                                                            
                                                                       
                                                                    
                                                                           
                              
                                                                         
                                                                         
                                                                         
                           
    TsanIgnoreReadsBegin();

                                                                       
                                                                              
                                                                     
                                                                            
                                                                           
                                                                            
                                                           
    ret.storage = *reinterpret_cast<Storage const volatile *>(&valRef);
    TsanIgnoreReadsEnd();
    return ret.val;
  }

  template <typename T>
  T concurrentRead(const T &ref) {
    return kConcurrentGC ? concurrentReadImpl<T>(ref) : ref;
  }
};

                                                                             
                         
                                                                            
                                               
class HadesGC::MarkWeakRootsAcceptor final : public WeakRootAcceptor {
 public:
  MarkWeakRootsAcceptor(HadesGC &gc) : gc_{gc} {}

  void acceptWeak(WeakRootBase &wr) override {
    if (!wr) {
      return;
    }
    GCCell *const cell = wr.getNoBarrierUnsafe(gc_.getPointerBase());
    HERMES_SLOW_ASSERT(gc_.dbgContains(cell) && "ptr not in heap");
    if (HeapSegment::getCellMarkBit(cell)) {
                                                         
      return;
    }
                                                
    wr = nullptr;
  }

 private:
  HadesGC &gc_;
};

class HadesGC::Executor {
 public:
  Executor() : thread_([this] { worker(); }) {}
  ~Executor() {
    {
      std::lock_guard<std::mutex> lk(mtx_);
      shutdown_ = true;
      cv_.notify_one();
    }
    thread_.join();
  }

                                                                      
  template <typename Fn>
  void add(Fn &&fn) {
    std::lock_guard<std::mutex> lk(mtx_);
    queue_.emplace_back(std::forward<Fn>(fn));
    cv_.notify_one();
  }

                                        
  std::thread::id getThreadId() const {
    return thread_.get_id();
  }

 private:
                                                       
  void worker() {
    oscompat::set_thread_name("hades");
    std::unique_lock<std::mutex> lk(mtx_);
    while (!shutdown_) {
      cv_.wait(lk, [this]() { return !queue_.empty() || shutdown_; });
      while (!queue_.empty()) {
        auto fn = std::move(queue_.front());
        queue_.pop_front();
        lk.unlock();
        fn();
        lk.lock();
      }
    }
  }

  std::mutex mtx_;
  std::condition_variable cv_;
  std::deque<std::function<void()>> queue_;
  bool shutdown_{false};
  std::thread thread_;
};

bool HadesGC::OldGen::sweepNext(bool backgroundThread) {
                                                                               
                                                                                
                                                              
  if (!sweepIterator_.segNumber)
    return false;
  assert(gc_.gcMutex_ && "gcMutex_ must be held while sweeping.");

  sweepIterator_.segNumber--;

  const bool isTracking = gc_.isTrackingIDs();
                                                                             
                                                                         
  const uint64_t externalBytesBefore = externalBytes();

  auto &segBuckets = segmentBuckets_[sweepIterator_.segNumber];

                                                                           
                                                            
                                                                            
                                                                           
                                                                          
            
  for (size_t bucket = 0; bucket < kNumFreelistBuckets; bucket++) {
    auto *segBucket = &segBuckets[bucket];
    if (segBucket->head) {
      segBucket->removeFromFreelist();
      segBucket->head = nullptr;
    }
  }

  char *freeRangeStart = nullptr, *freeRangeEnd = nullptr;
  size_t mergedCells = 0;
  int32_t segmentSweptBytes = 0;
  for (GCCell *cell : segments_[sweepIterator_.segNumber].cells()) {
    assert(cell->isValid() && "Invalid cell in sweeping");
    if (HeapSegment::getCellMarkBit(cell)) {
                                                                    
                                                                              
                                             
      if (kConcurrentGC && backgroundThread)
        continue;
      const uint32_t cellSize = cell->getAllocatedSize();
      const uint32_t trimmedSize =
          cell->getVT()->getTrimmedSize(cell, cellSize);
      assert(cellSize >= trimmedSize && "Growing objects is not supported.");
      assert(
          trimmedSize >= minAllocationSize() &&
          "Trimmed object must still meet minimum size.");
      assert(
          isSizeHeapAligned(trimmedSize) &&
          "Trimmed size must also be heap aligned");
      const uint32_t trimmableBytes = cellSize - trimmedSize;

                                                           
      if (LLVM_UNLIKELY(trimmableBytes >= minAllocationSize())) {
        static_cast<VariableSizeRuntimeCell *>(cell)->setSizeFromGC(
            trimmedSize);
        GCCell *newCell = cell->nextCell();
                                                                     
        constructCell<FillerCell>(newCell, trimmableBytes);
        assert(
            !HeapSegment::getCellMarkBit(newCell) &&
            "Trimmed space cannot be marked");
        HeapSegment::setCellHead(newCell, trimmableBytes);
#ifndef NDEBUG
        sweepIterator_.trimmedBytes += trimmableBytes;
#endif
      }
      continue;
    }

    const auto sz = cell->getAllocatedSize();
    char *const cellCharPtr = reinterpret_cast<char *>(cell);

    if (freeRangeEnd != cellCharPtr) {
      assert(
          freeRangeEnd < cellCharPtr &&
          "Should not overshoot the start of an object");
                                                                  
      if (LLVM_LIKELY(freeRangeStart))
        addCellToFreelistFromSweep(
            freeRangeStart, freeRangeEnd, segBuckets, mergedCells > 1);

      mergedCells = 0;
      freeRangeEnd = freeRangeStart = cellCharPtr;
    }
                                                                 
    freeRangeEnd += sz;
    mergedCells++;

    if (vmisa<FreelistCell>(cell))
      continue;

    segmentSweptBytes += sz;
                                                           
    cell->getVT()->finalizeIfExists(cell, gc_);
    if (isTracking && !vmisa<FillerCell>(cell)) {
      gc_.untrackObject(cell, sz);
    }
  }

                                             
  if (freeRangeStart)
    addCellToFreelistFromSweep(
        freeRangeStart, freeRangeEnd, segBuckets, mergedCells > 1);

                                                                             
                    
  for (size_t bucket = 0; bucket < kNumFreelistBuckets; ++bucket) {
    auto *segBucket = &segBuckets[bucket];
    if (segBucket->head)
      segBucket->addToFreelist(&buckets_[bucket]);

                                                                            
                                                                                
                                                                                
                                
    freelistBucketBitArray_.set(bucket, buckets_[bucket].next);
  }

                                      
  incrementAllocatedBytes(-segmentSweptBytes);
  sweepIterator_.sweptBytes += segmentSweptBytes;
  sweepIterator_.sweptExternalBytes += externalBytesBefore - externalBytes();

                                     
  if (sweepIterator_.segNumber)
    return true;

                                                              
  auto &stats = *gc_.ogCollectionStats_;

  auto sweptBytes = sweepIterator_.sweptBytes;
  auto preAllocated = stats.beforeAllocatedBytes();
  if (sweptBytes > preAllocated) {
                                                                                
                                                                           
                                    
    assert(sweepIterator_.trimmedBytes >= (sweptBytes - preAllocated));
                                                                            
                                                                                
                                           
    sweptBytes = preAllocated;
  }
  stats.setSweptBytes(sweptBytes);
  stats.setSweptExternalBytes(sweepIterator_.sweptExternalBytes);
  const uint64_t targetSizeBytes =
      (stats.afterAllocatedBytes() + stats.afterExternalBytes()) /
      gc_.occupancyTarget_;

                                                                            
                                                                                
                                                                                
                                    
  uint64_t clampedSizeBytes = std::min(targetSizeBytes, gc_.maxHeapSize_);
  targetSizeBytes_.update(clampedSizeBytes);
  sweepIterator_ = {};
  return false;
}

void HadesGC::OldGen::initializeSweep() {
  assert(
      !sweepIterator_.segNumber && !sweepIterator_.sweptBytes &&
      !sweepIterator_.sweptExternalBytes && "Sweep is already in progress.");
  sweepIterator_.segNumber = segments_.size();
}

size_t HadesGC::OldGen::sweepSegmentsRemaining() const {
  return sweepIterator_.segNumber;
}

size_t HadesGC::OldGen::getMemorySize() const {
  size_t memorySize = segments_.size() * sizeof(HeapSegment);
  memorySize += segmentBuckets_.size() * sizeof(SegmentBuckets);
  return memorySize;
}

                                                     
constexpr double kYGInitialSurvivalRatio = 0.3;

HadesGC::OldGen::OldGen(HadesGC &gc) : gc_(gc) {}

HadesGC::HadesGC(
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
          HeapKind::HadesGC),
      maxHeapSize_{std::max<uint64_t>(
          gcConfig.getMaxHeapSize(),
                                                        
          2 * AlignedStorage::size())},
      provider_(std::move(provider)),
      oldGen_{*this},
      backgroundExecutor_{
          kConcurrentGC ? std::make_unique<Executor>() : nullptr},
      promoteYGToOG_{!gcConfig.getAllocInYoung()},
      revertToYGAtTTI_{gcConfig.getRevertToYGAtTTI()},
      overwriteDeadYGObjects_{gcConfig.getOverwriteDeadYGObjects()},
      occupancyTarget_(gcConfig.getOccupancyTarget()),
      ygAverageSurvivalBytes_{           0.5,
                                       kYGInitialSizeFactor *
                                  HeapSegment::maxSize() *
                                  kYGInitialSurvivalRatio} {
  (void)vmExperimentFlags;
  std::lock_guard<Mutex> lk(gcMutex_);
  crashMgr_->setCustomData("HermesGC", getKindAsStr().c_str());
                                                                            
                          
  llvh::ErrorOr<HeapSegment> newYoungGen = createSegment();
  if (!newYoungGen)
    hermes_fatal("Failed to initialize the young gen", newYoungGen.getError());
  setYoungGen(std::move(newYoungGen.get()));
  const size_t initHeapSize = std::max<uint64_t>(
      {gcConfig.getMinHeapSize(),
       gcConfig.getInitHeapSize(),
       HeapSegment::maxSize()});
  oldGen_.setTargetSizeBytes(initHeapSize - HeapSegment::maxSize());
}

HadesGC::~HadesGC() {
                                                                               
                
  assert(
      concurrentPhase_ == Phase::None &&
      "Must call finalizeAll before destructor.");
}

void HadesGC::getHeapInfo(HeapInfo &info) {
  std::lock_guard<Mutex> lk{gcMutex_};
  GCBase::getHeapInfo(info);
  info.allocatedBytes = allocatedBytes();
                                                                               
  info.heapSize = (oldGen_.numSegments() + 1) * AlignedStorage::size();
                                                                                
  info.totalAllocatedBytes = totalAllocatedBytes_ + youngGen().used();
  info.va = info.heapSize;
  info.externalBytes = oldGen_.externalBytes() + getYoungGenExternalBytes();
  info.youngGenStats = ygCumulativeStats_;
  info.fullStats = ogCumulativeStats_;
  info.numCompactions = numCompactions_;
}

void HadesGC::getHeapInfoWithMallocSize(HeapInfo &info) {
                             
  getHeapInfo(info);
                                       
  GCBase::getHeapInfoWithMallocSize(info);
  std::lock_guard<Mutex> lk{gcMutex_};
                                                
  info.mallocSizeEstimate += gcCallbacks_.mallocSize();
                                                                         
                                            
  forAllObjs([&info](GCCell *cell) {
    info.mallocSizeEstimate += cell->getVT()->getMallocSize(cell);
  });
}

void HadesGC::getCrashManagerHeapInfo(
    CrashManager::HeapInformation &crashInfo) {
  HeapInfo info;
  getHeapInfo(info);
  crashInfo.size_ = info.heapSize;
  crashInfo.used_ = info.allocatedBytes;
}

#ifdef HERMES_MEMORY_INSTRUMENTATION
void HadesGC::createSnapshot(llvh::raw_ostream &os, bool captureNumericValue) {
  std::lock_guard<Mutex> lk{gcMutex_};
                                                                            
  NoAllocScope scope{*this};
                                                                      
  waitForCollectionToFinish("snapshot");
  {
    GCCycle cycle{*this, "GC Heap Snapshot"};
    GCBase::createSnapshot(*this, os, captureNumericValue);
  }
}

void HadesGC::snapshotAddGCNativeNodes(HeapSnapshot &snap) {
  GCBase::snapshotAddGCNativeNodes(snap);
  if (nativeIDs_.ygFinalizables == IDTracker::kInvalidNode) {
    nativeIDs_.ygFinalizables = getIDTracker().nextNativeID();
  }
  if (nativeIDs_.og == IDTracker::kInvalidNode) {
    nativeIDs_.og = getIDTracker().nextNativeID();
  }
  snap.beginNode();
  snap.endNode(
      HeapSnapshot::NodeType::Native,
      "std::vector<GCCell *>",
      nativeIDs_.ygFinalizables,
      youngGenFinalizables_.capacity() * sizeof(GCCell *),
      0);
  snap.beginNode();
  snap.endNode(
      HeapSnapshot::NodeType::Native,
      "OldGen",
      nativeIDs_.og,
      sizeof(oldGen_) + oldGen_.getMemorySize(),
      0);
}

void HadesGC::snapshotAddGCNativeEdges(HeapSnapshot &snap) {
  GCBase::snapshotAddGCNativeEdges(snap);
                                                                             
                                  
  assert(nativeIDs_.ygFinalizables != IDTracker::kInvalidNode);
  assert(nativeIDs_.og != IDTracker::kInvalidNode);
  snap.addNamedEdge(
      HeapSnapshot::EdgeType::Internal,
      "youngGenFinalizables",
      nativeIDs_.ygFinalizables);
  snap.addNamedEdge(HeapSnapshot::EdgeType::Internal, "oldGen", nativeIDs_.og);
}

void HadesGC::enableHeapProfiler(
    std::function<void(
        uint64_t,
        std::chrono::microseconds,
        std::vector<GCBase::AllocationLocationTracker::HeapStatsUpdate>)>
        fragmentCallback) {
  std::lock_guard<Mutex> lk{gcMutex_};
                                                                        
  waitForCollectionToFinish("heap profiler enable");
  GCBase::enableHeapProfiler(std::move(fragmentCallback));
}

void HadesGC::disableHeapProfiler() {
  std::lock_guard<Mutex> lk{gcMutex_};
                                                                         
  waitForCollectionToFinish("heap profiler disable");
  GCBase::disableHeapProfiler();
}

void HadesGC::enableSamplingHeapProfiler(
    size_t samplingInterval,
    int64_t seed) {
  std::lock_guard<Mutex> lk{gcMutex_};
                                                                        
  waitForCollectionToFinish("sampling heap profiler enable");
  GCBase::enableSamplingHeapProfiler(samplingInterval, seed);
}

void HadesGC::disableSamplingHeapProfiler(llvh::raw_ostream &os) {
  std::lock_guard<Mutex> lk{gcMutex_};
                                                                         
  waitForCollectionToFinish("sampling heap profiler disable");
  GCBase::disableSamplingHeapProfiler(os);
}
#endif                                 

void HadesGC::printStats(JSONEmitter &json) {
  GCBase::printStats(json);
  json.emitKey("specific");
  json.openDict();
  json.emitKeyValue("collector", getKindAsStr());
  json.emitKey("stats");
  json.openDict();
  json.emitKeyValue("Num compactions", numCompactions_);
  json.closeDict();
  json.closeDict();
}

std::string HadesGC::getKindAsStr() const {
  return kGCName;
}

void HadesGC::collect(std::string cause, bool                    ) {
  {
                                                                             
    std::lock_guard<Mutex> lk{gcMutex_};
                                                                            
                                                                                
                                                                           
    promoteYGToOG_ = false;
    waitForCollectionToFinish(cause);
  }
                                                            
                                                          
  youngGenCollection(cause,                           true);
  {
                                           
    std::lock_guard<Mutex> lk{gcMutex_};
    waitForCollectionToFinish(cause);
  }
                                                                     
                                                                   
                                                                                
                                                                        
                                                                       
                                                                     
  youngGenCollection(std::move(cause),                           false);
}

void HadesGC::waitForCollectionToFinish(std::string cause) {
  assert(
      gcMutex_ &&
      "gcMutex_ must be held before calling waitForCollectionToFinish");
  if (concurrentPhase_ == Phase::None) {
    return;
  }
  GCCycle cycle{*this, "GC Old Gen (Direct)"};

  assert(!ygCollectionStats_ && "Cannot collect OG during a YG collection");
  CollectionStats waitingStats(*this, std::move(cause), "waiting");
  waitingStats.beginCPUTimeSection();
  waitingStats.setBeginTime();

  while (concurrentPhase_ != Phase::None)
    incrementalCollect(false);

  waitingStats.endCPUTimeSection();
  waitingStats.setEndTime();
  recordGCStats(std::move(waitingStats).getEvent(), true);
}

void HadesGC::oldGenCollection(std::string cause, bool forceCompaction) {
                     
                                                              
                                               
                                                             
  assert(gcMutex_ && "gcMutex_ must be held when starting an OG collection");
  assert(
      gcMutex_.depth() == 1 &&
      "Need ability to release mutex in oldGenCollection.");
  assert(
      concurrentPhase_ == Phase::None &&
      "Starting a second old gen collection");
                                                      
  if (kConcurrentGC) {
                                                                          
                                                                               
                                                                              
                                                                  
    std::unique_lock<Mutex> lk{gcMutex_, std::adopt_lock};
    ogPauseCondVar_.wait(lk, [this] { return !backgroundTaskActive_; });
    lk.release();
  }
                                                                              
                           
  ygCollectionStats_->addCollectionType("old gen start");
#ifdef HERMES_SLOW_DEBUG
  checkWellFormed();
#endif
  ogCollectionStats_ =
      std::make_unique<CollectionStats>(*this, std::move(cause), "old");
                                                                            
                         
  if (kConcurrentGC)
    ogCollectionStats_->beginCPUTimeSection();
  ogCollectionStats_->setBeginTime();
  ogCollectionStats_->setBeforeSizes(
      oldGen_.allocatedBytes(), oldGen_.externalBytes(), segmentFootprint());

                                                                      
  promoteYGToOG_ = false;

                                                                         
                                                         
  for (HeapSegment &seg : oldGen_)
    seg.markBitArray().clear();

                                                                           
                                      
  gcCallbacks_.unmarkSymbols();

                                                     
                                                                                
                                                                       
                                                           
  oldGenMarker_.reset(new MarkAcceptor{*this});
  {
                                                                            
                         
    DroppingAcceptor<MarkAcceptor> nameAcceptor{*oldGenMarker_};
    markRoots(nameAcceptor,                   true);
                                                                        
                               
  }

  concurrentPhase_ = Phase::Mark;
                                                                             
                                          
  ogMarkingBarriers_ = true;
                                                                               
                                                                            
                                                                                
  prepareCompactee(forceCompaction);

                                                                           
                                                                           
                                                                     
                                                                         
                                                                         
                                                                           
                                 
                                                                                
                   
  oldGen_.initializeSweep();

  if (!kConcurrentGC) {
                                                                         
                                                                
                                                                               
                                                                                
                                                                     
                                                                

                                 
    oldGenMarker_->setDrainRate(getDrainRate());
    return;
  }
  ogCollectionStats_->endCPUTimeSection();
                                                                    
                                                                    
                                                                         
                                                                               
                                                                           
            
  collectOGInBackground();
                                                                          
}

void HadesGC::collectOGInBackground() {
  assert(gcMutex_ && "Must hold GC mutex when scheduling background work.");
  assert(
      !backgroundTaskActive_ && "Should only have one active task at a time");
  assert(kConcurrentGC && "Background work can only be done in concurrent GC");

  backgroundTaskActive_ = true;

  backgroundExecutor_->add([this]() {
    std::unique_lock<Mutex> lk(gcMutex_);
    while (true) {
                                                                           
                                                                               
                                        
      ogPauseCondVar_.wait(
          lk, [this] { return !ogPaused_.load(std::memory_order_relaxed); });
      assert(
          backgroundTaskActive_ &&
          "backgroundTaskActive_ must be true when the background task is in the loop.");
      incrementalCollect(true);
      if (concurrentPhase_ == Phase::None ||
          concurrentPhase_ == Phase::CompleteMarking) {
        backgroundTaskActive_ = false;
                                                                                
                         
        ogPauseCondVar_.notify_one();
        break;
      }
    }
  });
}

std::lock_guard<Mutex> HadesGC::pauseBackgroundTask() {
  assert(kConcurrentGC && "Should not be called in incremental mode");
  assert(!calledByBackgroundThread() && "Must be called from mutator");
                                                                    
                     
  ogPaused_.store(true, std::memory_order_relaxed);
                                                                         
  gcMutex_.lock();
                                                                               
                                                                       
  ogPaused_.store(false, std::memory_order_relaxed);
  ogPauseCondVar_.notify_one();
  return std::lock_guard(gcMutex_, std::adopt_lock);
}

void HadesGC::incrementalCollect(bool backgroundThread) {
  assert(gcMutex_ && "Must hold the GC mutex when calling incrementalCollect");
  switch (concurrentPhase_) {
    case Phase::None:
      break;
    case Phase::Mark:
      if (!kConcurrentGC && ygCollectionStats_)
        ygCollectionStats_->addCollectionType("marking");
                                                                         
                                                
      if (!oldGenMarker_->drainSomeWork())
        concurrentPhase_ = Phase::CompleteMarking;
      break;
    case Phase::CompleteMarking:
                                                                               
               
      if (!backgroundThread) {
        if (ygCollectionStats_)
          ygCollectionStats_->addCollectionType("complete marking");
        completeMarking();
        concurrentPhase_ = Phase::Sweep;
      }
      break;
    case Phase::Sweep:
      if (!kConcurrentGC && ygCollectionStats_)
        ygCollectionStats_->addCollectionType("sweeping");
                                                                 
      if (!oldGen_.sweepNext(backgroundThread)) {
                                             
        ogCollectionStats_->setEndTime();
        ogCollectionStats_->setAfterSize(segmentFootprint());
        concurrentPhase_ = Phase::None;
        if (!backgroundThread)
          checkTripwireAndSubmitStats();
      }
      break;
    default:
      llvm_unreachable("No other possible state between iterations");
  }
}

void HadesGC::prepareCompactee(bool forceCompaction) {
  assert(gcMutex_);
  assert(
      compactee_.empty() &&
      "Ongoing compaction at the start of an OG collection.");
  if (promoteYGToOG_)
    return;

#ifdef HERMESVM_SANITIZE_HANDLES
                                                            
  if (sanitizeRate_)
    forceCompaction = true;
#endif

                                                                             
                                                                            
                                                                               
            
  uint64_t buffer = std::max<uint64_t>(
      oldGen_.targetSizeBytes() / 20, HeapSegment::maxSize());
  uint64_t threshold = oldGen_.targetSizeBytes() + buffer;
  uint64_t totalBytes = oldGen_.size() + oldGen_.externalBytes();
  if ((forceCompaction || totalBytes > threshold) &&
      oldGen_.numSegments() > 1) {
    compactee_.segment = std::make_shared<HeapSegment>(oldGen_.popSegment());
    addSegmentExtentToCrashManager(
        *compactee_.segment, kCompacteeNameForCrashMgr);
    compactee_.start = compactee_.segment->lowLim();
    compactee_.startCP = CompressedPointer::encodeNonNull(
        reinterpret_cast<GCCell *>(compactee_.segment->lowLim()),
        getPointerBase());
  }
}

void HadesGC::finalizeCompactee() {
  char *stop = compactee_.segment->level();
  char *cur = compactee_.segment->start();
  PointerBase &base = getPointerBase();
                                                                                
                             
  int32_t preAllocated = 0;
  while (cur < stop) {
    auto *cell = reinterpret_cast<GCCell *>(cur);
    if (cell->hasMarkedForwardingPointer()) {
      auto size = cell->getMarkedForwardingPointer()
                      .getNonNull(base)
                      ->getAllocatedSize();
      preAllocated += size;
      cur += size;
    } else {
      auto size = cell->getAllocatedSize();
      if (!vmisa<OldGen::FreelistCell>(cell)) {
        cell->getVT()->finalizeIfExists(cell, *this);
        preAllocated += size;
      }
      cur += size;
    }
  }
                                                                                
                                                                               
                                
  oldGen_.incrementAllocatedBytes(-preAllocated);

  const size_t segIdx =
      SegmentInfo::segmentIndexFromStart(compactee_.segment->lowLim());
  segmentIndices_.push_back(segIdx);
  removeSegmentExtentFromCrashManager(std::to_string(segIdx));
  removeSegmentExtentFromCrashManager(kCompacteeNameForCrashMgr);
  compactee_ = {};
}

void HadesGC::updateOldGenThreshold() {
  const double markedBytes = oldGenMarker_->markedBytes();
  const double preAllocated = ogCollectionStats_->beforeAllocatedBytes();
  assert(markedBytes <= preAllocated && "Cannot mark more than was allocated");
  const double postAllocated = oldGen_.allocatedBytes();
  assert(postAllocated >= preAllocated && "Cannot free memory during marking");

                                                                              
                                                                            
                                                                               
                                                                               
                                                                              
                                                                      
                                                                             
                                                                              
                                                                                
                                        
  const auto concurrentMarkRate =
      markedBytes / std::max(postAllocated - preAllocated, 1.0);

                                                                    
                                                                               
                                                                                
                                                                          
                                                                       
                                                                             
                                                                               
                                                
  const auto clampedRate = std::min(concurrentMarkRate, 20.0);

                                                                               
                                                                                
                                                                         
                                                                      
                                                                               
                                                                              
                                           
                                   
                                                                               
                                                                       
                      
                                                                               
                                    
  ogThreshold_.update(clampedRate / (clampedRate + 1));
}

void HadesGC::markWeakMapEntrySlots() {
  bool newlyMarkedValue;
  do {
    newlyMarkedValue = false;
    weakMapEntrySlots_.forEach([this](WeakMapEntrySlot &slot) {
      if (!slot.key || !slot.owner)
        return;
      GCCell *ownerMapCell = slot.owner.getNoBarrierUnsafe(getPointerBase());
                                                                            
      if (!HeapSegment::getCellMarkBit(ownerMapCell))
        return;
      GCCell *cell = slot.key.getNoBarrierUnsafe(getPointerBase());
                                                                  
                                                                     
      if (!HeapSegment::getCellMarkBit(cell))
        return;
      oldGenMarker_->accept(slot.mappedValue);
    });
    newlyMarkedValue = !oldGenMarker_->isLocalWorklistEmpty();
    oldGenMarker_->drainAllWork();
  } while (newlyMarkedValue);

                                                                              
  weakMapEntrySlots_.forEach([this](WeakMapEntrySlot &slot) {
    if (!slot.key || !slot.owner) {
      slot.mappedValue = HermesValue::encodeEmptyValue();
      return;
    }
    GCCell *cell = slot.key.getNoBarrierUnsafe(getPointerBase());
    GCCell *ownerMapCell = slot.owner.getNoBarrierUnsafe(getPointerBase());
    if (!HeapSegment::getCellMarkBit(cell) ||
        !HeapSegment::getCellMarkBit(ownerMapCell)) {
      slot.mappedValue = HermesValue::encodeEmptyValue();
    }
  });
}

void HadesGC::completeMarking() {
  assert(inGC() && "inGC_ must be set during the STW pause");
                                                                               
                                                               
  updateOldGenThreshold();
  ogMarkingBarriers_ = false;
                                                                              
                   
  oldGenMarker_->globalWorklist().flushPushChunk();
  {
                                                                         
    DroppingAcceptor<MarkAcceptor> nameAcceptor{*oldGenMarker_};
    gcCallbacks_.markRootsForCompleteMarking(nameAcceptor);
  }
                             
  oldGenMarker_->drainAllWork();
  assert(
      oldGenMarker_->globalWorklist().empty() &&
      "Marking worklist wasn't drained");
  markWeakMapEntrySlots();
                                                                               
                     
  compactee_.evacStart = compactee_.start;
  compactee_.evacStartCP = compactee_.startCP;
  assert(
      oldGenMarker_->globalWorklist().empty() &&
      "Marking worklist wasn't drained");
                                                              
                
  MarkWeakRootsAcceptor acceptor{*this};
  markWeakRoots(acceptor,                   true);

                                    
  gcCallbacks_.freeSymbols(oldGenMarker_->markedSymbols());

                                                        
  oldGenMarker_.reset();
}

void HadesGC::finalizeAll() {
  std::lock_guard<Mutex> lk{gcMutex_};
                                          
  concurrentPhase_ = Phase::None;
  if (ogCollectionStats_)
    ogCollectionStats_->markUsed();
                                                                   
  if (ygCollectionStats_)
    ygCollectionStats_->markUsed();
                           
                                                                                
                                                                               
                                                      
  finalizeYoungGenObjects();

                                                                              
                                                                              
                                 
  transferExternalMemoryToOldGen();

  const auto finalizeCallback = [this](GCCell *cell) {
    assert(cell->isValid() && "Invalid cell in finalizeAll");
    cell->getVT()->finalizeIfExists(cell, *this);
  };
  if (compactee_.segment)
    compactee_.segment->forCompactedObjs(finalizeCallback, getPointerBase());

  for (HeapSegment &seg : oldGen_)
    seg.forAllObjs(finalizeCallback);
}

void HadesGC::creditExternalMemory(GCCell *cell, uint32_t sz) {
  assert(canAllocExternalMemory(sz) && "Precondition");
  if (inYoungGen(cell)) {
    size_t newYGExtBytes = getYoungGenExternalBytes() + sz;
    setYoungGenExternalBytes(newYGExtBytes);
    auto adj = std::min<size_t>(sz, youngGen_.available());
    youngGen_.setEffectiveEnd(youngGen_.effectiveEnd() - adj);
  } else {
    std::lock_guard<Mutex> lk{gcMutex_};
    oldGen_.creditExternalMemory(sz);
    uint64_t totalBytes = oldGen_.allocatedBytes() + oldGen_.externalBytes();
    if (totalBytes > oldGen_.targetSizeBytes())
      youngGen_.setEffectiveEnd(youngGen_.level());
  }
}

void HadesGC::debitExternalMemory(GCCell *cell, uint32_t sz) {
  if (inYoungGen(cell)) {
    size_t oldYGExtBytes = getYoungGenExternalBytes();
    assert(
        oldYGExtBytes >= sz && "Debiting more native memory than was credited");
    setYoungGenExternalBytes(oldYGExtBytes - sz);
                                                                             
                                                                              
              
  } else {
    std::lock_guard<Mutex> lk{gcMutex_};
    oldGen_.debitExternalMemory(sz);
  }
}

void HadesGC::writeBarrierSlow(const GCHermesValue *loc, HermesValue value) {
  if (ogMarkingBarriers_) {
    snapshotWriteBarrierInternal(*loc);
  }
  if (!value.isPointer()) {
    return;
  }
  relocationWriteBarrier(loc, value.getPointer());
}

void HadesGC::writeBarrierSlow(
    const GCSmallHermesValue *loc,
    SmallHermesValue value) {
  if (ogMarkingBarriers_) {
    snapshotWriteBarrierInternal(*loc);
  }
  if (!value.isPointer()) {
    return;
  }
  relocationWriteBarrier(loc, value.getPointer(getPointerBase()));
}

void HadesGC::writeBarrierSlow(const GCPointerBase *loc, const GCCell *value) {
  if (*loc && ogMarkingBarriers_)
    snapshotWriteBarrierInternal(*loc);
                                                                           
                
  relocationWriteBarrier(loc, value);
}

void HadesGC::constructorWriteBarrierSlow(
    const GCHermesValue *loc,
    HermesValue value) {
                                                                         
                                            
  if (!value.isPointer()) {
    return;
  }
  relocationWriteBarrier(loc, value.getPointer());
}

void HadesGC::constructorWriteBarrierSlow(
    const GCSmallHermesValue *loc,
    SmallHermesValue value) {
                                                                         
                                            
  if (!value.isPointer()) {
    return;
  }
  relocationWriteBarrier(loc, value.getPointer(getPointerBase()));
}

void HadesGC::constructorWriteBarrierRangeSlow(
    const GCHermesValue *start,
    uint32_t numHVs) {
  assert(
      AlignedStorage::containedInSame(start, start + numHVs) &&
      "Range must start and end within a heap segment.");

                                                                             
                                                                             
                                                                                
                                                                             

  AlignedHeapSegment::cardTableCovering(start)->dirtyCardsForAddressRange(
      start, start + numHVs);
}

void HadesGC::constructorWriteBarrierRangeSlow(
    const GCSmallHermesValue *start,
    uint32_t numHVs) {
  assert(
      AlignedStorage::containedInSame(start, start + numHVs) &&
      "Range must start and end within a heap segment.");
  AlignedHeapSegment::cardTableCovering(start)->dirtyCardsForAddressRange(
      start, start + numHVs);
}

void HadesGC::snapshotWriteBarrierRangeSlow(
    const GCHermesValue *start,
    uint32_t numHVs) {
  for (uint32_t i = 0; i < numHVs; ++i) {
    snapshotWriteBarrierInternal(start[i]);
  }
}

void HadesGC::snapshotWriteBarrierRangeSlow(
    const GCSmallHermesValue *start,
    uint32_t numHVs) {
  for (uint32_t i = 0; i < numHVs; ++i) {
    snapshotWriteBarrierInternal(start[i]);
  }
}

void HadesGC::snapshotWriteBarrierInternal(GCCell *oldValue) {
  assert(
      (oldValue->isValid()) &&
      "Invalid cell encountered in snapshotWriteBarrier");
  if (!inYoungGen(oldValue)) {
    HERMES_SLOW_ASSERT(
        dbgContains(oldValue) &&
        "Non-heap pointer encountered in snapshotWriteBarrier");
    oldGenMarker_->globalWorklist().enqueue(oldValue);
  }
}

void HadesGC::snapshotWriteBarrierInternal(CompressedPointer oldValue) {
  assert(
      (oldValue.get(getPointerBase())->isValid()) &&
      "Invalid cell encountered in snapshotWriteBarrier");
  if (!inYoungGen(oldValue)) {
    GCCell *ptr = oldValue.get(getPointerBase());
    HERMES_SLOW_ASSERT(
        dbgContains(ptr) &&
        "Non-heap pointer encountered in snapshotWriteBarrier");
    oldGenMarker_->globalWorklist().enqueue(ptr);
  }
}

void HadesGC::snapshotWriteBarrierInternal(HermesValue oldValue) {
  if (oldValue.isPointer()) {
    snapshotWriteBarrierInternal(static_cast<GCCell *>(oldValue.getPointer()));
  } else if (oldValue.isSymbol()) {
                                            
    snapshotWriteBarrierInternal(oldValue.getSymbol());
  }
}

void HadesGC::snapshotWriteBarrierInternal(SmallHermesValue oldValue) {
  if (oldValue.isPointer()) {
    snapshotWriteBarrierInternal(oldValue.getPointer());
  } else if (oldValue.isSymbol()) {
                                            
    snapshotWriteBarrierInternal(oldValue.getSymbol());
  }
}

void HadesGC::snapshotWriteBarrierInternal(SymbolID symbol) {
  HERMES_SLOW_ASSERT(
      ogMarkingBarriers_ &&
      "snapshotWriteBarrier should only be called while the OG is marking");
  oldGenMarker_->markSymbol(symbol);
}

void HadesGC::relocationWriteBarrier(const void *loc, const void *value) {
  assert(!inYoungGen(loc) && "Pre-condition from other callers");
                                                                          
                                                                              
                                   
  if (AlignedStorage::containedInSame(loc, value)) {
    return;
  }
  if (inYoungGen(value) || compactee_.contains(value)) {
                                                                             
                                                                            
                  
                                                                                
                                               
    HeapSegment::cardTableCovering(loc)->dirtyCardForAddress(loc);
  }
}

void HadesGC::weakRefReadBarrier(HermesValue value) {
  assert(
      !calledByBackgroundThread() &&
      "Read barrier invoked by background thread.");
  if (ogMarkingBarriers_)
    snapshotWriteBarrierInternal(value);
}

void HadesGC::weakRefReadBarrier(GCCell *value) {
  assert(
      !calledByBackgroundThread() &&
      "Read barrier invoked by background thread.");
                                                                 
  if (ogMarkingBarriers_)
    snapshotWriteBarrierInternal(value);

                                                                      
                                                        
}

bool HadesGC::canAllocExternalMemory(uint32_t size) {
  return size <= maxHeapSize_;
}

void HadesGC::forAllObjs(const std::function<void(GCCell *)> &callback) {
  std::lock_guard<Mutex> lk{gcMutex_};
  youngGen().forAllObjs(callback);

  const auto skipGarbageCallback = [callback](GCCell *cell) {
                                                                         
                                                                       
                                                                     
                                 
    if (HeapSegment::getCellMarkBit(cell)) {
      callback(cell);
    }
  };
  for (HeapSegment &seg : oldGen_) {
    if (concurrentPhase_ != Phase::Sweep)
      seg.forAllObjs(callback);
    else
      seg.forAllObjs(skipGarbageCallback);
  }
  if (compactee_.segment) {
    if (!compactee_.evacActive())
      compactee_.segment->forAllObjs(callback);
    else
      compactee_.segment->forAllObjs(skipGarbageCallback);
  }
}

void HadesGC::ttiReached() {
  if (revertToYGAtTTI_)
    promoteYGToOG_ = false;
}

#ifndef NDEBUG

bool HadesGC::calledByBackgroundThread() const {
                                                                         
                       
  return kConcurrentGC &&
      backgroundExecutor_->getThreadId() == std::this_thread::get_id();
}

bool HadesGC::validPointer(const void *p) const {
  return dbgContains(p) && static_cast<const GCCell *>(p)->isValid();
}

bool HadesGC::dbgContains(const void *p) const {
  return inYoungGen(p) || inOldGen(p);
}

void HadesGC::trackReachable(CellKind kind, unsigned sz) {}

bool HadesGC::needsWriteBarrier(void *loc, GCCell *value) {
  return !inYoungGen(loc);
}
#endif

void *HadesGC::allocSlow(uint32_t sz) {
  AllocResult res;
                                                             
  youngGenCollection(
      kNaturalCauseForAnalytics,                           false);
  res = youngGen().alloc(sz);
  if (res.success)
    return res.ptr;

                                                                              
                         
  youngGen().clearExternalMemoryCharge();
  res = youngGen().alloc(sz);
  if (res.success)
    return res.ptr;

                                                                           
                                                                        
                    
                                                                      
                                                                         
                                                                        
  oom(make_error_code(OOMError::SuperSegmentAlloc));
}

void *HadesGC::allocLongLived(uint32_t sz) {
  assert(
      isSizeHeapAligned(sz) &&
      "Call to allocLongLived must use a size aligned to HeapAlign");
  assert(gcMutex_ && "GC mutex must be held when calling allocLongLived");
  totalAllocatedBytes_ += sz;
                                     
  return oldGen_.alloc(sz);
}

GCCell *HadesGC::OldGen::alloc(uint32_t sz) {
  assert(
      isSizeHeapAligned(sz) &&
      "Should be aligned before entering this function");
  assert(sz >= minAllocationSize() && "Allocating too small of an object");
  assert(sz <= maxAllocationSize() && "Allocating too large of an object");
  assert(gc_.gcMutex_ && "gcMutex_ must be held before calling oldGenAlloc");
  if (GCCell *cell = search(sz)) {
    return cell;
  }
                                                                            
                                                                         
                                   
  llvh::ErrorOr<HeapSegment> seg = gc_.createSegment();
  if (seg) {
                                                   
    AllocResult res = seg->alloc(sz);
    assert(
        res.success &&
        "A newly created segment should always be able to allocate");
                                                                             
                                                       
    seg->setCellHead(static_cast<GCCell *>(res.ptr), sz);
                                                                               
                 
    addSegment(std::move(seg.get()));
    GCCell *newObj = static_cast<GCCell *>(res.ptr);
    HeapSegment::setCellMarkBit(newObj);
    return newObj;
  }

                                                                            
                   

                                                              
  if (GCCell *cell = search(sz)) {
    return cell;
  }

                                              
                                                                            
                                                                              
              
  gc_.oom(seg.getError());
}

uint32_t HadesGC::OldGen::getFreelistBucket(uint32_t size) {
                                                                             
                                             
  if (size < kMinSizeForLargeBlock) {
    auto bucket = size >> LogHeapAlign;
    assert(
        bucket < kNumSmallFreelistBuckets &&
        "Small blocks must be within the small free list range");
    return bucket;
  }
                                                                               
                

  auto bucket =
      kNumSmallFreelistBuckets + llvh::Log2_32(size) - kLogMinSizeForLargeBlock;
  assert(
      bucket < kNumFreelistBuckets &&
      "Block size must be within the freelist range!");
  return bucket;
}

GCCell *HadesGC::OldGen::search(uint32_t sz) {
  size_t bucket = getFreelistBucket(sz);
  if (bucket < kNumSmallFreelistBuckets) {
                                                                             
                                            
    if (auto *segBucket = buckets_[bucket].next) {
      assert(freelistBucketBitArray_.at(bucket));
      FreelistCell *cell = removeCellFromFreelist(bucket, segBucket);
      assert(
          cell->getAllocatedSize() == sz &&
          "Size bucket should be an exact match");
      return finishAlloc(cell, sz);
    }
                                                                                
    bucket = getFreelistBucket(sz + minAllocationSize());
  }
                                                                                
                                                                  
  bucket = freelistBucketBitArray_.findNextSetBitFrom(bucket);
  for (; bucket < kNumFreelistBuckets;
       bucket = freelistBucketBitArray_.findNextSetBitFrom(bucket + 1)) {
    auto *segBucket = buckets_[bucket].next;
    do {
                                                                              
      AssignableCompressedPointer *prevLoc = &segBucket->head;
      AssignableCompressedPointer cellCP = segBucket->head;

      do {
        auto *cell =
            vmcast<FreelistCell>(cellCP.getNonNull(gc_.getPointerBase()));
        assert(
            cellCP == *prevLoc &&
            "prevLoc should be updated in each iteration");
        assert(
            (!cell->next_ ||
             cell->next_.getNonNull(gc_.getPointerBase())->isValid()) &&
            "Next pointer points to an invalid cell");
        const auto cellSize = cell->getAllocatedSize();
        assert(
            getFreelistBucket(cellSize) == bucket &&
            "Found an incorrectly sized block in this bucket");
                                                                          
        if (cellSize >= sz + minAllocationSize()) {
                                                                
                                                                              
                                  
          auto newCell = cell->carve(sz);
                                                                           
                                        
          auto newBucket = getFreelistBucket(cell->getAllocatedSize());
          assert(newBucket <= bucket && "Split cell must be smaller.");
          if (newBucket != bucket) {
            removeCellFromFreelist(prevLoc, bucket, segBucket);
                                                                            
                                                                          
                                                                               
            auto diff = bucket - newBucket;
            addCellToFreelist(cell, segBucket - diff);
          }
                                                                        
                                                                           
                                                      
          __asan_unpoison_memory_region(newCell, sz);
          return finishAlloc(newCell, sz);
        } else if (cellSize == sz) {
                                  
          removeCellFromFreelist(prevLoc, bucket, segBucket);
          return finishAlloc(cell, sz);
        }
                                                                            
                                      
                                                                             
                                                                             
                                                                   
                                                                         
                                                                            
                                                                               
                                                                                
                                                                 
        prevLoc = &cell->next_;
        cellCP = cell->next_;
      } while (cellCP);
      segBucket = segBucket->next;
    } while (segBucket);
  }
  return nullptr;
}

template <typename Acceptor>
void HadesGC::youngGenEvacuateImpl(Acceptor &acceptor, bool doCompaction) {
                                                            
  {
    DroppingAcceptor<Acceptor> nameAcceptor{acceptor};
    markRoots(nameAcceptor,                   doCompaction);

                                                                                
                                                                             
                                                                             
                                                                                
                                                         
    weakMapEntrySlots_.forEach([&nameAcceptor](WeakMapEntrySlot &slot) {
      nameAcceptor.accept(slot.mappedValue);
    });
  }
                                                                    
                
  scanDirtyCards(acceptor);
                                                        
  while (CopyListCell *const copyCell = acceptor.pop()) {
    assert(
        copyCell->hasMarkedForwardingPointer() && "Discovered unmarked object");
    assert(
        (inYoungGen(copyCell) || compactee_.evacContains(copyCell)) &&
        "Unexpected object in YG collection");
                                                                     
                                                       
    GCCell *const cell =
        copyCell->getMarkedForwardingPointer().getNonNull(getPointerBase());
    markCell(cell, acceptor);
  }

                                                                                
                               
  markWeakRoots(acceptor,                   doCompaction);
}

void HadesGC::youngGenCollection(
    std::string cause,
    bool forceOldGenCollection) {
  ygCollectionStats_ = std::make_unique<CollectionStats>(*this, cause, "young");
  ygCollectionStats_->beginCPUTimeSection();
  ygCollectionStats_->setBeginTime();
                                                               
  auto lk = ensureBackgroundTaskPaused();
                                                             
  assert(!inGC() && "Cannot be in GC at the start of YG!");
  GCCycle cycle{*this, "GC Young Gen"};
#ifdef HERMES_SLOW_DEBUG
  checkWellFormed();
                                                                      
  verifyCardTable();
#endif
  assert(
      youngGen().markBitArray().findNextUnmarkedBitFrom(0) ==
          youngGen().markBitArray().size() &&
      "Young gen segment must have all mark bits set");
  struct {
    uint64_t before{0};
    uint64_t after{0};
  } heapBytes, externalBytes;
  heapBytes.before = youngGen().used();
  externalBytes.before = getYoungGenExternalBytes();
                                                           
  totalAllocatedBytes_ += youngGen().used();
  const bool doCompaction = compactee_.evacActive();
                                                                             
                                             
  if (promoteYoungGenToOldGen()) {
                                                                         
                                                                       
                                         
    ygCollectionStats_->setBeforeSizes(
        heapBytes.before, externalBytes.before, segmentFootprint());
    ygCollectionStats_->addCollectionType("promotion");
    assert(!doCompaction && "Cannot do compactions during YG promotions.");
  } else {
    auto &yg = youngGen();

    if (compactee_.segment) {
      EvacAcceptor<true> acceptor{*this};
      youngGenEvacuateImpl(acceptor, doCompaction);
                                                                             
                             
      heapBytes.after = acceptor.evacuatedBytes();
    } else {
      EvacAcceptor<false> acceptor{*this};
      youngGenEvacuateImpl(acceptor, false);
      heapBytes.after = acceptor.evacuatedBytes();
    }
                                                                         
    if (isTrackingIDs()) {
      auto trackerCallback = [this](GCCell *cell) {
                                                                           
                                                                             
                                        
        if (!vmisa<OldGen::FreelistCell>(cell)) {
          untrackObject(cell, cell->getAllocatedSize());
        }
      };
      yg.forCompactedObjs(trackerCallback, getPointerBase());
      if (doCompaction) {
        compactee_.segment->forCompactedObjs(trackerCallback, getPointerBase());
      }
    }
                                            
    finalizeYoungGenObjects();
                                                                       
                                                                                
    externalBytes.after = getYoungGenExternalBytes();

    if (overwriteDeadYGObjects_)
      memset(yg.start(), kInvalidHeapValue, yg.used());

                                                                        
                                             
    yg.resetLevel();
    assert(
        yg.markBitArray().findNextUnmarkedBitFrom(0) ==
            yg.markBitArray().size() &&
        "Young gen segment must have all mark bits set");

    if (doCompaction) {
      numCompactions_++;
      ygCollectionStats_->addCollectionType("compact");
                                                                            
                                                                              
                  
      uint64_t ogExternalBefore = oldGen_.externalBytes();
                                                                                
                                                 
      uint64_t ogAllocatedBefore = oldGen_.allocatedBytes();
      finalizeCompactee();
      heapBytes.before += ogAllocatedBefore - oldGen_.allocatedBytes();
      const uint64_t externalCompactedBytes =
          ogExternalBefore - oldGen_.externalBytes();
                                                                              
                                                              
      externalBytes.before += externalCompactedBytes;
    }

                                                             
    transferExternalMemoryToOldGen();

                                                                               
                                                                                
                                                                         
                             
    if (!doCompaction)
      updateYoungGenSizeFactor();

                                                                              
                                                                               
                                                                         
                                                                                
    youngGen().setEffectiveEnd(
        youngGen().start() +
        static_cast<size_t>(ygSizeFactor_ * HeapSegment::maxSize()));

                                                                           
                                       
    ygCollectionStats_->setBeforeSizes(
        heapBytes.before, externalBytes.before, segmentFootprint());

                                                                  
    ygCollectionStats_->setSweptBytes(heapBytes.before - heapBytes.after);
    ygCollectionStats_->setSweptExternalBytes(
        externalBytes.before - externalBytes.after);
    ygCollectionStats_->setAfterSize(segmentFootprint());
                                                                         
                                                                       
                                                                            
    if (!doCompaction)
      ygAverageSurvivalBytes_.update(
          ygCollectionStats_->afterAllocatedBytes() +
          ygCollectionStats_->afterExternalBytes());
  }
#ifdef HERMES_SLOW_DEBUG
                                                                     
  verifyCardTable();
#endif
                                                           
                                                                         
                                                                              
                                                                             
                            
  yieldToOldGen();
                                                                         
                                                                              
                                                                              
                                                                                
                
  if (concurrentPhase_ == Phase::None && !compactee_.evacActive()) {
                                                                                
                                      
    checkTripwireAndSubmitStats();
    if (forceOldGenCollection) {
                                                                           
                                                                         
                                                                       
      oldGenCollection(std::move(cause),                     true);
    } else {
                                                                            
                          
                                                                               
                                                                                
                                                       
      const uint64_t totalAllocated =
          oldGen_.allocatedBytes() + oldGen_.externalBytes();
      const uint64_t totalBytes = oldGen_.targetSizeBytes();
      double allocatedRatio = static_cast<double>(totalAllocated) / totalBytes;
      if (allocatedRatio >= ogThreshold_) {
        oldGenCollection(kNaturalCauseForAnalytics,                     false);
      }
    }
  }
#ifdef HERMES_SLOW_DEBUG
                                            
  checkWellFormed();
#endif
  ygCollectionStats_->setEndTime();
  ygCollectionStats_->endCPUTimeSection();
  auto statsEvent = std::move(*ygCollectionStats_).getEvent();
  recordGCStats(statsEvent, true);
  recordGCStats(statsEvent, &ygCumulativeStats_, true);
  ygCollectionStats_.reset();
}

bool HadesGC::promoteYoungGenToOldGen() {
  if (!promoteYGToOG_) {
    return false;
  }

                                                                         
                                                         
                                                                               
                                                                               
                                                          
  llvh::ErrorOr<HeapSegment> newYoungGen = createSegment();
  if (!newYoungGen) {
    promoteYGToOG_ = false;
    return false;
  }

                                                                               
                                                              
  transferExternalMemoryToOldGen();
                                                                         
                      
                                                                      
                                                                        
                                                         
  youngGen_.forAllObjs([this](GCCell *cell) {
    youngGen_.setCellHead(cell, cell->getAllocatedSize());
  });
                                                                      
                                                                   
                                                
                                                         
  oldGen_.addSegment(setYoungGen(std::move(newYoungGen.get())));

  return true;
}

HadesGC::HeapSegment HadesGC::setYoungGen(HeapSegment seg) {
  addSegmentExtentToCrashManager(seg, "YG");
  youngGenFinalizables_.clear();
  std::swap(youngGen_, seg);
  youngGenCP_ = CompressedPointer::encodeNonNull(
      reinterpret_cast<GCCell *>(youngGen_.lowLim()), getPointerBase());
  return seg;
}

void HadesGC::checkTripwireAndSubmitStats() {
  assert(
      gcMutex_ &&
      "gcMutex must be held before calling checkTripwireAndSubmitStats");
  assert(
      concurrentPhase_ == Phase::None &&
      "Cannot check stats while OG collection is ongoing.");
  if (!ogCollectionStats_) {
    return;
  }
  const auto usedBytes = ogCollectionStats_->afterAllocatedBytes() +
      ogCollectionStats_->afterExternalBytes();
                                                                            
                           
  checkTripwire(usedBytes);
  auto event = std::move(*ogCollectionStats_).getEvent();
  recordGCStats(event, false);
  recordGCStats(event, &ogCumulativeStats_, false);
  ogCollectionStats_.reset();
}

void HadesGC::transferExternalMemoryToOldGen() {
  oldGen_.creditExternalMemory(getYoungGenExternalBytes());
  setYoungGenExternalBytes(0);
  youngGen_.clearExternalMemoryCharge();
}

void HadesGC::updateYoungGenSizeFactor() {
  assert(
      ygSizeFactor_ <= 1.0 && ygSizeFactor_ >= 0.25 && "YG size out of range.");
  const auto ygDuration = ygCollectionStats_->getElapsedTime().count();
                                                                                
                               
  if (ygDuration < kTargetMaxPauseMs * 0.2)
    ygSizeFactor_ = std::min(ygSizeFactor_ * 1.1, 1.0);
                                                                                
                                                                             
                                                                       
  else if (ygDuration > kTargetMaxPauseMs * 0.4)
    ygSizeFactor_ = std::max(ygSizeFactor_ * 0.9, 0.25);
}

template <bool CompactionEnabled>
void HadesGC::scanDirtyCardsForSegment(
    SlotVisitor<EvacAcceptor<CompactionEnabled>> &visitor,
    HeapSegment &seg) {
  const auto &cardTable = seg.cardTable();
                                                                           
          
  const char *const origSegLevel = seg.level();
  size_t from = cardTable.addressToIndex(seg.start());
  const size_t to = cardTable.addressToIndex(origSegLevel - 1) + 1;

                                                                               
                            
                                                                              
                                                                
                                                                              
                                                                           
                                                                           
                                                                             
                                                                               
                      
  const bool visitUnmarked = concurrentPhase_ != Phase::Sweep;

  while (const auto oiBegin = cardTable.findNextDirtyCard(from, to)) {
    const auto iBegin = *oiBegin;

    const auto oiEnd = cardTable.findNextCleanCard(iBegin, to);
    const auto iEnd = oiEnd ? *oiEnd : to;

    assert(
        (iEnd == to || !cardTable.isCardForIndexDirty(iEnd)) &&
        cardTable.isCardForIndexDirty(iEnd - 1) &&
        "end should either be the end of the card table, or the first "
        "non-dirty card after a sequence of dirty cards");
    assert(iBegin < iEnd && "Indices must be apart by at least one");

    const char *const begin = cardTable.indexToAddress(iBegin);
    const char *const end = cardTable.indexToAddress(iEnd);
                                                                            
    const void *const boundary = std::min(end, origSegLevel);

                                                                           
                     
    GCCell *const firstObj = seg.getFirstCellHead(iBegin);
    GCCell *obj = firstObj;
                                                                         
                                                                             
                                                                        
                                                                     
                                                                              
                                                                              
                                                                        
                 

                                                                       
    if (visitUnmarked || HeapSegment::getCellMarkBit(obj))
      markCellWithinRange(visitor, obj, obj->getKind(), begin, end);

    obj = obj->nextCell();
                                                               
    if (LLVM_LIKELY(obj < boundary)) {
                                                                           
                                                                              
                                                                         
                                              
      for (GCCell *next = obj->nextCell(); next < boundary;
           next = next->nextCell()) {
        if (visitUnmarked || HeapSegment::getCellMarkBit(obj))
          markCell(visitor, obj, obj->getKind());
        obj = next;
      }

                                                                          
                    
      assert(
          obj < boundary && obj->nextCell() >= boundary &&
          "Last object in card must touch or cross cross the card boundary");
      if (visitUnmarked || HeapSegment::getCellMarkBit(obj))
        markCellWithinRange(visitor, obj, obj->getKind(), begin, end);
    }

    from = iEnd;
  }
}

template <bool CompactionEnabled>
void HadesGC::scanDirtyCards(EvacAcceptor<CompactionEnabled> &acceptor) {
  SlotVisitor<EvacAcceptor<CompactionEnabled>> visitor{acceptor};
  const bool preparingCompaction =
      CompactionEnabled && !compactee_.evacActive();
                                                                      
                                                                           
                                                                            
                                                                            
                                                                     
                
  const auto segEnd = oldGen_.numSegments();
  for (size_t i = 0; i < segEnd; ++i) {
                                                                
                                                                           
    HeapSegment &seg = oldGen_[i];
    scanDirtyCardsForSegment(visitor, seg);
                                                                           
                                                                             
                                           
    if (!preparingCompaction)
      seg.cardTable().clear();
  }

                                                                    
                                                               
  if (preparingCompaction)
    scanDirtyCardsForSegment(visitor, *compactee_.segment);
}

void HadesGC::finalizeYoungGenObjects() {
  for (GCCell *cell : youngGenFinalizables_) {
    if (!cell->hasMarkedForwardingPointer()) {
      cell->getVT()->finalize(cell, *this);
    }
  }
  youngGenFinalizables_.clear();
}

uint64_t HadesGC::allocatedBytes() const {
                                                                               
  return (youngGen_ ? youngGen_.used() : 0) + oldGen_.allocatedBytes();
}

uint64_t HadesGC::externalBytes() const {
  return getYoungGenExternalBytes() + oldGen_.externalBytes();
}

uint64_t HadesGC::segmentFootprint() const {
  size_t totalSegments = oldGen_.numSegments() + (youngGen_ ? 1 : 0) +
      (compactee_.segment ? 1 : 0);
  return totalSegments * AlignedStorage::size();
}

uint64_t HadesGC::heapFootprint() const {
  return segmentFootprint() + externalBytes();
}

uint64_t HadesGC::OldGen::allocatedBytes() const {
  return allocatedBytes_;
}

void HadesGC::OldGen::incrementAllocatedBytes(int32_t incr) {
  allocatedBytes_ += incr;
  assert(allocatedBytes_ <= size() && "Invalid increment");
}

uint64_t HadesGC::OldGen::externalBytes() const {
  assert(gc_.gcMutex_ && "OG external bytes must be accessed under gcMutex_.");
  return externalBytes_;
}

uint64_t HadesGC::OldGen::size() const {
  size_t totalSegments = numSegments() + (gc_.compactee_.segment ? 1 : 0);
  return totalSegments * HeapSegment::maxSize();
}

uint64_t HadesGC::OldGen::targetSizeBytes() const {
  assert(gc_.gcMutex_ && "Must hold gcMutex_ when accessing targetSizeBytes_.");
  return targetSizeBytes_;
}

size_t HadesGC::getYoungGenExternalBytes() const {
  assert(
      !calledByBackgroundThread() &&
      "ygExternalBytes_ is only accessible from the mutator.");
  return ygExternalBytes_;
}
void HadesGC::setYoungGenExternalBytes(size_t sz) {
  assert(
      !calledByBackgroundThread() &&
      "ygExternalBytes_ is only accessible from the mutator.");
  ygExternalBytes_ = sz;
}

llvh::ErrorOr<size_t> HadesGC::getVMFootprintForTest() const {
                            
  size_t footprint = 0;
  auto ygFootprint =
      hermes::oscompat::vm_footprint(youngGen_.start(), youngGen_.hiLim());
                              
  if (!ygFootprint)
    return ygFootprint;

                         
  for (const HeapSegment &seg : oldGen_) {
    auto segFootprint =
        hermes::oscompat::vm_footprint(seg.start(), seg.hiLim());
    if (!segFootprint)
      return segFootprint;
    footprint += *segFootprint;
  }
  return footprint;
}

std::deque<HadesGC::HeapSegment>::iterator HadesGC::OldGen::begin() {
  return segments_.begin();
}

std::deque<HadesGC::HeapSegment>::iterator HadesGC::OldGen::end() {
  return segments_.end();
}

std::deque<HadesGC::HeapSegment>::const_iterator HadesGC::OldGen::begin()
    const {
  return segments_.begin();
}

std::deque<HadesGC::HeapSegment>::const_iterator HadesGC::OldGen::end() const {
  return segments_.end();
}

size_t HadesGC::OldGen::numSegments() const {
  return segments_.size();
}

HadesGC::HeapSegment &HadesGC::OldGen::operator[](size_t i) {
  return segments_[i];
}

llvh::ErrorOr<HadesGC::HeapSegment> HadesGC::createSegment() {
                                                                               
                               
  if (!sanitizeRate_ && heapFootprint() >= maxHeapSize_)
    return make_error_code(OOMError::MaxHeapReached);

  auto res = AlignedStorage::create(provider_.get(), "hades-segment");
  if (!res) {
    return res.getError();
  }
  HeapSegment seg(std::move(res.get()));
                                                                            
                           
  size_t segIdx;
  if (segmentIndices_.size()) {
    segIdx = segmentIndices_.back();
    segmentIndices_.pop_back();
  } else {
    segIdx = ++numSegments_;
  }
  pointerBase_.setSegment(segIdx, seg.lowLim());
  addSegmentExtentToCrashManager(seg, std::to_string(segIdx));
  seg.markBitArray().markAll();
  return llvh::ErrorOr<HadesGC::HeapSegment>(std::move(seg));
}

void HadesGC::OldGen::addSegment(HeapSegment seg) {
  segments_.emplace_back(std::move(seg));
  HeapSegment &newSeg = segments_.back();
  incrementAllocatedBytes(newSeg.used());
                                                    
  segmentBuckets_.emplace_back();

  assert(
      segmentBuckets_.size() == segments_.size() &&
      "Must have as many freelists as segments.");

                                                      
  uint32_t sz = newSeg.available();
  if (sz >= minAllocationSize()) {
    auto res = newSeg.alloc(sz);
    assert(res.success);
    auto bucket = getFreelistBucket(sz);
    addCellToFreelist(res.ptr, sz, &segmentBuckets_.back()[bucket]);
  }

  gc_.addSegmentExtentToCrashManager(newSeg, std::to_string(numSegments()));
}

HadesGC::HeapSegment HadesGC::OldGen::popSegment() {
  const auto &segBuckets = segmentBuckets_.back();
  for (size_t bucket = 0; bucket < kNumFreelistBuckets; ++bucket) {
    if (segBuckets[bucket].head) {
      segBuckets[bucket].removeFromFreelist();
      freelistBucketBitArray_.set(bucket, buckets_[bucket].next);
    }
  }
  segmentBuckets_.pop_back();

  auto oldSeg = std::move(segments_.back());
  segments_.pop_back();
  return oldSeg;
}

void HadesGC::OldGen::setTargetSizeBytes(size_t targetSizeBytes) {
  assert(gc_.gcMutex_ && "Must hold gcMutex_ when accessing targetSizeBytes_.");
  assert(!targetSizeBytes_ && "Should only initialise targetSizeBytes_ once.");
  targetSizeBytes_ = ExponentialMovingAverage(0.5, targetSizeBytes);
}

bool HadesGC::inOldGen(const void *p) const {
                                                                                
            
  return compactee_.contains(p) ||
      std::any_of(oldGen_.begin(), oldGen_.end(), [p](const HeapSegment &seg) {
           return seg.contains(p);
         });
}

void HadesGC::yieldToOldGen() {
  assert(inGC() && "Must be in GC when yielding to old gen");
  if (!kConcurrentGC && concurrentPhase_ != Phase::None) {
                                                                      
                  
    if (concurrentPhase_ == Phase::Mark)
      oldGenMarker_->setDrainRate(getDrainRate());

    constexpr uint32_t kYGIncrementalCollectBudget = kTargetMaxPauseMs / 2;
    const auto initialPhase = concurrentPhase_;
                                                                              
                                                                             
                                                                    
    do {
      incrementalCollect(false);
    } while (concurrentPhase_ == initialPhase &&
             ygCollectionStats_->getElapsedTime().count() <
                 kYGIncrementalCollectBudget);

  } else if (concurrentPhase_ == Phase::CompleteMarking) {
    incrementalCollect(false);
    collectOGInBackground();
  }
}

size_t HadesGC::getDrainRate() {
                                                                         
                                                                           
                                                            
                                                                          
                                                                          
                                
  assert(!kConcurrentGC);

                                                                             
                                                                                
                                                                            
                                                                              
                                                                            
                                                                             
                                                                           
  constexpr size_t baseMarkRate = 3;
  uint64_t drainRate = baseMarkRate * ygAverageSurvivalBytes_;
                                                                              
                                    
  constexpr uint64_t byteDrainRateMin = 8192;
  return std::max(drainRate, byteDrainRateMin);
}

void HadesGC::addSegmentExtentToCrashManager(
    const HeapSegment &seg,
    const std::string &extraName) {
  assert(!extraName.empty() && "extraName can't be empty");
  if (!crashMgr_) {
    return;
  }
  const std::string segmentName = name_ + ":HeapSegment:" + extraName;
                                                                        
             
  constexpr unsigned kAddressMaxSize = 18;
  char segmentAddressBuffer[kAddressMaxSize];
  snprintf(segmentAddressBuffer, kAddressMaxSize, "%p", seg.lowLim());
  crashMgr_->setContextualCustomData(segmentName.c_str(), segmentAddressBuffer);

#ifdef HERMESVM_PLATFORM_LOGGING
  hermesLog(
      "HermesGC",
      "Added segment extent: %s = %s",
      segmentName.c_str(),
      segmentAddressBuffer);
#endif
}

void HadesGC::removeSegmentExtentFromCrashManager(
    const std::string &extraName) {
  assert(!extraName.empty() && "extraName can't be empty");
  if (!crashMgr_) {
    return;
  }
  const std::string segmentName = name_ + ":HeapSegment:" + extraName;
  crashMgr_->removeContextualCustomData(segmentName.c_str());
}

#ifdef HERMES_SLOW_DEBUG

void HadesGC::checkWellFormed() {
  CheckHeapWellFormedAcceptor acceptor(*this);
  {
    DroppingAcceptor<CheckHeapWellFormedAcceptor> nameAcceptor{acceptor};
    markRoots(nameAcceptor, true);
  }
  markWeakRoots(acceptor,                   true);
  forAllObjs([this, &acceptor](GCCell *cell) {
    assert(cell->isValid() && "Invalid cell encountered in heap");
    markCell(cell, acceptor);
  });

  weakMapEntrySlots_.forEach([](WeakMapEntrySlot &slot) {
    if (slot.mappedValue.isEmpty()) {
      assert(
          !slot.key ||
          !slot.owner && "Reachable entry should have not have Empty value.");
    }
  });
}

void HadesGC::verifyCardTable() {
  assert(inGC() && "Must be in GC to call verifyCardTable");
  struct VerifyCardDirtyAcceptor final : public SlotAcceptor {
    HadesGC &gc;

    explicit VerifyCardDirtyAcceptor(HadesGC &gc) : gc(gc) {}

    void acceptHelper(void *valuePtr, void *locPtr) {
      const bool crossRegionCompacteePtr =
          !gc.compactee_.evacContains(locPtr) &&
          gc.compactee_.evacContains(valuePtr);
      if (!gc.inYoungGen(locPtr) &&
          (gc.inYoungGen(valuePtr) || crossRegionCompacteePtr)) {
        assert(
            HeapSegment::cardTableCovering(locPtr)->isCardForAddressDirty(
                locPtr));
      }
    }

    void accept(GCPointerBase &ptr) override {
      acceptHelper(ptr.get(gc.getPointerBase()), &ptr);
    }

    void accept(GCHermesValue &hv) override {
      if (hv.isPointer())
        acceptHelper(hv.getPointer(), &hv);
    }
    void accept(GCSmallHermesValue &hv) override {
      if (hv.isPointer())
        acceptHelper(hv.getPointer(gc.getPointerBase()), &hv);
    }

    void accept(const GCSymbolID &hv) override {}
  };

  VerifyCardDirtyAcceptor acceptor{*this};
  forAllObjs([this, &acceptor](GCCell *cell) { markCell(cell, acceptor); });

  for (const HeapSegment &seg : oldGen_) {
    seg.cardTable().verifyBoundaries(seg.start(), seg.level());
  }
}

#endif

}                
}                    

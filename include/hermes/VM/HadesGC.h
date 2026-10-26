/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_HADESGC_H
#define HERMES_VM_HADESGC_H

#include "hermes/ADT/BitArray.h"
#include "hermes/ADT/ExponentialMovingAverage.h"
#include "hermes/Support/Algorithms.h"
#include "hermes/Support/SlowAssert.h"
#include "hermes/VM/AlignedHeapSegment.h"
#include "hermes/VM/GCBase.h"
#include "hermes/VM/VMExperiments.h"

#include "llvh/ADT/SparseBitVector.h"
#include "llvh/Support/ErrorOr.h"
#include "llvh/Support/PointerLikeTypeTraits.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace hermes {
namespace vm {

                                                                          
                                   
   
                                                             
                                                                   
                     
   
                                                                               
                                                                       
                                                                               
                                                                        
   
                                                             
   
                                                                           
                                                 
class HadesGC final : public GCBase {
 public:
                                                                     
                   
                                                                               
                                    
                                                                               
            
                                                                   
  HadesGC(
      GCCallbacks &gcCallbacks,
      PointerBase &pointerBase,
      const GCConfig &gcConfig,
      std::shared_ptr<CrashManager> crashMgr,
      std::shared_ptr<StorageProvider> provider,
      experiments::VMExperimentFlags vmExperimentFlags);

  ~HadesGC() override;

  static bool classof(const GCBase *gc) {
    return gc->getKind() == HeapKind::HadesGC;
  }

  static constexpr uint32_t maxAllocationSizeImpl() {
                                                                         
                        
    return HeapSegment::maxSize();
  }

  static constexpr uint32_t minAllocationSizeImpl() {
    return heapAlignSize(
        std::max(sizeof(OldGen::FreelistCell), sizeof(CopyListCell)));
  }

                            
        

  void getHeapInfo(HeapInfo &info) override;
  void getHeapInfoWithMallocSize(HeapInfo &info) override;
  void getCrashManagerHeapInfo(CrashManager::HeapInformation &info) override;
#ifdef HERMES_MEMORY_INSTRUMENTATION
  void createSnapshot(llvh::raw_ostream &os, bool captureNumericValue) override;
  void snapshotAddGCNativeNodes(HeapSnapshot &snap) override;
  void snapshotAddGCNativeEdges(HeapSnapshot &snap) override;
  void enableHeapProfiler(
      std::function<void(
          uint64_t,
          std::chrono::microseconds,
          std::vector<GCBase::AllocationLocationTracker::HeapStatsUpdate>)>
          fragmentCallback) override;
  void disableHeapProfiler() override;
  void enableSamplingHeapProfiler(size_t samplingInterval, int64_t seed)
      override;
  void disableSamplingHeapProfiler(llvh::raw_ostream &os) override;
#endif                                 
  void printStats(JSONEmitter &json) override;
  std::string getKindAsStr() const override;

        

                              
        

                                                                         
                                                                               
                           
                                                                   
  template <
      typename T,
      bool fixedSize = true,
      HasFinalizer hasFinalizer = HasFinalizer::No,
      LongLived longLived = LongLived::No,
      class... Args>
  inline T *makeA(uint32_t size, Args &&...args);

                                       
                                                   
  void collect(std::string cause, bool canEffectiveOOM = false) override;

                                              
  void finalizeAll() override;

                                              
                                                   
                                                
  void creditExternalMemory(GCCell *alloc, uint32_t size) override;

                                                   
                                                   
  void debitExternalMemory(GCCell *alloc, uint32_t size) override;

                          
        

                                                     
                                                                              
                       

                                                                    
                                                                      
                                                                           
                                                        
  void writeBarrier(const GCHermesValue *loc, HermesValue value) {
    assert(
        !calledByBackgroundThread() &&
        "Write barrier invoked by background thread.");
                                                                 
    if (LLVM_UNLIKELY(!inYoungGen(loc)))
      writeBarrierSlow(loc, value);
  }
  void writeBarrierSlow(const GCHermesValue *loc, HermesValue value);

  void writeBarrier(const GCSmallHermesValue *loc, SmallHermesValue value) {
    assert(
        !calledByBackgroundThread() &&
        "Write barrier invoked by background thread.");
                                                                 
    if (LLVM_UNLIKELY(!inYoungGen(loc)))
      writeBarrierSlow(loc, value);
  }
  void writeBarrierSlow(const GCSmallHermesValue *loc, SmallHermesValue value);

                                                                            
                                                                      
                                                                           
                                                        
  void writeBarrier(const GCPointerBase *loc, const GCCell *value) {
    assert(
        !calledByBackgroundThread() &&
        "Write barrier invoked by background thread.");
                                                                 
    if (LLVM_UNLIKELY(!inYoungGen(loc)))
      writeBarrierSlow(loc, value);
  }
  void writeBarrierSlow(const GCPointerBase *loc, const GCCell *value);

                                                                              
                                 
  void constructorWriteBarrier(const GCHermesValue *loc, HermesValue value) {
                                                                 
    if (LLVM_UNLIKELY(!inYoungGen(loc)))
      constructorWriteBarrierSlow(loc, value);
  }
  void constructorWriteBarrierSlow(const GCHermesValue *loc, HermesValue value);

  void constructorWriteBarrier(
      const GCSmallHermesValue *loc,
      SmallHermesValue value) {
                                                                 
    if (LLVM_UNLIKELY(!inYoungGen(loc)))
      constructorWriteBarrierSlow(loc, value);
  }
  void constructorWriteBarrierSlow(
      const GCSmallHermesValue *loc,
      SmallHermesValue value);

  void constructorWriteBarrier(const GCPointerBase *loc, const GCCell *value) {
                                                                 
    if (LLVM_UNLIKELY(!inYoungGen(loc)))
      relocationWriteBarrier(loc, value);
  }

  void constructorWriteBarrierRange(
      const GCHermesValue *start,
      uint32_t numHVs) {
                                                                 
    if (LLVM_UNLIKELY(!inYoungGen(start)))
      constructorWriteBarrierRangeSlow(start, numHVs);
  }
  void constructorWriteBarrierRangeSlow(
      const GCHermesValue *start,
      uint32_t numHVs);

  void constructorWriteBarrierRange(
      const GCSmallHermesValue *start,
      uint32_t numHVs) {
                                                                 
    if (LLVM_UNLIKELY(!inYoungGen(start)))
      constructorWriteBarrierRangeSlow(start, numHVs);
  }
  void constructorWriteBarrierRangeSlow(
      const GCSmallHermesValue *start,
      uint32_t numHVs);

  void snapshotWriteBarrier(const GCHermesValue *loc) {
    if (LLVM_UNLIKELY(!inYoungGen(loc) && ogMarkingBarriers_))
      snapshotWriteBarrierInternal(*loc);
  }
  void snapshotWriteBarrier(const GCSmallHermesValue *loc) {
    if (LLVM_UNLIKELY(!inYoungGen(loc) && ogMarkingBarriers_))
      snapshotWriteBarrierInternal(*loc);
  }
  void snapshotWriteBarrier(const GCPointerBase *loc) {
    if (LLVM_UNLIKELY(!inYoungGen(loc) && ogMarkingBarriers_))
      if (CompressedPointer cp = *loc)
        snapshotWriteBarrierInternal(cp);
  }
  void snapshotWriteBarrier(const GCSymbolID *loc) {
    if (LLVM_UNLIKELY(!inYoungGen(loc) && ogMarkingBarriers_))
      snapshotWriteBarrierInternal(*loc);
  }

  void snapshotWriteBarrierRange(const GCHermesValue *start, uint32_t numHVs) {
    if (LLVM_UNLIKELY(!inYoungGen(start) && ogMarkingBarriers_))
      snapshotWriteBarrierRangeSlow(start, numHVs);
  }
  void snapshotWriteBarrierRangeSlow(
      const GCHermesValue *start,
      uint32_t numHVs);

  void snapshotWriteBarrierRange(
      const GCSmallHermesValue *start,
      uint32_t numHVs) {
    if (LLVM_UNLIKELY(!inYoungGen(start) && ogMarkingBarriers_))
      snapshotWriteBarrierRangeSlow(start, numHVs);
  }
  void snapshotWriteBarrierRangeSlow(
      const GCSmallHermesValue *start,
      uint32_t numHVs);

                                                                         
                                 
  void weakRefReadBarrier(HermesValue value);

  void weakRefReadBarrier(GCCell *value);

        

                                                                      
                                                                               
                                                                           
                                                                               
               
  bool canAllocExternalMemory(uint32_t size) override;

                                                                         
                                                              
  void forAllObjs(const std::function<void(GCCell *)> &callback) override;

                                                                                
                                                          
  void ttiReached() override;

        

                                                                
  bool inYoungGen(const void *p) const override {
    return youngGen_.lowLim() == AlignedStorage::start(p);
  }
  bool inYoungGen(CompressedPointer p) const {
    return p.getSegmentStart() == youngGenCP_;
  }

                                                                             
                                                                                
                                                                            
              
  llvh::ErrorOr<size_t> getVMFootprintForTest() const;

#ifndef NDEBUG
                      
        

  bool calledByBackgroundThread() const override;

                            
  bool calledByGC() const override {
                                                                           
           
    return calledByBackgroundThread() || inGC();
  }

                                                                             
                             
  bool validPointer(const void *ptr) const override;

                                                                       
                                                                          
                                 
  bool dbgContains(const void *ptr) const override;

                                                                     
                                   
  void trackReachable(CellKind kind, unsigned sz) override;

  bool needsWriteBarrier(void *loc, GCCell *value) override;
        
#endif

  class CollectionStats;
  class HeapMarkingAcceptor;
  template <bool CompactionEnabled>
  class EvacAcceptor;
  class MarkAcceptor;
  class MarkWeakRootsAcceptor;
  class OldGen;
  class Executor;

  struct CopyListCell final : public GCCell {
                                                                      
    AssignableCompressedPointer next_;
  };

                                                               
  class HeapSegment final : public AlignedHeapSegment {
   public:
    explicit HeapSegment(AlignedStorage storage)
        : AlignedHeapSegment(std::move(storage)) {}
    HeapSegment() = default;

                                                                            
    static void setCellHead(const GCCell *start, const size_t sz);

                                                                           
                   
                                
                                                           
    GCCell *getFirstCellHead(const size_t cardIdx);

                                                                              
    template <typename CallbackFunction>
    void forAllObjs(CallbackFunction callback);
                                                                    
    template <typename CallbackFunction>
    void forCompactedObjs(CallbackFunction callback, PointerBase &base);
  };

  class OldGen final {
   public:
    explicit OldGen(HadesGC &gc);

    std::deque<HeapSegment>::iterator begin();
    std::deque<HeapSegment>::iterator end();
    std::deque<HeapSegment>::const_iterator begin() const;
    std::deque<HeapSegment>::const_iterator end() const;

    size_t numSegments() const;

    HeapSegment &operator[](size_t i);

                                            
    void addSegment(HeapSegment seg);

                                            
                                             
    HeapSegment popSegment();

                                                                           
    void setTargetSizeBytes(size_t targetSizeBytes);

                                                                              
                                                           
                                                                              
                                         
                                                                
                                                                          
    GCCell *alloc(uint32_t sz);

                                                                              
                                                                              
                                    
    uint64_t allocatedBytes() const;

                                                        
    void incrementAllocatedBytes(int32_t incr);

                                                                                
                                   
    uint64_t externalBytes() const;

                                                                              
                                                                           
    uint64_t size() const;

                                                                      
                                                                             
                                                                     
    uint64_t targetSizeBytes() const;

                                                
    void creditExternalMemory(uint32_t size) {
      assert(
          gc_.gcMutex_ && "OG external bytes must be accessed under gcMutex_.");
      externalBytes_ += size;
    }

                                                     
    void debitExternalMemory(uint32_t size) {
      assert(
          externalBytes_ >= size && "Debiting more memory than was credited");
      assert(
          gc_.gcMutex_ && "OG external bytes must be accessed under gcMutex_.");
      externalBytes_ -= size;
    }

    class FreelistCell final : public VariableSizeRuntimeCell {
      friend void FreelistBuildMeta(const GCCell *, Metadata::Builder &);

     private:
      static const VTable vt;

     public:
                                                    
      AssignableCompressedPointer next_{nullptr};

                                                                                
                                                                       
                          
                                                                 
                                                             
      GCCell *carve(uint32_t sz);

      static constexpr CellKind getCellKind() {
        return CellKind::FreelistKind;
      }
      static bool classof(const GCCell *cell) {
        return cell->getKind() == CellKind::FreelistKind;
      }
    };

                                                                                
                                                                           
                                                                                
                                            
    bool sweepNext(bool backgroundThread);

                                                                            
                                                                               
                                                                        
                                      
    void initializeSweep();

                                                                            
                                                                          
    size_t sweepSegmentsRemaining() const;

                                                                           
    size_t getMemorySize() const;

   private:
                                                                        
                                                                              
                                                                          
                                                                            
                   

                                                                             
                                                            

                                                    
                                                    
                                                    
                                                    

    static constexpr size_t kLogNumSmallFreelistBuckets = 8;
    static constexpr size_t kNumSmallFreelistBuckets = 1
        << kLogNumSmallFreelistBuckets;
    static constexpr size_t kLogMinSizeForLargeBlock =
        kLogNumSmallFreelistBuckets + LogHeapAlign;
    static constexpr size_t kMinSizeForLargeBlock = 1
        << kLogMinSizeForLargeBlock;
    static constexpr size_t kNumLargeFreelistBuckets =
        llvh::detail::ConstantLog2<HeapSegment::maxSize()>::value -
        kLogMinSizeForLargeBlock + 1;
    static constexpr size_t kNumFreelistBuckets =
        kNumSmallFreelistBuckets + kNumLargeFreelistBuckets;

                                                                            
                
                                                                  
    static uint32_t getFreelistBucket(uint32_t size);

                                                                               
                                                                              
                                                                              
                    
    struct SegmentBucket {
                                                        
      SegmentBucket *next{nullptr};
      SegmentBucket *prev{nullptr};

                                                                               
                                                                          
                   
      AssignableCompressedPointer head{nullptr};

                                                                             
      void addToFreelist(SegmentBucket *dummyHead);

                                                                               
                              
      void removeFromFreelist() const;
    };

                                                                      
    using SegmentBuckets = std::array<SegmentBucket, kNumFreelistBuckets>;

                                                                              
    void addCellToFreelist(void *addr, uint32_t sz, SegmentBucket *segBucket);

                                                                  
                                          
    void addCellToFreelist(FreelistCell *cell, SegmentBucket *segBucket);

                                                                    
                                                             
                                              
    FreelistCell *removeCellFromFreelist(
        AssignableCompressedPointer *prevLoc,
        size_t bucket,
        SegmentBucket *segBucket);

                                                                              
                 
                                              
    FreelistCell *removeCellFromFreelist(
        size_t bucket,
        SegmentBucket *segBucket);

                                                                                
                                                                      
                                                                               
                                                                            
    void addCellToFreelistFromSweep(
        char *freeRangeStart,
        char *freeRangeEnd,
        SegmentBuckets &segBuckets,
        bool setHead);

    HadesGC &gc_;

                                                                            
                                        
    std::deque<HeapSegment> segments_;

                                       
    ExponentialMovingAverage targetSizeBytes_{0, 0};

                                                                               
                                                                   
                                
    uint64_t allocatedBytes_{0};

                                                                             
    uint64_t externalBytes_{0};

                                                            
                                                                             
                                                           
                                   
                                                                         
                                                                           
                                                 
                                                                    
                                            

                                                                               
                                         
    BitArray<kNumFreelistBuckets> freelistBucketBitArray_;

                                                                           
                                                                              
                                                                               
                  
    std::deque<SegmentBuckets> segmentBuckets_;

                                                                             
    std::array<SegmentBucket, kNumFreelistBuckets> buckets_{};

                                                
    struct SweepIterator {
                                                                                
                                                                         
                   
      size_t segNumber{0};

                                                                                
                
      uint64_t sweptBytes{0};
      uint64_t sweptExternalBytes{0};

#ifndef NDEBUG
                                                                  
      uint64_t trimmedBytes{0};
#endif
    } sweepIterator_;

                                                            
                                                                                
                                  
    GCCell *search(uint32_t sz);

                                                         
                                                                                
             
                                                                      
    GCCell *finishAlloc(GCCell *cell, uint32_t sz);
  };

 private:
                                                                              
                                     
  const uint64_t maxHeapSize_;

                                                                         
                                                            
  uint64_t numSegments_{0};

                                                                 
                                                                      
  std::vector<size_t> segmentIndices_;

                                                                              
  std::shared_ptr<StorageProvider> provider_;

                                                                            
                            
  HeapSegment youngGen_;
  AssignableCompressedPointer youngGenCP_;

                                                                             
               
                            
  std::vector<GCCell *> youngGenFinalizables_;

                                                                            
                                                                               
                                                                               
                                                                               
                                                                              
                         
  static constexpr double kYGInitialSizeFactor = 0.5;
  double ygSizeFactor_{kYGInitialSizeFactor};

                                                                   
                     
                            
  OldGen oldGen_;

                                                                               
                                                   
  Mutex gcMutex_;

                                                                                
                                                      
  AtomicIfConcurrentGC<bool> ogPaused_{false};

                                                                              
                                    
                                                                             
                                                      
                                                                              
                                          
  std::condition_variable_any ogPauseCondVar_;

  enum class Phase : uint8_t {
    None,
    Mark,
    CompleteMarking,
    Sweep,
  };

                                                                               
                                                                               
                                       
  Phase concurrentPhase_{Phase::None};

                                                                                
                                                              
                                                                                
                                                                          
                                                                      
  bool ogMarkingBarriers_{false};

                                                             
                            
  std::unique_ptr<MarkAcceptor> oldGenMarker_;

                                                                        
                                    
  std::unique_ptr<Executor> backgroundExecutor_;

                                                                             
                                                                  
  bool backgroundTaskActive_{false};

                                                                   
  bool promoteYGToOG_;

                                                                         
  bool revertToYGAtTTI_;

                                                                               
                                       
  bool overwriteDeadYGObjects_;

                                                               
  const double occupancyTarget_;

                                                                              
                                                
  ExponentialMovingAverage ogThreshold_{0.5, 0.75};

                                                                             
                                                            
  std::unique_ptr<CollectionStats> ygCollectionStats_;

                                                                              
                                                             
  std::unique_ptr<CollectionStats> ogCollectionStats_;

                                                   
  CumulativeHeapStats ogCumulativeStats_;
  CumulativeHeapStats ygCumulativeStats_;

                                                                                
                         
  ExponentialMovingAverage ygAverageSurvivalBytes_;

                                                                           
                                     
  uint64_t ygExternalBytes_{0};

  struct CompacteeState {
                                                                                
                                 
    bool contains(const void *p) const {
      return start == AlignedStorage::start(p);
    }
    bool contains(CompressedPointer p) const {
      return p.getSegmentStart() == startCP;
    }

                                                                                
                                 
    bool evacContains(const void *p) const {
      return evacStart == AlignedStorage::start(p);
    }
    bool evacContains(CompressedPointer p) const {
      return p.getSegmentStart() == evacStartCP;
    }

                                                               
    bool evacActive() const {
      return evacStart != reinterpret_cast<void *>(kInvalidCompacteeStart);
    }

#ifndef NDEBUG
                                                            
    bool empty() const {
      void *const invalid = reinterpret_cast<void *>(kInvalidCompacteeStart);
      return evacStart == invalid && start == invalid && !segment;
    }
#endif

                                                               
                                                                          
                                                                                
                                      
                                                                              
                                                              
                                                                           

                                                                             
                                                               
    static constexpr uintptr_t kInvalidCompacteeStart = 0x1;

                                                                             
                                                                                
                                    
    void *start{reinterpret_cast<void *>(kInvalidCompacteeStart)};
    AssignableCompressedPointer startCP{
        CompressedPointer::fromRaw(kInvalidCompacteeStart)};

                                                                                
                                                                               
                                                       
    void *evacStart{reinterpret_cast<void *>(kInvalidCompacteeStart)};
    AssignableCompressedPointer evacStartCP{
        CompressedPointer::fromRaw(kInvalidCompacteeStart)};

                                                                             
                                                                         
                 
    std::shared_ptr<HeapSegment> segment;
  } compactee_;

                                                      
  size_t numCompactions_{0};

  struct NativeIDs {
    HeapSnapshot::NodeID ygFinalizables{IDTracker::kInvalidNode};
    HeapSnapshot::NodeID og{IDTracker::kInvalidNode};
  } nativeIDs_;

                                              
                                                                             
                                        
                                                                             
                                                                        
                                               
                                                                           
                                                                              
  template <bool fixedSize, HasFinalizer hasFinalizer>
  inline void *allocWork(uint32_t sz);

                                
  void *allocSlow(uint32_t sz);

                                                                        
                                                                         
                                
  void *allocLongLived(uint32_t sz);

                                                                               
                
                                                         
                                                                              
                                     
                                                                           
                    
  void youngGenCollection(std::string cause, bool forceOldGenCollection);

  template <typename Acceptor>
  void youngGenEvacuateImpl(Acceptor &acceptor, bool doCompaction);

                                                                            
                                           
                                                                
  bool promoteYoungGenToOldGen();

                                                                            
                                                                         
                                                
                                                                       
               
                                                                            
                                            
  void checkTripwireAndSubmitStats();

                                                                            
                 
  void transferExternalMemoryToOldGen();

                                                                               
                                                                          
  void updateYoungGenSizeFactor();

                                                                           
                                                                             
                                    
                                                                               
                                                     
  void oldGenCollection(std::string cause, bool forceCompaction);

                                                                         
                                                                            
                              
                                                                   
                                                                           
                                              
  void waitForCollectionToFinish(std::string cause);

                                                                              
                                                          
  void collectOGInBackground();

                                                                     
                               
  LLVM_NODISCARD std::lock_guard<Mutex> ensureBackgroundTaskPaused() {
    if constexpr (kConcurrentGC) {
      return pauseBackgroundTask();
    }
    return std::lock_guard(gcMutex_);
  }

                                                                             
                                                                        
                                                                        
                                                                             
                                            
  LLVM_NODISCARD std::lock_guard<Mutex> pauseBackgroundTask();

                                                                              
                                                            
  void incrementalCollect(bool backgroundThread);

                                                                          
                                                                   
                                                                               
                                                                               
                            
  void markWeakMapEntrySlots();

                                                                            
                                                                                
                       
  void completeMarking();

                                                                              
                                                                                
                                                                   
  void updateOldGenThreshold();

                                                                          
                      
                                                                                
                                                                      
                                               
  void prepareCompactee(bool forceCompaction);

                                                                     
  void finalizeCompactee();

                                                                             
                                 
  template <bool CompactionEnabled>
  void scanDirtyCardsForSegment(
      SlotVisitor<EvacAcceptor<CompactionEnabled>> &visitor,
      HeapSegment &segment);

                                                                             
                                                                        
                                
  template <bool CompactionEnabled>
  void scanDirtyCards(EvacAcceptor<CompactionEnabled> &acceptor);

                                                                                
  void snapshotWriteBarrierInternal(GCCell *oldValue);
  void snapshotWriteBarrierInternal(CompressedPointer oldValue);

                                                                                
                                                                           
                                                                                
                  
  void snapshotWriteBarrierInternal(HermesValue oldValue);
  void snapshotWriteBarrierInternal(SmallHermesValue oldValue);

                                                                             
                                                                                
  void snapshotWriteBarrierInternal(SymbolID symbol);

                                                                       
                                                                       
                
  void relocationWriteBarrier(const void *loc, const void *value);

                                                      
  void finalizeYoungGenObjects();

                                                                      
  uint64_t allocatedBytes() const;

                                                                            
                                            
  uint64_t externalBytes() const;

                                                                                
               
  uint64_t segmentFootprint() const;

                                                                           
                                   
  uint64_t heapFootprint() const;

                          
  HeapSegment &youngGen() {
    return youngGen_;
  }
  const HadesGC::HeapSegment &youngGen() const {
    return youngGen_;
  }

                                                           
  llvh::ErrorOr<HeapSegment> createSegment();

                                            
                                      
  HeapSegment setYoungGen(HeapSegment seg);

                                                                  
  size_t getYoungGenExternalBytes() const;
  void setYoungGenExternalBytes(size_t sz);

                                                                              
                                                                                
                 
                                                    
  bool inOldGen(const void *p) const;

                                                                           
                 
  void yieldToOldGen();

                                                                           
                                                                                
               
  size_t getDrainRate();

                                                                              
                                                                      
                  
  void addSegmentExtentToCrashManager(
      const HeapSegment &seg,
      const std::string &extraName);

                                                            
                                                                               
              
  void removeSegmentExtentFromCrashManager(const std::string &extraName);

#ifdef HERMES_SLOW_DEBUG
                                                       
  void checkWellFormed();

                                                                              
                                                                    
  void verifyCardTable();
#endif
};

                                
      

template <
    typename T,
    bool fixedSize,
    HasFinalizer hasFinalizer,
    LongLived longLived,
    class... Args>
inline T *HadesGC::makeA(uint32_t size, Args &&...args) {
  assert(
      isSizeHeapAligned(size) &&
      "Call to makeA must use a size aligned to HeapAlign");
  assert(noAllocLevel_ == 0 && "No allocs allowed right now.");
  if (longLived == LongLived::Yes) {
    auto lk = ensureBackgroundTaskPaused();
    return constructCell<T>(
        allocLongLived(size), size, std::forward<Args>(args)...);
  }

  return constructCell<T>(
      allocWork<fixedSize, hasFinalizer>(size),
      size,
      std::forward<Args>(args)...);
}

template <bool fixedSize, HasFinalizer hasFinalizer>
void *HadesGC::allocWork(uint32_t sz) {
  assert(
      isSizeHeapAligned(sz) &&
      "Should be aligned before entering this function");
  assert(sz >= minAllocationSize() && "Allocating too small of an object");
  if (shouldSanitizeHandles()) {
                                                                                
                                                                         
                                                                               
                                                                      
                                                                             
                                                      
    youngGenCollection(
        kHandleSanCauseForAnalytics,                           true);
  }
  AllocResult res = youngGen().alloc(sz);
  void *resPtr = LLVM_UNLIKELY(!res.success) ? allocSlow(sz) : res.ptr;
  if (hasFinalizer == HasFinalizer::Yes)
    youngGenFinalizables_.emplace_back(static_cast<GCCell *>(resPtr));
  return resPtr;
}

      

}                
}                    
#endif

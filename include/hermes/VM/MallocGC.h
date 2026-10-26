/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_MALLOCGC_H
#define HERMES_VM_MALLOCGC_H

#include "hermes/Public/GCConfig.h"
#include "hermes/VM/CompressedPointer.h"
#include "hermes/VM/GCBase.h"
#include "hermes/VM/GCCell.h"
#include "hermes/VM/VMExperiments.h"

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/DenseSet.h"
#include "llvh/Support/raw_ostream.h"

#include <deque>
#include <limits>
#include <vector>

namespace hermes {
namespace vm {

class MallocGC final : public GCBase {
  class CellHeader {
                                                                         
                                                                              
                                   
    bool marked_ = false;

#ifdef HERMESVM_SANITIZE_HANDLES
                                                                                
                                        
                                                                 
    CellHeader *forwardingPtr_ = nullptr;
#endif

                                                                             
                                  
    static_assert(
        alignof(GCCell) <= HeapAlign,
        "GCCell's alignment exceeds the alignment requirement of the heap");
    alignas(HeapAlign) uint8_t data_[0];

   public:
    bool isMarked() const {
      return marked_;
    }

                                                                    
    void mark() {
      assert(!isMarked() && "Marking an already marked pointer");
      marked_ = true;
    }

    void markWithForwardingPointer(CellHeader *newLocation) {
      mark();
#ifdef HERMESVM_SANITIZE_HANDLES
      forwardingPtr_ = newLocation;
#else
      llvm_unreachable(
          "Trying to add a forwarding pointer outside of handle-san mode");
#endif
    }

    void unmark() {
      assert(isMarked() && "Unmarking an already unmarked pointer");
      marked_ = false;
#ifdef HERMESVM_SANITIZE_HANDLES
      forwardingPtr_ = nullptr;
#endif
    }

    GCCell *data() {
      return reinterpret_cast<GCCell *>(data_);
    }

    const GCCell *data() const {
      return reinterpret_cast<const GCCell *>(data_);
    }

    CellHeader *getForwardingPointer() {
      assert(isMarked() && "Getting forwarding pointer from unmarked pointer");
#ifdef HERMESVM_SANITIZE_HANDLES
      assert(forwardingPtr_ && "Accessing a null forwarding pointer");
      return forwardingPtr_;
#else
      llvm_unreachable(
          "Can't get a forwarding pointer outside of handle-san mode");
#endif
    }

    static CellHeader *from(GCCell *cell) {
      return reinterpret_cast<CellHeader *>(
          reinterpret_cast<char *>(cell) - offsetof(CellHeader, data_));
    }

    static const CellHeader *from(const GCCell *cell) {
      return reinterpret_cast<const CellHeader *>(
          reinterpret_cast<const char *>(cell) - offsetof(CellHeader, data_));
    }
  };

                                                                                
                                                                                
                
  llvh::DenseSet<CellHeader *> pointers_;
                                                                         
                                                                            
            
                                               
  llvh::DenseSet<CellHeader *> newPointers_;
                                                                                
                  
  const gcheapsize_t maxSize_;
                                                                  
  gcheapsize_t sizeLimit_;
                                                                         
  gcheapsize_t allocatedBytes_{0};
                                                                          
  uint64_t externalBytes_{0};

 public:
                            
  class Size final {
   public:
    explicit Size(const GCConfig &gcConfig)
        : Size(gcConfig.getMinHeapSize(), gcConfig.getMaxHeapSize()) {}
    Size(gcheapsize_t min, gcheapsize_t max) : min_(min), max_(max) {}

    gcheapsize_t min() const {
      return min_;
    }

    gcheapsize_t max() const {
      return max_;
    }

    gcheapsize_t storageFootprint() const;
    gcheapsize_t minStorageFootprint() const;

   private:
    gcheapsize_t min_;
    gcheapsize_t max_;
  };

  MallocGC(
      GCCallbacks &gcCallbacks,
      PointerBase &pointerBase,
      const GCConfig &gcConfig,
      std::shared_ptr<CrashManager> crashMgr,
      std::shared_ptr<StorageProvider> provider,
      experiments::VMExperimentFlags vmExperimentFlags);

  ~MallocGC() override;

                                                                       
                                                                       
               
  void collectBeforeAlloc(std::string cause, uint32_t size);

                                                                         
                                                                               
                           
                                                                   
  template <
      typename T,
      bool fixedSize = true,
      HasFinalizer hasFinalizer = HasFinalizer::No,
      LongLived longLived = LongLived::Yes,
      class... Args>
  inline T *makeA(uint32_t size, Args &&...args);

                                                                      
                                                                                
                                                                           
                                                                                
               
  bool canAllocExternalMemory(uint32_t size) override;

                                                                              
                                               
  void collect(std::string cause, bool canEffectiveOOM = false) override;

  static constexpr uint32_t minAllocationSizeImpl() {
                                                           
    return 0;
  }

  static constexpr uint32_t maxAllocationSizeImpl() {
                                                           
    return std::numeric_limits<uint32_t>::max();
  }

                                              
  void finalizeAll() override;

                                                                            
                                 
                                                               
  bool inFullCollection() const {
    return true;
  }

#ifndef NDEBUG
                            
  bool calledByGC() const override {
    return inGC();
  }

                                                                 
  bool validPointer(const void *p) const override;
  bool dbgContains(const void *p) const override;

  bool needsWriteBarrier(void *loc, GCCell *value) override;
#endif

#ifdef HERMES_MEMORY_INSTRUMENTATION
                                   
  virtual void createSnapshot(llvh::raw_ostream &os, bool captureNumericValue)
      override;
#endif

  virtual void creditExternalMemory(GCCell *alloc, uint32_t size) override;
  virtual void debitExternalMemory(GCCell *alloc, uint32_t size) override;

  void writeBarrier(const GCHermesValue *, HermesValue) {}
  void writeBarrier(const GCSmallHermesValue *, SmallHermesValue) {}
  void writeBarrier(const GCPointerBase *, const GCCell *) {}
  void constructorWriteBarrier(const GCHermesValue *, HermesValue) {}
  void constructorWriteBarrier(const GCSmallHermesValue *, SmallHermesValue) {}
  void constructorWriteBarrier(const GCPointerBase *, const GCCell *) {}
  void writeBarrierRange(const GCHermesValue *, uint32_t) {}
  void writeBarrierRange(const GCSmallHermesValue *, uint32_t) {}
  void constructorWriteBarrierRange(const GCHermesValue *, uint32_t) {}
  void constructorWriteBarrierRange(const GCSmallHermesValue *, uint32_t) {}
  void snapshotWriteBarrier(const GCHermesValue *) {}
  void snapshotWriteBarrier(const GCSmallHermesValue *) {}
  void snapshotWriteBarrier(const GCPointerBase *) {}
  void snapshotWriteBarrier(const GCSymbolID *) {}
  void snapshotWriteBarrierRange(const GCHermesValue *, uint32_t) {}
  void snapshotWriteBarrierRange(const GCSmallHermesValue *, uint32_t) {}
  void weakRefReadBarrier(HermesValue) {}
  void weakRefReadBarrier(GCCell *) {}

  void getHeapInfo(HeapInfo &info) override;
  void getHeapInfoWithMallocSize(HeapInfo &info) override;
  void getCrashManagerHeapInfo(CrashManager::HeapInformation &info) override;
  std::string getKindAsStr() const override;

                                                           
  size_t maxSize() const {
    return maxSize_;
  }

                                                                         
                                                              
  void forAllObjs(const std::function<void(GCCell *)> &callback) override;

  static bool classof(const GCBase *gc) {
    return gc->getKind() == HeapKind::MallocGC;
  }

 private:
#ifdef HERMES_SLOW_DEBUG
  void checkWellFormed();
  void clearUnmarkedPropertyMaps();
#endif

                                                                            
                       
  template <
      bool fixedSizeIgnored = true,
      HasFinalizer hasFinalizer = HasFinalizer::No>
  inline void *alloc(uint32_t size);

                                                                  
  inline void initCell(GCCell *cell, uint32_t size);

                                
  void printStats(JSONEmitter &json) override;

                                                             
  void resetStats();

  struct MarkingAcceptor;
  class SkipWeakRefsMarkingAcceptor;
  struct FullMSCUpdateWeakRootsAcceptor;

                                                                      
                                                               
                                                             
  void drainMarkStack(MarkingAcceptor &acceptor);

                                                                          
                                                                       
                                                                               
                                                                      
                                        
  void markWeakMapEntrySlots(MarkingAcceptor &acceptor);

                                                                             
                   
  void updateWeakReferences();
};

                                
      

template <bool fixedSizeIgnored, HasFinalizer hasFinalizer>
inline void *MallocGC::alloc(uint32_t size) {
  assert(noAllocLevel_ == 0 && "no alloc allowed right now");
  assert(
      isSizeHeapAligned(size) &&
      "Call to alloc must use a size aligned to HeapAlign");
  if (shouldSanitizeHandles()) {
    collectBeforeAlloc(kHandleSanCauseForAnalytics, size);
  }
                                         
  if (LLVM_UNLIKELY(size > sizeLimit_ - allocatedBytes_)) {
    collectBeforeAlloc(kNaturalCauseForAnalytics, size);
  }
                              
  auto *header = new (checkedMalloc(size + sizeof(CellHeader))) CellHeader();
  GCCell *mem = header->data();
  initCell(mem, size);
                                                
  pointers_.insert(header);
  allocatedBytes_ += size;
  totalAllocatedBytes_ += size;
#ifndef NDEBUG
  ++numAllocatedObjects_;
#endif
  return mem;
}

inline bool MallocGC::canAllocExternalMemory(uint32_t size) {
  return size <= maxSize_;
}

template <
    typename T,
    bool fixedSize,
    HasFinalizer hasFinalizer,
    LongLived longLived,
    class... Args>
inline T *MallocGC::makeA(uint32_t size, Args &&...args) {
  assert(
      isSizeHeapAligned(size) &&
      "Call to makeA must use a size aligned to HeapAlign");
                                                                              
                       
  void *mem = alloc<fixedSize, hasFinalizer>(size);
  return constructCell<T>(mem, size, std::forward<Args>(args)...);
}

inline void MallocGC::initCell(GCCell *cell, uint32_t size) {
#ifndef NDEBUG
                                           
  std::fill_n(reinterpret_cast<char *>(cell), size, kInvalidHeapValue);
#endif
}

      

}                
}                    

#endif

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_GCBASE_H
#define HERMES_VM_GCBASE_H

#include "hermes/ADT/ManagedChunkedList.h"
#include "hermes/Inst/Inst.h"
#include "hermes/Platform/Logging.h"
#include "hermes/Public/CrashManager.h"
#include "hermes/Public/GCConfig.h"
#include "hermes/Public/GCTripwireContext.h"
#include "hermes/Support/CheckedMalloc.h"
#include "hermes/Support/OSCompat.h"
#include "hermes/Support/StatsAccumulator.h"
#include "hermes/VM/AllocOptions.h"
#include "hermes/VM/BuildMetadata.h"
#include "hermes/VM/CellKind.h"
#include "hermes/VM/CompressedPointer.h"
#include "hermes/VM/GCDecl.h"
#include "hermes/VM/GCExecTrace.h"
#include "hermes/VM/GCPointer.h"
#include "hermes/VM/HeapAlign.h"
#include "hermes/VM/HeapSnapshot.h"
#include "hermes/VM/HermesValue.h"
#include "hermes/VM/SlotAcceptor.h"
#include "hermes/VM/SlotVisitor.h"
#include "hermes/VM/SmallHermesValue.h"
#include "hermes/VM/StackTracesTree-NoRuntime.h"
#include "hermes/VM/StorageProvider.h"
#include "hermes/VM/StringRefUtils.h"
#include "hermes/VM/VTable.h"
#include "hermes/VM/WeakRefSlot.h"

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/BitVector.h"
#include "llvh/ADT/DenseMap.h"
#include "llvh/Support/ErrorHandling.h"

#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <list>
#include <random>
#include <system_error>
#include <vector>
#pragma GCC diagnostic push

namespace hermes {
namespace vm {

                         
class GCCell;
class JSObject;
class JSWeakMapImplBase;

#ifdef HERMESVM_GC_RUNTIME
#define RUNTIME_GC_KINDS GC_KIND(HadesGC)
#endif

                                                            
enum XorPtrKeyID {
  ArrayBufferData,
  JSFunctionCodeBlock,
  DummyObjectFinalizerCallback,
  _NumKeys
};

                                                                         
                                                        

                                                                               
                                                                                
                                                                            
                                                                             
                                                                            
                                                                             
                                          
                                   
   
                
                   
                              
                                                     
                                            
                      
                                                    
   
                                                                               
                                                                           
                                                                               
                                          
   
                                                 
   
                                                     
   
                                                              
                                                             
   
                                                                        
            
                                      
   
                                                                            
                                                        
   
                               
                                            
   
                                              
                                         
   
                                                                           
                           
   
                                                                           
                          
   
                                         
                                                                     
   
                                                                   
                                        
   
                                                         
                                            
                                 
   
                                                               
                                    
                         
   
                                                       
                                              
   
                                                               
                                                                         
                              
   
                                                                         
                                    
   
                                                                    
                                                                       
                                                                 
                          
                                          
                                    
   
                                                                            
                                                                           
                                                                         
   
                                                                                
                                   
                                     
                                     
                               
                                     
                                          
                                    
                                     
                                     
                                 
   
                                                                           
                                                                  
                                               
                                                                            
                                                                             
                   
                                                   
   
                                                                           
                                                                       
                                
                                                                      
                               
                                                     
                    
                                          
                                       
                             
                                          
                                            
                             
   
                                                                              
                                                    
                                                            
                                                                 
                                                            
                                                             
                                       
                                       
                             
                                       
                                            
                             
   
                                                                            
                                              
                                                        
   
                                                                      
                                                                          
                                                                         
                                                                          
                        
                                      
   
                                     
                 
                                                     
                                                                      
                                            
                                                 
                                                               
                                 
                                                               
                                 
                                                                       
                                                        
                                              
   
class GCBase {
 public:
  static const char kNaturalCauseForAnalytics[];
  static const char kHandleSanCauseForAnalytics[];

                                                                        
              
  struct GCCallbacks {
                                             
    virtual ~GCCallbacks() = 0;

                                                                        
                                                      
                                                                            
                                                                     
                                                                       
                                                             
    virtual void markRoots(
        RootAndSlotAcceptorWithNames &acceptor,
        bool markLongLived = true) = 0;

                                                                             
                              
    virtual void markWeakRoots(
        WeakRootAcceptor &weakAcceptor,
        bool markLongLived = true) = 0;

                                                                             
                                                                            
                                                                                
                                                                              
                                                                         
                
                                                                    
                                                                               
                                              
    virtual void markRootsForCompleteMarking(
        RootAndSlotAcceptorWithNames &acceptor) = 0;

                                                                                
                                                                          
                                                                    
    virtual unsigned getSymbolsEnd() const = 0;

                                                                             
                                                                
    virtual void unmarkSymbols() = 0;

                                                                             
                                                              
    virtual void freeSymbols(const llvh::BitVector &markedSymbols) = 0;

                                                                      
                                                                      
                                 
    virtual void printRuntimeGCStats(JSONEmitter &json) const = 0;

                                                                           
                                                
    virtual size_t mallocSize() const = 0;

                                                                          
                                                                              
                                                                            
                        
    virtual void visitIdentifiers(
        const std::function<void(SymbolID, const StringPrimitive *)>
            &acceptor) = 0;

                                                                      
                                                                         
                                                                          
                         
    virtual std::string convertSymbolToUTF8(SymbolID id) = 0;

                                                                           
                             
    virtual std::string getCallStackNoAlloc() = 0;

                                                                             
                                 
                                                                           
    virtual void onGCEvent(GCEventKind kind, const std::string &extraInfo) = 0;

                                                                             
                                                                     
    virtual const inst::Inst *getCurrentIPSlow() const = 0;

#ifdef HERMES_MEMORY_INSTRUMENTATION
                                                                               
                      
    virtual StackTracesTreeNode *getCurrentStackTracesTreeNode(
        const inst::Inst *ip) = 0;

                                                                              
                                                                                
    virtual StackTracesTree *getStackTracesTree() = 0;
#endif

#ifdef HERMES_SLOW_DEBUG
                                                                          
              
                                                                       
                                                  
    virtual bool isSymbolLive(SymbolID id) = 0;

                                                                          
                  
    virtual const void *getStringForSymbol(SymbolID id) = 0;
#endif
  };

                                                                     
  struct CumulativeHeapStats {
    unsigned numCollections{0};

                                                                               
                                  
    StatsAccumulator<double> gcWallTime;

                                            
    StatsAccumulator<double> gcCPUTime;

    gcheapsize_t finalHeapSize{0};

                                                 
    StatsAccumulator<gcheapsize_t, uint64_t> usedBefore;

                                       
    StatsAccumulator<gcheapsize_t, uint64_t> usedAfter;
  };

  struct HeapInfo {
                                                                   
    unsigned numCollections{0};
                                                                          
    unsigned numCompactions{0};
                                                                             
    uint64_t totalAllocatedBytes{0};
                                                                           
                                                                        
    uint64_t allocatedBytes{0};
                                                  
    uint64_t heapSize{0};
                                                                              
                                                                            
                                                            
    unsigned mallocSizeEstimate{0};
                                                                            
    uint64_t va{0};
                                                                               
                                                                       
                                                                                
                                                                      
    uint64_t externalBytes{0};
                                                                     
                                      
    unsigned numMarkStackOverflows{0};
                                                                
    CumulativeHeapStats generalStats;
                                                                   
    CumulativeHeapStats fullStats;
                                                                
                             
    CumulativeHeapStats youngGenStats;
  };

#ifndef NDEBUG
  struct DebugHeapInfo {
                                                                              
                    
    unsigned numAllocatedObjects{0};
                                                           
    unsigned numReachableObjects{0};
                                                           
    unsigned numCollectedObjects{0};
                                                           
    unsigned numFinalizedObjects{0};
                                 
    unsigned numMarkedSymbols{0};
                                                                 
    unsigned numHiddenClasses{0};
                                                                        
    unsigned numLeafHiddenClasses{0};

                                                                     
                     
    void assertInvariants() const;
  };
#endif

#ifdef HERMES_MEMORY_INSTRUMENTATION
                                                                        
                                                                         
                                           
  struct AllocationLocationTracker final {
    explicit AllocationLocationTracker(GCBase *gc);

                                                                
    bool isEnabled() const;
                                                                               
    void newAlloc(const GCCell *ptr, uint32_t sz);

                                                           
    void updateSize(const GCCell *ptr, uint32_t oldSize, uint32_t newSize);

                                                                             
    void freeAlloc(const GCCell *ptr, uint32_t sz);
                                                                          
                             
    StackTracesTreeNode *getStackTracesTreeNodeForAlloc(
        HeapSnapshot::NodeID id) const;

                                                                      
                                                                       
                                                                             
                                                                     
    struct Fragment {
      HeapSnapshot::NodeID lastSeenObjectID_;
      std::chrono::microseconds timestamp_;
                                                                          
                                                                      
      uint64_t numObjects_;
                                                             
      uint64_t numBytes_;
                                                                              
      bool touchedSinceLastFlush_;
    };

                                                                       
                            
    using HeapStatsUpdate = std::tuple<uint64_t, uint64_t, uint64_t>;

                                 
    void enable(
        std::function<void(
            uint64_t,
            std::chrono::microseconds,
            std::vector<HeapStatsUpdate>)> callback);

                                                                              
                                           
    void disable();

                                                                              
    void addSamplesToSnapshot(HeapSnapshot &snap);

   private:
                                                                                
                            
    static constexpr uint64_t kFlushThreshold = 128 * (1 << 10);
                                                                           
                                                                              
                             
    Mutex mtx_;
                                                                               
             
    llvh::DenseMap<HeapSnapshot::NodeID, StackTracesTreeNode *> stackMap_;
                                                                                
                  
    GCBase *gc_;
                                                            
    bool enabled_{false};
                                           
    std::chrono::steady_clock::time_point startTime_;
                                                                              
                
    std::function<
        void(uint64_t, std::chrono::microseconds, std::vector<HeapStatsUpdate>)>
        fragmentCallback_;
                                                                               
                            
    std::vector<Fragment> fragments_;

                                                                            
                                                                               
                                 
    void flushCallback();

                                                        
                                                                           
                    
    Fragment &findFragmentForID(HeapSnapshot::NodeID id);
  };

  class SamplingAllocationLocationTracker final {
   public:
    explicit inline SamplingAllocationLocationTracker(GCBase *gc) : gc_(gc) {}

                                                                
    bool isEnabled() const {
      return !!dist_;
    }

                                                                               
    void newAlloc(const GCCell *ptr, uint32_t sz);

                                                                             
    void freeAlloc(const GCCell *ptr, uint32_t sz);

                                                           
    void updateSize(const GCCell *ptr, uint32_t oldSize, uint32_t newSize);

                                                              
                                                                         
                            
                                                                            
                                                 
    void enable(size_t samplingInterval, int64_t seed);

    void disable(llvh::raw_ostream &os);

   private:
    struct Sample final {
      size_t size;
      StackTracesTreeNode *node;
                                                                          
                                     
      uint64_t id;
    };

                                                                               
                                                                       
    Mutex mtx_;

    GCBase *gc_;

                                                                             
                      
    size_t limit_{0};

                                               
    llvh::DenseMap<HeapSnapshot::NodeID, Sample> samples_;

                                                                          
    std::minstd_rand randomEngine_;
    std::unique_ptr<std::poisson_distribution<>> dist_;

                                                                           
                                  
    uint64_t nextSampleID_{1};

                                                                      
    size_t nextSample();
  };
#endif

  class IDTracker final {
   public:
                                                            
    enum class ReservedObjectID : HeapSnapshot::NodeID {
                                          
      SuperRoot,
                                          
      GCRoots,
#define ROOT_SECTION(name) name,
#include "hermes/VM/RootSections.def"
      IdentifierTableLookupVector,
      IdentifierTableHashTable,
      IdentifierTableMarkedSymbols,
      JSIHermesValueList,
      JSIWeakHermesValueList,
      WeakRefSlotStorage,
      Undefined,
      Null,
      True,
      False,
      Number,
      FirstNonReservedID,
    };

                                                   
    static constexpr HeapSnapshot::NodeID kInvalidNode = 0;

    static constexpr HeapSnapshot::NodeID reserved(ReservedObjectID id) {
                                                                          
                                                                  
      return static_cast<std::underlying_type<ReservedObjectID>::type>(id) * 2 +
          1;
    }

                                                 
    struct DoubleComparator {
      static double getEmptyKey() {
                                                                              
                           
                                                                              
                            
        return llvh::BitsToDouble(HermesValue::encodeUndefinedValue().getRaw());
      }
      static double getTombstoneKey() {
                                                                             
                           
                                                                              
                            
        return llvh::BitsToDouble(HermesValue::encodeNullValue().getRaw());
      }
      static unsigned getHashValue(double val) {
        uint64_t bits = llvh::DoubleToBits(val);
                                                                              
                                                                           
                                                                                
                                                                             
                                                                          
                                                                                
                                                                              
                                                                           
                                                                            
                                                                             
                                                         
        return llvh::hash_value(bits);
      }
      static bool isEqual(double LHS, double RHS) {
        return llvh::DoubleToBits(LHS) == llvh::DoubleToBits(RHS);
      }
    };

    explicit IDTracker();

                                                    
    bool hasTrackedObjectIDs();

                                                    
    bool isTrackingNumberIDs();

                                                                      
    void startTrackingNumberIDs();

                                                                     
    void stopTrackingNumberIDs();

                                                     
                                                     
    HeapSnapshot::NodeID getObjectID(CompressedPointer cell);

                                                                              
                        
    bool hasObjectID(CompressedPointer cell);

                                                                             
           
    HeapSnapshot::NodeID getObjectIDMustExist(CompressedPointer cell);

                                                                               
                                                  
    HeapSnapshot::NodeID getObjectID(SymbolID sym);

                                                                          
                                                     
    HeapSnapshot::NodeID getNativeID(const void *mem);

                                                                       
                                                                             
                            
                                                                           
                                
    llvh::SmallVector<HeapSnapshot::NodeID, 1> &getExtraNativeIDs(
        HeapSnapshot::NodeID node);

                                                                                
                                                                            
                                                              
                                                                          
                            
    HeapSnapshot::NodeID getNumberID(double num);

                                                                          
                    
                                                       
    llvh::Optional<CompressedPointer> getObjectForID(HeapSnapshot::NodeID id);

                                                            
                                                                               
                                                          
    void moveObject(
        CompressedPointer oldLocation,
        CompressedPointer newLocation);

                                                                             
                                   
    void untrackObject(CompressedPointer cell);

                                                                            
                              
    void untrackSymbol(uint32_t symIdx);

                                                                                
                                                                           
                                                                           
                    
    void untrackNative(const void *mem);

                                                                              
                                   
    bool hasNativeIDs();

                                                                              
                    
    HeapSnapshot::NodeID lastID() const;

                                                                   
                                                                             
                
    HeapSnapshot::NodeID nextNativeID();

   private:
                                                                 
    HeapSnapshot::NodeID nextObjectID();
                                                   
    HeapSnapshot::NodeID nextNumberID();

                                                                             
                                                                               
                                   
    static constexpr HeapSnapshot::NodeID kIDStep = 2;

                                                                         
                                                                               
                                                           
    Mutex mtx_;

                                                                       
                                                                             
                                                             
    HeapSnapshot::NodeID lastID_{
        reserved(ReservedObjectID::FirstNonReservedID)};

                                                                         
                                                                              
                                           
                                                                               
                                                              
    llvh::DenseMap<CompressedPointer::RawType, HeapSnapshot::NodeID>
        objectIDMap_;

                                                                             
                                                                                
                                                                            
                                                                             
    llvh::DenseMap<HeapSnapshot::NodeID, CompressedPointer::RawType>
        idObjectMap_;

                                                             
                                           
    llvh::DenseMap<const void *, HeapSnapshot::NodeID> nativeIDMap_;

                                                                         
                                                                              
                                                                       
                        
    llvh::DenseMap<
        HeapSnapshot::NodeID,
        llvh::SmallVector<HeapSnapshot::NodeID, 1>>
        extraNativeIDs_;

                                                                      
                                           
    llvh::DenseMap<uint32_t, HeapSnapshot::NodeID> symbolIDMap_;

                                                                               
             
    llvh::DenseMap<double, HeapSnapshot::NodeID, DoubleComparator> numberIDMap_;

                                                                            
    bool isTrackingNumberIDs_ = true;
  };

  enum class HeapKind { HadesGC, MallocGC };

  GCBase(
      GCCallbacks &gcCallbacks,
      PointerBase &pointerBase,
      const GCConfig &gcConfig,
      std::shared_ptr<CrashManager> crashMgr,
      HeapKind kind);

  virtual ~GCBase() {
    assert(
        weakMapEntrySlots_.sizeForTests() == 0 &&
        "weakMapEntrySlots_ must all be freed");
    assert(weakSlots_.sizeForTests() == 0 && "weakSlots_ must all be freed");
  }

                                           
                                                                   
  template <
      typename T,
      HasFinalizer hasFinalizer = HasFinalizer::No,
      LongLived longLived = LongLived::No,
      class... Args>
  T *makeAFixed(Args &&...args);

                                                               
                                                                   
  template <
      typename T,
      HasFinalizer hasFinalizer = HasFinalizer::No,
      LongLived longLived = LongLived::No,
      class... Args>
  T *makeAVariable(uint32_t size, Args &&...args);

  template <
      typename T,
      bool fixedSize = true,
      HasFinalizer hasFinalizer = HasFinalizer::No,
      LongLived longLived = LongLived::No,
      class... Args>
  T *makeA(uint32_t size, Args &&...args);

                                         
  const std::string &getName() const {
    return name_;
  }

                                               
                                                                    
                                                                   
                                                
  PointerBase &getPointerBase() const {
    return pointerBase_;
  }

  GCCallbacks &getCallbacks() const {
    return gcCallbacks_;
  }

                                                                           
                        
  std::string convertSymbolToUTF8(SymbolID id) {
    return gcCallbacks_.convertSymbolToUTF8(id);
  }

                                                                               
                     
  void runtimeWillExecute();

                                                                      
                                                                      
               
  virtual void ttiReached() {}

                                                                     
                                                                 
  virtual void recordNumAllocatedObjects() {}

                                                                              
  void printAllCollectedStats(llvh::raw_ostream &os);

                                              
  unsigned getNumGCs() const {
    return cumStats_.numCollections;
  }

                                                                         
  double getGCTime() const {
    return cumStats_.gcWallTime.sum();
  }

                                                                        
  double getGCCPUTime() const {
    return cumStats_.gcCPUTime.sum();
  }

  GCCallbacks &getGCCallbacks() const {
    return gcCallbacks_;
  }

                                        
  virtual size_t getPeakAllocatedBytes() const {
    return cumStats_.usedBefore.max();
  }
  virtual size_t getPeakLiveAfterGC() const {
    return cumStats_.usedAfter.max();
  }

                                                       
  virtual void getHeapInfo(HeapInfo &info);
                                                                             
  virtual void getHeapInfoWithMallocSize(HeapInfo &info);

                                                                    
                                                                             
  const GCExecTrace &getGCExecTrace() const;

                                                                    
  virtual void getCrashManagerHeapInfo(CrashManager::HeapInformation &info) = 0;

#ifndef NDEBUG
                                                                            
                                                     
  virtual void getDebugHeapInfo(DebugHeapInfo &info);

                                                        
                                         
  size_t countUsedWeakRefs() const;

                                                                             
                             
  virtual bool validPointer(const void *ptr) const = 0;
#endif

#ifdef HERMESVM_GC_RUNTIME
  inline static constexpr uint32_t minAllocationSizeImpl();

  inline static constexpr uint32_t maxAllocationSizeImpl();
#endif

  inline static constexpr uint32_t minAllocationSize();

  inline static constexpr uint32_t maxAllocationSize();

                                                                    
  virtual void dump(llvh::raw_ostream &os, bool verbose = false);

                                              
  virtual void finalizeAll() = 0;

                                                                          
              
  virtual void collect(std::string cause, bool canEffectiveOOM = false) = 0;

                                                                         
                                                              
  virtual void forAllObjs(const std::function<void(GCCell *)> &callback) = 0;

                                                                
  virtual bool inYoungGen(const void *p) const {
    return false;
  }

                                                                      
                                                                               
                                                                           
                                                                               
               
  virtual bool canAllocExternalMemory(uint32_t size) {
    return true;
  }

  WeakRefSlot *allocWeakSlot(CompressedPointer ptr);

                                                                           
                                           
                                                      
                                                         
  WeakMapEntrySlot *allocWeakMapEntrySlot(
      JSObject *key,
      HermesValue value,
      JSWeakMapImplBase *owner);

#ifndef NDEBUG
                      
        
  virtual bool calledByBackgroundThread() const {
    return false;
  }
  virtual bool calledByGC() const {
    return true;
  }
  virtual bool dbgContains(const void *ptr) const = 0;
  virtual void trackReachable(CellKind kind, unsigned sz) {}
  virtual bool needsWriteBarrier(void *loc, GCCell *value) = 0;
        
#endif

                                                                            
                                
  LLVM_ATTRIBUTE_NORETURN void oom(std::error_code reason);

#ifdef HERMES_MEMORY_INSTRUMENTATION
                                                                            
                                                                 
  std::error_code createSnapshotToFile(const std::string &fileName);

                                                                                
                                           
  using SavedNumRootEdges = std::array<
      llvh::Optional<HeapSizeType>,
      static_cast<unsigned>(RootSectionAcceptor::Section::NumSections)>;

                                                                           
                                                         
  virtual void createSnapshot(
      llvh::raw_ostream &os,
      bool captureNumericValue) = 0;
  void createSnapshot(GC &gc, llvh::raw_ostream &os, bool captureNumericValue);
                                                                          
                                                                            
                                                                           
                                                          
  void createSnapshotImpl(
      GC &gc,
      HeapSnapshot &snap,
      SavedNumRootEdges &numRootEdges);

                                                                        
  virtual void snapshotAddGCNativeNodes(HeapSnapshot &snap);

                                                          
  virtual void snapshotAddGCNativeEdges(HeapSnapshot &snap);

                                                                               
                                                
  virtual void enableHeapProfiler(
      std::function<void(
          uint64_t,
          std::chrono::microseconds,
          std::vector<GCBase::AllocationLocationTracker::HeapStatsUpdate>)>
          fragmentCallback);

                                                                              
                                  
                                                                          
                                                            
  virtual void disableHeapProfiler();

                                                            
                                                                       
                          
                                                                          
                                               
  virtual void enableSamplingHeapProfiler(
      size_t samplingInterval,
      int64_t seed);

                                                                       
                                                                               
                                                                                
                   
  virtual void disableSamplingHeapProfiler(llvh::raw_ostream &os);
#endif                                 

                                                              
  virtual void creditExternalMemory(GCCell *alloc, uint32_t size) = 0;
  virtual void debitExternalMemory(GCCell *alloc, uint32_t size) = 0;

#ifdef HERMESVM_GC_RUNTIME
                                                                      
  void writeBarrier(const GCHermesValue *loc, HermesValue value);
  void writeBarrier(const GCSmallHermesValue *loc, SmallHermesValue value);
  void writeBarrier(const GCPointerBase *loc, const GCCell *value);
  void constructorWriteBarrier(const GCHermesValue *loc, HermesValue value);
  void constructorWriteBarrier(
      const GCSmallHermesValue *loc,
      SmallHermesValue value);
  void constructorWriteBarrier(const GCPointerBase *loc, const GCCell *value);
  void writeBarrierRange(const GCHermesValue *start, uint32_t numHVs);
  void writeBarrierRange(const GCSmallHermesValue *start, uint32_t numHVs);
  void constructorWriteBarrierRange(
      const GCHermesValue *start,
      uint32_t numHVs);
  void constructorWriteBarrierRange(
      const GCSmallHermesValue *start,
      uint32_t numHVs);
  void snapshotWriteBarrier(const GCHermesValue *loc);
  void snapshotWriteBarrier(const GCSmallHermesValue *loc);
  void snapshotWriteBarrier(const GCPointerBase *loc);
  void snapshotWriteBarrier(const GCSymbolID *symbol);
  void snapshotWriteBarrierRange(const GCHermesValue *start, uint32_t numHVs);
  void snapshotWriteBarrierRange(
      const GCSmallHermesValue *start,
      uint32_t numHVs);
  void weakRefReadBarrier(HermesValue value);
  void weakRefReadBarrier(GCCell *value);
#endif

                        
        

                                   
                                      
                                                                 
  template <typename Acceptor>
  inline void markCell(GCCell *cell, Acceptor &acceptor);

                                                                           
               
  template <typename Acceptor>
  inline void markCell(GCCell *cell, CellKind kind, Acceptor &acceptor);

                                                                  
  template <typename Acceptor>
  inline void
  markCell(SlotVisitor<Acceptor> &visitor, GCCell *cell, CellKind kind);

                                                                             
                   
  template <typename Acceptor>
  inline void markCellWithinRange(
      SlotVisitor<Acceptor> &visitor,
      GCCell *cell,
      CellKind kind,
      const char *begin,
      const char *end);

                                                                       
                                         
  template <typename Acceptor>
  inline void markCellWithNames(
      SlotVisitorWithNames<Acceptor> &visitor,
      GCCell *cell);

        

                                                                              
                                                                               
                                                                          
                                                                           
  bool inGC() const {
    return inGC_;
  }

  HeapKind getKind() const {
    return heapKind_;
  }

                                                        
  virtual std::string getKindAsStr() const = 0;

  bool isTrackingIDs() {
#ifdef HERMES_MEMORY_INSTRUMENTATION
    return getIDTracker().hasTrackedObjectIDs() ||
        getAllocationLocationTracker().isEnabled() ||
        getSamplingAllocationTracker().isEnabled();
#else
    return getIDTracker().hasTrackedObjectIDs();
#endif
  }

  IDTracker &getIDTracker() {
    return idTracker_;
  }

#ifdef HERMES_MEMORY_INSTRUMENTATION
  AllocationLocationTracker &getAllocationLocationTracker() {
    return allocationLocationTracker_;
  }

  SamplingAllocationLocationTracker &getSamplingAllocationTracker() {
    return samplingAllocationTracker_;
  }
#endif

                               
        
                                                                          
                                    
  HeapSnapshot::NodeID getObjectID(const GCCell *cell);
  HeapSnapshot::NodeID getObjectIDMustExist(const GCCell *cell);
  HeapSnapshot::NodeID getObjectID(CompressedPointer cell);
  HeapSnapshot::NodeID getObjectID(SymbolID sym);
  HeapSnapshot::NodeID getNativeID(const void *mem);
                                                                            
                                 
  llvh::Optional<HeapSnapshot::NodeID> getSnapshotID(HermesValue val);

                                                                         
                                                        
  void *getObjectForID(HeapSnapshot::NodeID id);

                                                                  
  bool hasObjectID(const GCCell *cell);
                                                 
  void newAlloc(const GCCell *ptr, uint32_t sz);
                                                                       
  void moveObject(
      const GCCell *oldPtr,
      uint32_t oldSize,
      const GCCell *newPtr,
      uint32_t newSize);
                                                
  void untrackObject(const GCCell *cell, uint32_t sz);
        

#ifndef NDEBUG
                                                                                
                                                                                
                              
  uint64_t nextObjectID();
#endif

                                                                    
                                                                  
#if defined(UNIT_TEST) || defined(_MSC_VER)
 public:
#else
 protected:
#endif

                                                                            
                                                                                
                                                                                
                
  void checkTripwire(size_t dataSize);

                                                                     

 protected:
                                                                               
             
  class GCCycle final {
   public:
    explicit GCCycle(GCBase &gc, std::string extraInfo = "");
    ~GCCycle();

    const std::string &extraInfo() {
      return extraInfo_;
    }

   private:
    GCBase &gc_;
    std::string extraInfo_;
    bool previousInGC_;
  };

                                                                        
                                                     
                                                            
  virtual gcheapsize_t bytesAllocatedSinceLastGC() const {
    return 0;
  }

                                                                      
                                                                     
                                                                          
                                                                      
                                                                      
                                                                     
                                         
  void markRoots(RootAndSlotAcceptorWithNames &acceptor, bool markLongLived) {
    gcCallbacks_.markRoots(acceptor, markLongLived);
  }

                                                                           
                                                                     
  void markWeakRoots(WeakRootAcceptor &acceptor, bool markLongLived) {
    gcCallbacks_.markWeakRoots(acceptor, markLongLived);
    acceptor.beginRootSection(RootAcceptor::Section::WeakRefSlots);
    weakSlots_.forEach(
        [&acceptor](WeakRefSlot &slot) { slot.markWeakRoots(acceptor); });

    weakMapEntrySlots_.forEach(
        [&acceptor](WeakMapEntrySlot &slot) { slot.markWeakRoots(acceptor); });
    acceptor.endRootSection();
  }

                                      
  virtual void printStats(JSONEmitter &json);

                                                                          
                                                       
  void recordGCStats(const GCAnalyticsEvent &event, bool onMutator);

                                                                          
                                                     
  void recordGCStats(
      const GCAnalyticsEvent &event,
      CumulativeHeapStats *stats,
      bool onMutator);

                                                                             
                                                         
  void sizeDiagnosticCensus(size_t allocatedBytes);

                                                                            
                                                                      
  virtual void oomDetail(
      llvh::MutableArrayRef<char> detailBuffer,
      std::error_code reason);

  template <typename T, class... Args>
  static T *constructCell(void *ptr, uint32_t size, Args &&...args) {
    auto *cell = new (ptr) T(std::forward<Args>(args)...);
    constexpr auto kind = T::getCellKind();
    cell->setKindAndSize({kind, size});
    return cell;
  }

                                                         
  unsigned numFinalizedObjects_{0};

                                                           
  uint64_t totalAllocatedBytes_{0};

                              
  GCExecTrace execTrace_;

                                                       
#ifndef NDEBUG
                                                                                
                                                       
  unsigned numAllocatedObjects_{0};
                                                                               
                                                                          
                                                                               
                                                                               
                     
  unsigned numReachableObjects_{0};
                                                                   
                                                                 
                                                          
  unsigned numCollectedObjects_{0};
                               
  unsigned numMarkedSymbols_{0};
                                                               
  unsigned numHiddenClasses_{0};
                                                                      
  unsigned numLeafHiddenClasses_{0};

                                                                           
                                               
  uint64_t debugAllocationCounter_{0};
#endif

                                                                               
            
  GCCallbacks &gcCallbacks_;

                                                                 
  PointerBase &pointerBase_;

                                                             
  std::shared_ptr<CrashManager> crashMgr_;

  HeapKind heapKind_;

                                                                            
                                         
  std::function<void(const GCAnalyticsEvent &)> analyticsCallback_;

                                                             
  std::vector<GCAnalyticsEvent> analyticsEvents_;

                                                              
  bool recordGcStats_{false};

                                                       
  bool inGC_{false};

                                                                             
                                                                
  bool hasOOMed_{false};

                                                                    
                                                                      
                                                                 
                                                                     
                                                                     
                                                                   
  bool execStartTimeRecorded_{false};

                                                     
  std::chrono::time_point<std::chrono::steady_clock> execStartTime_;
  std::chrono::microseconds execStartCPUTime_;
                                                                         
  long startNumVoluntaryContextSwitches_{0};
  long startNumInvoluntaryContextSwitches_{0};

                             
  CumulativeHeapStats cumStats_;

                                         
  std::string name_;

                                                                           
                                                                           
                                                
  ManagedChunkedList<WeakRefSlot> weakSlots_;

                                                                                
                                                                               
                                                                               
  ManagedChunkedList<WeakMapEntrySlot> weakMapEntrySlots_;

                                                                          
                                        
  IDTracker idTracker_;

#ifdef HERMES_MEMORY_INSTRUMENTATION
                                                    
  AllocationLocationTracker allocationLocationTracker_;

                                                    
  SamplingAllocationLocationTracker samplingAllocationTracker_;
#endif

#ifndef NDEBUG
                                                                           
          
  uint32_t noAllocLevel_{0};

  friend class NoAllocScope;
#endif

#ifdef HERMESVM_SANITIZE_HANDLES
                                                                              
                                           
  bool shouldSanitizeHandles();

                                                                             
  double sanitizeRate_{1.0};

                                                  
  std::minstd_rand randomEngine_;
#else
                                                                              
                           
  static constexpr double sanitizeRate_{0.0};

  static constexpr bool shouldSanitizeHandles() {
    return false;
  }
#endif

 private:
#ifdef HERMESVM_GC_RUNTIME
                                                                              
                            
  template <typename Func>
  auto runtimeGCDispatch(Func f) {
    switch (getKind()) {
#define GC_KIND(kind)          \
  case GCBase::HeapKind::kind: \
    return f(llvh::cast<kind>(this));
      RUNTIME_GC_KINDS
#undef GC_KIND
      default:
        llvm_unreachable("No other valid GC for RuntimeGC");
    }
  }
#endif

  template <typename T, XorPtrKeyID K>
  friend class XorPtr;

                                                                  
  uintptr_t pointerEncryptionKey_[XorPtrKeyID::_NumKeys];

                                                                     
                
  std::function<void(GCTripwireContext &)> tripwireCallback_;

                                                                    
  gcheapsize_t tripwireLimit_;

                                                                
  bool tripwireCalled_{false};
};

                                                            

                                                                 
                                                     
struct DurationFormatObj {
  double secs;
};
llvh::raw_ostream &operator<<(
    llvh::raw_ostream &os,
    const DurationFormatObj &dfo);
inline DurationFormatObj formatSecs(double secs) {
  return {secs};
}

                                                                 
                                              
struct SizeFormatObj {
  uint64_t bytes;
};
llvh::raw_ostream &operator<<(llvh::raw_ostream &os, const SizeFormatObj &sfo);
inline SizeFormatObj formatSize(uint64_t size) {
  return {size};
}

}                
}                    
#pragma GCC diagnostic pop

#endif                      

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "gc"
#include "hermes/VM/GC.h"

#include "hermes/Platform/Logging.h"
#include "hermes/Public/JSOutOfMemoryError.h"
#include "hermes/Support/ErrorHandling.h"
#include "hermes/Support/OSCompat.h"
#include "hermes/VM/CellKind.h"
#include "hermes/VM/JSWeakMapImpl.h"
#include "hermes/VM/RootAndSlotAcceptorDefault.h"
#include "hermes/VM/Runtime.h"
#include "hermes/VM/SmallHermesValue-inline.h"
#include "hermes/VM/VTable.h"

#include "llvh/Support/Debug.h"
#include "llvh/Support/FileSystem.h"
#include "llvh/Support/Format.h"
#include "llvh/Support/raw_os_ostream.h"
#include "llvh/Support/raw_ostream.h"

#include <inttypes.h>
#include <clocale>
#include <stdexcept>
#include <system_error>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
using llvh::format;

namespace hermes {
namespace vm {

const char GCBase::kNaturalCauseForAnalytics[] = "natural";
const char GCBase::kHandleSanCauseForAnalytics[] = "handle-san";

GCBase::GCBase(
    GCCallbacks &gcCallbacks,
    PointerBase &pointerBase,
    const GCConfig &gcConfig,
    std::shared_ptr<CrashManager> crashMgr,
    HeapKind kind)
    : gcCallbacks_(gcCallbacks),
      pointerBase_(pointerBase),
      crashMgr_(crashMgr),
      heapKind_(kind),
      analyticsCallback_(gcConfig.getAnalyticsCallback()),
      recordGcStats_(gcConfig.getShouldRecordStats()),
                             
      inGC_(false),
      name_(gcConfig.getName()),
      weakSlots_(gcConfig.getOccupancyTarget(), 0.5                   ),
      weakMapEntrySlots_(gcConfig.getOccupancyTarget(), 0.5                   ),
#ifdef HERMES_MEMORY_INSTRUMENTATION
      allocationLocationTracker_(this),
      samplingAllocationTracker_(this),
#endif
#ifdef HERMESVM_SANITIZE_HANDLES
      sanitizeRate_(gcConfig.getSanitizeConfig().getSanitizeRate()),
#endif
      tripwireCallback_(gcConfig.getTripwireConfig().getCallback()),
      tripwireLimit_(gcConfig.getTripwireConfig().getLimit()) {
  for (unsigned i = 0; i < (unsigned)XorPtrKeyID::_NumKeys; ++i) {
    pointerEncryptionKey_[i] = std::random_device()();
    if constexpr (sizeof(uintptr_t) >= 8) {
                                                                     
      pointerEncryptionKey_[i] =
          (pointerEncryptionKey_[i] << 32) | std::random_device()();
    }
  }
  buildMetadataTable();
#ifdef HERMESVM_PLATFORM_LOGGING
  hermesLog(
      "HermesGC",
      "Initialisation (Init: %dMB, Max: %dMB, Tripwire: %dMB)",
      gcConfig.getInitHeapSize() >> 20,
      gcConfig.getMaxHeapSize() >> 20,
      gcConfig.getTripwireConfig().getLimit() >> 20);
#endif                             
#ifdef HERMESVM_SANITIZE_HANDLES
  const std::minstd_rand::result_type seed =
      gcConfig.getSanitizeConfig().getRandomSeed() >= 0
      ? gcConfig.getSanitizeConfig().getRandomSeed()
      : std::random_device()();
  if (sanitizeRate_ > 0.0 && sanitizeRate_ < 1.0) {
    llvh::errs()
        << "Warning: you are using handle sanitization with random sampling.\n"
        << "Sanitize Rate: ";
    llvh::write_double(llvh::errs(), sanitizeRate_, llvh::FloatStyle::Percent);
    llvh::errs() << "\n"
                 << "Sanitize Rate Seed: " << seed << "\n"
                 << "Re-run with -gc-sanitize-handles-random-seed=" << seed
                 << " for deterministic crashes.\n";
  }
  randomEngine_.seed(seed);
#endif
}

GCBase::GCCycle::GCCycle(GCBase &gc, std::string extraInfo)
    : gc_(gc), extraInfo_(std::move(extraInfo)), previousInGC_(gc_.inGC_) {
  if (!previousInGC_) {
    gc_.getCallbacks().onGCEvent(GCEventKind::CollectionStart, extraInfo_);
    gc_.inGC_ = true;
  }
}

GCBase::GCCycle::~GCCycle() {
  if (!previousInGC_) {
    gc_.inGC_ = false;
    gc_.getCallbacks().onGCEvent(GCEventKind::CollectionEnd, extraInfo_);
  }
}

void GCBase::runtimeWillExecute() {
  if (recordGcStats_ && !execStartTimeRecorded_) {
    execStartTime_ = std::chrono::steady_clock::now();
    execStartCPUTime_ = oscompat::thread_cpu_time();
    oscompat::num_context_switches(
        startNumVoluntaryContextSwitches_, startNumInvoluntaryContextSwitches_);
    execStartTimeRecorded_ = true;
  }
}

#ifdef HERMES_MEMORY_INSTRUMENTATION
std::error_code GCBase::createSnapshotToFile(const std::string &fileName) {
  std::error_code code;
  llvh::raw_fd_ostream os(fileName, code, llvh::sys::fs::FileAccess::FA_Write);
  if (code) {
    return code;
  }
  createSnapshot(os, true);
  return std::error_code{};
}

namespace {

constexpr HeapSnapshot::NodeID objectIDForRootSection(
    RootAcceptor::Section section) {
                                                                          
                                                                     
                    
  return GCBase::IDTracker::reserved(
      static_cast<GCBase::IDTracker::ReservedObjectID>(
          static_cast<HeapSnapshot::NodeID>(
              GCBase::IDTracker::ReservedObjectID::GCRoots) +
          1 + static_cast<HeapSnapshot::NodeID>(section)));
}

                                                  
struct SnapshotAcceptor : public RootAndSlotAcceptorWithNamesDefault {
  using RootAndSlotAcceptorWithNamesDefault::accept;

  SnapshotAcceptor(PointerBase &base, HeapSnapshot &snap)
      : RootAndSlotAcceptorWithNamesDefault(base), snap_(snap) {}

  void acceptHV(HermesValue &hv, const char *name) override {
    if (hv.isPointer()) {
      GCCell *ptr = static_cast<GCCell *>(hv.getPointer());
      accept(ptr, name);
    }
  }
  void acceptSHV(SmallHermesValue &hv, const char *name) override {
    if (hv.isPointer()) {
      GCCell *ptr = static_cast<GCCell *>(hv.getPointer(pointerBase_));
      accept(ptr, name);
    }
  }

 protected:
  HeapSnapshot &snap_;
};

struct PrimitiveNodeAcceptor : public SnapshotAcceptor {
  using SnapshotAcceptor::accept;

  PrimitiveNodeAcceptor(
      PointerBase &base,
      HeapSnapshot &snap,
      GCBase::IDTracker &tracker)
      : SnapshotAcceptor(base, snap), tracker_(tracker) {}

                                              
  void accept(GCCell *&ptr, const char *name) override {}

  void acceptHV(HermesValue &hv, const char *) override {
    if (tracker_.isTrackingNumberIDs() && hv.isNumber()) {
      seenNumbers_.insert(hv.getNumber());
    }
  }

  void acceptSHV(SmallHermesValue &hv, const char *) override {
    if (tracker_.isTrackingNumberIDs() && hv.isNumber()) {
      seenNumbers_.insert(hv.getNumber(pointerBase_));
    }
  }

  void writeAllNodes() {
                                                 
    snap_.beginNode();
    snap_.endNode(
        HeapSnapshot::NodeType::Object,
        "undefined",
        GCBase::IDTracker::reserved(
            GCBase::IDTracker::ReservedObjectID::Undefined),
        0,
        0);
    snap_.beginNode();
    snap_.endNode(
        HeapSnapshot::NodeType::Object,
        "null",
        GCBase::IDTracker::reserved(GCBase::IDTracker::ReservedObjectID::Null),
        0,
        0);
    snap_.beginNode();
    snap_.endNode(
        HeapSnapshot::NodeType::Object,
        "true",
        GCBase::IDTracker::reserved(GCBase::IDTracker::ReservedObjectID::True),
        0,
        0);
    snap_.beginNode();
    snap_.endNode(
        HeapSnapshot::NodeType::Object,
        "false",
        GCBase::IDTracker::reserved(GCBase::IDTracker::ReservedObjectID::False),
        0,
        0);
    if (tracker_.isTrackingNumberIDs()) {
      for (double num : seenNumbers_) {
                                                                    
        snap_.beginNode();
                                                                               
                    
        char buf[hermes::NUMBER_TO_STRING_BUF_SIZE];
        size_t len = hermes::numberToString(num, buf, sizeof(buf));
        snap_.endNode(
            HeapSnapshot::NodeType::Number,
            llvh::StringRef{buf, len},
            tracker_.getNumberID(num),
                                                                                
            0,
            0);
      }
    } else {
      snap_.beginNode();
      snap_.endNode(
          HeapSnapshot::NodeType::Object,
          "number",
          GCBase::IDTracker::reserved(
              GCBase::IDTracker::ReservedObjectID::Number),
          0,
          0);
    }
  }

 private:
  GCBase::IDTracker &tracker_;
                                                                               
                  
  llvh::DenseSet<double, GCBase::IDTracker::DoubleComparator> seenNumbers_;
};

struct EdgeAddingAcceptor : public SnapshotAcceptor {
  using SnapshotAcceptor::accept;

  EdgeAddingAcceptor(GCBase &gc, HeapSnapshot &snap)
      : SnapshotAcceptor(gc.getPointerBase(), snap), gc_(gc) {}

  void accept(GCCell *&ptr, const char *name) override {
    if (!ptr) {
      return;
    }
    snap_.addNamedEdge(
        HeapSnapshot::EdgeType::Internal,
        llvh::StringRef::withNullAsEmpty(name),
        gc_.getObjectID(ptr));
  }

  void acceptHV(HermesValue &hv, const char *name) override {
    if (auto id = gc_.getSnapshotID(hv)) {
      snap_.addNamedEdge(
          HeapSnapshot::EdgeType::Internal,
          llvh::StringRef::withNullAsEmpty(name),
          id.getValue());
    }
  }

  void acceptSHV(SmallHermesValue &shv, const char *name) override {
    HermesValue hv = shv.toHV(pointerBase_);
    acceptHV(hv, name);
  }

  void acceptSym(SymbolID sym, const char *name) override {
    if (sym.isInvalid()) {
      return;
    }
    snap_.addNamedEdge(
        HeapSnapshot::EdgeType::Internal,
        llvh::StringRef::withNullAsEmpty(name),
        gc_.getObjectID(sym));
  }

 private:
  GCBase &gc_;
};

struct SnapshotRootSectionAcceptor : public SnapshotAcceptor,
                                     public WeakAcceptorDefault {
  using SnapshotAcceptor::accept;
  using WeakRootAcceptor::acceptWeak;

  SnapshotRootSectionAcceptor(PointerBase &base, HeapSnapshot &snap)
      : SnapshotAcceptor(base, snap), WeakAcceptorDefault(base) {}

  void accept(GCCell *&, const char *) override {
                                                                              
                
  }

  void acceptWeak(GCCell *&ptr) override {
                                   
  }

  void beginRootSection(Section section) override {
                                                                     
    snap_.addIndexedEdge(
        HeapSnapshot::EdgeType::Element,
        rootSectionNum_++,
        objectIDForRootSection(section));
  }

  void endRootSection() override {
                                                  
  }

 private:
                                     
  int rootSectionNum_{1};
};

struct SnapshotRootAcceptor : public SnapshotAcceptor,
                              public WeakAcceptorDefault {
  using SnapshotAcceptor::accept;
  using WeakRootAcceptor::acceptWeak;

  SnapshotRootAcceptor(
      GCBase &gc,
      HeapSnapshot &snap,
      GCBase::SavedNumRootEdges &numRootEdges)
      : SnapshotAcceptor(gc.getPointerBase(), snap),
        WeakAcceptorDefault(gc.getPointerBase()),
        gc_(gc),
        numRootEdges_(numRootEdges) {}

  void accept(GCCell *&ptr, const char *name) override {
    pointerAccept(ptr, name, false);
  }

  void acceptWeak(GCCell *&ptr) override {
    pointerAccept(ptr, nullptr, true);
  }

  void acceptSym(SymbolID sym, const char *name) override {
    if (sym.isInvalid()) {
      return;
    }
    auto nameRef = llvh::StringRef::withNullAsEmpty(name);
    const auto id = gc_.getObjectID(sym);
    if (!nameRef.empty()) {
      snap_.addNamedEdge(HeapSnapshot::EdgeType::Internal, nameRef, id);
    } else {
                                   
      snap_.addIndexedEdge(HeapSnapshot::EdgeType::Element, nextEdge_++, id);
    }
  }

  void provideSnapshot(
      const std::function<void(HeapSnapshot &)> &func) override {
    func(snap_);
  }

  void beginRootSection(Section section) override {
    assert(
        currentSection_ == Section::InvalidSection &&
        "beginRootSection called while previous section is open");
    snap_.beginNode();
    currentSection_ = section;
  }

  void endRootSection() override {
                                                                             
                           
    static const char *rootNames[] = {
                                                          
#define ROOT_SECTION(name) "(" #name ")",
#include "hermes/VM/RootSections.def"
    };

                                                                              
    auto sectionIdx = static_cast<unsigned>(currentSection_);
    if (!numRootEdges_[sectionIdx].hasValue()) {
      numRootEdges_[sectionIdx] = snap_.getCurEdgeCount();
    } else {
                                                                               
                                                                              
                                                                             
                          
      auto savedEdgeCount = numRootEdges_[sectionIdx].getValue();
      assert(
          savedEdgeCount >= snap_.getCurEdgeCount() &&
          "Unexpected new edges added");
      const auto id = GCBase::IDTracker::reserved(
          GCBase::IDTracker::ReservedObjectID::Undefined);
      for (auto i = snap_.getCurEdgeCount(); i < savedEdgeCount; ++i) {
        snap_.addIndexedEdge(HeapSnapshot::EdgeType::Element, nextEdge_++, id);
      }
    }

    snap_.endNode(
        HeapSnapshot::NodeType::Synthetic,
        rootNames[static_cast<unsigned>(currentSection_)],
        objectIDForRootSection(currentSection_),
                                                                                
                                                          
        0,
        0);
    currentSection_ = Section::InvalidSection;
                                                                            
            
    nextEdge_ = 0;
  }

 private:
  GCBase &gc_;
  llvh::DenseSet<HeapSnapshot::NodeID> seenIDs_;
                                             
  unsigned nextEdge_{0};
  Section currentSection_{Section::InvalidSection};
                                            
  GCBase::SavedNumRootEdges &numRootEdges_;

  void pointerAccept(GCCell *ptr, const char *name, bool weak) {
    assert(
        currentSection_ != Section::InvalidSection &&
        "accept called outside of begin/end root section pair");
    if (!ptr) {
      return;
    }

    const auto id = gc_.getObjectID(ptr);
    if (!seenIDs_.insert(id).second) {
                                                        
      return;
    }
    auto nameRef = llvh::StringRef::withNullAsEmpty(name);
    if (!nameRef.empty()) {
      snap_.addNamedEdge(
          weak ? HeapSnapshot::EdgeType::Weak
               : HeapSnapshot::EdgeType::Internal,
          nameRef,
          id);
    } else if (weak) {
      std::string numericName = std::to_string(nextEdge_++);
      snap_.addNamedEdge(HeapSnapshot::EdgeType::Weak, numericName.c_str(), id);
    } else {
                                   
      snap_.addIndexedEdge(HeapSnapshot::EdgeType::Element, nextEdge_++, id);
    }
  }
};

}             

void GCBase::createSnapshotImpl(
    GC &gc,
    HeapSnapshot &snap,
    SavedNumRootEdges &numRootEdges) {
  const auto rootScan = [&gc, &snap, &numRootEdges, this]() {
    {
                                                                     
      SnapshotRootSectionAcceptor rootSectionAcceptor(getPointerBase(), snap);
                                                                         
                                                                             
                                                                       
      snap.beginNode();
      snap.addIndexedEdge(
          HeapSnapshot::EdgeType::Element,
          1,
          IDTracker::reserved(IDTracker::ReservedObjectID::GCRoots));
      snap.endNode(
          HeapSnapshot::NodeType::Synthetic,
          "",
          IDTracker::reserved(IDTracker::ReservedObjectID::SuperRoot),
          0,
          0);
      snapshotAddGCNativeNodes(snap);
      snap.beginNode();
      markRoots(rootSectionAcceptor, true);
      markWeakRoots(rootSectionAcceptor,                   true);
      snapshotAddGCNativeEdges(snap);
      snap.endNode(
          HeapSnapshot::NodeType::Synthetic,
          "(GC roots)",
          static_cast<HeapSnapshot::NodeID>(
              IDTracker::reserved(IDTracker::ReservedObjectID::GCRoots)),
          0,
          0);
    }
    {
                                                                              
                                                                            
                                                                               
                                             
      SnapshotRootAcceptor rootAcceptor(gc, snap, numRootEdges);
      markRoots(rootAcceptor, true);
      markWeakRoots(rootAcceptor,                   true);
    }
    gcCallbacks_.visitIdentifiers([&snap, this](
                                      SymbolID sym,
                                      const StringPrimitive *str) {
      snap.beginNode();
      if (str) {
        snap.addNamedEdge(
            HeapSnapshot::EdgeType::Internal, "description", getObjectID(str));
      }
      snap.endNode(
          HeapSnapshot::NodeType::Symbol,
          convertSymbolToUTF8(sym),
          idTracker_.getObjectID(sym),
          sizeof(SymbolID),
          0);
    });
  };

  snap.beginSection(HeapSnapshot::Section::Nodes);
  rootScan();
                                                                    
                                                                        
                                                                                
                               
                                                                               
              
  PrimitiveNodeAcceptor primitiveAcceptor(
      getPointerBase(), snap, getIDTracker());
  SlotVisitorWithNames<PrimitiveNodeAcceptor> primitiveVisitor{
      primitiveAcceptor};
                                            
  const auto snapshotForObject =
      [&snap, &primitiveVisitor, &gc, this](GCCell *cell) {
        auto &allocationLocationTracker = getAllocationLocationTracker();
                                     
        markCellWithNames(primitiveVisitor, cell);
        EdgeAddingAcceptor acceptor(gc, snap);
        SlotVisitorWithNames<EdgeAddingAcceptor> visitor(acceptor);
                                                             
        cell->getVT()->snapshotMetaData.addNodes(cell, gc, snap);
        snap.beginNode();
                                        
        markCellWithNames(visitor, cell);
                                                                       
        cell->getVT()->snapshotMetaData.addEdges(cell, gc, snap);
        auto stackTracesTreeNode =
            allocationLocationTracker.getStackTracesTreeNodeForAlloc(
                gc.getObjectID(cell));
        snap.endNode(
            cell->getVT()->snapshotMetaData.nodeType(),
            cell->getVT()->snapshotMetaData.nameForNode(cell, gc),
            gc.getObjectID(cell),
            cell->getAllocatedSize(),
            stackTracesTreeNode ? stackTracesTreeNode->id : 0);
      };
  gc.forAllObjs(snapshotForObject);
                                                                       
                                         
  weakMapEntrySlots_.forEach([&primitiveAcceptor](WeakMapEntrySlot &slot) {
    primitiveAcceptor.accept(slot.mappedValue);
  });
                                                        
  primitiveAcceptor.writeAllNodes();
  snap.endSection(HeapSnapshot::Section::Nodes);

  snap.beginSection(HeapSnapshot::Section::Edges);
  rootScan();
                                                                               
                                           
  gc.forAllObjs(snapshotForObject);
  snap.endSection(HeapSnapshot::Section::Edges);

  snap.emitAllocationTraceInfo();

  snap.beginSection(HeapSnapshot::Section::Samples);
  getAllocationLocationTracker().addSamplesToSnapshot(snap);
  snap.endSection(HeapSnapshot::Section::Samples);

  snap.beginSection(HeapSnapshot::Section::Locations);
  forAllObjs([&snap, &gc](GCCell *cell) {
    cell->getVT()->snapshotMetaData.addLocations(cell, gc, snap);
  });
  snap.endSection(HeapSnapshot::Section::Locations);
}

void GCBase::createSnapshot(
    GC &gc,
    llvh::raw_ostream &os,
    bool captureNumericValue) {
  if (!captureNumericValue) {
    idTracker_.stopTrackingNumberIDs();
  }
                                                                            
                                                                               
                                                                                
                                                                             
                                                                             
                                                               
  JSONEmitter dummyJSON{llvh::nulls()};
  HeapSnapshot dummySnap{dummyJSON, 0, 0, 0, gcCallbacks_.getStackTracesTree()};
                                                                           
                                                                                
                                                          
  SavedNumRootEdges numRootEdges;
  createSnapshotImpl(gc, dummySnap, numRootEdges);

                                                                             
                
  JSONEmitter json{os};
  HeapSnapshot snap{
      json,
      dummySnap.getNodeCount(),
      dummySnap.getEdgeCount(),
      dummySnap.getTraceFunctionCount(),
      gcCallbacks_.getStackTracesTree()};
  createSnapshotImpl(gc, snap, numRootEdges);
                                                               
  assert(
      dummySnap.getNodeCount() == snap.getNodeCount() &&
      "Node count of two passes of createSnapshotImpl are not equal");
  assert(
      dummySnap.getEdgeCount() == snap.getEdgeCount() &&
      "Edge count of two passes of createSnapshotImpl are not equal");
  idTracker_.startTrackingNumberIDs();
}

void GCBase::snapshotAddGCNativeNodes(HeapSnapshot &snap) {
  snap.beginNode();
  snap.endNode(
      HeapSnapshot::NodeType::Native,
      "hermes::ManagedChunkedList<WeakRefSlot>",
      IDTracker::reserved(IDTracker::ReservedObjectID::WeakRefSlotStorage),
      weakSlots_.capacity() * sizeof(decltype(weakSlots_)::value_type),
      0);
}

void GCBase::snapshotAddGCNativeEdges(HeapSnapshot &snap) {
  snap.addNamedEdge(
      HeapSnapshot::EdgeType::Internal,
      "weakRefSlots",
      IDTracker::reserved(IDTracker::ReservedObjectID::WeakRefSlotStorage));
}

void GCBase::enableHeapProfiler(
    std::function<void(
        uint64_t,
        std::chrono::microseconds,
        std::vector<GCBase::AllocationLocationTracker::HeapStatsUpdate>)>
        fragmentCallback) {
  getAllocationLocationTracker().enable(std::move(fragmentCallback));
}

void GCBase::disableHeapProfiler() {
  getAllocationLocationTracker().disable();
}

void GCBase::enableSamplingHeapProfiler(size_t samplingInterval, int64_t seed) {
  getSamplingAllocationTracker().enable(samplingInterval, seed);
}

void GCBase::disableSamplingHeapProfiler(llvh::raw_ostream &os) {
  getSamplingAllocationTracker().disable(os);
}
#endif                                 

void GCBase::checkTripwire(size_t dataSize) {
  if (LLVM_LIKELY(!tripwireCallback_) ||
      LLVM_LIKELY(dataSize < tripwireLimit_) || tripwireCalled_) {
    return;
  }

#ifdef HERMES_MEMORY_INSTRUMENTATION
  class Ctx : public GCTripwireContext {
   public:
    Ctx(GCBase *gc) : gc_(gc) {}

    std::error_code createSnapshotToFile(const std::string &path) override {
      return gc_->createSnapshotToFile(path);
    }

    std::error_code createSnapshot(std::ostream &os, bool captureNumericValue)
        override {
      llvh::raw_os_ostream ros(os);
      gc_->createSnapshot(ros, captureNumericValue);
      return std::error_code{};
    }

   private:
    GCBase *gc_;
  } ctx(this);
#else                                           
  class Ctx : public GCTripwireContext {
   public:
    std::error_code createSnapshotToFile(const std::string &path) override {
      return std::error_code(ENOSYS, std::system_category());
    }

    std::error_code createSnapshot(std::ostream &os, bool captureNumericValue)
        override {
      return std::error_code(ENOSYS, std::system_category());
    }
  } ctx;
#endif                                           

  tripwireCalled_ = true;
  tripwireCallback_(ctx);
}

void GCBase::printAllCollectedStats(llvh::raw_ostream &os) {
  if (!recordGcStats_)
    return;

  dump(os);
  os << "GC stats:\n";
  JSONEmitter json{os,            true};
  json.openDict();
  printStats(json);
  json.closeDict();
  os << "\n";
}

void GCBase::getHeapInfo(HeapInfo &info) {
  info.numCollections = cumStats_.numCollections;
  info.generalStats = cumStats_;
}

void GCBase::getHeapInfoWithMallocSize(HeapInfo &info) {
                                                              
  info.mallocSizeEstimate =
      weakSlots_.capacity() * sizeof(decltype(weakSlots_)::value_type);
}

#ifndef NDEBUG
void GCBase::getDebugHeapInfo(DebugHeapInfo &info) {
  recordNumAllocatedObjects();
  info.numAllocatedObjects = numAllocatedObjects_;
  info.numReachableObjects = numReachableObjects_;
  info.numCollectedObjects = numCollectedObjects_;
  info.numFinalizedObjects = numFinalizedObjects_;
  info.numMarkedSymbols = numMarkedSymbols_;
  info.numHiddenClasses = numHiddenClasses_;
  info.numLeafHiddenClasses = numLeafHiddenClasses_;
}

size_t GCBase::countUsedWeakRefs() const {
  return weakSlots_.sizeForTests();
}
#endif

#ifndef NDEBUG
void GCBase::DebugHeapInfo::assertInvariants() const {
                                                                       
                                            
  assert(numAllocatedObjects >= numReachableObjects);
                                                                          
                                 
  assert(numCollectedObjects >= numFinalizedObjects);
}
#endif

void GCBase::dump(llvh::raw_ostream &, bool) {           }

void GCBase::printStats(JSONEmitter &json) {
  json.emitKeyValue("type", "hermes");
  json.emitKeyValue("version", 0);
  gcCallbacks_.printRuntimeGCStats(json);

  std::chrono::duration<double> elapsedTime =
      std::chrono::steady_clock::now() - execStartTime_;
  auto elapsedCPUSeconds =
      std::chrono::duration_cast<std::chrono::duration<double>>(
          oscompat::thread_cpu_time())
          .count() -
      std::chrono::duration_cast<std::chrono::duration<double>>(
          execStartCPUTime_)
          .count();

  HeapInfo info;
  getHeapInfoWithMallocSize(info);
  getHeapInfo(info);
#ifndef NDEBUG
  DebugHeapInfo debugInfo;
  getDebugHeapInfo(debugInfo);
#endif

  json.emitKey("heapInfo");
  json.openDict();
#ifndef NDEBUG
  json.emitKeyValue("Num allocated cells", debugInfo.numAllocatedObjects);
  json.emitKeyValue("Num reachable cells", debugInfo.numReachableObjects);
  json.emitKeyValue("Num collected cells", debugInfo.numCollectedObjects);
  json.emitKeyValue("Num finalized cells", debugInfo.numFinalizedObjects);
  json.emitKeyValue("Num marked symbols", debugInfo.numMarkedSymbols);
  json.emitKeyValue("Num hidden classes", debugInfo.numHiddenClasses);
  json.emitKeyValue("Num leaf classes", debugInfo.numLeafHiddenClasses);
  json.emitKeyValue("Num weak references", ((GC *)this)->countUsedWeakRefs());
#endif
  json.emitKeyValue("Peak RSS", oscompat::peak_rss());
  json.emitKeyValue("Current RSS", oscompat::current_rss());
  json.emitKeyValue("Current Dirty", oscompat::current_private_dirty());
  json.emitKeyValue("Heap size", info.heapSize);
  json.emitKeyValue("Allocated bytes", info.allocatedBytes);
  json.emitKeyValue("Num collections", info.numCollections);
  json.emitKeyValue("Malloc size", info.mallocSizeEstimate);
  json.closeDict();

  long vol = -1;
  long invol = -1;
  if (oscompat::num_context_switches(vol, invol)) {
    vol -= startNumVoluntaryContextSwitches_;
    invol -= startNumInvoluntaryContextSwitches_;
  }

  json.emitKey("general");
  json.openDict();
  json.emitKeyValue("numCollections", cumStats_.numCollections);
  json.emitKeyValue("totalTime", elapsedTime.count());
  json.emitKeyValue("totalCPUTime", elapsedCPUSeconds);
  json.emitKeyValue("totalGCTime", formatSecs(cumStats_.gcWallTime.sum()).secs);
  json.emitKeyValue("volCtxSwitch", vol);
  json.emitKeyValue("involCtxSwitch", invol);
  json.emitKeyValue(
      "avgGCPause", formatSecs(cumStats_.gcWallTime.average()).secs);
  json.emitKeyValue("maxGCPause", formatSecs(cumStats_.gcWallTime.max()).secs);
  json.emitKeyValue(
      "totalGCCPUTime", formatSecs(cumStats_.gcCPUTime.sum()).secs);
  json.emitKeyValue(
      "avgGCCPUPause", formatSecs(cumStats_.gcCPUTime.average()).secs);
  json.emitKeyValue(
      "maxGCCPUPause", formatSecs(cumStats_.gcCPUTime.max()).secs);
  json.emitKeyValue("finalHeapSize", formatSize(cumStats_.finalHeapSize).bytes);
  json.emitKeyValue(
      "peakAllocatedBytes", formatSize(getPeakAllocatedBytes()).bytes);
  json.emitKeyValue("peakLiveAfterGC", formatSize(getPeakLiveAfterGC()).bytes);
  json.emitKeyValue(
      "totalAllocatedBytes", formatSize(info.totalAllocatedBytes).bytes);
  json.closeDict();

  json.emitKey("collections");
  json.openArray();
  for (const auto &event : analyticsEvents_) {
    json.openDict();
    json.emitKeyValue("runtimeDescription", event.runtimeDescription);
    json.emitKeyValue("gcKind", event.gcKind);
    json.emitKeyValue("collectionType", event.collectionType);
    json.emitKeyValue("cause", event.cause);
    json.emitKeyValue("duration", event.duration.count());
    json.emitKeyValue("cpuDuration", event.cpuDuration.count());
    json.emitKeyValue("preAllocated", event.allocated.before);
    json.emitKeyValue("postAllocated", event.allocated.after);
    json.emitKeyValue("preSize", event.size.before);
    json.emitKeyValue("postSize", event.size.after);
    json.emitKeyValue("preExternal", event.external.before);
    json.emitKeyValue("postExternal", event.external.after);
    json.emitKeyValue("survivalRatio", event.survivalRatio);
    json.emitKey("tags");
    json.openArray();
    for (const auto &tag : event.tags) {
      json.emitValue(tag);
    }
    json.closeArray();
    json.closeDict();
  }
  json.closeArray();
}

void GCBase::recordGCStats(
    const GCAnalyticsEvent &event,
    CumulativeHeapStats *stats,
    bool onMutator) {
                                                                               
                                                    
  if (onMutator)
    stats->gcWallTime.record(
        std::chrono::duration<double>(event.duration).count());
  stats->gcCPUTime.record(
      std::chrono::duration<double>(event.cpuDuration).count());
  stats->finalHeapSize = event.size.after;
  stats->usedBefore.record(event.allocated.before);
  stats->usedAfter.record(event.allocated.after);
  stats->numCollections++;
}

void GCBase::recordGCStats(const GCAnalyticsEvent &event, bool onMutator) {
  if (analyticsCallback_) {
    analyticsCallback_(event);
  }
  if (recordGcStats_) {
    analyticsEvents_.push_back(event);
  }
  recordGCStats(event, &cumStats_, onMutator);
}

void GCBase::oom(std::error_code reason) {
  hasOOMed_ = true;
  char detailBuffer[400];
  oomDetail(detailBuffer, reason);
#ifdef HERMESVM_EXCEPTION_ON_OOM
                                                                                
              
  throw JSOutOfMemoryError(
      std::string(detailBuffer) + "\ncall stack:\n" +
      gcCallbacks_.getCallStackNoAlloc());
#else
  hermesLog("HermesGC", "OOM: %s.", detailBuffer);
                                                       
  crashMgr_->setCustomData("HermesGCOOMDetailBasic", detailBuffer);
  hermes_fatal("OOM", reason);
#endif
}

void GCBase::oomDetail(
    llvh::MutableArrayRef<char> detailBuffer,
    std::error_code reason) {
  HeapInfo heapInfo;
  getHeapInfo(heapInfo);
  snprintf(
      detailBuffer.data(),
      detailBuffer.size(),
      "[%.20s] reason = %.150s (%d from category: %.50s), numCollections = %u, heapSize = %" PRIu64
      ", allocated = %" PRIu64 ", va = %" PRIu64 ", external = %" PRIu64,
      name_.c_str(),
      reason.message().c_str(),
      reason.value(),
      reason.category().name(),
      heapInfo.numCollections,
      heapInfo.heapSize,
      heapInfo.allocatedBytes,
      heapInfo.va,
      heapInfo.externalBytes);
}

#ifdef HERMESVM_SANITIZE_HANDLES
bool GCBase::shouldSanitizeHandles() {
  static std::uniform_real_distribution<> dist(0.0, 1.0);
  return dist(randomEngine_) < sanitizeRate_;
}
#endif

#ifdef HERMESVM_GC_RUNTIME

#define GCBASE_BARRIER_1(name, type1)                     \
  void GCBase::name(type1 arg1) {                         \
    runtimeGCDispatch([&](auto *gc) { gc->name(arg1); }); \
  }

#define GCBASE_BARRIER_2(name, type1, type2)                    \
  void GCBase::name(type1 arg1, type2 arg2) {                   \
    runtimeGCDispatch([&](auto *gc) { gc->name(arg1, arg2); }); \
  }

GCBASE_BARRIER_2(writeBarrier, const GCHermesValue *, HermesValue);
GCBASE_BARRIER_2(writeBarrier, const GCSmallHermesValue *, SmallHermesValue);
GCBASE_BARRIER_2(writeBarrier, const GCPointerBase *, const GCCell *);
GCBASE_BARRIER_2(constructorWriteBarrier, const GCHermesValue *, HermesValue);
GCBASE_BARRIER_2(
    constructorWriteBarrier,
    const GCSmallHermesValue *,
    SmallHermesValue);
GCBASE_BARRIER_2(
    constructorWriteBarrier,
    const GCPointerBase *,
    const GCCell *);
GCBASE_BARRIER_2(writeBarrierRange, const GCHermesValue *, uint32_t);
GCBASE_BARRIER_2(writeBarrierRange, const GCSmallHermesValue *, uint32_t);
GCBASE_BARRIER_2(constructorWriteBarrierRange, const GCHermesValue *, uint32_t);
GCBASE_BARRIER_2(
    constructorWriteBarrierRange,
    const GCSmallHermesValue *,
    uint32_t);
GCBASE_BARRIER_1(snapshotWriteBarrier, const GCHermesValue *);
GCBASE_BARRIER_1(snapshotWriteBarrier, const GCSmallHermesValue *);
GCBASE_BARRIER_1(snapshotWriteBarrier, const GCPointerBase *);
GCBASE_BARRIER_1(snapshotWriteBarrier, const GCSymbolID *);
GCBASE_BARRIER_2(snapshotWriteBarrierRange, const GCHermesValue *, uint32_t);
GCBASE_BARRIER_2(
    snapshotWriteBarrierRange,
    const GCSmallHermesValue *,
    uint32_t);
GCBASE_BARRIER_1(weakRefReadBarrier, HermesValue);
GCBASE_BARRIER_1(weakRefReadBarrier, GCCell *);

#undef GCBASE_BARRIER_1
#undef GCBASE_BARRIER_2
#endif

WeakRefSlot *GCBase::allocWeakSlot(CompressedPointer ptr) {
  return &weakSlots_.add(ptr);
}

WeakMapEntrySlot *GCBase::allocWeakMapEntrySlot(
    JSObject *key,
    HermesValue value,
    JSWeakMapImplBase *owner) {
  return &weakMapEntrySlots_.add(
      CompressedPointer::encode(key, getPointerBase()),
      value,
      CompressedPointer::encode(owner, getPointerBase()));
}

HeapSnapshot::NodeID GCBase::getObjectID(const GCCell *cell) {
  assert(cell && "Called getObjectID on a null pointer");
  return getObjectID(
      CompressedPointer::encodeNonNull(
          const_cast<GCCell *>(cell), pointerBase_));
}

HeapSnapshot::NodeID GCBase::getObjectIDMustExist(const GCCell *cell) {
  assert(cell && "Called getObjectID on a null pointer");
  return idTracker_.getObjectIDMustExist(
      CompressedPointer::encodeNonNull(
          const_cast<GCCell *>(cell), pointerBase_));
}

HeapSnapshot::NodeID GCBase::getObjectID(CompressedPointer cell) {
  assert(cell && "Called getObjectID on a null pointer");
  return idTracker_.getObjectID(cell);
}

HeapSnapshot::NodeID GCBase::getObjectID(SymbolID sym) {
  return idTracker_.getObjectID(sym);
}

HeapSnapshot::NodeID GCBase::getNativeID(const void *mem) {
  assert(mem && "Called getNativeID on a null pointer");
  return idTracker_.getNativeID(mem);
}

bool GCBase::hasObjectID(const GCCell *cell) {
  assert(cell && "Called hasObjectID on a null pointer");
  return idTracker_.hasObjectID(
      CompressedPointer::encodeNonNull(
          const_cast<GCCell *>(cell), pointerBase_));
}

void GCBase::newAlloc(const GCCell *ptr, uint32_t sz) {
#ifdef HERMES_MEMORY_INSTRUMENTATION
  allocationLocationTracker_.newAlloc(ptr, sz);
  samplingAllocationTracker_.newAlloc(ptr, sz);
#endif
}

void GCBase::moveObject(
    const GCCell *oldPtr,
    uint32_t oldSize,
    const GCCell *newPtr,
    uint32_t newSize) {
  idTracker_.moveObject(
      CompressedPointer::encodeNonNull(
          const_cast<GCCell *>(oldPtr), pointerBase_),
      CompressedPointer::encodeNonNull(
          const_cast<GCCell *>(newPtr), pointerBase_));
#ifdef HERMES_MEMORY_INSTRUMENTATION
                                                          
  allocationLocationTracker_.updateSize(newPtr, oldSize, newSize);
  samplingAllocationTracker_.updateSize(newPtr, oldSize, newSize);
#endif
}

void GCBase::untrackObject(const GCCell *cell, uint32_t sz) {
  assert(cell && "Called untrackObject on a null pointer");
                                                                      
                          
#ifdef HERMES_MEMORY_INSTRUMENTATION
  getAllocationLocationTracker().freeAlloc(cell, sz);
  getSamplingAllocationTracker().freeAlloc(cell, sz);
#endif
  idTracker_.untrackObject(
      CompressedPointer::encodeNonNull(
          const_cast<GCCell *>(cell), pointerBase_));
}

#ifndef NDEBUG
uint64_t GCBase::nextObjectID() {
  return debugAllocationCounter_++;
}
#endif

const GCExecTrace &GCBase::getGCExecTrace() const {
  return execTrace_;
}

llvh::raw_ostream &operator<<(
    llvh::raw_ostream &os,
    const DurationFormatObj &dfo) {
  if (dfo.secs >= 1.0) {
    os << format("%5.3f", dfo.secs) << " s";
  } else if (dfo.secs >= 0.001) {
    os << format("%5.3f", dfo.secs * 1000.0) << " ms";
  } else {
    os << format("%5.3f", dfo.secs * 1000000.0) << " us";
  }
  return os;
}

llvh::raw_ostream &operator<<(llvh::raw_ostream &os, const SizeFormatObj &sfo) {
  double dblsize = static_cast<double>(sfo.bytes);
  if (sfo.bytes >= (1024 * 1024 * 1024)) {
    double gbs = dblsize / (1024.0 * 1024.0 * 1024.0);
    os << format("%0.3f GiB", gbs);
  } else if (sfo.bytes >= (1024 * 1024)) {
    double mbs = dblsize / (1024.0 * 1024.0);
    os << format("%0.3f MiB", mbs);
  } else if (sfo.bytes >= 1024) {
    double kbs = dblsize / 1024.0;
    os << format("%0.3f KiB", kbs);
  } else {
    os << sfo.bytes << " B";
  }
  return os;
}

GCBase::GCCallbacks::~GCCallbacks() {}

GCBase::IDTracker::IDTracker() {
  assert(lastID_ % 2 == 1 && "First JS object ID isn't odd");
}

void GCBase::IDTracker::moveObject(
    CompressedPointer oldLocation,
    CompressedPointer newLocation) {
  if (oldLocation == newLocation) {
                                                                              
                                                                            
    return;
  }
  std::lock_guard<Mutex> lk{mtx_};
  auto old = objectIDMap_.find(oldLocation.getRaw());
  if (old == objectIDMap_.end()) {
                                                                       
    return;
  }
  const auto oldID = old->second;
  assert(
      objectIDMap_.count(newLocation.getRaw()) == 0 &&
      "Moving to a location that is already tracked");
                                                                               
  objectIDMap_.erase(old);
  objectIDMap_[newLocation.getRaw()] = oldID;
                                               
  auto reverseMappingIt = idObjectMap_.find(oldID);
  if (reverseMappingIt != idObjectMap_.end()) {
    assert(
        reverseMappingIt->second == oldLocation.getRaw() &&
        "The reverse mapping should have the old address");
    reverseMappingIt->second = newLocation.getRaw();
  }
}

llvh::SmallVector<HeapSnapshot::NodeID, 1> &
GCBase::IDTracker::getExtraNativeIDs(HeapSnapshot::NodeID node) {
  std::lock_guard<Mutex> lk{mtx_};
                                                                               
           
  return extraNativeIDs_[node];
}

HeapSnapshot::NodeID GCBase::IDTracker::getNumberID(double num) {
  std::lock_guard<Mutex> lk{mtx_};
  if (isTrackingNumberIDs_) {
    auto &numberRef = numberIDMap_[num];
                                                                 
    if (numberRef != 0) {
      return numberRef;
    }
                                                         
    return numberRef = nextNumberID();
  } else {
    return GCBase::IDTracker::reserved(
        GCBase::IDTracker::ReservedObjectID::Number);
  }
}

llvh::Optional<CompressedPointer> GCBase::IDTracker::getObjectForID(
    HeapSnapshot::NodeID id) {
  std::lock_guard<Mutex> lk{mtx_};
  auto it = idObjectMap_.find(id);
  if (it != idObjectMap_.end()) {
    return CompressedPointer::fromRaw(it->second);
  }
                                                              
                                                                 
  for (const auto &p : objectIDMap_) {
    if (p.second == id) {
                                                       
                                                                              
                                                     
      auto itAndDidInsert = idObjectMap_.try_emplace(p.second, p.first);
      assert(itAndDidInsert.second);
      return CompressedPointer::fromRaw(itAndDidInsert.first->second);
    }
  }
                                                             
  return llvh::None;
}

bool GCBase::IDTracker::hasNativeIDs() {
  std::lock_guard<Mutex> lk{mtx_};
  return !nativeIDMap_.empty();
}

bool GCBase::IDTracker::hasTrackedObjectIDs() {
  std::lock_guard<Mutex> lk{mtx_};
  return !objectIDMap_.empty();
}

bool GCBase::IDTracker::isTrackingNumberIDs() {
  std::lock_guard<Mutex> lk{mtx_};
  return isTrackingNumberIDs_;
}

void GCBase::IDTracker::startTrackingNumberIDs() {
  std::lock_guard<Mutex> lk{mtx_};
  isTrackingNumberIDs_ = true;
}

void GCBase::IDTracker::stopTrackingNumberIDs() {
  std::lock_guard<Mutex> lk{mtx_};
  isTrackingNumberIDs_ = false;
}

HeapSnapshot::NodeID GCBase::IDTracker::getObjectID(CompressedPointer cell) {
  std::lock_guard<Mutex> lk{mtx_};
  auto iter = objectIDMap_.find(cell.getRaw());
  if (iter != objectIDMap_.end()) {
    return iter->second;
  }
                                                                                
  const auto objID = nextObjectID();
  objectIDMap_[cell.getRaw()] = objID;
  return objID;
}

bool GCBase::IDTracker::hasObjectID(CompressedPointer cell) {
  std::lock_guard<Mutex> lk{mtx_};
  return objectIDMap_.count(cell.getRaw());
}

HeapSnapshot::NodeID GCBase::IDTracker::getObjectIDMustExist(
    CompressedPointer cell) {
  std::lock_guard<Mutex> lk{mtx_};
  auto iter = objectIDMap_.find(cell.getRaw());
  assert(iter != objectIDMap_.end() && "cell must already have an ID");
  return iter->second;
}

HeapSnapshot::NodeID GCBase::IDTracker::getObjectID(SymbolID sym) {
  std::lock_guard<Mutex> lk{mtx_};
  auto iter = symbolIDMap_.find(sym.unsafeGetIndex());
  if (iter != symbolIDMap_.end()) {
    return iter->second;
  }
                                                                               
  const auto symID = nextObjectID();
  symbolIDMap_[sym.unsafeGetIndex()] = symID;
  return symID;
}

HeapSnapshot::NodeID GCBase::IDTracker::getNativeID(const void *mem) {
  std::lock_guard<Mutex> lk{mtx_};
  auto iter = nativeIDMap_.find(mem);
  if (iter != nativeIDMap_.end()) {
    return iter->second;
  }
                                                                             
                      
  const auto objID = nextNativeID();
  nativeIDMap_[mem] = objID;
  return objID;
}

void GCBase::IDTracker::untrackObject(CompressedPointer cell) {
  std::lock_guard<Mutex> lk{mtx_};
                                                                                
                                                                         
  const auto id = objectIDMap_[cell.getRaw()];
  objectIDMap_.erase(cell.getRaw());
  extraNativeIDs_.erase(id);
                                                  
  idObjectMap_.erase(id);
}

void GCBase::IDTracker::untrackNative(const void *mem) {
  std::lock_guard<Mutex> lk{mtx_};
  nativeIDMap_.erase(mem);
}

void GCBase::IDTracker::untrackSymbol(uint32_t symIdx) {
  std::lock_guard<Mutex> lk{mtx_};
  symbolIDMap_.erase(symIdx);
}

HeapSnapshot::NodeID GCBase::IDTracker::lastID() const {
  return lastID_;
}

HeapSnapshot::NodeID GCBase::IDTracker::nextObjectID() {
                                                                               
  if (LLVM_UNLIKELY(
          lastID_ >=
          std::numeric_limits<HeapSnapshot::NodeID>::max() - kIDStep)) {
    hermes_fatal("Ran out of object IDs");
  }
  return lastID_ += kIDStep;
}

HeapSnapshot::NodeID GCBase::IDTracker::nextNativeID() {
                                                                     
                                                                               
  HeapSnapshot::NodeID id = nextObjectID();
  assert(id > 0 && "nextObjectID should check for overflow");
  return id - 1;
}

HeapSnapshot::NodeID GCBase::IDTracker::nextNumberID() {
                                                                 
  return nextObjectID();
}

#ifdef HERMES_MEMORY_INSTRUMENTATION

GCBase::AllocationLocationTracker::AllocationLocationTracker(GCBase *gc)
    : gc_(gc) {}

bool GCBase::AllocationLocationTracker::isEnabled() const {
  return enabled_;
}

StackTracesTreeNode *
GCBase::AllocationLocationTracker::getStackTracesTreeNodeForAlloc(
    HeapSnapshot::NodeID id) const {
  auto mapIt = stackMap_.find(id);
  return mapIt == stackMap_.end() ? nullptr : mapIt->second;
}

void GCBase::AllocationLocationTracker::enable(
    std::function<
        void(uint64_t, std::chrono::microseconds, std::vector<HeapStatsUpdate>)>
        callback) {
  assert(!enabled_ && "Shouldn't enable twice");
  enabled_ = true;
  std::lock_guard<Mutex> lk{mtx_};
                                                                              
                                                                               
                                                                               
                                         
  uint64_t numObjects = 0;
  uint64_t numBytes = 0;
  gc_->forAllObjs([&numObjects, &numBytes, this](GCCell *cell) {
    numObjects++;
    numBytes += cell->getAllocatedSize();
    gc_->getObjectID(cell);
  });
  fragmentCallback_ = std::move(callback);
  startTime_ = std::chrono::steady_clock::now();
  fragments_.clear();
                                                                              
             
                                                               
  fragments_.emplace_back(
      Fragment{
          IDTracker::kInvalidNode,
          std::chrono::microseconds(),
          numObjects,
          numBytes,
                                                                  
                                            
          true});
                                          
  flushCallback();
}

void GCBase::AllocationLocationTracker::disable() {
  std::lock_guard<Mutex> lk{mtx_};
  flushCallback();
  enabled_ = false;
  fragmentCallback_ = nullptr;
}

void GCBase::AllocationLocationTracker::newAlloc(
    const GCCell *ptr,
    uint32_t sz) {
                                                                         
                                                                            
                                                                      
                       
  const auto *ip = gc_->gcCallbacks_.getCurrentIPSlow();
  if (!enabled_) {
    return;
  }
  std::lock_guard<Mutex> lk{mtx_};
                                                                   
  const auto id = gc_->getObjectID(ptr);
  HERMES_SLOW_ASSERT(
      &findFragmentForID(id) == &fragments_.back() &&
      "Should only ever be allocating into the newest fragment");
  Fragment &lastFrag = fragments_.back();
  assert(
      lastFrag.lastSeenObjectID_ == IDTracker::kInvalidNode &&
      "Last fragment should not have an ID assigned yet");
  lastFrag.numObjects_++;
  lastFrag.numBytes_ += sz;
  lastFrag.touchedSinceLastFlush_ = true;
  if (lastFrag.numBytes_ >= kFlushThreshold) {
    flushCallback();
  }
  if (auto node = gc_->gcCallbacks_.getCurrentStackTracesTreeNode(ip)) {
    auto itAndDidInsert = stackMap_.try_emplace(id, node);
    assert(itAndDidInsert.second && "Failed to create a new node");
    (void)itAndDidInsert;
  }
}

void GCBase::AllocationLocationTracker::updateSize(
    const GCCell *ptr,
    uint32_t oldSize,
    uint32_t newSize) {
  int32_t delta = static_cast<int32_t>(newSize) - static_cast<int32_t>(oldSize);
  if (!delta || !enabled_) {
                         
    return;
  }
  std::lock_guard<Mutex> lk{mtx_};
  const auto id = gc_->getObjectIDMustExist(ptr);
  Fragment &frag = findFragmentForID(id);
  frag.numBytes_ += delta;
  frag.touchedSinceLastFlush_ = true;
}

void GCBase::AllocationLocationTracker::freeAlloc(
    const GCCell *ptr,
    uint32_t sz) {
  if (!enabled_) {
                                                                
    return;
  }
                                                                               
                                       
  std::lock_guard<Mutex> lk{mtx_};
                                                                               
                                                                     
  const auto id = gc_->getObjectIDMustExist(ptr);
  stackMap_.erase(id);
  Fragment &frag = findFragmentForID(id);
  assert(
      frag.numObjects_ >= 1 && "Num objects decremented too much for fragment");
  frag.numObjects_--;
  assert(frag.numBytes_ >= sz && "Num bytes decremented too much for fragment");
  frag.numBytes_ -= sz;
  frag.touchedSinceLastFlush_ = true;
}

GCBase::AllocationLocationTracker::Fragment &
GCBase::AllocationLocationTracker::findFragmentForID(HeapSnapshot::NodeID id) {
  assert(fragments_.size() >= 1 && "Must have at least one fragment available");
  for (auto it = fragments_.begin(); it != fragments_.end() - 1; ++it) {
    if (it->lastSeenObjectID_ >= id) {
      return *it;
    }
  }
                                                                       
  return fragments_.back();
}

void GCBase::AllocationLocationTracker::flushCallback() {
  Fragment &lastFrag = fragments_.back();
  const auto lastID = gc_->getIDTracker().lastID();
  const auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - startTime_);
  assert(
      lastFrag.lastSeenObjectID_ == IDTracker::kInvalidNode &&
      "Last fragment should not have an ID assigned yet");
                                                                               
              
  if (lastFrag.touchedSinceLastFlush_) {
    lastFrag.lastSeenObjectID_ = lastID;
    lastFrag.timestamp_ = duration;
                                                              
    fragments_.emplace_back(
        Fragment{
            IDTracker::kInvalidNode, std::chrono::microseconds(), 0, 0, false});
  }
  if (fragmentCallback_) {
    std::vector<HeapStatsUpdate> updatedFragments;
                                                                         
                      
    for (size_t i = 0; i < fragments_.size() - 1; ++i) {
      auto &fragment = fragments_[i];
      if (fragment.touchedSinceLastFlush_) {
        updatedFragments.emplace_back(
            i, fragment.numObjects_, fragment.numBytes_);
        fragment.touchedSinceLastFlush_ = false;
      }
    }
    fragmentCallback_(lastID, duration, std::move(updatedFragments));
  }
}

void GCBase::AllocationLocationTracker::addSamplesToSnapshot(
    HeapSnapshot &snap) {
  std::lock_guard<Mutex> lk{mtx_};
  if (enabled_) {
    flushCallback();
  }
                                                                              
                                         
  assert(
      (fragments_.empty() ||
       fragments_.back().lastSeenObjectID_ == IDTracker::kInvalidNode) &&
      "Last fragment should not have an ID assigned yet");
                                                                          
  for (size_t i = 0, e = fragments_.size(); i + 1 < e; ++i) {
    const auto &fragment = fragments_[i];
    snap.addSample(fragment.timestamp_, fragment.lastSeenObjectID_);
  }
}

void GCBase::SamplingAllocationLocationTracker::enable(
    size_t samplingInterval,
    int64_t seed) {
  if (seed < 0) {
    seed = std::random_device()();
  }
  randomEngine_.seed(seed);
  dist_ = llvh::make_unique<std::poisson_distribution<>>(samplingInterval);
  limit_ = nextSample();
}

void GCBase::SamplingAllocationLocationTracker::disable(llvh::raw_ostream &os) {
  JSONEmitter json{os};
  ChromeSamplingMemoryProfile profile{json};
  std::lock_guard<Mutex> lk{mtx_};
                                                           
  llvh::DenseMap<StackTracesTreeNode *, llvh::DenseMap<size_t, size_t>>
      sizesToCounts;
                                            
  for (const auto &s : samples_) {
    const Sample &sample = s.second;
    sizesToCounts[sample.node][sample.size]++;
  }

                                                                          
                                     
  profile.emitTree(gc_->gcCallbacks_.getStackTracesTree(), sizesToCounts);
  profile.beginSamples();
  for (const auto &s : samples_) {
    const Sample &sample = s.second;
    profile.emitSample(sample.size, sample.node, sample.id);
  }
  profile.endSamples();
  dist_.reset();
  samples_.clear();
  limit_ = 0;
}

void GCBase::SamplingAllocationLocationTracker::newAlloc(
    const GCCell *ptr,
    uint32_t sz) {
                                                                       
  if (!isEnabled()) {
    return;
  }
  if (sz <= limit_) {
                                              
    limit_ -= sz;
    return;
  }
  const auto *ip = gc_->gcCallbacks_.getCurrentIPSlow();
                                                                   
  const auto id = gc_->getObjectID(ptr);
  if (StackTracesTreeNode *node =
          gc_->gcCallbacks_.getCurrentStackTracesTreeNode(ip)) {
                                            
    std::lock_guard<Mutex> lk{mtx_};
    auto sampleItAndDidInsert =
        samples_.try_emplace(id, Sample{sz, node, nextSampleID_++});
    assert(sampleItAndDidInsert.second && "Failed to create a sample");
    (void)sampleItAndDidInsert;
  }
                     
  limit_ = nextSample();
}

void GCBase::SamplingAllocationLocationTracker::freeAlloc(
    const GCCell *ptr,
    uint32_t sz) {
                                                                       
  if (!isEnabled()) {
    return;
  }
  if (!gc_->hasObjectID(ptr)) {
                                                  
    return;
  }
  const auto id = gc_->getObjectIDMustExist(ptr);
                                          
  std::lock_guard<Mutex> lk{mtx_};
  samples_.erase(id);
}

void GCBase::SamplingAllocationLocationTracker::updateSize(
    const GCCell *ptr,
    uint32_t oldSize,
    uint32_t newSize) {
  int32_t delta = static_cast<int32_t>(newSize) - static_cast<int32_t>(oldSize);
  if (!delta || !isEnabled() || !gc_->hasObjectID(ptr)) {
                         
    return;
  }
  const auto id = gc_->getObjectIDMustExist(ptr);
                                          
  std::lock_guard<Mutex> lk{mtx_};
  const auto it = samples_.find(id);
  if (it == samples_.end()) {
    return;
  }
  Sample &sample = it->second;
                                          
  sample.size = newSize;
}

size_t GCBase::SamplingAllocationLocationTracker::nextSample() {
  return (*dist_)(randomEngine_);
}
#endif                                 

llvh::Optional<HeapSnapshot::NodeID> GCBase::getSnapshotID(HermesValue val) {
  if (val.isPointer() && val.getPointer()) {
                                                    
                                                                             
    return val.getPointer()
        ? getObjectID(static_cast<GCCell *>(val.getPointer()))
        : IDTracker::reserved(IDTracker::ReservedObjectID::Null);
  } else if (val.isNumber()) {
    return idTracker_.getNumberID(val.getNumber());
  } else if (val.isSymbol() && val.getSymbol().isValid()) {
    return idTracker_.getObjectID(val.getSymbol());
  } else if (val.isUndefined()) {
    return IDTracker::reserved(IDTracker::ReservedObjectID::Undefined);
  } else if (val.isNull()) {
    return static_cast<HeapSnapshot::NodeID>(
        IDTracker::reserved(IDTracker::ReservedObjectID::Null));
  } else if (val.isBool()) {
    return static_cast<HeapSnapshot::NodeID>(
        val.getBool()
            ? IDTracker::reserved(IDTracker::ReservedObjectID::True)
            : IDTracker::reserved(IDTracker::ReservedObjectID::False));
  } else {
    return llvh::None;
  }
}

void *GCBase::getObjectForID(HeapSnapshot::NodeID id) {
  if (llvh::Optional<CompressedPointer> ptr = idTracker_.getObjectForID(id)) {
    return ptr->get(pointerBase_);
  }
  return nullptr;
}

void GCBase::sizeDiagnosticCensus(size_t allocatedBytes) {
  struct DiagnosticStat {
    uint64_t count{0};
    uint64_t size{0};
    std::map<std::string, DiagnosticStat> breakdown;

    static constexpr double getPercent(double numer, double denom) {
      return denom != 0 ? 100 * numer / denom : 0.0;
    }
    void printBreakdown(size_t depth) const {
      if (breakdown.empty())
        return;

      static const char *fmtBase =
          "%-25s : %'10" PRIu64 " [%'10" PRIu64 " B | %4.1f%%]";
      const std::string fmtStr = std::string(depth, '\t') + fmtBase;
      size_t totalSize = 0;
      size_t totalCount = 0;
      for (const auto &stat : breakdown) {
        hermesLog(
            "HermesGC",
            fmtStr.c_str(),
            stat.first.c_str(),
            stat.second.count,
            stat.second.size,
            getPercent(stat.second.size, size));
        stat.second.printBreakdown(depth + 1);
        totalSize += stat.second.size;
        totalCount += stat.second.count;
      }
      if (size_t other = size - totalSize)
        hermesLog(
            "HermesGC",
            fmtStr.c_str(),
            "Other",
            count - totalCount,
            other,
            getPercent(other, size));
    }
  };

  struct HeapSizeDiagnostic {
    uint64_t numCell = 0;
    uint64_t numVariableSizedObject = 0;
    DiagnosticStat stats;

    void rootsDiagnosticFrame() const {
                                                  
      char *currentLocale = std::setlocale(LC_NUMERIC, nullptr);
      std::setlocale(LC_NUMERIC, "");
      hermesLog("HermesGC", "Root size: %'7" PRIu64 " B", stats.size);
      stats.printBreakdown(1);
      std::setlocale(LC_NUMERIC, currentLocale);
    }

    void sizeDiagnosticFrame() const {
                                                  
      char *currentLocale = std::setlocale(LC_NUMERIC, nullptr);
      std::setlocale(LC_NUMERIC, "");

      hermesLog("HermesGC", "Heap size: %'7" PRIu64 " B", stats.size);
      hermesLog("HermesGC", "\tTotal cells: %'7" PRIu64, numCell);
      hermesLog(
          "HermesGC",
          "\tNum variable size cells: %'7" PRIu64,
          numVariableSizedObject);

      stats.printBreakdown(1);

      std::setlocale(LC_NUMERIC, currentLocale);
    }
  };

  struct HeapSizeDiagnosticAcceptor final : public RootAndSlotAcceptor {
                                        
    const int64_t HINT8_MIN = -(1 << 7);
    const int64_t HINT8_MAX = (1 << 7) - 1;
    const int64_t HINT16_MIN = -(1 << 15);
    const int64_t HINT16_MAX = (1 << 15) - 1;
    const int64_t HINT24_MIN = -(1 << 23);
    const int64_t HINT24_MAX = (1 << 23) - 1;
    const int64_t HINT32_MIN = -(1LL << 31);
    const int64_t HINT32_MAX = (1LL << 31) - 1;

    HeapSizeDiagnostic diagnostic;
    PointerBase &pointerBase_;

    HeapSizeDiagnosticAcceptor(PointerBase &pb) : pointerBase_{pb} {}

    using SlotAcceptor::accept;

    void accept(GCCell *&ptr) override {
      diagnostic.stats.breakdown["Pointer"].count++;
      diagnostic.stats.breakdown["Pointer"].size += sizeof(GCCell *);
    }

    void accept(GCPointerBase &ptr) override {
      diagnostic.stats.breakdown["GCPointer"].count++;
      diagnostic.stats.breakdown["GCPointer"].size += sizeof(GCPointerBase);
    }

    void accept(PinnedHermesValue &hv) override {
      acceptNullable(hv);
    }
    void acceptNullable(PinnedHermesValue &hv) override {
      acceptHV(
          hv,
          diagnostic.stats.breakdown["HermesValue"],
          sizeof(PinnedHermesValue));
    }
    void accept(GCHermesValue &hv) override {
      acceptHV(
          hv, diagnostic.stats.breakdown["HermesValue"], sizeof(GCHermesValue));
    }
    void accept(GCSmallHermesValue &shv) override {
      acceptHV(
          shv.toHV(pointerBase_),
          diagnostic.stats.breakdown["SmallHermesValue"],
          sizeof(GCSmallHermesValue));
    }
    void acceptHV(
        const HermesValue &hv,
        DiagnosticStat &diag,
        const size_t hvBytes) {
      diag.count++;
      diag.size += hvBytes;
      llvh::StringRef hvType;
      if (hv.isBool()) {
        hvType = "Bool";
      } else if (hv.isNumber()) {
        hvType = "Number";
        double val = hv.getNumber();
        double intpart;
        llvh::StringRef numType = "Doubles";
        if (std::modf(val, &intpart) == 0.0) {
          if (val >= static_cast<double>(HINT8_MIN) &&
              val <= static_cast<double>(HINT8_MAX)) {
            numType = "Int8";
          } else if (
              val >= static_cast<double>(HINT16_MIN) &&
              val <= static_cast<double>(HINT16_MAX)) {
            numType = "Int16";
          } else if (
              val >= static_cast<double>(HINT24_MIN) &&
              val <= static_cast<double>(HINT24_MAX)) {
            numType = "Int24";
          } else if (
              val >= static_cast<double>(HINT32_MIN) &&
              val <= static_cast<double>(HINT32_MAX)) {
            numType = "Int32";
          }
        }
        diag.breakdown["Number"].breakdown[numType].count++;
        diag.breakdown["Number"].breakdown[numType].size += hvBytes;
      } else if (hv.isString()) {
        hvType = "StringPointer";
      } else if (hv.isSymbol()) {
        hvType = "Symbol";
      } else if (hv.isObject()) {
        hvType = "ObjectPointer";
      } else if (hv.isNull()) {
        hvType = "Null";
      } else if (hv.isUndefined()) {
        hvType = "Undefined";
      } else if (hv.isEmpty()) {
        hvType = "Empty";
      } else if (hv.isNativeValue()) {
        hvType = "NativeValue";
      } else {
        assert(false && "Should be no other hermes values");
      }
      diag.breakdown[hvType].count++;
      diag.breakdown[hvType].size += hvBytes;
    }

    void accept(const RootSymbolID &sym) override {
      acceptSym(sym);
    }
    void accept(const GCSymbolID &sym) override {
      acceptSym(sym);
    }
    void acceptSym(SymbolID sym) {
      diagnostic.stats.breakdown["Symbol"].count++;
      diagnostic.stats.breakdown["Symbol"].size += sizeof(SymbolID);
    }
  };

  hermesLog("HermesGC", "%s:", "Roots");
  HeapSizeDiagnosticAcceptor rootAcceptor{getPointerBase()};
  DroppingAcceptor<HeapSizeDiagnosticAcceptor> namedRootAcceptor{rootAcceptor};
  markRoots(namedRootAcceptor,                     true);
                                                                       
  for (const auto &substat : rootAcceptor.diagnostic.stats.breakdown) {
    rootAcceptor.diagnostic.stats.count += substat.second.count;
    rootAcceptor.diagnostic.stats.size += substat.second.size;
  }
  rootAcceptor.diagnostic.rootsDiagnosticFrame();

  hermesLog("HermesGC", "%s:", "Heap contents");
  HeapSizeDiagnosticAcceptor acceptor{getPointerBase()};
  forAllObjs([&acceptor, this](GCCell *cell) {
    markCell(cell, acceptor);
    acceptor.diagnostic.numCell++;
    if (cell->isVariableSize()) {
      acceptor.diagnostic.numVariableSizedObject++;
                                                                                
                                                                         
                          
      acceptor.diagnostic.stats.breakdown["Cell headers"].size +=
          (sizeof(GCCell) + sizeof(uint32_t));
    } else {
      acceptor.diagnostic.stats.breakdown["Cell headers"].size +=
          sizeof(GCCell);
    }

                                                                           
                                                         
                                                                       
                                                          
    auto *strprim = dyn_vmcast<StringPrimitive>(cell);
    if (strprim && !isBufferedStringPrimitive(cell)) {
      auto &stat = strprim->isASCII()
          ? acceptor.diagnostic.stats.breakdown["StringPrimitive (ASCII)"]
          : acceptor.diagnostic.stats.breakdown["StringPrimitive (UTF-16)"];
      stat.count++;
      const size_t len = strprim->getStringLength();
                                                                      
                    
      const size_t sz = strprim->isASCII() ? len : len * 2;
      stat.size += sz;
      if (len < 8) {
        auto &subStat =
            stat.breakdown
                ["StringPrimitive (size " + std::to_string(len) + ")"];
        subStat.count++;
        subStat.size += sz;
      }
    }
  });

  assert(
      acceptor.diagnostic.stats.size == 0 &&
      acceptor.diagnostic.stats.count == 0 &&
      "Should not be setting overall stats during heap scan.");
  for (const auto &substat : acceptor.diagnostic.stats.breakdown)
    acceptor.diagnostic.stats.count += substat.second.count;
  acceptor.diagnostic.stats.size = allocatedBytes;
  acceptor.diagnostic.sizeDiagnosticFrame();
}

}                
}                    

#undef DEBUG_TYPE

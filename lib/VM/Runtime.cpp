/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Support/StackOverflowGuard.h"
#define DEBUG_TYPE "vm"
#include "hermes/VM/Runtime.h"

#include "hermes/AST/SemValidate.h"
#include "hermes/BCGen/HBC/BytecodeDataProvider.h"
#include "hermes/BCGen/HBC/BytecodeProviderFromSrc.h"
#include "hermes/BCGen/HBC/SimpleBytecodeBuilder.h"
#include "hermes/FrontEndDefs/Builtins.h"
#include "hermes/InternalBytecode/InternalBytecode.h"
#include "hermes/Platform/Logging.h"
#include "hermes/Support/OSCompat.h"
#include "hermes/Support/PerfSection.h"
#include "hermes/VM/AlignedStorage.h"
#include "hermes/VM/BuildMetadata.h"
#include "hermes/VM/Callable.h"
#include "hermes/VM/CodeBlock.h"
#include "hermes/VM/Domain.h"
#include "hermes/VM/FillerCell.h"
#include "hermes/VM/HeapRuntime.h"
#include "hermes/VM/IdentifierTable.h"
#include "hermes/VM/JSArray.h"
#include "hermes/VM/JSError.h"
#include "hermes/VM/JSLib.h"
#include "hermes/VM/JSLib/JSLibStorage.h"
#include "hermes/VM/Operations.h"
#include "hermes/VM/OrderedHashMap.h"
#include "hermes/VM/PredefinedStringIDs.h"
#include "hermes/VM/Profiler/CodeCoverageProfiler.h"
#include "hermes/VM/Profiler/SamplingProfiler.h"
#include "hermes/VM/StackFrame-inline.h"
#include "hermes/VM/StackTracesTree.h"
#include "hermes/VM/StringView.h"

#ifndef HERMESVM_LEAN
#include "hermes/Support/MemoryBuffer.h"
#endif

#include "llvh/ADT/Hashing.h"
#include "llvh/ADT/ScopeExit.h"
#include "llvh/Support/Debug.h"
#include "llvh/Support/raw_ostream.h"

#ifdef HERMESVM_PROFILER_BB
#include "hermes/VM/IterationKind.h"
#include "hermes/VM/JSArray.h"
#include "hermes/VM/Profiler/InlineCacheProfiler.h"
#include "llvh/ADT/DenseMap.h"
#endif

#include <future>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif

#ifdef __EMSCRIPTEN__
                                                                                
                                                                             
                                                                   
__attribute__((__weak__)) extern "C" bool test_wasm_host_timeout() {
  return false;
}
__attribute__((__weak__)) extern "C" bool test_and_clear_wasm_host_timeout() {
  return false;
}
#endif

namespace hermes {
namespace vm {

namespace {

                                                                             
static constexpr uint32_t kMaxSupportedNumRegisters =
    UINT32_MAX / sizeof(PinnedHermesValue);

#ifdef HERMES_CHECK_NATIVE_STACK
                                                     
static constexpr uint32_t kMinSupportedNativeStackGap =
#if LLVM_ADDRESS_SANITIZER_BUILD
    256 * 1024;
#else
    64 * 1024;
#endif
#endif

                                                                 
                                            
static constexpr size_t MIN_IO_TRACKING_SIZE = 64 * 1024;

static const Predefined::Str fixedPropCacheNames[(size_t)PropCacheID::_COUNT] =
    {
#define V(id, predef) predef,
        PROP_CACHE_IDS(V)
#undef V
};

}             

                                                                     
                                                                      
                                                                     
                                                                    
                    
class Runtime::StackRuntime {
 public:
  StackRuntime(const vm::RuntimeConfig &runtimeConfig)
      : thread_(runtimeMemoryThread, this) {
    startup_.get_future().get();
    new (runtime_) Runtime(StorageProvider::mmapProvider(), runtimeConfig);
  }

  ~StackRuntime() {
    runtime_->~Runtime();
    shutdown_.set_value();
    thread_.join();
  }

  static std::shared_ptr<Runtime> create(const RuntimeConfig &runtimeConfig) {
    auto srt = std::make_shared<StackRuntime>(runtimeConfig);
    return std::shared_ptr<Runtime>(srt, srt->runtime_);
  }

 private:
  static void runtimeMemoryThread(StackRuntime *stack) {
    ::hermes::oscompat::set_thread_name("hermes-runtime-memorythread");
    std::aligned_storage<sizeof(Runtime)>::type rt;
    stack->runtime_ = reinterpret_cast<Runtime *>(&rt);
    stack->startup_.set_value();
    stack->shutdown_.get_future().get();
  }

                            
                          
                                  
                                       
                                           
  std::promise<void> startup_;
  std::promise<void> shutdown_;
  Runtime *runtime_{nullptr};
  std::thread thread_;
};

            
std::shared_ptr<Runtime> Runtime::create(const RuntimeConfig &runtimeConfig) {
#if defined(HERMESVM_CONTIGUOUS_HEAP)
  uint64_t maxHeapSize = runtimeConfig.getGCConfig().getMaxHeapSize();
                                                                           
  uint64_t providerSize =
      std::min<uint64_t>(1ULL << 32, maxHeapSize + AlignedStorage::size() * 4);
  std::shared_ptr<StorageProvider> sp =
      StorageProvider::contiguousVAProvider(providerSize);
  auto rt = HeapRuntime<Runtime>::create(sp);
  new (rt.get()) Runtime(std::move(sp), runtimeConfig);
  return rt;
#elif defined(HERMES_FACEBOOK_BUILD) && !defined(HERMES_FBCODE_BUILD) && \
    !defined(__EMSCRIPTEN__)
                                                                              
  return StackRuntime::create(runtimeConfig);
#else
  return std::shared_ptr<Runtime>{
      new Runtime(StorageProvider::mmapProvider(), runtimeConfig)};
#endif
}

CallResult<PseudoHandle<>> Runtime::getNamed(
    Handle<JSObject> obj,
    PropCacheID id) {
  CompressedPointer clazzPtr{obj->getClassGCPtr()};
  auto *cacheEntry = &fixedPropCache_[static_cast<int>(id)];
  if (LLVM_LIKELY(cacheEntry->clazz == clazzPtr)) {
                                                                      
    return createPseudoHandle(
        JSObject::getNamedSlotValueUnsafe<PropStorage::Inline::Yes>(
            *obj, *this, cacheEntry->slot)
            .unboxToHV(*this));
  }
  auto sym = Predefined::getSymbolID(fixedPropCacheNames[static_cast<int>(id)]);
  NamedPropertyDescriptor desc;
                                                                               
             
  if (LLVM_LIKELY(
          JSObject::tryGetOwnNamedDescriptorFast(*obj, *this, sym, desc)) &&
      !desc.flags.accessor && desc.flags.writable &&
      !desc.flags.internalSetter) {
    HiddenClass *clazz = vmcast<HiddenClass>(clazzPtr.getNonNull(*this));
    if (LLVM_LIKELY(!clazz->isDictionary())) {
                                               
      cacheEntry->clazz = clazzPtr;
      cacheEntry->slot = desc.slot;
    }
    return JSObject::getNamedSlotValue(createPseudoHandle(*obj), *this, desc);
  }
  return JSObject::getNamed_RJS(obj, *this, sym);
}

ExecutionStatus Runtime::putNamedThrowOnError(
    Handle<JSObject> obj,
    PropCacheID id,
    SmallHermesValue shv) {
  CompressedPointer clazzPtr{obj->getClassGCPtr()};
  auto *cacheEntry = &fixedPropCache_[static_cast<int>(id)];
  if (LLVM_LIKELY(cacheEntry->clazz == clazzPtr)) {
    JSObject::setNamedSlotValueUnsafe<PropStorage::Inline::Yes>(
        *obj, *this, cacheEntry->slot, shv);
    return ExecutionStatus::RETURNED;
  }
  auto sym = Predefined::getSymbolID(fixedPropCacheNames[static_cast<int>(id)]);
  NamedPropertyDescriptor desc;
  if (LLVM_LIKELY(
          JSObject::tryGetOwnNamedDescriptorFast(*obj, *this, sym, desc)) &&
      !desc.flags.accessor && desc.flags.writable &&
      !desc.flags.internalSetter) {
    HiddenClass *clazz = vmcast<HiddenClass>(clazzPtr.getNonNull(*this));
    if (LLVM_LIKELY(!clazz->isDictionary())) {
                                           
      cacheEntry->clazz = clazzPtr;
      cacheEntry->slot = desc.slot;
    }
    JSObject::setNamedSlotValueUnsafe(*obj, *this, desc.slot, shv);
    return ExecutionStatus::RETURNED;
  }
  Handle<> value = makeHandle(shv.unboxToHV(*this));
  return JSObject::putNamed_RJS(
             obj, *this, sym, value, PropOpFlags().plusThrowOnError())
      .getStatus();
}

Runtime::Runtime(
    std::shared_ptr<StorageProvider> provider,
    const RuntimeConfig &runtimeConfig)
                                                          
    : enableEval(runtimeConfig.getEnableEval()),
      verifyEvalIR(runtimeConfig.getVerifyEvalIR()),
      optimizedEval(runtimeConfig.getOptimizedEval()),
      asyncBreakCheckInEval(runtimeConfig.getAsyncBreakCheckInEval()),
      enableBlockScopingInEval(runtimeConfig.getEnableBlockScoping()),
      traceMode(runtimeConfig.getSynthTraceMode()),
      heapStorage_(
          *this,
          *this,
          runtimeConfig.getGCConfig(),
          runtimeConfig.getCrashMgr(),
          std::move(provider),
          runtimeConfig.getVMExperimentFlags()),
      hasES6Promise_(runtimeConfig.getES6Promise()),
      hasES6Proxy_(runtimeConfig.getES6Proxy()),
      hasES6Class_(runtimeConfig.getES6Class()),
      hasIntl_(runtimeConfig.getIntl()),
      hasArrayBuffer_(runtimeConfig.getArrayBuffer()),
      hasMicrotaskQueue_(runtimeConfig.getMicrotaskQueue()),
      shouldRandomizeMemoryLayout_(runtimeConfig.getRandomizeMemoryLayout()),
      bytecodeWarmupPercent_(runtimeConfig.getBytecodeWarmupPercent()),
      trackIO_(runtimeConfig.getTrackIO()),
      vmExperimentFlags_(runtimeConfig.getVMExperimentFlags()),
      jsLibStorage_(createJSLibStorage()),
      stackPointer_(),
      crashMgr_(runtimeConfig.getCrashMgr()),
#ifdef HERMES_CHECK_NATIVE_STACK
      overflowGuard_(
          StackOverflowGuard::nativeStackGuard(
              std::max(
                  runtimeConfig.getNativeStackGap(),
                  kMinSupportedNativeStackGap))),
#else
      overflowGuard_(
          StackOverflowGuard::depthCounterGuard(
              Runtime::MAX_NATIVE_CALL_FRAME_DEPTH)),
#endif
      crashCallbackKey_(
          crashMgr_->registerCallback([this](int fd) { crashCallback(fd); })),
      codeCoverageProfiler_(std::make_unique<CodeCoverageProfiler>(*this)),
      gcEventCallback_(runtimeConfig.getGCConfig().getCallback()) {
  assert(
      (void *)this == (void *)(HandleRootOwner *)this &&
      "cast to HandleRootOwner should be no-op");
#ifdef HERMES_FACEBOOK_BUILD
  const bool isSnapshot = std::strstr(__FILE__, "hermes-snapshot");
  crashMgr_->setCustomData("HermesIsSnapshot", isSnapshot ? "true" : "false");
#endif
  crashMgr_->registerMemory(this, sizeof(Runtime));
  auto maxNumRegisters = runtimeConfig.getMaxNumRegisters();
  if (LLVM_UNLIKELY(maxNumRegisters > kMaxSupportedNumRegisters)) {
    hermes_fatal("RuntimeConfig maxNumRegisters too big");
  }
  registerStackStart_ = runtimeConfig.getRegisterStack();
  if (!registerStackStart_) {
                                                                              
                                                                
                                                        
    const uint32_t numBytesForRegisters = llvh::alignTo(
        sizeof(PinnedHermesValue) * maxNumRegisters, oscompat::page_size());
    auto result = oscompat::vm_allocate(numBytesForRegisters);
    if (!result) {
      hermes_fatal("Failed to allocate register stack", result.getError());
    }
    registerStackStart_ = static_cast<PinnedHermesValue *>(result.get());
    registerStackAllocation_ = {registerStackStart_, numBytesForRegisters};
    crashMgr_->registerMemory(registerStackStart_, numBytesForRegisters);
  }

  registerStackEnd_ = registerStackStart_ + maxNumRegisters;
  if (shouldRandomizeMemoryLayout_) {
    const unsigned bytesOff = std::random_device()() % oscompat::page_size();
    registerStackStart_ += bytesOff / sizeof(PinnedHermesValue);
    assert(
        registerStackEnd_ >= registerStackStart_ && "register stack too small");
  }
  stackPointer_ = registerStackStart_;

                                  
  setCurrentFrameToTopOfStack();
                                                         
  allocStack(
      StackFrameLayout::CalleeExtraRegistersAtStart,
      HermesValue::encodeUndefinedValue());

                                   
                                               
  initPredefinedStrings();
                                                                         
                                                                        
  RuntimeModuleFlags flags;
  flags.hidesEpilogue = true;
  specialCodeBlockDomain_ = Domain::create(*this).getHermesValue();
  specialCodeBlockRuntimeModule_ = RuntimeModule::createUninitialized(
      *this, Handle<Domain>::vmcast(&specialCodeBlockDomain_), flags);
  assert(
      &runtimeModuleList_.back() == specialCodeBlockRuntimeModule_ &&
      "specialCodeBlockRuntimeModule_ not added to runtimeModuleList_");

                                                                         

                                                    
  initCharacterStrings();

  GCScope scope(*this);

                                                                         
             
  specialCodeBlockRuntimeModule_->initializeWithoutCJSModulesMayAllocate(
      hbc::BCProviderFromBuffer::createBCProviderFromBuffer(
          generateSpecialRuntimeBytecode())
          .first);
  emptyCodeBlock_ = specialCodeBlockRuntimeModule_->getCodeBlockMayAllocate(0);
  returnThisCodeBlock_ =
      specialCodeBlockRuntimeModule_->getCodeBlockMayAllocate(1);

                                                       
  {
    MutableHandle<HiddenClass> clazz(
        *this,
        vmcast<HiddenClass>(
            ignoreAllocationFailure(HiddenClass::createRoot(*this))));
    rootClazzes_[0] = clazz.getHermesValue();
    for (unsigned i = 1; i <= InternalProperty::NumAnonymousInternalProperties;
         ++i) {
      auto addResult = HiddenClass::reserveSlot(clazz, *this);
      assert(
          addResult != ExecutionStatus::EXCEPTION &&
          "Could not possibly grow larger than the limit");
      clazz = *addResult->first;
      rootClazzes_[i] = clazz.getHermesValue();
    }
  }

  global_ =
      JSObject::create(*this, makeNullHandle<JSObject>()).getHermesValue();

  JSLibFlags jsLibFlags{};
  jsLibFlags.enableHermesInternal = runtimeConfig.getEnableHermesInternal();
  jsLibFlags.enableHermesInternalTestMethods =
      runtimeConfig.getEnableHermesInternalTestMethods();
  initGlobalObject(*this, jsLibFlags);

                                                                             
                        
  initNativeBuiltins();

                                                                             
                                
  ignoreAllocationFailure(
      JSObject::setParent(
          vmcast<JSObject>(global_),
          *this,
          vmcast<JSObject>(objectPrototype),
          PropOpFlags().plusThrowOnError()));

  symbolRegistry_.init(*this);

                                                                   
#ifdef HERMESVM_PROFILER_BB
  inlineCacheProfiler_.setHiddenClassArray(
      ignoreAllocationFailure(JSArray::create(*this, 4, 4)).get());
#endif

  codeCoverageProfiler_->disable();
                                   
  auto jsBuiltinsObj = runInternalBytecode();
  codeCoverageProfiler_->restore();

                                                                                
  initJSBuiltins(builtins_, jsBuiltinsObj);
  populateAsyncGeneratorPrototype(*this);

#if HERMESVM_SAMPLING_PROFILER_AVAILABLE
  if (runtimeConfig.getEnableSampleProfiling())
    samplingProfiler = SamplingProfiler::create(*this);
#endif                                        

  LLVM_DEBUG(llvh::dbgs() << "Runtime initialized\n");
}

Runtime::~Runtime() {
#if HERMESVM_SAMPLING_PROFILER_AVAILABLE
  samplingProfiler.reset();
#endif                                        

  getHeap().finalizeAll();
                                                                         
  for (auto &module : runtimeModuleList_) {
    module.prepareForDestruction();
  }
                                                                               
                                                    
  while (!runtimeModuleList_.empty()) {
                                                                 
    delete &runtimeModuleList_.back();
  }
                                                                             
                                                                               
                               
  assert(
      !getHeap().getIDTracker().hasNativeIDs() &&
      "A pointer is left in the ID tracker that is from non-JS memory. "
      "Was untrackNative called?");
  crashMgr_->unregisterCallback(crashCallbackKey_);
  if (!registerStackAllocation_.empty()) {
    crashMgr_->unregisterMemory(registerStackAllocation_.data());
    oscompat::vm_free(
        registerStackAllocation_.data(), registerStackAllocation_.size());
  }

  assert(
      !formattingStackTrace_ &&
      "Runtime is being destroyed while exception is being formatted");

                                                                             
                                
  if (timeLimitMonitor) {
    timeLimitMonitor->unwatchRuntime(*this);
  }

  crashMgr_->unregisterMemory(this);
}

                                                                              
                                                                        
                                
class Runtime::MarkRootsPhaseTimer {
 public:
  MarkRootsPhaseTimer(Runtime &rt, RootAcceptor::Section section)
      : rt_(rt), section_(section), start_(std::chrono::steady_clock::now()) {
    if (static_cast<unsigned>(section) == 0) {
                                                                     
      rt_.startOfMarkRoots_ = start_;
    }
  }
  ~MarkRootsPhaseTimer() {
    auto tp = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = (tp - start_);
    start_ = tp;
    unsigned index = static_cast<unsigned>(section_);
    rt_.markRootsPhaseTimes_[index] += elapsed.count();
    if (index + 1 ==
        static_cast<unsigned>(RootAcceptor::Section::NumSections)) {
      std::chrono::duration<double> totalElapsed = (tp - rt_.startOfMarkRoots_);
      rt_.totalMarkRootsTime_ += totalElapsed.count();
    }
  }

 private:
  Runtime &rt_;
  RootAcceptor::Section section_;
  std::chrono::time_point<std::chrono::steady_clock> start_;
};

void Runtime::markRoots(
    RootAndSlotAcceptorWithNames &acceptor,
    bool markLongLived) {
                                                                             
                                                                 
  {
    MarkRootsPhaseTimer timer(*this, RootAcceptor::Section::Registers);
    acceptor.beginRootSection(RootAcceptor::Section::Registers);
    for (auto *p = registerStackStart_, *e = stackPointer_; p != e; ++p)
      acceptor.accept(*p);
    acceptor.endRootSection();
  }

  {
    MarkRootsPhaseTimer timer(
        *this, RootAcceptor::Section::RuntimeInstanceVars);
    acceptor.beginRootSection(RootAcceptor::Section::RuntimeInstanceVars);
    for (auto &clazz : rootClazzes_)
      acceptor.accept(clazz, "rootClass");
#define RUNTIME_HV_FIELD_INSTANCE(name) acceptor.accept((name), #name);
#include "hermes/VM/RuntimeHermesValueFields.def"
#undef RUNTIME_HV_FIELD_INSTANCE
    acceptor.endRootSection();
  }

  {
    MarkRootsPhaseTimer timer(*this, RootAcceptor::Section::RuntimeModules);
    acceptor.beginRootSection(RootAcceptor::Section::RuntimeModules);
#define RUNTIME_HV_FIELD_RUNTIMEMODULE(name) acceptor.accept(name);
#include "hermes/VM/RuntimeHermesValueFields.def"
#undef RUNTIME_HV_FIELD_RUNTIMEMODULE
    for (auto &rm : runtimeModuleList_)
      rm.markRoots(acceptor, markLongLived);
    acceptor.endRootSection();
  }

  {
    MarkRootsPhaseTimer timer(*this, RootAcceptor::Section::CharStrings);
    acceptor.beginRootSection(RootAcceptor::Section::CharStrings);
    if (markLongLived) {
      for (auto &hv : charStrings_)
        acceptor.accept(hv);
    }
    acceptor.endRootSection();
  }

  {
    MarkRootsPhaseTimer timer(
        *this, RootAcceptor::Section::StringCycleCheckVisited);
    acceptor.beginRootSection(RootAcceptor::Section::StringCycleCheckVisited);
    for (auto *&ptr : stringCycleCheckVisited_)
      acceptor.acceptPtr(ptr);
    acceptor.endRootSection();
  }

  {
    MarkRootsPhaseTimer timer(*this, RootAcceptor::Section::Builtins);
    acceptor.beginRootSection(RootAcceptor::Section::Builtins);
    for (Callable *&f : builtins_)
      acceptor.acceptPtr(f);
    acceptor.endRootSection();
  }

  {
    MarkRootsPhaseTimer timer(*this, RootAcceptor::Section::Jobs);
    acceptor.beginRootSection(RootAcceptor::Section::Jobs);
    for (Callable *&f : jobQueue_)
      acceptor.acceptPtr(f);
    acceptor.endRootSection();
  }

#ifdef MARK
#error "Shouldn't have defined mark already"
#endif
#define MARK(field) acceptor.accept((field), #field)
  {
    MarkRootsPhaseTimer timer(*this, RootAcceptor::Section::Prototypes);
    acceptor.beginRootSection(RootAcceptor::Section::Prototypes);
                  
#define RUNTIME_HV_FIELD_PROTOTYPE(name) MARK(name);
#include "hermes/VM/RuntimeHermesValueFields.def"
#undef RUNTIME_HV_FIELD_PROTOTYPE
    acceptor.acceptPtr(objectPrototypeRawPtr, "objectPrototype");
    acceptor.acceptPtr(functionPrototypeRawPtr, "functionPrototype");
#undef MARK
    acceptor.endRootSection();
  }

  {
    MarkRootsPhaseTimer timer(*this, RootAcceptor::Section::IdentifierTable);
    if (markLongLived) {
#ifdef HERMES_MEMORY_INSTRUMENTATION
                                                                             
                 
      acceptor.provideSnapshot([this](HeapSnapshot &snap) {
        identifierTable_.snapshotAddNodes(snap);
      });
#endif
      acceptor.beginRootSection(RootAcceptor::Section::IdentifierTable);
      identifierTable_.markIdentifiers(acceptor, getHeap());
#ifdef HERMES_MEMORY_INSTRUMENTATION
      acceptor.provideSnapshot([this](HeapSnapshot &snap) {
        identifierTable_.snapshotAddEdges(snap);
      });
#endif
      acceptor.endRootSection();
    }
  }

  {
    MarkRootsPhaseTimer timer(*this, RootAcceptor::Section::GCScopes);
    acceptor.beginRootSection(RootAcceptor::Section::GCScopes);
    markGCScopes(acceptor);
    acceptor.endRootSection();
  }

  {
    MarkRootsPhaseTimer timer(*this, RootAcceptor::Section::SymbolRegistry);
    acceptor.beginRootSection(RootAcceptor::Section::SymbolRegistry);
    symbolRegistry_.markRoots(acceptor);
    acceptor.endRootSection();
  }
#if HERMESVM_SAMPLING_PROFILER_AVAILABLE
  {
    MarkRootsPhaseTimer timer(*this, RootAcceptor::Section::SamplingProfiler);
    acceptor.beginRootSection(RootAcceptor::Section::SamplingProfiler);
    if (samplingProfiler) {
      samplingProfiler->markRoots(acceptor);
    }
    acceptor.endRootSection();
  }
#endif

  {
    MarkRootsPhaseTimer timer(
        *this, RootAcceptor::Section::CodeCoverageProfiler);
    acceptor.beginRootSection(RootAcceptor::Section::CodeCoverageProfiler);
    if (codeCoverageProfiler_) {
      codeCoverageProfiler_->markRoots(acceptor);
    }
#ifdef HERMESVM_PROFILER_BB
    auto *&hiddenClassArray = inlineCacheProfiler_.getHiddenClassArray();
    if (hiddenClassArray) {
      acceptor.acceptPtr(hiddenClassArray);
    }
#endif
    acceptor.endRootSection();
  }

  {
    MarkRootsPhaseTimer timer(*this, RootAcceptor::Section::Custom);
                                                   
    for (auto &fn : customSnapshotNodeFuncs_) {
      acceptor.provideSnapshot(fn);
    }
    acceptor.beginRootSection(RootAcceptor::Section::Custom);
    for (auto &fn : customMarkRootFuncs_)
      fn(&getHeap(), acceptor);
                                                  
    for (auto &fn : customSnapshotEdgeFuncs_) {
      acceptor.provideSnapshot(fn);
    }
    acceptor.endRootSection();
  }
}

void Runtime::markWeakRoots(WeakRootAcceptor &acceptor, bool markLongLived) {
  MarkRootsPhaseTimer timer(*this, RootAcceptor::Section::WeakRefs);
  acceptor.beginRootSection(RootAcceptor::Section::WeakRefs);
                                                                                
                                                                               
  markDomainRefInRuntimeModules(acceptor);
  if (markLongLived) {
    for (auto &entry : fixedPropCache_) {
      acceptor.acceptWeak(entry.clazz);
    }
    for (auto &rm : runtimeModuleList_)
      rm.markLongLivedWeakRoots(acceptor);
  }
  for (auto &fn : customMarkWeakRootFuncs_)
    fn(&getHeap(), acceptor);
  acceptor.endRootSection();
}

void Runtime::markDomainRefInRuntimeModules(WeakRootAcceptor &acceptor) {
  std::vector<RuntimeModule *> modulesToDelete;
  for (auto &rm : runtimeModuleList_) {
    rm.markDomainRef(acceptor);
                                                                        
                         
    if (LLVM_UNLIKELY(rm.isOwningDomainDead())) {
                                                                              
                                                    
      rm.prepareForDestruction();
      modulesToDelete.push_back(&rm);
    }
  }

                                                          
                                                                    
                                                                                
                                                                              
                               
  for (auto *rm : modulesToDelete) {
                                                                 
    delete rm;
  }
}

void Runtime::markRootsForCompleteMarking(
    RootAndSlotAcceptorWithNames &acceptor) {
#if HERMESVM_SAMPLING_PROFILER_AVAILABLE
  MarkRootsPhaseTimer timer(*this, RootAcceptor::Section::SamplingProfiler);
  acceptor.beginRootSection(RootAcceptor::Section::SamplingProfiler);
  if (samplingProfiler) {
    samplingProfiler->markRootsForCompleteMarking(acceptor);
  }
#endif                                        
  acceptor.endRootSection();
}

void Runtime::visitIdentifiers(
    const std::function<void(SymbolID, const StringPrimitive *)> &acceptor) {
  identifierTable_.visitIdentifiers(acceptor);
}

std::string Runtime::convertSymbolToUTF8(SymbolID id) {
  return identifierTable_.convertSymbolToUTF8(id);
}

void Runtime::printRuntimeGCStats(JSONEmitter &json) const {
  const unsigned kNumPhases =
      static_cast<unsigned>(RootAcceptor::Section::NumSections);
#define ROOT_SECTION(phase) "MarkRoots_" #phase,
  static const char *markRootsPhaseNames[kNumPhases] = {
#include "hermes/VM/RootSections.def"
  };
#undef ROOT_SECTION
  json.emitKey("runtime");
  json.openDict();
  json.emitKeyValue("totalMarkRootsTime", formatSecs(totalMarkRootsTime_).secs);
  for (unsigned phaseNum = 0; phaseNum < kNumPhases; phaseNum++) {
    json.emitKeyValue(
        std::string(markRootsPhaseNames[phaseNum]) + "Time",
        formatSecs(markRootsPhaseTimes_[phaseNum]).secs);
  }
  json.closeDict();
}

void Runtime::printHeapStats(llvh::raw_ostream &os) {
  getHeap().printAllCollectedStats(os);
#ifndef NDEBUG
  printArrayCensus(os);
#endif
  if (trackIO_) {
    getIOTrackingInfoJSON(os);
  }
}

void Runtime::getIOTrackingInfoJSON(llvh::raw_ostream &os) {
  JSONEmitter json(os);
  json.openArray();
  for (auto &module : getRuntimeModules()) {
    auto tracker = module.getBytecode()->getPageAccessTracker();
    if (tracker) {
      json.openDict();
      json.emitKeyValue("url", module.getSourceURL());
      json.emitKey("tracking_info");
      tracker->getJSONStats(json);
      json.closeDict();
    }
  }
  json.closeArray();
}

void Runtime::removeRuntimeModule(RuntimeModule *rm) {
#ifdef HERMES_ENABLE_DEBUGGER
  debugger_.willUnloadModule(rm);
#endif
  runtimeModuleList_.remove(*rm);
}

#ifndef NDEBUG
void Runtime::printArrayCensus(llvh::raw_ostream &os) {
                                 
                                                                
                                                     
  std::map<std::pair<size_t, size_t>, std::pair<size_t, size_t>>
      arraySizeToCountAndWastedSlots;
  auto printTable = [&os](
                        const std::map<
                            std::pair<size_t, size_t>,
                            std::pair<size_t, size_t>>
                            &arraySizeToCountAndWastedSlots) {
    os << llvh::format(
        "%8s %8s %8s %10s %15s %15s %15s %20s %25s\n",
        (const char *)"Capacity",
        (const char *)"Sizeof",
        (const char *)"Count",
        (const char *)"Count %",
        (const char *)"Cum Count %",
        (const char *)"Bytes %",
        (const char *)"Cum Bytes %",
        (const char *)"Wasted Slots %",
        (const char *)"Cum Wasted Slots %");
    size_t totalBytes = 0;
    size_t totalCount = 0;
    size_t totalWastedSlots = 0;
    for (const auto &p : arraySizeToCountAndWastedSlots) {
      totalBytes += p.first.second * p.second.first;
      totalCount += p.second.first;
      totalWastedSlots += p.second.second;
    }
    size_t cumulativeBytes = 0;
    size_t cumulativeCount = 0;
    size_t cumulativeWastedSlots = 0;
    for (const auto &p : arraySizeToCountAndWastedSlots) {
      cumulativeBytes += p.first.second * p.second.first;
      cumulativeCount += p.second.first;
      cumulativeWastedSlots += p.second.second;
      os << llvh::format(
          "%8d %8d %8d %9.2f%% %14.2f%% %14.2f%% %14.2f%% %19.2f%% %24.2f%%\n",
          p.first.first,
          p.first.second,
          p.second.first,
          p.second.first * 100.0 / totalCount,
          cumulativeCount * 100.0 / totalCount,
          p.first.second * p.second.first * 100.0 / totalBytes,
          cumulativeBytes * 100.0 / totalBytes,
          totalWastedSlots ? p.second.second * 100.0 / totalWastedSlots : 100.0,
          totalWastedSlots ? cumulativeWastedSlots * 100.0 / totalWastedSlots
                           : 100.0);
    }
    os << "\n";
  };

  os << "Array Census for ArrayStorage:\n";
  getHeap().forAllObjs([&arraySizeToCountAndWastedSlots](GCCell *cell) {
    if (cell->getKind() == CellKind::ArrayStorageKind) {
      ArrayStorage *arr = vmcast<ArrayStorage>(cell);
      const auto key = std::make_pair(arr->capacity(), arr->getAllocatedSize());
      arraySizeToCountAndWastedSlots[key].first++;
      arraySizeToCountAndWastedSlots[key].second +=
          arr->capacity() - arr->size();
    }
  });
  if (arraySizeToCountAndWastedSlots.empty()) {
    os << "\tNo ArrayStorages\n\n";
  } else {
    printTable(arraySizeToCountAndWastedSlots);
  }

  os << "Array Census for SegmentedArray:\n";
  arraySizeToCountAndWastedSlots.clear();
  getHeap().forAllObjs([&arraySizeToCountAndWastedSlots, this](GCCell *cell) {
    if (cell->getKind() == CellKind::SegmentedArrayKind) {
      SegmentedArray *arr = vmcast<SegmentedArray>(cell);
      const auto key =
          std::make_pair(arr->totalCapacityOfSpine(), arr->getAllocatedSize());
      arraySizeToCountAndWastedSlots[key].first++;
      arraySizeToCountAndWastedSlots[key].second +=
          arr->totalCapacityOfSpine() - arr->size(*this);
    }
  });
  if (arraySizeToCountAndWastedSlots.empty()) {
    os << "\tNo SegmentedArrays\n\n";
  } else {
    printTable(arraySizeToCountAndWastedSlots);
  }

  os << "Array Census for Segment:\n";
  arraySizeToCountAndWastedSlots.clear();
  getHeap().forAllObjs([&arraySizeToCountAndWastedSlots](GCCell *cell) {
    if (cell->getKind() == CellKind::SegmentKind) {
      SegmentedArray::Segment *seg = vmcast<SegmentedArray::Segment>(cell);
      const auto key = std::make_pair(seg->length(), seg->getAllocatedSize());
      arraySizeToCountAndWastedSlots[key].first++;
      arraySizeToCountAndWastedSlots[key].second +=
          SegmentedArray::Segment::kMaxLength - seg->length();
    }
  });
  if (arraySizeToCountAndWastedSlots.empty()) {
    os << "\tNo Segments\n\n";
  } else {
    printTable(arraySizeToCountAndWastedSlots);
  }

  os << "Array Census for JSArray:\n";
  arraySizeToCountAndWastedSlots.clear();
  getHeap().forAllObjs([&arraySizeToCountAndWastedSlots, this](GCCell *cell) {
    if (JSArray *arr = dyn_vmcast<JSArray>(cell)) {
      JSArray::StorageType *storage = arr->getIndexedStorage(*this);
      const auto capacity = storage ? storage->totalCapacityOfSpine() : 0;
      const auto sz = storage ? storage->size(*this) : 0;
      const auto key = std::make_pair(capacity, arr->getAllocatedSize());
      arraySizeToCountAndWastedSlots[key].first++;
      arraySizeToCountAndWastedSlots[key].second += capacity - sz;
    }
  });
  if (arraySizeToCountAndWastedSlots.empty()) {
    os << "\tNo JSArrays\n\n";
  } else {
    printTable(arraySizeToCountAndWastedSlots);
  }

  os << "\n";
}
#endif

unsigned Runtime::getSymbolsEnd() const {
  return identifierTable_.getSymbolsEnd();
}

void Runtime::unmarkSymbols() {
  identifierTable_.unmarkSymbols();
}

void Runtime::freeSymbols(const llvh::BitVector &markedSymbols) {
  identifierTable_.freeUnmarkedSymbols(markedSymbols, getHeap().getIDTracker());
}

#ifdef HERMES_SLOW_DEBUG
bool Runtime::isSymbolLive(SymbolID id) {
  return identifierTable_.isSymbolLive(id);
}

const void *Runtime::getStringForSymbol(SymbolID id) {
  return identifierTable_.getStringForSymbol(id);
}
#endif

size_t Runtime::mallocSize() const {
                                                                            
                                                          
  return sizeof(IdentifierTable) + identifierTable_.additionalMemorySize();
}

#ifdef HERMESVM_SANITIZE_HANDLES
void Runtime::potentiallyMoveHeap() {
                                                                               
           
  FillerCell::create(
      *this,
      std::max<size_t>(
          heapAlignSize(sizeof(FillerCell)), GC::minAllocationSize()));
}
#endif

LLVM_ATTRIBUTE_NOINLINE
static CallResult<HermesValue> interpretFunctionWithRandomStack(
    Runtime &runtime,
    CodeBlock *globalCode) {
  static void *volatile dummy;
  const unsigned amount = std::random_device()() % oscompat::page_size();
                                                                          
  dummy = alloca(amount);
  (void)dummy;
  return runtime.interpretFunction(globalCode);
}

CallResult<HermesValue> Runtime::run(
    llvh::StringRef code,
    llvh::StringRef sourceURL,
    const hbc::CompileFlags &compileFlags) {
#ifdef HERMESVM_LEAN
  return raiseEvalUnsupported(code);
#else
  std::unique_ptr<hermes::Buffer> buffer;
  if (compileFlags.lazy) {
    buffer.reset(new hermes::OwnedMemoryBuffer(
        llvh::MemoryBuffer::getMemBufferCopy(code)));
  } else {
    buffer.reset(
        new hermes::OwnedMemoryBuffer(llvh::MemoryBuffer::getMemBuffer(code)));
  }
  return run(std::move(buffer), sourceURL, compileFlags);
#endif
}

CallResult<HermesValue> Runtime::run(
    std::unique_ptr<hermes::Buffer> code,
    llvh::StringRef sourceURL,
    const hbc::CompileFlags &compileFlags) {
#ifdef HERMESVM_LEAN
  auto buffer = code.get();
  return raiseEvalUnsupported(
      llvh::StringRef(
          reinterpret_cast<const char *>(buffer->data()), buffer->size()));
#else
  std::unique_ptr<hbc::BCProviderFromSrc> bytecode;
  {
    PerfSection loading("Loading new JavaScript code");
    loading.addArg("url", sourceURL);
    auto bytecode_err = hbc::BCProviderFromSrc::createBCProviderFromSrc(
        std::move(code), sourceURL, compileFlags);
    if (!bytecode_err.first) {
      return raiseSyntaxError(TwineChar16(bytecode_err.second));
    }
    bytecode = std::move(bytecode_err.first);
  }

  PerfSection loading("Executing global function");
  RuntimeModuleFlags rmflags;
  rmflags.persistent = true;
  return runBytecode(
      std::move(bytecode), rmflags, sourceURL, makeNullHandle<Environment>());
#endif
}

CallResult<HermesValue> Runtime::runBytecode(
    std::shared_ptr<hbc::BCProvider> &&bytecode,
    RuntimeModuleFlags flags,
    llvh::StringRef sourceURL,
    Handle<Environment> environment,
    Handle<> thisArg) {
  clearThrownValue();

  auto globalFunctionIndex = bytecode->getGlobalFunctionIndex();

  if (bytecode->getBytecodeOptions().staticBuiltins && !builtinsFrozen_) {
    if (assertBuiltinsUnmodified() == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    freezeBuiltins();
    assert(builtinsFrozen_ && "Builtins must be frozen by now.");
  }

  if (bytecode->getBytecodeOptions().hasAsync && !hasES6Promise_) {
    return raiseTypeError(
        "Cannot execute a bytecode having async functions when Promise is disabled.");
  }

  if (flags.persistent) {
    persistentBCProviders_.push_back(bytecode);
    if (bytecodeWarmupPercent_ > 0) {
                                                                    
      bytecode->startWarmup(bytecodeWarmupPercent_);
    }
    if (getVMExperimentFlags() & experiments::MAdviseRandom) {
      bytecode->madvise(oscompat::MAdvice::Random);
    } else if (getVMExperimentFlags() & experiments::MAdviseSequential) {
      bytecode->madvise(oscompat::MAdvice::Sequential);
    }
    if (getVMExperimentFlags() & experiments::VerifyBytecodeChecksum) {
      llvh::ArrayRef<uint8_t> buf = bytecode->getRawBuffer();
                                              
      if (!buf.empty()) {
        if (!hbc::BCProviderFromBuffer::bytecodeHashIsValid(buf)) {
          const char *msg = "Bytecode checksum verification failed";
          hermesLog("Hermes", "%s", msg);
          hermes_fatal(msg);
        }
      }
    }
  }
                                                                   
                                              
  if (flags.persistent && trackIO_ &&
      bytecode->getRawBuffer().size() > MIN_IO_TRACKING_SIZE) {
    bytecode->startPageAccessTracker();
    if (!bytecode->getPageAccessTracker()) {
      hermesLog(
          "Hermes",
          "Failed to start bytecode I/O instrumentation, "
          "maybe not supported on this platform.");
    }
  }

  GCScope scope(*this);

  Handle<Domain> domain = makeHandle(Domain::create(*this));

  auto runtimeModuleRes = RuntimeModule::create(
      *this, domain, nextScriptId_++, std::move(bytecode), flags, sourceURL);
  if (LLVM_UNLIKELY(runtimeModuleRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto runtimeModule = *runtimeModuleRes;
  auto globalCode = runtimeModule->getCodeBlockMayAllocate(globalFunctionIndex);

#ifdef HERMES_ENABLE_DEBUGGER
                                                                               
  getDebugger().willExecuteModule(runtimeModule, globalCode);
#endif

  if (runtimeModule->hasCJSModules()) {
    auto requireContext = RequireContext::create(
        *this, domain, getPredefinedStringHandle(Predefined::dotSlash));
    return runRequireCall(
        *this,
        requireContext,
        domain,
        *domain->getCJSModuleOffset(*this, domain->getCJSEntryModuleID()));
  } else if (runtimeModule->hasCJSModulesStatic()) {
    return runRequireCall(
        *this,
        makeNullHandle<RequireContext>(),
        domain,
        *domain->getCJSModuleOffset(*this, domain->getCJSEntryModuleID()));
  } else {
                                                                         
                                                                             
                                                                             
                          
    auto func = JSFunction::create(
        *this,
        domain,
        Handle<JSObject>::vmcast(&functionPrototype),
        environment,
        globalCode);

    ScopedNativeCallFrame newFrame{
        *this,
        0,
        func.getHermesValue(),
        HermesValue::encodeUndefinedValue(),
        *thisArg};
    if (LLVM_UNLIKELY(newFrame.overflowed()))
      return raiseStackOverflow(StackOverflowKind::NativeStack);
    return shouldRandomizeMemoryLayout_
        ? interpretFunctionWithRandomStack(*this, globalCode)
        : interpretFunction(globalCode);
  }
}

ExecutionStatus Runtime::loadSegment(
    std::shared_ptr<hbc::BCProvider> &&bytecode,
    Handle<RequireContext> requireContext,
    RuntimeModuleFlags flags) {
  GCScopeMarkerRAII marker{*this};
  auto domain = makeHandle(RequireContext::getDomain(*this, *requireContext));

  if (LLVM_UNLIKELY(
          RuntimeModule::create(
              *this, domain, nextScriptId_++, std::move(bytecode), flags, "") ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  return ExecutionStatus::RETURNED;
}

Handle<JSObject> Runtime::runInternalBytecode() {
  auto module = getInternalBytecode();
  std::pair<std::unique_ptr<hbc::BCProvider>, std::string> bcResult =
      hbc::BCProviderFromBuffer::createBCProviderFromBuffer(
          std::make_unique<Buffer>(module.data(), module.size()));
  if (LLVM_UNLIKELY(!bcResult.first)) {
    hermes_fatal((llvh::Twine("Error running internal bytecode: ") +
                  bcResult.second.c_str())
                     .str());
  }
                                                                        
  RuntimeModuleFlags flags;
  flags.persistent = true;
  flags.hidesEpilogue = true;
  auto res = runBytecode(
      std::move(bcResult.first),
      flags,
                    "InternalBytecode.js",
      makeNullHandle<Environment>());
                                                                         
  assert(
      res != ExecutionStatus::EXCEPTION && "Internal bytecode threw exception");
  assert(
      res->isObject() &&
      "Completion value of internal bytecode must be an object");

  return makeHandle<JSObject>(*res);
}

void Runtime::printException(llvh::raw_ostream &os, Handle<> valueHandle) {
  os << "Uncaught ";
  clearThrownValue();

                                  
  CallResult<PseudoHandle<>> propRes{ExecutionStatus::EXCEPTION};
  if (auto objHandle = Handle<JSObject>::dyn_vmcast(valueHandle)) {
    if (LLVM_UNLIKELY(
            (propRes = JSObject::getNamed_RJS(
                 objHandle,
                 *this,
                 Predefined::getSymbolID(Predefined::stack))) ==
            ExecutionStatus::EXCEPTION)) {
                                                                                
      bool wasFormattingStackTrace = formattingStackTrace();
      if (LLVM_LIKELY(!wasFormattingStackTrace)) {
        setFormattingStackTrace(true);
      }
      const auto &guard = llvh::make_scope_exit([=, this]() {
        if (formattingStackTrace() != wasFormattingStackTrace) {
          setFormattingStackTrace(wasFormattingStackTrace);
        }
      });
      (void)guard;

      if (LLVM_UNLIKELY(
              (propRes = JSObject::getNamed_RJS(
                   objHandle,
                   *this,
                   Predefined::getSymbolID(Predefined::stack))) ==
              ExecutionStatus::EXCEPTION)) {
        os << "exception thrown while getting stack trace\n";
        return;
      }
    }
  }
  SmallU16String<32> tmp;
  if (LLVM_UNLIKELY(
          propRes == ExecutionStatus::EXCEPTION || (*propRes)->isUndefined())) {
                                                                   
    auto strRes = toString_RJS(*this, valueHandle);
    if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
      os << "exception thrown in toString of original exception\n";
      return;
    }

    strRes->get()->appendUTF16String(tmp);
    os << tmp << "\n";
    return;
  }
                                                           
  auto strRes = toString_RJS(*this, makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    os << "exception thrown in toString of stack trace\n";
    return;
  }
  PseudoHandle<StringPrimitive> str = std::move(*strRes);
  if (str->getStringLength() == 0) {
    str.invalidate();
                                              
                                                              
    auto errToStringRes = toString_RJS(*this, valueHandle);
    if (LLVM_UNLIKELY(errToStringRes == ExecutionStatus::EXCEPTION)) {
      os << "exception thrown in toString of original exception\n";
      return;
    }
    str = std::move(*errToStringRes);
  }
  str->appendUTF16String(tmp);
  os << tmp << "\n";
}

Handle<JSObject> Runtime::getGlobal() {
  return Handle<JSObject>::vmcast(&global_);
}

std::vector<llvh::ArrayRef<uint8_t>> Runtime::getEpilogues() {
  std::vector<llvh::ArrayRef<uint8_t>> result;
  for (const auto &m : runtimeModuleList_) {
    if (!m.hidesEpilogue()) {
      result.push_back(m.getEpilogue());
    }
  }
  return result;
}

#ifdef HERMES_ENABLE_DEBUGGER

llvh::Optional<Runtime::StackFrameInfo> Runtime::stackFrameInfoByIndex(
    uint32_t frameIdx) const {
                      
  auto frames = getStackFrames();
  auto it = frames.begin();
  for (; frameIdx && it != frames.end(); ++it, --frameIdx) {
  }
  if (it == frames.end())
    return llvh::None;

  StackFrameInfo info;
  info.frame = *it++;
  info.isGlobal = it == frames.end();
  return info;
}

                                                                          
                                                                            
         
uint32_t Runtime::calcFrameOffset(ConstStackFrameIterator it) const {
  assert(it != getStackFrames().end() && "invalid frame");
  return it->ptr() - registerStackStart_;
}

                                                                        
                                                                      
uint32_t Runtime::getCurrentFrameOffset() const {
  return calcFrameOffset(getStackFrames().begin());
}

#endif

static ExecutionStatus
raisePlaceholder(Runtime &runtime, Handle<JSError> errorObj, Handle<> message) {
  JSError::recordStackTrace(errorObj, runtime);
  JSError::setMessage(errorObj, runtime, message);
  return runtime.setThrownValue(errorObj.getHermesValue());
}

                                                                                
            
static ExecutionStatus raisePlaceholder(
    Runtime &runtime,
    Handle<JSObject> prototype,
    Handle<> message) {
  GCScopeMarkerRAII gcScope{runtime};

                                                                        
  auto errorObj = runtime.makeHandle(JSError::create(runtime, prototype));
  return raisePlaceholder(runtime, errorObj, message);
}

                                                                        
                                                        
                                      
static ExecutionStatus raisePlaceholder(
    Runtime &runtime,
    Handle<JSObject> prototype,
    const TwineChar16 &msg) {
                                                                         
             
  GCScope gcScope{runtime};

  SmallU16String<64> buf;
  msg.toVector(buf);

  auto strRes = StringPrimitive::create(runtime, buf);
  if (strRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto str = runtime.makeHandle<StringPrimitive>(*strRes);
  LLVM_DEBUG(llvh::errs() << buf.arrayRef() << "\n");
  return raisePlaceholder(runtime, prototype, str);
}

ExecutionStatus Runtime::raiseError(const TwineChar16 &msg) {
  return raisePlaceholder(
      *this, Handle<JSObject>::vmcast(&ErrorPrototype), msg);
}

ExecutionStatus Runtime::raiseTypeError(Handle<> message) {
                                                                         
             
  GCScope gcScope{*this};
  return raisePlaceholder(
      *this, Handle<JSObject>::vmcast(&TypeErrorPrototype), message);
}

ExecutionStatus Runtime::raiseTypeErrorForValue(
    const TwineChar16 &msg1,
    Handle<> value,
    const TwineChar16 &msg2) {
  switch (value->getTag()) {
    case HermesValue::Tag::Object:
      return raiseTypeError(msg1 + "Object" + msg2);
    case HermesValue::Tag::Str:
      return raiseTypeError(
          msg1 + "'" + vmcast<StringPrimitive>(*value) + "'" + msg2);
    case HermesValue::Tag::BoolSymbol:
      if (value->isBool()) {
        if (value->getBool()) {
          return raiseTypeError(msg1 + "true" + msg2);
        } else {
          return raiseTypeError(msg1 + "false" + msg2);
        }
      }
      return raiseTypeError(
          msg1 + "Symbol(" + getStringPrimFromSymbolID(value->getSymbol()) +
          ")" + msg2);
    case HermesValue::Tag::UndefinedNull:
      if (value->isUndefined())
        return raiseTypeError(msg1 + "undefined" + msg2);
      else
        return raiseTypeError(msg1 + "null" + msg2);
    default:
      if (value->isNumber()) {
        char buf[hermes::NUMBER_TO_STRING_BUF_SIZE];
        size_t len = hermes::numberToString(
            value->getNumber(), buf, hermes::NUMBER_TO_STRING_BUF_SIZE);
        return raiseTypeError(msg1 + llvh::StringRef{buf, len} + msg2);
      }
  }
  return raiseTypeError(msg1 + "Value" + msg2);
}

ExecutionStatus Runtime::raiseTypeErrorForCallable(Handle<> callable) {
  if (CodeBlock *curCodeBlock = getCurrentFrame().getCalleeCodeBlock(*this)) {
    if (OptValue<uint32_t> textifiedCalleeOffset =
            curCodeBlock->getTextifiedCalleeOffset()) {
                                                                     
                                                                         
      OptValue<llvh::StringRef> tCallee =
          curCodeBlock->getRuntimeModule()
              ->getBytecode()
              ->getDebugInfo()
              ->getTextifiedCalleeUTF8(
                  *textifiedCalleeOffset,
                  curCodeBlock->getOffsetOf(getCurrentIP()));
      if (tCallee.hasValue()) {
                                                                          
                 
        if (isAllASCII(tCallee->begin(), tCallee->end())) {
                                                     
          return raiseTypeErrorForValue(
              TwineChar16(*tCallee) + " is not a function (it is ",
              callable,
              ")");
        }

                                                           
        llvh::SmallVector<char16_t, 16> tCalleeUTF16;
        convertUTF8WithSurrogatesToUTF16(
            std::back_inserter(tCalleeUTF16), tCallee->begin(), tCallee->end());
        return raiseTypeErrorForValue(
            TwineChar16(tCalleeUTF16) + " is not a function (it is ",
            callable,
            ")");
      }
    }
  }

  return raiseTypeErrorForValue(callable, " is not a function");
}

ExecutionStatus Runtime::raiseTypeError(const TwineChar16 &msg) {
  return raisePlaceholder(
      *this, Handle<JSObject>::vmcast(&TypeErrorPrototype), msg);
}

ExecutionStatus Runtime::raiseSyntaxError(const TwineChar16 &msg) {
  return raisePlaceholder(
      *this, Handle<JSObject>::vmcast(&SyntaxErrorPrototype), msg);
}

ExecutionStatus Runtime::raiseRangeError(const TwineChar16 &msg) {
  return raisePlaceholder(
      *this, Handle<JSObject>::vmcast(&RangeErrorPrototype), msg);
}

ExecutionStatus Runtime::raiseReferenceError(const TwineChar16 &msg) {
  return raisePlaceholder(
      *this, Handle<JSObject>::vmcast(&ReferenceErrorPrototype), msg);
}

ExecutionStatus Runtime::raiseURIError(const TwineChar16 &msg) {
  return raisePlaceholder(
      *this, Handle<JSObject>::vmcast(&URIErrorPrototype), msg);
}

ExecutionStatus Runtime::raiseStackOverflow(StackOverflowKind kind) {
  const char *msg;
  switch (kind) {
    case StackOverflowKind::JSRegisterStack:
      msg = "Maximum call stack size exceeded";
      break;
    case StackOverflowKind::NativeStack:
      msg = "Maximum call stack size exceeded (native stack depth)";
      break;
    case StackOverflowKind::JSONParser:
      msg = "Maximum nesting level in JSON parser exceeded";
      break;
    case StackOverflowKind::JSONStringify:
      msg = "Maximum nesting level in JSON stringifyer exceeded";
      break;
  }
  return raisePlaceholder(
      *this, Handle<JSObject>::vmcast(&RangeErrorPrototype), msg);
}

ExecutionStatus Runtime::raiseQuitError() {
  return raiseUncatchableError(
      Handle<JSObject>::vmcast(&QuitErrorPrototype), "Quit");
}

ExecutionStatus Runtime::raiseTimeoutError() {
  return raiseUncatchableError(
      Handle<JSObject>::vmcast(&TimeoutErrorPrototype),
      "Javascript execution has timed out.");
}

ExecutionStatus Runtime::raiseUncatchableError(
    Handle<JSObject> prototype,
    llvh::StringRef errMessage) {
  Handle<JSError> err =
      makeHandle(JSError::createUncatchable(*this, prototype));
  auto res = StringPrimitive::create(
      *this, llvh::ASCIIRef{errMessage.begin(), errMessage.end()});
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto str = makeHandle(*res);
  return raisePlaceholder(*this, err, str);
}

ExecutionStatus Runtime::raiseEvalUnsupported(llvh::StringRef code) {
  return raiseSyntaxError(
      TwineChar16("Parsing source code unsupported: ") + code.substr(0, 32));
}

bool Runtime::insertVisitedObject(JSObject *obj) {
  if (llvh::find(stringCycleCheckVisited_, obj) !=
      stringCycleCheckVisited_.end())
    return true;
  stringCycleCheckVisited_.push_back(obj);
  return false;
}

void Runtime::removeVisitedObject(JSObject *obj) {
  (void)obj;
  assert(
      stringCycleCheckVisited_.back() == obj && "string cycle stack corrupted");
  stringCycleCheckVisited_.pop_back();
}

std::unique_ptr<Buffer> Runtime::generateSpecialRuntimeBytecode() {
  hbc::SimpleBytecodeBuilder builder;
  {
    hbc::BytecodeInstructionGenerator bcGen;
    bcGen.emitLoadConstUndefined(0);
    bcGen.emitRet(0);
    builder.addFunction(1, 1, bcGen.acquireBytecode());
  }
  {
    hbc::BytecodeInstructionGenerator bcGen;
    bcGen.emitGetGlobalObject(0);
    bcGen.emitRet(0);
    builder.addFunction(1, 1, bcGen.acquireBytecode());
  }
  auto buffer = builder.generateBytecodeBuffer();
  assert(buffer->size() < MIN_IO_TRACKING_SIZE);
  return buffer;
}

void Runtime::initPredefinedStrings() {
  assert(!getTopGCScope() && "There shouldn't be any handles allocated yet");

  auto buffer = predefStringAndSymbolChars;
  auto propLengths = predefPropertyLengths;
  auto strLengths = predefStringLengths;
  auto symLengths = predefSymbolLengths;

  static const uint32_t hashes[] = {
#define STR(name, string) constexprHashString(string),
#include "hermes/VM/PredefinedStrings.def"
  };

  uint32_t offset = 0;
  uint32_t registered = 0;
  (void)registered;
  const uint32_t strCount = Predefined::NumStrings;
  const uint32_t symCount = Predefined::NumSymbols;
  identifierTable_.reserve(Predefined::_IPROP_AFTER_LAST + strCount + symCount);

  for (uint32_t idx = 0; idx < Predefined::_IPROP_AFTER_LAST; ++idx) {
    SymbolID sym = identifierTable_.createNotUniquedLazySymbol(
        ASCIIRef{&buffer[offset], propLengths[idx]});

    assert(sym == Predefined::getSymbolID((Predefined::IProp)registered++));
    (void)sym;

    offset += propLengths[idx];
  }

  assert(
      strCount == sizeof hashes / sizeof hashes[0] &&
      "Arrays should have same length");
  for (uint32_t idx = 0; idx < strCount; idx++) {
    SymbolID sym = identifierTable_.registerLazyIdentifier(
        ASCIIRef{&buffer[offset], strLengths[idx]}, hashes[idx]);

    assert(sym == Predefined::getSymbolID((Predefined::Str)registered++));
    (void)sym;

    offset += strLengths[idx];
  }

  for (uint32_t idx = 0; idx < symCount; ++idx) {
    SymbolID sym = identifierTable_.createNotUniquedLazySymbol(
        ASCIIRef{&buffer[offset], symLengths[idx]});

    assert(sym == Predefined::getSymbolID((Predefined::Sym)registered++));
    (void)sym;

    offset += symLengths[idx];
  }

  assert(
      !getTopGCScope() &&
      "There shouldn't be any handles allocated during initializing the predefined strings");
}

void Runtime::initCharacterStrings() {
  GCScope gc(*this);
  auto marker = gc.createMarker();
  charStrings_.reserve(256);
  for (char16_t ch = 0; ch < 256; ++ch) {
    gc.flushToMarker(marker);
    charStrings_.push_back(allocateCharacterString(ch).getHermesValue());
  }
}

Handle<StringPrimitive> Runtime::allocateCharacterString(char16_t ch) {
                                                                      
                                                                           
                                                                            
                                                       
                                  

  PinnedHermesValue strRes;
  if (LLVM_LIKELY(ch < 128)) {
    strRes = ignoreAllocationFailure(
        StringPrimitive::createLongLived(*this, ASCIIRef(ch)));
  } else {
    strRes = ignoreAllocationFailure(
        StringPrimitive::createLongLived(*this, UTF16Ref(ch)));
  }
  return makeHandle<StringPrimitive>(strRes);
}

Handle<StringPrimitive> Runtime::getCharacterString(char16_t ch) {
  if (LLVM_LIKELY(ch < 256))
    return Handle<StringPrimitive>::vmcast(&charStrings_[ch]);

  return makeHandle<StringPrimitive>(
      ignoreAllocationFailure(StringPrimitive::create(*this, UTF16Ref(ch))));
}

                                                                           
static const struct {
  uint16_t object, method;
#ifndef NDEBUG
  const char *name;
#define BUILTIN_METHOD(object, method) \
  {(uint16_t)Predefined::object,       \
   (uint16_t)Predefined::method,       \
   #object "::" #method},
#else
#define BUILTIN_METHOD(object, method) \
  {(uint16_t)Predefined::object, (uint16_t)Predefined::method},
#endif
#define PRIVATE_BUILTIN(name)
#define JS_BUILTIN(name)
} publicNativeBuiltins[] = {
#include "hermes/FrontEndDefs/Builtins.def"
};

static_assert(
    sizeof(publicNativeBuiltins) / sizeof(publicNativeBuiltins[0]) ==
        BuiltinMethod::_firstPrivate,
    "builtin method table mismatch");

ExecutionStatus Runtime::forEachPublicNativeBuiltin(
    const std::function<ExecutionStatus(
        unsigned methodIndex,
        Predefined::Str objectName,
        Handle<JSObject> &object,
        SymbolID methodID)> &callback) {
  MutableHandle<JSObject> lastObject{*this};
  Predefined::Str lastObjectName = Predefined::_STRING_AFTER_LAST;

  for (unsigned methodIndex = 0; methodIndex < BuiltinMethod::_firstPrivate;
       ++methodIndex) {
    GCScopeMarkerRAII marker{*this};
    LLVM_DEBUG(llvh::dbgs() << publicNativeBuiltins[methodIndex].name << "\n");
                                            
    auto objectName = (Predefined::Str)publicNativeBuiltins[methodIndex].object;
    if (objectName != lastObjectName) {
      auto objectID = Predefined::getSymbolID(objectName);
                                                                        
                        
      NamedPropertyDescriptor desc;
                                            
      if (!JSObject::getOwnNamedDescriptor(
              getGlobal(), *this, objectID, desc)) {
        return raiseTypeError(
            TwineChar16{
                "Cannot execute a bytecode compiled with -fstatic-builtins: "} +
            getPredefinedString(objectName) + " was deleted");
      }
                               
      auto cr = JSObject::getNamedSlotValue(getGlobal(), *this, desc);
      if (LLVM_UNLIKELY(cr == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
                                                                              
                             
      if (LLVM_UNLIKELY(!vmisa<JSObject>(cr->get()))) {
        return raiseTypeError(
            TwineChar16{
                "Cannot execute a bytecode compiled with -fstatic-builtins: "} +
            getPredefinedString(objectName) + " is not an object");
      }

      lastObject = vmcast<JSObject>(cr->get());
      lastObjectName = objectName;
    }

                       
    auto methodName = (Predefined::Str)publicNativeBuiltins[methodIndex].method;
    auto methodID = Predefined::getSymbolID(methodName);

    ExecutionStatus status =
        callback(methodIndex, objectName, lastObject, methodID);
    if (status != ExecutionStatus::RETURNED) {
      return ExecutionStatus::EXCEPTION;
    }
  }
  return ExecutionStatus::RETURNED;
}

void Runtime::initNativeBuiltins() {
  GCScopeMarkerRAII gcScope{*this};

  builtins_.resize(BuiltinMethod::_count);

  (void)forEachPublicNativeBuiltin([this](
                                       unsigned methodIndex,
                                       Predefined::Str                 ,
                                       Handle<JSObject> &currentObject,
                                       SymbolID methodID) {
    auto cr = JSObject::getNamed_RJS(currentObject, *this, methodID);
    assert(
        cr.getStatus() != ExecutionStatus::EXCEPTION &&
        "getNamed() of builtin method failed");
    assert(
        vmisa<NativeFunction>(cr->get()) &&
        "getNamed() of builtin method must be a NativeFunction");
    builtins_[methodIndex] = vmcast<NativeFunction>(cr->get());
    return ExecutionStatus::RETURNED;
  });

                                         
  createHermesBuiltins(*this, builtins_);
#ifndef NDEBUG
                                               
  for (unsigned i = 0; i < BuiltinMethod::_firstJS; ++i) {
    assert(builtins_[i] && "native builtin not initialized");
  }
#endif
}

static const struct JSBuiltin {
  uint16_t symID, builtinIndex;
} jsBuiltins[] = {
#define BUILTIN_METHOD(object, method)
#define PRIVATE_BUILTIN(name)
#define JS_BUILTIN(name) \
  {(uint16_t)Predefined::name, (uint16_t)BuiltinMethod::HermesBuiltin##_##name},
#include "hermes/FrontEndDefs/Builtins.def"
};

void Runtime::initJSBuiltins(
    llvh::MutableArrayRef<Callable *> builtins,
    Handle<JSObject> jsBuiltinsObj) {
  for (const JSBuiltin &jsBuiltin : jsBuiltins) {
    auto symID = jsBuiltin.symID;
    auto builtinIndex = jsBuiltin.builtinIndex;

                                                     
    auto getRes = JSObject::getNamed_RJS(
        jsBuiltinsObj, *this, Predefined::getSymbolID((Predefined::Str)symID));
    assert(getRes == ExecutionStatus::RETURNED && "Failed to get JS builtin.");
    JSFunction *jsFunc = vmcast<JSFunction>(getRes->getHermesValue());

    builtins[builtinIndex] = jsFunc;
  }
}

ExecutionStatus Runtime::assertBuiltinsUnmodified() {
  assert(!builtinsFrozen_ && "Builtins are already frozen.");
  GCScope gcScope(*this);
  NoRJSScope noRJS{*this};

  return forEachPublicNativeBuiltin([this](
                                        unsigned methodIndex,
                                        Predefined::Str objectName,
                                        Handle<JSObject> &currentObject,
                                        SymbolID methodID) {
                                                                                
            
    NamedPropertyDescriptor desc;
                                          
                                                                  
    if (!JSObject::getOwnNamedDescriptor(
            currentObject, *this, methodID, desc) ||
        desc.flags.proxyObject || desc.flags.hostObject) {
      return raiseTypeError(
          TwineChar16{
              "Cannot execute a bytecode compiled with -fstatic-builtins: "} +
          getPredefinedString(objectName) + "." +
          getStringPrimFromSymbolID(methodID) + " has been modified");
    }
    auto cr = JSObject::getNamedSlotValue(currentObject, *this, desc);
    if (LLVM_UNLIKELY(cr == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    auto currentBuiltin = dyn_vmcast<NativeFunction>(cr->get());
    if (!currentBuiltin || currentBuiltin != builtins_[methodIndex]) {
      return raiseTypeError(
          TwineChar16{
              "Cannot execute a bytecode compiled with -fstatic-builtins: "} +
          getPredefinedString(objectName) + "." +
          getStringPrimFromSymbolID(methodID) + " has been modified");
    }
    return ExecutionStatus::RETURNED;
  });
}

void Runtime::freezeBuiltins() {
  assert(!builtinsFrozen_ && "Builtins are already frozen.");
  GCScope gcScope{*this};

                                                                               
                
  std::vector<SymbolID> objectList;
                                                                                
                 
  std::vector<SymbolID> methodList;

                                                                   
  PropertyFlags clearFlags;
  clearFlags.configurable = 1;
  clearFlags.writable = 1;
  PropertyFlags setFlags;
  setFlags.staticBuiltin = 1;

  (void)forEachPublicNativeBuiltin(
      [this, &objectList, &methodList, &clearFlags, &setFlags](
          unsigned methodIndex,
          Predefined::Str objectName,
          Handle<JSObject> &currentObject,
          SymbolID methodID) {
        methodList.push_back(methodID);
                                                     
        if (methodIndex + 1 == BuiltinMethod::_publicCount ||
            objectName != publicNativeBuiltins[methodIndex + 1].object) {
                                                   
          SymbolID objectID = Predefined::getSymbolID(objectName);
          objectList.push_back(objectID);
                                                                               
                    
          JSObject::updatePropertyFlagsWithoutTransitions(
              currentObject,
              *this,
              clearFlags,
              setFlags,
              llvh::ArrayRef<SymbolID>(methodList));
          methodList.clear();
        }
        return ExecutionStatus::RETURNED;
      });

                                                                              
            
  JSObject::updatePropertyFlagsWithoutTransitions(
      getGlobal(),
      *this,
      clearFlags,
      setFlags,
      llvh::ArrayRef<SymbolID>(objectList));

  builtinsFrozen_ = true;
}

ExecutionStatus Runtime::drainJobs() {
  GCScope gcScope{*this};
  MutableHandle<Callable> job{*this};
                                                            
  while (!jobQueue_.empty()) {
    GCScopeMarkerRAII marker{gcScope};

    job = jobQueue_.front();
    jobQueue_.pop_front();

                                               
    auto callRes =
        Callable::executeCall0(job, *this, Runtime::getUndefinedValue());

                                                                                
                                                                          
    if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
  }
  return ExecutionStatus::RETURNED;
}

ExecutionStatus Runtime::addToKeptObjects(Handle<JSObject> obj) {
                                           
  if (keptObjects_.isUndefined()) {
    auto mapRes = OrderedHashMap::create(*this);
    if (LLVM_UNLIKELY(mapRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    keptObjects_ = mapRes->getHermesValue();
  }
  auto mapHandle = Handle<OrderedHashMap>::vmcast(&keptObjects_);
  return OrderedHashMap::insert(mapHandle, *this, obj, obj);
}

void Runtime::clearKeptObjects() {
  keptObjects_ = HermesValue::encodeUndefinedValue();
}

uint64_t Runtime::gcStableHashHermesValue(Handle<HermesValue> value) {
  switch (value->getTag()) {
    case HermesValue::Tag::Object: {
                                                                    
                                              
      auto id = JSObject::getObjectID(vmcast<JSObject>(*value), *this);
      return llvh::hash_value(id);
    }
    case HermesValue::Tag::BigInt: {
                                                 
      auto bytes = Handle<BigIntPrimitive>::vmcast(value)->getRawDataCompact();
      return llvh::hash_combine_range(bytes.begin(), bytes.end());
    }
    case HermesValue::Tag::Str: {
                                                 
      auto strView = StringPrimitive::createStringView(
          *this, Handle<StringPrimitive>::vmcast(value));
      return llvh::hash_combine_range(strView.begin(), strView.end());
    }
    default:
      assert(!value->isPointer() && "Unhandled pointer type");
      if (value->isNumber()) {
                                                                             
                                                    
        if (LLVM_UNLIKELY(value->isNaN()))
          return llvh::hash_value(HermesValue::encodeNaNValue().getRaw());
                                
        if (value->getNumber() == 0)
          return 0;
      }
                                                                    
      return llvh::hash_value(value->getRaw());
  }
}

bool Runtime::symbolEqualsToStringPrim(SymbolID id, StringPrimitive *strPrim) {
  auto view = identifierTable_.getStringView(*this, id);
  return strPrim->equals(view);
}

LLVM_ATTRIBUTE_NOINLINE
void Runtime::allocStack(uint32_t count, HermesValue initValue) {
                                                                             
                                                                        
                                                                         
                   
  auto *oldStackPointer = stackPointer_;
  allocUninitializedStack(count);
                                  
  std::uninitialized_fill_n(oldStackPointer, count, initValue);
}

void Runtime::dumpCallFrames(llvh::raw_ostream &OS) {
  OS << "== Call Frames ==\n";
  const PinnedHermesValue *next = getStackPointer();
  unsigned i = 0;
  for (StackFramePtr sf : getStackFrames()) {
    OS << i++ << " ";
    if (auto *closure = dyn_vmcast<Callable>(sf.getCalleeClosureOrCBRef())) {
      OS << cellKindStr(closure->getKind()) << " ";
    }
    if (auto *cb = sf.getCalleeCodeBlock(*this)) {
      OS << formatSymbolID(cb->getNameMayAllocate()) << " ";
    }
    dumpStackFrame(sf, OS, next);
    next = sf.ptr();
  }
}

LLVM_ATTRIBUTE_NOINLINE
void Runtime::dumpCallFrames() {
  dumpCallFrames(llvh::errs());
}

                         
llvh::raw_ostream &operator<<(
    llvh::raw_ostream &OS,
    Runtime::FormatSymbolID format) {
  if (!format.symbolID.isValid())
    return OS << "SymbolID(INVALID)";

  OS << "SymbolID("
     << (format.symbolID.isNotUniqued() ? "(External)" : "(Internal)")
     << format.symbolID.unsafeGetIndex() << " \"";

  OS << format.runtime.getIdentifierTable().convertSymbolToUTF8(
      format.symbolID);
  return OS << "\")";
}

                                                                             
                                                                          
                                                                           
                                                                              
void Runtime::crashCallback(int fd) {
  llvh::raw_fd_ostream jsonStream(fd, false);
  JSONEmitter json(jsonStream);

                                                                            
                                                                         
                
  char hexBuf[20];
  auto writeHex = [&hexBuf](void *ptr) {
    unsigned len = snprintf(hexBuf, sizeof(hexBuf), "%p", ptr);
    assert(len < sizeof(hexBuf) && "Need more chars than expected");
    return llvh::StringRef{hexBuf, len};
  };

  json.openDict();
  json.emitKeyValue("type", "runtime");
  json.emitKeyValue("address", writeHex(this));
  json.emitKeyValue(
      "registerStackAllocation", writeHex(registerStackAllocation_.data()));
  json.emitKeyValue("registerStackStart", writeHex(registerStackStart_));
  json.emitKeyValue("registerStackPointer", writeHex(stackPointer_));
  json.emitKeyValue("registerStackEnd", writeHex(registerStackEnd_));
  json.emitKey("callstack");
  crashWriteCallStack(json);
  json.closeDict();
}

                                                                             
                                                                          
                                                                           
                                                                              
void Runtime::crashWriteCallStack(JSONEmitter &json) {
  json.openArray();
  for (auto frame : getStackFrames()) {
    json.openDict();
    json.emitKeyValue(
        "StackFrameRegOffs", (uint32_t)(frame.ptr() - registerStackStart_));
    auto codeBlock = frame.getSavedCodeBlock();
    if (codeBlock) {
      json.emitKeyValue("FunctionID", codeBlock->getFunctionID());
      auto bytecodeOffs = codeBlock->getOffsetOf(frame.getSavedIP());
      json.emitKeyValue("ByteCodeOffset", bytecodeOffs);
      auto blockSourceCode = codeBlock->getDebugSourceLocationsOffset();
      const RuntimeModule *runtimeModule = codeBlock->getRuntimeModule();
      if (blockSourceCode.hasValue()) {
        auto debugInfo = runtimeModule->getBytecode()->getDebugInfo();
        auto sourceLocation = debugInfo->getLocationForAddress(
            blockSourceCode.getValue(), bytecodeOffs);
        if (sourceLocation) {
          auto file = debugInfo->getFilenameByID(sourceLocation->filenameId);
          char buf[256];
          unsigned len = snprintf(
              buf,
              sizeof(buf),
              "%s:%d:%d",
              file.c_str(),
              sourceLocation->line,
              sourceLocation->column);
                                                                             
                                                                    
          llvh::StringRef str{buf, std::min<size_t>(len, sizeof(buf) - 1)};
          json.emitKeyValue("SourceLocation", str);
        }
      }
      uint32_t segmentID = runtimeModule->getBytecode()->getSegmentID();
      llvh::StringRef sourceURL = runtimeModule->getSourceURL();
      json.emitKeyValue("SegmentID", segmentID);
      json.emitKeyValue("SourceURL", sourceURL);
    } else {
      json.emitKeyValue("NativeCode", true);
    }
    json.closeDict();         
  }
  json.closeArray();          
}

std::string Runtime::getCallStackNoAlloc(const Inst *ip) {
  NoAllocScope noAlloc(*this);
  std::string res;
                                                                         
  for (auto frame : getStackFrames()) {
    auto codeBlock = frame->getCalleeCodeBlock(*this);
    if (codeBlock) {
      res += codeBlock->getNameString(*this);
                                                 
                                                                
                                
      const uint32_t bytecodeOffs =
          ip != nullptr ? codeBlock->getOffsetOf(ip) : 0;
      auto blockSourceCode = codeBlock->getDebugSourceLocationsOffset();
      if (blockSourceCode.hasValue()) {
        auto debugInfo =
            codeBlock->getRuntimeModule()->getBytecode()->getDebugInfo();
        auto sourceLocation = debugInfo->getLocationForAddress(
            blockSourceCode.getValue(), bytecodeOffs);
        if (sourceLocation) {
          auto file = debugInfo->getFilenameByID(sourceLocation->filenameId);
          res += ": " + file + ":" + std::to_string(sourceLocation->line) +
              ":" + std::to_string(sourceLocation->column);
        }
      }
      res += "\n";
    } else {
      res += "<Native code>\n";
    }
                                                                           
                      
    ip = frame.getSavedIP();
  }
  return res;
}

void Runtime::onGCEvent(GCEventKind kind, const std::string &extraInfo) {
#if HERMESVM_SAMPLING_PROFILER_AVAILABLE
  if (samplingProfiler) {
    switch (kind) {
      case GCEventKind::CollectionStart:
        samplingProfiler->suspend(
            SamplingProfiler::SuspendFrameInfo::Kind::GC, extraInfo);
        break;
      case GCEventKind::CollectionEnd:
        samplingProfiler->resume();
        break;
      default:
        llvm_unreachable("unknown GCEventKind");
    }
  }
#endif                                        
  if (gcEventCallback_) {
    gcEventCallback_(kind, extraInfo.c_str());
  }
}

#ifdef HERMESVM_PROFILER_BB

llvh::Optional<std::tuple<std::string, uint32_t, uint32_t>>
Runtime::getIPSourceLocation(const CodeBlock *codeBlock, const Inst *ip) {
  auto bytecodeOffs = codeBlock->getOffsetOf(ip);
  auto blockSourceCode = codeBlock->getDebugSourceLocationsOffset();

  if (!blockSourceCode) {
    return llvh::None;
  }
  auto debugInfo = codeBlock->getRuntimeModule()->getBytecode()->getDebugInfo();
  auto sourceLocation = debugInfo->getLocationForAddress(
      blockSourceCode.getValue(), bytecodeOffs);
  if (!sourceLocation) {
    return llvh::None;
  }
  auto filename = debugInfo->getFilenameByID(sourceLocation->filenameId);
  auto line = sourceLocation->line;
  auto col = sourceLocation->column;
  return std::make_tuple(filename, line, col);
}

void Runtime::preventHCGC(HiddenClass *hc) {
  auto &classIdToIdxMap = inlineCacheProfiler_.getClassIdtoIndexMap();
  auto &hcIdx = inlineCacheProfiler_.getHiddenClassArrayIndex();
  auto ret = classIdToIdxMap.insert(
      std::pair<ClassId, uint32_t>(getHeap().getObjectID(hc), hcIdx));
  if (ret.second) {
    auto *hiddenClassArray = inlineCacheProfiler_.getHiddenClassArray();
    JSArray::setElementAt(
        makeHandle(hiddenClassArray), *this, hcIdx++, makeHandle(hc));
  }
}

void Runtime::recordHiddenClass(
    CodeBlock *codeBlock,
    const Inst *cacheMissInst,
    SymbolID symbolID,
    HiddenClass *objectHiddenClass,
    HiddenClass *cachedHiddenClass) {
  auto offset = codeBlock->getOffsetOf(cacheMissInst);

                       
  if (objectHiddenClass == cachedHiddenClass) {
    inlineCacheProfiler_.insertICHit(codeBlock, offset);
    return;
  }

                        
  assert(objectHiddenClass != nullptr && "object hidden class should exist");
                                                 
  preventHCGC(objectHiddenClass);
  ClassId objectHiddenClassId = getHeap().getObjectID(objectHiddenClass);
                                                 
  ClassId cachedHiddenClassId =
      static_cast<ClassId>(GCBase::IDTracker::kInvalidNode);
  if (cachedHiddenClass != nullptr) {
    preventHCGC(cachedHiddenClass);
    cachedHiddenClassId = getHeap().getObjectID(cachedHiddenClass);
  }
                                              
  inlineCacheProfiler_.insertICMiss(
      codeBlock, offset, symbolID, objectHiddenClassId, cachedHiddenClassId);
}

void Runtime::getInlineCacheProfilerInfo(llvh::raw_ostream &ostream) {
  inlineCacheProfiler_.dumpRankedInlineCachingMisses(*this, ostream);
}

HiddenClass *Runtime::resolveHiddenClassId(ClassId classId) {
  if (classId == static_cast<ClassId>(GCBase::IDTracker::kInvalidNode)) {
    return nullptr;
  }
  auto &classIdToIdxMap = inlineCacheProfiler_.getClassIdtoIndexMap();
  auto *hiddenClassArray = inlineCacheProfiler_.getHiddenClassArray();
  auto hcHermesVal =
      hiddenClassArray->at(*this, classIdToIdxMap[classId]).unboxToHV(*this);
  return vmcast<HiddenClass>(hcHermesVal);
}

#endif

ExecutionStatus Runtime::notifyTimeout() {
                                       
  return raiseTimeoutError();
}

#ifdef HERMES_MEMORY_INSTRUMENTATION

std::pair<const CodeBlock *, const inst::Inst *>
Runtime::getCurrentInterpreterLocation(const inst::Inst *ip) {
  assert(ip && "IP being null implies we're not currently in the interpreter.");
  auto callFrames = getStackFrames();
  const CodeBlock *codeBlock = nullptr;
  for (auto frameIt = callFrames.begin(); frameIt != callFrames.end();
       ++frameIt) {
    codeBlock = frameIt->getCalleeCodeBlock(*this);
    if (codeBlock) {
      break;
    } else {
      ip = frameIt->getSavedIP();
    }
  }
  assert(codeBlock && "Could not find CodeBlock.");
  return {codeBlock, ip};
}

StackTracesTreeNode *Runtime::getCurrentStackTracesTreeNode(
    const inst::Inst *ip) {
  assert(stackTracesTree_ && "Runtime not configured to track alloc stacks");
  assert(
      (getHeap().getAllocationLocationTracker().isEnabled() ||
       getHeap().getSamplingAllocationTracker().isEnabled()) &&
      "AllocationLocationTracker not enabled");
  if (!ip) {
    return nullptr;
  }
  const CodeBlock *codeBlock;
  std::tie(codeBlock, ip) = getCurrentInterpreterLocation(ip);
  return stackTracesTree_->getStackTrace(*this, codeBlock, ip);
}

void Runtime::enableAllocationLocationTracker(
    std::function<void(
        uint64_t,
        std::chrono::microseconds,
        std::vector<GCBase::AllocationLocationTracker::HeapStatsUpdate>)>
        fragmentCallback) {
  if (!stackTracesTree_) {
    stackTracesTree_ = std::make_unique<StackTracesTree>();
  }
  stackTracesTree_->syncWithRuntimeStack(*this);
  getHeap().enableHeapProfiler(std::move(fragmentCallback));
}

void Runtime::disableAllocationLocationTracker(bool clearExistingTree) {
  getHeap().disableHeapProfiler();
  if (clearExistingTree) {
    stackTracesTree_.reset();
  }
}

void Runtime::enableSamplingHeapProfiler(
    size_t samplingInterval,
    int64_t seed) {
  if (!stackTracesTree_) {
    stackTracesTree_ = std::make_unique<StackTracesTree>();
  }
  stackTracesTree_->syncWithRuntimeStack(*this);
  getHeap().enableSamplingHeapProfiler(samplingInterval, seed);
}

void Runtime::disableSamplingHeapProfiler(llvh::raw_ostream &os) {
  getHeap().disableSamplingHeapProfiler(os);
  stackTracesTree_.reset();
}

void Runtime::popCallStackImpl() {
  assert(stackTracesTree_ && "Runtime not configured to track alloc stacks");
  stackTracesTree_->popCallStack();
}

void Runtime::pushCallStackImpl(
    const CodeBlock *codeBlock,
    const inst::Inst *ip) {
  assert(stackTracesTree_ && "Runtime not configured to track alloc stacks");
  stackTracesTree_->pushCallStack(*this, codeBlock, ip);
}

#endif                                 

void ScopedNativeDepthReducer::staticAsserts() {
#ifdef HERMES_CHECK_NATIVE_STACK
  static_assert(
      kReducedNativeStackGap < kMinSupportedNativeStackGap,
      "kMinSupportedNativeStackGap too low, must be reduced in the reducer");
#endif
}

}                
}                    

#undef DEBUG_TYPE

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_RUNTIME_H
#define HERMES_VM_RUNTIME_H

#include "hermes/Public/DebuggerTypes.h"
#include "hermes/Public/RuntimeConfig.h"
#include "hermes/Support/Compiler.h"
#include "hermes/Support/ErrorHandling.h"
#include "hermes/Support/StackOverflowGuard.h"
#include "hermes/VM/AllocOptions.h"
#include "hermes/VM/AllocResult.h"
#include "hermes/VM/BasicBlockExecutionInfo.h"
#include "hermes/VM/CallResult.h"
#include "hermes/VM/Casting.h"
#include "hermes/VM/Debugger/Debugger.h"
#include "hermes/VM/GC.h"
#include "hermes/VM/GCBase-inline.h"
#include "hermes/VM/GCStorage.h"
#include "hermes/VM/Handle-inline.h"
#include "hermes/VM/HandleRootOwner-inline.h"
#include "hermes/VM/IdentifierTable.h"
#include "hermes/VM/InternalProperty.h"
#include "hermes/VM/InterpreterState.h"
#include "hermes/VM/PointerBase.h"
#include "hermes/VM/Predefined.h"
#include "hermes/VM/Profiler.h"
#include "hermes/VM/Profiler/SamplingProfilerDefs.h"
#include "hermes/VM/PropertyCache.h"
#include "hermes/VM/PropertyDescriptor.h"
#include "hermes/VM/RegExpMatch.h"
#include "hermes/VM/RuntimeModule.h"
#include "hermes/VM/StackFrame.h"
#include "hermes/VM/StackTracesTree-NoRuntime.h"
#include "hermes/VM/SymbolRegistry.h"
#include "hermes/VM/TimeLimitMonitor.h"
#include "hermes/VM/TwineChar16.h"
#include "hermes/VM/VMExperiments.h"

#ifdef HERMESVM_PROFILER_BB
#include "hermes/VM/Profiler/InlineCacheProfiler.h"
#endif

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/SmallVector.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <type_traits>
#include <vector>

#ifdef __EMSCRIPTEN__
                                                                       
                                                                           
                                           
extern "C" bool test_wasm_host_timeout();
extern "C" bool test_and_clear_wasm_host_timeout();
#endif

namespace hermes {
                       
class JSONEmitter;

namespace inst {
struct Inst;
enum class OpCode : uint8_t;
}                  

namespace hbc {
class BytecodeModule;
struct CompileFlags;
}                 

namespace vm {

                                 
class CodeBlock;
class Environment;
class Interpreter;
class JSObject;
class PropertyAccessor;
struct JSLibStorage;
struct RuntimeOffsets;
class ScopedNativeDepthReducer;
class ScopedNativeDepthTracker;
class ScopedNativeCallFrame;
class CodeCoverageProfiler;
struct StackTracesTree;

#if HERMESVM_SAMPLING_PROFILER_AVAILABLE
class SamplingProfiler;
#endif                                        

#ifdef HERMESVM_PROFILER_BB
class JSArray;
#endif

                                                                          
                                                                          
                                         
static const unsigned STACK_RESERVE = 32;

                                                          
using ObjectID = uint32_t;

#define PROP_CACHE_IDS(V) V(RegExpLastIndex, Predefined::lastIndex)

                                                           
enum class PropCacheID {
#define V(id, predef) id,
  PROP_CACHE_IDS(V)
#undef V
      _COUNT
};

                                                             
class CrashTraceImpl {
                                              
  struct Record {
                                           
    uint32_t ipOffset;
                                            
    inst::OpCode opCode;
  };

 public:
                                                                      
                   
  inline void recordModule(
      uint32_t segmentID,
      llvh::StringRef sourceURL,
      llvh::StringRef sourceHash);

                                                
  void recordInst(uint32_t ipOffset, inst::OpCode opCode) {
    static_assert(
        kTraceLength && (kTraceLength & (kTraceLength - 1)) == 0,
        "kTraceLength must be a power of 2");
    unsigned n = (last_ + 1) & (kTraceLength - 1);
    last_ = n;
    Record *p = trace_ + n;
    p->ipOffset = ipOffset;
    p->opCode = opCode;
  }

 private:
                                  
  static constexpr unsigned kTraceLength = 8;
                                                        
  unsigned last_ = kTraceLength - 1;
                                  
  Record trace_[kTraceLength] = {};

                        
  uint32_t segmentID_ = 0;
                                             
  char sourceURL_[16] = {};
                       
  uint8_t sourceHash_[20] = {};
};

inline void CrashTraceImpl::recordModule(
    uint32_t segmentID,
    llvh::StringRef sourceURL,
    llvh::StringRef sourceHash) {
  segmentID_ = segmentID;
  size_t len = std::min(sizeof(sourceURL_) - 1, sourceURL.size());
  ::memcpy(sourceURL_, sourceURL.data(), len);
  sourceURL_[len] = 0;
  ::memcpy(
      sourceHash_,
      sourceHash.data(),
      std::min(sizeof(sourceHash_), sourceHash.size()));
}

class CrashTraceNoop {
 public:
  void recordModule(
      uint32_t segmentID,
      llvh::StringRef sourceURL,
      llvh::StringRef sourceHash) {}

                                                
  void recordInst(uint32_t ipOffset, inst::OpCode opCode) {}
};

#ifndef HERMESVM_CRASH_TRACE
                                                      
#define HERMESVM_CRASH_TRACE 0
#endif

#if HERMESVM_CRASH_TRACE
using CrashTrace = CrashTraceImpl;
#else
using CrashTrace = CrashTraceNoop;
#endif

                                                                               
                                                         
class HERMES_EMPTY_BASES Runtime : public PointerBase,
                                   public HandleRootOwner,
                                   private GCBase::GCCallbacks {
 public:
  static std::shared_ptr<Runtime> create(const RuntimeConfig &runtimeConfig);

  ~Runtime() override;

                                                                               
                                                                         
              
  void addCustomRootsFunction(
      std::function<void(GC *, RootAcceptor &)> markRootsFn);

                                                                         
                                                                              
              
  void addCustomWeakRootsFunction(
      std::function<void(GC *, WeakRootAcceptor &)> markRootsFn);

                                                                                
                             
                                                                             
                       
                                                                             
                                               
  void addCustomSnapshotFunction(
      std::function<void(HeapSnapshot &)> nodes,
      std::function<void(HeapSnapshot &)> edges);

                                                                            
                                                                            
                                                                   
                                                        
                                          
  CallResult<HermesValue> run(
      llvh::StringRef code,
      llvh::StringRef sourceURL,
      const hbc::CompileFlags &compileFlags);

                                                                            
                                                                   
                                                        
                                          
  CallResult<HermesValue> run(
      std::unique_ptr<Buffer> code,
      llvh::StringRef sourceURL,
      const hbc::CompileFlags &compileFlags);

                                                                             
                                                                                
                                                                            
                                                                         
                                                                              
                                              
  CallResult<HermesValue> runBytecode(
      std::shared_ptr<hbc::BCProvider> &&bytecode,
      RuntimeModuleFlags runtimeModuleFlags,
      llvh::StringRef sourceURL,
      Handle<Environment> environment,
      Handle<> thisArg);

                                                                              
                                                                             
           
                                                 
                                                                         
                        
  CallResult<HermesValue> runBytecode(
      std::shared_ptr<hbc::BCProvider> &&bytecode,
      RuntimeModuleFlags runtimeModuleFlags,
      llvh::StringRef sourceURL,
      Handle<Environment> environment) {
    getHeap().runtimeWillExecute();
    return runBytecode(
        std::move(bytecode),
        runtimeModuleFlags,
        sourceURL,
        environment,
        Handle<>(&global_));
  }

  ExecutionStatus loadSegment(
      std::shared_ptr<hbc::BCProvider> &&bytecode,
      Handle<RequireContext> requireContext,
      RuntimeModuleFlags flags = {});

                                                                            
                                                             
  Handle<JSObject> runInternalBytecode();

                                                               
  void printException(llvh::raw_ostream &os, Handle<> valueHandle);

                           
        

                                           
                                                                 
                        
                                                                   
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

                                                                          
                     
                                                                        
                   
  template <typename T>
  T ignoreAllocationFailure(CallResult<T> res);

                                                                          
                     
  void ignoreAllocationFailure(ExecutionStatus status);

                                                                         
                                                       
  void ttiReached();

                                       
  void collect(std::string cause) {
    getHeap().collect(std::move(cause));
  }

                                                             
  void potentiallyMoveHeap();

  using HandleRootOwner::makeHandle;
  using HandleRootOwner::makeMutableHandle;

                                                               
  template <class T>
  inline Handle<T> makeHandle(const GCPointer<T> &p);

                                                                      
  template <class T>
  MutableHandle<T> makeMutableHandle(const GCPointer<T> &p);

                                                            
  StringPrimitive *getPredefinedString(Predefined::Str predefined);
  StringPrimitive *getPredefinedString(Predefined::Sym predefined);

                                                                  
  Handle<StringPrimitive> getPredefinedStringHandle(Predefined::Str predefined);
  Handle<StringPrimitive> getPredefinedStringHandle(Predefined::Sym predefined);

                                                             
  inline StringPrimitive *getStringPrimFromSymbolID(SymbolID id);

                                                                             
                                             
  bool symbolEqualsToStringPrim(SymbolID id, StringPrimitive *strPrim);

                                                                          
  struct FormatSymbolID {
    Runtime &runtime;
    SymbolID const symbolID;

    FormatSymbolID(Runtime &runtime, SymbolID symbolID)
        : runtime(runtime), symbolID(symbolID) {}
  };

                                                                               
                    
  FormatSymbolID formatSymbolID(SymbolID id);

  GC &getHeap() {
    return *heapStorage_.get();
  }

        

                                                              
                                                                              
                                 
  inline Callable *getBuiltinCallable(unsigned builtinMethodID);

                                                             
                                                                            
  inline void enqueueJob(Callable *job);

                              
                                                                       
     
                                                                          
                                                                              
                                                             
                                                                             
                                                                            
     
                                                                             
                                                                             
                                                                               
                                                                    
  ExecutionStatus drainJobs();

                                                                               
                                                                          
                                                              
  ExecutionStatus addToKeptObjects(Handle<JSObject> obj);

                                                
                                                                                
                                                                           
                                                               
  void clearKeptObjects();

  IdentifierTable &getIdentifierTable() {
    return identifierTable_;
  }

  SymbolRegistry &getSymbolRegistry() {
    return symbolRegistry_;
  }

                                                                              
                                                                          
  Handle<StringPrimitive> getCharacterString(char16_t ch);

  CodeBlock *getEmptyCodeBlock() const {
    assert(emptyCodeBlock_ && "Invalid empty code block");
    return emptyCodeBlock_;
  }

  CodeBlock *getReturnThisCodeBlock() const {
    assert(returnThisCodeBlock_ && "Invalid return this code block");
    return returnThisCodeBlock_;
  }

                                        
  ObjectID generateNextObjectID() {
    return ++nextObjectID_;
  }

                                                                       
                                                                     
                                 
  uint64_t gcStableHashHermesValue(Handle<HermesValue> value);

                           
        

                                        
  PinnedHermesValue *getStackPointer() {
    return stackPointer_;
  }

                                                                      
  inline void popToSavedStackPointer(PinnedHermesValue *stackPointer);

                                                  
  inline uint32_t getStackLevel() const;

                                                     
  inline uint32_t availableStackSize() const;

                                                                               
                
  inline bool checkAvailableStack(uint32_t count);

                                                                           
                                       
                                    
  inline PinnedHermesValue *allocUninitializedStack(uint32_t count);

                                                                    
                   
                                                     
  LLVM_ATTRIBUTE_NOINLINE
  void allocStack(uint32_t count, HermesValue initValue);

                                                                                
                                      
                                                   
                                                                          
                                                   
  inline bool checkAndAllocStack(uint32_t count, HermesValue initValue);

                                                          
  inline void popStack(uint32_t count);

                                        
  StackFramePtr getCurrentFrame() {
    return currentFrame_;
  }

                                                                              
         
                                                                            
                                                                           
                                                                            
                                                                          
  inline void setCurrentFrameToTopOfStack(StackFramePtr topFrame);

                                                                              
         
                                                         
  inline StackFramePtr setCurrentFrameToTopOfStack();

                                                                         
                                                  
                                                                      
                                                                            
                                                                        
                                                                        
                     
                                                             
  inline StackFramePtr restoreStackAndPreviousFrame(StackFramePtr currentFrame);

                                                                         
                                                  
                                                             
  inline StackFramePtr restoreStackAndPreviousFrame();

                                                                        
                                     
  inline llvh::iterator_range<StackFrameIterator> getStackFrames();

                                                                        
                                     
  inline llvh::iterator_range<ConstStackFrameIterator> getStackFrames() const;

                                                       
  void dumpCallFrames(llvh::raw_ostream &OS);

                                                                        
                                                          
  void dumpCallFrames();

                                                                       
                                                                            
                                                                         
                                                               
  inline bool isStackOverflowing();

                                                                
  inline StackOverflowGuard getOverflowGuardForRegex();

                            
  HermesValue getThrownValue() const {
    return thrownValue_;
  }

                                                                         
                                                   
  ExecutionStatus setThrownValue(HermesValue value);

                                 
  void clearThrownValue();

                                                                           
                                                                   
  inline Handle<HiddenClass> getHiddenClassForPrototype(
      JSObject *proto,
      unsigned reservedSlots);

                               
  Handle<JSObject> getGlobal();

                                                    
  std::vector<llvh::ArrayRef<uint8_t>> getEpilogues();

  void printHeapStats(llvh::raw_ostream &os);

                                                                  
                                                                       
                                                                           
                                                                                
                           
  void getIOTrackingInfoJSON(llvh::raw_ostream &os);

#ifndef NDEBUG
                                                                               
  void printArrayCensus(llvh::raw_ostream &os);
#endif

                                           
  JSLibStorage *getJSLibStorage() {
    return jsLibStorage_.get();
  }

  const GCExecTrace &getGCExecTrace() {
    return getHeap().getGCExecTrace();
  }

#if defined(HERMES_ENABLE_DEBUGGER)
                                                                                
                                                                                
                     
  void triggerDebuggerAsyncBreak(
      ::facebook::hermes::debugger::AsyncPauseKind kind) {
    triggerAsyncBreak(
        kind == ::facebook::hermes::debugger::AsyncPauseKind::Explicit
            ? AsyncBreakReasonBits::DebuggerExplicit
            : AsyncBreakReasonBits::DebuggerImplicit);
  }
#endif

                                                                                
                                                                           
                                  
  void triggerTimeoutAsyncBreak() {
    triggerAsyncBreak(AsyncBreakReasonBits::Timeout);
  }

#ifdef HERMES_ENABLE_DEBUGGER
                                                                        
                                                                       
                           
  struct StackFrameInfo {
    ConstStackFramePtr frame;
    bool isGlobal;
  };

                                                             
                                                                           
                                                                                
  llvh::Optional<StackFrameInfo> stackFrameInfoByIndex(uint32_t frameIdx) const;

                                                                            
                                                                              
           
  uint32_t calcFrameOffset(ConstStackFrameIterator it) const;

                                                                          
                                                                        
  uint32_t getCurrentFrameOffset() const;
#endif

                                                                          
                                    
                                        
  LLVM_NODISCARD ExecutionStatus raiseError(const TwineChar16 &msg);

                                                                               
                                    
                                                                       
  LLVM_NODISCARD ExecutionStatus raiseTypeError(Handle<> message);

                                                                          
              
                                        
  LLVM_NODISCARD ExecutionStatus raiseTypeError(const TwineChar16 &msg);

                                                                          
                                                                       
                  
                                        
  LLVM_NODISCARD ExecutionStatus
  raiseTypeErrorForValue(Handle<> value, llvh::StringRef msg) {
    return raiseTypeErrorForValue("", value, msg);
  }

                                                                          
                                                                          
                                                            
  LLVM_NODISCARD ExecutionStatus raiseTypeErrorForValue(
      const TwineChar16 &msg1,
      Handle<> value,
      const TwineChar16 &msg2);

                                                                          
                                                                               
                                                                      
                                                                   
                                
  LLVM_NODISCARD ExecutionStatus raiseTypeErrorForCallable(Handle<> callable);

                                                              
                                        
  LLVM_NODISCARD ExecutionStatus raiseSyntaxError(const TwineChar16 &msg);

                                                                          
  LLVM_NODISCARD ExecutionStatus raiseEvalUnsupported(llvh::StringRef code);

                                      
                                        
  LLVM_NODISCARD ExecutionStatus raiseRangeError(const TwineChar16 &msg);

                                          
                                        
  LLVM_NODISCARD ExecutionStatus raiseReferenceError(const TwineChar16 &msg);

                                    
                                        
  LLVM_NODISCARD ExecutionStatus raiseURIError(const TwineChar16 &msg);

  enum class StackOverflowKind {
                                           
    JSRegisterStack,
                                                           
                                                                  
                              
    NativeStack,
                                                                      
                                                    
    JSONParser,
                                                        
    JSONStringify,
  };

                                                                            
                                                                     
                                                                    
                                        
  LLVM_NODISCARD ExecutionStatus raiseStackOverflow(StackOverflowKind kind);

                                                                        
  LLVM_NODISCARD ExecutionStatus raiseQuitError();

                                                                        
  LLVM_NODISCARD ExecutionStatus raiseTimeoutError();

                                                                        
  LLVM_NODISCARD ExecutionStatus
  raiseUncatchableError(Handle<JSObject> prototype, llvh::StringRef errMessage);

                                                                          
                                                                     
  CallResult<HermesValue> interpretFunction(CodeBlock *newCodeBlock);

#ifdef HERMES_ENABLE_DEBUGGER
                                                                      
  ExecutionStatus stepFunction(InterpreterState &state);
#endif

                                                                           
                    
                                       
  bool insertVisitedObject(JSObject *obj);

                                                                              
                                                                           
                                                    
  void removeVisitedObject(JSObject *obj);

                                                                              
  CallResult<PseudoHandle<>> getNamed(Handle<JSObject> obj, PropCacheID id);

                                                                               
                               
  ExecutionStatus putNamedThrowOnError(
      Handle<JSObject> obj,
      PropCacheID id,
      SmallHermesValue hv);

        

#define RUNTIME_HV_FIELD(name) PinnedHermesValue name{};
#define RUNTIME_HV_FIELD_PROTOTYPE(name) RUNTIME_HV_FIELD(name)
#define RUNTIME_HV_FIELD_INSTANCE(name) RUNTIME_HV_FIELD(name)
#define RUNTIME_HV_FIELD_RUNTIMEMODULE(name) RUNTIME_HV_FIELD(name)
#include "hermes/VM/RuntimeHermesValueFields.def"
#undef RUNTIME_HV_FIELD

                                 
  JSObject *objectPrototypeRawPtr{};

  JSObject *functionPrototypeRawPtr{};

  RegExpMatch regExpLastMatch{};

                                              
  const bool enableEval : 1;
                                                                             
  const bool verifyEvalIR : 1;
                                                                                
           
  const bool optimizedEval : 1;
                                                               
  const bool asyncBreakCheckInEval : 1;
                                                
  const bool enableBlockScopingInEval : 1;

  const SynthTraceMode traceMode;

#ifdef HERMESVM_PROFILER_OPCODE
                                                            
  uint32_t opcodeExecuteFrequency[256] = {0};

                                                                        
  uint64_t timeSpent[256] = {0};

                                    
  void dumpOpcodeStats(llvh::raw_ostream &os) const;
#endif

#if defined(HERMESVM_PROFILER_JSFUNCTION)
  static std::atomic<ProfilerID> nextProfilerId;

  std::vector<ProfilerFunctionInfo> functionInfo{};

                                                                         
  ProfilerID getProfilerID(CodeBlock *block);

                                                                     
                                          
  const ProfilerFunctionInfo *getProfilerInfo(ProfilerID id);

                                          
  uint32_t maxStackLevel = 0;
#endif

#if defined(HERMESVM_PROFILER_JSFUNCTION)
  std::vector<ProfilerFunctionEvent> functionEvents{};

                                                       
  uint64_t opcodeCount = 0;

                                              
  enum class ProfileType { TIME, OPCODES, ALL };
  void dumpJSFunctionStats(ProfileType type = ProfileType::ALL);
#endif

#ifdef HERMESVM_PROFILER_BB
  BasicBlockExecutionInfo &getBasicBlockExecutionInfo();

                                                             
  void dumpBasicBlockProfileTrace(llvh::raw_ostream &OS);
#endif

  CodeCoverageProfiler &getCodeCoverageProfiler() {
    return *codeCoverageProfiler_;
  }

#if HERMESVM_SAMPLING_PROFILER_AVAILABLE
                                                                                
                                                                         
  std::unique_ptr<SamplingProfiler> samplingProfiler;
#endif                                        

                                               
  std::shared_ptr<TimeLimitMonitor> timeLimitMonitor;

#ifdef HERMESVM_PROFILER_NATIVECALL
                                         
  void dumpNativeCallStats(llvh::raw_ostream &OS);
#endif

#ifdef HERMES_ENABLE_DEBUGGER
  Debugger &getDebugger() {
    return debugger_;
  }
#endif

  RuntimeModuleList &getRuntimeModules() {
    return runtimeModuleList_;
  }

  bool hasES6Promise() const {
    return hasES6Promise_;
  }

  bool hasES6Proxy() const {
    return hasES6Proxy_;
  }

  bool hasES6Class() const {
#ifndef HERMES_FACEBOOK_BUILD
    return hasES6Class_;
#else
    return false;
#endif
  }

  bool hasIntl() const {
    return hasIntl_;
  }

  bool hasArrayBuffer() const {
    return hasArrayBuffer_;
  }

  bool hasMicrotaskQueue() const {
    return hasMicrotaskQueue_;
  }

  bool builtinsAreFrozen() const {
    return builtinsFrozen_;
  }

  experiments::VMExperimentFlags getVMExperimentFlags() const {
    return vmExperimentFlags_;
  }

                                                      
  inline CrashManager &getCrashManager();

                                                                          
                                                                       
                
                                                   
  std::string getCallStackNoAlloc(const Inst *ip);

                                                                              
                                                                                
                                     
  std::string getCallStackNoAlloc() override {
    return getCallStackNoAlloc(nullptr);
  }

                                                                              
                                           
  bool formattingStackTrace() const {
    return formattingStackTrace_;
  }

                                                                           
                                           
  void setFormattingStackTrace(bool value) {
    assert(
        value != formattingStackTrace() &&
        "All calls to setFormattingStackTrace must actually change the current state");
    formattingStackTrace_ = value;
  }

                                                                                
                     
  static constexpr unsigned MAX_NATIVE_CALL_FRAME_DEPTH =
#ifdef HERMES_LIMIT_STACK_DEPTH
                                                                            
                                       
      30
#elif defined(_MSC_VER) && defined(__clang__) && defined(HERMES_SLOW_DEBUG)
      30
#elif defined(_MSC_VER) && defined(HERMES_SLOW_DEBUG)
                                                                            
                                                                 
      128
#elif defined(_MSC_VER) && defined(__clang__) && !defined(NDEBUG)
      128
#elif defined(_MSC_VER) && !NDEBUG
      192
#else
                                                     
                                                                  
                                                                         
                                                                               
      384
#endif
      ;

                                                                      
  void onGCEvent(GCEventKind kind, const std::string &extraInfo) override;

#ifdef HERMESVM_PROFILER_BB
  using ClassId = InlineCacheProfiler::ClassId;

                                                       
                                                                         
  llvh::Optional<std::tuple<std::string, uint32_t, uint32_t>>
  getIPSourceLocation(const CodeBlock *codeBlock, const Inst *ip);

                                                                         
                
  void preventHCGC(HiddenClass *hc);

                                                     
  void recordHiddenClass(
      CodeBlock *codeBlock,
      const Inst *cacheMissInst,
      SymbolID symbolID,
      HiddenClass *objectHiddenClass,
      HiddenClass *cachedHiddenClass);

                                                            
  HiddenClass *resolveHiddenClassId(ClassId classId);

                                       
  void getInlineCacheProfilerInfo(llvh::raw_ostream &ostream);
#endif

 private:
                                                                   
  CallResult<HermesValue> interpretFunctionImpl(CodeBlock *newCodeBlock);

 private:
  explicit Runtime(
      std::shared_ptr<StorageProvider> provider,
      const RuntimeConfig &runtimeConfig);

                                                                                
                                                             
                                                              
                                                                         
                                 
  void markRoots(RootAndSlotAcceptorWithNames &acceptor, bool markLongLived)
      override;

                                                                              
                                                      
  void markWeakRoots(WeakRootAcceptor &weakAcceptor, bool markLongLived)
      override;

                                                                               
                                                                             
                                        
  void markDomainRefInRuntimeModules(WeakRootAcceptor &weakRootAcceptor);

                                                  
  void markRootsForCompleteMarking(
      RootAndSlotAcceptorWithNames &acceptor) override;

                                                                        
                                                                             
                                                                         
                                  
  void visitIdentifiers(
      const std::function<void(SymbolID, const StringPrimitive *)> &acceptor)
      override;

#ifdef HERMESVM_PROFILER_BB
 public:
#endif
                                                                    
  std::string convertSymbolToUTF8(SymbolID id) override;

                                                                    
                                                                    
                               
  void printRuntimeGCStats(JSONEmitter &json) const override;

                                                                              
                                                                        
                                                                  
  virtual unsigned getSymbolsEnd() const override;

                                                                           
                                                              
  virtual void unmarkSymbols() override;

                                                                                
                    
  virtual void freeSymbols(const llvh::BitVector &markedSymbols) override;

#ifdef HERMES_SLOW_DEBUG
                                                                        
            
  virtual bool isSymbolLive(SymbolID id) override;

                                                                        
                
  virtual const void *getStringForSymbol(SymbolID id) override;
#endif

                                     
  size_t mallocSize() const override;

                                                                       
                                                  
                                                   
  static std::unique_ptr<Buffer> generateSpecialRuntimeBytecode();

                                                             
                                                                                
                                           
  void initPredefinedStrings();

                                                                          
                
  void initCharacterStrings();

                                                                           
                                                                     
                                                                               
                           
                                                                          
                 
                                                                 
  using ForEachPublicNativeBuiltinCallback = ExecutionStatus(
      unsigned methodIndex,
      Predefined::Str objectName,
      Handle<JSObject> &object,
      SymbolID methodID);

                                                                             
                  
                                                                              
                                                                           
                                      
                                                              
  ExecutionStatus forEachPublicNativeBuiltin(
      const std::function<ForEachPublicNativeBuiltinCallback> &callback);

                                                       
                                                                               
                                                                             
  void initNativeBuiltins();

                                                                           
                                                         
  void initJSBuiltins(
      llvh::MutableArrayRef<Callable *> builtins,
      Handle<JSObject> jsBuiltins);

                                                                                
                                                                                
                   
  ExecutionStatus assertBuiltinsUnmodified();

                                                                              
                                                       
  void freezeBuiltins();

                                                                              
                                            
  Handle<StringPrimitive> allocateCharacterString(char16_t ch);

                                                              
  void addRuntimeModule(RuntimeModule *rm) {
    runtimeModuleList_.push_back(*rm);
  }

                                                                   
  void removeRuntimeModule(RuntimeModule *rm);

                                                                                
                                                                             
                                                                           
                                                       
  void crashCallback(int fd);

                                                                 
  void crashWriteCallStack(JSONEmitter &json);

 private:
  GCStorage heapStorage_;

  std::vector<std::function<void(GC *, RootAcceptor &)>> customMarkRootFuncs_;
  std::vector<std::function<void(GC *, WeakRootAcceptor &)>>
      customMarkWeakRootFuncs_;
  std::vector<std::function<void(HeapSnapshot &)>> customSnapshotNodeFuncs_;
  std::vector<std::function<void(HeapSnapshot &)>> customSnapshotEdgeFuncs_;

                                                  
  const bool hasES6Promise_;

                                                
  const bool hasES6Proxy_;

                                               
  const bool hasES6Class_;

                                                         
  const bool hasIntl_;

                                                                             
  const bool hasArrayBuffer_;

                                             
  const bool hasMicrotaskQueue_;

                                                             
  const bool shouldRandomizeMemoryLayout_;

                                                                              
  const uint8_t bytecodeWarmupPercent_;

                                                     
  const bool trackIO_;

                                                                               
                                
  bool formattingStackTrace_{false};

                                                                           
                                                                        
                                                                              
                                                                        
                                                                               
                                                       
  experiments::VMExperimentFlags vmExperimentFlags_{experiments::Default};

  friend class GCScope;
  friend class HandleBase;
  friend class Interpreter;
  friend class RuntimeModule;
  friend class MarkRootsPhaseTimer;
  friend struct RuntimeOffsets;
  friend class ScopedNativeDepthReducer;
  friend class ScopedNativeDepthTracker;
  friend class ScopedNativeCallFrame;

  class StackRuntime;
  class MarkRootsPhaseTimer;

                                                                                
                                                                              
  std::chrono::time_point<std::chrono::steady_clock> startOfMarkRoots_;
                                                                     
  double markRootsPhaseTimes_[static_cast<unsigned>(
      RootAcceptor::Section::NumSections)] = {};
                                                               
  double totalMarkRootsTime_ = 0.0;

                                                                     
  ObjectID nextObjectID_{0};

                           
  IdentifierTable identifierTable_{};

                                 
  SymbolRegistry symbolRegistry_{};

                                                               
  std::unique_ptr<JSLibStorage> jsLibStorage_;

                                              
                                              
  CodeBlock *emptyCodeBlock_{};

                                                
                                              
  CodeBlock *returnThisCodeBlock_{};

                                                                            
                                                                               
                                              
  RuntimeModule *specialCodeBlockRuntimeModule_{};

                                                                             
                                                                          
                                                                           
                                                                    
  RuntimeModuleList runtimeModuleList_{};

                                                                            
  CrashTrace crashTrace_{};

                            
        

                                                                             
                        
  llvh::MutableArrayRef<PinnedHermesValue> registerStackAllocation_;
  PinnedHermesValue *registerStackStart_;
  PinnedHermesValue *registerStackEnd_;
  PinnedHermesValue *stackPointer_;
                                                     
  std::shared_ptr<CrashManager> crashMgr_;
                                                                              
                                                                       
                                 
  StackFramePtr currentFrame_{nullptr};

                                                                              
                                  
  StackOverflowGuard overflowGuard_;

                                                                            
                                     
  std::array<
      PinnedHermesValue,
      InternalProperty::NumAnonymousInternalProperties + 1>
      rootClazzes_;

                                                
  PropertyCacheEntry fixedPropCache_[(size_t)PropCacheID::_COUNT];

                                                                 
                                                                     
                                                      
  std::vector<PinnedHermesValue> charStrings_{};

                                                                              
                                            
  std::vector<JSObject *> stringCycleCheckVisited_{};

                                                       
  std::vector<Callable *> builtins_{};

                                                                           
  bool builtinsFrozen_{false};

                                       
                                                           
     
                                                                              
                                                                            
                                                                             
                                                                              
     
                                                                              
                                                                
                                                                               
                                                                              
                                                                               
     
                                                                              
                                                                              
                                                                          
                                                                              
                                                                             
                                                                     
  std::deque<Callable *> jobQueue_{};

#ifdef HERMESVM_PROFILER_BB
  BasicBlockExecutionInfo basicBlockExecInfo_;

                                                
  InlineCacheProfiler inlineCacheProfiler_;
#endif

                                                        
  facebook::hermes::debugger::ScriptID nextScriptId_{1};

                                                                      
                                                      
  const CrashManager::CallbackKey crashCallbackKey_;

                                            
  const std::unique_ptr<CodeCoverageProfiler> codeCoverageProfiler_;

                                                
  enum class AsyncBreakReasonBits : uint8_t {
    DebuggerExplicit = 0x1,
    DebuggerImplicit = 0x2,
    Timeout = 0x4,
  };

                                                          
                                                                    
                                      
                                                    
  std::atomic<uint8_t> asyncBreakRequestFlag_{0};

#if defined(HERMES_ENABLE_DEBUGGER)
                                                                            
                                                                              
                         
  uint8_t testAndClearDebuggerAsyncBreakRequest() {
    return testAndClearAsyncBreakRequest(
        (uint8_t)AsyncBreakReasonBits::DebuggerExplicit |
        (uint8_t)AsyncBreakReasonBits::DebuggerImplicit);
  }

  Debugger debugger_{*this};
#endif

                                                                         
                                                                               
                                                                   
  std::vector<std::shared_ptr<hbc::BCProvider>> persistentBCProviders_;

                                             
  std::function<void(GCEventKind, const char *)> gcEventCallback_;

        

                                                          
  bool hasAsyncBreak() const {
    return asyncBreakRequestFlag_.load(std::memory_order_relaxed) != 0
#ifdef __EMSCRIPTEN__
        || test_wasm_host_timeout()
#endif
        ;
  }

                                                                               
                                         
  uint8_t testAndClearAsyncBreakRequest(uint8_t reasonBits) {
                                                                             
                                                                                
             
    uint8_t flag = asyncBreakRequestFlag_.load(std::memory_order_relaxed);
    if (LLVM_LIKELY((flag & (uint8_t)reasonBits) == 0)) {
                   
      return false;
    }
                                
    uint8_t oldFlag = asyncBreakRequestFlag_.fetch_and(
        ~(uint8_t)reasonBits, std::memory_order_relaxed);
    assert(oldFlag != 0 && "Why is oldFlag zero?");
    return oldFlag;
  }

                                                                         
                                    
  bool testAndClearTimeoutAsyncBreakRequest() {
    return testAndClearAsyncBreakRequest((uint8_t)AsyncBreakReasonBits::Timeout)
#ifdef __EMSCRIPTEN__
                                                                       
        | test_and_clear_wasm_host_timeout()
#endif
        ;
  }

                                                                
                            
  void triggerAsyncBreak(AsyncBreakReasonBits reason) {
    asyncBreakRequestFlag_.fetch_or((uint8_t)reason, std::memory_order_relaxed);
  }

                                           
  ExecutionStatus notifyTimeout();

 private:
#ifdef NDEBUG
                                                       
  const inst::Inst *currentIP_{nullptr};
#else
                                                                              
                                                                                
                                    
  llvh::Optional<const inst::Inst *> currentIP_{(const inst::Inst *)nullptr};

                                                                              
                
  uint32_t noRJSLevel_{0};

  friend class NoRJSScope;
#endif

 public:
                                                                              
                                                                              
                                                                             
                                                                                
                                                                              
                                                                       
  inline void setCurrentIP(const inst::Inst *ip) {
    currentIP_ = ip;
  }

                                                                            
                                                                              
                                                                       
                                                                  
  inline const inst::Inst *getCurrentIP() const {
#ifdef NDEBUG
    return currentIP_;
#else
    assert(
        currentIP_.hasValue() &&
        "Current IP unknown - this probably means a CAPTURE_IP_* is missing in the interpreter.");
    return *currentIP_;
#endif
  }

                                                                 
  inline const inst::Inst *getCurrentIPSlow() const override {
    return getCurrentIP();
  }

#ifdef NDEBUG
  void invalidateCurrentIP() {}
#else
  void invalidateCurrentIP() {
    currentIP_.reset();
  }
#endif

                                                               
                                                                            
                            
  void saveCallerIPInStackFrame() {
#ifndef NDEBUG
    assert(
        (!currentFrame_.getSavedIP() ||
         (currentIP_.hasValue() && currentFrame_.getSavedIP() == currentIP_)) &&
        "The ip should either be null or already have the expected value");
#endif
    currentFrame_.getSavedIPRef() =
        HermesValue::encodeNativePointer(getCurrentIP());
  }

 private:
#ifdef HERMES_MEMORY_INSTRUMENTATION
                                                                               
                                                                          
                                                                              
              
  std::pair<const CodeBlock *, const inst::Inst *>
  getCurrentInterpreterLocation(const inst::Inst *initialSearchIP);

 public:
                                                                         
                                                                       
                                                                          
                                                                           
                                                                         
                                                                            
                                                                            
                                                                 
  StackTracesTreeNode *getCurrentStackTracesTreeNode(
      const inst::Inst *ip) override;

                                                                          
  StackTracesTree *getStackTracesTree() override {
    return stackTracesTree_.get();
  }

                                                                           
                 
                                            
                                                                             
                       
  inline void pushCallStack(const CodeBlock *codeBlock, const inst::Inst *ip) {
    if (stackTracesTree_) {
      pushCallStackImpl(codeBlock, ip);
    }
  }

                                                        
  inline void popCallStack() {
    if (stackTracesTree_) {
      popCallStackImpl();
    }
  }

  void enableAllocationLocationTracker() {
    enableAllocationLocationTracker(nullptr);
  }
  void enableAllocationLocationTracker(
      std::function<void(
          uint64_t,
          std::chrono::microseconds,
          std::vector<GCBase::AllocationLocationTracker::HeapStatsUpdate>)>
          fragmentCallback);

                                                                              
                                                                    
                                                                            
                                                                               
  void disableAllocationLocationTracker(bool clearExistingTree = false);

                                                                              
                                                                           
                           
                                                                              
                   
                                                                          
  void enableSamplingHeapProfiler(size_t samplingInterval, int64_t seed = -1);

                                                                            
  void disableSamplingHeapProfiler(llvh::raw_ostream &os);

 private:
  void popCallStackImpl();
  void pushCallStackImpl(const CodeBlock *codeBlock, const inst::Inst *ip);
  std::unique_ptr<StackTracesTree> stackTracesTree_;
#endif
};

                                                                      
template <typename T, XorPtrKeyID K>
class XorPtr {
  uintptr_t bits_;

 public:
  XorPtr() = default;
  XorPtr(Runtime &runtime, T *ptr) {
    set(runtime, ptr);
  }
  void set(Runtime &runtime, T *ptr) {
    set(runtime.getHeap(), ptr);
  }
  void set(GC &gc, T *ptr) {
    bits_ = reinterpret_cast<uintptr_t>(ptr) ^ gc.pointerEncryptionKey_[K];
  }
  T *get(Runtime &runtime) const {
    return get(runtime.getHeap());
  }
  T *get(GC &gc) const {
    return reinterpret_cast<T *>(bits_ ^ gc.pointerEncryptionKey_[K]);
  }
};

static_assert(
    std::is_trivial<XorPtr<void, XorPtrKeyID::_NumKeys>>::value,
    "XorPtr must be trivial");

                                                                         
class ScopedNativeDepthTracker {
  Runtime &runtime_;
                                                                    
  bool overflowed_;

 public:
  explicit ScopedNativeDepthTracker(Runtime &runtime) : runtime_(runtime) {
    (void)runtime_;
#ifndef HERMES_CHECK_NATIVE_STACK
    ++runtime.overflowGuard_.callDepth;
#endif
    overflowed_ = runtime.isStackOverflowing();
  }
  ~ScopedNativeDepthTracker() {
#ifndef HERMES_CHECK_NATIVE_STACK
    --runtime_.overflowGuard_.callDepth;
#endif
  }

                                                                
  bool overflowed() const {
    return overflowed_;
  }
};

                                                                     
                                                                    
                                                                   
                                                                 
class ScopedNativeDepthReducer {
  Runtime &runtime_;
#ifdef HERMES_CHECK_NATIVE_STACK
  unsigned nativeStackGapOld;
                                     
  static constexpr int kReducedNativeStackGap =
#if LLVM_ADDRESS_SANITIZER_BUILD
      128 * 1024;
#else
      32 * 1024;
#endif
#else
  bool undo = false;
                                     
  static constexpr int kDepthAdjustment = 3;
#endif

 public:
#ifdef HERMES_CHECK_NATIVE_STACK
  explicit ScopedNativeDepthReducer(Runtime &runtime)
      : runtime_(runtime),
        nativeStackGapOld(runtime.overflowGuard_.nativeStackGap) {
                                                                               
                                                                          
                                                                          
                
    runtime_.overflowGuard_.nativeStackGap = kReducedNativeStackGap;
  }
  ~ScopedNativeDepthReducer() {
    assert(
        runtime_.overflowGuard_.nativeStackGap == kReducedNativeStackGap &&
        "ScopedNativeDepthReducer gap was overridden");
    runtime_.overflowGuard_.nativeStackGap = nativeStackGapOld;
                                                       
    runtime_.overflowGuard_.clearStackBounds();
  }
#else
  explicit ScopedNativeDepthReducer(Runtime &runtime) : runtime_(runtime) {
    if (runtime.overflowGuard_.callDepth >= kDepthAdjustment) {
      runtime.overflowGuard_.callDepth -= kDepthAdjustment;
      undo = true;
    }
  }
  ~ScopedNativeDepthReducer() {
    if (undo) {
      runtime_.overflowGuard_.callDepth += kDepthAdjustment;
    }
  }
#endif

 private:
                                                                       
  static void staticAsserts();
};

                                                                         
                                                                              
                                                                              
                                                                          
                                                                             
                         
                                                                                
                                                                                
                     
class ScopedNativeCallFrame {
                                      
  Runtime &runtime_;

                                                                
  PinnedHermesValue *const savedSP_;

                                    
  StackFramePtr frame_;

                                         
  bool overflowed_;

#ifndef NDEBUG
                                                                   
  mutable bool overflowHasBeenChecked_{false};
#endif

                                                                                
                                                                            
                                           
  static bool runtimeCanAllocateFrame(
      Runtime &runtime,
      uint32_t registersNeeded) {
    return runtime.checkAvailableStack(registersNeeded) &&
        !runtime.isStackOverflowing();
  }

 public:
                                                                              
                                                                            
                                                                                
                                                                   
                                                                            
                                     
                                                                              
                       
                                                                             
                                                        
  ScopedNativeCallFrame(
      Runtime &runtime,
      uint32_t argCount,
      HermesValue callee,
      HermesValue newTarget,
      HermesValue thisArg)
      : runtime_(runtime), savedSP_(runtime.getStackPointer()) {
#ifndef HERMES_CHECK_NATIVE_STACK
    runtime.overflowGuard_.callDepth++;
#endif
    uint32_t registersNeeded =
        StackFrameLayout::callerOutgoingRegisters(argCount);
    overflowed_ = !runtimeCanAllocateFrame(runtime, registersNeeded);
    if (LLVM_UNLIKELY(overflowed_)) {
      return;
    }

                                                                             
                                                          
    auto *stack = runtime.allocUninitializedStack(registersNeeded);
    frame_ = StackFramePtr::initFrame(
        stack,
        runtime.currentFrame_,
        nullptr,
        nullptr,
        argCount,
        callee,
        newTarget);
    frame_.getThisArgRef() = thisArg;
#if HERMES_SLOW_DEBUG
                                                                                
            
    assert(!overflowed_ && "Overflow should return early");
    overflowHasBeenChecked_ = true;
    fillArguments(argCount, HermesValue::encodeInvalidValue());
                                                    
    overflowHasBeenChecked_ = false;
#endif
  }

                                                                              
                                                                               
                                                                                
                  
                                                                             
                                                        
  ScopedNativeCallFrame(
      Runtime &runtime,
      uint32_t argCount,
      Callable *callee,
      bool construct,
      HermesValue thisArg)
      : ScopedNativeCallFrame(
            runtime,
            argCount,
            HermesValue::encodeObjectValue(callee),
            construct ? HermesValue::encodeObjectValue(callee)
                      : HermesValue::encodeUndefinedValue(),
            thisArg) {}

  ~ScopedNativeCallFrame() {
                                                                             
                                                  
#ifndef HERMES_CHECK_NATIVE_STACK
    runtime_.overflowGuard_.callDepth--;
#endif
    runtime_.popToSavedStackPointer(savedSP_);
#ifndef NDEBUG
                                                
    frame_ = StackFramePtr{};
#endif
  }

                                                                   
  void fillArguments(uint32_t argCount, HermesValue fillValue) {
    assert(overflowHasBeenChecked_ && "ScopedNativeCallFrame could overflow");
    assert(argCount == frame_.getArgCount() && "Arg count mismatch.");
    std::uninitialized_fill_n(frame_.argsBegin(), argCount, fillValue);
  }

                                                 
  bool overflowed() const {
#ifndef NDEBUG
    overflowHasBeenChecked_ = !overflowed_;
#endif
    return overflowed_;
  }

                                             
  StackFramePtr operator->() {
    assert(overflowHasBeenChecked_ && "ScopedNativeCallFrame could overflow");
    return frame_;
  }
};

#ifdef NDEBUG

                                                                              
                                                                               
class NoAllocScope {
 public:
  explicit NoAllocScope(Runtime &runtime) {}
  explicit NoAllocScope(GC &gc) {}
  NoAllocScope(const NoAllocScope &) = default;
  NoAllocScope(NoAllocScope &&) = default;
  NoAllocScope &operator=(const NoAllocScope &) = default;
  NoAllocScope &operator=(NoAllocScope &&rhs) = default;
  void release() {}

 private:
  NoAllocScope() = delete;
};
using NoHandleScope = NoAllocScope;
using NoRJSScope = NoAllocScope;

#else

                                                               
class BaseNoScope {
 public:
  explicit BaseNoScope(uint32_t *level) : level_(level) {
    assert(level_ && "constructing BaseNoScope with moved/release object");
    ++*level_;
  }

  BaseNoScope(const BaseNoScope &other) : BaseNoScope(other.level_) {}
  BaseNoScope(BaseNoScope &&other) : level_(other.level_) {
                                                                       
    other.level_ = nullptr;
  }

  ~BaseNoScope() {
    if (level_)
      release();
  }

  BaseNoScope &operator=(BaseNoScope &&rhs) {
    if (level_) {
      release();
    }

                                                                          
                                        
    auto ptr = rhs.level_;
    rhs.level_ = nullptr;
    level_ = ptr;
    return *this;
  }

  BaseNoScope &operator=(const BaseNoScope &other) {
    return *this = BaseNoScope(other.level_);
  }

                                                    
  void release() {
    assert(level_ && "already released");
    assert(*level_ > 0 && "unbalanced no alloc");
    --*level_;
    level_ = nullptr;
  }

 protected:
  uint32_t *level_;

 private:
  BaseNoScope() = delete;
};

                                                       
class NoHandleScope : public BaseNoScope {
 public:
  explicit NoHandleScope(Runtime &runtime)
      : BaseNoScope(&runtime.noHandleLevel_) {}
  using BaseNoScope::BaseNoScope;
  using BaseNoScope::operator=;
};

                                                                       
class NoAllocScope : public BaseNoScope {
 public:
  explicit NoAllocScope(Runtime &runtime) : NoAllocScope(runtime.getHeap()) {}
  explicit NoAllocScope(GC &gc) : BaseNoScope(&gc.noAllocLevel_) {}
  using BaseNoScope::BaseNoScope;
  using BaseNoScope::operator=;
};

                                                               
class NoRJSScope : public BaseNoScope {
 public:
  explicit NoRJSScope(Runtime &runtime) : BaseNoScope(&runtime.noRJSLevel_) {}
  using BaseNoScope::BaseNoScope;
  using BaseNoScope::operator=;
};
#endif

                                                                                
                          

inline void Runtime::addCustomRootsFunction(
    std::function<void(GC *, RootAcceptor &)> markRootsFn) {
  customMarkRootFuncs_.emplace_back(std::move(markRootsFn));
}

inline void Runtime::addCustomWeakRootsFunction(
    std::function<void(GC *, WeakRootAcceptor &)> markRootsFn) {
  customMarkWeakRootFuncs_.emplace_back(std::move(markRootsFn));
}

inline void Runtime::addCustomSnapshotFunction(
    std::function<void(HeapSnapshot &)> nodes,
    std::function<void(HeapSnapshot &)> edges) {
  customSnapshotNodeFuncs_.emplace_back(std::move(nodes));
  customSnapshotEdgeFuncs_.emplace_back(std::move(edges));
}

template <
    typename T,
    HasFinalizer hasFinalizer,
    LongLived longLived,
    class... Args>
T *Runtime::makeAFixed(Args &&...args) {
#ifndef NDEBUG
                                                                             
                                                                            
                                                                        
                                                
  (void)getCurrentIP();
#endif
  return getHeap().makeAFixed<T, hasFinalizer, longLived>(
      std::forward<Args>(args)...);
}

template <
    typename T,
    HasFinalizer hasFinalizer,
    LongLived longLived,
    class... Args>
T *Runtime::makeAVariable(uint32_t size, Args &&...args) {
#ifndef NDEBUG
                                                                             
                                                                            
                                                                        
                                                
  (void)getCurrentIP();
#endif
  return getHeap().makeAVariable<T, hasFinalizer, longLived>(
      size, std::forward<Args>(args)...);
}

template <typename T>
inline T Runtime::ignoreAllocationFailure(CallResult<T> res) {
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION))
    hermes_fatal("Unhandled out of memory exception");
                                                                     
                                                 
                                                        
  return std::move(res.getValue());
}

inline void Runtime::ignoreAllocationFailure(ExecutionStatus status) {
  if (LLVM_UNLIKELY(status == ExecutionStatus::EXCEPTION))
    hermes_fatal("Unhandled out of memory exception");
}

inline void Runtime::ttiReached() {
                                                          
  getHeap().ttiReached();
}

template <class T>
inline Handle<T> Runtime::makeHandle(const GCPointer<T> &p) {
  return Handle<T>(*this, p.get(*this));
}

template <class T>
inline MutableHandle<T> Runtime::makeMutableHandle(const GCPointer<T> &p) {
  return MutableHandle<T>(*this, p.get(*this));
}

inline StringPrimitive *Runtime::getPredefinedString(
    Predefined::Str predefined) {
  return getStringPrimFromSymbolID(Predefined::getSymbolID(predefined));
}

inline StringPrimitive *Runtime::getPredefinedString(
    Predefined::Sym predefined) {
  return getStringPrimFromSymbolID(Predefined::getSymbolID(predefined));
}

inline Handle<StringPrimitive> Runtime::getPredefinedStringHandle(
    Predefined::Str predefined) {
  return makeHandle(getPredefinedString(predefined));
}

inline Handle<StringPrimitive> Runtime::getPredefinedStringHandle(
    Predefined::Sym predefined) {
  return makeHandle(getPredefinedString(predefined));
}

inline StringPrimitive *Runtime::getStringPrimFromSymbolID(SymbolID id) {
  return identifierTable_.getStringPrim(*this, id);
}

#ifdef HERMESVM_PROFILER_BB
inline BasicBlockExecutionInfo &Runtime::getBasicBlockExecutionInfo() {
  return basicBlockExecInfo_;
}

inline void Runtime::dumpBasicBlockProfileTrace(llvh::raw_ostream &OS) {
  basicBlockExecInfo_.dump(OS);
}
#endif

inline Runtime::FormatSymbolID Runtime::formatSymbolID(SymbolID id) {
  return FormatSymbolID(*this, id);
}

inline void Runtime::popToSavedStackPointer(PinnedHermesValue *stackPointer) {
  assert(
      stackPointer <= stackPointer_ &&
      "attempting to pop the stack to a higher level");
  stackPointer_ = stackPointer;
}

inline uint32_t Runtime::getStackLevel() const {
  return (uint32_t)(stackPointer_ - registerStackStart_);
}

inline uint32_t Runtime::availableStackSize() const {
  return (uint32_t)(registerStackEnd_ - stackPointer_);
}

inline bool Runtime::checkAvailableStack(uint32_t count) {
                                                                            
                                                              
  return availableStackSize() >= (uint64_t)count + STACK_RESERVE;
}

inline PinnedHermesValue *Runtime::allocUninitializedStack(uint32_t count) {
  assert(availableStackSize() >= count && "register stack overflow");
  return stackPointer_ += count;
}

inline bool Runtime::checkAndAllocStack(uint32_t count, HermesValue initValue) {
  if (!checkAvailableStack(count))
    return false;
  allocStack(count, initValue);
  return true;
}

inline void Runtime::popStack(uint32_t count) {
  assert(getStackLevel() >= count && "register stack underflow");
  stackPointer_ += count;
}

inline void Runtime::setCurrentFrameToTopOfStack(StackFramePtr topFrame) {
  assert(
      topFrame.ptr() == stackPointer_ &&
      "topFrame must equal the top of stack");
  currentFrame_ = topFrame;
}

                                                                            
       
                                                       
inline StackFramePtr Runtime::setCurrentFrameToTopOfStack() {
  return currentFrame_ = StackFramePtr(stackPointer_);
}

inline StackFramePtr Runtime::restoreStackAndPreviousFrame(
    StackFramePtr currentFrame) {
  assert(
      currentFrame_ == currentFrame &&
      "currentFrame parameter must match currentFrame_");
  stackPointer_ = currentFrame.ptr();
  return currentFrame_ = currentFrame.getPreviousFrame();
}

inline StackFramePtr Runtime::restoreStackAndPreviousFrame() {
  return restoreStackAndPreviousFrame(currentFrame_);
}

inline llvh::iterator_range<StackFrameIterator> Runtime::getStackFrames() {
  return {
      StackFrameIterator{currentFrame_},
      StackFrameIterator{registerStackStart_}};
};

inline llvh::iterator_range<ConstStackFrameIterator> Runtime::getStackFrames()
    const {
  return {
      ConstStackFrameIterator{currentFrame_},
      ConstStackFrameIterator{registerStackStart_}};
};

inline StackOverflowGuard Runtime::getOverflowGuardForRegex() {
  StackOverflowGuard copy = overflowGuard_;
#ifndef HERMES_CHECK_NATIVE_STACK
                                                                                
                                                                               
                                                                             
                                                                                
                                                                             
                               
  constexpr uint32_t kRegexMaxDepthMult = 5;
  copy.maxCallDepth *= kRegexMaxDepthMult;
#endif
  return copy;
}

inline bool Runtime::isStackOverflowing() {
  return overflowGuard_.isOverflowing();
}

inline ExecutionStatus Runtime::setThrownValue(HermesValue value) {
  thrownValue_ = value;
  return ExecutionStatus::EXCEPTION;
}

inline void Runtime::clearThrownValue() {
  thrownValue_ = HermesValue::encodeEmptyValue();
}

inline CrashManager &Runtime::getCrashManager() {
  return *crashMgr_;
}

#ifndef HERMESVM_SANITIZE_HANDLES
inline void Runtime::potentiallyMoveHeap() {}
#endif

                                                                                

                                                                 
                                   
template <typename T, typename... CtorArgs>
inline void constructInHeapObj(void *mem, CtorArgs... args) {
  new (mem) T(args...);
}

                         
llvh::raw_ostream &operator<<(
    llvh::raw_ostream &OS,
    Runtime::FormatSymbolID format);

}                
}                    

#endif                       

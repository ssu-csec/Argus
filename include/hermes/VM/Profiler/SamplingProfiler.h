/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_PROFILER_SAMPLINGPROFILER_H_
#define HERMES_VM_PROFILER_SAMPLINGPROFILER_H_

#include "hermes/VM/Profiler/SamplingProfilerDefs.h"

#if HERMESVM_SAMPLING_PROFILER_AVAILABLE

#include "hermes/Public/SamplingProfiler.h"
#include "hermes/VM/Callable.h"
#include "hermes/VM/JSNativeFunctions.h"
#include "hermes/VM/Runtime.h"

#include "llvh/ADT/DenseMap.h"

#include <atomic>
#include <chrono>
#include <mutex>
#include <unordered_set>
#include <vector>

namespace hermes {
namespace vm {
namespace sampling_profiler {
struct Sampler;
}                               

                                                                             
                                                                        
              
class SamplingProfiler {
 public:
  using ThreadId = uint64_t;
  using TimeStampType = std::chrono::steady_clock::time_point;
  using ThreadNamesMap =
      llvh::DenseMap<SamplingProfiler::ThreadId, std::string>;

                                                                    
                                                                         
                
  struct JSFunctionFrameInfo {
                                                      
    RuntimeModule *module;
                                                 
    uint32_t functionId;
                                     
    uint32_t offset;
  };
                                                                  
  using LoomNativeFrameInfo = NativeFunctionPtr;
                                                                             
                                                                                
                
  using NativeFunctionFrameInfo = size_t;

                                    
  struct SuspendFrameInfo {
                                                                  
    using GCFrameInfo = const std::string *;

                                
    enum class Kind {
                                                                                
                                     
      GC,
                                                
      Debugger,
                                             
      Multiple,
    } kind;
                                                                          
                                                                         
                                                  
                                                            
                       
    GCFrameInfo gcFrame;
  };

                                                                               
                                                                             
                                                   
  struct StackFrame {
                      
    enum class FrameKind {
      JSFunction,
      NativeFunction,
      FinalizableNativeFunction,
      SuspendFrame,
    };

                                                   
                                                                  
    union {
                                      
      JSFunctionFrameInfo jsFrame;
                                                                     
      LoomNativeFrameInfo nativeFunctionPtrForLoom;
                                                                          
      NativeFunctionFrameInfo nativeFrame;
                             
      SuspendFrameInfo suspendFrame;
    };
    FrameKind kind;
  };

                                                     
  struct StackTrace {
                                                             
    ThreadId tid{0};
                                                
    TimeStampType timeStamp;
                              
    std::vector<StackFrame> stack;

    explicit StackTrace(uint32_t preallocatedSize) : stack(preallocatedSize) {}
    explicit StackTrace(
        ThreadId tid,
        TimeStampType ts,
        const std::vector<StackFrame>::iterator stackStart,
        const std::vector<StackFrame>::iterator stackEnd)
        : tid(tid), timeStamp(ts), stack(stackStart, stackEnd) {}
  };

                                                                          
                                                                     
                                                                          
                                                                          
                          
  bool belongsToCurrentThread();

                                                                        
                       
  NativeFunctionPtr getNativeFunctionPtr(const StackFrame &stackFrame) const {
    assert(
        (stackFrame.kind == StackFrame::FrameKind::NativeFunction ||
         stackFrame.kind == StackFrame::FrameKind::FinalizableNativeFunction) &&
        "unexpected stack frame kind");
    return nativeFunctions_[stackFrame.nativeFrame]->getFunctionPtr();
  }

                                                                           
                       
  std::string getNativeFunctionName(const StackFrame &stackFrame) const {
    if (stackFrame.kind == StackFrame::FrameKind::NativeFunction) {
                                                                               
                                                                             
                                                                    
      const char *name =
          hermes::vm::getFunctionName(getNativeFunctionPtr(stackFrame));
      if (strcmp(name, "")) {
        return name;
      }
    }

                                                                 
                                                                            
                                           
    return nativeFunctions_[stackFrame.nativeFrame]->getNameIfExists(runtime_);
  }

 private:
  friend struct sampling_profiler::Sampler;

                                 
  static const int kMaxStackDepth = 500;

                                                                     
                                                      
  std::mutex runtimeDataLock_;

 protected:
                                                                   
  std::vector<StackTrace> sampledStacks_;

 private:
                                                                            
                                                                             
                                   
                                                                           
                
  std::atomic<uint32_t> suspendCount_{0};
                                                                
  volatile uint32_t preSuspendStackDepth_{0};
                                      
  StackTrace preSuspendStackStorage_{kMaxStackDepth};

                                                         
  ThreadNamesMap threadNames_;

                                                   
  ThreadId threadID_;

                                                   
  std::unordered_set<std::string> gcEventExtraInfoSet_;

                                                                       
                       
  std::vector<Domain *> domains_;

                                                                           
                                    
  std::vector<NativeFunction *> nativeFunctions_;

 protected:
  Runtime &runtime_;

                                                                               
                                                        
  bool isSuspended() const {
    return suspendCount_ != 0;
  }

 private:
                                                                          
                                    
                                                                          
  void registerDomain(Domain *domain);

                                                                               
             
  NativeFunctionFrameInfo registerNativeFunction(
      NativeFunction *nativeFunction);

 protected:
  enum class InLoom { No, Yes };

                                                              
                                                                    
                                                                   
                                                                              
                                                                                
                                                                       
                                                     
  uint32_t walkRuntimeStack(
      StackTrace &sampleStorage,
      InLoom inLoom,
      uint32_t startIndex = 0);

 private:
                                                             
                       
  void recordPreSuspendStack(
      SuspendFrameInfo::Kind reason,
      llvh::StringRef gcFrame);

 protected:
                                    
                                                       
  void clear();

 public:
  static std::unique_ptr<SamplingProfiler> create(Runtime &rt);

  virtual ~SamplingProfiler() = default;

                                                  
  void markRootsForCompleteMarking(RootAcceptor &acceptor);

                                                             
  void markRoots(RootAcceptor &acceptor);

                                  
                                               
  void dumpSampledStack(llvh::raw_ostream &OS);

                                                         
  void dumpChromeTrace(llvh::raw_ostream &OS);

                                                                          
              
  facebook::hermes::sampling_profiler::Profile dumpAsProfile();

                                                                   
                                    
     
                                                                                   
     
                        
  void serializeInDevToolsFormat(llvh::raw_ostream &OS);

                                          
  static void dumpSampledStackGlobal(llvh::raw_ostream &OS);

                                         
  static void dumpChromeTraceGlobal(llvh::raw_ostream &OS);

                                 
  static bool enable(double meanHzFreq = 100);

                                 
  static bool disable();

                                                                               
                                                                               
                                                                           
  void suspend(
      SuspendFrameInfo::Kind reason,
      llvh::StringRef gcSuspendDetails = "");

                                                                           
                                                
  void resume();

                                                                         
                                     
  void setRuntimeThread();

 protected:
  explicit SamplingProfiler(Runtime &runtime);
};

                                                                             
             
class SuspendSamplingProfilerRAII {
 public:
  explicit SuspendSamplingProfilerRAII(
      Runtime &runtime,
      SamplingProfiler::SuspendFrameInfo::Kind reason)
      : profiler_(runtime.samplingProfiler.get()) {
    if (profiler_) {
      profiler_->suspend(reason);
    }
  }

  ~SuspendSamplingProfilerRAII() {
    if (profiler_) {
      profiler_->resume();
    }
  }

 private:
  SamplingProfiler *profiler_;
};

bool operator==(
    const SamplingProfiler::StackFrame &left,
    const SamplingProfiler::StackFrame &right);

}                
}                    

#endif                                        

#endif                                          

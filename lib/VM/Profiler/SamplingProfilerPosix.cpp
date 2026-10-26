/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "SamplingProfilerSampler.h"

#if defined(HERMESVM_SAMPLING_PROFILER_POSIX)

#include "hermes/Support/Semaphore.h"
#include "hermes/Support/ThreadLocal.h"
#include "hermes/VM/Callable.h"
#include "hermes/VM/HostModel.h"
#include "hermes/VM/Profiler/SamplingProfiler.h"
#include "hermes/VM/Runtime.h"
#include "hermes/VM/RuntimeModule-inline.h"
#include "hermes/VM/StackFrame-inline.h"

#include "llvh/Support/Compiler.h"

#include "ChromeTraceSerializer.h"

                                                                        
                                                    
  
                                               
  
                                             

#if defined(HERMES_FACEBOOK_BUILD) && defined(HERMESVM_ALLOW_LOOM) && \
    (defined(__APPLE__) || defined(__ANDROID__))
#define HERMESVM_ENABLE_LOOM
#endif

#if defined(HERMESVM_ENABLE_LOOM) && defined(__ANDROID__)
                                                                        
                         
#include <ucontext.h>
#endif

#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <cassert>
#include <chrono>
#include <cmath>
#include <csignal>
#include <random>
#include <thread>

#if defined(HERMESVM_ENABLE_LOOM) && defined(__ANDROID__)
#include <profilo/ExternalApi.h>

#elif defined(HERMESVM_ENABLE_LOOM) && defined(__APPLE__)
#include <FBLoom/ExternalApi/ExternalApi.h>

#endif

namespace hermes {
namespace vm {
namespace sampling_profiler {
namespace {

                          
constexpr char kSamplingDoneSemaphoreName[] = "/samplingDoneSem";

struct SamplingProfilerPosix : SamplingProfiler {
  SamplingProfilerPosix(Runtime &rt);
  ~SamplingProfilerPosix() override;

                                                                               
                                                                          
                                   
  pthread_t currentThread_;

#if defined(HERMESVM_ENABLE_LOOM) && defined(__ANDROID__)
                                                           
  static StackCollectionRetcode collectStackForLoom(
      ucontext_t *ucontext,
      int64_t *frames,
      uint16_t *depth,
      uint16_t max_depth);

#elif defined(HERMESVM_ENABLE_LOOM) && defined(__APPLE__)
                                                                              
                                                                               
                                                                              
                                         
  bool loomDataPushEnabled_{false};

                                                                            
                                                                             
  std::chrono::time_point<std::chrono::system_clock> previousPushTs;

                                                                 
  bool shouldPushDataToLoom() const;

                                                                
  void pushLastSampledStackToLoom();

#endif

#if defined(HERMESVM_ENABLE_LOOM)
                                                                          
                                
  void collectStackForLoomCommon(
      const StackFrame &frame,
      int64_t *frames,
      uint32_t index);
#endif                                 
};

struct SamplerPosix : Sampler {
  SamplerPosix();
  ~SamplerPosix() override;
                                                          
                                                                     
                               
  static std::atomic<SamplerPosix *> instance_;

                                                                             
                                                                 
                                                        
  static std::atomic<SamplingProfiler *> profilerForSig_;

#if defined(HERMESVM_ENABLE_LOOM) && defined(__ANDROID__)
                                                      
                                                       
  ThreadLocal<SamplingProfilerPosix> threadLocalProfilerForLoom_;
#endif

                                                                              
  bool isSigHandlerRegistered_{false};

                                                                           
  Semaphore samplingDoneSem_;

                                                       
                                       
  bool registerSignalHandlers();

                                         
  bool unregisterSignalHandler();

                                              
  static void profilingSignalHandler(int signo);
};
}             

SamplingProfilerPosix::SamplingProfilerPosix(Runtime &rt)
    : SamplingProfiler(rt), currentThread_{pthread_self()} {
#if defined(HERMESVM_ENABLE_LOOM) && defined(__APPLE__)
  fbloom_profilo_api()->fbloom_register_enable_for_loom_callback(
      FBLoomTracerType::JAVASCRIPT, []() { return enable(); });
  fbloom_profilo_api()->fbloom_register_disable_for_loom_callback(
      FBLoomTracerType::JAVASCRIPT, disable);
  loomDataPushEnabled_ = true;
#endif
}

SamplingProfilerPosix::~SamplingProfilerPosix() {
                                                                               
                                                         
  Sampler::get()->unregisterRuntime(this);
}

std::atomic<SamplerPosix *> SamplerPosix::instance_{nullptr};

std::atomic<SamplingProfiler *> SamplerPosix::profilerForSig_{nullptr};

namespace {
                                                        
                                                            
static int invokeSignalAction(void (*handler)(int)) {
  struct sigaction actions;
  memset(&actions, 0, sizeof(actions));
  sigemptyset(&actions.sa_mask);
                                                 
  actions.sa_flags = SA_RESTART;
  actions.sa_handler = handler;
  return sigaction(SIGPROF, &actions, nullptr);
}
}             

bool SamplerPosix::registerSignalHandlers() {
  if (isSigHandlerRegistered_) {
    return true;
  }
  if (invokeSignalAction(profilingSignalHandler) != 0) {
    perror("signal handler registration failed");
    return false;
  }
  isSigHandlerRegistered_ = true;
  return true;
}

bool SamplerPosix::unregisterSignalHandler() {
  if (!isSigHandlerRegistered_) {
    return true;
  }
                        
  if (invokeSignalAction(SIG_DFL) != 0) {
    perror("signal handler unregistration failed");
    return false;
  }
  isSigHandlerRegistered_ = false;
  return true;
}

void SamplerPosix::profilingSignalHandler(int signo) {
                                                                           
                                     
  SamplingProfiler *localProfiler;
  while (!(localProfiler = profilerForSig_.load(std::memory_order_acquire))) {
  }

                                                                            
                     
  auto oldErrno = errno;

  auto *profilerInstance = static_cast<SamplerPosix *>(instance_.load());
  assert(
      profilerInstance != nullptr &&
      "Why is SamplerPosix::instance_ not initialized yet?");

  profilerInstance->walkRuntimeStack(localProfiler);

                                                                            
  profilerForSig_.store(nullptr);

  if (!profilerInstance->samplingDoneSem_.notifyOne()) {
    errno = oldErrno;
    abort();                       
  }
  errno = oldErrno;
}

           Sampler *Sampler::get() {
                                                                        
                                                    
  static SamplerPosix *instance = new SamplerPosix{};
  return instance;
}

SamplerPosix::~SamplerPosix() = default;

SamplerPosix::SamplerPosix() {
  instance_.store(this);
#if defined(HERMESVM_ENABLE_LOOM) && defined(__ANDROID__)
  profilo_api()->register_external_tracer_callback(
      TRACER_TYPE_JAVASCRIPT, SamplingProfilerPosix::collectStackForLoom);
#endif
}

bool Sampler::platformEnable() {
  auto *self = static_cast<SamplerPosix *>(this);
  if (!self->samplingDoneSem_.open(kSamplingDoneSemaphoreName)) {
    return false;
  }
  if (!self->registerSignalHandlers()) {
    return false;
  }

  return true;
}

bool Sampler::platformDisable() {
  auto *self = static_cast<SamplerPosix *>(this);
  if (!self->samplingDoneSem_.close()) {
    return false;
  }
                                         
  if (!self->unregisterSignalHandler()) {
    return false;
  }

  return true;
}

void Sampler::platformRegisterRuntime(SamplingProfiler *profiler) {
#if defined(HERMESVM_ENABLE_LOOM) && defined(__ANDROID__)
  auto *self = static_cast<SamplerPosix *>(this);
  assert(
      self->threadLocalProfilerForLoom_.get() == nullptr &&
      "multiple hermes runtime in the same thread");
  self->threadLocalProfilerForLoom_.set(
      static_cast<SamplingProfilerPosix *>(profiler));
#endif
}

void Sampler::platformUnregisterRuntime(SamplingProfiler *profiler) {
#if defined(HERMESVM_ENABLE_LOOM) && defined(__ANDROID__)
  auto *self = static_cast<SamplerPosix *>(this);
                                                                         
                                                  
  self->threadLocalProfilerForLoom_.set(nullptr);
#endif
}

void Sampler::platformPostSampleStack(SamplingProfiler *localProfiler) {
#if defined(HERMESVM_ENABLE_LOOM) && defined(__APPLE__)
  auto *posixProfiler = static_cast<SamplingProfilerPosix *>(localProfiler);
  if (posixProfiler->shouldPushDataToLoom()) {
    posixProfiler->pushLastSampledStackToLoom();
  }
#endif                                       
}

bool Sampler::platformSuspendVMAndWalkStack(SamplingProfiler *profiler) {
  auto *self = static_cast<SamplerPosix *>(this);
  auto *posixProfiler = static_cast<SamplingProfilerPosix *>(profiler);
                                                                    
                                      
  self->profilerForSig_.store(profiler, std::memory_order_release);

                                                                         
                                                                       
                                           
  pthread_kill(posixProfiler->currentThread_, SIGPROF);

                                                                      
                                                                      
  if (!self->samplingDoneSem_.wait()) {
    return false;
  }

                                                                     
                                      
  while (self->profilerForSig_.load(std::memory_order_acquire) != nullptr) {
  }

  return true;
}

#if defined(HERMESVM_ENABLE_LOOM)
void SamplingProfilerPosix::collectStackForLoomCommon(
    const StackFrame &frame,
    int64_t *frames,
    uint32_t index) {
  constexpr uint64_t kNativeFrameMask = ((uint64_t)1 << 63);
  switch (frame.kind) {
    case StackFrame::FrameKind::JSFunction: {
      auto *bcProvider = frame.jsFrame.module->getBytecode();
      uint32_t virtualOffset =
          bcProvider->getVirtualOffsetForFunction(frame.jsFrame.functionId) +
          frame.jsFrame.offset;
      uint32_t segmentID = bcProvider->getSegmentID();
      uint64_t frameAddress = ((uint64_t)segmentID << 32) + virtualOffset;
      assert(
          (frameAddress & kNativeFrameMask) == 0 &&
          "Module id should take less than 32 bits");
      frames[(index)] = static_cast<int64_t>(frameAddress);
      break;
    }

    case StackFrame::FrameKind::NativeFunction:
    case StackFrame::FrameKind::FinalizableNativeFunction: {
#if defined(HERMESVM_ENABLE_LOOM) && defined(__ANDROID__)
      NativeFunctionPtr nativeFrame = frame.nativeFunctionPtrForLoom;
#elif defined(HERMESVM_ENABLE_LOOM) && defined(__APPLE__)
      NativeFunctionPtr nativeFrame = getNativeFunctionPtr(frame);
#else
                                                      
                                                                       
                     
#endif
      frames[(index)] = ((uint64_t)nativeFrame | kNativeFrameMask);
      break;
    }

#if defined(HERMESVM_ENABLE_LOOM) && defined(__APPLE__)
    case StackFrame::FrameKind::SuspendFrame:
      break;
#endif

    default:
      llvm_unreachable("Loom: unknown frame kind");
  }
}
#endif

#if defined(HERMESVM_ENABLE_LOOM) && defined(__ANDROID__)
           StackCollectionRetcode SamplingProfilerPosix::collectStackForLoom(
    ucontext_t *ucontext,
    int64_t *frames,
    uint16_t *depth,
    uint16_t max_depth) {
  auto profilerInstance = SamplerPosix::instance_.load();
  SamplingProfilerPosix *localProfiler =
      profilerInstance->threadLocalProfilerForLoom_.get();
  if (localProfiler == nullptr) {
                                 
    return StackCollectionRetcode::NO_STACK_FOR_THREAD;
  }

  uint32_t sampledStackDepth = 0;
                                                          
                                 
  if (LLVM_LIKELY(!localProfiler->isSuspended())) {
    Runtime &curThreadRuntime = localProfiler->runtime_;
    assert(
        !curThreadRuntime.getHeap().inGC() &&
        "sampling profiler should be suspended before GC");
    (void)curThreadRuntime;
    assert(
        profilerInstance != nullptr &&
        "Why is Sampler::instance_ not initialized yet?");
                                                                              
                     
    sampledStackDepth = localProfiler->walkRuntimeStack(
        profilerInstance->sampleStorage_, InLoom::Yes);
  } else {
                                            
    sampledStackDepth = 0;
  }

                                             
                                                                         
                                                                              
                               
                                                                  
                                                         
  sampledStackDepth = std::min(sampledStackDepth, (uint32_t)max_depth);
  for (uint32_t i = 0; i < sampledStackDepth; ++i) {
    const StackFrame &stackFrame = profilerInstance->sampleStorage_.stack[i];
    localProfiler->collectStackForLoomCommon(stackFrame, frames, i);
  }
  *depth = sampledStackDepth;
  if (*depth == 0) {
    return StackCollectionRetcode::EMPTY_STACK;
  }
  return StackCollectionRetcode::SUCCESS;
}
#endif

#if defined(HERMESVM_ENABLE_LOOM) && defined(__APPLE__)
bool SamplingProfilerPosix::shouldPushDataToLoom() const {
  auto now = std::chrono::system_clock::now();
  constexpr auto kLoomDelay = std::chrono::milliseconds(50);
                                                                             
                           
  return loomDataPushEnabled_ && (now - previousPushTs > kLoomDelay);
}

void SamplingProfilerPosix::pushLastSampledStackToLoom() {
  constexpr uint16_t maxDepth = 512;
  int64_t frames[maxDepth];
  uint16_t depth = 0;
                                                                          
                                   
  auto sample = sampledStacks_.back();
  for (auto iter = sample.stack.rbegin(); iter != sample.stack.rend(); ++iter) {
    const StackFrame &frame = *iter;
    collectStackForLoomCommon(frame, frames, depth);
    depth++;
    if (depth > maxDepth) {
      return;
    }
  }
  fbloom_profilo_api()->fbloom_write_stack_to_loom(
      FBLoomTracerType::JAVASCRIPT, frames, depth);
  previousPushTs = std::chrono::system_clock::now();
  clear();
}
#endif
}                               

std::unique_ptr<SamplingProfiler> SamplingProfiler::create(Runtime &rt) {
  return std::make_unique<sampling_profiler::SamplingProfilerPosix>(rt);
}

bool SamplingProfiler::belongsToCurrentThread() {
  auto profiler = static_cast<sampling_profiler::SamplingProfilerPosix *>(this);
  std::lock_guard<std::mutex> lock(profiler->runtimeDataLock_);
  return profiler->currentThread_ == pthread_self();
}

void SamplingProfiler::setRuntimeThread() {
  auto profiler = static_cast<sampling_profiler::SamplingProfilerPosix *>(this);
  std::lock_guard<std::mutex> lock(profiler->runtimeDataLock_);
  profiler->currentThread_ = pthread_self();
  threadID_ = oscompat::global_thread_id();
  threadNames_[threadID_] = oscompat::thread_name();
}

}                
}                    

#endif                                             

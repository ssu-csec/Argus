/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "SamplingProfilerSampler.h"

#if defined(HERMESVM_SAMPLING_PROFILER_WINDOWS)

#if defined(HERMES_FACEBOOK_BUILD) && defined(HERMESVM_ALLOW_LOOM)
#define HERMESVM_ENABLE_LOOM
#endif

#if defined(HERMESVM_ENABLE_LOOM)
#include <FBLoom/ExternalApi/ExternalApi.h>
#endif

#include "hermes/VM/Profiler/SamplingProfiler.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "Windows.h"

namespace hermes {
namespace vm {

                                                                             
                                                       
static HANDLE openCurrentThread() {
  return OpenThread(
      THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
      false,
      GetCurrentThreadId());
}

namespace sampling_profiler {
namespace {
struct SamplingProfilerWindows : SamplingProfiler {
  SamplingProfilerWindows(Runtime &rt) : SamplingProfiler(rt) {
    currentThread_ = openCurrentThread();

#if defined(HERMESVM_ENABLE_LOOM)
    fbloom_profilo_api()->fbloom_register_enable_for_loom_callback(
        FBLoomTracerType::JAVASCRIPT, []() { return enable(); });
    fbloom_profilo_api()->fbloom_register_disable_for_loom_callback(
        FBLoomTracerType::JAVASCRIPT, disable);
    loomDataPushEnabled_ = true;
#endif                                 
  }

  ~SamplingProfilerWindows() override {
                                                                        
                                                                    
    Sampler::get()->unregisterRuntime(this);

    CloseHandle(currentThread_);
  }

#if defined(HERMESVM_ENABLE_LOOM)
  bool shouldPushDataToLoom() const {
    auto now = std::chrono::system_clock::now();
    constexpr auto kLoomDelay = std::chrono::milliseconds(50);
                                                                         
                                   
    return loomDataPushEnabled_ && (now - previousPushTs > kLoomDelay);
  }

  void collectStackForLoomCommon(
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
        NativeFunctionPtr nativeFrame = getNativeFunctionPtr(frame);
        frames[(index)] = ((uint64_t)nativeFrame | kNativeFrameMask);
        break;
      }
      case StackFrame::FrameKind::SuspendFrame:
        break;
      default:
        llvm_unreachable("Loom: unknown frame kind");
    }
  }

  void pushLastSampledStackToLoom() {
    constexpr uint16_t maxDepth = 512;
    int64_t frames[maxDepth];
    uint16_t depth = 0;
                                                                            
                                     
    auto sample = sampledStacks_.back();
    for (auto iter = sample.stack.rbegin(); iter != sample.stack.rend();
         ++iter) {
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

                                                                            
                                                                             
  std::chrono::time_point<std::chrono::system_clock> previousPushTs;

  bool loomDataPushEnabled_{false};
#endif                                 

                                                                        
                                         
  HANDLE currentThread_;
};
}             

namespace {
struct SamplerWindows : Sampler {
  SamplerWindows();
  ~SamplerWindows() override;
};
}             

Sampler *Sampler::get() {
                                                                        
                                                    
  static SamplerWindows *instance = new SamplerWindows{};
  return instance;
}

SamplerWindows::~SamplerWindows() = default;

SamplerWindows::SamplerWindows() = default;

bool Sampler::platformEnable() {
  return true;
}

bool Sampler::platformDisable() {
  return true;
}

void Sampler::platformRegisterRuntime(SamplingProfiler *profiler) {}

void Sampler::platformUnregisterRuntime(SamplingProfiler *profiler) {}

void Sampler::platformPostSampleStack(SamplingProfiler *localProfiler) {
#if defined(HERMESVM_ENABLE_LOOM)
  auto *windowsProfiler = static_cast<SamplingProfilerWindows *>(localProfiler);
  if (windowsProfiler->shouldPushDataToLoom()) {
    windowsProfiler->pushLastSampledStackToLoom();
  }
#endif                                 
}

bool Sampler::platformSuspendVMAndWalkStack(SamplingProfiler *profiler) {
  auto *winProfiler = static_cast<SamplingProfilerWindows *>(profiler);

                                                                               
                                                                         
            
  DWORD prevSuspendCount = SuspendThread(winProfiler->currentThread_);
  if (prevSuspendCount == static_cast<DWORD>(-1)) {
    return true;
  }

                                                                          
               
  CONTEXT context;
  GetThreadContext(winProfiler->currentThread_, &context);

                    
  walkRuntimeStack(profiler);

                       
  prevSuspendCount = ResumeThread(winProfiler->currentThread_);
  assert(
      prevSuspendCount != static_cast<DWORD>(-1) &&
      "couldn't resume js thread");
  (void)prevSuspendCount;

  return true;
}
}                               

std::unique_ptr<SamplingProfiler> SamplingProfiler::create(Runtime &rt) {
  return std::make_unique<sampling_profiler::SamplingProfilerWindows>(rt);
}

bool SamplingProfiler::belongsToCurrentThread() {
  auto profiler =
      static_cast<sampling_profiler::SamplingProfilerWindows *>(this);
  std::lock_guard<std::mutex> lock(profiler->runtimeDataLock_);
  return GetThreadId(profiler->currentThread_) == GetCurrentThreadId();
}

void SamplingProfiler::setRuntimeThread() {
  auto profiler =
      static_cast<sampling_profiler::SamplingProfilerWindows *>(this);
  std::lock_guard<std::mutex> lock(profiler->runtimeDataLock_);
  CloseHandle(profiler->currentThread_);
  profiler->currentThread_ = openCurrentThread();
  threadID_ = oscompat::global_thread_id();
  threadNames_[threadID_] = oscompat::thread_name();
}

}                
}                    
#endif                                                

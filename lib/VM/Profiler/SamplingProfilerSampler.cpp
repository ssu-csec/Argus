/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "SamplingProfilerSampler.h"

#if HERMESVM_SAMPLING_PROFILER_AVAILABLE

#include "hermes/VM/Callable.h"
#include "hermes/VM/HostModel.h"
#include "hermes/VM/Runtime.h"
#include "hermes/VM/RuntimeModule-inline.h"
#include "hermes/VM/StackFrame-inline.h"

#include "llvh/Support/Compiler.h"

#include "ChromeTraceSerializer.h"

#include <fcntl.h>
#include <cassert>
#include <chrono>
#include <cmath>
#include <csignal>
#include <random>
#include <thread>

#if defined(_WINDOWS)
#include <windows.h>
                                   
#include <mmsystem.h>
#include "llvh/ADT/ScopeExit.h"
#endif

namespace hermes {
namespace vm {
namespace sampling_profiler {

Sampler::~Sampler() = default;

void Sampler::registerRuntime(SamplingProfiler *profiler) {
  std::lock_guard<std::mutex> lockGuard(profilerLock_);
  profilers_.insert(profiler);
  platformRegisterRuntime(profiler);
}

void Sampler::unregisterRuntime(SamplingProfiler *profiler) {
  std::lock_guard<std::mutex> lockGuard(profilerLock_);
  bool succeed = profilers_.erase(profiler);
                                          
                                                     
  assert(succeed && "How can runtime not registered yet?");
  (void)succeed;
  platformUnregisterRuntime(profiler);
}

bool Sampler::sampleStacks() {
  for (SamplingProfiler *localProfiler : profilers_) {
    std::lock_guard<std::mutex> lk(localProfiler->runtimeDataLock_);
    if (!sampleStack(localProfiler)) {
      return false;
    }
    platformPostSampleStack(localProfiler);
  }
  return true;
}

bool Sampler::sampleStack(SamplingProfiler *localProfiler) {
  if (localProfiler->suspendCount_ > 0) {
                                                                              
                                  
    if (localProfiler->preSuspendStackDepth_ > 0) {
      sampleStorage_ = localProfiler->preSuspendStackStorage_;
      sampledStackDepth_ = localProfiler->preSuspendStackDepth_;
    } else {
                                                                             
                                           
                                      
      sampledStackDepth_ = 0;
    }
  } else {
                                                                             
                      
    localProfiler->domains_.reserve(
        localProfiler->domains_.size() + SamplingProfiler::kMaxStackDepth);
    size_t domainCapacityBefore = localProfiler->domains_.capacity();
    (void)domainCapacityBefore;

                                  
    localProfiler->nativeFunctions_.reserve(
        localProfiler->nativeFunctions_.size() +
        SamplingProfiler::kMaxStackDepth);
    size_t nativeFunctionsCapacityBefore =
        localProfiler->nativeFunctions_.capacity();
    (void)nativeFunctionsCapacityBefore;

    if (!platformSuspendVMAndWalkStack(localProfiler)) {
      return false;
    }

    assert(
        localProfiler->domains_.capacity() == domainCapacityBefore &&
        "Must not dynamically allocate in signal handler");

    assert(
        localProfiler->nativeFunctions_.capacity() ==
            nativeFunctionsCapacityBefore &&
        "Must not dynamically allocate in signal handler");
  }

  assert(
      sampledStackDepth_ <= sampleStorage_.stack.size() &&
      "How can we sample more frames than storage?");
  localProfiler->sampledStacks_.emplace_back(
      sampleStorage_.tid,
      sampleStorage_.timeStamp,
      sampleStorage_.stack.begin(),
      sampleStorage_.stack.begin() + sampledStackDepth_);
  return true;
}

void Sampler::walkRuntimeStack(SamplingProfiler *profiler) {
  assert(
      profiler->suspendCount_ == 0 &&
      "Shouldn't interrupt the VM thread when the sampling profiler is "
      "suspended.");

                                                                             
              
  auto &curThreadRuntime = profiler->runtime_;
  assert(
      !curThreadRuntime.getHeap().inGC() &&
      "sampling profiler should be suspended before GC");
  (void)curThreadRuntime;
  sampledStackDepth_ =
      profiler->walkRuntimeStack(sampleStorage_, SamplingProfiler::InLoom::No);
}

void Sampler::timerLoop(double meanHzFreq) {
  oscompat::set_thread_name("hermes-sampling-profiler");

  std::random_device rd{};
  std::mt19937 gen{rd()};
                                                                                
                                                                              
            
  double interval = 1.0 / meanHzFreq;
  std::normal_distribution<> distribution{interval, interval / 2};
  std::unique_lock<std::mutex> uniqueLock(profilerLock_);

#if defined(_WINDOWS)
                                                                             
                                                                            
                                                                          
                                                                  
  timeBeginPeriod(1);
  auto restorePeriod = llvh::make_scope_exit([] { timeEndPeriod(1); });
#endif
  while (enabled_) {
    if (!sampleStacks()) {
      return;
    }

    double dur = std::fabs(distribution(gen));
    enabledCondVar_.wait_for(
        uniqueLock, std::chrono::duration<double>(dur), [this]() {
          return !enabled_;
        });
  }
}

bool Sampler::enabled() {
  std::lock_guard<std::mutex> lockGuard(profilerLock_);
  return enabled_;
}

bool Sampler::enable(double meanHzFreq) {
  std::lock_guard<std::mutex> lockGuard(profilerLock_);
  if (enabled_) {
    return true;
  }
  if (!platformEnable()) {
    return false;
  }
  enabled_ = true;
                        
  timerThread_ = std::thread(&Sampler::timerLoop, this, meanHzFreq);
  return true;
}

bool Sampler::disable() {
  {
    std::lock_guard<std::mutex> lockGuard(profilerLock_);
    if (!enabled_) {
                          
      return true;
    }
    if (!platformDisable()) {
      return false;
    }
                                    
    enabled_ = false;
  }
                                                       
  enabledCondVar_.notify_all();
                                                                             
                                                                             
                                                                        
  timerThread_.join();
  return true;
}

}                               
}                
}                    

#endif                                        

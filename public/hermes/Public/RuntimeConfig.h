/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PUBLIC_RUNTIMECONFIG_H
#define HERMES_PUBLIC_RUNTIMECONFIG_H

#include "hermes/Public/CrashManager.h"
#include "hermes/Public/CtorConfig.h"
#include "hermes/Public/GCConfig.h"

#include <cstdint>
#include <memory>

namespace hermes {
namespace vm {

enum CompilationMode {
  SmartCompilation,
  ForceEagerCompilation,
  ForceLazyCompilation
};

enum class SynthTraceMode : int8_t {
  None,
  Replaying,
  Tracing,
  TracingAndReplaying,
};

class PinnedHermesValue;

                                                                           
                                                           
#define RUNTIME_FIELDS(F)                                              \
                                                                       \
  F(HERMES_NON_CONSTEXPR, vm::GCConfig, GCConfig)                      \
                                                                       \
                                                                       \
  F(constexpr, PinnedHermesValue *, RegisterStack, nullptr)            \
                                                                       \
                                                                       \
  F(constexpr, unsigned, MaxNumRegisters, 128 * 1024)                  \
                                                                       \
                                                                       \
  F(constexpr, unsigned, NativeStackGap, 64 * 1024)                    \
                                                                       \
                                                                       \
  F(constexpr, bool, EnableEval, true)                                 \
                                                                       \
                                                                       \
  F(constexpr, bool, VerifyEvalIR, false)                              \
                                                                       \
                                                                       \
  F(constexpr, bool, OptimizedEval, false)                             \
                                                                       \
                                                                       \
  F(constexpr, bool, AsyncBreakCheckInEval, true)                      \
                                                                       \
                                                                       \
  F(constexpr, bool, ES6Promise, true)                                 \
                                                                       \
                                                                       \
  F(constexpr, bool, ES6Proxy, true)                                   \
                                                                       \
                                                                       \
  F(constexpr, bool, ES6Class, false)                                  \
                                                                       \
                                                                       \
  F(constexpr, bool, Intl, true)                                       \
                                                                       \
                                                                       \
  F(constexpr, bool, ArrayBuffer, true)                                \
                                                                       \
                                                                       \
  F(constexpr, bool, MicrotaskQueue, false)                            \
                                                                       \
                                                                       \
  F(constexpr, SynthTraceMode, SynthTraceMode, SynthTraceMode::None)   \
                                                                       \
                                                                       \
  F(constexpr, bool, EnableSampledStats, false)                        \
                                                                       \
                                                                       \
  F(constexpr, bool, EnableSampleProfiling, false)                     \
                                                                       \
                                                                       \
  F(constexpr, bool, RandomizeMemoryLayout, false)                     \
                                                                       \
                                                                       \
  F(constexpr, unsigned, BytecodeWarmupPercent, 0)                     \
                                                                       \
                                                                       \
                                                                       \
  F(constexpr, bool, TrackIO, false)                                   \
                                                                       \
                                                                       \
  F(constexpr, bool, EnableHermesInternal, true)                       \
                                                                       \
                                                                       \
  F(constexpr, bool, EnableHermesInternalTestMethods, false)           \
                                                                       \
                                                                       \
  F(constexpr,                                                         \
    CompilationMode,                                                   \
    CompilationMode,                                                   \
    CompilationMode::SmartCompilation)                                 \
                                                                       \
                                                                       \
  F(constexpr, bool, EnableGenerator, true)                            \
                                                                       \
                                                                       \
  F(HERMES_NON_CONSTEXPR,                                              \
    std::shared_ptr<CrashManager>,                                     \
    CrashMgr,                                                          \
    new NopCrashManager)                                               \
                                                                       \
                                                                       \
  F(constexpr, uint32_t, VMExperimentFlags, 0)                         \
                                                                       \
                                                                       \
  F(constexpr, bool, EnableBlockScoping, false)                        \
                          

_HERMES_CTORCONFIG_STRUCT(RuntimeConfig, RUNTIME_FIELDS, {})

#undef RUNTIME_FIELDS

}                
}                    

#endif                                 

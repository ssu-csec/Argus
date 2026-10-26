/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_PROFILER_PROFILEGENERATOR_H
#define HERMES_VM_PROFILER_PROFILEGENERATOR_H

#include "hermes/VM/Profiler/SamplingProfilerDefs.h"

#if HERMESVM_SAMPLING_PROFILER_AVAILABLE

#include "hermes/VM/Profiler/SamplingProfiler.h"

namespace hermes {
namespace vm {

                                                                          
                                                                            
            
facebook::hermes::sampling_profiler::Profile generateProfile(
    const SamplingProfiler &samplingProfiler,
    const std::vector<SamplingProfiler::StackTrace> &sampledStacks);

}                
}                    

#endif                                        

#endif                                         

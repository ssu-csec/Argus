/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_OPTIMIZER_PASSMANAGER_PIPELINE_H
#define HERMES_OPTIMIZER_PASSMANAGER_PIPELINE_H

#include "hermes/IR/IR.h"

#include <string>
#include <vector>

namespace hermes {
class Module;

                                      
bool runCustomOptimizationPasses(
    Module &M,
    const std::vector<std::string> &Opts);

                                                
void runFullOptimizationPasses(Module &M);

                                                
void runDebugOptimizationPasses(Module &M);

                                                
void runNoOptimizationPasses(Module &M);
}                    

#endif                                           

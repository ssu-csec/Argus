/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "hoiststartgenerator"

#include "hermes/Optimizer/Scalar/HoistStartGenerator.h"

#include "hermes/IR/Instrs.h"

using namespace hermes;

bool HoistStartGenerator::runOnFunction(Function *F) {
  auto *innerFn = llvh::dyn_cast<GeneratorInnerFunction>(F);
  if (!innerFn) {
                                                        
    return false;
  }

  for (BasicBlock &bb : *F) {
    for (Instruction &inst : bb) {
      if (auto *startGen = llvh::dyn_cast<StartGeneratorInst>(&inst)) {
        startGen->moveBefore(&*F->front().begin());
                                                                       
                          
        return true;
      }
    }
  }

  return false;
}

std::unique_ptr<Pass> hermes::createHoistStartGenerator() {
  return std::make_unique<HoistStartGenerator>();
}

#undef DEBUG_TYPE

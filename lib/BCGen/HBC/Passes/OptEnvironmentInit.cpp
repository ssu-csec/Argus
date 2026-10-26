/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/BCGen/HBC/Passes/OptEnvironmentInit.h"

#include "hermes/IR/IRBuilder.h"
#include "hermes/Support/Statistic.h"

#include "llvh/ADT/SmallPtrSet.h"

#define DEBUG_TYPE "OptEnvironmentInit"

STATISTIC(
    NumStoreUndefinedRemoved,
    "Number of store undefined instructions removed");

namespace hermes {
namespace hbc {

bool OptEnvironmentInit::runOnFunction(Function *F) {
  IRBuilder builder{F};
  bool changed = false;

  for (auto &BB : *F) {
    IRBuilder::InstructionDestroyer destroyer{};

                                              
    llvh::SmallPtrSet<Value *, 2> createdEnvs{};

                                                           
    llvh::SmallPtrSet<Variable *, 8> writtenSlots{};

    for (auto &I : BB) {
      auto *inst = &I;

      if (auto *CE = llvh::dyn_cast<HBCCreateEnvironmentInst>(inst)) {
        createdEnvs.insert(CE);
        continue;
      }

                                                                           
                            
      if (auto *SE = llvh::dyn_cast<HBCStoreToEnvironmentInst>(inst)) {
                                                                        
                                                                         
                                                                            
                                                                     
        if (!createdEnvs.count(SE->getEnvironment()))
          break;

                                                                     
        if (!llvh::isa<LiteralUndefined>(SE->getStoredValue())) {
          writtenSlots.insert(SE->getResolvedName());
          continue;
        }

                                                               
        if (writtenSlots.count(SE->getResolvedName()))
          continue;

                                                
        ++NumStoreUndefinedRemoved;
        changed = true;
        destroyer.add(SE);
        continue;
      }

                                                                        
                               
      if (inst->mayExecute())
        break;
    }
  }

  return changed;
}

}                 
}                    

#undef DEBUG_TYPE

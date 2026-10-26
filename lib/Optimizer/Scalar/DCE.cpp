/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "dce"

#include "hermes/Optimizer/Scalar/DCE.h"

#include "hermes/IR/Analysis.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Support/Statistic.h"

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/DenseSet.h"
#include "llvh/Support/Debug.h"

using namespace hermes;
using llvh::dbgs;

STATISTIC(NumDCE, "Number of instructions DCE'd");
STATISTIC(NumFuncDCE, "Number of functions DCE'd");

static bool performFunctionDCE(Function *F) {
  bool changed = false;
  PostOrderAnalysis PO(F);

                                                                              
                                                                               
                                                               
  for (auto *BB : PO) {
                                                            
    for (auto it = BB->rbegin(), e = BB->rend(); it != e;              ) {
      Instruction *I = &*it;
                                                                          
                                                    
      ++it;

                                                                            
                                                                             
                
        
                                                                             
                      
        
                                                                     
                                                                             
                     
        
                                                                               
                                                       
      if (I->mayWriteMemory() || llvh::isa<TerminatorInst>(I) ||
          llvh::isa<CreateScopeInst>(I) ||
          llvh::isa<ThrowIfHasRestrictedGlobalPropertyInst>(I)) {
        continue;
      }

                                                                               
                            
      if (I->getNumUsers())
        continue;

      LLVM_DEBUG(
          dbgs() << "\t\tDCE: Erasing instruction \"" << I->getName()
                 << "\"\n");
      I->eraseFromParent();
      ++NumDCE;
      changed = true;
    }
  }
  return changed;
}

bool DCE::runOnModule(Module *M) {
  bool changed = false;

                                                          
                                                                           
                                                                        
                                                                               
                                                                             
                        
  llvh::SmallVector<Function *, 16> toDestroy;

                              
  for (auto &F : *M) {
    LLVM_DEBUG(
        dbgs() << "\tDCE: running on function \"" << F.getInternalName()
               << "\"\n");
    changed |= performFunctionDCE(&F);
  }

  bool localChanged = false;
  do {
                                                                         
                 
    llvh::SmallVector<Function *, 16> toRemove;
    localChanged = false;
    for (auto &F : *M) {
                                                                               
                                                              
      if (M->findCJSModule(&F)) {
                                                 
        continue;
      }
                                                                            
                                 
      if (!F.isGlobalScope() && &F != M->getTopLevelFunction() &&
          !F.hasUsers()) {
        toRemove.push_back(&F);
        toDestroy.push_back(&F);
        changed = true;
        localChanged = true;
        NumFuncDCE++;
      }
    }

                                                                       
                                                                      
                                               
    for (auto *F : toRemove) {
      LLVM_DEBUG(
          dbgs() << "\tDCE: Erasing function \"" << F->getInternalName()
                 << "\"\n");
      F->eraseFromParentNoDestroy();
    }
  } while (localChanged);

                                                                           
                                                                   
  for (auto *F : toDestroy) {
    assert(F->empty() && "All basic blocks should have been deleted.");
    Value::destroy(F);
  }

  return changed | localChanged;
}

std::unique_ptr<Pass> hermes::createDCE() {
  return std::make_unique<DCE>();
}

#undef DEBUG_TYPE

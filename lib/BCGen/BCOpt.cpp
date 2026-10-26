/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/BCGen/BCOpt.h"
#include "hermes/BCGen/RegAlloc.h"
#include "hermes/IR/Analysis.h"
#include "hermes/IR/IR.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/Instrs.h"

#include "llvh/Support/raw_ostream.h"

#define DEBUG_TYPE "bcopt"

using namespace hermes;

bool MovElimination::runOnFunction(Function *F) {
  bool changed = false;

                                                           
  llvh::DenseMap<Register, unsigned> lastAssignment;
                                                    
  llvh::DenseMap<Register, unsigned> lastUse;

  IRBuilder::InstructionDestroyer destroyer;

                                                                                
                                                        
  PostOrderAnalysis PO(F);
  llvh::SmallVector<BasicBlock *, 16> order(PO.rbegin(), PO.rend());
  for (auto *BB : order) {
    unsigned index = 0;
    lastAssignment.clear();
    lastUse.clear();
    for (auto &it : *BB) {
                                                         
      if (!RA_.isAllocated(&it))
        continue;

                                                                             
      bool movRemoved = false;

      index++;
      Register dest = RA_.getRegister(&it);

      if (auto *mov = llvh::dyn_cast<MovInst>(&it)) {
        Value *op = mov->getSingleOperand();
                                                                             
                                                                           
                    
        auto *IOp = llvh::dyn_cast<Instruction>(op);

                                                           
        if (!RA_.isAllocated(op))
          continue;

        if (IOp && op->hasOneUser() && IOp->getParent() == BB) {
          Register src = RA_.getRegister(IOp);
                                                                                
                                                                  
          unsigned srcIdx = lastAssignment.lookup(src);
          unsigned destIdx = lastAssignment.lookup(dest);
          unsigned destUseIdx = lastUse.lookup(dest);

                                                                               
                                                                               
                                                                             
                                  
                                                                            
          if (destIdx < srcIdx && !llvh::isa<PhiInst>(IOp) &&
              destUseIdx <= srcIdx) {
            RA_.updateRegister(op, dest);
            destroyer.add(mov);
            mov->replaceAllUsesWith(op);
            changed = true;
            movRemoved = true;
          }
        }
      }

                                                                         
                               
      lastAssignment[dest] = index;

                                                                                
                    
      if (!movRemoved) {
        for (unsigned i = 0, e = it.getNumOperands(); i != e; ++i) {
          auto *op = it.getOperand(i);
          if (RA_.isAllocated(op))
            lastUse[RA_.getRegister(op)] = index;
        }
      }
    }
  }

  return changed;
}

#undef DEBUG_TYPE

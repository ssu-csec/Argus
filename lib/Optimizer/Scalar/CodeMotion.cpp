/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "codemotion"
#include "hermes/Optimizer/Scalar/CodeMotion.h"
#include "hermes/IR/Analysis.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Optimizer/Scalar/Utils.h"
#include "hermes/Support/Statistic.h"

#include "llvh/ADT/DenseMap.h"

#include <algorithm>

using namespace hermes;

STATISTIC(NumCM, "Number of instructions moved");
STATISTIC(NumHoistedCond, "Number of instructions hoisted from conditionals");
STATISTIC(NumHoistedLoop, "Number of instructions hoisted from loops");
STATISTIC(NumSunk, "Number of instructions sunk");

                                                                          
                                                                               
                                
                                                                 
static Instruction *findIdenticalInWindow(
    Instruction *I,
    Instruction *copy,
    unsigned searchBudget) {
                             
  if (llvh::isa<TerminatorInst>(I) || llvh::isa<TerminatorInst>(copy))
    return nullptr;

  while (searchBudget) {
    if (I->isIdenticalTo(copy))
      return copy;

                                                                            
                                                 
    if (I->hasSideEffect() && copy->hasSideEffect())
      return nullptr;

    searchBudget--;
    copy = copy->getNextNode();

    if (llvh::isa<TerminatorInst>(copy))
      return nullptr;
  }

  return nullptr;
}

                                                            
                                                    
static bool hoistCBI(CondBranchInst *CBI) {
                                                                         
  if (CBI->hasSideEffect())
    return false;

  BasicBlock *BB0 = CBI->getTrueDest();
  BasicBlock *BB1 = CBI->getFalseDest();

                                                                 
  if (BB0 == BB1 || pred_count(BB0) != 1 || pred_count(BB1) != 1)
    return false;

  bool changed = false;

  while (true) {
    Instruction *I0 = &*BB0->begin();
    Instruction *I1 = &*BB1->begin();

                               
    if (llvh::isa<TerminatorInst>(I0) || llvh::isa<TerminatorInst>(I1))
      return changed;

    Instruction *LHS;
    Instruction *RHS;

                                                                              
                      
    if (Instruction *copy = findIdenticalInWindow(I0, I1, 5)) {
      LHS = I0;
      RHS = copy;
    } else if (Instruction *copy2 = findIdenticalInWindow(I1, I0, 5)) {
      LHS = I1;
      RHS = copy2;
    } else {
                                                     
      return changed;
    }

    changed = true;
    ++NumCM;
    ++NumHoistedCond;
    LHS->moveBefore(CBI);
    RHS->replaceAllUsesWith(LHS);
    RHS->eraseFromParent();
  }
}

                                                                           
                                                                            
                                                                             
                                
                                                        
                                              
static bool canHoistFromLoop(
    Instruction *inst,
    Instruction *branchInst,
    const DominanceInfo &dominance) {
  if (!isSimpleSideEffectFreeInstruction(inst)) {
    return false;
  }
  for (int i = 0, e = inst->getNumOperands(); i < e; ++i) {
    auto *operand = llvh::dyn_cast<Instruction>(inst->getOperand(i));
    if (operand && !dominance.properlyDominates(operand, branchInst)) {
      return false;
    }
  }
  return true;
}

                                                                 
                                                    
static bool hoistInstructionsFromLoop(
    BasicBlock *BB,
    const DominanceInfo &dominance,
    const LoopAnalysis &loops) {
  bool changed = false;
  BasicBlock *preheader = loops.getLoopPreheader(BB);
  if (!preheader) {
                                                                                
                                                                               
                                                                                
                                                                               
    return changed;
  }
  Instruction *branchInst = &preheader->back();

  for (auto it = BB->begin(), e = BB->end(); it != e;) {
                                                                           
                                
    auto nextIt = std::next(it);
    Instruction *inst = &*it;
    if (canHoistFromLoop(inst, branchInst, dominance)) {
      inst->moveBefore(branchInst);
      changed = true;
      ++NumCM;
      ++NumHoistedLoop;
    }
    it = nextIt;
  }
  return changed;
}

                                                                  
static bool sinkInstructionsInBlock(
    BasicBlock *BB,
    const DominanceInfo &dominance,
    const LoopAnalysis &loops) {
  bool changed = false;
  const bool inLoop = loops.isBlockInLoop(BB);
  const BasicBlock *header = loops.getLoopHeader(BB);
  for (auto it = BB->rbegin(), e = BB->rend(); it != e; ++it) {
    Instruction *inst = &*it;

    if (llvh::isa<PhiInst>(inst))
      continue;

    for (int i = 0, numOperands = inst->getNumOperands(); i < numOperands;
         i++) {
      auto *I = llvh::dyn_cast<Instruction>(inst->getOperand(i));
                                                                              
                                                              
      if (!I || !I->hasOneUser() || I->hasSideEffect() ||
          llvh::isa<PhiInst>(I) || llvh::isa<TerminatorInst>(I) ||
          llvh::isa<CreateArgumentsInst>(I))
        continue;

                                                                          
      BasicBlock *parent = I->getParent();
      if (inLoop && parent != BB && (loops.getLoopHeader(parent) != header)) {
        continue;
      }

      I->moveBefore(inst);
      changed = true;
      ++NumCM;
      ++NumSunk;
    }
  }
  return changed;
}

bool CodeMotion::runOnFunction(Function *F) {
  bool changed = false;
  PostOrderAnalysis PO(F);

  for (auto &BB : PO) {
    auto *term = BB->getTerminator();

    if (auto *CBI = llvh::dyn_cast<CondBranchInst>(term)) {
      changed |= hoistCBI(CBI);
    }
  }

  DominanceInfo dominance(F);
  LoopAnalysis loops(F, dominance);

                                                             
    
                                                                            
                                                                 
                                                                       
    
                                                                            
                                                                        
                                                                             
                                             
    
                                                                             
                                                       
  for (auto *BB : PO) {
    changed |= sinkInstructionsInBlock(BB, dominance, loops);
    changed |= hoistInstructionsFromLoop(BB, dominance, loops);
  }

  return changed;
}

std::unique_ptr<Pass> hermes::createCodeMotion() {
  return std::make_unique<CodeMotion>();
}

#undef DEBUG_TYPE

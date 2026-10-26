/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "tdzdedup"
#include "hermes/Optimizer/Scalar/TDZDedup.h"
#include "hermes/ADT/ScopedHashTable.h"
#include "hermes/IR/Analysis.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Optimizer/Scalar/Utils.h"
#include "hermes/Support/Statistic.h"

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/DenseSet.h"
#include "llvh/ADT/Hashing.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/Support/RecyclingAllocator.h"

STATISTIC(NumTDZFrameDedup, "Number of TDZ frame checks eliminated");
STATISTIC(NumTDZStackDedup, "Number of TDZ stack checks eliminated");
STATISTIC(NumTDZOtherDedup, "Number of TDZ other checks eliminated");
STATISTIC(NumTDZDedup, "Number of TDZ instructions eliminated");

namespace hermes {

namespace {

class TDZDedupContext;

using ScopedHTType = hermes::ScopedHashTable<Value *, bool>;
using ScopeType = hermes::ScopedHashTableScope<Value *, bool>;

                                                                              
                                                                           
                                                                         
                                               
class StackNode : public DomTreeDFS::StackNode<TDZDedupContext> {
 public:
  inline StackNode(TDZDedupContext *ctx, const DominanceInfoNode *n);

 private:
                                                                       
                
  ScopeType scope_;
};

                                                                               
                                                       
class TDZDedupContext : public DomTreeDFS::Visitor<TDZDedupContext, StackNode> {
 public:
  TDZDedupContext(Function *F, DominanceInfo &DT)
      : DomTreeDFS::Visitor<TDZDedupContext, StackNode>(DT), F_(F) {}

  bool run();

  bool processNode(StackNode *SN);

 private:
  friend StackNode;

  Function *const F_;

                                                 
  llvh::DenseSet<Value *> tdzState_{};

                                                                        
                                                                            
                                                                     
                                                                              
                                                                    
     
                                                                               
                                                                           
                                                                            
                                                                                
     
                                                                               
  ScopedHTType availableValues_{};
};

inline StackNode::StackNode(TDZDedupContext *ctx, const DominanceInfoNode *n)
    : DomTreeDFS::StackNode<TDZDedupContext>(ctx, n),
      scope_{ctx->availableValues_} {}

bool TDZDedupContext::run() {
                                            
  for (auto &BB : *F_) {
    for (auto &I : BB) {
      auto *TIU = llvh::dyn_cast<ThrowIfEmptyInst>(&I);
      if (!TIU)
        continue;

      Value *checkedValue = TIU->getCheckedValue();
      Value *tdzStorage;

      if (auto *LFI = llvh::dyn_cast<LoadFrameInst>(checkedValue)) {
        tdzStorage = LFI->getLoadVariable();
      } else if (auto *LSI = llvh::dyn_cast<LoadStackInst>(checkedValue)) {
        tdzStorage = LSI->getSingleOperand();
      } else {
        continue;
      }

      tdzState_.insert(tdzStorage);
    }
  }

  return DFS();
}

bool TDZDedupContext::processNode(StackNode *SN) {
  BasicBlock *BB = SN->node()->getBlock();
  bool changed = false;

                                                                            
                  
  IRBuilder::InstructionDestroyer destroyer;

                                                                               
                                      
  for (auto &inst : *BB) {
                                                                      
    Value *tdzStorage = nullptr;
    ThrowIfEmptyInst *TIE = nullptr;
    if ((TIE = llvh::dyn_cast<ThrowIfEmptyInst>(&inst)) != nullptr) {
      auto *checkedValue = TIE->getCheckedValue();

      if (auto *LFI = llvh::dyn_cast<LoadFrameInst>(checkedValue)) {
        tdzStorage = LFI->getLoadVariable();
      } else if (auto *LSI = llvh::dyn_cast<LoadStackInst>(checkedValue)) {
        tdzStorage = LSI->getSingleOperand();
      } else {
        tdzStorage = checkedValue;
      }
    } else if (auto *SF = llvh::dyn_cast<StoreFrameInst>(&inst)) {
      tdzStorage = SF->getVariable();
                                            
      if (!tdzState_.count(tdzStorage))
        continue;
                                                                          
                                  
      if (SF->getValue()->getType().canBeEmpty()) {
        availableValues_.setInCurrentScope(tdzStorage, false);
        continue;
      }
    } else if (auto *SS = llvh::dyn_cast<StoreStackInst>(&inst)) {
      tdzStorage = SS->getPtr();
                                            
      if (!tdzState_.count(tdzStorage))
        continue;
                                                             
      if (SS->getValue()->getType().canBeEmpty()) {
        availableValues_.setInCurrentScope(tdzStorage, false);
        continue;
      }
    } else {
      continue;
    }

                                                                         
               
    if (!availableValues_.lookup(tdzStorage)) {
      availableValues_.setInCurrentScope(tdzStorage, true);
      continue;
    }

                                             
    if (!TIE)
      continue;

                                                                       
                   
    TIE->replaceAllUsesWith(TIE->getCheckedValue());
    destroyer.add(TIE);
    changed = true;
    ++NumTDZDedup;

                                                                     
    if (auto *LFI = llvh::dyn_cast<LoadFrameInst>(TIE->getCheckedValue())) {
      ++NumTDZFrameDedup;
      if (LFI->hasOneUser())
        destroyer.add(LFI);
    } else if (
        auto *LSI = llvh::dyn_cast<LoadStackInst>(TIE->getCheckedValue())) {
      ++NumTDZStackDedup;
      if (LSI->hasOneUser())
        destroyer.add(LSI);
    } else {
      ++NumTDZOtherDedup;
    }
  }

  return changed;
}

}                           

bool TDZDedup::runOnFunction(Function *F) {
  DominanceInfo DT{F};
  TDZDedupContext CCtx{F, DT};
  return CCtx.run();
}

std::unique_ptr<Pass> createTDZDedup() {
  return std::make_unique<TDZDedup>();
}

}                    

#undef DEBUG_TYPE

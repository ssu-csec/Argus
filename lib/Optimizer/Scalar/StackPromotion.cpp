/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "stackpromotion"

#include "hermes/Optimizer/Scalar/StackPromotion.h"
#include "hermes/IR/Analysis.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Optimizer/Scalar/Utils.h"
#include "hermes/Support/Statistic.h"

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/DenseSet.h"
#include "llvh/ADT/SetVector.h"
#include "llvh/Support/Debug.h"

using namespace hermes;
using llvh::dbgs;

STATISTIC(NumSP, "Number of stack allocations promoted");
STATISTIC(NumOpsPostponed, "Number of stack ops removed or postponed");

STATISTIC(NumConstProm, "Number of loads of single store constants promoted");
STATISTIC(NumInstProm, "Number of loads of single store instructions promoted");

                                                                          
static bool hasExternalUses(Variable *V) {
  auto *parent = V->getParent();

                   
  for (auto *U : V->getUsers()) {
    auto *I = cast<Instruction>(U);
                                                        
    if (I->getParent()->getParent() != parent->getFunction())
      return true;
  }

                       
  return false;
}

static void promoteConstVariable(
    DominanceInfo &DT,
    Variable *V,
    Function *func,
    Value *val) {
  IRBuilder builder(func->getParent());
  BasicBlock &entry = func->front();
  builder.setInsertionBlock(&entry);
  auto *stackVar = builder.createAllocStackInst(V->getName());
  stackVar->moveBefore(&*entry.begin());

  IRBuilder::InstructionDestroyer destroyer;

  bool needToKeepStores = false;

  for (auto *U : V->getUsers()) {
    if (auto *LF = llvh::dyn_cast<LoadFrameInst>(U)) {
      if (auto *P = llvh::dyn_cast<Parameter>(val)) {
        if (P->getParent() != LF->getParent()->getParent()) {
          needToKeepStores = true;
          continue;
        }

        LF->replaceAllUsesWith(val);
        destroyer.add(LF);
        NumConstProm++;
        continue;
      }

      if (llvh::isa<Literal>(val)) {
        LF->replaceAllUsesWith(val);
        destroyer.add(LF);
        NumConstProm++;
        continue;
      }

      if (auto *I = llvh::dyn_cast<Instruction>(val)) {
                                                                               
                                            
        if (I->getParent() == LF->getParent() && DT.properlyDominates(I, LF)) {
          LF->replaceAllUsesWith(I);
          destroyer.add(LF);
          NumInstProm++;
        }

                                                                              
                                                        
        needToKeepStores = true;
      }
      continue;
    }

    if (llvh::isa<StoreFrameInst>(U))
      continue;

    llvm_unreachable("invalid user!");
  }

                                                                       
  if (!needToKeepStores) {
    for (auto *U : V->getUsers()) {
      if (llvh::isa<LoadFrameInst>(U))
        continue;

      if (auto *SF = llvh::dyn_cast<StoreFrameInst>(U))
        destroyer.add(SF);
    }
  }

  ++NumSP;
}

namespace {

                                                                  
bool unionSets(
    llvh::DenseSet<Variable *> &current,
    llvh::DenseSet<Variable *> &toInsert) {
  unsigned previousSize = current.size();
  current.insert(toInsert.begin(), toInsert.end());
  return previousSize != current.size();
}

                                                                             
                                                
void collectCapturedVariables(
    llvh::DenseSet<Variable *> &captured,
    Function *base,
    Function *current) {
  for (auto &BB : *current) {
    for (auto &I : BB) {
      if (auto *create = llvh::dyn_cast<CreateFunctionInst>(&I)) {
        collectCapturedVariables(captured, base, create->getFunctionCode());
        continue;
      }

      Variable *var = nullptr;
      if (auto *load = llvh::dyn_cast<LoadFrameInst>(&I)) {
        var = load->getLoadVariable();
      } else if (auto *store = llvh::dyn_cast<StoreFrameInst>(&I)) {
        var = store->getVariable();
      }
      if (!var || var->getParent()->getFunction() != base)
        continue;

      captured.insert(var);
    }
  }
}

                                                                           
                                                                           
                       
                                                                              
                                                                         
                                                                               
                      
void determineCapturedVariableUsage(
    Function *F,
    llvh::DenseMap<BasicBlock *, llvh::DenseSet<Variable *>>
        &capturedVariableUsage,
    llvh::SetVector<Function *> &maybeUnreachableFuncs) {
  for (auto &BB : *F) {
    capturedVariableUsage.FindAndConstruct(&BB);
  }

  llvh::DenseSet<BasicBlock *> toPropagate;
  IRBuilder::InstructionDestroyer destroyer{};
  for (auto &BB : *F) {
    for (auto &I : BB) {
      auto *create = llvh::dyn_cast<CreateFunctionInst>(&I);
      if (!create)
        continue;

                                                                        
                                                          
      if (!create->hasUsers()) {
        destroyer.add(create);
        maybeUnreachableFuncs.insert(create->getFunctionCode());
        continue;
      }

      llvh::DenseSet<Variable *> variables;
      collectCapturedVariables(variables, F, create->getFunctionCode());

                                                                         
                                                                     
                                                                             
      for (auto *user : create->getUsers()) {
        auto *block = user->getParent();
        capturedVariableUsage[block].insert(variables.begin(), variables.end());
        toPropagate.insert(block);
      }
    }
  }

                                                                             
  while (toPropagate.size()) {
    auto *BB = *toPropagate.begin();
    toPropagate.erase(BB);

    for (auto I = succ_begin(BB), E = succ_end(BB); I != E; ++I) {
      if (unionSets(capturedVariableUsage[*I], capturedVariableUsage[BB])) {
        toPropagate.insert(*I);
      }
    }
  }
}

                                                       
                             
struct StorePoint {
  BasicBlock *from{};
  BasicBlock *to{};
  llvh::SmallVector<Variable *, 2> variables{};

  StorePoint(BasicBlock *from, BasicBlock *to) : from(from), to(to) {}
};

                                                             
                                                             
  
                            
                                                               
                     
                                                       
                                                      
        
      
                                
                                            
    
bool promoteVariables(
    Function *F,
    llvh::SetVector<Function *> &maybeUnreachableFuncs) {
  bool changed = false;

  llvh::DenseMap<BasicBlock *, llvh::DenseSet<Variable *>>
      capturedVariableUsage;
  determineCapturedVariableUsage(
      F, capturedVariableUsage, maybeUnreachableFuncs);

                                                              
  llvh::DenseMap<ScopeDesc *, ScopeCreationInst *> scopeCreation;
  auto scopeForVariable = [&scopeCreation](Variable *var) {
    ScopeCreationInst *sci = scopeCreation[var->getParent()];
    assert(sci && "missing scope creation for accessing variable.");
    return sci;
  };

  F->forEachScope([F, &scopeCreation](ScopeDesc *currScopeDesc) {
    for (Value *U : currScopeDesc->getUsers()) {
      if (auto *sci = llvh::dyn_cast<ScopeCreationInst>(U)) {
        if (currScopeDesc == sci->getCreatedScopeDesc()) {
          assert(
              F == currScopeDesc->getFunction() &&
              "materializing foreign scope");
          auto res = scopeCreation.insert(std::make_pair(currScopeDesc, sci));
          assert(
              !res.second ||
              res.first->second == sci && "multi instructions creating scope.");
          (void)res;
        }
      }
    }
    (void)F;
  });

                                                   
  llvh::DenseSet<Variable *> needsOptimizing;
  F->forEachScope([&](ScopeDesc *currScopeDesc) {
    for (auto *var : currScopeDesc->getVariables()) {
      if (!hasExternalUses(var)) {
                                                                               
        needsOptimizing.insert(var);
        continue;
      }

                                                                           
      for (auto *use : var->getUsers()) {
        if (use->getParent()->getParent() != F)
          continue;
        if (capturedVariableUsage[use->getParent()].count(var))
          continue;

                                                          
        needsOptimizing.insert(var);
        break;
      }
    }
  });

                                                                           
                                                                           
  IRBuilder builder(F);
  llvh::DenseMap<Variable *, AllocStackInst *> stackMap;

  F->forEachScope([&](ScopeDesc *currScopeDesc) {
    for (auto *var : currScopeDesc->getVariables()) {
      if (!needsOptimizing.count(var))
        continue;
      if (!var->getNumUsers())
        continue;

      builder.setInsertionPoint(&*F->begin()->begin());
      auto *stackVar = builder.createAllocStackInst(var->getName());
      builder.createStoreStackInst(builder.getLiteralUndefined(), stackVar);
      stackMap[var] = stackVar;
      changed = true;

      {
        IRBuilder::InstructionDestroyer destroyer;
        for (auto *U : var->getUsers()) {
                                                           
          if (U->getParent()->getParent() != F)
            continue;

                                                        
          if (capturedVariableUsage[U->getParent()].count(var))
            continue;

          NumOpsPostponed++;

          if (auto *LF = llvh::dyn_cast<LoadFrameInst>(U)) {
            builder.setInsertionPoint(LF);
            auto *LS = builder.createLoadStackInst(stackVar);
            LS->moveBefore(LF);
            LF->replaceAllUsesWith(LS);
            destroyer.add(LF);
            continue;
          }
          if (auto *SF = llvh::dyn_cast<StoreFrameInst>(U)) {
            builder.setInsertionPoint(SF);
            auto *SS = builder.createStoreStackInst(SF->getValue(), stackVar);
            SS->moveBefore(SF);
            destroyer.add(SF);
            continue;
          }
          llvm_unreachable("Invalid user");
        }
      }
                                         
      if (!var->getNumUsers()) {
        ++NumSP;
      }
    }
  });

                                                                     
                                       
  llvh::DenseSet<std::pair<BasicBlock *, Variable *>> alreadyProcessed;
  for (auto &BB : *F) {
                         
    if (!pred_count(&BB))
      continue;

    llvh::DenseSet<Variable *> commons = capturedVariableUsage[&BB];
    for (auto *predecessor : predecessors(&BB)) {
      llvh::SmallVector<Variable *, 4> toErase;
      for (auto *var : commons) {
        if (needsOptimizing.count(var) &&
            !capturedVariableUsage[predecessor].count(var))
          continue;
        toErase.push_back(var);
      }
      for (auto *var : toErase) {
        commons.erase(var);
      }
    }
    if (!commons.size())
      continue;

    auto insertionPoint = BB.begin();
    while (llvh::isa<TryEndInst>(*insertionPoint) ||
           llvh::isa<CatchInst>(*insertionPoint) ||
           llvh::isa<PhiInst>(*insertionPoint)) {
      insertionPoint++;
    }
    builder.setInsertionPoint(&*insertionPoint);

                                                                           
    F->forEachScope([&](ScopeDesc *currScopeDesc) {
      for (auto *var : currScopeDesc->getVariables()) {
        if (!commons.count(var))
          continue;
                                                                           
                                                                            
                                   
                                                                              
                                                                        
        auto *value = builder.createLoadStackInst(stackMap[var]);
        builder.createStoreFrameInst(value, var, scopeForVariable(var));
        alreadyProcessed.insert(std::pair<BasicBlock *, Variable *>(&BB, var));
        changed = true;
      }
    });
  }

                                                                   
                                
  llvh::SmallVector<StorePoint, 4> storePoints;
  for (auto &BB : *F) {
    TerminatorInst *terminator = BB.getTerminator();
    auto &usedHere = capturedVariableUsage[&BB];

                                                                             
                                                  
                                                              
                                         
    llvh::SmallPtrSet<BasicBlock *, 16> storeSuccessors;
    for (int i = 0, e = terminator->getNumSuccessors(); i < e; i++) {
      auto *next = terminator->getSuccessor(i);
                                                  
      if (!storeSuccessors.insert(next).second) {
        continue;
      }
      auto &usedNext = capturedVariableUsage[next];
      StorePoint *point = nullptr;

      F->forEachScope([&](ScopeDesc *currScopeDesc) {
        for (auto *var : currScopeDesc->getVariables()) {
          if (!needsOptimizing.count(var))
            continue;
                                                           
                                                
          if (usedHere.count(var) || !usedNext.count(var))
            continue;
                                                               
          if (alreadyProcessed.count(
                  std::pair<BasicBlock *, Variable *>(next, var)))
            continue;

          if (!point) {
            storePoints.push_back(StorePoint(&BB, next));
            point = &storePoints.back();
          }
          point->variables.push_back(var);
        }
      });
    }
  }

                                                      
  for (auto &point : storePoints) {
    splitCriticalEdge(&builder, point.from, point.to);
    for (auto *var : point.variables) {
      auto *value = builder.createLoadStackInst(stackMap[var]);
      builder.createStoreFrameInst(value, var, scopeForVariable(var));
      changed = true;
    }
  }
  return changed;
}

bool runOnFunction(
    Function *F,
    llvh::SetVector<Function *> &maybeUnreachableFuncs) {
  bool changed = false;

  LLVM_DEBUG(
      dbgs() << "Promoting variables in " << F->getInternalNameStr() << "\n");
  DominanceInfo DT(F);

  F->forEachScope([&](ScopeDesc *currScopeDesc) {
    for (auto *V : currScopeDesc->getVariables()) {
                                    
      if (Value *val = isStoreOnceVariable(V)) {
        promoteConstVariable(DT, V, F, val);
      }
    }
  });
  promoteVariables(F, maybeUnreachableFuncs);

                                                                             
                               
  F->forEachScope([&](ScopeDesc *currScopeDesc) {
    auto &vars = currScopeDesc->getMutableVariables();
    vars.erase(
        std::remove_if(
            vars.begin(),
            vars.end(),
            [](Variable *V) {
              if (V->getNumUsers())
                return false;
              Value::destroy(V);
              return true;
            }),
        vars.end());
  });

  return changed;
}

}             

bool StackPromotion::runOnModule(Module *M) {
  bool changed = false;
                                                                   
  llvh::SetVector<Function *> maybeUnreachableFuncs{};
  for (Function &func : *M) {
    Function *F = &func;
                                                              
    if (maybeUnreachableFuncs.count(F) && !F->hasUsers())
      continue;
    changed |= runOnFunction(F, maybeUnreachableFuncs);
  }

                                                                               
                                                                     
    
                                                                                
                                                                           
                                                                                
                                                                                
                          
  while (!maybeUnreachableFuncs.empty()) {
    Function *F = maybeUnreachableFuncs.pop_back_val();
    if (F->hasUsers())
      continue;

                                                                             
                       
    for (auto &BB : *F) {
      for (auto &I : BB) {
        if (auto *CFI = llvh::dyn_cast<CreateFunctionInst>(&I))
          maybeUnreachableFuncs.insert(CFI->getFunctionCode());
      }
    }
    F->eraseFromParentNoDestroy();
    Value::destroy(F);
  }

  return changed;
}

std::unique_ptr<Pass> hermes::createStackPromotion() {
  return std::make_unique<StackPromotion>();
}

#undef DEBUG_TYPE

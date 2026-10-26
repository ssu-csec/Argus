/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "simplifycfg"

#include "hermes/Optimizer/Scalar/SimplifyCFG.h"
#include "hermes/IR/Analysis.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/IREval.h"
#include "hermes/Optimizer/Scalar/Utils.h"
#include "hermes/Support/Statistic.h"

#include "llvh/ADT/SmallPtrSet.h"
#include "llvh/ADT/SmallVector.h"

using namespace hermes;

STATISTIC(NumUnreachableBlock, "Number of unreachable blocks eliminated");
STATISTIC(NumSB, "Number of static branches simplified");

                                                                            
                   
static bool isCrossCatchRegionBranch(BasicBlock *src, BasicBlock *dest) {
  auto kind = dest->front().getKind();
  if (kind == ValueKind::TryStartInstKind ||
      kind == ValueKind::TryEndInstKind || kind == ValueKind::CatchInstKind)
    return true;
  return false;
}

                                                               
static bool isUsedInPhiNode(BasicBlock *BB) {
  for (auto use : BB->getUsers())
    if (llvh::isa<PhiInst>(use))
      return true;

  return false;
}

static void removeEntryFromPhi(BasicBlock *BB, BasicBlock *edge) {
                                
  for (auto &it : *BB) {
    auto *P = llvh::dyn_cast<PhiInst>(&it);
    if (!P)
      continue;
                          
    for (int i = 0, e = P->getNumEntries(); i < e; i++) {
      auto E = P->getEntry(i);
                                  
      if (E.second == edge) {
        P->removeEntry(i);
        break;
      }
    }
  }
}

                                                                       
                              
static void replaceCondBranchWithDirectBranch(
    CondBranchInst *CB,
    BasicBlock *dest) {
  BasicBlock *currentBlock = CB->getParent();
  auto *trueDest = CB->getTrueDest();
  auto *falseDest = CB->getFalseDest();

  if (trueDest != dest)
    removeEntryFromPhi(trueDest, currentBlock);
  if (falseDest != dest)
    removeEntryFromPhi(falseDest, currentBlock);

  IRBuilder builder(currentBlock->getParent());
  builder.setInsertionBlock(currentBlock);
  builder.createBranchInst(dest);
  CB->eraseFromParent();
}

                                             
static bool attemptBranchRemovalFromPhiNodes(BasicBlock *BB) {
                                                                
  if (BB->getTerminator() != &*(BB->begin()) ||
      BB->getTerminator()->getKind() != ValueKind::BranchInstKind) {
    return false;
  }

                                                       
                                      
  llvh::SmallPtrSet<BasicBlock *, 8> blockParents;
                                                                       
  llvh::SmallVector<BasicBlock *, 8> orderedParents;
  for (const auto *user : BB->getUsers()) {
    switch (user->getKind()) {
      case ValueKind::BranchInstKind:
      case ValueKind::CondBranchInstKind:
      case ValueKind::SwitchInstKind:
      case ValueKind::GetPNamesInstKind:
      case ValueKind::GetNextPNameInstKind:
                                                                       
                                                                    
        if (blockParents.count(user->getParent()) == 0) {
          orderedParents.push_back(user->getParent());
        }
        blockParents.insert(user->getParent());
        break;
      case ValueKind::PhiInstKind:
                                                                    
                           
        break;
      default:
                                                                            
                                                                      
        return false;
    }
  }

  if (blockParents.empty()) {
    return false;
  }

  BasicBlock *phiBlock = nullptr;

                                                                 
  for (auto *user : BB->getUsers()) {
    if (auto *phi = llvh::dyn_cast<PhiInst>(user)) {
      if (phiBlock && phi->getParent() != phiBlock) {
                                                                          
                                                                           
        llvm_unreachable(
            "Different BBs use Phi for BB with single static jump");
      }
      phiBlock = phi->getParent();

      Value *ourValue = nullptr;
      for (unsigned int i = 0; i < phi->getNumEntries(); i++) {
        auto entry = phi->getEntry(i);
        if (entry.second == BB) {
          if (ourValue) {
                                                                         
            llvm_unreachable("Phi node has multiple entries for a branch.");
          }
          ourValue = entry.first;
        }
      }

      if (!ourValue) {
        llvm_unreachable("getUsers returned a non-user PhiInst");
      }

      for (unsigned int i = 0; i < phi->getNumEntries(); i++) {
        auto entry = phi->getEntry(i);
        if (blockParents.count(entry.second)) {
                                                                            
                  
                                          
                  
                            
                  
                                       
          if (entry.first == ourValue) {
                                                                           
                               
          } else {
                                                                  
                                                                       
                                         
            return false;
          }
        }
      }
    }
  }
  if (!phiBlock) {
    llvm_unreachable("We shouldn't be in this function if there are no Phis.");
  }

                                                                
  for (auto *user : BB->getUsers()) {
    if (auto *phi = llvh::dyn_cast<PhiInst>(user)) {
      Value *ourValue = nullptr;

      const unsigned int numEntries = phi->getNumEntries();
      for (unsigned int i = 0; i < numEntries; i++) {
        auto entry = phi->getEntry(i);
        if (entry.second == BB) {
          ourValue = entry.first;
        }
      }
      assert(ourValue && "getUsers returned a non-user PhiInst");

      for (int i = phi->getNumEntries() - 1; i >= 0; i--) {
        auto pair = phi->getEntry(i);
        if (pair.second == BB || blockParents.count(pair.second)) {
          phi->removeEntry(i);
        }
      }

                                                                      
      for (BasicBlock *parent : orderedParents) {
        phi->addEntry(ourValue, parent);
      }
    }
  }
                                                                         
                                                                            
  BB->replaceAllUsesWith(phiBlock);
  BB->eraseFromParent();
  return true;
}

                                                                           
                                                                               
                                                                        
static bool literalStrictEquality(Literal *L1, Literal *L2) {
  if (llvh::isa<LiteralNumber>(L1) && llvh::isa<LiteralNumber>(L2)) {
    return llvh::cast<LiteralNumber>(L1)->getValue() ==
        llvh::cast<LiteralNumber>(L2)->getValue();
  }
  return L1 == L2;
}

                                                                         
                                          
static bool simplifySwitchInst(SwitchInst *SI) {
  auto *thisBlock = SI->getParent();
  IRBuilder builder(thisBlock->getParent());
  builder.setInsertionBlock(thisBlock);

  Value *input = SI->getInputValue();
  auto *litInput = llvh::dyn_cast<Literal>(input);

                                                            
  if (!litInput) {
    return false;
  }

  auto *destination = SI->getDefaultDestination();

  for (unsigned i = 0, e = SI->getNumCasePair(); i < e; i++) {
    auto switchCase = SI->getCasePair(i);

                                           
    if (literalStrictEquality(switchCase.first, litInput)) {
      destination = switchCase.second;
      break;
    }
  }

                                                                               
  for (unsigned i = 0, e = SI->getNumSuccessors(); i < e; i++) {
    auto *successor = SI->getSuccessor(i);
    if (successor == destination)
      continue;
    deleteIncomingBlockFromPhis(successor, thisBlock);
  }

  auto *newBranch = builder.createBranchInst(destination);
  SI->replaceAllUsesWith(newBranch);
  SI->eraseFromParent();
  return true;
}

                                                                          
                             
static bool optimizeStaticBranches(Function *F) {
  bool changed = false;
  IRBuilder builder(F);

                                                           
  for (auto &it : *F) {
    BasicBlock *BB = &it;

                                                                               
                     
    if (auto *switchInst = llvh::dyn_cast<SwitchInst>(BB->getTerminator())) {
      changed |= simplifySwitchInst(switchInst);
      continue;
    }

    auto *cbr = llvh::dyn_cast<CondBranchInst>(BB->getTerminator());
    if (!cbr)
      continue;

    BasicBlock *trueDest = cbr->getTrueDest();
    BasicBlock *falseDest = cbr->getFalseDest();

                                                                               
                
    if (trueDest == falseDest) {
      replaceCondBranchWithDirectBranch(cbr, trueDest);
      changed = true;
      ++NumSB;
      continue;
    }

                                                                              
                                     
    auto *cond = cbr->getCondition();
    BasicBlock *dest = nullptr;

    if (LiteralBool *B = evalToBoolean(builder, cond)) {
      if (B->getValue()) {
        dest = trueDest;
      } else {
        dest = falseDest;
      }
    }

    if (dest != nullptr) {
      replaceCondBranchWithDirectBranch(cbr, dest);
      ++NumSB;
      changed = true;
      continue;
    }
  }                   

                                                                                
                                                                               
                                              
  for (auto &it : *F) {
    BasicBlock *BB = &it;
    auto *br = llvh::dyn_cast<BranchInst>(BB->getTerminator());
    if (!br)
      continue;

    BasicBlock *dest = br->getBranchDest();

                                                                  
    if (dest == BB)
      continue;

                                                          
    if (isCrossCatchRegionBranch(BB, dest))
      continue;

                                                   
    if (isUsedInPhiNode(BB)) {
      if (attemptBranchRemovalFromPhiNodes(BB)) {
        ++NumSB;
        changed = true;
        break;                         
      }
      continue;
    }

                                                                    
    bool isSingleInstr = (&*BB->begin() == br);

                                                                            
                                                                                
    if (isSingleInstr && !pred_empty(BB)) {
      BB->replaceAllUsesWith(dest);
      ++NumSB;
      changed = true;
      assert(pred_count(BB) == 0);
      continue;
    }

                                                                               
                                   
    if (pred_count(dest) == 1 && dest != BB) {
                                                                      
      while (dest->begin() != dest->end()) {
        dest->begin()->moveBefore(br);
      }

                                                                                
                                                                             
      dest->replaceAllUsesWith(BB);
      br->eraseFromParent();
      dest->eraseFromParent();
      ++NumSB;
      changed = true;

                                                                          
                                      
      break;
    }
  }                   

  return changed;
}

                                                          
static void deleteBasicBlock(BasicBlock *B) {
                                         

                                                                                
              
  Value::UseListTy users(B->getUsers().begin(), B->getUsers().end());

                                                                          
                                                                     
                        
  for (auto *I : users) {
    if (auto *Phi = llvh::dyn_cast<PhiInst>(I)) {
      Phi->removeEntry(B);
      continue;
    }
  }

                                                                        
  B->replaceAllUsesWith(nullptr);
                            
  B->eraseFromParent();
}

                                            
static bool removeUnreachedBasicBlocks(Function *F) {
  bool changed = false;

                                
  llvh::SmallPtrSet<BasicBlock *, 16> visited;
  llvh::SmallVector<BasicBlock *, 32> workList;

  workList.push_back(&*F->begin());
  while (!workList.empty()) {
    auto *BB = workList.pop_back_val();
                       
    if (!visited.insert(BB).second)
      continue;

    for (auto *succ : successors(BB))
      workList.push_back(succ);
  }

                                            
  for (auto it = F->begin(), e = F->end(); it != e;) {
    auto *BB = &*it++;
    if (!visited.count(BB)) {
      ++NumUnreachableBlock;
      deleteBasicBlock(BB);
      changed = true;
    }
  }

  return changed;
}

bool SimplifyCFG::runOnFunction(hermes::Function *F) {
  bool changed = false;

  bool iterChanged = false;
                                                                              
                                    
  do {
    iterChanged = optimizeStaticBranches(F) || removeUnreachedBasicBlocks(F);
    changed |= iterChanged;
  } while (iterChanged);

  return changed;
}

std::unique_ptr<Pass> hermes::createSimplifyCFG() {
  return std::make_unique<SimplifyCFG>();
}

#undef DEBUG_TYPE

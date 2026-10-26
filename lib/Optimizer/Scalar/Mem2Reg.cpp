/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "mem2reg"

#include "hermes/Optimizer/Scalar/Mem2Reg.h"
#include "hermes/IR/Analysis.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Optimizer/Scalar/Utils.h"
#include "hermes/Support/Statistic.h"

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/DenseSet.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/Support/Debug.h"

#include <queue>

using namespace hermes;
using llvh::dbgs;
using llvh::SmallPtrSet;
using llvh::SmallVector;
using llvh::SmallVectorImpl;

static const int kFrameSizeThreshold = 128;

STATISTIC(NumPhi, "Number of Phi inserted");
STATISTIC(NumAlloc, "Number of AllocStack removed");

STATISTIC(NumLoad, "Number of loads eliminated");
STATISTIC(NumStore, "Number of stores eliminated");
STATISTIC(NumSOL, "Number of store only locations");
STATISTIC(NumInitVar, "Number of init once variables");

using BlockSet = llvh::DenseSet<BasicBlock *>;
using BlockToInstMap = llvh::DenseMap<BasicBlock *, Instruction *>;

                                                                            
                                              
static bool getSingleInitializer(Variable *V) {
  StoreFrameInst *singleStore = nullptr;

  for (auto *U : V->getUsers()) {
    if (auto *S = llvh::dyn_cast<StoreFrameInst>(U)) {
                                     
      if (singleStore)
        return false;

                                                         
      if (S->getParent()->getParent() != V->getParent()->getFunction())
        return false;

      singleStore = S;
    }
  }

  return singleStore;
}

                                                                               
                                                                            
                                                                          
static void collectCapturedVariables(
    llvh::DenseSet<Variable *> &capturedLoads,
    llvh::DenseSet<Variable *> &capturedStores,
    Function *F) {
                                          
  for (auto blockIter = F->begin(), e = F->end(); blockIter != e; ++blockIter) {
    BasicBlock *BB = &*blockIter;
    for (auto &instIter : *BB) {
      Instruction *II = &instIter;

                                                                        
                 
      if (auto *CF = llvh::dyn_cast<CreateFunctionInst>(II)) {
        collectCapturedVariables(
            capturedLoads, capturedStores, CF->getFunctionCode());
        continue;
      }

      if (auto *LF = llvh::dyn_cast<LoadFrameInst>(II)) {
        Variable *V = LF->getLoadVariable();
        if (V->getParent()->getFunction() != F) {
          capturedLoads.insert(V);
        }
      }

      if (auto *SF = llvh::dyn_cast<StoreFrameInst>(II)) {
        auto *V = SF->getVariable();
        if (V->getParent()->getFunction() != F) {
          capturedStores.insert(V);
        }
      }
    }
  }
}

static bool promoteLoads(BasicBlock *BB) {
                                            
  Function *F = BB->getParent();
  bool isEntryBlock = (BB == &*F->begin());

                                                             
                                                                             
                     
  llvh::DenseMap<Variable *, Value *> knownFrameValues;

                                                                             
                              
  llvh::DenseMap<Variable *, Value *> constFrameValues;

                                                                               
                                                                          
                                                                            
                                                                              
                                                                               
                                                                          
                                                                           
                                      
  llvh::DenseMap<AllocStackInst *, Value *> knownStackValues;

                                                             
  llvh::DenseSet<Variable *> capturedVariableLoads;
                                                              
  llvh::DenseSet<Variable *> capturedVariableStores;

                                                                               
                                                 
  bool usePreciseCaptureAnalysis = isEntryBlock;

  IRBuilder::InstructionDestroyer destroyer;

  bool changed = false;

  for (auto &it : *BB) {
    Instruction *II = &it;

    if (auto *SS = llvh::dyn_cast<StoreStackInst>(II)) {
                                              
      knownStackValues[SS->getPtr()] = SS->getValue();
      continue;
    }

    if (auto *SF = llvh::dyn_cast<StoreFrameInst>(II)) {
      Variable *var = SF->getVariable();

                                              
      knownFrameValues[var] = SF->getValue();
      continue;
    }

                                                                      
                                                                      
              
    if (II->mayWriteMemory()) {
      for (unsigned i = 0, e = II->getNumOperands(); i != e; ++i) {
        if (auto *ASI = llvh::dyn_cast<AllocStackInst>(II->getOperand(i)))
          knownStackValues.erase(ASI);
      }
    }

                                                                
    if (auto *LS = llvh::dyn_cast<LoadStackInst>(II)) {
      AllocStackInst *dest = LS->getPtr();
      auto entry = knownStackValues.find(dest);

                                                                          
                                                                             
                                                                
      if (entry == knownStackValues.end()) {
        knownStackValues[dest] = LS;
        continue;
      }

                                                                
      LS->replaceAllUsesWith(entry->second);
      ++NumLoad;

                                                    
      destroyer.add(LS);
      changed = true;
      continue;
    }

                                                                
    if (auto *LF = llvh::dyn_cast<LoadFrameInst>(II)) {
      Variable *dest = LF->getLoadVariable();

                                                                            
                                           
      auto constEntry = constFrameValues.find(dest);
      if (constEntry != constFrameValues.end() &&
          dest->getParent()->getFunction() != LF->getParent()->getParent()) {
                                                                       
        LF->replaceAllUsesWith(constEntry->second);
        ++NumInitVar;

                                                      
        destroyer.add(LF);
        changed = true;
        continue;
      }

                                                                            
                                
      if (getSingleInitializer(dest)) {
        constFrameValues[dest] = LF;
      }

                                           
      auto entry = knownFrameValues.find(dest);

                                                                               
                                                                               
                            
      if (entry == knownFrameValues.end() || !entry->second) {
        knownFrameValues[dest] = LF;
        continue;
      }

                                                                     
      LF->replaceAllUsesWith(entry->second);
      ++NumLoad;

                                                    
      destroyer.add(LF);
      changed = true;
      continue;
    }

    if (auto *CF = llvh::dyn_cast<CreateFunctionInst>(II)) {
                                        
      if (usePreciseCaptureAnalysis) {
        collectCapturedVariables(
            capturedVariableLoads,
            capturedVariableStores,
            CF->getFunctionCode());
      }
    }

                                                                               
                                                         
    if (II->mayWriteMemory()) {
                                                                           
                                                    
      if (usePreciseCaptureAnalysis &&
          knownFrameValues.size() < kFrameSizeThreshold) {
                                         
        for (auto &I : knownFrameValues) {
                                                                                
                                                                               
          if (I.first->getParent()->getFunction() != F ||
              capturedVariableStores.count(I.first)) {
            I.second = nullptr;
          }
        }
      } else {
        knownFrameValues.clear();
      }
    }
  }

  return changed;
}

static bool eliminateStores(
    BasicBlock *BB,
    llvh::ArrayRef<AllocStackInst *> unsafeAllocas) {
                                            
  Function *F = BB->getParent();
  bool isEntryBlock = (BB == &*F->begin());

                                                          
  llvh::DenseMap<Variable *, StoreFrameInst *> prevStoreFrame;

                                                     
  llvh::DenseMap<AllocStackInst *, StoreStackInst *> prevStoreStack;

                                                     
  IRBuilder::InstructionDestroyer destroyer;

                                                       
  llvh::DenseSet<Variable *> capturedVariables;

                                                                               
                                                 
  bool usePreciseCaptureAnalysis = isEntryBlock;

  bool changed = false;

  for (auto &it : *BB) {
    Instruction *II = &it;

                                                                   
    if (auto *SF = llvh::dyn_cast<StoreFrameInst>(II)) {
      auto *V = SF->getVariable();
      auto entry = prevStoreFrame.find(V);

      if (entry != prevStoreFrame.end()) {
                                                                         
        if (entry->second) {
          destroyer.add(entry->second);
          ++NumStore;
          changed = true;
        }

        entry->second = SF;
        continue;
      }

      prevStoreFrame[V] = SF;
      continue;
    }

                                                                   
    if (auto *SS = llvh::dyn_cast<StoreStackInst>(II)) {
      auto *AS = SS->getPtr();
      auto entry = prevStoreStack.find(AS);

      if (entry != prevStoreStack.end()) {
                                                                         
        if (entry->second) {
          destroyer.add(entry->second);
          ++NumStore;
          changed = true;
        }

        entry->second = SS;
        continue;
      }

      prevStoreStack[AS] = SS;
      continue;
    }

                                          
    if (auto *LF = llvh::dyn_cast<LoadFrameInst>(II)) {
      auto *V = LF->getLoadVariable();
      prevStoreFrame[V] = nullptr;
      continue;
    }

                                          
    if (auto *LS = llvh::dyn_cast<LoadStackInst>(II)) {
      AllocStackInst *AS = LS->getPtr();
      prevStoreStack[AS] = nullptr;
      continue;
    }

    if (II->mayExecute()) {
      for (auto *A : unsafeAllocas) {
        prevStoreStack[A] = nullptr;
      }
    }

                                                                      
                                                                     
    if (II->mayReadMemory()) {
                                                                               
                                                                          
                                                      
                                                                           
                                                    
      if (usePreciseCaptureAnalysis &&
          prevStoreFrame.size() < kFrameSizeThreshold) {
                                         
        for (auto &I : prevStoreFrame) {
          if (I.first->getParent()->getFunction() != F ||
              capturedVariables.count(I.first)) {
            I.second = nullptr;
          }
        }
      } else {
                                    
        prevStoreFrame.clear();
      }
    }

    if (auto *CF = llvh::dyn_cast<CreateFunctionInst>(II)) {
                                        
      if (usePreciseCaptureAnalysis) {
        collectCapturedVariables(
            capturedVariables, capturedVariables, CF->getFunctionCode());
      }
    }
  }

  return changed;
}

                                                                    
static bool hasNonStoreUses(AllocStackInst *ASI) {
  for (auto *U : ASI->getUsers()) {
    if (!llvh::isa<StoreStackInst>(U))
      return true;
  }

  return false;
}

static bool eliminateStoreOnlyLocations(BasicBlock *BB) {
  bool changed = false;
  IRBuilder::InstructionDestroyer destroyer;

  for (auto &it : *BB) {
    auto *ASI = llvh::dyn_cast<AllocStackInst>(&it);
    if (!ASI)
      continue;

    if (hasNonStoreUses(ASI)) {
      continue;
    }

                                                                   
    for (auto *U : ASI->getUsers()) {
      destroyer.add(cast<Instruction>(U));
    }

    ++NumSOL;
    destroyer.add(ASI);
    changed = true;
  }

  return changed;
}

                                                                      
                                                                             
                                                     
   
                                                                            
                                                                             
                                                                       
static bool isUnsafeStackLocation(
    AllocStackInst *ASI,
    DominanceInfo *DT,
    BlockSet &exceptionHandlingBlocks) {
                                           
  for (auto *U : ASI->getUsers()) {
    if (llvh::isa<LoadStackInst>(U) || llvh::isa<StoreStackInst>(U)) {
                                                                                
                              
      for (auto *BB : exceptionHandlingBlocks) {
        if (DT->dominates(BB, U->getParent()))
          return true;
      }
                                            
      continue;
    }

                                                   
    return true;
  }

  return false;
}

                                                                               
                                                                                
                                                                 
static void collectStackAllocations(
    Function *F,
    DominanceInfo *DT,
    SmallVectorImpl<AllocStackInst *> &allocas,
    SmallVectorImpl<AllocStackInst *> &unsafe) {
                                                               
  BlockSet exceptionHandlingBlocks;
  for (auto &BB : *F) {
    Instruction *I = &*BB.begin();
    if (llvh::isa<TryStartInst>(BB.getTerminator()) ||
        llvh::isa<CatchInst>(I)) {
      exceptionHandlingBlocks.insert(&BB);
    }
  }

                                             
  for (auto &BB : *F) {
    for (auto &it : BB) {
      auto *ASI = llvh::dyn_cast<AllocStackInst>(&it);
      if (!ASI)
        continue;

                                                                               
                               
      if (isUnsafeStackLocation(ASI, DT, exceptionHandlingBlocks)) {
        unsafe.push_back(ASI);
        continue;
      }

      allocas.push_back(ASI);
    }
  }
}

using DomTreeNode = llvh::DomTreeNodeBase<BasicBlock>;
using DomTreeLevelMap = llvh::DenseMap<DomTreeNode *, unsigned>;

using DomTreeNodePair = std::pair<DomTreeNode *, unsigned>;
using NodePriorityQueue = std::priority_queue<
    DomTreeNodePair,
    SmallVector<DomTreeNodePair, 32>,
    llvh::less_second>;

                                                    
static void computeDomTreeLevels(
    DominanceInfo *DT,
    DomTreeLevelMap &DomTreeLevels) {
  SmallVector<DomTreeNode *, 32> worklist;
  DomTreeNode *root = DT->getRootNode();

                         
  DomTreeLevels[root] = 0;
  worklist.push_back(root);

                                                    
  while (!worklist.empty()) {
    DomTreeNode *Node = worklist.pop_back_val();
    unsigned ChildLevel = DomTreeLevels[Node] + 1;
                                     
    for (auto &CI : *Node) {
      DomTreeLevels[CI] = ChildLevel;
      worklist.push_back(CI);
    }
  }
}

static Value *getLiveOutValue(
    BasicBlock *startBB,
    BlockToInstMap &phiLoc,
    DominanceInfo &DT,
    BlockToInstMap &stores) {
  LLVM_DEBUG(llvh::dbgs() << "Searching for a value definition.\n");

                                                     
  for (DomTreeNode *Node = DT.getNode(startBB); Node; Node = Node->getIDom()) {
    BasicBlock *BB = Node->getBlock();

                                                                         
    auto it = stores.find(BB);
    if (it != stores.end()) {
      return cast<StoreStackInst>(it->second)->getValue();
    }

                                                  
    auto pit = phiLoc.find(BB);
    if (pit != phiLoc.end()) {
      return pit->second;
    }
                                         
  }
  LLVM_DEBUG(llvh::dbgs() << "Could not find a def. Using undefined.\n");
  IRBuilder builder(startBB->getParent());
  return builder.getLiteralUndefined();
}

                                                                              
                                      
static Value *getLiveInValue(
    BasicBlock *BB,
    BlockToInstMap &phiLoc,
    DominanceInfo &DT,
    BlockToInstMap &stores) {
                                                                             
                                       
  auto it = phiLoc.find(BB);
  if (it != phiLoc.end())
    return it->second;

  auto *node = DT.getNode(BB);
  if (!node) {
                                                                              
                                         
    IRBuilder builder(BB->getParent());
    return builder.getLiteralUndefined();
  }

  assert(DT.getNode(BB) && "Block must be a part of the dom tree");

                                                                              
                                                                              
                             

  DomTreeNode *IDom = node->getIDom();
  assert(IDom && "Reached the top of the tree!");

  return getLiveOutValue(IDom->getBlock(), phiLoc, DT, stores);
}

static void promoteAllocStackToSSA(
    AllocStackInst *ASI,
    DominanceInfo &DT,
    DomTreeLevelMap &domTreeLevels) {
                                                       
  BlockSet phiBlocks;

                                                                          
  NodePriorityQueue PQ;

                                                                              
                              
  for (auto *U : ASI->getUsers()) {
                                            
    if (llvh::isa<StoreStackInst>(U)) {
                                                                        
      if (DomTreeNode *Node = DT.getNode(U->getParent()))
        PQ.push(std::make_pair(Node, domTreeLevels[Node]));
    }
  }

  LLVM_DEBUG(llvh::dbgs() << " Found: " << PQ.size() << " Defs\n");

                                                                            
  llvh::SmallPtrSet<DomTreeNode *, 32> visited;

  SmallVector<DomTreeNode *, 32> worklist;

                                                                             
           
  while (!PQ.empty()) {
    DomTreeNodePair rootPair = PQ.top();
    PQ.pop();
    DomTreeNode *root = rootPair.first;
    unsigned rootLevel = rootPair.second;

                                                                            
                                                                           
                          
    worklist.clear();
    worklist.push_back(root);

    while (!worklist.empty()) {
      DomTreeNode *node = worklist.pop_back_val();
      BasicBlock *BB = node->getBlock();

                                        
      for (auto succ : successors(BB)) {
        DomTreeNode *succNode = DT.getNode(succ);

                                                        
        if (succNode->getIDom() == node)
          continue;

                                                                           
                             
        unsigned succLevel = domTreeLevels[succNode];
        if (succLevel > rootLevel)
          continue;

                                
        if (!visited.insert(succNode).second)
          continue;

                                                                                
        if (!DT.dominates(ASI->getParent(), succNode->getBlock()))
          continue;

                                                                         
                                                                           
        if (phiBlocks.insert(succ).second)
          PQ.push(std::make_pair(succNode, succLevel));
      }

                                                          
      for (auto &CI : *node)
        if (!visited.count(CI))
          worklist.push_back(CI);
    }
  }

  LLVM_DEBUG(llvh::dbgs() << " Found: " << phiBlocks.size() << " new PHIs\n");

                                                                              
                                                                                
                   

  BlockToInstMap phiLoc;

  IRBuilder builder(ASI->getParent()->getParent());

                                               
  for (auto *BB : phiBlocks) {
    builder.setInsertionPoint(&*BB->begin());
                                                                                
    phiLoc[BB] = builder.createPhiInst();
  }

  BlockToInstMap stores;
  llvh::SmallVector<LoadStackInst *, 16> loads;

                                          
  for (auto *U : ASI->getUsers()) {
    if (auto *L = llvh::dyn_cast<LoadStackInst>(U)) {
      loads.push_back(L);
      continue;
    }
    if (auto *S = llvh::dyn_cast<StoreStackInst>(U)) {
      assert(!stores.count(S->getParent()) && "multiple stores per block!");
      stores[S->getParent()] = S;
      continue;
    }
    llvm_unreachable("Invalid use");
  }

  LLVM_DEBUG(llvh::dbgs() << " Finished placing Phis \n");

                                               
  for (auto *BB : phiBlocks) {
    NumPhi++;
    auto *phi = cast<PhiInst>(phiLoc[BB]);

    SmallVector<BasicBlock *, 4> preds(predecessors(BB));
    SmallPtrSet<BasicBlock *, 4> processed{};
    for (auto *pred : preds) {
                                                                     
      if (!processed.insert(pred).second)
        continue;

      auto *val = getLiveOutValue(pred, phiLoc, DT, stores);
      phi->addEntry(val, pred);
    }
  }

  {
    IRBuilder::InstructionDestroyer destroyer;

                                                
    for (auto &ld : loads) {
      auto *repl = getLiveInValue(ld->getParent(), phiLoc, DT, stores);
      ld->replaceAllUsesWith(repl);
      destroyer.add(ld);
    }

                         
    for (auto &st : stores) {
      destroyer.add(st.second);
    }
  }

  NumAlloc++;
  LLVM_DEBUG(llvh::dbgs() << " Finished placing Phis \n");
}

bool Mem2Reg::runOnFunction(Function *F) {
  bool changed = false;
  DominanceInfo D(F);

                                                         
  DomTreeLevelMap domTreeLevels;
  computeDomTreeLevels(&D, domTreeLevels);

                                            
  SmallVector<AllocStackInst *, 16> allocations;

                                                             
  SmallVector<AllocStackInst *, 16> unsafeAllocations;

  collectStackAllocations(F, &D, allocations, unsafeAllocations);

  LLVM_DEBUG(
      dbgs() << "Optimizing loads and stores in " << F->getInternalNameStr()
             << "\n");

  for (auto &it : *F) {
    BasicBlock *BB = &it;
    changed |= promoteLoads(BB);
    changed |= eliminateStores(BB, unsafeAllocations);
  }

  for (auto &it : *F) {
    BasicBlock *BB = &it;
    changed |= eliminateStoreOnlyLocations(BB);
  }

  allocations.clear();
  unsafeAllocations.clear();
  collectStackAllocations(F, &D, allocations, unsafeAllocations);

  for (auto *ASI : allocations) {
    promoteAllocStackToSSA(ASI, D, domTreeLevels);
  }

  return changed;
}

std::unique_ptr<Pass> hermes::createMem2Reg() {
  return std::make_unique<Mem2Reg>();
}

#undef DEBUG_TYPE

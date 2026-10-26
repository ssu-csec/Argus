/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "cse"
#include "hermes/Optimizer/Scalar/CSE.h"
#include "hermes/IR/Analysis.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Optimizer/Scalar/Utils.h"
#include "hermes/Support/Statistic.h"

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/DenseSet.h"
#include "llvh/ADT/Hashing.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/ScopedHashTable.h"
#include "llvh/Support/RecyclingAllocator.h"

using namespace hermes;

STATISTIC(NumCSE, "Number of instructions CSE'd");

                                                                                
                                              
                                                                                

namespace {
                                                                         
                      
struct CSEValue {
  Instruction *inst_;

  CSEValue(Instruction *I) : inst_(I) {
    assert((isSentinel() || canHandle(I)) && "Inst can't be handled!");
  }

  bool isSentinel() const {
    return inst_ == llvh::DenseMapInfo<Instruction *>::getEmptyKey() ||
        inst_ == llvh::DenseMapInfo<Instruction *>::getTombstoneKey();
  }

                                                         
  static bool canHandle(Instruction *Inst) {
    return isSimpleSideEffectFreeInstruction(Inst);
  }
};
}                           

namespace llvh {
template <>
struct DenseMapInfo<CSEValue> {
  static inline CSEValue getEmptyKey() {
    return DenseMapInfo<hermes::Instruction *>::getEmptyKey();
  }
  static inline CSEValue getTombstoneKey() {
    return DenseMapInfo<hermes::Instruction *>::getTombstoneKey();
  }
  static unsigned getHashValue(CSEValue Val);
  static bool isEqual(CSEValue LHS, CSEValue RHS);
};
}                      

unsigned llvh::DenseMapInfo<CSEValue>::getHashValue(CSEValue Val) {
  return Val.inst_->getHashCode();
}

bool llvh::DenseMapInfo<CSEValue>::isEqual(CSEValue LHS, CSEValue RHS) {
  hermes::Instruction *LHSI = LHS.inst_, *RHSI = RHS.inst_;
  if (LHS.isSentinel() || RHS.isSentinel())
    return LHSI == RHSI;

  return LHSI->getKind() == RHSI->getKind() && LHSI->isIdenticalTo(RHSI);
}

                                                                                
                                              
                                                                                

namespace {

class CSEContext;

using CSEValueHTType = llvh::ScopedHashTableVal<CSEValue, Value *>;
using AllocatorTy =
    llvh::RecyclingAllocator<llvh::BumpPtrAllocator, CSEValueHTType>;
using ScopedHTType = llvh::ScopedHashTable<
    CSEValue,
    Value *,
    llvh::DenseMapInfo<CSEValue>,
    AllocatorTy>;

                                                                              
                                                                           
                                                                         
                                               
class StackNode : public DomTreeDFS::StackNode<CSEContext> {
 public:
  inline StackNode(CSEContext *ctx, const DominanceInfoNode *n);

 private:
                                                                       
                
  ScopedHTType::ScopeTy scope_;
};

                                                                          
                                                       
class CSEContext : public DomTreeDFS::Visitor<CSEContext, StackNode> {
 public:
  CSEContext(const DominanceInfo &DT)
      : DomTreeDFS::Visitor<CSEContext, StackNode>(DT) {}

  bool run() {
    return DFS();
  }

  bool processNode(StackNode *SN);

 private:
  friend StackNode;

                                                                             
                                                                            
                                                                               
                                                                               
                   
  ScopedHTType availableValues_{};
};

inline StackNode::StackNode(CSEContext *ctx, const DominanceInfoNode *n)
    : DomTreeDFS::StackNode<CSEContext>(ctx, n),
      scope_{ctx->availableValues_} {}
}                           

                                                                                
                                                 
                                                                                

bool CSEContext::processNode(StackNode *SN) {
  BasicBlock *BB = SN->node()->getBlock();
  bool changed = false;

                                                                            
                  
  IRBuilder::InstructionDestroyer destroyer;

                                                                               
                                      
  for (auto &Inst : *BB) {
                                                                             
    if (!CSEValue::canHandle(&Inst))
      continue;

                                                                       
                                                          
    if (Value *V = availableValues_.lookup(&Inst)) {
      Inst.replaceAllUsesWith(V);
      destroyer.add(&Inst);
      changed = true;
      ++NumCSE;
      continue;
    }

                                                             
    availableValues_.insert(&Inst, &Inst);
  }

  return changed;
}

bool CSE::runOnFunction(Function *F) {
  DominanceInfo DT{F};
  CSEContext CCtx{DT};
  return CCtx.run();
}

std::unique_ptr<Pass> hermes::createCSE() {
  return std::make_unique<CSE>();
}

#undef DEBUG_TYPE

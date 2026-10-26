//===- Dominators.h - Dominator Info Calculation ----------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the DominatorTree class, which provides fast and efficient
// dominance queries.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_DOMINATORS_H
#define LLVM_IR_DOMINATORS_H

#include "llvh/ADT/DenseMapInfo.h"
#include "llvh/ADT/DepthFirstIterator.h"
#include "llvh/ADT/GraphTraits.h"
#include "llvh/ADT/Hashing.h"
#include "llvh/IR/BasicBlock.h"
#include "llvh/IR/CFG.h"
#include "llvh/IR/PassManager.h"
#include "llvh/Pass.h"
#include "llvh/Support/GenericDomTree.h"
#include <utility>

namespace llvh {

class Function;
class Instruction;
class Module;
class raw_ostream;

extern template class DomTreeNodeBase<BasicBlock>;
extern template class DominatorTreeBase<BasicBlock, false>;           
extern template class DominatorTreeBase<BasicBlock, true>;               

extern template class cfg::Update<BasicBlock *>;

namespace DomTreeBuilder {
using BBDomTree = DomTreeBase<BasicBlock>;
using BBPostDomTree = PostDomTreeBase<BasicBlock>;

using BBUpdates = ArrayRef<llvh::cfg::Update<BasicBlock *>>;

extern template void Calculate<BBDomTree>(BBDomTree &DT);
extern template void CalculateWithUpdates<BBDomTree>(BBDomTree &DT,
                                                     BBUpdates U);

extern template void Calculate<BBPostDomTree>(BBPostDomTree &DT);

extern template void InsertEdge<BBDomTree>(BBDomTree &DT, BasicBlock *From,
                                           BasicBlock *To);
extern template void InsertEdge<BBPostDomTree>(BBPostDomTree &DT,
                                               BasicBlock *From,
                                               BasicBlock *To);

extern template void DeleteEdge<BBDomTree>(BBDomTree &DT, BasicBlock *From,
                                           BasicBlock *To);
extern template void DeleteEdge<BBPostDomTree>(BBPostDomTree &DT,
                                               BasicBlock *From,
                                               BasicBlock *To);

extern template void ApplyUpdates<BBDomTree>(BBDomTree &DT, BBUpdates);
extern template void ApplyUpdates<BBPostDomTree>(BBPostDomTree &DT, BBUpdates);

extern template bool Verify<BBDomTree>(const BBDomTree &DT,
                                       BBDomTree::VerificationLevel VL);
extern template bool Verify<BBPostDomTree>(const BBPostDomTree &DT,
                                           BBPostDomTree::VerificationLevel VL);
}                             

using DomTreeNode = DomTreeNodeBase<BasicBlock>;

class BasicBlockEdge {
  const BasicBlock *Start;
  const BasicBlock *End;

public:
  BasicBlockEdge(const BasicBlock *Start_, const BasicBlock *End_) :
    Start(Start_), End(End_) {}

  BasicBlockEdge(const std::pair<BasicBlock *, BasicBlock *> &Pair)
      : Start(Pair.first), End(Pair.second) {}

  BasicBlockEdge(const std::pair<const BasicBlock *, const BasicBlock *> &Pair)
      : Start(Pair.first), End(Pair.second) {}

  const BasicBlock *getStart() const {
    return Start;
  }

  const BasicBlock *getEnd() const {
    return End;
  }

                                                           
  bool isSingleEdge() const;
};

template <> struct DenseMapInfo<BasicBlockEdge> {
  using BBInfo = DenseMapInfo<const BasicBlock *>;

  static unsigned getHashValue(const BasicBlockEdge *V);

  static inline BasicBlockEdge getEmptyKey() {
    return BasicBlockEdge(BBInfo::getEmptyKey(), BBInfo::getEmptyKey());
  }

  static inline BasicBlockEdge getTombstoneKey() {
    return BasicBlockEdge(BBInfo::getTombstoneKey(), BBInfo::getTombstoneKey());
  }

  static unsigned getHashValue(const BasicBlockEdge &Edge) {
    return hash_combine(BBInfo::getHashValue(Edge.getStart()),
                        BBInfo::getHashValue(Edge.getEnd()));
  }

  static bool isEqual(const BasicBlockEdge &LHS, const BasicBlockEdge &RHS) {
    return BBInfo::isEqual(LHS.getStart(), RHS.getStart()) &&
           BBInfo::isEqual(LHS.getEnd(), RHS.getEnd());
  }
};

                                                                    
                          
   
                                                                              
                                                                               
                                                                
   
                                                                           
                                                                               
                                                                              
                                                                            
                                                       
   
                                                                         
                                                                             
                                                                            
                                                                             
                                                                            
class DominatorTree : public DominatorTreeBase<BasicBlock, false> {
 public:
  using Base = DominatorTreeBase<BasicBlock, false>;

  DominatorTree() = default;
  explicit DominatorTree(Function &F) { recalculate(F); }
  explicit DominatorTree(DominatorTree &DT, DomTreeBuilder::BBUpdates U) {
    recalculate(*DT.Parent, U);
  }

                                     
  bool invalidate(Function &F, const PreservedAnalyses &PA,
                  FunctionAnalysisManager::Invalidator &);

                                             
  using Base::dominates;

                                                 
     
                                                                                
                                                                      
  bool dominates(const Instruction *Def, const Use &U) const;
  bool dominates(const Instruction *Def, const Instruction *User) const;
  bool dominates(const Instruction *Def, const BasicBlock *BB) const;

                                             
     
                                                                           
                             
  bool dominates(const BasicBlockEdge &BBE, const Use &U) const;
  bool dominates(const BasicBlockEdge &BBE, const BasicBlock *BB) const;

                                             
  using Base::isReachableFromEntry;

                                    
  bool isReachableFromEntry(const Use &U) const;

                                                                              
  void viewGraph(const Twine &Name, const Twine &Title);
  void viewGraph();
};

                                          
                                                                        
                                       

template <class Node, class ChildIterator> struct DomTreeGraphTraitsBase {
  using NodeRef = Node *;
  using ChildIteratorType = ChildIterator;
  using nodes_iterator = df_iterator<Node *, df_iterator_default_set<Node*>>;

  static NodeRef getEntryNode(NodeRef N) { return N; }
  static ChildIteratorType child_begin(NodeRef N) { return N->begin(); }
  static ChildIteratorType child_end(NodeRef N) { return N->end(); }

  static nodes_iterator nodes_begin(NodeRef N) {
    return df_begin(getEntryNode(N));
  }

  static nodes_iterator nodes_end(NodeRef N) { return df_end(getEntryNode(N)); }
};

template <>
struct GraphTraits<DomTreeNode *>
    : public DomTreeGraphTraitsBase<DomTreeNode, DomTreeNode::iterator> {};

template <>
struct GraphTraits<const DomTreeNode *>
    : public DomTreeGraphTraitsBase<const DomTreeNode,
                                    DomTreeNode::const_iterator> {};

template <> struct GraphTraits<DominatorTree*>
  : public GraphTraits<DomTreeNode*> {
  static NodeRef getEntryNode(DominatorTree *DT) { return DT->getRootNode(); }

  static nodes_iterator nodes_begin(DominatorTree *N) {
    return df_begin(getEntryNode(N));
  }

  static nodes_iterator nodes_end(DominatorTree *N) {
    return df_end(getEntryNode(N));
  }
};

                                                    
class DominatorTreeAnalysis : public AnalysisInfoMixin<DominatorTreeAnalysis> {
  friend AnalysisInfoMixin<DominatorTreeAnalysis>;
  static AnalysisKey Key;

public:
                                                        
  using Result = DominatorTree;

                                                                         
  DominatorTree run(Function &F, FunctionAnalysisManager &);
};

                                          
class DominatorTreePrinterPass
    : public PassInfoMixin<DominatorTreePrinterPass> {
  raw_ostream &OS;

public:
  explicit DominatorTreePrinterPass(raw_ostream &OS);

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
};

                                           
struct DominatorTreeVerifierPass : PassInfoMixin<DominatorTreeVerifierPass> {
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
};

                                                           
class DominatorTreeWrapperPass : public FunctionPass {
  DominatorTree DT;

public:
  static char ID;

  DominatorTreeWrapperPass() : FunctionPass(ID) {
    initializeDominatorTreeWrapperPassPass(*PassRegistry::getPassRegistry());
  }

  DominatorTree &getDomTree() { return DT; }
  const DominatorTree &getDomTree() const { return DT; }

  bool runOnFunction(Function &F) override;

  void verifyAnalysis() const override;

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesAll();
  }

  void releaseMemory() override { DT.releaseMemory(); }

  void print(raw_ostream &OS, const Module *M = nullptr) const override;
};
}                      

#endif                        

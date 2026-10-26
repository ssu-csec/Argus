/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_IR_ANALYSIS_H
#define HERMES_IR_ANALYSIS_H

#include "hermes/IR/CFG.h"
#include "hermes/IR/IR.h"
#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/Optional.h"
#include "llvh/ADT/SmallPtrSet.h"
#include "llvh/Support/RecyclingAllocator.h"

namespace hermes {

                                                                    
                                                                          
                                                                        
                                                                            
                                                               
class PostOrderAnalysis {
  using BlockList = std::vector<BasicBlock *>;

                                                         
  Context &ctx_;

                                             
  BlockList Order;

                                                                               
                                                                             
                 
  static void visitPostOrder(BasicBlock *BB, BlockList &order);

 public:
  explicit PostOrderAnalysis(Function *F);

  void dump();

  using iterator = decltype(Order)::iterator;
  using const_iterator = decltype(Order)::const_iterator;
  using reverse_iterator = decltype(Order)::reverse_iterator;
  using const_reverse_iterator = decltype(Order)::const_reverse_iterator;

  using range = llvh::iterator_range<iterator>;
  using const_range = llvh::iterator_range<const_iterator>;
  using reverse_range = llvh::iterator_range<reverse_iterator>;
  using const_reverse_range = llvh::iterator_range<const_reverse_iterator>;

  inline iterator begin() {
    return Order.begin();
  }
  inline iterator end() {
    return Order.end();
  }
  inline reverse_iterator rbegin() {
    return Order.rbegin();
  }
  inline reverse_iterator rend() {
    return Order.rend();
  }
  inline const_iterator begin() const {
    return Order.begin();
  }
  inline const_iterator end() const {
    return Order.end();
  }
  inline const_reverse_iterator rbegin() const {
    return Order.rbegin();
  }
  inline const_reverse_iterator rend() const {
    return Order.rend();
  }
};

                                                                          
                                                                               
                                                                             
                                                                              
                                                                    
   
                               
         
                                       
           
           
                                
           
           
                        
           
           
                            
            
class LoopAnalysis {
  template <typename T>
  using BlockMap = llvh::SmallDenseMap<const BasicBlock *, T, 16>;

                                                                                
                                                       
  BlockMap<BasicBlock *> blockToHeader_{};
                                                            
  BlockMap<BasicBlock *> headerToPreheader_{};

 public:
  explicit LoopAnalysis(Function *F, const DominanceInfo &dominanceInfo);

                                          
  bool isBlockInLoop(const BasicBlock *BB) const {
                                                                                
                                                               
    return blockToHeader_.count(BB);
  }
                                                           
  bool isBlockHeader(const BasicBlock *BB) const {
    return getLoopHeader(BB) == BB;
  }
                                                                                
                                         
  BasicBlock *getLoopHeader(const BasicBlock *BB) const;
                                                                                
                                                          
  BasicBlock *getLoopPreheader(const BasicBlock *BB) const;
};

                                                             
                                                         
                             
class FunctionScopeAnalysis {
  struct ScopeData {
                                                                        
                                                                                
                                                                              
    int32_t depth;

                                                                        
                                                                                
                     
    bool orphaned;

    ScopeData(int32_t depth = 0, bool orphaned = false)
        : depth(depth), orphaned(orphaned) {}

                                                            
    static ScopeData orphan() {
      return ScopeData(0, true);
    }
  };

  using LexicalScopeDescMap = llvh::DenseMap<const ScopeDesc *, ScopeData>;
  LexicalScopeDescMap lexicalScopeDescMap_{};

                                                                       
                                                                             
                         
                                            
  ScopeData calculateFunctionScopeData(
      ScopeDesc *scopeDesc,
      llvh::Optional<int> depth = llvh::None);

  static Function *computeParent(
      ScopeDesc *thisScope,
      ScopeDesc *parentScope,
      const ScopeData &sd);

 public:
  explicit FunctionScopeAnalysis(Function *entryPoint) {
    ScopeData data =
        calculateFunctionScopeData(entryPoint->getFunctionScopeDesc(), 0);
    assert(!data.orphaned && data.depth == 0);
    (void)data;
  }

                                         
  llvh::Optional<int32_t> getScopeDepth(ScopeDesc *S);
};

                                                                            
                                             
namespace DomTreeDFS {

                                                                         
                                                                              
                                                                              
                                                 
template <typename Visitor>
class StackNode {
 public:
  StackNode(const StackNode &) = delete;
  void operator=(const StackNode &) = delete;

  StackNode(Visitor *, const DominanceInfoNode *n)
      : node_(n), childIter_(n->begin()), endIter_(n->end()), done_(false) {}

               
  const DominanceInfoNode *node() {
    return node_;
  }
                                                                         
  DominanceInfoNode *nextChild() {
    return childIter_ == endIter_ ? nullptr : *childIter_++;
  }
  bool isDone() {
    return done_;
  }
  void markDone() {
    done_ = true;
  }

 private:
             
  const DominanceInfoNode *node_;
  DominanceInfoNode::const_iterator childIter_;
  const DominanceInfoNode::const_iterator endIter_;
  bool done_;
};

                                                                            
                                  
template <typename Derived, typename StackNode>
class Visitor {
  llvh::RecyclingAllocator<llvh::BumpPtrAllocator, StackNode> nodeAllocator_;

  Derived *derived() {
    return static_cast<Derived *>(this);
  }

  StackNode *newNode(const DominanceInfoNode *n) {
    auto *sn = nodeAllocator_.Allocate();
    return new (sn) StackNode(derived(), n);
  }
  void freeNode(StackNode *n) {
    n->~StackNode();
    nodeAllocator_.Deallocate(n);
  }

 protected:
  const DominanceInfo &DT_;

  Visitor(const DominanceInfo &DT) : DT_(DT) {}

                                  
  bool DFS() {
    return DFS(DT_.getRootNode());
  }

                                        
  bool DFS(const DominanceInfoNode *DIN) {
    llvh::SmallVector<StackNode *, 4> nodesToProcess;

    bool changed = false;

                             
    nodesToProcess.push_back(newNode(DIN));

                         
    while (!nodesToProcess.empty()) {
                                                                              
                                                 
      StackNode *toProcess = nodesToProcess.back();

                                                 
      if (!toProcess->isDone()) {
                            
        changed |= derived()->processNode(toProcess);
                                        
        toProcess->markDone();
      } else if (auto *child = toProcess->nextChild()) {
                                              
        nodesToProcess.push_back(newNode(child));
      } else {
                                                                            
                                  
        freeNode(nodesToProcess.pop_back_val());
      }
    }

    return changed;
  }
};

}                        

}                        

#endif

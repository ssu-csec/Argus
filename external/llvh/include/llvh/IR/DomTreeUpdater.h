//===- DomTreeUpdater.h - DomTree/Post DomTree Updater ----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the DomTreeUpdater class, which provides a uniform way to
// update dominator tree related data structures.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_DOMTREEUPDATER_H
#define LLVM_DOMTREEUPDATER_H

#include "llvh/Analysis/PostDominators.h"
#include "llvh/IR/Dominators.h"
#include "llvh/IR/Instructions.h"
#include "llvh/IR/ValueHandle.h"
#include "llvh/Support/GenericDomTree.h"
#include <functional>
#include <vector>

namespace llvh {
class DomTreeUpdater {
public:
  enum class UpdateStrategy : unsigned char { Eager = 0, Lazy = 1 };

  explicit DomTreeUpdater(UpdateStrategy Strategy_) : Strategy(Strategy_) {}
  DomTreeUpdater(DominatorTree &DT_, UpdateStrategy Strategy_)
      : DT(&DT_), Strategy(Strategy_) {}
  DomTreeUpdater(DominatorTree *DT_, UpdateStrategy Strategy_)
      : DT(DT_), Strategy(Strategy_) {}
  DomTreeUpdater(PostDominatorTree &PDT_, UpdateStrategy Strategy_)
      : PDT(&PDT_), Strategy(Strategy_) {}
  DomTreeUpdater(PostDominatorTree *PDT_, UpdateStrategy Strategy_)
      : PDT(PDT_), Strategy(Strategy_) {}
  DomTreeUpdater(DominatorTree &DT_, PostDominatorTree &PDT_,
                 UpdateStrategy Strategy_)
      : DT(&DT_), PDT(&PDT_), Strategy(Strategy_) {}
  DomTreeUpdater(DominatorTree *DT_, PostDominatorTree *PDT_,
                 UpdateStrategy Strategy_)
      : DT(DT_), PDT(PDT_), Strategy(Strategy_) {}

  ~DomTreeUpdater() { flush(); }

                                                   
  bool isLazy() const { return Strategy == UpdateStrategy::Lazy; };

                                                    
  bool isEager() const { return Strategy == UpdateStrategy::Eager; };

                                               
  bool hasDomTree() const { return DT != nullptr; }

                                                   
  bool hasPostDomTree() const { return PDT != nullptr; }

                                                            
                                                           
                                         
                                               
  bool hasPendingDeletedBB() const { return !DeletedBBs.empty(); }

                                                 
                                               
  bool isBBPendingDeletion(BasicBlock *DelBB) const;

                                                                      
                                                                     
                                                                
                                                    
                                               
  bool hasPendingUpdates() const;

                                                             
                                                                
  bool hasPendingDomTreeUpdates() const;

                                                                 
                                                                 
  bool hasPendingPostDomTreeUpdates() const;

                                                                           
                                                                         
                                                                               
                                                                          
                                                                        
                                                                        
                                                                            
                                                                                
                                                                             
  void applyUpdates(ArrayRef<DominatorTree::UpdateType> Updates,
                    bool ForceRemoveDuplicates = false);

                                                                             
                                                                         
                                                                       
                                                                       
                                                                         
                                                                              
                                                                               
                                                                               
                        
  void insertEdge(BasicBlock *From, BasicBlock *To);

                                                      
                                                                           
                                                                    
                               
                                      
                                                                               
                                                                                
                                                                             
             
  void insertEdgeRelaxed(BasicBlock *From, BasicBlock *To);

                                                                            
                                                                         
                                                                       
                                                                       
                                                                         
                                                                              
                                                                               
                                                                               
                               
  void deleteEdge(BasicBlock *From, BasicBlock *To);

                                                     
                                                                           
                                                                 
                               
                                      
                                                                               
                                                                                
                                                                             
             
  void deleteEdgeRelaxed(BasicBlock *From, BasicBlock *To);

                                                             
                                                                       
                                                                      
                                                                             
                                                                               
                                                                                
                                             
  void deleteBB(BasicBlock *DelBB);

                                                             
                                                                      
                                                
                                                                      
                                                                             
                                                                               
                                                                                
                                      
  void callbackDeleteBB(BasicBlock *DelBB,
                        std::function<void(BasicBlock *)> Callback);

                                                               
                                    
  void recalculate(Function &F);

                                               
                                                                      
                                                         
                                                   
  DominatorTree &getDomTree();

                                                       
                                                                      
                                                         
                                                       
  PostDominatorTree &getPostDomTree();

                                                                            
                        
                                              
  void flush();

                                                                 
  LLVM_DUMP_METHOD void dump() const;

private:
  class CallBackOnDeletion final : public CallbackVH {
  public:
    CallBackOnDeletion(BasicBlock *V,
                       std::function<void(BasicBlock *)> Callback)
        : CallbackVH(V), DelBB(V), Callback_(Callback) {}

  private:
    BasicBlock *DelBB = nullptr;
    std::function<void(BasicBlock *)> Callback_;

    void deleted() override {
      Callback_(DelBB);
      CallbackVH::deleted();
    }
  };

  SmallVector<DominatorTree::UpdateType, 16> PendUpdates;
  size_t PendDTUpdateIndex = 0;
  size_t PendPDTUpdateIndex = 0;
  DominatorTree *DT = nullptr;
  PostDominatorTree *PDT = nullptr;
  const UpdateStrategy Strategy;
  SmallPtrSet<BasicBlock *, 8> DeletedBBs;
  std::vector<CallBackOnDeletion> Callbacks;
  bool IsRecalculatingDomTree = false;
  bool IsRecalculatingPostDomTree = false;

                                                                               
                                                                              
                                                                                
                                                                              
                                                                         
  void validateDeleteBB(BasicBlock *DelBB);

                                                         
  bool forceFlushDeletedBB();

                                                                         
                                                                      
  bool applyLazyUpdate(DominatorTree::UpdateKind Kind, BasicBlock *From,
                       BasicBlock *To);

                                                           
  void applyDomTreeUpdates();

                                                               
  void applyPostDomTreeUpdates();

                                                                   
                           
  void tryFlushDeletedBB();

                                                                               
                                         
  void dropOutOfDateUpdates();

                                                                 
                                     
  void eraseDelBBNode(BasicBlock *DelBB);

                                                        
                                                       
                                                                  
  bool isUpdateValid(DominatorTree::UpdateType Update) const;

                                                   
  bool isSelfDominance(DominatorTree::UpdateType Update) const;
};
}                  

#endif                         

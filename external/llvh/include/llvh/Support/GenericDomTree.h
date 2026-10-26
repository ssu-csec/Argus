//===- GenericDomTree.h - Generic dominator trees for graphs ----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
/// \file
///
/// This file defines a set of templates that efficiently compute a dominator
/// tree over a generic graph. This is used typically in LLVM for fast
/// dominance queries on the CFG, but is fully generic w.r.t. the underlying
/// graph types.
///
/// Unlike ADT/* graph algorithms, generic dominator tree has more requirements
/// on the graph's NodeRef. The NodeRef should be a pointer and,
/// NodeRef->getParent() must return the parent node that is also a pointer.
///
/// FIXME: Maybe GenericDomTree needs a TreeTraits, instead of GraphTraits.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_GENERICDOMTREE_H
#define LLVM_SUPPORT_GENERICDOMTREE_H

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/GraphTraits.h"
#include "llvh/ADT/PointerIntPair.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/SmallPtrSet.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/Support/CFGUpdate.h"
#include "llvh/Support/raw_ostream.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <iterator>
#include <memory>
#include <type_traits>
#include <utility>
#include <vector>

namespace llvh {

template <typename NodeT, bool IsPostDom>
class DominatorTreeBase;

namespace DomTreeBuilder {
template <typename DomTreeT>
struct SemiNCAInfo;
}                             

                                                  
template <class NodeT> class DomTreeNodeBase {
  friend class PostDominatorTree;
  friend class DominatorTreeBase<NodeT, false>;
  friend class DominatorTreeBase<NodeT, true>;
  friend struct DomTreeBuilder::SemiNCAInfo<DominatorTreeBase<NodeT, false>>;
  friend struct DomTreeBuilder::SemiNCAInfo<DominatorTreeBase<NodeT, true>>;

  NodeT *TheBB;
  DomTreeNodeBase *IDom;
  unsigned Level;
  std::vector<DomTreeNodeBase *> Children;
  mutable unsigned DFSNumIn = ~0;
  mutable unsigned DFSNumOut = ~0;

 public:
  DomTreeNodeBase(NodeT *BB, DomTreeNodeBase *iDom)
      : TheBB(BB), IDom(iDom), Level(IDom ? IDom->Level + 1 : 0) {}

  using iterator = typename std::vector<DomTreeNodeBase *>::iterator;
  using const_iterator =
      typename std::vector<DomTreeNodeBase *>::const_iterator;

  iterator begin() { return Children.begin(); }
  iterator end() { return Children.end(); }
  const_iterator begin() const { return Children.begin(); }
  const_iterator end() const { return Children.end(); }

  NodeT *getBlock() const { return TheBB; }
  DomTreeNodeBase *getIDom() const { return IDom; }
  unsigned getLevel() const { return Level; }

  const std::vector<DomTreeNodeBase *> &getChildren() const { return Children; }

  std::unique_ptr<DomTreeNodeBase> addChild(
      std::unique_ptr<DomTreeNodeBase> C) {
    Children.push_back(C.get());
    return C;
  }

  size_t getNumChildren() const { return Children.size(); }

  void clearAllChildren() { Children.clear(); }

  bool compare(const DomTreeNodeBase *Other) const {
    if (getNumChildren() != Other->getNumChildren())
      return true;

    if (Level != Other->Level) return true;

    SmallPtrSet<const NodeT *, 4> OtherChildren;
    for (const DomTreeNodeBase *I : *Other) {
      const NodeT *Nd = I->getBlock();
      OtherChildren.insert(Nd);
    }

    for (const DomTreeNodeBase *I : *this) {
      const NodeT *N = I->getBlock();
      if (OtherChildren.count(N) == 0)
        return true;
    }
    return false;
  }

  void setIDom(DomTreeNodeBase *NewIDom) {
    assert(IDom && "No immediate dominator?");
    if (IDom == NewIDom) return;

    auto I = find(IDom->Children, this);
    assert(I != IDom->Children.end() &&
           "Not in immediate dominator children set!");
                                   
    IDom->Children.erase(I);

                              
    IDom = NewIDom;
    IDom->Children.push_back(this);

    UpdateLevel();
  }

                                                                                
                                                              
                                         
  unsigned getDFSNumIn() const { return DFSNumIn; }
  unsigned getDFSNumOut() const { return DFSNumOut; }

private:
                                                                              
              
  bool DominatedBy(const DomTreeNodeBase *other) const {
    return this->DFSNumIn >= other->DFSNumIn &&
           this->DFSNumOut <= other->DFSNumOut;
  }

  void UpdateLevel() {
    assert(IDom);
    if (Level == IDom->Level + 1) return;

    SmallVector<DomTreeNodeBase *, 64> WorkStack = {this};

    while (!WorkStack.empty()) {
      DomTreeNodeBase *Current = WorkStack.pop_back_val();
      Current->Level = Current->IDom->Level + 1;

      for (DomTreeNodeBase *C : *Current) {
        assert(C->IDom);
        if (C->Level != C->IDom->Level + 1) WorkStack.push_back(C);
      }
    }
  }
};

template <class NodeT>
raw_ostream &operator<<(raw_ostream &O, const DomTreeNodeBase<NodeT> *Node) {
  if (Node->getBlock())
    Node->getBlock()->printAsOperand(O, false);
  else
    O << " <<exit node>>";

  O << " {" << Node->getDFSNumIn() << "," << Node->getDFSNumOut() << "} ["
    << Node->getLevel() << "]\n";

  return O;
}

template <class NodeT>
void PrintDomTree(const DomTreeNodeBase<NodeT> *N, raw_ostream &O,
                  unsigned Lev) {
  O.indent(2 * Lev) << "[" << Lev << "] " << N;
  for (typename DomTreeNodeBase<NodeT>::const_iterator I = N->begin(),
                                                       E = N->end();
       I != E; ++I)
    PrintDomTree<NodeT>(*I, O, Lev + 1);
}

namespace DomTreeBuilder {
                                                                            
template <typename DomTreeT>
void Calculate(DomTreeT &DT);

template <typename DomTreeT>
void CalculateWithUpdates(DomTreeT &DT,
                          ArrayRef<typename DomTreeT::UpdateType> Updates);

template <typename DomTreeT>
void InsertEdge(DomTreeT &DT, typename DomTreeT::NodePtr From,
                typename DomTreeT::NodePtr To);

template <typename DomTreeT>
void DeleteEdge(DomTreeT &DT, typename DomTreeT::NodePtr From,
                typename DomTreeT::NodePtr To);

template <typename DomTreeT>
void ApplyUpdates(DomTreeT &DT,
                  ArrayRef<typename DomTreeT::UpdateType> Updates);

template <typename DomTreeT>
bool Verify(const DomTreeT &DT, typename DomTreeT::VerificationLevel VL);
}                             

                                   
   
                                                                             
                                                           
template <typename NodeT, bool IsPostDom>
class DominatorTreeBase {
 public:
  static_assert(std::is_pointer<typename GraphTraits<NodeT *>::NodeRef>::value,
                "Currently DominatorTreeBase supports only pointer nodes");
  using NodeType = NodeT;
  using NodePtr = NodeT *;
  using ParentPtr = decltype(std::declval<NodeT *>()->getParent());
  static_assert(std::is_pointer<ParentPtr>::value,
                "Currently NodeT's parent must be a pointer type");
  using ParentType = typename std::remove_pointer<ParentPtr>::type;
  static constexpr bool IsPostDominator = IsPostDom;

  using UpdateType = cfg::Update<NodePtr>;
  using UpdateKind = cfg::UpdateKind;
  static constexpr UpdateKind Insert = UpdateKind::Insert;
  static constexpr UpdateKind Delete = UpdateKind::Delete;

  enum class VerificationLevel { Fast, Basic, Full };

protected:
                                                                        
  SmallVector<NodeT *, IsPostDom ? 4 : 1> Roots;

  using DomTreeNodeMapType =
     DenseMap<NodeT *, std::unique_ptr<DomTreeNodeBase<NodeT>>>;
  DomTreeNodeMapType DomTreeNodes;
  DomTreeNodeBase<NodeT> *RootNode;
  ParentPtr Parent = nullptr;

  mutable bool DFSInfoValid = false;
  mutable unsigned int SlowQueries = 0;

  friend struct DomTreeBuilder::SemiNCAInfo<DominatorTreeBase>;

 public:
  DominatorTreeBase() {}

  DominatorTreeBase(DominatorTreeBase &&Arg)
      : Roots(std::move(Arg.Roots)),
        DomTreeNodes(std::move(Arg.DomTreeNodes)),
        RootNode(Arg.RootNode),
        Parent(Arg.Parent),
        DFSInfoValid(Arg.DFSInfoValid),
        SlowQueries(Arg.SlowQueries) {
    Arg.wipe();
  }

  DominatorTreeBase &operator=(DominatorTreeBase &&RHS) {
    Roots = std::move(RHS.Roots);
    DomTreeNodes = std::move(RHS.DomTreeNodes);
    RootNode = RHS.RootNode;
    Parent = RHS.Parent;
    DFSInfoValid = RHS.DFSInfoValid;
    SlowQueries = RHS.SlowQueries;
    RHS.wipe();
    return *this;
  }

  DominatorTreeBase(const DominatorTreeBase &) = delete;
  DominatorTreeBase &operator=(const DominatorTreeBase &) = delete;

                                                                             
                                                                       
                                                                      
     
  const SmallVectorImpl<NodeT *> &getRoots() const { return Roots; }

                                                                  
     
  bool isPostDominator() const { return IsPostDominator; }

                                                                          
                                                 
  bool compare(const DominatorTreeBase &Other) const {
    if (Parent != Other.Parent) return true;

    if (Roots.size() != Other.Roots.size())
      return true;

    if (!std::is_permutation(Roots.begin(), Roots.end(), Other.Roots.begin()))
      return true;

    const DomTreeNodeMapType &OtherDomTreeNodes = Other.DomTreeNodes;
    if (DomTreeNodes.size() != OtherDomTreeNodes.size())
      return true;

    for (const auto &DomTreeNode : DomTreeNodes) {
      NodeT *BB = DomTreeNode.first;
      typename DomTreeNodeMapType::const_iterator OI =
          OtherDomTreeNodes.find(BB);
      if (OI == OtherDomTreeNodes.end())
        return true;

      DomTreeNodeBase<NodeT> &MyNd = *DomTreeNode.second;
      DomTreeNodeBase<NodeT> &OtherNd = *OI->second;

      if (MyNd.compare(&OtherNd))
        return true;
    }

    return false;
  }

  void releaseMemory() { reset(); }

                                                                           
                                                                             
                                                                    
                                   
  DomTreeNodeBase<NodeT> *getNode(const NodeT *BB) const {
    auto I = DomTreeNodes.find(BB);
    if (I != DomTreeNodes.end())
      return I->second.get();
    return nullptr;
  }

                  
  DomTreeNodeBase<NodeT> *operator[](const NodeT *BB) const {
    return getNode(BB);
  }

                                                                                
                                                                                
                                                                            
                                                                             
                                                                     
                  
     
  DomTreeNodeBase<NodeT> *getRootNode() { return RootNode; }
  const DomTreeNodeBase<NodeT> *getRootNode() const { return RootNode; }

                                                       
  void getDescendants(NodeT *R, SmallVectorImpl<NodeT *> &Result) const {
    Result.clear();
    const DomTreeNodeBase<NodeT> *RN = getNode(R);
    if (!RN)
      return;                                                                
    SmallVector<const DomTreeNodeBase<NodeT> *, 8> WL;
    WL.push_back(RN);

    while (!WL.empty()) {
      const DomTreeNodeBase<NodeT> *N = WL.pop_back_val();
      Result.push_back(N->getBlock());
      WL.append(N->begin(), N->end());
    }
  }

                                                                    
                                                      
     
  bool properlyDominates(const DomTreeNodeBase<NodeT> *A,
                         const DomTreeNodeBase<NodeT> *B) const {
    if (!A || !B)
      return false;
    if (A == B)
      return false;
    return dominates(A, B);
  }

  bool properlyDominates(const NodeT *A, const NodeT *B) const;

                                                                       
                                          
  bool isReachableFromEntry(const NodeT *A) const {
    assert(!this->isPostDominator() &&
           "This is not implemented for post dominators");
    return isReachableFromEntry(getNode(const_cast<NodeT *>(A)));
  }

  bool isReachableFromEntry(const DomTreeNodeBase<NodeT> *A) const { return A; }

                                                                          
                              
     
  bool dominates(const DomTreeNodeBase<NodeT> *A,
                 const DomTreeNodeBase<NodeT> *B) const {
                                         
    if (B == A)
      return true;

                                                    
    if (!isReachableFromEntry(B))
      return true;

                             
    if (!isReachableFromEntry(A))
      return false;

    if (B->getIDom() == A) return true;

    if (A->getIDom() == B) return false;

                                                         
    if (A->getLevel() >= B->getLevel()) return false;

                                                                            
                          
#ifdef EXPENSIVE_CHECKS
    assert((!DFSInfoValid ||
            (dominatedBySlowTreeWalk(A, B) == B->DominatedBy(A))) &&
           "Tree walk disagrees with dfs numbers!");
#endif

    if (DFSInfoValid)
      return B->DominatedBy(A);

                                                               
                                                                    
    SlowQueries++;
    if (SlowQueries > 32) {
      updateDFSNumbers();
      return B->DominatedBy(A);
    }

    return dominatedBySlowTreeWalk(A, B);
  }

  bool dominates(const NodeT *A, const NodeT *B) const;

  NodeT *getRoot() const {
    assert(this->Roots.size() == 1 && "Should always have entry node!");
    return this->Roots[0];
  }

                                                                            
                                                                             
  NodeT *findNearestCommonDominator(NodeT *A, NodeT *B) const {
    assert(A && B && "Pointers are not valid");
    assert(A->getParent() == B->getParent() &&
           "Two blocks are not in same function");

                                                                            
                                
    if (!isPostDominator()) {
      NodeT &Entry = A->getParent()->front();
      if (A == &Entry || B == &Entry)
        return &Entry;
    }

    DomTreeNodeBase<NodeT> *NodeA = getNode(A);
    DomTreeNodeBase<NodeT> *NodeB = getNode(B);

    if (!NodeA || !NodeB) return nullptr;

                                                                           
                                                        
    while (NodeA && NodeA != NodeB) {
      if (NodeA->getLevel() < NodeB->getLevel()) std::swap(NodeA, NodeB);

      NodeA = NodeA->IDom;
    }

    return NodeA ? NodeA->getBlock() : nullptr;
  }

  const NodeT *findNearestCommonDominator(const NodeT *A,
                                          const NodeT *B) const {
                                                            
                                                 
    return findNearestCommonDominator(const_cast<NodeT *>(A),
                                      const_cast<NodeT *>(B));
  }

  bool isVirtualRoot(const DomTreeNodeBase<NodeT> *A) const {
    return isPostDominator() && !A->getBlock();
  }

                                                                                
                                                                            
               

                                                                           
                                                       
     
                                                                             
                                                                             
                                                                           
                        
                                                                        
                                                                          
                                                     
                                                                             
                                             
     
                                                                                
                                                                              
                                                                              
     
                                                                            
                                                                            
                                                                            
            
     
                                                                          
                                                                         
                                                                        
                                                                               
                                         
     
                                                                 
     
  void applyUpdates(ArrayRef<UpdateType> Updates) {
    DomTreeBuilder::ApplyUpdates(*this, Updates);
  }

                                                                               
     
                                                                                
                                                                             
                              
     
                                                                           
                                                                            
     
  void insertEdge(NodeT *From, NodeT *To) {
    assert(From);
    assert(To);
    assert(From->getParent() == Parent);
    assert(To->getParent() == Parent);
    DomTreeBuilder::InsertEdge(*this, From, To);
  }

                                                                              
     
                                                                               
                                                                               
                                                            
                                        
     
                                                                          
                                                                            
     
  void deleteEdge(NodeT *From, NodeT *To) {
    assert(From);
    assert(To);
    assert(From->getParent() == Parent);
    assert(To->getParent() == Parent);
    DomTreeBuilder::DeleteEdge(*this, From, To);
  }

                                                       
     
                                                                            
                                                        
     
                                
                                                     
                                                                    
     
  DomTreeNodeBase<NodeT> *addNewBlock(NodeT *BB, NodeT *DomBB) {
    assert(getNode(BB) == nullptr && "Block already in dominator tree!");
    DomTreeNodeBase<NodeT> *IDomNode = getNode(DomBB);
    assert(IDomNode && "Not immediate dominator specified for block!");
    DFSInfoValid = false;
    return (DomTreeNodes[BB] = IDomNode->addChild(
                llvh::make_unique<DomTreeNodeBase<NodeT>>(BB, IDomNode))).get();
  }

                                                                          
     
                                
                                                                    
     
  DomTreeNodeBase<NodeT> *setNewRoot(NodeT *BB) {
    assert(getNode(BB) == nullptr && "Block already in dominator tree!");
    assert(!this->isPostDominator() &&
           "Cannot change root of post-dominator tree");
    DFSInfoValid = false;
    DomTreeNodeBase<NodeT> *NewNode = (DomTreeNodes[BB] =
      llvh::make_unique<DomTreeNodeBase<NodeT>>(BB, nullptr)).get();
    if (Roots.empty()) {
      addRoot(BB);
    } else {
      assert(Roots.size() == 1);
      NodeT *OldRoot = Roots.front();
      auto &OldNode = DomTreeNodes[OldRoot];
      OldNode = NewNode->addChild(std::move(DomTreeNodes[OldRoot]));
      OldNode->IDom = NewNode;
      OldNode->UpdateLevel();
      Roots[0] = BB;
    }
    return RootNode = NewNode;
  }

                                                                            
                                                                 
     
  void changeImmediateDominator(DomTreeNodeBase<NodeT> *N,
                                DomTreeNodeBase<NodeT> *NewIDom) {
    assert(N && NewIDom && "Cannot change null node pointers!");
    DFSInfoValid = false;
    N->setIDom(NewIDom);
  }

  void changeImmediateDominator(NodeT *BB, NodeT *NewBB) {
    changeImmediateDominator(getNode(BB), getNode(NewBB));
  }

                                                                        
                                                                            
                                                                           
  void eraseNode(NodeT *BB) {
    DomTreeNodeBase<NodeT> *Node = getNode(BB);
    assert(Node && "Removing node that isn't in dominator tree.");
    assert(Node->getChildren().empty() && "Node is not a leaf node.");

    DFSInfoValid = false;

                                                            
    DomTreeNodeBase<NodeT> *IDom = Node->getIDom();
    if (IDom) {
      const auto I = find(IDom->Children, Node);
      assert(I != IDom->Children.end() &&
             "Not in immediate dominator children set!");
                                     
      IDom->Children.erase(I);
    }

    DomTreeNodes.erase(BB);

    if (!IsPostDom) return;

                                                  
    auto RIt = llvh::find(Roots, BB);
    if (RIt != Roots.end()) {
      std::swap(*RIt, Roots.back());
      Roots.pop_back();
    }
  }

                                                                             
                                  
  void splitBlock(NodeT *NewBB) {
    if (IsPostDominator)
      Split<Inverse<NodeT *>>(NewBB);
    else
      Split<NodeT *>(NewBB);
  }

                                            
     
  void print(raw_ostream &O) const {
    O << "=============================--------------------------------\n";
    if (IsPostDominator)
      O << "Inorder PostDominator Tree: ";
    else
      O << "Inorder Dominator Tree: ";
    if (!DFSInfoValid)
      O << "DFSNumbers invalid: " << SlowQueries << " slow queries.";
    O << "\n";

                                                                     
    if (getRootNode()) PrintDomTree<NodeT>(getRootNode(), O, 1);
    if (IsPostDominator) {
      O << "Roots: ";
      for (const NodePtr Block : Roots) {
        Block->printAsOperand(O, false);
        O << " ";
      }
      O << "\n";
    }
  }

public:
                                                                             
                                  
  void updateDFSNumbers() const {
    if (DFSInfoValid) {
      SlowQueries = 0;
      return;
    }

    SmallVector<std::pair<const DomTreeNodeBase<NodeT> *,
                          typename DomTreeNodeBase<NodeT>::const_iterator>,
                32> WorkStack;

    const DomTreeNodeBase<NodeT> *ThisRoot = getRootNode();
    assert((!Parent || ThisRoot) && "Empty constructed DomTree");
    if (!ThisRoot)
      return;

                                                                              
                                                              
    WorkStack.push_back({ThisRoot, ThisRoot->begin()});

    unsigned DFSNum = 0;
    ThisRoot->DFSNumIn = DFSNum++;

    while (!WorkStack.empty()) {
      const DomTreeNodeBase<NodeT> *Node = WorkStack.back().first;
      const auto ChildIt = WorkStack.back().second;

                                                                              
                                    
      if (ChildIt == Node->end()) {
        Node->DFSNumOut = DFSNum++;
        WorkStack.pop_back();
      } else {
                                                   
        const DomTreeNodeBase<NodeT> *Child = *ChildIt;
        ++WorkStack.back().second;

        WorkStack.push_back({Child, Child->begin()});
        Child->DFSNumIn = DFSNum++;
      }
    }

    SlowQueries = 0;
    DFSInfoValid = true;
  }

                                                                   
  void recalculate(ParentType &Func) {
    Parent = &Func;
    DomTreeBuilder::Calculate(*this);
  }

  void recalculate(ParentType &Func, ArrayRef<UpdateType> Updates) {
    Parent = &Func;
    DomTreeBuilder::CalculateWithUpdates(*this, Updates);
  }

                                                                                
                                                                        
                                                                            
                       
                                    
     
                                                                             
                                                                            
                                    
     
                                                                            
                                   
                                                                               
                                        
  bool verify(VerificationLevel VL = VerificationLevel::Full) const {
    return DomTreeBuilder::Verify(*this, VL);
  }

protected:
  void addRoot(NodeT *BB) { this->Roots.push_back(BB); }

  void reset() {
    DomTreeNodes.clear();
    Roots.clear();
    RootNode = nullptr;
    Parent = nullptr;
    DFSInfoValid = false;
    SlowQueries = 0;
  }

                                                                          
                         
  template <class N>
  void Split(typename GraphTraits<N>::NodeRef NewBB) {
    using GraphT = GraphTraits<N>;
    using NodeRef = typename GraphT::NodeRef;
    assert(std::distance(GraphT::child_begin(NewBB),
                         GraphT::child_end(NewBB)) == 1 &&
           "NewBB should have a single successor!");
    NodeRef NewBBSucc = *GraphT::child_begin(NewBB);

    std::vector<NodeRef> PredBlocks;
    for (const auto &Pred : children<Inverse<N>>(NewBB))
      PredBlocks.push_back(Pred);

    assert(!PredBlocks.empty() && "No predblocks?");

    bool NewBBDominatesNewBBSucc = true;
    for (const auto &Pred : children<Inverse<N>>(NewBBSucc)) {
      if (Pred != NewBB && !dominates(NewBBSucc, Pred) &&
          isReachableFromEntry(Pred)) {
        NewBBDominatesNewBBSucc = false;
        break;
      }
    }

                                                                              
             
    NodeT *NewBBIDom = nullptr;
    unsigned i = 0;
    for (i = 0; i < PredBlocks.size(); ++i)
      if (isReachableFromEntry(PredBlocks[i])) {
        NewBBIDom = PredBlocks[i];
        break;
      }

                                                                          
                                                                        
               
    if (!NewBBIDom) return;

    for (i = i + 1; i < PredBlocks.size(); ++i) {
      if (isReachableFromEntry(PredBlocks[i]))
        NewBBIDom = findNearestCommonDominator(NewBBIDom, PredBlocks[i]);
    }

                                                                       
    DomTreeNodeBase<NodeT> *NewBBNode = addNewBlock(NewBB, NewBBIDom);

                                                                             
                                                                         
    if (NewBBDominatesNewBBSucc) {
      DomTreeNodeBase<NodeT> *NewBBSuccNode = getNode(NewBBSucc);
      changeImmediateDominator(NewBBSuccNode, NewBBNode);
    }
  }

 private:
  bool dominatedBySlowTreeWalk(const DomTreeNodeBase<NodeT> *A,
                               const DomTreeNodeBase<NodeT> *B) const {
    assert(A != B);
    assert(isReachableFromEntry(B));
    assert(isReachableFromEntry(A));

    const unsigned ALevel = A->getLevel();
    const DomTreeNodeBase<NodeT> *IDom;

                                                                           
                                                                    
    while ((IDom = B->getIDom()) != nullptr && IDom->getLevel() >= ALevel)
      B = IDom;                     

    return B == A;
  }

                                                             
     
                                                                             
                                                              
  void wipe() {
    DomTreeNodes.clear();
    RootNode = nullptr;
    Parent = nullptr;
  }
};

template <typename T>
using DomTreeBase = DominatorTreeBase<T, false>;

template <typename T>
using PostDomTreeBase = DominatorTreeBase<T, true>;

                                                                            
                                                             
template <typename NodeT, bool IsPostDom>
bool DominatorTreeBase<NodeT, IsPostDom>::dominates(const NodeT *A,
                                                    const NodeT *B) const {
  if (A == B)
    return true;

                                                          
                                                              
                  
  return dominates(getNode(const_cast<NodeT *>(A)),
                   getNode(const_cast<NodeT *>(B)));
}
template <typename NodeT, bool IsPostDom>
bool DominatorTreeBase<NodeT, IsPostDom>::properlyDominates(
    const NodeT *A, const NodeT *B) const {
  if (A == B)
    return false;

                                                          
                                                              
                  
  return dominates(getNode(const_cast<NodeT *>(A)),
                   getNode(const_cast<NodeT *>(B)));
}

}                      

#endif                                 

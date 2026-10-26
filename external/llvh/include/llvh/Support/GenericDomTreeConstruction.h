//===- GenericDomTreeConstruction.h - Dominator Calculation ------*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
/// \file
///
/// Generic dominator tree construction - This file provides routines to
/// construct immediate dominator information for a flow-graph based on the
/// Semi-NCA algorithm described in this dissertation:
///
///   Linear-Time Algorithms for Dominators and Related Problems
///   Loukas Georgiadis, Princeton University, November 2005, pp. 21-23:
///   ftp://ftp.cs.princeton.edu/reports/2005/737.pdf
///
/// This implements the O(n*log(n)) versions of EVAL and LINK, because it turns
/// out that the theoretically slower O(n*log(n)) implementation is actually
/// faster than the almost-linear O(n*alpha(n)) version, even for large CFGs.
///
/// The file uses the Depth Based Search algorithm to perform incremental
/// updates (insertion and deletions). The implemented algorithm is based on
/// this publication:
///
///   An Experimental Study of Dynamic Dominators
///   Loukas Georgiadis, et al., April 12 2016, pp. 5-7, 9-10:
///   https://arxiv.org/pdf/1604.02711.pdf
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_GENERICDOMTREECONSTRUCTION_H
#define LLVM_SUPPORT_GENERICDOMTREECONSTRUCTION_H

#include <queue>
#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/DenseSet.h"
#include "llvh/ADT/DepthFirstIterator.h"
#include "llvh/ADT/PointerIntPair.h"
#include "llvh/ADT/SmallPtrSet.h"
#include "llvh/Support/Debug.h"
#include "llvh/Support/GenericDomTree.h"

#define DEBUG_TYPE "dom-tree-builder"

namespace llvh {
namespace DomTreeBuilder {

template <typename DomTreeT>
struct SemiNCAInfo {
  using NodePtr = typename DomTreeT::NodePtr;
  using NodeT = typename DomTreeT::NodeType;
  using TreeNodePtr = DomTreeNodeBase<NodeT> *;
  using RootsT = decltype(DomTreeT::Roots);
  static constexpr bool IsPostDom = DomTreeT::IsPostDominator;

                                                                  
  struct InfoRec {
    unsigned DFSNum = 0;
    unsigned Parent = 0;
    unsigned Semi = 0;
    NodePtr Label = nullptr;
    NodePtr IDom = nullptr;
    SmallVector<NodePtr, 2> ReverseChildren;
  };

                                                                            
                     
  std::vector<NodePtr> NumToNode = {nullptr};
  DenseMap<NodePtr, InfoRec> NodeToInfo;

  using UpdateT = typename DomTreeT::UpdateType;
  using UpdateKind = typename DomTreeT::UpdateKind;
  struct BatchUpdateInfo {
    SmallVector<UpdateT, 4> Updates;
    using NodePtrAndKind = PointerIntPair<NodePtr, 1, UpdateKind>;

                                                                         
                                                                            
                                                                              
                                                                         
                                                                        
                                                                              
                                                            
    DenseMap<NodePtr, SmallVector<NodePtrAndKind, 4>> FutureSuccessors;
    DenseMap<NodePtr, SmallVector<NodePtrAndKind, 4>> FuturePredecessors;
                                                                            
                            
    bool IsRecalculated = false;
  };

  BatchUpdateInfo *BatchUpdates;
  using BatchUpdatePtr = BatchUpdateInfo *;

                                                                   
  SemiNCAInfo(BatchUpdatePtr BUI) : BatchUpdates(BUI) {}

  void clear() {
    NumToNode = {nullptr};                                                     
    NodeToInfo.clear();
                                                                              
                                                            
  }

  template <bool Inverse>
  struct ChildrenGetter {
    using ResultTy = SmallVector<NodePtr, 8>;

    static ResultTy Get(NodePtr N, std::integral_constant<bool, false>) {
      auto RChildren = reverse(children<NodePtr>(N));
      return ResultTy(RChildren.begin(), RChildren.end());
    }

    static ResultTy Get(NodePtr N, std::integral_constant<bool, true>) {
      auto IChildren = inverse_children<NodePtr>(N);
      return ResultTy(IChildren.begin(), IChildren.end());
    }

    using Tag = std::integral_constant<bool, Inverse>;

                                                                              
                                                                              
                                                                               
                                                         
    static ResultTy Get(NodePtr N, BatchUpdatePtr BUI) {
      ResultTy Res = Get(N, Tag());
                                                                               
      if (!BUI) return Res;

                                                                              
                                                                           
                                                
      auto &FutureChildren = (Inverse != IsPostDom) ? BUI->FuturePredecessors
                                                    : BUI->FutureSuccessors;
      auto FCIt = FutureChildren.find(N);
      if (FCIt == FutureChildren.end()) return Res;

      for (auto ChildAndKind : FCIt->second) {
        const NodePtr Child = ChildAndKind.getPointer();
        const UpdateKind UK = ChildAndKind.getInt();

                                           
        if (UK == UpdateKind::Insert) {
                                                                               
                                                                        
          assert(llvh::find(Res, Child) != Res.end()
                 && "Expected child not found in the CFG");
          Res.erase(std::remove(Res.begin(), Res.end(), Child), Res.end());
          LLVM_DEBUG(dbgs() << "\tHiding edge " << BlockNamePrinter(N) << " -> "
                            << BlockNamePrinter(Child) << "\n");
        } else {
                                                                                
                                                                
          assert(llvh::find(Res, Child) == Res.end() &&
                 "Unexpected child found in the CFG");
          LLVM_DEBUG(dbgs() << "\tShowing virtual edge " << BlockNamePrinter(N)
                            << " -> " << BlockNamePrinter(Child) << "\n");
          Res.push_back(Child);
        }
      }

      return Res;
    }
  };

  NodePtr getIDom(NodePtr BB) const {
    auto InfoIt = NodeToInfo.find(BB);
    if (InfoIt == NodeToInfo.end()) return nullptr;

    return InfoIt->second.IDom;
  }

  TreeNodePtr getNodeForBlock(NodePtr BB, DomTreeT &DT) {
    if (TreeNodePtr Node = DT.getNode(BB)) return Node;

                                                                           
                           
    NodePtr IDom = getIDom(BB);

    assert(IDom || DT.DomTreeNodes[nullptr]);
    TreeNodePtr IDomNode = getNodeForBlock(IDom, DT);

                                                                    
               
    return (DT.DomTreeNodes[BB] = IDomNode->addChild(
        llvh::make_unique<DomTreeNodeBase<NodeT>>(BB, IDomNode)))
        .get();
  }

  static bool AlwaysDescend(NodePtr, NodePtr) { return true; }

  struct BlockNamePrinter {
    NodePtr N;

    BlockNamePrinter(NodePtr Block) : N(Block) {}
    BlockNamePrinter(TreeNodePtr TN) : N(TN ? TN->getBlock() : nullptr) {}

    friend raw_ostream &operator<<(raw_ostream &O, const BlockNamePrinter &BP) {
      if (!BP.N)
        O << "nullptr";
      else
        BP.N->printAsOperand(O, false);

      return O;
    }
  };

                                                                       
                                                                               
                                          
    
                                                                          
                                                                            
                              
  template <bool IsReverse = false, typename DescendCondition>
  unsigned runDFS(NodePtr V, unsigned LastNum, DescendCondition Condition,
                  unsigned AttachToNum) {
    assert(V);
    SmallVector<NodePtr, 64> WorkList = {V};
    if (NodeToInfo.count(V) != 0) NodeToInfo[V].Parent = AttachToNum;

    while (!WorkList.empty()) {
      const NodePtr BB = WorkList.pop_back_val();
      auto &BBInfo = NodeToInfo[BB];

                                                        
      if (BBInfo.DFSNum != 0) continue;
      BBInfo.DFSNum = BBInfo.Semi = ++LastNum;
      BBInfo.Label = BB;
      NumToNode.push_back(BB);

      constexpr bool Direction = IsReverse != IsPostDom;         
      for (const NodePtr Succ :
           ChildrenGetter<Direction>::Get(BB, BatchUpdates)) {
        const auto SIT = NodeToInfo.find(Succ);
                                                                   
                           
        if (SIT != NodeToInfo.end() && SIT->second.DFSNum != 0) {
          if (Succ != BB) SIT->second.ReverseChildren.push_back(BB);
          continue;
        }

        if (!Condition(BB, Succ)) continue;

                                                                            
                         
        auto &SuccInfo = NodeToInfo[Succ];
        WorkList.push_back(Succ);
        SuccInfo.Parent = LastNum;
        SuccInfo.ReverseChildren.push_back(BB);
      }
    }

    return LastNum;
  }

  NodePtr eval(NodePtr VIn, unsigned LastLinked) {
    auto &VInInfo = NodeToInfo[VIn];
    if (VInInfo.DFSNum < LastLinked)
      return VIn;

    SmallVector<NodePtr, 32> Work;
    SmallPtrSet<NodePtr, 32> Visited;

    if (VInInfo.Parent >= LastLinked)
      Work.push_back(VIn);

    while (!Work.empty()) {
      NodePtr V = Work.back();
      auto &VInfo = NodeToInfo[V];
      NodePtr VAncestor = NumToNode[VInfo.Parent];

                               
      if (Visited.insert(VAncestor).second && VInfo.Parent >= LastLinked) {
        Work.push_back(VAncestor);
        continue;
      }
      Work.pop_back();

                                            
      if (VInfo.Parent < LastLinked)
        continue;

      auto &VAInfo = NodeToInfo[VAncestor];
      NodePtr VAncestorLabel = VAInfo.Label;
      NodePtr VLabel = VInfo.Label;
      if (NodeToInfo[VAncestorLabel].Semi < NodeToInfo[VLabel].Semi)
        VInfo.Label = VAncestorLabel;
      VInfo.Parent = VAInfo.Parent;
    }

    return VInInfo.Label;
  }

                                                            
  void runSemiNCA(DomTreeT &DT, const unsigned MinLevel = 0) {
    const unsigned NextDFSNum(NumToNode.size());
                                                 
    for (unsigned i = 1; i < NextDFSNum; ++i) {
      const NodePtr V = NumToNode[i];
      auto &VInfo = NodeToInfo[V];
      VInfo.IDom = NumToNode[VInfo.Parent];
    }

                                                             
    for (unsigned i = NextDFSNum - 1; i >= 2; --i) {
      NodePtr W = NumToNode[i];
      auto &WInfo = NodeToInfo[W];

                                                                   
      WInfo.Semi = WInfo.Parent;
      for (const auto &N : WInfo.ReverseChildren) {
        if (NodeToInfo.count(N) == 0)                                   
          continue;

        const TreeNodePtr TN = DT.getNode(N);
                                                                                
        if (TN && TN->getLevel() < MinLevel)
          continue;

        unsigned SemiU = NodeToInfo[eval(N, i + 1)].Semi;
        if (SemiU < WInfo.Semi) WInfo.Semi = SemiU;
      }
    }

                                                                         
                                                              
                                                                           
                                       
    for (unsigned i = 2; i < NextDFSNum; ++i) {
      const NodePtr W = NumToNode[i];
      auto &WInfo = NodeToInfo[W];
      const unsigned SDomNum = NodeToInfo[NumToNode[WInfo.Semi]].DFSNum;
      NodePtr WIDomCandidate = WInfo.IDom;
      while (NodeToInfo[WIDomCandidate].DFSNum > SDomNum)
        WIDomCandidate = NodeToInfo[WIDomCandidate].IDom;

      WInfo.IDom = WIDomCandidate;
    }
  }

                                                                              
                                                                             
                                                                          
                                              
                                                                          
  void addVirtualRoot() {
    assert(IsPostDom && "Only postdominators have a virtual root");
    assert(NumToNode.size() == 1 && "SNCAInfo must be freshly constructed");

    auto &BBInfo = NodeToInfo[nullptr];
    BBInfo.DFSNum = BBInfo.Semi = 1;
    BBInfo.Label = nullptr;

    NumToNode.push_back(nullptr);                            
  }

                                                                                
                                                                                
                                        
  static bool HasForwardSuccessors(const NodePtr N, BatchUpdatePtr BUI) {
    assert(N && "N must be a valid node");
    return !ChildrenGetter<false>::Get(N, BUI).empty();
  }

  static NodePtr GetEntryNode(const DomTreeT &DT) {
    assert(DT.Parent && "Parent not set");
    return GraphTraits<typename DomTreeT::ParentPtr>::getEntryNode(DT.Parent);
  }

                                                                               
          
                                                                  
  static RootsT FindRoots(const DomTreeT &DT, BatchUpdatePtr BUI) {
    assert(DT.Parent && "Parent pointer is not set");
    RootsT Roots;

                                                                          
    if (!IsPostDom) {
      Roots.push_back(GetEntryNode(DT));
      return Roots;
    }

    SemiNCAInfo SNCA(BUI);

                                                   
    SNCA.addVirtualRoot();
    unsigned Num = 1;

    LLVM_DEBUG(dbgs() << "\t\tLooking for trivial roots\n");

                                                                            
                         
    unsigned Total = 0;
                                                                                
                                                                             
                                                                            
                                                                               
                         
    for (const NodePtr N : nodes(DT.Parent)) {
      ++Total;
                                                            
      if (!HasForwardSuccessors(N, BUI)) {
        Roots.push_back(N);
                                                      
        Num = SNCA.runDFS(N, Num, AlwaysDescend, 1);
        LLVM_DEBUG(dbgs() << "Found a new trivial root: " << BlockNamePrinter(N)
                          << "\n");
        LLVM_DEBUG(dbgs() << "Last visited node: "
                          << BlockNamePrinter(SNCA.NumToNode[Num]) << "\n");
      }
    }

    LLVM_DEBUG(dbgs() << "\t\tLooking for non-trivial roots\n");

                                                                              
                                                                               
                                
    bool HasNonTrivialRoots = false;
                                                                             
             
    if (Total + 1 != Num) {
      HasNonTrivialRoots = true;
                                                               
                                                                              
                 
                                                                               
                                                                              
                                                                       
                                       
      SmallPtrSet<NodePtr, 4> ConnectToExitBlock;
      for (const NodePtr I : nodes(DT.Parent)) {
        if (SNCA.NodeToInfo.count(I) == 0) {
          LLVM_DEBUG(dbgs()
                     << "\t\t\tVisiting node " << BlockNamePrinter(I) << "\n");
                                                                            
                                                                                
                                                                          
                                                                      
                                                        
                                                                               
                                                                                
                                                                               
                                                                                
                                                                          
          LLVM_DEBUG(dbgs() << "\t\t\tRunning forward DFS\n");

          const unsigned NewNum = SNCA.runDFS<true>(I, Num, AlwaysDescend, Num);
          const NodePtr FurthestAway = SNCA.NumToNode[NewNum];
          LLVM_DEBUG(dbgs() << "\t\t\tFound a new furthest away node "
                            << "(non-trivial root): "
                            << BlockNamePrinter(FurthestAway) << "\n");
          ConnectToExitBlock.insert(FurthestAway);
          Roots.push_back(FurthestAway);
          LLVM_DEBUG(dbgs() << "\t\t\tPrev DFSNum: " << Num << ", new DFSNum: "
                            << NewNum << "\n\t\t\tRemoving DFS info\n");
          for (unsigned i = NewNum; i > Num; --i) {
            const NodePtr N = SNCA.NumToNode[i];
            LLVM_DEBUG(dbgs() << "\t\t\t\tRemoving DFS info for "
                              << BlockNamePrinter(N) << "\n");
            SNCA.NodeToInfo.erase(N);
            SNCA.NumToNode.pop_back();
          }
          const unsigned PrevNum = Num;
          LLVM_DEBUG(dbgs() << "\t\t\tRunning reverse DFS\n");
          Num = SNCA.runDFS(FurthestAway, Num, AlwaysDescend, 1);
          for (unsigned i = PrevNum + 1; i <= Num; ++i)
            LLVM_DEBUG(dbgs() << "\t\t\t\tfound node "
                              << BlockNamePrinter(SNCA.NumToNode[i]) << "\n");
        }
      }
    }

    LLVM_DEBUG(dbgs() << "Total: " << Total << ", Num: " << Num << "\n");
    LLVM_DEBUG(dbgs() << "Discovered CFG nodes:\n");
    LLVM_DEBUG(for (size_t i = 0; i <= Num; ++i) dbgs()
               << i << ": " << BlockNamePrinter(SNCA.NumToNode[i]) << "\n");

    assert((Total + 1 == Num) && "Everything should have been visited");

                                                                            
    if (HasNonTrivialRoots) RemoveRedundantRoots(DT, BUI, Roots);

    LLVM_DEBUG(dbgs() << "Found roots: ");
    LLVM_DEBUG(for (auto *Root
                    : Roots) dbgs()
               << BlockNamePrinter(Root) << " ");
    LLVM_DEBUG(dbgs() << "\n");

    return Roots;
  }

                                                       
                                                                               
                                                                
                               
                                                                             
                                                                              
                                                                           
                 
  static void RemoveRedundantRoots(const DomTreeT &DT, BatchUpdatePtr BUI,
                                   RootsT &Roots) {
    assert(IsPostDom && "This function is for postdominators only");
    LLVM_DEBUG(dbgs() << "Removing redundant roots\n");

    SemiNCAInfo SNCA(BUI);

    for (unsigned i = 0; i < Roots.size(); ++i) {
      auto &Root = Roots[i];
                                                
      if (!HasForwardSuccessors(Root, BUI)) continue;
      LLVM_DEBUG(dbgs() << "\tChecking if " << BlockNamePrinter(Root)
                        << " remains a root\n");
      SNCA.clear();
                                                       
      const unsigned Num = SNCA.runDFS<true>(Root, 0, AlwaysDescend, 0);
                                                                              
                           
      for (unsigned x = 2; x <= Num; ++x) {
        const NodePtr N = SNCA.NumToNode[x];
                                                                               
                                                                                
               
        if (llvh::find(Roots, N) != Roots.end()) {
          LLVM_DEBUG(dbgs() << "\tForward DFS walk found another root "
                            << BlockNamePrinter(N) << "\n\tRemoving root "
                            << BlockNamePrinter(Root) << "\n");
          std::swap(Root, Roots.back());
          Roots.pop_back();

                                                             
                                                               
          --i;
          break;
        }
      }
    }
  }

  template <typename DescendCondition>
  void doFullDFSWalk(const DomTreeT &DT, DescendCondition DC) {
    if (!IsPostDom) {
      assert(DT.Roots.size() == 1 && "Dominators should have a singe root");
      runDFS(DT.Roots[0], 0, DC, 0);
      return;
    }

    addVirtualRoot();
    unsigned Num = 1;
    for (const NodePtr Root : DT.Roots) Num = runDFS(Root, Num, DC, 0);
  }

  static void CalculateFromScratch(DomTreeT &DT, BatchUpdatePtr BUI) {
    auto *Parent = DT.Parent;
    DT.reset();
    DT.Parent = Parent;
    SemiNCAInfo SNCA(nullptr);                                            
                                                                           

                                                                                
                                        
    DT.Roots = FindRoots(DT, nullptr);
    SNCA.doFullDFSWalk(DT, AlwaysDescend);

    SNCA.runSemiNCA(DT);
    if (BUI) {
      BUI->IsRecalculated = true;
      LLVM_DEBUG(
          dbgs() << "DomTree recalculated, skipping future batch updates\n");
    }

    if (DT.Roots.empty()) return;

                                                                             
                                                                               
                                                                       
    NodePtr Root = IsPostDom ? nullptr : DT.Roots[0];

    DT.RootNode = (DT.DomTreeNodes[Root] =
                       llvh::make_unique<DomTreeNodeBase<NodeT>>(Root, nullptr))
        .get();
    SNCA.attachNewSubtree(DT, DT.RootNode);
  }

  void attachNewSubtree(DomTreeT& DT, const TreeNodePtr AttachTo) {
                                                      
    NodeToInfo[NumToNode[1]].IDom = AttachTo->getBlock();
                                                                
    for (size_t i = 1, e = NumToNode.size(); i != e; ++i) {
      NodePtr W = NumToNode[i];
      LLVM_DEBUG(dbgs() << "\tdiscovered a new reachable node "
                        << BlockNamePrinter(W) << "\n");

                                                                                
      if (DT.DomTreeNodes[W]) continue;                                      

      NodePtr ImmDom = getIDom(W);

                                                               
      TreeNodePtr IDomNode = getNodeForBlock(ImmDom, DT);

                                                                           
                  
      DT.DomTreeNodes[W] = IDomNode->addChild(
          llvh::make_unique<DomTreeNodeBase<NodeT>>(W, IDomNode));
    }
  }

  void reattachExistingSubtree(DomTreeT &DT, const TreeNodePtr AttachTo) {
    NodeToInfo[NumToNode[1]].IDom = AttachTo->getBlock();
    for (size_t i = 1, e = NumToNode.size(); i != e; ++i) {
      const NodePtr N = NumToNode[i];
      const TreeNodePtr TN = DT.getNode(N);
      assert(TN);
      const TreeNodePtr NewIDom = DT.getNode(NodeToInfo[N].IDom);
      TN->setIDom(NewIDom);
    }
  }

                                               
  struct InsertionInfo {
    using BucketElementTy = std::pair<unsigned, TreeNodePtr>;
    struct DecreasingLevel {
      bool operator()(const BucketElementTy &First,
                      const BucketElementTy &Second) const {
        return First.first > Second.first;
      }
    };

    std::priority_queue<BucketElementTy, SmallVector<BucketElementTy, 8>,
        DecreasingLevel>
        Bucket;                                                             
    SmallDenseSet<TreeNodePtr, 8> Affected;
    SmallDenseMap<TreeNodePtr, unsigned, 8> Visited;
    SmallVector<TreeNodePtr, 8> AffectedQueue;
    SmallVector<TreeNodePtr, 8> VisitedNotAffectedQueue;
  };

  static void InsertEdge(DomTreeT &DT, const BatchUpdatePtr BUI,
                         const NodePtr From, const NodePtr To) {
    assert((From || IsPostDom) &&
           "From has to be a valid CFG node or a virtual root");
    assert(To && "Cannot be a nullptr");
    LLVM_DEBUG(dbgs() << "Inserting edge " << BlockNamePrinter(From) << " -> "
                      << BlockNamePrinter(To) << "\n");
    TreeNodePtr FromTN = DT.getNode(From);

    if (!FromTN) {
                                                                      
      if (!IsPostDom) return;

                                                                       
      TreeNodePtr VirtualRoot = DT.getNode(nullptr);
      FromTN =
          (DT.DomTreeNodes[From] = VirtualRoot->addChild(
               llvh::make_unique<DomTreeNodeBase<NodeT>>(From, VirtualRoot)))
              .get();
      DT.Roots.push_back(From);
    }

    DT.DFSInfoValid = false;

    const TreeNodePtr ToTN = DT.getNode(To);
    if (!ToTN)
      InsertUnreachable(DT, BUI, FromTN, To);
    else
      InsertReachable(DT, BUI, FromTN, ToTN);
  }

                                                                         
                                                                  
  static bool UpdateRootsBeforeInsertion(DomTreeT &DT, const BatchUpdatePtr BUI,
                                         const TreeNodePtr From,
                                         const TreeNodePtr To) {
    assert(IsPostDom && "This function is only for postdominators");
                                                                              
            
    if (!DT.isVirtualRoot(To->getIDom())) return false;

    auto RIt = llvh::find(DT.Roots, To->getBlock());
    if (RIt == DT.Roots.end())
      return false;                                         

    LLVM_DEBUG(dbgs() << "\t\tAfter the insertion, " << BlockNamePrinter(To)
                      << " is no longer a root\n\t\tRebuilding the tree!!!\n");

    CalculateFromScratch(DT, BUI);
    return true;
  }

                                                                            
                                                                              
                           
  static void UpdateRootsAfterUpdate(DomTreeT &DT, const BatchUpdatePtr BUI) {
    assert(IsPostDom && "This function is only for postdominators");

                                                            
    if (std::none_of(DT.Roots.begin(), DT.Roots.end(), [BUI](const NodePtr N) {
          return HasForwardSuccessors(N, BUI);
        }))
      return;

                                    
    auto Roots = FindRoots(DT, BUI);
    if (DT.Roots.size() != Roots.size() ||
        !std::is_permutation(DT.Roots.begin(), DT.Roots.end(), Roots.begin())) {
                                                                      
                                                                               
                                                                            
                                      

      LLVM_DEBUG(dbgs() << "Roots are different in updated trees\n"
                        << "The entire tree needs to be rebuilt\n");
                                                                            
                                                                            
      CalculateFromScratch(DT, BUI);
      return;
    }
  }

                                                               
  static void InsertReachable(DomTreeT &DT, const BatchUpdatePtr BUI,
                              const TreeNodePtr From, const TreeNodePtr To) {
    LLVM_DEBUG(dbgs() << "\tReachable " << BlockNamePrinter(From->getBlock())
                      << " -> " << BlockNamePrinter(To->getBlock()) << "\n");
    if (IsPostDom && UpdateRootsBeforeInsertion(DT, BUI, From, To)) return;
                                                                           
                                                                             
                        
    const NodePtr NCDBlock =
        (From->getBlock() && To->getBlock())
            ? DT.findNearestCommonDominator(From->getBlock(), To->getBlock())
            : nullptr;
    assert(NCDBlock || DT.isPostDominator());
    const TreeNodePtr NCD = DT.getNode(NCDBlock);
    assert(NCD);

    LLVM_DEBUG(dbgs() << "\t\tNCA == " << BlockNamePrinter(NCD) << "\n");
    const TreeNodePtr ToIDom = To->getIDom();

                                              
                                                      
    if (NCD == To || NCD == ToIDom) return;

                                           
    InsertionInfo II;
    LLVM_DEBUG(dbgs() << "Marking " << BlockNamePrinter(To)
                      << " as affected\n");
    II.Affected.insert(To);
    const unsigned ToLevel = To->getLevel();
    LLVM_DEBUG(dbgs() << "Putting " << BlockNamePrinter(To)
                      << " into a Bucket\n");
    II.Bucket.push({ToLevel, To});

    while (!II.Bucket.empty()) {
      const TreeNodePtr CurrentNode = II.Bucket.top().second;
      const unsigned  CurrentLevel = CurrentNode->getLevel();
      II.Bucket.pop();
      LLVM_DEBUG(dbgs() << "\tAdding to Visited and AffectedQueue: "
                        << BlockNamePrinter(CurrentNode) << "\n");

      II.Visited.insert({CurrentNode, CurrentLevel});
      II.AffectedQueue.push_back(CurrentNode);

                                                                      
      VisitInsertion(DT, BUI, CurrentNode, CurrentLevel, NCD, II);
    }

                                                          
    UpdateInsertion(DT, BUI, NCD, II);
  }

                                                                 
  static void VisitInsertion(DomTreeT &DT, const BatchUpdatePtr BUI,
                             const TreeNodePtr TN, const unsigned RootLevel,
                             const TreeNodePtr NCD, InsertionInfo &II) {
    const unsigned NCDLevel = NCD->getLevel();
    LLVM_DEBUG(dbgs() << "Visiting " << BlockNamePrinter(TN) << ",  RootLevel "
                      << RootLevel << "\n");

    SmallVector<TreeNodePtr, 8> Stack = {TN};
    assert(TN->getBlock() && II.Visited.count(TN) && "Preconditions!");

    SmallPtrSet<TreeNodePtr, 8> Processed;

    do {
      TreeNodePtr Next = Stack.pop_back_val();
      LLVM_DEBUG(dbgs() << " Next: " << BlockNamePrinter(Next) << "\n");

      for (const NodePtr Succ :
           ChildrenGetter<IsPostDom>::Get(Next->getBlock(), BUI)) {
        const TreeNodePtr SuccTN = DT.getNode(Succ);
        assert(SuccTN && "Unreachable successor found at reachable insertion");
        const unsigned SuccLevel = SuccTN->getLevel();

        LLVM_DEBUG(dbgs() << "\tSuccessor " << BlockNamePrinter(Succ)
                          << ", level = " << SuccLevel << "\n");

                                                       
        if (Processed.count(Next) > 0)
          continue;

                                                          
                                                          
        if (SuccLevel > RootLevel) {
          LLVM_DEBUG(dbgs() << "\t\tDominated by subtree From\n");
          if (II.Visited.count(SuccTN) != 0) {
            LLVM_DEBUG(dbgs() << "\t\t\talready visited at level "
                              << II.Visited[SuccTN] << "\n\t\t\tcurrent level "
                              << RootLevel << ")\n");

                                                                           
                                         
            if (II.Visited[SuccTN] >= RootLevel)
              continue;
          }

          LLVM_DEBUG(dbgs() << "\t\tMarking visited not affected "
                            << BlockNamePrinter(Succ) << "\n");
          II.Visited.insert({SuccTN, RootLevel});
          II.VisitedNotAffectedQueue.push_back(SuccTN);
          Stack.push_back(SuccTN);
        } else if ((SuccLevel > NCDLevel + 1) &&
            II.Affected.count(SuccTN) == 0) {
          LLVM_DEBUG(dbgs() << "\t\tMarking affected and adding "
                            << BlockNamePrinter(Succ) << " to a Bucket\n");
          II.Affected.insert(SuccTN);
          II.Bucket.push({SuccLevel, SuccTN});
        }
      }

      Processed.insert(Next);
    } while (!Stack.empty());
  }

                                                             
  static void UpdateInsertion(DomTreeT &DT, const BatchUpdatePtr BUI,
                              const TreeNodePtr NCD, InsertionInfo &II) {
    LLVM_DEBUG(dbgs() << "Updating NCD = " << BlockNamePrinter(NCD) << "\n");

    for (const TreeNodePtr TN : II.AffectedQueue) {
      LLVM_DEBUG(dbgs() << "\tIDom(" << BlockNamePrinter(TN)
                        << ") = " << BlockNamePrinter(NCD) << "\n");
      TN->setIDom(NCD);
    }

    UpdateLevelsAfterInsertion(II);
    if (IsPostDom) UpdateRootsAfterUpdate(DT, BUI);
  }

  static void UpdateLevelsAfterInsertion(InsertionInfo &II) {
    LLVM_DEBUG(
        dbgs() << "Updating levels for visited but not affected nodes\n");

    for (const TreeNodePtr TN : II.VisitedNotAffectedQueue) {
      LLVM_DEBUG(dbgs() << "\tlevel(" << BlockNamePrinter(TN) << ") = ("
                        << BlockNamePrinter(TN->getIDom()) << ") "
                        << TN->getIDom()->getLevel() << " + 1\n");
      TN->UpdateLevel();
    }
  }

                                                       
  static void InsertUnreachable(DomTreeT &DT, const BatchUpdatePtr BUI,
                                const TreeNodePtr From, const NodePtr To) {
    LLVM_DEBUG(dbgs() << "Inserting " << BlockNamePrinter(From)
                      << " -> (unreachable) " << BlockNamePrinter(To) << "\n");

                                                           
    SmallVector<std::pair<NodePtr, TreeNodePtr>, 8> DiscoveredEdgesToReachable;
                                                                           
    ComputeUnreachableDominators(DT, BUI, To, From, DiscoveredEdgesToReachable);

    LLVM_DEBUG(dbgs() << "Inserted " << BlockNamePrinter(From)
                      << " -> (prev unreachable) " << BlockNamePrinter(To)
                      << "\n");

                                                                           
             
    for (const auto &Edge : DiscoveredEdgesToReachable) {
      LLVM_DEBUG(dbgs() << "\tInserting discovered connecting edge "
                        << BlockNamePrinter(Edge.first) << " -> "
                        << BlockNamePrinter(Edge.second) << "\n");
      InsertReachable(DT, BUI, DT.getNode(Edge.first), Edge.second);
    }
  }

                                                            
  static void ComputeUnreachableDominators(
      DomTreeT &DT, const BatchUpdatePtr BUI, const NodePtr Root,
      const TreeNodePtr Incoming,
      SmallVectorImpl<std::pair<NodePtr, TreeNodePtr>>
          &DiscoveredConnectingEdges) {
    assert(!DT.getNode(Root) && "Root must not be reachable");

                                               
    auto UnreachableDescender = [&DT, &DiscoveredConnectingEdges](NodePtr From,
                                                                  NodePtr To) {
      const TreeNodePtr ToTN = DT.getNode(To);
      if (!ToTN) return true;

      DiscoveredConnectingEdges.push_back({From, ToTN});
      return false;
    };

    SemiNCAInfo SNCA(BUI);
    SNCA.runDFS(Root, 0, UnreachableDescender, 0);
    SNCA.runSemiNCA(DT);
    SNCA.attachNewSubtree(DT, Incoming);

    LLVM_DEBUG(dbgs() << "After adding unreachable nodes\n");
  }

  static void DeleteEdge(DomTreeT &DT, const BatchUpdatePtr BUI,
                         const NodePtr From, const NodePtr To) {
    assert(From && To && "Cannot disconnect nullptrs");
    LLVM_DEBUG(dbgs() << "Deleting edge " << BlockNamePrinter(From) << " -> "
                      << BlockNamePrinter(To) << "\n");

#ifndef NDEBUG
                                                                             
                            
                                                                
    auto IsSuccessor = [BUI](const NodePtr SuccCandidate, const NodePtr Of) {
      auto Successors = ChildrenGetter<IsPostDom>::Get(Of, BUI);
      return llvh::find(Successors, SuccCandidate) != Successors.end();
    };
    (void)IsSuccessor;
    assert(!IsSuccessor(To, From) && "Deleted edge still exists in the CFG!");
#endif

    const TreeNodePtr FromTN = DT.getNode(From);
                                                           
    if (!FromTN) return;

    const TreeNodePtr ToTN = DT.getNode(To);
    if (!ToTN) {
      LLVM_DEBUG(
          dbgs() << "\tTo (" << BlockNamePrinter(To)
                 << ") already unreachable -- there is no edge to delete\n");
      return;
    }

    const NodePtr NCDBlock = DT.findNearestCommonDominator(From, To);
    const TreeNodePtr NCD = DT.getNode(NCDBlock);

                                             
    if (ToTN != NCD) {
      DT.DFSInfoValid = false;

      const TreeNodePtr ToIDom = ToTN->getIDom();
      LLVM_DEBUG(dbgs() << "\tNCD " << BlockNamePrinter(NCD) << ", ToIDom "
                        << BlockNamePrinter(ToIDom) << "\n");

                                             
                                                                      
      if (FromTN != ToIDom || HasProperSupport(DT, BUI, ToTN))
        DeleteReachable(DT, BUI, FromTN, ToTN);
      else
        DeleteUnreachable(DT, BUI, ToTN);
    }

    if (IsPostDom) UpdateRootsAfterUpdate(DT, BUI);
  }

                                                              
  static void DeleteReachable(DomTreeT &DT, const BatchUpdatePtr BUI,
                              const TreeNodePtr FromTN,
                              const TreeNodePtr ToTN) {
    LLVM_DEBUG(dbgs() << "Deleting reachable " << BlockNamePrinter(FromTN)
                      << " -> " << BlockNamePrinter(ToTN) << "\n");
    LLVM_DEBUG(dbgs() << "\tRebuilding subtree\n");

                                                            
                                                      
    const NodePtr ToIDom =
        DT.findNearestCommonDominator(FromTN->getBlock(), ToTN->getBlock());
    assert(ToIDom || DT.isPostDominator());
    const TreeNodePtr ToIDomTN = DT.getNode(ToIDom);
    assert(ToIDomTN);
    const TreeNodePtr PrevIDomSubTree = ToIDomTN->getIDom();
                                                                            
               
    if (!PrevIDomSubTree) {
      LLVM_DEBUG(dbgs() << "The entire tree needs to be rebuilt\n");
      CalculateFromScratch(DT, BUI);
      return;
    }

                                                      
    const unsigned Level = ToIDomTN->getLevel();
    auto DescendBelow = [Level, &DT](NodePtr, NodePtr To) {
      return DT.getNode(To)->getLevel() > Level;
    };

    LLVM_DEBUG(dbgs() << "\tTop of subtree: " << BlockNamePrinter(ToIDomTN)
                      << "\n");

    SemiNCAInfo SNCA(BUI);
    SNCA.runDFS(ToIDom, 0, DescendBelow, 0);
    LLVM_DEBUG(dbgs() << "\tRunning Semi-NCA\n");
    SNCA.runSemiNCA(DT, Level);
    SNCA.reattachExistingSubtree(DT, PrevIDomSubTree);
  }

                                                                            
                                                 
  static bool HasProperSupport(DomTreeT &DT, const BatchUpdatePtr BUI,
                               const TreeNodePtr TN) {
    LLVM_DEBUG(dbgs() << "IsReachableFromIDom " << BlockNamePrinter(TN)
                      << "\n");
    for (const NodePtr Pred :
         ChildrenGetter<!IsPostDom>::Get(TN->getBlock(), BUI)) {
      LLVM_DEBUG(dbgs() << "\tPred " << BlockNamePrinter(Pred) << "\n");
      if (!DT.getNode(Pred)) continue;

      const NodePtr Support =
          DT.findNearestCommonDominator(TN->getBlock(), Pred);
      LLVM_DEBUG(dbgs() << "\tSupport " << BlockNamePrinter(Support) << "\n");
      if (Support != TN->getBlock()) {
        LLVM_DEBUG(dbgs() << "\t" << BlockNamePrinter(TN)
                          << " is reachable from support "
                          << BlockNamePrinter(Support) << "\n");
        return true;
      }
    }

    return false;
  }

                                                             
                                                    
  static void DeleteUnreachable(DomTreeT &DT, const BatchUpdatePtr BUI,
                                const TreeNodePtr ToTN) {
    LLVM_DEBUG(dbgs() << "Deleting unreachable subtree "
                      << BlockNamePrinter(ToTN) << "\n");
    assert(ToTN);
    assert(ToTN->getBlock());

    if (IsPostDom) {
                                                                            
                                                                             
                                 
      LLVM_DEBUG(dbgs() << "\tDeletion made a region reverse-unreachable\n");
      LLVM_DEBUG(dbgs() << "\tAdding new root " << BlockNamePrinter(ToTN)
                        << "\n");
      DT.Roots.push_back(ToTN->getBlock());
      InsertReachable(DT, BUI, DT.getNode(nullptr), ToTN);
      return;
    }

    SmallVector<NodePtr, 16> AffectedQueue;
    const unsigned Level = ToTN->getLevel();

                                                                             
                                 
    auto DescendAndCollect = [Level, &AffectedQueue, &DT](NodePtr, NodePtr To) {
      const TreeNodePtr TN = DT.getNode(To);
      assert(TN);
      if (TN->getLevel() > Level) return true;
      if (llvh::find(AffectedQueue, To) == AffectedQueue.end())
        AffectedQueue.push_back(To);

      return false;
    };

    SemiNCAInfo SNCA(BUI);
    unsigned LastDFSNum =
        SNCA.runDFS(ToTN->getBlock(), 0, DescendAndCollect, 0);

    TreeNodePtr MinNode = ToTN;

                                                                           
                          
    for (const NodePtr N : AffectedQueue) {
      const TreeNodePtr TN = DT.getNode(N);
      const NodePtr NCDBlock =
          DT.findNearestCommonDominator(TN->getBlock(), ToTN->getBlock());
      assert(NCDBlock || DT.isPostDominator());
      const TreeNodePtr NCD = DT.getNode(NCDBlock);
      assert(NCD);

      LLVM_DEBUG(dbgs() << "Processing affected node " << BlockNamePrinter(TN)
                        << " with NCD = " << BlockNamePrinter(NCD)
                        << ", MinNode =" << BlockNamePrinter(MinNode) << "\n");
      if (NCD != TN && NCD->getLevel() < MinNode->getLevel()) MinNode = NCD;
    }

                                                         
    if (!MinNode->getIDom()) {
      LLVM_DEBUG(dbgs() << "The entire tree needs to be rebuilt\n");
      CalculateFromScratch(DT, BUI);
      return;
    }

                                                                                
                                    
    for (unsigned i = LastDFSNum; i > 0; --i) {
      const NodePtr N = SNCA.NumToNode[i];
      const TreeNodePtr TN = DT.getNode(N);
      LLVM_DEBUG(dbgs() << "Erasing node " << BlockNamePrinter(TN) << "\n");

      EraseNode(DT, TN);
    }

                                                                                
    if (MinNode == ToTN) return;

    LLVM_DEBUG(dbgs() << "DeleteUnreachable: running DFS with MinNode = "
                      << BlockNamePrinter(MinNode) << "\n");
    const unsigned MinLevel = MinNode->getLevel();
    const TreeNodePtr PrevIDom = MinNode->getIDom();
    assert(PrevIDom);
    SNCA.clear();

                                                          
    auto DescendBelow = [MinLevel, &DT](NodePtr, NodePtr To) {
      const TreeNodePtr ToTN = DT.getNode(To);
      return ToTN && ToTN->getLevel() > MinLevel;
    };
    SNCA.runDFS(MinNode->getBlock(), 0, DescendBelow, 0);

    LLVM_DEBUG(dbgs() << "Previous IDom(MinNode) = "
                      << BlockNamePrinter(PrevIDom) << "\nRunning Semi-NCA\n");

                                                      
    SNCA.runSemiNCA(DT, MinLevel);
    SNCA.reattachExistingSubtree(DT, PrevIDom);
  }

                                                     
  static void EraseNode(DomTreeT &DT, const TreeNodePtr TN) {
    assert(TN);
    assert(TN->getNumChildren() == 0 && "Not a tree leaf");

    const TreeNodePtr IDom = TN->getIDom();
    assert(IDom);

    auto ChIt = llvh::find(IDom->Children, TN);
    assert(ChIt != IDom->Children.end());
    std::swap(*ChIt, IDom->Children.back());
    IDom->Children.pop_back();

    DT.DomTreeNodes.erase(TN->getBlock());
  }

      
                                                                                
      

  static void ApplyUpdates(DomTreeT &DT, ArrayRef<UpdateT> Updates) {
    const size_t NumUpdates = Updates.size();
    if (NumUpdates == 0)
      return;

                                                                                
                 
    if (NumUpdates == 1) {
      const auto &Update = Updates.front();
      if (Update.getKind() == UpdateKind::Insert)
        DT.insertEdge(Update.getFrom(), Update.getTo());
      else
        DT.deleteEdge(Update.getFrom(), Update.getTo());

      return;
    }

    BatchUpdateInfo BUI;
    LLVM_DEBUG(dbgs() << "Legalizing " << BUI.Updates.size() << " updates\n");
    cfg::LegalizeUpdates<NodePtr>(Updates, BUI.Updates, IsPostDom);

    const size_t NumLegalized = BUI.Updates.size();
    BUI.FutureSuccessors.reserve(NumLegalized);
    BUI.FuturePredecessors.reserve(NumLegalized);

                                                                           
                                                                               
                                                                       
    for (UpdateT &U : BUI.Updates) {
      BUI.FutureSuccessors[U.getFrom()].push_back({U.getTo(), U.getKind()});
      BUI.FuturePredecessors[U.getTo()].push_back({U.getFrom(), U.getKind()});
    }

    LLVM_DEBUG(dbgs() << "About to apply " << NumLegalized << " updates\n");
    LLVM_DEBUG(if (NumLegalized < 32) for (const auto &U
                                           : reverse(BUI.Updates)) {
      dbgs() << "\t";
      U.dump();
      dbgs() << "\n";
    });
    LLVM_DEBUG(dbgs() << "\n");

                                                                          
                                                                               
           
    for (size_t i = 0; i < NumLegalized && !BUI.IsRecalculated; ++i)
      ApplyNextUpdate(DT, BUI);
  }

  static void ApplyNextUpdate(DomTreeT &DT, BatchUpdateInfo &BUI) {
    assert(!BUI.Updates.empty() && "No updates to apply!");
    UpdateT CurrentUpdate = BUI.Updates.pop_back_val();
    LLVM_DEBUG(dbgs() << "Applying update: ");
    LLVM_DEBUG(CurrentUpdate.dump(); dbgs() << "\n");

                                                                           
                                                                             
                                                           
    auto &FS = BUI.FutureSuccessors[CurrentUpdate.getFrom()];
    assert(FS.back().getPointer() == CurrentUpdate.getTo() &&
           FS.back().getInt() == CurrentUpdate.getKind());
    FS.pop_back();
    if (FS.empty()) BUI.FutureSuccessors.erase(CurrentUpdate.getFrom());

    auto &FP = BUI.FuturePredecessors[CurrentUpdate.getTo()];
    assert(FP.back().getPointer() == CurrentUpdate.getFrom() &&
           FP.back().getInt() == CurrentUpdate.getKind());
    FP.pop_back();
    if (FP.empty()) BUI.FuturePredecessors.erase(CurrentUpdate.getTo());

    if (CurrentUpdate.getKind() == UpdateKind::Insert)
      InsertEdge(DT, &BUI, CurrentUpdate.getFrom(), CurrentUpdate.getTo());
    else
      DeleteEdge(DT, &BUI, CurrentUpdate.getFrom(), CurrentUpdate.getTo());
  }

      
                                                                                
      

                                                                             
                                                                          
                                                                           
           
                        
  bool verifyRoots(const DomTreeT &DT) {
    if (!DT.Parent && !DT.Roots.empty()) {
      errs() << "Tree has no parent but has roots!\n";
      errs().flush();
      return false;
    }

    if (!IsPostDom) {
      if (DT.Roots.empty()) {
        errs() << "Tree doesn't have a root!\n";
        errs().flush();
        return false;
      }

      if (DT.getRoot() != GetEntryNode(DT)) {
        errs() << "Tree's root is not its parent's entry node!\n";
        errs().flush();
        return false;
      }
    }

    RootsT ComputedRoots = FindRoots(DT, nullptr);
    if (DT.Roots.size() != ComputedRoots.size() ||
        !std::is_permutation(DT.Roots.begin(), DT.Roots.end(),
                             ComputedRoots.begin())) {
      errs() << "Tree has different roots than freshly computed ones!\n";
      errs() << "\tPDT roots: ";
      for (const NodePtr N : DT.Roots) errs() << BlockNamePrinter(N) << ", ";
      errs() << "\n\tComputed roots: ";
      for (const NodePtr N : ComputedRoots)
        errs() << BlockNamePrinter(N) << ", ";
      errs() << "\n";
      errs().flush();
      return false;
    }

    return true;
  }

                                                                        
                        
  bool verifyReachability(const DomTreeT &DT) {
    clear();
    doFullDFSWalk(DT, AlwaysDescend);

    for (auto &NodeToTN : DT.DomTreeNodes) {
      const TreeNodePtr TN = NodeToTN.second.get();
      const NodePtr BB = TN->getBlock();

                                                           
      if (DT.isVirtualRoot(TN)) continue;

      if (NodeToInfo.count(BB) == 0) {
        errs() << "DomTree node " << BlockNamePrinter(BB)
               << " not found by DFS walk!\n";
        errs().flush();

        return false;
      }
    }

    for (const NodePtr N : NumToNode) {
      if (N && !DT.getNode(N)) {
        errs() << "CFG node " << BlockNamePrinter(N)
               << " not found in the DomTree!\n";
        errs().flush();

        return false;
      }
    }

    return true;
  }

                                                                             
                      
                        
  static bool VerifyLevels(const DomTreeT &DT) {
    for (auto &NodeToTN : DT.DomTreeNodes) {
      const TreeNodePtr TN = NodeToTN.second.get();
      const NodePtr BB = TN->getBlock();
      if (!BB) continue;

      const TreeNodePtr IDom = TN->getIDom();
      if (!IDom && TN->getLevel() != 0) {
        errs() << "Node without an IDom " << BlockNamePrinter(BB)
               << " has a nonzero level " << TN->getLevel() << "!\n";
        errs().flush();

        return false;
      }

      if (IDom && TN->getLevel() != IDom->getLevel() + 1) {
        errs() << "Node " << BlockNamePrinter(BB) << " has level "
               << TN->getLevel() << " while its IDom "
               << BlockNamePrinter(IDom->getBlock()) << " has level "
               << IDom->getLevel() << "!\n";
        errs().flush();

        return false;
      }
    }

    return true;
  }

                                                                              
                                                                      
                               
  static bool VerifyDFSNumbers(const DomTreeT &DT) {
    if (!DT.DFSInfoValid || !DT.Parent)
      return true;

    const NodePtr RootBB = IsPostDom ? nullptr : DT.getRoots()[0];
    const TreeNodePtr Root = DT.getNode(RootBB);

    auto PrintNodeAndDFSNums = [](const TreeNodePtr TN) {
      errs() << BlockNamePrinter(TN) << " {" << TN->getDFSNumIn() << ", "
             << TN->getDFSNumOut() << '}';
    };

                                                                              
                                                                        
    if (Root->getDFSNumIn() != 0) {
      errs() << "DFSIn number for the tree root is not:\n\t";
      PrintNodeAndDFSNums(Root);
      errs() << '\n';
      errs().flush();
      return false;
    }

                                                                               
                                
    for (const auto &NodeToTN : DT.DomTreeNodes) {
      const TreeNodePtr Node = NodeToTN.second.get();

                            
      if (Node->getChildren().empty()) {
        if (Node->getDFSNumIn() + 1 != Node->getDFSNumOut()) {
          errs() << "Tree leaf should have DFSOut = DFSIn + 1:\n\t";
          PrintNodeAndDFSNums(Node);
          errs() << '\n';
          errs().flush();
          return false;
        }

        continue;
      }

                                                                               
                                                          
      SmallVector<TreeNodePtr, 8> Children(Node->begin(), Node->end());
      llvh::sort(Children, [](const TreeNodePtr Ch1, const TreeNodePtr Ch2) {
        return Ch1->getDFSNumIn() < Ch2->getDFSNumIn();
      });

      auto PrintChildrenError = [Node, &Children, PrintNodeAndDFSNums](
          const TreeNodePtr FirstCh, const TreeNodePtr SecondCh) {
        assert(FirstCh);

        errs() << "Incorrect DFS numbers for:\n\tParent ";
        PrintNodeAndDFSNums(Node);

        errs() << "\n\tChild ";
        PrintNodeAndDFSNums(FirstCh);

        if (SecondCh) {
          errs() << "\n\tSecond child ";
          PrintNodeAndDFSNums(SecondCh);
        }

        errs() << "\nAll children: ";
        for (const TreeNodePtr Ch : Children) {
          PrintNodeAndDFSNums(Ch);
          errs() << ", ";
        }

        errs() << '\n';
        errs().flush();
      };

      if (Children.front()->getDFSNumIn() != Node->getDFSNumIn() + 1) {
        PrintChildrenError(Children.front(), nullptr);
        return false;
      }

      if (Children.back()->getDFSNumOut() + 1 != Node->getDFSNumOut()) {
        PrintChildrenError(Children.back(), nullptr);
        return false;
      }

      for (size_t i = 0, e = Children.size() - 1; i != e; ++i) {
        if (Children[i]->getDFSNumOut() + 1 != Children[i + 1]->getDFSNumIn()) {
          PrintChildrenError(Children[i], Children[i + 1]);
          return false;
        }
      }
    }

    return true;
  }

                                                                                
                                                                         
                                                                             
                                                                             
                                                                              
                                                                                
                                                                             
                                                                         
                                                                       
                                                                             
                                                     

                                                                             
                                                            
                                     

                                                                               
                                                                                
                                                                             
                                                                               
                                                                              
                                                                              
                                                                               
                                                       

                                                                            
                                                                               
                                                                           
                                                                               
                                                                          
                          

                                                                  
                                                                        
                                                                           

                                                                                
                                                                              
                                  
                          
    
                                                                            
                                                                   
  bool verifyParentProperty(const DomTreeT &DT) {
    for (auto &NodeToTN : DT.DomTreeNodes) {
      const TreeNodePtr TN = NodeToTN.second.get();
      const NodePtr BB = TN->getBlock();
      if (!BB || TN->getChildren().empty()) continue;

      LLVM_DEBUG(dbgs() << "Verifying parent property of node "
                        << BlockNamePrinter(TN) << "\n");
      clear();
      doFullDFSWalk(DT, [BB](NodePtr From, NodePtr To) {
        return From != BB && To != BB;
      });

      for (TreeNodePtr Child : TN->getChildren())
        if (NodeToInfo.count(Child->getBlock()) != 0) {
          errs() << "Child " << BlockNamePrinter(Child)
                 << " reachable after its parent " << BlockNamePrinter(BB)
                 << " is removed!\n";
          errs().flush();

          return false;
        }
    }

    return true;
  }

                                                                            
                                                 
                          
    
                                                                                
                                          
  bool verifySiblingProperty(const DomTreeT &DT) {
    for (auto &NodeToTN : DT.DomTreeNodes) {
      const TreeNodePtr TN = NodeToTN.second.get();
      const NodePtr BB = TN->getBlock();
      if (!BB || TN->getChildren().empty()) continue;

      const auto &Siblings = TN->getChildren();
      for (const TreeNodePtr N : Siblings) {
        clear();
        NodePtr BBN = N->getBlock();
        doFullDFSWalk(DT, [BBN](NodePtr From, NodePtr To) {
          return From != BBN && To != BBN;
        });

        for (const TreeNodePtr S : Siblings) {
          if (S == N) continue;

          if (NodeToInfo.count(S->getBlock()) == 0) {
            errs() << "Node " << BlockNamePrinter(S)
                   << " not reachable when its sibling " << BlockNamePrinter(N)
                   << " is removed!\n";
            errs().flush();

            return false;
          }
        }
      }
    }

    return true;
  }

                                                                               
            
                                                                              
    
                                                                             
                                                                    
                  
  static bool IsSameAsFreshTree(const DomTreeT &DT) {
    DomTreeT FreshTree;
    FreshTree.recalculate(*DT.Parent);
    const bool Different = DT.compare(FreshTree);

    if (Different) {
      errs() << (DT.isPostDominator() ? "Post" : "")
             << "DominatorTree is different than a freshly computed one!\n"
             << "\tCurrent:\n";
      DT.print(errs());
      errs() << "\n\tFreshly computed tree:\n";
      FreshTree.print(errs());
      errs().flush();
    }

    return !Different;
  }
};

template <class DomTreeT>
void Calculate(DomTreeT &DT) {
  SemiNCAInfo<DomTreeT>::CalculateFromScratch(DT, nullptr);
}

template <typename DomTreeT>
void CalculateWithUpdates(DomTreeT &DT,
                          ArrayRef<typename DomTreeT::UpdateType> Updates) {
                                                                     
  typename SemiNCAInfo<DomTreeT>::BatchUpdateInfo BUI;
  LLVM_DEBUG(dbgs() << "Legalizing " << BUI.Updates.size() << " updates\n");
  cfg::LegalizeUpdates<typename DomTreeT::NodePtr>(Updates, BUI.Updates,
                                                   DomTreeT::IsPostDominator);
  const size_t NumLegalized = BUI.Updates.size();
  BUI.FutureSuccessors.reserve(NumLegalized);
  BUI.FuturePredecessors.reserve(NumLegalized);
  for (auto &U : BUI.Updates) {
    BUI.FutureSuccessors[U.getFrom()].push_back({U.getTo(), U.getKind()});
    BUI.FuturePredecessors[U.getTo()].push_back({U.getFrom(), U.getKind()});
  }

  SemiNCAInfo<DomTreeT>::CalculateFromScratch(DT, &BUI);
}

template <class DomTreeT>
void InsertEdge(DomTreeT &DT, typename DomTreeT::NodePtr From,
                typename DomTreeT::NodePtr To) {
  if (DT.isPostDominator()) std::swap(From, To);
  SemiNCAInfo<DomTreeT>::InsertEdge(DT, nullptr, From, To);
}

template <class DomTreeT>
void DeleteEdge(DomTreeT &DT, typename DomTreeT::NodePtr From,
                typename DomTreeT::NodePtr To) {
  if (DT.isPostDominator()) std::swap(From, To);
  SemiNCAInfo<DomTreeT>::DeleteEdge(DT, nullptr, From, To);
}

template <class DomTreeT>
void ApplyUpdates(DomTreeT &DT,
                  ArrayRef<typename DomTreeT::UpdateType> Updates) {
  SemiNCAInfo<DomTreeT>::ApplyUpdates(DT, Updates);
}

template <class DomTreeT>
bool Verify(const DomTreeT &DT, typename DomTreeT::VerificationLevel VL) {
  SemiNCAInfo<DomTreeT> SNCA(nullptr);

                                                                    
                                                                 
  if (!SNCA.IsSameAsFreshTree(DT))
    return false;

                                                                            
  if (!SNCA.verifyRoots(DT) || !SNCA.verifyReachability(DT) ||
      !SNCA.VerifyLevels(DT) || !SNCA.VerifyDFSNumbers(DT))
    return false;

                                                              
  if (VL == DomTreeT::VerificationLevel::Basic ||
      VL == DomTreeT::VerificationLevel::Full)
    if (!SNCA.verifyParentProperty(DT))
      return false;
  if (VL == DomTreeT::VerificationLevel::Full)
    if (!SNCA.verifySiblingProperty(DT))
      return false;

  return true;
}

}                             
}                   

#undef DEBUG_TYPE

#endif

//===- CFGDiff.h - Define a CFG snapshot. -----------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines specializations of GraphTraits that allows generic
// algorithms to see a different snapshot of a CFG.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_CFGDIFF_H
#define LLVM_IR_CFGDIFF_H

#include "llvh/ADT/GraphTraits.h"
#include "llvh/ADT/iterator.h"
#include "llvh/ADT/iterator_range.h"
#include "llvh/IR/BasicBlock.h"
#include "llvh/IR/CFG.h"
#include "llvh/Support/CFGUpdate.h"
#include "llvh/Support/type_traits.h"
#include <cassert>
#include <cstddef>
#include <iterator>

                                                    
                                                                              
                                                  
                                                                               
                                                                       
                                                                      

                                                                         
                                                                        
                                                
                                                                              
                                                                               
                       

                                                                         
                                                                     
                                                                     
                                                                                
                                                               

                              
                                                                  
                                                                          
                                                                               
                           
                                                                              
                                      

                                    
                                                                 
                                  
                                                                
                       
                                                                          
                                 
                                                               
                                            
                                                                          
                                    
                                                             
                                            
                                                                                
                                     
                                                                            

namespace llvh {

                                                                            
                                                                                
                                                                           
                                                                          
                                                
template <typename NodePtr, bool InverseGraph = false> class GraphDiff {
  using UpdateMapType = SmallDenseMap<NodePtr, SmallVector<NodePtr, 2>>;
  UpdateMapType SuccInsert;
  UpdateMapType SuccDelete;
  UpdateMapType PredInsert;
  UpdateMapType PredDelete;
                                                                       
              
  SmallVector<NodePtr, 1> Empty;

  void printMap(raw_ostream &OS, const UpdateMapType &M) const {
    for (auto Pair : M)
      for (auto Child : Pair.second) {
        OS << "(";
        Pair.first->printAsOperand(OS, false);
        OS << ", ";
        Child->printAsOperand(OS, false);
        OS << ") ";
      }
    OS << "\n";
  }

public:
  GraphDiff() {}
  GraphDiff(ArrayRef<cfg::Update<NodePtr>> Updates) {
    SmallVector<cfg::Update<NodePtr>, 4> LegalizedUpdates;
    cfg::LegalizeUpdates<NodePtr>(Updates, LegalizedUpdates, InverseGraph);
    for (auto U : LegalizedUpdates) {
      if (U.getKind() == cfg::UpdateKind::Insert) {
        SuccInsert[U.getFrom()].push_back(U.getTo());
        PredInsert[U.getTo()].push_back(U.getFrom());
      } else {
        SuccDelete[U.getFrom()].push_back(U.getTo());
        PredDelete[U.getTo()].push_back(U.getFrom());
      }
    }
  }

  bool ignoreChild(const NodePtr BB, NodePtr EdgeEnd, bool InverseEdge) const {
    auto &DeleteChildren =
        (InverseEdge != InverseGraph) ? PredDelete : SuccDelete;
    auto It = DeleteChildren.find(BB);
    if (It == DeleteChildren.end())
      return false;
    auto &EdgesForBB = It->second;
    return llvh::find(EdgesForBB, EdgeEnd) != EdgesForBB.end();
  }

  iterator_range<typename SmallVectorImpl<NodePtr>::const_iterator>
  getAddedChildren(const NodePtr BB, bool InverseEdge) const {
    auto &InsertChildren =
        (InverseEdge != InverseGraph) ? PredInsert : SuccInsert;
    auto It = InsertChildren.find(BB);
    if (It == InsertChildren.end())
      return make_range(Empty.begin(), Empty.end());
    return make_range(It->second.begin(), It->second.end());
  }

  void print(raw_ostream &OS) const {
    OS << "===== GraphDiff: CFG edge changes to create a CFG snapshot. \n"
          "===== (Note: notion of children/inverse_children depends on "
          "the direction of edges and the graph.)\n";
    OS << "Children to insert:\n\t";
    printMap(OS, SuccInsert);
    OS << "Children to delete:\n\t";
    printMap(OS, SuccDelete);
    OS << "Inverse_children to insert:\n\t";
    printMap(OS, PredInsert);
    OS << "Inverse_children to delete:\n\t";
    printMap(OS, PredDelete);
    OS << "\n";
  }

#if !defined(NDEBUG) || defined(LLVM_ENABLE_DUMP)
  LLVM_DUMP_METHOD void dump() const { print(dbgs()); }
#endif
};

template <bool InverseGraph = false> struct CFGViewSuccessors {
  using DataRef = const GraphDiff<BasicBlock *, InverseGraph> *;
  using NodeRef = std::pair<DataRef, BasicBlock *>;

  using ExistingChildIterator =
      WrappedPairNodeDataIterator<succ_iterator, NodeRef, DataRef>;
  struct DeletedEdgesFilter {
    BasicBlock *BB;
    DeletedEdgesFilter(BasicBlock *BB) : BB(BB){};
    bool operator()(NodeRef N) const {
      return !N.first->ignoreChild(BB, N.second, false);
    }
  };
  using FilterExistingChildrenIterator =
      filter_iterator<ExistingChildIterator, DeletedEdgesFilter>;

  using vec_iterator = SmallVectorImpl<BasicBlock *>::const_iterator;
  using AddNewChildrenIterator =
      WrappedPairNodeDataIterator<vec_iterator, NodeRef, DataRef>;
  using ChildIteratorType =
      concat_iterator<NodeRef, FilterExistingChildrenIterator,
                      AddNewChildrenIterator>;

  static ChildIteratorType child_begin(NodeRef N) {
    auto InsertVec = N.first->getAddedChildren(N.second, false);
                            
    auto firstit = make_filter_range(
        make_range<ExistingChildIterator>({succ_begin(N.second), N.first},
                                          {succ_end(N.second), N.first}),
        DeletedEdgesFilter(N.second));
                                 
    auto secondit = make_range<AddNewChildrenIterator>(
        {InsertVec.begin(), N.first}, {InsertVec.end(), N.first});

    return concat_iterator<NodeRef, FilterExistingChildrenIterator,
                           AddNewChildrenIterator>(firstit, secondit);
  }

  static ChildIteratorType child_end(NodeRef N) {
    auto InsertVec = N.first->getAddedChildren(N.second, false);
                            
    auto firstit = make_filter_range(
        make_range<ExistingChildIterator>({succ_end(N.second), N.first},
                                          {succ_end(N.second), N.first}),
        DeletedEdgesFilter(N.second));
                                 
    auto secondit = make_range<AddNewChildrenIterator>(
        {InsertVec.end(), N.first}, {InsertVec.end(), N.first});

    return concat_iterator<NodeRef, FilterExistingChildrenIterator,
                           AddNewChildrenIterator>(firstit, secondit);
  }
};

template <bool InverseGraph = false> struct CFGViewPredecessors {
  using DataRef = const GraphDiff<BasicBlock *, InverseGraph> *;
  using NodeRef = std::pair<DataRef, BasicBlock *>;

  using ExistingChildIterator =
      WrappedPairNodeDataIterator<pred_iterator, NodeRef, DataRef>;
  struct DeletedEdgesFilter {
    BasicBlock *BB;
    DeletedEdgesFilter(BasicBlock *BB) : BB(BB){};
    bool operator()(NodeRef N) const {
      return !N.first->ignoreChild(BB, N.second, true);
    }
  };
  using FilterExistingChildrenIterator =
      filter_iterator<ExistingChildIterator, DeletedEdgesFilter>;

  using vec_iterator = SmallVectorImpl<BasicBlock *>::const_iterator;
  using AddNewChildrenIterator =
      WrappedPairNodeDataIterator<vec_iterator, NodeRef, DataRef>;
  using ChildIteratorType =
      concat_iterator<NodeRef, FilterExistingChildrenIterator,
                      AddNewChildrenIterator>;

  static ChildIteratorType child_begin(NodeRef N) {
    auto InsertVec = N.first->getAddedChildren(N.second, true);
                            
    auto firstit = make_filter_range(
        make_range<ExistingChildIterator>({pred_begin(N.second), N.first},
                                          {pred_end(N.second), N.first}),
        DeletedEdgesFilter(N.second));
                                 
    auto secondit = make_range<AddNewChildrenIterator>(
        {InsertVec.begin(), N.first}, {InsertVec.end(), N.first});

    return concat_iterator<NodeRef, FilterExistingChildrenIterator,
                           AddNewChildrenIterator>(firstit, secondit);
  }

  static ChildIteratorType child_end(NodeRef N) {
    auto InsertVec = N.first->getAddedChildren(N.second, true);
                            
    auto firstit = make_filter_range(
        make_range<ExistingChildIterator>({pred_end(N.second), N.first},
                                          {pred_end(N.second), N.first}),
        DeletedEdgesFilter(N.second));
                                 
    auto secondit = make_range<AddNewChildrenIterator>(
        {InsertVec.end(), N.first}, {InsertVec.end(), N.first});

    return concat_iterator<NodeRef, FilterExistingChildrenIterator,
                           AddNewChildrenIterator>(firstit, secondit);
  }
};

template <>
struct GraphTraits<
    std::pair<const GraphDiff<BasicBlock *, false> *, BasicBlock *>>
    : CFGViewSuccessors<false> {};
template <>
struct GraphTraits<
    std::pair<const GraphDiff<BasicBlock *, true> *, BasicBlock *>>
    : CFGViewSuccessors<true> {};
template <>
struct GraphTraits<
    std::pair<const GraphDiff<BasicBlock *, false> *, Inverse<BasicBlock *>>>
    : CFGViewPredecessors<false> {};
template <>
struct GraphTraits<
    std::pair<const GraphDiff<BasicBlock *, true> *, Inverse<BasicBlock *>>>
    : CFGViewPredecessors<true> {};
}                      

#endif                     

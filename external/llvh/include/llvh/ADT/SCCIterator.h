//===- ADT/SCCIterator.h - Strongly Connected Comp. Iter. -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
/// \file
///
/// This builds on the llvm/ADT/GraphTraits.h file to find the strongly
/// connected components (SCCs) of a graph in O(N+E) time using Tarjan's DFS
/// algorithm.
///
/// The SCC iterator has the important property that if a node in SCC S1 has an
/// edge to a node in SCC S2, then it visits S1 *after* S2.
///
/// To visit S1 *before* S2, use the scc_iterator on the Inverse graph. (NOTE:
/// This requires some simple wrappers and is not supported yet.)
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_SCCITERATOR_H
#define LLVM_ADT_SCCITERATOR_H

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/GraphTraits.h"
#include "llvh/ADT/iterator.h"
#include <cassert>
#include <cstddef>
#include <iterator>
#include <vector>

namespace llvh {

                                                                       
                   
   
                                                                               
                                                                             
                                                             
template <class GraphT, class GT = GraphTraits<GraphT>>
class scc_iterator : public iterator_facade_base<
                         scc_iterator<GraphT, GT>, std::forward_iterator_tag,
                         const std::vector<typename GT::NodeRef>, ptrdiff_t> {
  using NodeRef = typename GT::NodeRef;
  using ChildItTy = typename GT::ChildIteratorType;
  using SccTy = std::vector<NodeRef>;
  using reference = typename scc_iterator::reference;

                                       
  struct StackElement {
    NodeRef Node;                                       
    ChildItTy NextChild;                                                   
    unsigned MinVisited;                                                    

    StackElement(NodeRef Node, const ChildItTy &Child, unsigned Min)
        : Node(Node), NextChild(Child), MinVisited(Min) {}

    bool operator==(const StackElement &Other) const {
      return Node == Other.Node &&
             NextChild == Other.NextChild &&
             MinVisited == Other.MinVisited;
    }
  };

                                                                            
                                     
     
                                                                          
  unsigned visitNum;
  DenseMap<NodeRef, unsigned> nodeVisitNumbers;

                                     
  std::vector<NodeRef> SCCNodeStack;

                                                   
  SccTy CurrentSCC;

                                                                             
                                                                              
  std::vector<StackElement> VisitStack;

                                                              
  void DFSVisitOne(NodeRef N);

                                                   
  void DFSVisitChildren();

                                                   
  void GetNextSCC();

  scc_iterator(NodeRef entryN) : visitNum(0) {
    DFSVisitOne(entryN);
    GetNextSCC();
  }

                                         
  scc_iterator() = default;

public:
  static scc_iterator begin(const GraphT &G) {
    return scc_iterator(GT::getEntryNode(G));
  }
  static scc_iterator end(const GraphT &) { return scc_iterator(); }

                                                               
                               
  bool isAtEnd() const {
    assert(!CurrentSCC.empty() || VisitStack.empty());
    return CurrentSCC.empty();
  }

  bool operator==(const scc_iterator &x) const {
    return VisitStack == x.VisitStack && CurrentSCC == x.CurrentSCC;
  }

  scc_iterator &operator++() {
    GetNextSCC();
    return *this;
  }

  reference operator*() const {
    assert(!CurrentSCC.empty() && "Dereferencing END SCC iterator!");
    return CurrentSCC;
  }

                                         
     
                                                                                
                                                                  
  bool hasLoop() const;

                                                                     
                                                              
  void ReplaceNode(NodeRef Old, NodeRef New) {
    assert(nodeVisitNumbers.count(Old) && "Old not in scc_iterator?");
    nodeVisitNumbers[New] = nodeVisitNumbers[Old];
    nodeVisitNumbers.erase(Old);
  }
};

template <class GraphT, class GT>
void scc_iterator<GraphT, GT>::DFSVisitOne(NodeRef N) {
  ++visitNum;
  nodeVisitNumbers[N] = visitNum;
  SCCNodeStack.push_back(N);
  VisitStack.push_back(StackElement(N, GT::child_begin(N), visitNum));
#if 0                                    
  dbgs() << "TarjanSCC: Node " << N <<
        " : visitNum = " << visitNum << "\n";
#endif
}

template <class GraphT, class GT>
void scc_iterator<GraphT, GT>::DFSVisitChildren() {
  assert(!VisitStack.empty());
  while (VisitStack.back().NextChild != GT::child_end(VisitStack.back().Node)) {
                                                      
    NodeRef childN = *VisitStack.back().NextChild++;
    typename DenseMap<NodeRef, unsigned>::iterator Visited =
        nodeVisitNumbers.find(childN);
    if (Visited == nodeVisitNumbers.end()) {
                                       
      DFSVisitOne(childN);
      continue;
    }

    unsigned childNum = Visited->second;
    if (VisitStack.back().MinVisited > childNum)
      VisitStack.back().MinVisited = childNum;
  }
}

template <class GraphT, class GT> void scc_iterator<GraphT, GT>::GetNextSCC() {
  CurrentSCC.clear();                                   
  while (!VisitStack.empty()) {
    DFSVisitChildren();

                                             
    NodeRef visitingN = VisitStack.back().Node;
    unsigned minVisitNum = VisitStack.back().MinVisited;
    assert(VisitStack.back().NextChild == GT::child_end(visitingN));
    VisitStack.pop_back();

                                                                              
    if (!VisitStack.empty() && VisitStack.back().MinVisited > minVisitNum)
      VisitStack.back().MinVisited = minVisitNum;

#if 0                                    
    dbgs() << "TarjanSCC: Popped node " << visitingN <<
          " : minVisitNum = " << minVisitNum << "; Node visit num = " <<
          nodeVisitNumbers[visitingN] << "\n";
#endif

    if (minVisitNum != nodeVisitNumbers[visitingN])
      continue;

                                                                      
                                                               
                                                             
                                           
    do {
      CurrentSCC.push_back(SCCNodeStack.back());
      SCCNodeStack.pop_back();
      nodeVisitNumbers[CurrentSCC.back()] = ~0U;
    } while (CurrentSCC.back() != visitingN);
    return;
  }
}

template <class GraphT, class GT>
bool scc_iterator<GraphT, GT>::hasLoop() const {
    assert(!CurrentSCC.empty() && "Dereferencing END SCC iterator!");
    if (CurrentSCC.size() > 1)
      return true;
    NodeRef N = CurrentSCC.front();
    for (ChildItTy CI = GT::child_begin(N), CE = GT::child_end(N); CI != CE;
         ++CI)
      if (*CI == N)
        return true;
    return false;
  }

                                                            
template <class T> scc_iterator<T> scc_begin(const T &G) {
  return scc_iterator<T>::begin(G);
}

                                                          
template <class T> scc_iterator<T> scc_end(const T &G) {
  return scc_iterator<T>::end(G);
}

}                      

#endif                          

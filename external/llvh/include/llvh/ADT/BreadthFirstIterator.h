//===- llvm/ADT/BreadthFirstIterator.h - Breadth First iterator -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file builds on the ADT/GraphTraits.h file to build a generic breadth
// first graph iterator.  This file exposes the following functions/types:
//
// bf_begin/bf_end/bf_iterator
//   * Normal breadth-first iteration - visit a graph level-by-level.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_BREADTHFIRSTITERATOR_H
#define LLVM_ADT_BREADTHFIRSTITERATOR_H

#include "llvh/ADT/GraphTraits.h"
#include "llvh/ADT/None.h"
#include "llvh/ADT/Optional.h"
#include "llvh/ADT/SmallPtrSet.h"
#include "llvh/ADT/iterator_range.h"
#include <iterator>
#include <queue>
#include <utility>

namespace llvh {

                                                                             
                                                                         
template <class SetType> class bf_iterator_storage {
public:
  SetType Visited;
};

                                                       
template <typename NodeRef, unsigned SmallSize = 8>
using bf_iterator_default_set = SmallPtrSet<NodeRef, SmallSize>;

                                         
template <class GraphT,
          class SetType =
              bf_iterator_default_set<typename GraphTraits<GraphT>::NodeRef>,
          class GT = GraphTraits<GraphT>>
class bf_iterator : public bf_iterator_storage<SetType> {
public:
  using iterator_category = std::forward_iterator_tag;
  using value_type = typename GT::NodeRef;
  using difference_type = std::ptrdiff_t;
  using pointer = value_type *;
  using reference = value_type &;

  using NodeRef = typename GT::NodeRef;
  using ChildItTy = typename GT::ChildIteratorType;

                                                                            
  using QueueElement = std::pair<NodeRef, Optional<ChildItTy>>;

                                                 
                                                   
  std::queue<Optional<QueueElement>> VisitQueue;

                   
  unsigned Level;

private:
  inline bf_iterator(NodeRef Node) {
    this->Visited.insert(Node);
    Level = 0;

                                           
    VisitQueue.push(QueueElement(Node, None));
    VisitQueue.push(None);
  }

  inline bf_iterator() = default;

  inline void toNext() {
    Optional<QueueElement> Head = VisitQueue.front();
    QueueElement H = Head.getValue();
    NodeRef Node = H.first;
    Optional<ChildItTy> &ChildIt = H.second;

    if (!ChildIt)
      ChildIt.emplace(GT::child_begin(Node));
    while (*ChildIt != GT::child_end(Node)) {
      NodeRef Next = *(*ChildIt)++;

                         
      if (this->Visited.insert(Next).second)
        VisitQueue.push(QueueElement(Next, None));
    }
    VisitQueue.pop();

                                                         
    if (!VisitQueue.empty()) {
      Head = VisitQueue.front();
      if (Head != None)
        return;
      Level += 1;
      VisitQueue.pop();

                                                      
                 
      if (!VisitQueue.empty())
        VisitQueue.push(None);
    }
  }

public:
                                                                      
  static bf_iterator begin(const GraphT &G) {
    return bf_iterator(GT::getEntryNode(G));
  }

  static bf_iterator end(const GraphT &G) { return bf_iterator(); }

  bool operator==(const bf_iterator &RHS) const {
    return VisitQueue == RHS.VisitQueue;
  }

  bool operator!=(const bf_iterator &RHS) const { return !(*this == RHS); }

  const NodeRef &operator*() const { return VisitQueue.front()->first; }

                                                                             
                                                                        
                                 
  NodeRef operator->() const { return **this; }

  bf_iterator &operator++() {                 
    toNext();
    return *this;
  }

  bf_iterator operator++(int) {                  
    bf_iterator ItCopy = *this;
    ++*this;
    return ItCopy;
  }

  unsigned getLevel() const { return Level; }
};

                                                                           
template <class T> bf_iterator<T> bf_begin(const T &G) {
  return bf_iterator<T>::begin(G);
}

template <class T> bf_iterator<T> bf_end(const T &G) {
  return bf_iterator<T>::end(G);
}

                                                                  
template <class T> iterator_range<bf_iterator<T>> breadth_first(const T &G) {
  return make_range(bf_begin(G), bf_end(G));
}

}                      

#endif                                   

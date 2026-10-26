//===- llvm/ADT/DepthFirstIterator.h - Depth First iterator -----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file builds on the ADT/GraphTraits.h file to build generic depth
// first graph iterator.  This file exposes the following functions/types:
//
// df_begin/df_end/df_iterator
//   * Normal depth-first iteration - visit a node and then all of its children.
//
// idf_begin/idf_end/idf_iterator
//   * Depth-first iteration on the 'inverse' graph.
//
// df_ext_begin/df_ext_end/df_ext_iterator
//   * Normal depth-first iteration - visit a node and then all of its children.
//     This iterator stores the 'visited' set in an external set, which allows
//     it to be more efficient, and allows external clients to use the set for
//     other purposes.
//
// idf_ext_begin/idf_ext_end/idf_ext_iterator
//   * Depth-first iteration on the 'inverse' graph.
//     This iterator stores the 'visited' set in an external set, which allows
//     it to be more efficient, and allows external clients to use the set for
//     other purposes.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_DEPTHFIRSTITERATOR_H
#define LLVM_ADT_DEPTHFIRSTITERATOR_H

#include "llvh/ADT/GraphTraits.h"
#include "llvh/ADT/None.h"
#include "llvh/ADT/Optional.h"
#include "llvh/ADT/SmallPtrSet.h"
#include "llvh/ADT/iterator_range.h"
#include <iterator>
#include <set>
#include <utility>
#include <vector>

namespace llvh {

                                                                             
                         
template<class SetType, bool External>                      
class df_iterator_storage {
public:
  SetType Visited;
};

template<class SetType>
class df_iterator_storage<SetType, true> {
public:
  df_iterator_storage(SetType &VSet) : Visited(VSet) {}
  df_iterator_storage(const df_iterator_storage &S) : Visited(S.Visited) {}

  SetType &Visited;
};

                                                                      
                                                                      
                                                                      
                                                                       
template <typename NodeRef, unsigned SmallSize=8>
struct df_iterator_default_set : public SmallPtrSet<NodeRef, SmallSize> {
  using BaseSet = SmallPtrSet<NodeRef, SmallSize>;
  using iterator = typename BaseSet::iterator;

  std::pair<iterator,bool> insert(NodeRef N) { return BaseSet::insert(N); }
  template <typename IterT>
  void insert(IterT Begin, IterT End) { BaseSet::insert(Begin,End); }

  void completed(NodeRef) {}
};

                               
template <class GraphT,
          class SetType =
              df_iterator_default_set<typename GraphTraits<GraphT>::NodeRef>,
          bool ExtStorage = false, class GT = GraphTraits<GraphT>>
class df_iterator : public df_iterator_storage<SetType, ExtStorage> {
public:
  using iterator_category = std::forward_iterator_tag;
  using value_type = typename GT::NodeRef;
  using difference_type = std::ptrdiff_t;
  using pointer = value_type *;
  using reference = value_type &;

private:
  using NodeRef = typename GT::NodeRef;
  using ChildItTy = typename GT::ChildIteratorType;

                                                                          
                                                                               
         
  using StackElement = std::pair<NodeRef, Optional<ChildItTy>>;

                                                                     
  std::vector<StackElement> VisitStack;

private:
  inline df_iterator(NodeRef Node) {
    this->Visited.insert(Node);
    VisitStack.push_back(StackElement(Node, None));
  }

  inline df_iterator() = default;                              

  inline df_iterator(NodeRef Node, SetType &S)
      : df_iterator_storage<SetType, ExtStorage>(S) {
    if (this->Visited.insert(Node).second)
      VisitStack.push_back(StackElement(Node, None));
  }

  inline df_iterator(SetType &S)
    : df_iterator_storage<SetType, ExtStorage>(S) {
                                 
  }

  inline void toNext() {
    do {
      NodeRef Node = VisitStack.back().first;
      Optional<ChildItTy> &Opt = VisitStack.back().second;

      if (!Opt)
        Opt.emplace(GT::child_begin(Node));

                                                          
                                                                       
                   
      while (*Opt != GT::child_end(Node)) {
        NodeRef Next = *(*Opt)++;
                                             
        if (this->Visited.insert(Next).second) {
                           
          VisitStack.push_back(StackElement(Next, None));
          return;
        }
      }
      this->Visited.completed(Node);

                                                                   
      VisitStack.pop_back();
    } while (!VisitStack.empty());
  }

public:
                                                                      
  static df_iterator begin(const GraphT &G) {
    return df_iterator(GT::getEntryNode(G));
  }
  static df_iterator end(const GraphT &G) { return df_iterator(); }

                                                                            
  static df_iterator begin(const GraphT &G, SetType &S) {
    return df_iterator(GT::getEntryNode(G), S);
  }
  static df_iterator end(const GraphT &G, SetType &S) { return df_iterator(S); }

  bool operator==(const df_iterator &x) const {
    return VisitStack == x.VisitStack;
  }
  bool operator!=(const df_iterator &x) const { return !(*this == x); }

  const NodeRef &operator*() const { return VisitStack.back().first; }

                                                                            
                                                                       
                                                                             
    
  NodeRef operator->() const { return **this; }

  df_iterator &operator++() {                
    toNext();
    return *this;
  }

                                                                       
     
                                                                         
                                                                            
  df_iterator &skipChildren() {
    VisitStack.pop_back();
    if (!VisitStack.empty())
      toNext();
    return *this;
  }

  df_iterator operator++(int) {                 
    df_iterator tmp = *this;
    ++*this;
    return tmp;
  }

                                                                       
                                                                               
                                                                           
    
  bool nodeVisited(NodeRef Node) const {
    return this->Visited.count(Node) != 0;
  }

                                                                              
                                        
  unsigned getPathLength() const { return VisitStack.size(); }

                                                                           
                   
  NodeRef getPath(unsigned n) const { return VisitStack[n].first; }
};

                                                                             
  
template <class T>
df_iterator<T> df_begin(const T& G) {
  return df_iterator<T>::begin(G);
}

template <class T>
df_iterator<T> df_end(const T& G) {
  return df_iterator<T>::end(G);
}

                                                                  
template <class T>
iterator_range<df_iterator<T>> depth_first(const T& G) {
  return make_range(df_begin(G), df_end(G));
}

                                                                  
template <class T, class SetTy = std::set<typename GraphTraits<T>::NodeRef>>
struct df_ext_iterator : public df_iterator<T, SetTy, true> {
  df_ext_iterator(const df_iterator<T, SetTy, true> &V)
    : df_iterator<T, SetTy, true>(V) {}
};

template <class T, class SetTy>
df_ext_iterator<T, SetTy> df_ext_begin(const T& G, SetTy &S) {
  return df_ext_iterator<T, SetTy>::begin(G, S);
}

template <class T, class SetTy>
df_ext_iterator<T, SetTy> df_ext_end(const T& G, SetTy &S) {
  return df_ext_iterator<T, SetTy>::end(G, S);
}

template <class T, class SetTy>
iterator_range<df_ext_iterator<T, SetTy>> depth_first_ext(const T& G,
                                                          SetTy &S) {
  return make_range(df_ext_begin(G, S), df_ext_end(G, S));
}

                                                                 
template <class T,
          class SetTy =
              df_iterator_default_set<typename GraphTraits<T>::NodeRef>,
          bool External = false>
struct idf_iterator : public df_iterator<Inverse<T>, SetTy, External> {
  idf_iterator(const df_iterator<Inverse<T>, SetTy, External> &V)
    : df_iterator<Inverse<T>, SetTy, External>(V) {}
};

template <class T>
idf_iterator<T> idf_begin(const T& G) {
  return idf_iterator<T>::begin(Inverse<T>(G));
}

template <class T>
idf_iterator<T> idf_end(const T& G){
  return idf_iterator<T>::end(Inverse<T>(G));
}

                                                                  
template <class T>
iterator_range<idf_iterator<T>> inverse_depth_first(const T& G) {
  return make_range(idf_begin(G), idf_end(G));
}

                                                                          
template <class T, class SetTy = std::set<typename GraphTraits<T>::NodeRef>>
struct idf_ext_iterator : public idf_iterator<T, SetTy, true> {
  idf_ext_iterator(const idf_iterator<T, SetTy, true> &V)
    : idf_iterator<T, SetTy, true>(V) {}
  idf_ext_iterator(const df_iterator<Inverse<T>, SetTy, true> &V)
    : idf_iterator<T, SetTy, true>(V) {}
};

template <class T, class SetTy>
idf_ext_iterator<T, SetTy> idf_ext_begin(const T& G, SetTy &S) {
  return idf_ext_iterator<T, SetTy>::begin(Inverse<T>(G), S);
}

template <class T, class SetTy>
idf_ext_iterator<T, SetTy> idf_ext_end(const T& G, SetTy &S) {
  return idf_ext_iterator<T, SetTy>::end(Inverse<T>(G), S);
}

template <class T, class SetTy>
iterator_range<idf_ext_iterator<T, SetTy>> inverse_depth_first_ext(const T& G,
                                                                   SetTy &S) {
  return make_range(idf_ext_begin(G, S), idf_ext_end(G, S));
}

}                      

#endif                                 

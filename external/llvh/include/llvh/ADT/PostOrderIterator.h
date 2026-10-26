//===- llvm/ADT/PostOrderIterator.h - PostOrder iterator --------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file builds on the ADT/GraphTraits.h file to build a generic graph
// post order iterator.  This should work over any graph type that has a
// GraphTraits specialization.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_POSTORDERITERATOR_H
#define LLVM_ADT_POSTORDERITERATOR_H

#include "llvh/ADT/GraphTraits.h"
#include "llvh/ADT/Optional.h"
#include "llvh/ADT/SmallPtrSet.h"
#include "llvh/ADT/iterator_range.h"
#include <iterator>
#include <set>
#include <utility>
#include <vector>

namespace llvh {

                                                                         
                                                                
  
                                                                           
                                                                 
  
                                                                     
  
                                                                           
                                                                        
                                                                          
                 
  
                                                                              
                                                                         
                                                          
  
                                                                            
                                                                              
                                                                              
  
                                                                             
                                                                            
                                                                             
                       

                                                                           
template<class SetType, bool External>
class po_iterator_storage {
  SetType Visited;

public:
                                                       
  template <typename NodeRef>
  bool insertEdge(Optional<NodeRef> From, NodeRef To) {
    return Visited.insert(To).second;
  }

                                                       
  template <typename NodeRef> void finishPostorder(NodeRef BB) {}
};

                                                                          
template<class SetType>
class po_iterator_storage<SetType, true> {
  SetType &Visited;

public:
  po_iterator_storage(SetType &VSet) : Visited(VSet) {}
  po_iterator_storage(const po_iterator_storage &S) : Visited(S.Visited) {}

                                                                                
                   
                                                             
  template <class NodeRef> bool insertEdge(Optional<NodeRef> From, NodeRef To) {
    return Visited.insert(To).second;
  }

                                                       
  template <class NodeRef> void finishPostorder(NodeRef BB) {}
};

template <class GraphT,
          class SetType =
              SmallPtrSet<typename GraphTraits<GraphT>::NodeRef, 8>,
          bool ExtStorage = false, class GT = GraphTraits<GraphT>>
class po_iterator : public po_iterator_storage<SetType, ExtStorage> {
public:
  using iterator_category = std::forward_iterator_tag;
  using value_type = typename GT::NodeRef;
  using difference_type = std::ptrdiff_t;
  using pointer = value_type *;
  using reference = value_type &;

private:
  using NodeRef = typename GT::NodeRef;
  using ChildItTy = typename GT::ChildIteratorType;

                                                                     
                                                                              
  std::vector<std::pair<NodeRef, ChildItTy>> VisitStack;

  po_iterator(NodeRef BB) {
    this->insertEdge(Optional<NodeRef>(), BB);
    VisitStack.push_back(std::make_pair(BB, GT::child_begin(BB)));
    traverseChild();
  }

  po_iterator() = default;                               

  po_iterator(NodeRef BB, SetType &S)
      : po_iterator_storage<SetType, ExtStorage>(S) {
    if (this->insertEdge(Optional<NodeRef>(), BB)) {
      VisitStack.push_back(std::make_pair(BB, GT::child_begin(BB)));
      traverseChild();
    }
  }

  po_iterator(SetType &S)
      : po_iterator_storage<SetType, ExtStorage>(S) {
  }                               

  void traverseChild() {
    while (VisitStack.back().second != GT::child_end(VisitStack.back().first)) {
      NodeRef BB = *VisitStack.back().second++;
      if (this->insertEdge(Optional<NodeRef>(VisitStack.back().first), BB)) {
                                         
        VisitStack.push_back(std::make_pair(BB, GT::child_begin(BB)));
      }
    }
  }

public:
                                     
  static po_iterator begin(GraphT G) {
    return po_iterator(GT::getEntryNode(G));
  }
  static po_iterator end(GraphT G) { return po_iterator(); }

  static po_iterator begin(GraphT G, SetType &S) {
    return po_iterator(GT::getEntryNode(G), S);
  }
  static po_iterator end(GraphT G, SetType &S) { return po_iterator(S); }

  bool operator==(const po_iterator &x) const {
    return VisitStack == x.VisitStack;
  }
  bool operator!=(const po_iterator &x) const { return !(*this == x); }

  const NodeRef &operator*() const { return VisitStack.back().first; }

                                                                            
                                                                             
                                                                             
    
  NodeRef operator->() const { return **this; }

  po_iterator &operator++() {                
    this->finishPostorder(VisitStack.back().first);
    VisitStack.pop_back();
    if (!VisitStack.empty())
      traverseChild();
    return *this;
  }

  po_iterator operator++(int) {                 
    po_iterator tmp = *this;
    ++*this;
    return tmp;
  }
};

                                                                             
  
template <class T>
po_iterator<T> po_begin(const T &G) { return po_iterator<T>::begin(G); }
template <class T>
po_iterator<T> po_end  (const T &G) { return po_iterator<T>::end(G); }

template <class T> iterator_range<po_iterator<T>> post_order(const T &G) {
  return make_range(po_begin(G), po_end(G));
}

                                                                
template <class T, class SetType = std::set<typename GraphTraits<T>::NodeRef>>
struct po_ext_iterator : public po_iterator<T, SetType, true> {
  po_ext_iterator(const po_iterator<T, SetType, true> &V) :
  po_iterator<T, SetType, true>(V) {}
};

template<class T, class SetType>
po_ext_iterator<T, SetType> po_ext_begin(T G, SetType &S) {
  return po_ext_iterator<T, SetType>::begin(G, S);
}

template<class T, class SetType>
po_ext_iterator<T, SetType> po_ext_end(T G, SetType &S) {
  return po_ext_iterator<T, SetType>::end(G, S);
}

template <class T, class SetType>
iterator_range<po_ext_iterator<T, SetType>> post_order_ext(const T &G, SetType &S) {
  return make_range(po_ext_begin(G, S), po_ext_end(G, S));
}

                                                                
template <class T, class SetType = std::set<typename GraphTraits<T>::NodeRef>,
          bool External = false>
struct ipo_iterator : public po_iterator<Inverse<T>, SetType, External> {
  ipo_iterator(const po_iterator<Inverse<T>, SetType, External> &V) :
     po_iterator<Inverse<T>, SetType, External> (V) {}
};

template <class T>
ipo_iterator<T> ipo_begin(const T &G) {
  return ipo_iterator<T>::begin(G);
}

template <class T>
ipo_iterator<T> ipo_end(const T &G){
  return ipo_iterator<T>::end(G);
}

template <class T>
iterator_range<ipo_iterator<T>> inverse_post_order(const T &G) {
  return make_range(ipo_begin(G), ipo_end(G));
}

                                                                        
template <class T, class SetType = std::set<typename GraphTraits<T>::NodeRef>>
struct ipo_ext_iterator : public ipo_iterator<T, SetType, true> {
  ipo_ext_iterator(const ipo_iterator<T, SetType, true> &V) :
    ipo_iterator<T, SetType, true>(V) {}
  ipo_ext_iterator(const po_iterator<Inverse<T>, SetType, true> &V) :
    ipo_iterator<T, SetType, true>(V) {}
};

template <class T, class SetType>
ipo_ext_iterator<T, SetType> ipo_ext_begin(const T &G, SetType &S) {
  return ipo_ext_iterator<T, SetType>::begin(G, S);
}

template <class T, class SetType>
ipo_ext_iterator<T, SetType> ipo_ext_end(const T &G, SetType &S) {
  return ipo_ext_iterator<T, SetType>::end(G, S);
}

template <class T, class SetType>
iterator_range<ipo_ext_iterator<T, SetType>>
inverse_post_order_ext(const T &G, SetType &S) {
  return make_range(ipo_ext_begin(G, S), ipo_ext_end(G, S));
}

                                                                              
                                       
                                                                              
  
                                                                              
                                                                               
                                                                       
                                                                               
                                                                              
                                                                                
  
                                                                             
                                                                           
                                    
  
                                       
    
                                                                               
                                                                
           
      
                                                                
           
      
    
  

template<class GraphT, class GT = GraphTraits<GraphT>>
class ReversePostOrderTraversal {
  using NodeRef = typename GT::NodeRef;

  std::vector<NodeRef> Blocks;                                 

  void Initialize(NodeRef BB) {
    std::copy(po_begin(BB), po_end(BB), std::back_inserter(Blocks));
  }

public:
  using rpo_iterator = typename std::vector<NodeRef>::reverse_iterator;

  ReversePostOrderTraversal(GraphT G) { Initialize(GT::getEntryNode(G)); }

                                                                                
  rpo_iterator begin() { return Blocks.rbegin(); }
  rpo_iterator end() { return Blocks.rend(); }
};

}                      

#endif                                

//===- llvm/ADT/ilist_iterator.h - Intrusive List Iterator ------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_ILIST_ITERATOR_H
#define LLVM_ADT_ILIST_ITERATOR_H

#include "llvh/ADT/ilist_node.h"
#include <cassert>
#include <cstddef>
#include <iterator>
#include <type_traits>

namespace llvh {

namespace ilist_detail {

                                  
template <class OptionsT, bool IsConst> struct IteratorTraits;
template <class OptionsT> struct IteratorTraits<OptionsT, false> {
  using value_type = typename OptionsT::value_type;
  using pointer = typename OptionsT::pointer;
  using reference = typename OptionsT::reference;
  using node_pointer = ilist_node_impl<OptionsT> *;
  using node_reference = ilist_node_impl<OptionsT> &;
};
template <class OptionsT> struct IteratorTraits<OptionsT, true> {
  using value_type = const typename OptionsT::value_type;
  using pointer = typename OptionsT::const_pointer;
  using reference = typename OptionsT::const_reference;
  using node_pointer = const ilist_node_impl<OptionsT> *;
  using node_reference = const ilist_node_impl<OptionsT> &;
};

template <bool IsReverse> struct IteratorHelper;
template <> struct IteratorHelper<false> : ilist_detail::NodeAccess {
  using Access = ilist_detail::NodeAccess;

  template <class T> static void increment(T *&I) { I = Access::getNext(*I); }
  template <class T> static void decrement(T *&I) { I = Access::getPrev(*I); }
};
template <> struct IteratorHelper<true> : ilist_detail::NodeAccess {
  using Access = ilist_detail::NodeAccess;

  template <class T> static void increment(T *&I) { I = Access::getPrev(*I); }
  template <class T> static void decrement(T *&I) { I = Access::getNext(*I); }
};

}                              

                                                      
template <class OptionsT, bool IsReverse, bool IsConst>
class ilist_iterator : ilist_detail::SpecificNodeAccess<OptionsT> {
  friend ilist_iterator<OptionsT, IsReverse, !IsConst>;
  friend ilist_iterator<OptionsT, !IsReverse, IsConst>;
  friend ilist_iterator<OptionsT, !IsReverse, !IsConst>;

  using Traits = ilist_detail::IteratorTraits<OptionsT, IsConst>;
  using Access = ilist_detail::SpecificNodeAccess<OptionsT>;

public:
  using value_type = typename Traits::value_type;
  using pointer = typename Traits::pointer;
  using reference = typename Traits::reference;
  using difference_type = ptrdiff_t;
  using iterator_category = std::bidirectional_iterator_tag;
  using const_pointer = typename OptionsT::const_pointer;
  using const_reference = typename OptionsT::const_reference;

private:
  using node_pointer = typename Traits::node_pointer;
  using node_reference = typename Traits::node_reference;

  node_pointer NodePtr = nullptr;

public:
                                
  explicit ilist_iterator(node_reference N) : NodePtr(&N) {}

  explicit ilist_iterator(pointer NP) : NodePtr(Access::getNodePtr(NP)) {}
  explicit ilist_iterator(reference NR) : NodePtr(Access::getNodePtr(&NR)) {}
  ilist_iterator() = default;

                                                                              
                           
  template <bool RHSIsConst>
  ilist_iterator(
      const ilist_iterator<OptionsT, IsReverse, RHSIsConst> &RHS,
      typename std::enable_if<IsConst || !RHSIsConst, void *>::type = nullptr)
      : NodePtr(RHS.NodePtr) {}

                                                                              
                           
  template <bool RHSIsConst>
  typename std::enable_if<IsConst || !RHSIsConst, ilist_iterator &>::type
  operator=(const ilist_iterator<OptionsT, IsReverse, RHSIsConst> &RHS) {
    NodePtr = RHS.NodePtr;
    return *this;
  }

                                                            
     
                                                                            
                                                                              
                                                                            
                                                                   
     
                                                     
  explicit ilist_iterator(
      const ilist_iterator<OptionsT, !IsReverse, IsConst> &RHS)
      : ilist_iterator(++RHS.getReverse()) {}

                                              
     
                                                                               
                                                                          
                                                                          
  ilist_iterator<OptionsT, !IsReverse, IsConst> getReverse() const {
    if (NodePtr)
      return ilist_iterator<OptionsT, !IsReverse, IsConst>(*NodePtr);
    return ilist_iterator<OptionsT, !IsReverse, IsConst>();
  }

                 
  ilist_iterator<OptionsT, IsReverse, false> getNonConst() const {
    if (NodePtr)
      return ilist_iterator<OptionsT, IsReverse, false>(
          const_cast<typename ilist_iterator<OptionsT, IsReverse,
                                             false>::node_reference>(*NodePtr));
    return ilist_iterator<OptionsT, IsReverse, false>();
  }

                 
  reference operator*() const {
    assert(!NodePtr->isKnownSentinel());
    return *Access::getValuePtr(NodePtr);
  }
  pointer operator->() const { return &operator*(); }

                         
  friend bool operator==(const ilist_iterator &LHS, const ilist_iterator &RHS) {
    return LHS.NodePtr == RHS.NodePtr;
  }
  friend bool operator!=(const ilist_iterator &LHS, const ilist_iterator &RHS) {
    return LHS.NodePtr != RHS.NodePtr;
  }

                                         
  ilist_iterator &operator--() {
    NodePtr = IsReverse ? NodePtr->getNext() : NodePtr->getPrev();
    return *this;
  }
  ilist_iterator &operator++() {
    NodePtr = IsReverse ? NodePtr->getPrev() : NodePtr->getNext();
    return *this;
  }
  ilist_iterator operator--(int) {
    ilist_iterator tmp = *this;
    --*this;
    return tmp;
  }
  ilist_iterator operator++(int) {
    ilist_iterator tmp = *this;
    ++*this;
    return tmp;
  }

                                    
  node_pointer getNodePtr() const { return static_cast<node_pointer>(NodePtr); }

                                                                  
  bool isEnd() const { return NodePtr ? NodePtr->isSentinel() : false; }
};

template <typename From> struct simplify_type;

                                                                               
                                                 
   
                                                                        
template <class OptionsT, bool IsConst>
struct simplify_type<ilist_iterator<OptionsT, false, IsConst>> {
  using iterator = ilist_iterator<OptionsT, false, IsConst>;
  using SimpleType = typename iterator::pointer;

  static SimpleType getSimplifiedValue(const iterator &Node) { return &*Node; }
};
template <class OptionsT, bool IsConst>
struct simplify_type<const ilist_iterator<OptionsT, false, IsConst>>
    : simplify_type<ilist_iterator<OptionsT, false, IsConst>> {};

}                      

#endif                             

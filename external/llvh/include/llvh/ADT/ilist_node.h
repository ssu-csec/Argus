//===- llvm/ADT/ilist_node.h - Intrusive Linked List Helper -----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the ilist_node class template, which is a convenient
// base class for creating classes that can be used with ilists.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_ILIST_NODE_H
#define LLVM_ADT_ILIST_NODE_H

#include "llvh/ADT/ilist_node_base.h"
#include "llvh/ADT/ilist_node_options.h"

namespace llvh {

namespace ilist_detail {

struct NodeAccess;

}                              

template <class OptionsT, bool IsReverse, bool IsConst> class ilist_iterator;
template <class OptionsT> class ilist_sentinel;

                                     
   
                                                                               
                                             
   
                                                                        
                                                                              
                                       
template <class OptionsT> class ilist_node_impl : OptionsT::node_base_type {
  using value_type = typename OptionsT::value_type;
  using node_base_type = typename OptionsT::node_base_type;
  using list_base_type = typename OptionsT::list_base_type;

  friend typename OptionsT::list_base_type;
  friend struct ilist_detail::NodeAccess;
  friend class ilist_sentinel<OptionsT>;
  friend class ilist_iterator<OptionsT, false, false>;
  friend class ilist_iterator<OptionsT, false, true>;
  friend class ilist_iterator<OptionsT, true, false>;
  friend class ilist_iterator<OptionsT, true, true>;

protected:
  using self_iterator = ilist_iterator<OptionsT, false, false>;
  using const_self_iterator = ilist_iterator<OptionsT, false, true>;
  using reverse_self_iterator = ilist_iterator<OptionsT, true, false>;
  using const_reverse_self_iterator = ilist_iterator<OptionsT, true, true>;

  ilist_node_impl() = default;

private:
  ilist_node_impl *getPrev() {
    return static_cast<ilist_node_impl *>(node_base_type::getPrev());
  }

  ilist_node_impl *getNext() {
    return static_cast<ilist_node_impl *>(node_base_type::getNext());
  }

  const ilist_node_impl *getPrev() const {
    return static_cast<ilist_node_impl *>(node_base_type::getPrev());
  }

  const ilist_node_impl *getNext() const {
    return static_cast<ilist_node_impl *>(node_base_type::getNext());
  }

  void setPrev(ilist_node_impl *N) { node_base_type::setPrev(N); }
  void setNext(ilist_node_impl *N) { node_base_type::setNext(N); }

public:
  self_iterator getIterator() { return self_iterator(*this); }
  const_self_iterator getIterator() const { return const_self_iterator(*this); }

  reverse_self_iterator getReverseIterator() {
    return reverse_self_iterator(*this);
  }

  const_reverse_self_iterator getReverseIterator() const {
    return const_reverse_self_iterator(*this);
  }

                                                              
  using node_base_type::isKnownSentinel;

                                              
     
                                                                        
                                                           
  bool isSentinel() const {
    static_assert(OptionsT::is_sentinel_tracking_explicit,
                  "Use ilist_sentinel_tracking<true> to enable isSentinel()");
    return node_base_type::isSentinel();
  }
};

                           
   
                                                                      
                                                                               
                               
   
                                                                       
                             
   
                                                                          
                                                 
                                                                              
                                                                              
                                                                               
                                                        
   
                                                          
                                                                               
                                                                           
                                                                              
          
   
                                                                             
                                                                            
                                                                         
   
            
                
                
                                                                           
   
                
                                          
                                          
           
                          
                          
     
               
   
                                                            
template <class T, class... Options>
class ilist_node
    : public ilist_node_impl<
          typename ilist_detail::compute_node_options<T, Options...>::type> {
  static_assert(ilist_detail::check_options<Options...>::value,
                "Unrecognized node option!");
};

namespace ilist_detail {

                                               
   
                                                                              
                                                                       
   
                                                                        
struct NodeAccess {
protected:
  template <class OptionsT>
  static ilist_node_impl<OptionsT> *getNodePtr(typename OptionsT::pointer N) {
    return N;
  }

  template <class OptionsT>
  static const ilist_node_impl<OptionsT> *
  getNodePtr(typename OptionsT::const_pointer N) {
    return N;
  }

  template <class OptionsT>
  static typename OptionsT::pointer getValuePtr(ilist_node_impl<OptionsT> *N) {
    return static_cast<typename OptionsT::pointer>(N);
  }

  template <class OptionsT>
  static typename OptionsT::const_pointer
  getValuePtr(const ilist_node_impl<OptionsT> *N) {
    return static_cast<typename OptionsT::const_pointer>(N);
  }

  template <class OptionsT>
  static ilist_node_impl<OptionsT> *getPrev(ilist_node_impl<OptionsT> &N) {
    return N.getPrev();
  }

  template <class OptionsT>
  static ilist_node_impl<OptionsT> *getNext(ilist_node_impl<OptionsT> &N) {
    return N.getNext();
  }

  template <class OptionsT>
  static const ilist_node_impl<OptionsT> *
  getPrev(const ilist_node_impl<OptionsT> &N) {
    return N.getPrev();
  }

  template <class OptionsT>
  static const ilist_node_impl<OptionsT> *
  getNext(const ilist_node_impl<OptionsT> &N) {
    return N.getNext();
  }
};

template <class OptionsT> struct SpecificNodeAccess : NodeAccess {
protected:
  using pointer = typename OptionsT::pointer;
  using const_pointer = typename OptionsT::const_pointer;
  using node_type = ilist_node_impl<OptionsT>;

  static node_type *getNodePtr(pointer N) {
    return NodeAccess::getNodePtr<OptionsT>(N);
  }

  static const node_type *getNodePtr(const_pointer N) {
    return NodeAccess::getNodePtr<OptionsT>(N);
  }

  static pointer getValuePtr(node_type *N) {
    return NodeAccess::getValuePtr<OptionsT>(N);
  }

  static const_pointer getValuePtr(const node_type *N) {
    return NodeAccess::getValuePtr<OptionsT>(N);
  }
};

}                              

template <class OptionsT>
class ilist_sentinel : public ilist_node_impl<OptionsT> {
public:
  ilist_sentinel() {
    this->initializeSentinel();
    reset();
  }

  void reset() {
    this->setPrev(this);
    this->setNext(this);
  }

  bool empty() const { return this == this->getPrev(); }
};

                                                  
   
                                                                              
                                                                             
template <typename NodeTy, typename ParentTy, class... Options>
class ilist_node_with_parent : public ilist_node<NodeTy, Options...> {
protected:
  ilist_node_with_parent() = default;

private:
                                     
     
                                                                       
                                                                    
                  
  const ParentTy *getNodeParent() const {
    return static_cast<const NodeTy *>(this)->getParent();
  }

public:
                                   
        
                                                             
  NodeTy *getPrevNode() {
                                                                              
                                             
    const auto &List =
        getNodeParent()->*(ParentTy::getSublistAccess((NodeTy *)nullptr));
    return List.getPrevNode(*static_cast<NodeTy *>(this));
  }

                                                             
  const NodeTy *getPrevNode() const {
    return const_cast<ilist_node_with_parent *>(this)->getPrevNode();
  }

                                                         
  NodeTy *getNextNode() {
                                                                              
                                             
    const auto &List =
        getNodeParent()->*(ParentTy::getSublistAccess((NodeTy *)nullptr));
    return List.getNextNode(*static_cast<NodeTy *>(this));
  }

                                                         
  const NodeTy *getNextNode() const {
    return const_cast<ilist_node_with_parent *>(this)->getNextNode();
  }
        
};

}                      

#endif                         

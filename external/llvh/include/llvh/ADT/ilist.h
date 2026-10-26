//==-- llvm/ADT/ilist.h - Intrusive Linked List Template ---------*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines classes to implement an intrusive doubly linked list class
// (i.e. each node of the list must contain a next and previous field for the
// list.
//
// The ilist class itself should be a plug in replacement for list.  This list
// replacement does not provide a constant time size() method, so be careful to
// use empty() when you really want to know if it's empty.
//
// The ilist class is implemented as a circular list.  The list itself contains
// a sentinel node, whose Next points at begin() and whose Prev points at
// rbegin().  The sentinel node itself serves as end() and rend().
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_ILIST_H
#define LLVM_ADT_ILIST_H

#include "llvh/ADT/simple_ilist.h"
#include <cassert>
#include <cstddef>
#include <iterator>

namespace llvh {

                                               
   
                                                                              
                                                                             
                                   
   
                             
template <typename NodeTy> struct ilist_alloc_traits {
  static void deleteNode(NodeTy *V) { delete V; }
};

                                            
   
                                                                     
                                                               
   
                                                                               
                         
   
         
               
                                                                        
            
template <typename NodeTy> struct ilist_noalloc_traits {
  static void deleteNode(NodeTy *V) {}
};

                                                        
   
                                                                         
               
template <typename NodeTy> struct ilist_callback_traits {
  void addNodeToList(NodeTy *) {}
  void removeNodeFromList(NodeTy *) {}

                                                      
     
                            
  template <class Iterator>
  void transferNodesFromList(ilist_callback_traits &OldList, Iterator          ,
                             Iterator         ) {
    (void)OldList;
  }
};

                                                                           
                            
   
                                                                
template <typename NodeTy>
struct ilist_node_traits : ilist_alloc_traits<NodeTy>,
                           ilist_callback_traits<NodeTy> {};

                                       
   
                                                 
template <typename NodeTy>
struct ilist_traits : public ilist_node_traits<NodeTy> {};

                                              
template <typename Ty> struct ilist_traits<const Ty> {};

namespace ilist_detail {

template <class T> T &make();

                                                                          
                                                     
template <class TraitsT, class NodeT> struct HasGetNext {
  typedef char Yes[1];
  typedef char No[2];
  template <size_t N> struct SFINAE {};

  template <class U>
  static Yes &test(U *I, decltype(I->getNext(&make<NodeT>())) * = 0);
  template <class> static No &test(...);

public:
  static const bool value = sizeof(test<TraitsT>(nullptr)) == sizeof(Yes);
};

                                                                               
                                                       
template <class TraitsT> struct HasCreateSentinel {
  typedef char Yes[1];
  typedef char No[2];

  template <class U>
  static Yes &test(U *I, decltype(I->createSentinel()) * = 0);
  template <class> static No &test(...);

public:
  static const bool value = sizeof(test<TraitsT>(nullptr)) == sizeof(Yes);
};

                                                                        
                                                                  
                 
template <class TraitsT, class NodeT> struct HasCreateNode {
  typedef char Yes[1];
  typedef char No[2];
  template <size_t N> struct SFINAE {};

  template <class U>
  static Yes &test(U *I, decltype(I->createNode(make<NodeT>())) * = 0);
  template <class> static No &test(...);

public:
  static const bool value = sizeof(test<TraitsT>(nullptr)) == sizeof(Yes);
};

template <class TraitsT, class NodeT> struct HasObsoleteCustomization {
  static const bool value = HasGetNext<TraitsT, NodeT>::value ||
                            HasCreateSentinel<TraitsT>::value ||
                            HasCreateNode<TraitsT, NodeT>::value;
};

}                              

                                                                                
  
                                                                       
              
   
                                                                              
                                                                       
                        
   
                                                                               
                                                                              
                                                                          
                                                                           
         
template <class IntrusiveListT, class TraitsT>
class iplist_impl : public TraitsT, IntrusiveListT {
  typedef IntrusiveListT base_list_type;

public:
  typedef typename base_list_type::pointer pointer;
  typedef typename base_list_type::const_pointer const_pointer;
  typedef typename base_list_type::reference reference;
  typedef typename base_list_type::const_reference const_reference;
  typedef typename base_list_type::value_type value_type;
  typedef typename base_list_type::size_type size_type;
  typedef typename base_list_type::difference_type difference_type;
  typedef typename base_list_type::iterator iterator;
  typedef typename base_list_type::const_iterator const_iterator;
  typedef typename base_list_type::reverse_iterator reverse_iterator;
  typedef
      typename base_list_type::const_reverse_iterator const_reverse_iterator;

private:
                                                                           
                                                                               
             
  static_assert(
      !ilist_detail::HasObsoleteCustomization<TraitsT, value_type>::value,
      "ilist customization points have changed!");

  static bool op_less(const_reference L, const_reference R) { return L < R; }
  static bool op_equal(const_reference L, const_reference R) { return L == R; }

public:
  iplist_impl() = default;

  iplist_impl(const iplist_impl &) = delete;
  iplist_impl &operator=(const iplist_impl &) = delete;

  iplist_impl(iplist_impl &&X)
      : TraitsT(std::move(X)), IntrusiveListT(std::move(X)) {}
  iplist_impl &operator=(iplist_impl &&X) {
    *static_cast<TraitsT *>(this) = std::move(X);
    *static_cast<IntrusiveListT *>(this) = std::move(X);
    return *this;
  }

  ~iplist_impl() { clear(); }

                                       
  size_type max_size() const { return size_type(-1); }

  using base_list_type::begin;
  using base_list_type::end;
  using base_list_type::rbegin;
  using base_list_type::rend;
  using base_list_type::empty;
  using base_list_type::front;
  using base_list_type::back;

  void swap(iplist_impl &RHS) {
    assert(0 && "Swap does not use list traits callback correctly yet!");
    base_list_type::swap(RHS);
  }

  iterator insert(iterator where, pointer New) {
    this->addNodeToList(New);                                         
    return base_list_type::insert(where, *New);
  }

  iterator insert(iterator where, const_reference New) {
    return this->insert(where, new value_type(New));
  }

  iterator insertAfter(iterator where, pointer New) {
    if (empty())
      return insert(begin(), New);
    else
      return insert(++where, New);
  }

                         
  template <class Cloner> void cloneFrom(const iplist_impl &L2, Cloner clone) {
    clear();
    for (const_reference V : L2)
      push_back(clone(V));
  }

  pointer remove(iterator &IT) {
    pointer Node = &*IT++;
    this->removeNodeFromList(Node);                                           
    base_list_type::remove(*Node);
    return Node;
  }

  pointer remove(const iterator &IT) {
    iterator MutIt = IT;
    return remove(MutIt);
  }

  pointer remove(pointer IT) { return remove(iterator(IT)); }
  pointer remove(reference IT) { return remove(iterator(IT)); }

                                                                         
  iterator erase(iterator where) {
    this->deleteNode(remove(where));
    return where;
  }

  iterator erase(pointer IT) { return erase(iterator(IT)); }
  iterator erase(reference IT) { return erase(iterator(IT)); }

                                                                  
                                           
     
                                                                          
                                                                      
  void clearAndLeakNodesUnsafely() { base_list_type::clear(); }

private:
                                                                              
                                 
    
  void transfer(iterator position, iplist_impl &L2, iterator first, iterator last) {
    if (position == last)
      return;

    if (this != &L2)                                       
      this->transferNodesFromList(L2, first, last);

    base_list_type::splice(position, L2, first, last);
  }

public:
                                                                                
                                                                
    

  using base_list_type::size;

  iterator erase(iterator first, iterator last) {
    while (first != last)
      first = erase(first);
    return last;
  }

  void clear() { erase(begin(), end()); }

                                
  void push_front(pointer val) { insert(begin(), val); }
  void push_back(pointer val) { insert(end(), val); }
  void pop_front() {
    assert(!empty() && "pop_front() on empty list!");
    erase(begin());
  }
  void pop_back() {
    assert(!empty() && "pop_back() on empty list!");
    iterator t = end(); erase(--t);
  }

                               
  template<class InIt> void insert(iterator where, InIt first, InIt last) {
    for (; first != last; ++first) insert(where, *first);
  }

                                                     
  void splice(iterator where, iplist_impl &L2) {
    if (!L2.empty())
      transfer(where, L2, L2.begin(), L2.end());
  }
  void splice(iterator where, iplist_impl &L2, iterator first) {
    iterator last = first; ++last;
    if (where == first || where == last) return;             
    transfer(where, L2, first, last);
  }
  void splice(iterator where, iplist_impl &L2, iterator first, iterator last) {
    if (first != last) transfer(where, L2, first, last);
  }
  void splice(iterator where, iplist_impl &L2, reference N) {
    splice(where, L2, iterator(N));
  }
  void splice(iterator where, iplist_impl &L2, pointer N) {
    splice(where, L2, iterator(N));
  }

  template <class Compare>
  void merge(iplist_impl &Right, Compare comp) {
    if (this == &Right)
      return;
    this->transferNodesFromList(Right, Right.begin(), Right.end());
    base_list_type::merge(Right, comp);
  }
  void merge(iplist_impl &Right) { return merge(Right, op_less); }

  using base_list_type::sort;

                                                             
  pointer getPrevNode(reference N) const {
    auto I = N.getIterator();
    if (I == begin())
      return nullptr;
    return &*std::prev(I);
  }
                                                             
  const_pointer getPrevNode(const_reference N) const {
    return getPrevNode(const_cast<reference >(N));
  }

                                                         
  pointer getNextNode(reference N) const {
    auto Next = std::next(N.getIterator());
    if (Next == end())
      return nullptr;
    return &*Next;
  }
                                                         
  const_pointer getNextNode(const_reference N) const {
    return getNextNode(const_cast<reference >(N));
  }
};

                                                                          
                                                           
   
                                                                             
                                                
template <class T, class... Options>
class iplist
    : public iplist_impl<simple_ilist<T, Options...>, ilist_traits<T>> {
  using iplist_impl_type = typename iplist::iplist_impl;

public:
  iplist() = default;

  iplist(const iplist &X) = delete;
  iplist &operator=(const iplist &X) = delete;

  iplist(iplist &&X) : iplist_impl_type(std::move(X)) {}
  iplist &operator=(iplist &&X) {
    *static_cast<iplist_impl_type *>(this) = std::move(X);
    return *this;
  }
};

template <class T, class... Options> using ilist = iplist<T, Options...>;

}                      

namespace std {

                                                
  template<class Ty>
  void swap(llvh::iplist<Ty> &Left, llvh::iplist<Ty> &Right) {
    Left.swap(Right);
  }

}                     

#endif                    

//===- llvm/ADT/simple_ilist.h - Simple Intrusive List ----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_SIMPLE_ILIST_H
#define LLVM_ADT_SIMPLE_ILIST_H

#include "llvh/ADT/ilist_base.h"
#include "llvh/ADT/ilist_iterator.h"
#include "llvh/ADT/ilist_node.h"
#include "llvh/ADT/ilist_node_options.h"
#include "llvh/Support/Compiler.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <functional>
#include <iterator>
#include <utility>

namespace llvh {

                                           
   
                                                                    
                                                                              
   
                                                                              
                                               
   
                                                                            
                                                                              
                                     
   
                                                                      
                                                                              
                                                                        
                                                                          
                                                                              
                                                                 
                               
                              
                     
   
                                                                        
                                                                           
                                                                            
                                                                             
                                                               
   
                                                                            
                                                                        
                                                     
                                                                            
                                                                        
                                     
                                                                           
                                                          
                                                                           
                                                                            
                               
   
                                          
                                                      
                                                                
                                 
                                                                      
                                                                   
                                                 
                                                                         
                           
   
                                                            
template <typename T, class... Options>
class simple_ilist
    : ilist_detail::compute_node_options<T, Options...>::type::list_base_type,
      ilist_detail::SpecificNodeAccess<
          typename ilist_detail::compute_node_options<T, Options...>::type> {
  static_assert(ilist_detail::check_options<Options...>::value,
                "Unrecognized node option!");
  using OptionsT =
      typename ilist_detail::compute_node_options<T, Options...>::type;
  using list_base_type = typename OptionsT::list_base_type;
  ilist_sentinel<OptionsT> Sentinel;

public:
  using value_type = typename OptionsT::value_type;
  using pointer = typename OptionsT::pointer;
  using reference = typename OptionsT::reference;
  using const_pointer = typename OptionsT::const_pointer;
  using const_reference = typename OptionsT::const_reference;
  using iterator = ilist_iterator<OptionsT, false, false>;
  using const_iterator = ilist_iterator<OptionsT, false, true>;
  using reverse_iterator = ilist_iterator<OptionsT, true, false>;
  using const_reverse_iterator = ilist_iterator<OptionsT, true, true>;
  using size_type = size_t;
  using difference_type = ptrdiff_t;

  simple_ilist() = default;
  ~simple_ilist() = default;

                          
  simple_ilist(const simple_ilist &) = delete;
  simple_ilist &operator=(const simple_ilist &) = delete;

                       
  simple_ilist(simple_ilist &&X) { splice(end(), X); }
  simple_ilist &operator=(simple_ilist &&X) {
    clear();
    splice(end(), X);
    return *this;
  }

  iterator begin() { return ++iterator(Sentinel); }
  const_iterator begin() const { return ++const_iterator(Sentinel); }
  iterator end() { return iterator(Sentinel); }
  const_iterator end() const { return const_iterator(Sentinel); }
  reverse_iterator rbegin() { return ++reverse_iterator(Sentinel); }
  const_reverse_iterator rbegin() const {
    return ++const_reverse_iterator(Sentinel);
  }
  reverse_iterator rend() { return reverse_iterator(Sentinel); }
  const_reverse_iterator rend() const {
    return const_reverse_iterator(Sentinel);
  }

                                                  
  LLVM_NODISCARD bool empty() const { return Sentinel.empty(); }

                                                    
  LLVM_NODISCARD size_type size() const {
    return std::distance(begin(), end());
  }

  reference front() { return *begin(); }
  const_reference front() const { return *begin(); }
  reference back() { return *rbegin(); }
  const_reference back() const { return *rbegin(); }

                                               
  void push_front(reference Node) { insert(begin(), Node); }

                                              
  void push_back(reference Node) { insert(end(), Node); }

                                                  
  void pop_front() { erase(begin()); }

                                                 
  void pop_back() { erase(--end()); }

                                                      
  void swap(simple_ilist &X) { std::swap(*this, X); }

                                               
  iterator insert(iterator I, reference Node) {
    list_base_type::insertBefore(*I.getNodePtr(), *this->getNodePtr(&Node));
    return iterator(&Node);
  }

                                            
  template <class Iterator>
  void insert(iterator I, Iterator First, Iterator Last) {
    for (; First != Last; ++First)
      insert(I, *First);
  }

                         
  template <class Cloner, class Disposer>
  void cloneFrom(const simple_ilist &L2, Cloner clone, Disposer dispose) {
    clearAndDispose(dispose);
    for (const_reference V : L2)
      push_back(*clone(V));
  }

                                                
     
                                               
                                                               
  void remove(reference N) { list_base_type::remove(*this->getNodePtr(&N)); }

                                                   
  template <class Disposer>
  void removeAndDispose(reference N, Disposer dispose) {
    remove(N);
    dispose(&N);
  }

                                               
     
                                                 
                                                              
  iterator erase(iterator I) {
    assert(I != end() && "Cannot remove end of list!");
    remove(*I++);
    return I;
  }

                                             
     
                                                               
  iterator erase(iterator First, iterator Last) {
    list_base_type::removeRange(*First.getNodePtr(), *Last.getNodePtr());
    return Last;
  }

                                                  
  template <class Disposer>
  iterator eraseAndDispose(iterator I, Disposer dispose) {
    auto Next = std::next(I);
    erase(I);
    dispose(&*I);
    return Next;
  }

                                                  
  template <class Disposer>
  iterator eraseAndDispose(iterator First, iterator Last, Disposer dispose) {
    while (First != Last)
      First = eraseAndDispose(First, dispose);
    return Last;
  }

                                    
     
                                                               
  void clear() { Sentinel.reset(); }

                                              
  template <class Disposer> void clearAndDispose(Disposer dispose) {
    eraseAndDispose(begin(), end(), dispose);
  }

                             
  void splice(iterator I, simple_ilist &L2) {
    splice(I, L2, L2.begin(), L2.end());
  }

                                         
  void splice(iterator I, simple_ilist &L2, iterator Node) {
    splice(I, L2, Node, std::next(Node));
  }

                                                   
  void splice(iterator I, simple_ilist &, iterator First, iterator Last) {
    list_base_type::transferBefore(*I.getNodePtr(), *First.getNodePtr(),
                                   *Last.getNodePtr());
  }

                            
     
                                         
       
  void merge(simple_ilist &RHS) { merge(RHS, std::less<T>()); }
  template <class Compare> void merge(simple_ilist &RHS, Compare comp);
       

                    
       
  void sort() { sort(std::less<T>()); }
  template <class Compare> void sort(Compare comp);
       
};

template <class T, class... Options>
template <class Compare>
void simple_ilist<T, Options...>::merge(simple_ilist &RHS, Compare comp) {
  if (this == &RHS || RHS.empty())
    return;
  iterator LI = begin(), LE = end();
  iterator RI = RHS.begin(), RE = RHS.end();
  while (LI != LE) {
    if (comp(*RI, *LI)) {
                                                           
      iterator RunStart = RI++;
      RI = std::find_if(RI, RE, [&](reference RV) { return !comp(RV, *LI); });
      splice(LI, RHS, RunStart, RI);
      if (RI == RE)
        return;
    }
    ++LI;
  }
                                                           
  splice(LE, RHS, RI, RE);
}

template <class T, class... Options>
template <class Compare>
void simple_ilist<T, Options...>::sort(Compare comp) {
                      
  if (empty() || std::next(begin()) == end())
    return;

                                  
  iterator Center = begin(), End = begin();
  while (End != end() && ++End != end()) {
    ++Center;
    ++End;
  }
  simple_ilist RHS;
  RHS.splice(RHS.end(), *this, Center, end());

                                               
  sort(comp);
  RHS.sort(comp);
  merge(RHS, comp);
}

}                      

#endif                           

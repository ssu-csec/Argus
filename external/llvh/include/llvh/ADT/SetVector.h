//===- llvm/ADT/SetVector.h - Set with insert order iteration ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements a set that has insertion order iteration
// characteristics. This is useful for keeping a set of things that need to be
// visited later but in a deterministic order (insertion order). The interface
// is purposefully minimal.
//
// This file defines SetVector and SmallSetVector, which performs no allocations
// if the SetVector has less than a certain number of elements.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_SETVECTOR_H
#define LLVM_ADT_SETVECTOR_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/DenseSet.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/Support/Compiler.h"
#include <algorithm>
#include <cassert>
#include <iterator>
#include <vector>

namespace llvh {

                                              
   
                                                                               
                                                                              
                       
template <typename T, typename Vector = std::vector<T>,
          typename Set = DenseSet<T>>
class SetVector {
public:
  using value_type = T;
  using key_type = T;
  using reference = T&;
  using const_reference = const T&;
  using set_type = Set;
  using vector_type = Vector;
  using iterator = typename vector_type::const_iterator;
  using const_iterator = typename vector_type::const_iterator;
  using reverse_iterator = typename vector_type::const_reverse_iterator;
  using const_reverse_iterator = typename vector_type::const_reverse_iterator;
  using size_type = typename vector_type::size_type;

                                  
  SetVector() = default;

                                                     
  template<typename It>
  SetVector(It Start, It End) {
    insert(Start, End);
  }

  ArrayRef<T> getArrayRef() const { return vector_; }

                                                           
  Vector takeVector() {
    set_.clear();
    return std::move(vector_);
  }

                                                 
  bool empty() const {
    return vector_.empty();
  }

                                                        
  size_type size() const {
    return vector_.size();
  }

                                                        
  iterator begin() {
    return vector_.begin();
  }

                                                             
  const_iterator begin() const {
    return vector_.begin();
  }

                                                  
  iterator end() {
    return vector_.end();
  }

                                                       
  const_iterator end() const {
    return vector_.end();
  }

                                                          
  reverse_iterator rbegin() {
    return vector_.rbegin();
  }

                                                               
  const_reverse_iterator rbegin() const {
    return vector_.rbegin();
  }

                                                               
  reverse_iterator rend() {
    return vector_.rend();
  }

                                                                     
  const_reverse_iterator rend() const {
    return vector_.rend();
  }

                                                
  const T &front() const {
    assert(!empty() && "Cannot call front() on empty SetVector!");
    return vector_.front();
  }

                                               
  const T &back() const {
    assert(!empty() && "Cannot call back() on empty SetVector!");
    return vector_.back();
  }

                               
  const_reference operator[](size_type n) const {
    assert(n < vector_.size() && "SetVector access out of range!");
    return vector_[n];
  }

                                              
                                                                   
  bool insert(const value_type &X) {
    bool result = set_.insert(X).second;
    if (result)
      vector_.push_back(X);
    return result;
  }

                                                    
  template<typename It>
  void insert(It Start, It End) {
    for (; Start != End; ++Start)
      if (set_.insert(*Start).second)
        vector_.push_back(*Start);
  }

                                         
  bool remove(const value_type& X) {
    if (set_.erase(X)) {
      typename vector_type::iterator I = find(vector_, X);
      assert(I != vector_.end() && "Corrupted SetVector instances!");
      vector_.erase(I);
      return true;
    }
    return false;
  }

                                                 
                                                                         
                                                                             
             
  iterator erase(iterator I) {
    const key_type &V = *I;
    assert(set_.count(V) && "Corrupted SetVector instances!");
    set_.erase(V);

                                                                   
                                                                        
                                                                          
    auto NI = vector_.begin();
    std::advance(NI, std::distance<iterator>(NI, I));

    return vector_.erase(NI);
  }

                                                                     
     
                                                                          
               
     
           
                                          
              
     
                                                                       
                                                 
     
                                              
  template <typename UnaryPredicate>
  bool remove_if(UnaryPredicate P) {
    typename vector_type::iterator I =
        llvh::remove_if(vector_, TestAndEraseFromSet<UnaryPredicate>(P, set_));
    if (I == vector_.end())
      return false;
    vector_.erase(I, vector_.end());
    return true;
  }

                                                                   
                                                                    
  size_type count(const key_type &key) const {
    return set_.count(key);
  }

                                    
  void clear() {
    set_.clear();
    vector_.clear();
  }

                                               
  void pop_back() {
    assert(!empty() && "Cannot remove an element from an empty SetVector!");
    set_.erase(back());
    vector_.pop_back();
  }

  LLVM_NODISCARD T pop_back_val() {
    T Ret = back();
    pop_back();
    return Ret;
  }

  bool operator==(const SetVector &that) const {
    return vector_ == that.vector_;
  }

  bool operator!=(const SetVector &that) const {
    return vector_ != that.vector_;
  }

                                                              
                                                                        
                                                              
  template <class STy>
  bool set_union(const STy &S) {
    bool Changed = false;

    for (typename STy::const_iterator SI = S.begin(), SE = S.end(); SI != SE;
         ++SI)
      if (insert(*SI))
        Changed = true;

    return Changed;
  }

                              
                                                                           
                                                              
  template <class STy>
  void set_subtract(const STy &S) {
    for (typename STy::const_iterator SI = S.begin(), SE = S.end(); SI != SE;
         ++SI)
      remove(*SI);
  }

private:
                                                               
     
                                                                              
                                                                     
  template <typename UnaryPredicate>
  class TestAndEraseFromSet {
    UnaryPredicate P;
    set_type &set_;

  public:
    TestAndEraseFromSet(UnaryPredicate P, set_type &set_)
        : P(std::move(P)), set_(set_) {}

    template <typename ArgumentT>
    bool operator()(const ArgumentT &Arg) {
      if (P(Arg)) {
        set_.erase(Arg);
        return true;
      }
      return false;
    }
  };

  set_type set_;                      
  vector_type vector_;                   
};

                                                            
                   
template <typename T, unsigned N>
class SmallSetVector
    : public SetVector<T, SmallVector<T, N>, SmallDenseSet<T, N>> {
public:
  SmallSetVector() = default;

                                                          
  template<typename It>
  SmallSetVector(It Start, It End) {
    this->insert(Start, End);
  }
};

}                      

#endif                        

//===- PriorityWorklist.h - Worklist with insertion priority ----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
///
/// \file
///
/// This file provides a priority worklist. See the class comments for details.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_PRIORITYWORKLIST_H
#define LLVM_ADT_PRIORITYWORKLIST_H

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/Support/Compiler.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <iterator>
#include <type_traits>
#include <vector>

namespace llvh {

                                                                         
   
                                                                           
                                                                      
                                                                            
                                                                         
                                             
   
                                                                           
                                                                          
   
                                                                            
                                                                             
                                                                              
                                     
   
                                                                             
                                                                               
                                                                              
                          
   
                                                                              
                                                                   
template <typename T, typename VectorT = std::vector<T>,
          typename MapT = DenseMap<T, ptrdiff_t>>
class PriorityWorklist {
public:
  using value_type = T;
  using key_type = T;
  using reference = T&;
  using const_reference = const T&;
  using size_type = typename MapT::size_type;

                                         
  PriorityWorklist() = default;

                                                        
  bool empty() const {
    return V.empty();
  }

                                                     
  size_type size() const {
    return M.size();
  }

                                                                          
                                                                           
  size_type count(const key_type &key) const {
    return M.count(key);
  }

                                                      
  const T &back() const {
    assert(!empty() && "Cannot call back() on empty PriorityWorklist!");
    return V.back();
  }

                                                     
                                                                          
  bool insert(const T &X) {
    assert(X != T() && "Cannot insert a null (default constructed) value!");
    auto InsertResult = M.insert({X, V.size()});
    if (InsertResult.second) {
                                                   
      V.push_back(X);
      return true;
    }

    auto &Index = InsertResult.first->second;
    assert(V[Index] == X && "Value not actually at index in map!");
    if (Index != (ptrdiff_t)(V.size() - 1)) {
                                                                              
      V[Index] = T();
      Index = (ptrdiff_t)V.size();
      V.push_back(X);
    }
    return false;
  }

                                                                  
  template <typename SequenceT>
  typename std::enable_if<!std::is_convertible<SequenceT, T>::value>::type
  insert(SequenceT &&Input) {
    if (std::begin(Input) == std::end(Input))
                                                   
      return;

                                                                     
                 
    ptrdiff_t StartIndex = V.size();
    V.insert(V.end(), std::begin(Input), std::end(Input));
                                                                              
    for (ptrdiff_t i = V.size() - 1; i >= StartIndex; --i) {
      auto InsertResult = M.insert({V[i], i});
      if (InsertResult.second)
        continue;

                                                                               
                    
      ptrdiff_t &Index = InsertResult.first->second;
      if (Index < StartIndex) {
        V[Index] = T();
        Index = i;
        continue;
      }

                                                                              
                   
      V[i] = T();
    }
  }

                                                      
  void pop_back() {
    assert(!empty() && "Cannot remove an element when empty!");
    assert(back() != T() && "Cannot have a null element at the back!");
    M.erase(back());
    do {
      V.pop_back();
    } while (!V.empty() && V.back() == T());
  }

  LLVM_NODISCARD T pop_back_val() {
    T Ret = back();
    pop_back();
    return Ret;
  }

                                      
     
                                                                                       
  bool erase(const T& X) {
    auto I = M.find(X);
    if (I == M.end())
      return false;

    assert(V[I->second] == X && "Value not actually at index in map!");
    if (I->second == (ptrdiff_t)(V.size() - 1)) {
      do {
        V.pop_back();
      } while (!V.empty() && V.back() == T());
    } else {
      V[I->second] = T();
    }
    M.erase(I);
    return true;
  }

                                                                    
     
                                                                          
               
     
           
                                          
              
     
                                                                              
                                                 
     
                                              
  template <typename UnaryPredicate>
  bool erase_if(UnaryPredicate P) {
    typename VectorT::iterator E =
        remove_if(V, TestAndEraseFromMap<UnaryPredicate>(P, M));
    if (E == V.end())
      return false;
    for (auto I = V.begin(); I != E; ++I)
      if (*I != T())
        M[*I] = I - V.begin();
    V.erase(E, V.end());
    return true;
  }

                                                
     
                                                                           
                                                    

                                           
  void clear() {
    M.clear();
    V.clear();
  }

private:
                                                               
     
                                                                              
                                                                            
                                                                         
            
  template <typename UnaryPredicateT>
  class TestAndEraseFromMap {
    UnaryPredicateT P;
    MapT &M;

  public:
    TestAndEraseFromMap(UnaryPredicateT P, MapT &M)
        : P(std::move(P)), M(M) {}

    bool operator()(const T &Arg) {
      if (Arg == T())
                                                    
        return false;

      if (P(Arg)) {
        M.erase(Arg);
        return true;
      }
      return false;
    }
  };

                                                
  MapT M;

                                                
  VectorT V;
};

                                                                           
                                      
template <typename T, unsigned N>
class SmallPriorityWorklist
    : public PriorityWorklist<T, SmallVector<T, N>,
                              SmallDenseMap<T, ptrdiff_t>> {
public:
  SmallPriorityWorklist() = default;
};

}                      

#endif                               

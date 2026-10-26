//===- llvm/ADT/SparseSet.h - Sparse set ------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the SparseSet class derived from the version described in
// Briggs, Torczon, "An efficient representation for sparse sets", ACM Letters
// on Programming Languages and Systems, Volume 2 Issue 1-4, March-Dec.  1993.
//
// A sparse set holds a small number of objects identified by integer keys from
// a moderately sized universe. The sparse set uses more memory than other
// containers in order to provide faster operations.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_SPARSESET_H
#define LLVM_ADT_SPARSESET_H

#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/Support/Allocator.h"
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <utility>

namespace llvh {

                                                                               
                                                                               
                                                                              
                                                                         
                                                                       
                                                                          
                                                                      
                                  
   
                                                                    
                                                  
                                                                           
   
                                                                
                                                                      
                                                                  
                                                                            
   
                                                                         
   
                                                             
   
template<typename ValueT>
struct SparseSetValTraits {
  static unsigned getValIndex(const ValueT &Val) {
    return Val.getSparseSetIndex();
  }
};

                                                                            
                                                                      
                                                           
   
template<typename KeyT, typename ValueT, typename KeyFunctorT>
struct SparseSetValFunctor {
  unsigned operator()(const ValueT &Val) const {
    return SparseSetValTraits<ValueT>::getValIndex(Val);
  }
};

                                                                         
                            
template<typename KeyT, typename KeyFunctorT>
struct SparseSetValFunctor<KeyT, KeyT, KeyFunctorT> {
  unsigned operator()(const KeyT &Key) const {
    return KeyFunctorT()(Key);
  }
};

                                                                            
                        
   
                                                                               
                                                                               
                                                                  
   
                                                                            
                                                                         
                                                                              
                                                                               
                                                                              
                                                                 
   
                                                                           
                                                                      
                                                      
   
                                                                          
                                                                               
                                                                        
                                                                            
             
   
                                                                               
                                  
   
                                                                               
                                                                              
            
   
                                                                             
                         
   
                                                       
                                                                            
                                                            
   
template<typename ValueT,
         typename KeyFunctorT = identity<unsigned>,
         typename SparseT = uint8_t>
class SparseSet {
  static_assert(std::numeric_limits<SparseT>::is_integer &&
                !std::numeric_limits<SparseT>::is_signed,
                "SparseT must be an unsigned integer type");

  using KeyT = typename KeyFunctorT::argument_type;
  using DenseT = SmallVector<ValueT, 8>;
  using size_type = unsigned;
  DenseT Dense;
  SparseT *Sparse = nullptr;
  unsigned Universe = 0;
  KeyFunctorT KeyIndexOf;
  SparseSetValFunctor<KeyT, ValueT, KeyFunctorT> ValIndexOf;

public:
  using value_type = ValueT;
  using reference = ValueT &;
  using const_reference = const ValueT &;
  using pointer = ValueT *;
  using const_pointer = const ValueT *;

  SparseSet() = default;
  SparseSet(const SparseSet &) = delete;
  SparseSet &operator=(const SparseSet &) = delete;
  ~SparseSet() { free(Sparse); }

                                                                              
                                                                          
            
     
                                                                  
     
  void setUniverse(unsigned U) {
                                                                              
                                                                            
    assert(empty() && "Can only resize universe on an empty map");
                                                  
    if (U >= Universe/4 && U <= Universe)
      return;
    free(Sparse);
                                                                          
                                                                       
                                                      
    Sparse = static_cast<SparseT*>(safe_calloc(U, sizeof(SparseT)));
    Universe = U;
  }

                                             
  using iterator = typename DenseT::iterator;
  using const_iterator = typename DenseT::const_iterator;

  const_iterator begin() const { return Dense.begin(); }
  const_iterator end() const { return Dense.end(); }
  iterator begin() { return Dense.begin(); }
  iterator end() { return Dense.end(); }

                                               
     
                                                 
     
  bool empty() const { return Dense.empty(); }

                                                       
     
                                                                             
               
     
  size_type size() const { return Dense.size(); }

                                                                           
     
  void clear() {
                                                      
    Dense.clear();
  }

                                               
     
                                         
                                                                      
     
  iterator findIndex(unsigned Idx) {
    assert(Idx < Universe && "Key out of range");
    const unsigned Stride = std::numeric_limits<SparseT>::max() + 1u;
    for (unsigned i = Sparse[Idx], e = size(); i < e; i += Stride) {
      const unsigned FoundIdx = ValIndexOf(Dense[i]);
      assert(FoundIdx < Universe && "Invalid key in set. Did object mutate?");
      if (Idx == FoundIdx)
        return begin() + i;
                                                                      
      if (!Stride)
        break;
    }
    return end();
  }

                                        
     
                                       
                                                                      
     
  iterator find(const KeyT &Key) {
    return findIndex(KeyIndexOf(Key));
  }

  const_iterator find(const KeyT &Key) const {
    return const_cast<SparseSet*>(this)->findIndex(KeyIndexOf(Key));
  }

                                                                          
                  
     
  size_type count(const KeyT &Key) const {
    return find(Key) == end() ? 0 : 1;
  }

                                                
     
                                                                               
                                             
     
                                                                             
                                                                          
     
                                          
     
  std::pair<iterator, bool> insert(const ValueT &Val) {
    unsigned Idx = ValIndexOf(Val);
    iterator I = findIndex(Idx);
    if (I != end())
      return std::make_pair(I, false);
    Sparse[Idx] = size();
    Dense.push_back(Val);
    return std::make_pair(end() - 1, true);
  }

                                                                              
                                                                         
                                            
  ValueT &operator[](const KeyT &Key) {
    return *insert(ValueT(Key)).first;
  }

  ValueT pop_back_val() {
                                                      
    return Dense.pop_back_val();
  }

                                                                        
     
                                                                              
                                                                             
                                   
     
                                                                  
                       
                             
              
                
     
                                                                         
     
  iterator erase(iterator I) {
    assert(unsigned(I - begin()) < size() && "Invalid iterator");
    if (I != end() - 1) {
      *I = Dense.back();
      unsigned BackIdx = ValIndexOf(Dense.back());
      assert(BackIdx < Universe && "Invalid key in set. Did object mutate?");
      Sparse[BackIdx] = I - begin();
    }
                                                                          
                                                           
    Dense.pop_back();
    return I;
  }

                                                                
     
                                                            
                                                                              
     
  bool erase(const KeyT &Key) {
    iterator I = find(Key);
    if (I == end())
      return false;
    erase(I);
    return true;
  }
};

}                      

#endif                        

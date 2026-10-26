//===- llvm/ADT/SparseMultiSet.h - Sparse multiset --------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the SparseMultiSet class, which adds multiset behavior to
// the SparseSet.
//
// A sparse multiset holds a small number of objects identified by integer keys
// from a moderately sized universe. The sparse multiset uses more memory than
// other containers in order to provide faster operations. Any key can map to
// multiple values. A SparseMultiSetNode class is provided, which serves as a
// convenient base class for the contents of a SparseMultiSet.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_SPARSEMULTISET_H
#define LLVM_ADT_SPARSEMULTISET_H

#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/SparseSet.h"
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <iterator>
#include <limits>
#include <utility>

namespace llvh {

                                                                            
                  
   
                                                                       
                                                                              
                                                                               
   
                                                                            
                                                                        
                                                                             
                                                                               
                                                                            
                                                                           
                                          
   
                                                                                
                                                                                
                                            
   
                                                                               
                                                                               
                                                                                
                                                                             
   
                                                                              
                                         
   
                                                                               
                                                                              
            
   
                                                                             
                         
   
                                                                             
                                                                              
                                                                           
                                                                                
                                                                        
                                                                              
                                                                       
                               
   
                                                       
                                                                            
                                                            
   
template<typename ValueT,
         typename KeyFunctorT = identity<unsigned>,
         typename SparseT = uint8_t>
class SparseMultiSet {
  static_assert(std::numeric_limits<SparseT>::is_integer &&
                !std::numeric_limits<SparseT>::is_signed,
                "SparseT must be an unsigned integer type");

                                                                            
                                                                          
                                                                            
                                                                      
                                                                          
                                   
  struct SMSNode {
    static const unsigned INVALID = ~0U;

    ValueT Data;
    unsigned Prev;
    unsigned Next;

    SMSNode(ValueT D, unsigned P, unsigned N) : Data(D), Prev(P), Next(N) {}

                                      
    bool isTail() const {
      return Next == INVALID;
    }

                                                                           
    bool isTombstone() const {
      return Prev == INVALID;
    }

                                                                                
             
    bool isValid() const { return Prev != INVALID; }
  };

  using KeyT = typename KeyFunctorT::argument_type;
  using DenseT = SmallVector<SMSNode, 8>;
  DenseT Dense;
  SparseT *Sparse = nullptr;
  unsigned Universe = 0;
  KeyFunctorT KeyIndexOf;
  SparseSetValFunctor<KeyT, ValueT, KeyFunctorT> ValIndexOf;

                                                                            
                                                                            
                                                     
  unsigned FreelistIdx = SMSNode::INVALID;
  unsigned NumFree = 0;

  unsigned sparseIndex(const ValueT &Val) const {
    assert(ValIndexOf(Val) < Universe &&
           "Invalid key in set. Did object mutate?");
    return ValIndexOf(Val);
  }
  unsigned sparseIndex(const SMSNode &N) const { return sparseIndex(N.Data); }

                                                                            
                                                                                
                                              
  bool isHead(const SMSNode &D) const {
    assert(D.isValid() && "Invalid node for head");
    return Dense[D.Prev].isTail();
  }

                                                                            
               
  bool isSingleton(const SMSNode &N) const {
    assert(N.isValid() && "Invalid node for singleton");
                                
    return &Dense[N.Prev] == &N;
  }

                                                                    
                                                     
  unsigned addValue(const ValueT& V, unsigned Prev, unsigned Next) {
    if (NumFree == 0) {
      Dense.push_back(SMSNode(V, Prev, Next));
      return Dense.size() - 1;
    }

                           
    unsigned Idx = FreelistIdx;
    unsigned NextFree = Dense[Idx].Next;
    assert(Dense[Idx].isTombstone() && "Non-tombstone free?");

    Dense[Idx] = SMSNode(V, Prev, Next);
    FreelistIdx = NextFree;
    --NumFree;
    return Idx;
  }

                                                                          
  void makeTombstone(unsigned Idx) {
    Dense[Idx].Prev = SMSNode::INVALID;
    Dense[Idx].Next = FreelistIdx;
    FreelistIdx = Idx;
    ++NumFree;
  }

public:
  using value_type = ValueT;
  using reference = ValueT &;
  using const_reference = const ValueT &;
  using pointer = ValueT *;
  using const_pointer = const ValueT *;
  using size_type = unsigned;

  SparseMultiSet() = default;
  SparseMultiSet(const SparseMultiSet &) = delete;
  SparseMultiSet &operator=(const SparseMultiSet &) = delete;
  ~SparseMultiSet() { free(Sparse); }

                                                                              
                                                                  
     
                                                                  
     
  void setUniverse(unsigned U) {
                                                                              
                                                                            
    assert(empty() && "Can only resize universe on an empty map");
                                                  
    if (U >= Universe/4 && U <= Universe)
      return;
    free(Sparse);
                                                                          
                                                                       
                                                      
    Sparse = static_cast<SparseT*>(safe_calloc(U, sizeof(SparseT)));
    Universe = U;
  }

                                                                             
          
  template <typename SMSPtrTy> class iterator_base {
    friend class SparseMultiSet;

  public:
    using iterator_category = std::bidirectional_iterator_tag;
    using value_type = ValueT;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type *;
    using reference = value_type &;

  private:
    SMSPtrTy SMS;
    unsigned Idx;
    unsigned SparseIdx;

    iterator_base(SMSPtrTy P, unsigned I, unsigned SI)
      : SMS(P), Idx(I), SparseIdx(SI) {}

                                                                 
    bool isEnd() const {
      if (Idx == SMSNode::INVALID)
        return true;

      assert(Idx < SMS->Dense.size() && "Out of range, non-INVALID Idx?");
      return false;
    }

                                                                           
    bool isKeyed() const { return SparseIdx < SMS->Universe; }

    unsigned Prev() const { return SMS->Dense[Idx].Prev; }
    unsigned Next() const { return SMS->Dense[Idx].Next; }

    void setPrev(unsigned P) { SMS->Dense[Idx].Prev = P; }
    void setNext(unsigned N) { SMS->Dense[Idx].Next = N; }

  public:
    reference operator*() const {
      assert(isKeyed() && SMS->sparseIndex(SMS->Dense[Idx].Data) == SparseIdx &&
             "Dereferencing iterator of invalid key or index");

      return SMS->Dense[Idx].Data;
    }
    pointer operator->() const { return &operator*(); }

                            
    bool operator==(const iterator_base &RHS) const {
                           
      if (SMS == RHS.SMS && Idx == RHS.Idx) {
        assert((isEnd() || SparseIdx == RHS.SparseIdx) &&
               "Same dense entry, but different keys?");
        return true;
      }

      return false;
    }

    bool operator!=(const iterator_base &RHS) const {
      return !operator==(RHS);
    }

                                         
    iterator_base &operator--() {                          
      assert(isKeyed() && "Decrementing an invalid iterator");
      assert((isEnd() || !SMS->isHead(SMS->Dense[Idx])) &&
             "Decrementing head of list");

                                                     
      if (isEnd())
        Idx = SMS->findIndex(SparseIdx).Prev();
      else
        Idx = Prev();

      return *this;
    }
    iterator_base &operator++() {                          
      assert(!isEnd() && isKeyed() && "Incrementing an invalid/end iterator");
      Idx = Next();
      return *this;
    }
    iterator_base operator--(int) {                 
      iterator_base I(*this);
      --*this;
      return I;
    }
    iterator_base operator++(int) {                 
      iterator_base I(*this);
      ++*this;
      return I;
    }
  };

  using iterator = iterator_base<SparseMultiSet *>;
  using const_iterator = iterator_base<const SparseMultiSet *>;

                      
  using RangePair = std::pair<iterator, iterator>;

                                                                                
                                                                    
  iterator end() { return iterator(this, SMSNode::INVALID, SMSNode::INVALID); }
  const_iterator end() const {
    return const_iterator(this, SMSNode::INVALID, SMSNode::INVALID);
  }

                                       
     
                                                 
     
  bool empty() const { return size() == 0; }

                                                
     
                                                                             
               
     
  size_type size() const {
    assert(NumFree <= Dense.size() && "Out-of-bounds free entries");
    return Dense.size() - NumFree;
  }

                                                                   
     
  void clear() {
                                                      
    Dense.clear();
    NumFree = 0;
    FreelistIdx = SMSNode::INVALID;
  }

                                   
     
                                         
                                                                      
     
  iterator findIndex(unsigned Idx) {
    assert(Idx < Universe && "Key out of range");
    const unsigned Stride = std::numeric_limits<SparseT>::max() + 1u;
    for (unsigned i = Sparse[Idx], e = Dense.size(); i < e; i += Stride) {
      const unsigned FoundIdx = sparseIndex(Dense[i]);
                                                                               
                         
      if (Idx == FoundIdx && Dense[i].isValid() && isHead(Dense[i]))
        return iterator(this, i, Idx);
                                                                      
      if (!Stride)
        break;
    }
    return end();
  }

                                 
     
                                       
                                                                      
     
  iterator find(const KeyT &Key) {
    return findIndex(KeyIndexOf(Key));
  }

  const_iterator find(const KeyT &Key) const {
    iterator I = const_cast<SparseMultiSet*>(this)->findIndex(KeyIndexOf(Key));
    return const_iterator(I.SMS, I.Idx, KeyIndexOf(Key));
  }

                                                                              
                                         
  size_type count(const KeyT &Key) const {
    unsigned Ret = 0;
    for (const_iterator It = find(Key); It != end(); ++It)
      ++Ret;

    return Ret;
  }

                                                                     
  bool contains(const KeyT &Key) const {
    return find(Key) != end();
  }

                                                                             
  iterator getHead(const KeyT &Key) { return find(Key); }
  iterator getTail(const KeyT &Key) {
    iterator I = find(Key);
    if (I != end())
      I = iterator(this, I.Prev(), KeyIndexOf(Key));
    return I;
  }

                                                                              
                                                                            
               
  RangePair equal_range(const KeyT &K) {
    iterator B = find(K);
    iterator E = iterator(this, SMSNode::INVALID, B.SparseIdx);
    return make_pair(B, E);
  }

                                                                              
                               
  iterator insert(const ValueT &Val) {
    unsigned Idx = sparseIndex(Val);
    iterator I = findIndex(Idx);

    unsigned NodeIdx = addValue(Val, SMSNode::INVALID, SMSNode::INVALID);

    if (I == end()) {
                              
      Sparse[Idx] = NodeIdx;
      Dense[NodeIdx].Prev = NodeIdx;
      return iterator(this, NodeIdx, Idx);
    }

                           
    unsigned HeadIdx = I.Idx;
    unsigned TailIdx = I.Prev();
    Dense[TailIdx].Next = NodeIdx;
    Dense[HeadIdx].Prev = NodeIdx;
    Dense[NodeIdx].Prev = TailIdx;

    return iterator(this, NodeIdx, Idx);
  }

                                                                
     
                                                                                
                                                                               
                                                                             
     
                                         
                      
                       
                             
              
                
     
                                                                           
                                                                                
              
     
                                        
                                                           
                              
                     
                 
                      
        
  iterator erase(iterator I) {
    assert(I.isKeyed() && !I.isEnd() && !Dense[I.Idx].isTombstone() &&
           "erasing invalid/end/tombstone iterator");

                                                                            
                                
    iterator NextI = unlink(Dense[I.Idx]);

                          
    makeTombstone(I.Idx);

    return NextI;
  }

                                                                 
                            
  void eraseAll(const KeyT &K) {
    for (iterator I = find(K); I != end();            )
      I = erase(I);
  }

private:
                                                                       
  iterator unlink(const SMSNode &N) {
    if (isSingleton(N)) {
                                      
      assert(N.Next == SMSNode::INVALID && "Singleton has next?");
      return iterator(this, SMSNode::INVALID, ValIndexOf(N.Data));
    }

    if (isHead(N)) {
                                                                      
      Sparse[sparseIndex(N)] = N.Next;
      Dense[N.Next].Prev = N.Prev;
      return iterator(this, N.Next, ValIndexOf(N.Data));
    }

    if (N.isTail()) {
                                                                  
      findIndex(sparseIndex(N)).setPrev(N.Prev);
      Dense[N.Prev].Next = N.Next;

                                                          
      iterator I(this, N.Prev, ValIndexOf(N.Data));
      return ++I;
    }

                              
    Dense[N.Next].Prev = N.Prev;
    Dense[N.Prev].Next = N.Next;
    return iterator(this, N.Next, ValIndexOf(N.Data));
  }
};

}                      

#endif                             

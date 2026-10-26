//===- llvm/ADT/SmallPtrSet.h - 'Normally small' pointer set ----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the SmallPtrSet class.  See the doxygen comment for
// SmallPtrSetImplBase for more details on the algorithm used.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_SMALLPTRSET_H
#define LLVM_ADT_SMALLPTRSET_H

#include "llvh/ADT/EpochTracker.h"
#include "llvh/Support/Compiler.h"
#include "llvh/Support/ReverseIteration.h"
#include "llvh/Support/type_traits.h"
#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <iterator>
#include <utility>

namespace llvh {

                                                                      
                                                                                
                                     
   
                                                                            
                                                                               
                                                                              
                                                                               
                                                                               
                                                                               
                                                      
   
                                                                                
                                                                               
                                                                            
                                                                                
                                                           
   
class SmallPtrSetImplBase : public DebugEpochBase {
  friend class SmallPtrSetIteratorImpl;

protected:
                                                                               
  const void **SmallArray;
                                                                             
                                      
  const void **CurArray;
                                                                           
  unsigned CurArraySize;

                                                                             
                                                                                
                       
  unsigned NumNonEmpty;
                                       
  unsigned NumTombstones;

                                                      
  SmallPtrSetImplBase(const void **SmallStorage,
                      const SmallPtrSetImplBase &that);
  SmallPtrSetImplBase(const void **SmallStorage, unsigned SmallSize,
                      SmallPtrSetImplBase &&that);

  explicit SmallPtrSetImplBase(const void **SmallStorage, unsigned SmallSize)
      : SmallArray(SmallStorage), CurArray(SmallStorage),
        CurArraySize(SmallSize), NumNonEmpty(0), NumTombstones(0) {
    assert(SmallSize && (SmallSize & (SmallSize-1)) == 0 &&
           "Initial size must be a power of two!");
  }

  ~SmallPtrSetImplBase() {
    if (!isSmall())
      free(CurArray);
  }

public:
  using size_type = unsigned;

  SmallPtrSetImplBase &operator=(const SmallPtrSetImplBase &) = delete;

  LLVM_NODISCARD bool empty() const { return size() == 0; }
  size_type size() const { return NumNonEmpty - NumTombstones; }

  void clear() {
    incrementEpoch();
                                                                              
                        
    if (!isSmall()) {
      if (size() * 4 < CurArraySize && CurArraySize > 32)
        return shrink_and_clear();
                                           
      memset(CurArray, -1, CurArraySize * sizeof(void *));
    }

    NumNonEmpty = 0;
    NumTombstones = 0;
  }

protected:
  static void *getTombstoneMarker() { return reinterpret_cast<void*>(-2); }

  static void *getEmptyMarker() {
                                                                            
                                                         
    return reinterpret_cast<void*>(-1);
  }

  const void **EndPointer() const {
    return isSmall() ? CurArray + NumNonEmpty : CurArray + CurArraySize;
  }

                                                                                
                                                                            
                                                                          
  std::pair<const void *const *, bool> insert_imp(const void *Ptr) {
    if (isSmall()) {
                                                  
      const void **LastTombstone = nullptr;
      for (const void **APtr = SmallArray, **E = SmallArray + NumNonEmpty;
           APtr != E; ++APtr) {
        const void *Value = *APtr;
        if (Value == Ptr)
          return std::make_pair(APtr, false);
        if (Value == getTombstoneMarker())
          LastTombstone = APtr;
      }

                                          
      if (LastTombstone != nullptr) {
        *LastTombstone = Ptr;
        --NumTombstones;
        incrementEpoch();
        return std::make_pair(LastTombstone, true);
      }

                                                                   
      if (NumNonEmpty < CurArraySize) {
        SmallArray[NumNonEmpty++] = Ptr;
        incrementEpoch();
        return std::make_pair(SmallArray + (NumNonEmpty - 1), true);
      }
                                                               
    }
    return insert_imp_big(Ptr);
  }

                                                                          
                                                                             
                                                                               
         
  bool erase_imp(const void * Ptr) {
    const void *const *P = find_imp(Ptr);
    if (P == EndPointer())
      return false;

    const void **Loc = const_cast<const void **>(P);
    assert(*Loc == Ptr && "broken find!");
    *Loc = getTombstoneMarker();
    NumTombstones++;
    return true;
  }

                                                                              
                                                                             
                            
  const void *const * find_imp(const void * Ptr) const {
    if (isSmall()) {
                                    
      for (const void *const *APtr = SmallArray,
                      *const *E = SmallArray + NumNonEmpty; APtr != E; ++APtr)
        if (*APtr == Ptr)
          return APtr;
      return EndPointer();
    }

                    
    auto *Bucket = FindBucketFor(Ptr);
    if (*Bucket == Ptr)
      return Bucket;
    return EndPointer();
  }

private:
  bool isSmall() const { return CurArray == SmallArray; }

  std::pair<const void *const *, bool> insert_imp_big(const void *Ptr);

  const void * const *FindBucketFor(const void *Ptr) const;
  void shrink_and_clear();

                                                                              
  void Grow(unsigned NewSize);

protected:
                                            
                                                                        
  void swap(SmallPtrSetImplBase &RHS);

  void CopyFrom(const SmallPtrSetImplBase &RHS);
  void MoveFrom(unsigned SmallSize, SmallPtrSetImplBase &&RHS);

private:
                                                     
  void MoveHelper(unsigned SmallSize, SmallPtrSetImplBase &&RHS);
                                                     
  void CopyHelper(const SmallPtrSetImplBase &RHS);
};

                                                                              
                                     
class SmallPtrSetIteratorImpl {
protected:
  const void *const *Bucket;
  const void *const *End;

public:
  explicit SmallPtrSetIteratorImpl(const void *const *BP, const void*const *E)
    : Bucket(BP), End(E) {
    if (shouldReverseIterate()) {
      RetreatIfNotValid();
      return;
    }
    AdvanceIfNotValid();
  }

  bool operator==(const SmallPtrSetIteratorImpl &RHS) const {
    return Bucket == RHS.Bucket;
  }
  bool operator!=(const SmallPtrSetIteratorImpl &RHS) const {
    return Bucket != RHS.Bucket;
  }

protected:
                                                                                
                                                                              
            
  void AdvanceIfNotValid() {
    assert(Bucket <= End);
    while (Bucket != End &&
           (*Bucket == SmallPtrSetImplBase::getEmptyMarker() ||
            *Bucket == SmallPtrSetImplBase::getTombstoneMarker()))
      ++Bucket;
  }
  void RetreatIfNotValid() {
    assert(Bucket >= End);
    while (Bucket != End &&
           (Bucket[-1] == SmallPtrSetImplBase::getEmptyMarker() ||
            Bucket[-1] == SmallPtrSetImplBase::getTombstoneMarker())) {
      --Bucket;
    }
  }
};

                                                                           
template <typename PtrTy>
class SmallPtrSetIterator : public SmallPtrSetIteratorImpl,
                            DebugEpochBase::HandleBase {
  using PtrTraits = PointerLikeTypeTraits<PtrTy>;

public:
  using value_type = PtrTy;
  using reference = PtrTy;
  using pointer = PtrTy;
  using difference_type = std::ptrdiff_t;
  using iterator_category = std::forward_iterator_tag;

  explicit SmallPtrSetIterator(const void *const *BP, const void *const *E,
                               const DebugEpochBase &Epoch)
      : SmallPtrSetIteratorImpl(BP, E), DebugEpochBase::HandleBase(&Epoch) {}

                                        

  const PtrTy operator*() const {
    assert(isHandleInSync() && "invalid iterator access!");
    if (shouldReverseIterate()) {
      assert(Bucket > End);
      return PtrTraits::getFromVoidPointer(const_cast<void *>(Bucket[-1]));
    }
    assert(Bucket < End);
    return PtrTraits::getFromVoidPointer(const_cast<void*>(*Bucket));
  }

  inline SmallPtrSetIterator& operator++() {                         
    assert(isHandleInSync() && "invalid iterator access!");
    if (shouldReverseIterate()) {
      --Bucket;
      RetreatIfNotValid();
      return *this;
    }
    ++Bucket;
    AdvanceIfNotValid();
    return *this;
  }

  SmallPtrSetIterator operator++(int) {                        
    SmallPtrSetIterator tmp = *this;
    ++*this;
    return tmp;
  }
};

                                                                                
                                                                       
template<unsigned N>
struct RoundUpToPowerOfTwo;

                                                                              
                                                          
template<unsigned N, bool isPowerTwo>
struct RoundUpToPowerOfTwoH {
  enum { Val = N };
};
template<unsigned N>
struct RoundUpToPowerOfTwoH<N, false> {
  enum {
                                                                                
                                                                                
    Val = RoundUpToPowerOfTwo<(N|(N-1)) + 1>::Val
  };
};

template<unsigned N>
struct RoundUpToPowerOfTwo {
  enum { Val = RoundUpToPowerOfTwoH<N, (N&(N-1)) == 0>::Val };
};

                                                                
                                                             
   
                                                                               
                                                                        
template <typename PtrType>
class SmallPtrSetImpl : public SmallPtrSetImplBase {
  using ConstPtrType = typename add_const_past_pointer<PtrType>::type;
  using PtrTraits = PointerLikeTypeTraits<PtrType>;
  using ConstPtrTraits = PointerLikeTypeTraits<ConstPtrType>;

protected:
                                           
  SmallPtrSetImpl(const void **SmallStorage, const SmallPtrSetImpl &that)
      : SmallPtrSetImplBase(SmallStorage, that) {}
  SmallPtrSetImpl(const void **SmallStorage, unsigned SmallSize,
                  SmallPtrSetImpl &&that)
      : SmallPtrSetImplBase(SmallStorage, SmallSize, std::move(that)) {}
  explicit SmallPtrSetImpl(const void **SmallStorage, unsigned SmallSize)
      : SmallPtrSetImplBase(SmallStorage, SmallSize) {}

public:
  using iterator = SmallPtrSetIterator<PtrType>;
  using const_iterator = SmallPtrSetIterator<PtrType>;
  using key_type = ConstPtrType;
  using value_type = PtrType;

  SmallPtrSetImpl(const SmallPtrSetImpl &) = delete;

                                                                              
                                                                             
                                                                             
                               
  std::pair<iterator, bool> insert(PtrType Ptr) {
    auto p = insert_imp(PtrTraits::getAsVoidPointer(Ptr));
    return std::make_pair(makeIterator(p.first), p.second);
  }

                                                                             
                                   
  bool erase(PtrType Ptr) {
    return erase_imp(PtrTraits::getAsVoidPointer(Ptr));
  }
                                                                           
  size_type count(ConstPtrType Ptr) const { return find(Ptr) != end() ? 1 : 0; }
  iterator find(ConstPtrType Ptr) const {
    return makeIterator(find_imp(ConstPtrTraits::getAsVoidPointer(Ptr)));
  }

  template <typename IterT>
  void insert(IterT I, IterT E) {
    for (; I != E; ++I)
      insert(*I);
  }

  void insert(std::initializer_list<PtrType> IL) {
    insert(IL.begin(), IL.end());
  }

  iterator begin() const {
    if (shouldReverseIterate())
      return makeIterator(EndPointer() - 1);
    return makeIterator(CurArray);
  }
  iterator end() const { return makeIterator(EndPointer()); }

private:
                                                                              
  iterator makeIterator(const void *const *P) const {
    if (shouldReverseIterate())
      return iterator(P == EndPointer() ? CurArray : P + 1, CurArray, *this);
    return iterator(P, EndPointer(), *this);
  }
};

                                                                            
                                                                                
                                                                             
                                                     
template<class PtrType, unsigned SmallSize>
class SmallPtrSet : public SmallPtrSetImpl<PtrType> {
                                                                            
                                                                            
                                                               
  static_assert(SmallSize <= 32, "SmallSize should be small");

  using BaseT = SmallPtrSetImpl<PtrType>;

                                                                 
  enum { SmallSizePowTwo = RoundUpToPowerOfTwo<SmallSize>::Val };
                                                             
  const void *SmallStorage[SmallSizePowTwo];

public:
  SmallPtrSet() : BaseT(SmallStorage, SmallSizePowTwo) {}
  SmallPtrSet(const SmallPtrSet &that) : BaseT(SmallStorage, that) {}
  SmallPtrSet(SmallPtrSet &&that)
      : BaseT(SmallStorage, SmallSizePowTwo, std::move(that)) {}

  template<typename It>
  SmallPtrSet(It I, It E) : BaseT(SmallStorage, SmallSizePowTwo) {
    this->insert(I, E);
  }

  SmallPtrSet(std::initializer_list<PtrType> IL)
      : BaseT(SmallStorage, SmallSizePowTwo) {
    this->insert(IL.begin(), IL.end());
  }

  SmallPtrSet<PtrType, SmallSize> &
  operator=(const SmallPtrSet<PtrType, SmallSize> &RHS) {
    if (&RHS != this)
      this->CopyFrom(RHS);
    return *this;
  }

  SmallPtrSet<PtrType, SmallSize> &
  operator=(SmallPtrSet<PtrType, SmallSize> &&RHS) {
    if (&RHS != this)
      this->MoveFrom(SmallSizePowTwo, std::move(RHS));
    return *this;
  }

  SmallPtrSet<PtrType, SmallSize> &
  operator=(std::initializer_list<PtrType> IL) {
    this->clear();
    this->insert(IL.begin(), IL.end());
    return *this;
  }

                                            
  void swap(SmallPtrSet<PtrType, SmallSize> &RHS) {
    SmallPtrSetImplBase::swap(RHS);
  }
};

}                      

namespace std {

                                                       
  template<class T, unsigned N>
  inline void swap(llvh::SmallPtrSet<T, N> &LHS, llvh::SmallPtrSet<T, N> &RHS) {
    LHS.swap(RHS);
  }

}                     

#endif                          

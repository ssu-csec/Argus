//===- llvm/ADT/DenseMap.h - Dense probed hash table ------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the DenseMap class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_DENSEMAP_H
#define LLVM_ADT_DENSEMAP_H

#include "llvh/ADT/DenseMapInfo.h"
#include "llvh/ADT/EpochTracker.h"
#include "llvh/Support/AlignOf.h"
#include "llvh/Support/Compiler.h"
#include "llvh/Support/MathExtras.h"
#include "llvh/Support/ReverseIteration.h"
#include "llvh/Support/type_traits.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <iterator>
#include <new>
#include <type_traits>
#include <utility>

#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif

namespace llvh {

namespace detail {

                                                                             
                                                
template <typename KeyT, typename ValueT>
struct DenseMapPair : public std::pair<KeyT, ValueT> {
  KeyT &getFirst() { return std::pair<KeyT, ValueT>::first; }
  const KeyT &getFirst() const { return std::pair<KeyT, ValueT>::first; }
  ValueT &getSecond() { return std::pair<KeyT, ValueT>::second; }
  const ValueT &getSecond() const { return std::pair<KeyT, ValueT>::second; }
};

}                        

template <
    typename KeyT, typename ValueT, typename KeyInfoT = DenseMapInfo<KeyT>,
    typename Bucket = detail::DenseMapPair<KeyT, ValueT>, bool IsConst = false>
class DenseMapIterator;

template <typename DerivedT, typename KeyT, typename ValueT, typename KeyInfoT,
          typename BucketT>
class DenseMapBase : public DebugEpochBase {
  template <typename T>
  using const_arg_type_t = typename const_pointer_or_const_ref<T>::type;

public:
  using size_type = unsigned;
  using key_type = KeyT;
  using mapped_type = ValueT;
  using value_type = BucketT;

  using iterator = DenseMapIterator<KeyT, ValueT, KeyInfoT, BucketT>;
  using const_iterator =
      DenseMapIterator<KeyT, ValueT, KeyInfoT, BucketT, true>;

  inline iterator begin() {
                                                                             
                     
    if (empty())
      return end();
    if (shouldReverseIterate<KeyT>())
      return makeIterator(getBucketsEnd() - 1, getBuckets(), *this);
    return makeIterator(getBuckets(), getBucketsEnd(), *this);
  }
  inline iterator end() {
    return makeIterator(getBucketsEnd(), getBucketsEnd(), *this, true);
  }
  inline const_iterator begin() const {
    if (empty())
      return end();
    if (shouldReverseIterate<KeyT>())
      return makeConstIterator(getBucketsEnd() - 1, getBuckets(), *this);
    return makeConstIterator(getBuckets(), getBucketsEnd(), *this);
  }
  inline const_iterator end() const {
    return makeConstIterator(getBucketsEnd(), getBucketsEnd(), *this, true);
  }

  LLVM_NODISCARD bool empty() const {
    return getNumEntries() == 0;
  }
  unsigned size() const { return getNumEntries(); }

                                                                           
                            
  void reserve(size_type NumEntries) {
    auto NumBuckets = getMinBucketToReserveForEntries(NumEntries);
    incrementEpoch();
    if (NumBuckets > getNumBuckets())
      grow(NumBuckets);
  }

  void clear() {
    incrementEpoch();
    if (getNumEntries() == 0 && getNumTombstones() == 0) return;

                                                                              
                        
    if (getNumEntries() * 4 < getNumBuckets() && getNumBuckets() > 64) {
      shrink_and_clear();
      return;
    }

    const KeyT EmptyKey = getEmptyKey(), TombstoneKey = getTombstoneKey();
    if (isPodLike<KeyT>::value && isPodLike<ValueT>::value) {
                                                         
      for (BucketT *P = getBuckets(), *E = getBucketsEnd(); P != E; ++P)
        P->getFirst() = EmptyKey;
    } else {
      unsigned NumEntries = getNumEntries();
      for (BucketT *P = getBuckets(), *E = getBucketsEnd(); P != E; ++P) {
        if (!KeyInfoT::isEqual(P->getFirst(), EmptyKey)) {
          if (!KeyInfoT::isEqual(P->getFirst(), TombstoneKey)) {
            P->getSecond().~ValueT();
            --NumEntries;
          }
          P->getFirst() = EmptyKey;
        }
      }
      assert(NumEntries == 0 && "Node count imbalance!");
                                                                       
      (void)NumEntries;
    }
    setNumEntries(0);
    setNumTombstones(0);
  }

                                                               
  size_type count(const_arg_type_t<KeyT> Val) const {
    const BucketT *TheBucket;
    return LookupBucketFor(Val, TheBucket) ? 1 : 0;
  }

  iterator find(const_arg_type_t<KeyT> Val) {
    BucketT *TheBucket;
    if (LookupBucketFor(Val, TheBucket))
      return makeIterator(TheBucket, getBucketsEnd(), *this, true);
    return end();
  }
  const_iterator find(const_arg_type_t<KeyT> Val) const {
    const BucketT *TheBucket;
    if (LookupBucketFor(Val, TheBucket))
      return makeConstIterator(TheBucket, getBucketsEnd(), *this, true);
    return end();
  }

                                                                        
                               
                                                           
                                                                         
                
  template<class LookupKeyT>
  iterator find_as(const LookupKeyT &Val) {
    BucketT *TheBucket;
    if (LookupBucketFor(Val, TheBucket))
      return makeIterator(TheBucket, getBucketsEnd(), *this, true);
    return end();
  }
  template<class LookupKeyT>
  const_iterator find_as(const LookupKeyT &Val) const {
    const BucketT *TheBucket;
    if (LookupBucketFor(Val, TheBucket))
      return makeConstIterator(TheBucket, getBucketsEnd(), *this, true);
    return end();
  }

                                                                   
                                                
  ValueT lookup(const_arg_type_t<KeyT> Val) const {
    const BucketT *TheBucket;
    if (LookupBucketFor(Val, TheBucket))
      return TheBucket->getSecond();
    return ValueT();
  }

                                                                             
                                                                              
           
  std::pair<iterator, bool> insert(const std::pair<KeyT, ValueT> &KV) {
    return try_emplace(KV.first, KV.second);
  }

                                                                             
                                                                              
           
  std::pair<iterator, bool> insert(std::pair<KeyT, ValueT> &&KV) {
    return try_emplace(std::move(KV.first), std::move(KV.second));
  }

                                                                             
                                                                              
                     
  template <typename... Ts>
  std::pair<iterator, bool> try_emplace(KeyT &&Key, Ts &&... Args) {
    BucketT *TheBucket;
    if (LookupBucketFor(Key, TheBucket))
      return std::make_pair(
               makeIterator(TheBucket, getBucketsEnd(), *this, true),
               false);                   

                                         
    TheBucket =
        InsertIntoBucket(TheBucket, std::move(Key), std::forward<Ts>(Args)...);
    return std::make_pair(
             makeIterator(TheBucket, getBucketsEnd(), *this, true),
             true);
  }

                                                                             
                                                                              
                     
  template <typename... Ts>
  std::pair<iterator, bool> try_emplace(const KeyT &Key, Ts &&... Args) {
    BucketT *TheBucket;
    if (LookupBucketFor(Key, TheBucket))
      return std::make_pair(
               makeIterator(TheBucket, getBucketsEnd(), *this, true),
               false);                   

                                         
    TheBucket = InsertIntoBucket(TheBucket, Key, std::forward<Ts>(Args)...);
    return std::make_pair(
             makeIterator(TheBucket, getBucketsEnd(), *this, true),
             true);
  }

                                                                          
                               
                                                           
                                                                         
                
  template <typename LookupKeyT>
  std::pair<iterator, bool> insert_as(std::pair<KeyT, ValueT> &&KV,
                                      const LookupKeyT &Val) {
    BucketT *TheBucket;
    if (LookupBucketFor(Val, TheBucket))
      return std::make_pair(
               makeIterator(TheBucket, getBucketsEnd(), *this, true),
               false);                   

                                         
    TheBucket = InsertIntoBucketWithLookup(TheBucket, std::move(KV.first),
                                           std::move(KV.second), Val);
    return std::make_pair(
             makeIterator(TheBucket, getBucketsEnd(), *this, true),
             true);
  }

                                        
  template<typename InputIt>
  void insert(InputIt I, InputIt E) {
    for (; I != E; ++I)
      insert(*I);
  }

  bool erase(const KeyT &Val) {
    BucketT *TheBucket;
    if (!LookupBucketFor(Val, TheBucket))
      return false;               

    TheBucket->getSecond().~ValueT();
    TheBucket->getFirst() = getTombstoneKey();
    decrementNumEntries();
    incrementNumTombstones();
    return true;
  }
  void erase(iterator I) {
    BucketT *TheBucket = &*I;
    TheBucket->getSecond().~ValueT();
    TheBucket->getFirst() = getTombstoneKey();
    decrementNumEntries();
    incrementNumTombstones();
  }

  value_type& FindAndConstruct(const KeyT &Key) {
    BucketT *TheBucket;
    if (LookupBucketFor(Key, TheBucket))
      return *TheBucket;

    return *InsertIntoBucket(TheBucket, Key);
  }

  ValueT &operator[](const KeyT &Key) {
    return FindAndConstruct(Key).second;
  }

  value_type& FindAndConstruct(KeyT &&Key) {
    BucketT *TheBucket;
    if (LookupBucketFor(Key, TheBucket))
      return *TheBucket;

    return *InsertIntoBucket(TheBucket, std::move(Key));
  }

  ValueT &operator[](KeyT &&Key) {
    return FindAndConstruct(std::move(Key)).second;
  }

                                                                             
                                                                             
                             
  bool isPointerIntoBucketsArray(const void *Ptr) const {
    return Ptr >= getBuckets() && Ptr < getBucketsEnd();
  }

                                                                              
                                                                          
                                                                       
  const void *getPointerIntoBucketsArray() const { return getBuckets(); }

protected:
  DenseMapBase() = default;

  void destroyAll() {
    if (getNumBuckets() == 0)                  
      return;

    const KeyT EmptyKey = getEmptyKey(), TombstoneKey = getTombstoneKey();
    for (BucketT *P = getBuckets(), *E = getBucketsEnd(); P != E; ++P) {
      if (!KeyInfoT::isEqual(P->getFirst(), EmptyKey) &&
          !KeyInfoT::isEqual(P->getFirst(), TombstoneKey))
        P->getSecond().~ValueT();
      P->getFirst().~KeyT();
    }
  }

  void initEmpty() {
    setNumEntries(0);
    setNumTombstones(0);

    assert((getNumBuckets() & (getNumBuckets()-1)) == 0 &&
           "# initial buckets must be a power of two!");
    const KeyT EmptyKey = getEmptyKey();
    for (BucketT *B = getBuckets(), *E = getBucketsEnd(); B != E; ++B)
      ::new (&B->getFirst()) KeyT(EmptyKey);
  }

                                                                               
                                                       
  unsigned getMinBucketToReserveForEntries(unsigned NumEntries) {
                                                    
    if (NumEntries == 0)
      return 0;
                                                     
                                                              
    return NextPowerOf2(NumEntries * 4 / 3 + 1);
  }

  void moveFromOldBuckets(BucketT *OldBucketsBegin, BucketT *OldBucketsEnd) {
    initEmpty();

                                   
    const KeyT EmptyKey = getEmptyKey();
    const KeyT TombstoneKey = getTombstoneKey();
    for (BucketT *B = OldBucketsBegin, *E = OldBucketsEnd; B != E; ++B) {
      if (!KeyInfoT::isEqual(B->getFirst(), EmptyKey) &&
          !KeyInfoT::isEqual(B->getFirst(), TombstoneKey)) {
                                                   
        BucketT *DestBucket;
        bool FoundVal = LookupBucketFor(B->getFirst(), DestBucket);
        (void)FoundVal;                    
        assert(!FoundVal && "Key already in new map?");
        DestBucket->getFirst() = std::move(B->getFirst());
        ::new (&DestBucket->getSecond()) ValueT(std::move(B->getSecond()));
        incrementNumEntries();

                          
        B->getSecond().~ValueT();
      }
      B->getFirst().~KeyT();
    }
  }

  template <typename OtherBaseT>
  void copyFrom(
      const DenseMapBase<OtherBaseT, KeyT, ValueT, KeyInfoT, BucketT> &other) {
    assert(&other != this);
    assert(getNumBuckets() == other.getNumBuckets());

    setNumEntries(other.getNumEntries());
    setNumTombstones(other.getNumTombstones());

    if (isPodLike<KeyT>::value && isPodLike<ValueT>::value)
      memcpy(reinterpret_cast<void *>(getBuckets()), other.getBuckets(),
             getNumBuckets() * sizeof(BucketT));
    else
      for (size_t i = 0; i < getNumBuckets(); ++i) {
        ::new (&getBuckets()[i].getFirst())
            KeyT(other.getBuckets()[i].getFirst());
        if (!KeyInfoT::isEqual(getBuckets()[i].getFirst(), getEmptyKey()) &&
            !KeyInfoT::isEqual(getBuckets()[i].getFirst(), getTombstoneKey()))
          ::new (&getBuckets()[i].getSecond())
              ValueT(other.getBuckets()[i].getSecond());
      }
  }

  static unsigned getHashValue(const KeyT &Val) {
    return KeyInfoT::getHashValue(Val);
  }

  template<typename LookupKeyT>
  static unsigned getHashValue(const LookupKeyT &Val) {
    return KeyInfoT::getHashValue(Val);
  }

  static const KeyT getEmptyKey() {
    static_assert(std::is_base_of<DenseMapBase, DerivedT>::value,
                  "Must pass the derived type to this template!");
    return KeyInfoT::getEmptyKey();
  }

  static const KeyT getTombstoneKey() {
    return KeyInfoT::getTombstoneKey();
  }

private:
  iterator makeIterator(BucketT *P, BucketT *E,
                        DebugEpochBase &Epoch,
                        bool NoAdvance=false) {
    if (shouldReverseIterate<KeyT>()) {
      BucketT *B = P == getBucketsEnd() ? getBuckets() : P + 1;
      return iterator(B, E, Epoch, NoAdvance);
    }
    return iterator(P, E, Epoch, NoAdvance);
  }

  const_iterator makeConstIterator(const BucketT *P, const BucketT *E,
                                   const DebugEpochBase &Epoch,
                                   const bool NoAdvance=false) const {
    if (shouldReverseIterate<KeyT>()) {
      const BucketT *B = P == getBucketsEnd() ? getBuckets() : P + 1;
      return const_iterator(B, E, Epoch, NoAdvance);
    }
    return const_iterator(P, E, Epoch, NoAdvance);
  }

  unsigned getNumEntries() const {
    return static_cast<const DerivedT *>(this)->getNumEntries();
  }

  void setNumEntries(unsigned Num) {
    static_cast<DerivedT *>(this)->setNumEntries(Num);
  }

  void incrementNumEntries() {
    setNumEntries(getNumEntries() + 1);
  }

  void decrementNumEntries() {
    setNumEntries(getNumEntries() - 1);
  }

  unsigned getNumTombstones() const {
    return static_cast<const DerivedT *>(this)->getNumTombstones();
  }

  void setNumTombstones(unsigned Num) {
    static_cast<DerivedT *>(this)->setNumTombstones(Num);
  }

  void incrementNumTombstones() {
    setNumTombstones(getNumTombstones() + 1);
  }

  void decrementNumTombstones() {
    setNumTombstones(getNumTombstones() - 1);
  }

  const BucketT *getBuckets() const {
    return static_cast<const DerivedT *>(this)->getBuckets();
  }

  BucketT *getBuckets() {
    return static_cast<DerivedT *>(this)->getBuckets();
  }

  unsigned getNumBuckets() const {
    return static_cast<const DerivedT *>(this)->getNumBuckets();
  }

  BucketT *getBucketsEnd() {
    return getBuckets() + getNumBuckets();
  }

  const BucketT *getBucketsEnd() const {
    return getBuckets() + getNumBuckets();
  }

  void grow(unsigned AtLeast) {
    static_cast<DerivedT *>(this)->grow(AtLeast);
  }

  void shrink_and_clear() {
    static_cast<DerivedT *>(this)->shrink_and_clear();
  }

  template <typename KeyArg, typename... ValueArgs>
  BucketT *InsertIntoBucket(BucketT *TheBucket, KeyArg &&Key,
                            ValueArgs &&... Values) {
    TheBucket = InsertIntoBucketImpl(Key, Key, TheBucket);

    TheBucket->getFirst() = std::forward<KeyArg>(Key);
    ::new (&TheBucket->getSecond()) ValueT(std::forward<ValueArgs>(Values)...);
    return TheBucket;
  }

  template <typename LookupKeyT>
  BucketT *InsertIntoBucketWithLookup(BucketT *TheBucket, KeyT &&Key,
                                      ValueT &&Value, LookupKeyT &Lookup) {
    TheBucket = InsertIntoBucketImpl(Key, Lookup, TheBucket);

    TheBucket->getFirst() = std::move(Key);
    ::new (&TheBucket->getSecond()) ValueT(std::move(Value));
    return TheBucket;
  }

  template <typename LookupKeyT>
  BucketT *InsertIntoBucketImpl(const KeyT &Key, const LookupKeyT &Lookup,
                                BucketT *TheBucket) {
    incrementEpoch();

                                                                              
                                                                            
                      
      
                                                                              
                                                                             
                                                                             
                                                                             
                                        
    unsigned NewNumEntries = getNumEntries() + 1;
    unsigned NumBuckets = getNumBuckets();
    if (LLVM_UNLIKELY(NewNumEntries * 4 >= NumBuckets * 3)) {
      this->grow(NumBuckets * 2);
      LookupBucketFor(Lookup, TheBucket);
      NumBuckets = getNumBuckets();
    } else if (LLVM_UNLIKELY(NumBuckets-(NewNumEntries+getNumTombstones()) <=
                             NumBuckets/8)) {
      this->grow(NumBuckets);
      LookupBucketFor(Lookup, TheBucket);
    }
    assert(TheBucket);

                                                                             
                                                                        
    incrementNumEntries();

                                                         
    const KeyT EmptyKey = getEmptyKey();
    if (!KeyInfoT::isEqual(TheBucket->getFirst(), EmptyKey))
      decrementNumTombstones();

    return TheBucket;
  }

                                                                              
                                                                            
                                                                               
                    
  template<typename LookupKeyT>
  bool LookupBucketFor(const LookupKeyT &Val,
                       const BucketT *&FoundBucket) const {
    const BucketT *BucketsPtr = getBuckets();
    const unsigned NumBuckets = getNumBuckets();

    if (NumBuckets == 0) {
      FoundBucket = nullptr;
      return false;
    }

                                                                                
    const BucketT *FoundTombstone = nullptr;
    const KeyT EmptyKey = getEmptyKey();
    const KeyT TombstoneKey = getTombstoneKey();
    assert(!KeyInfoT::isEqual(Val, EmptyKey) &&
           !KeyInfoT::isEqual(Val, TombstoneKey) &&
           "Empty/Tombstone value shouldn't be inserted into map!");

    unsigned BucketNo = getHashValue(Val) & (NumBuckets-1);
    unsigned ProbeAmt = 1;
    while (true) {
      const BucketT *ThisBucket = BucketsPtr + BucketNo;
                                               
      if (LLVM_LIKELY(KeyInfoT::isEqual(Val, ThisBucket->getFirst()))) {
        FoundBucket = ThisBucket;
        return true;
      }

                                                                       
                                                
      if (LLVM_LIKELY(KeyInfoT::isEqual(ThisBucket->getFirst(), EmptyKey))) {
                                                                              
                                                       
        FoundBucket = FoundTombstone ? FoundTombstone : ThisBucket;
        return false;
      }

                                                                                
                                                                            
      if (KeyInfoT::isEqual(ThisBucket->getFirst(), TombstoneKey) &&
          !FoundTombstone)
        FoundTombstone = ThisBucket;                                        

                                                                            
                 
      BucketNo += ProbeAmt++;
      BucketNo &= (NumBuckets-1);
    }
  }

  template <typename LookupKeyT>
  bool LookupBucketFor(const LookupKeyT &Val, BucketT *&FoundBucket) {
    const BucketT *ConstFoundBucket;
    bool Result = const_cast<const DenseMapBase *>(this)
      ->LookupBucketFor(Val, ConstFoundBucket);
    FoundBucket = const_cast<BucketT *>(ConstFoundBucket);
    return Result;
  }

public:
                                                               
                                                   
                                                                            
                       
  size_t getMemorySize() const {
    return getNumBuckets() * sizeof(BucketT);
  }
};

template <typename KeyT, typename ValueT,
          typename KeyInfoT = DenseMapInfo<KeyT>,
          typename BucketT = detail::DenseMapPair<KeyT, ValueT>>
class DenseMap : public DenseMapBase<DenseMap<KeyT, ValueT, KeyInfoT, BucketT>,
                                     KeyT, ValueT, KeyInfoT, BucketT> {
  friend class DenseMapBase<DenseMap, KeyT, ValueT, KeyInfoT, BucketT>;

                                                                      
                                     
  using BaseT = DenseMapBase<DenseMap, KeyT, ValueT, KeyInfoT, BucketT>;

  BucketT *Buckets;
  unsigned NumEntries;
  unsigned NumTombstones;
  unsigned NumBuckets;

public:
                                                                             
                                                                       
  explicit DenseMap(unsigned InitialReserve = 0) { init(InitialReserve); }

  DenseMap(const DenseMap &other) : BaseT() {
    init(0);
    copyFrom(other);
  }

  DenseMap(DenseMap &&other) : BaseT() {
    init(0);
    swap(other);
  }

  template<typename InputIt>
  DenseMap(const InputIt &I, const InputIt &E) {
    init(std::distance(I, E));
    this->insert(I, E);
  }

  ~DenseMap() {
    this->destroyAll();
    operator delete(Buckets);
  }

  void swap(DenseMap& RHS) {
    this->incrementEpoch();
    RHS.incrementEpoch();
    std::swap(Buckets, RHS.Buckets);
    std::swap(NumEntries, RHS.NumEntries);
    std::swap(NumTombstones, RHS.NumTombstones);
    std::swap(NumBuckets, RHS.NumBuckets);
  }

  DenseMap& operator=(const DenseMap& other) {
    if (&other != this)
      copyFrom(other);
    return *this;
  }

  DenseMap& operator=(DenseMap &&other) {
    this->destroyAll();
    operator delete(Buckets);
    init(0);
    swap(other);
    return *this;
  }

  void copyFrom(const DenseMap& other) {
    this->destroyAll();
    operator delete(Buckets);
    if (allocateBuckets(other.NumBuckets)) {
      this->BaseT::copyFrom(other);
    } else {
      NumEntries = 0;
      NumTombstones = 0;
    }
  }

  void init(unsigned InitNumEntries) {
    auto InitBuckets = BaseT::getMinBucketToReserveForEntries(InitNumEntries);
    if (allocateBuckets(InitBuckets)) {
      this->BaseT::initEmpty();
    } else {
      NumEntries = 0;
      NumTombstones = 0;
    }
  }

  void grow(unsigned AtLeast) {
    unsigned OldNumBuckets = NumBuckets;
    BucketT *OldBuckets = Buckets;

    allocateBuckets(std::max<unsigned>(64, static_cast<unsigned>(NextPowerOf2(AtLeast-1))));
    assert(Buckets);
    if (!OldBuckets) {
      this->BaseT::initEmpty();
      return;
    }

    this->moveFromOldBuckets(OldBuckets, OldBuckets+OldNumBuckets);

                          
    operator delete(OldBuckets);
  }

  void shrink_and_clear() {
    unsigned OldNumEntries = NumEntries;
    this->destroyAll();

                                    
    unsigned NewNumBuckets = 0;
    if (OldNumEntries)
      NewNumBuckets = std::max(64, 1 << (Log2_32_Ceil(OldNumEntries) + 1));
    if (NewNumBuckets == NumBuckets) {
      this->BaseT::initEmpty();
      return;
    }

    operator delete(Buckets);
    init(NewNumBuckets);
  }

private:
  unsigned getNumEntries() const {
    return NumEntries;
  }

  void setNumEntries(unsigned Num) {
    NumEntries = Num;
  }

  unsigned getNumTombstones() const {
    return NumTombstones;
  }

  void setNumTombstones(unsigned Num) {
    NumTombstones = Num;
  }

  BucketT *getBuckets() const {
    return Buckets;
  }

  unsigned getNumBuckets() const {
    return NumBuckets;
  }

  bool allocateBuckets(unsigned Num) {
    NumBuckets = Num;
    if (NumBuckets == 0) {
      Buckets = nullptr;
      return false;
    }

    Buckets = static_cast<BucketT*>(operator new(sizeof(BucketT) * NumBuckets));
    return true;
  }
};

template <typename KeyT, typename ValueT, unsigned InlineBuckets = 4,
          typename KeyInfoT = DenseMapInfo<KeyT>,
          typename BucketT = detail::DenseMapPair<KeyT, ValueT>>
class SmallDenseMap
    : public DenseMapBase<
          SmallDenseMap<KeyT, ValueT, InlineBuckets, KeyInfoT, BucketT>, KeyT,
          ValueT, KeyInfoT, BucketT> {
  friend class DenseMapBase<SmallDenseMap, KeyT, ValueT, KeyInfoT, BucketT>;

                                                                      
                                     
  using BaseT = DenseMapBase<SmallDenseMap, KeyT, ValueT, KeyInfoT, BucketT>;

  static_assert(isPowerOf2_64(InlineBuckets),
                "InlineBuckets must be a power of 2.");

  unsigned Small : 1;
  unsigned NumEntries : 31;
  unsigned NumTombstones;

  struct LargeRep {
    BucketT *Buckets;
    unsigned NumBuckets;
  };

                                                                     
                                                                          
  AlignedCharArrayUnion<BucketT[InlineBuckets], LargeRep> storage;

public:
  explicit SmallDenseMap(unsigned NumInitBuckets = 0) {
    init(NumInitBuckets);
  }

  SmallDenseMap(const SmallDenseMap &other) : BaseT() {
    init(0);
    copyFrom(other);
  }

  SmallDenseMap(SmallDenseMap &&other) : BaseT() {
    init(0);
    swap(other);
  }

  template<typename InputIt>
  SmallDenseMap(const InputIt &I, const InputIt &E) {
    init(NextPowerOf2(std::distance(I, E)));
    this->insert(I, E);
  }

  ~SmallDenseMap() {
    this->destroyAll();
    deallocateBuckets();
  }

  void swap(SmallDenseMap& RHS) {
    unsigned TmpNumEntries = RHS.NumEntries;
    RHS.NumEntries = NumEntries;
    NumEntries = TmpNumEntries;
    std::swap(NumTombstones, RHS.NumTombstones);

    const KeyT EmptyKey = this->getEmptyKey();
    const KeyT TombstoneKey = this->getTombstoneKey();
    if (Small && RHS.Small) {
                                                                             
                                                                          
                                                                   
                                             
      for (unsigned i = 0, e = InlineBuckets; i != e; ++i) {
        BucketT *LHSB = &getInlineBuckets()[i],
                *RHSB = &RHS.getInlineBuckets()[i];
        bool hasLHSValue = (!KeyInfoT::isEqual(LHSB->getFirst(), EmptyKey) &&
                            !KeyInfoT::isEqual(LHSB->getFirst(), TombstoneKey));
        bool hasRHSValue = (!KeyInfoT::isEqual(RHSB->getFirst(), EmptyKey) &&
                            !KeyInfoT::isEqual(RHSB->getFirst(), TombstoneKey));
        if (hasLHSValue && hasRHSValue) {
                                       
          std::swap(*LHSB, *RHSB);
          continue;
        }
                                                    
        std::swap(LHSB->getFirst(), RHSB->getFirst());
        if (hasLHSValue) {
          ::new (&RHSB->getSecond()) ValueT(std::move(LHSB->getSecond()));
          LHSB->getSecond().~ValueT();
        } else if (hasRHSValue) {
          ::new (&LHSB->getSecond()) ValueT(std::move(RHSB->getSecond()));
          RHSB->getSecond().~ValueT();
        }
      }
      return;
    }
    if (!Small && !RHS.Small) {
      std::swap(getLargeRep()->Buckets, RHS.getLargeRep()->Buckets);
      std::swap(getLargeRep()->NumBuckets, RHS.getLargeRep()->NumBuckets);
      return;
    }

    SmallDenseMap &SmallSide = Small ? *this : RHS;
    SmallDenseMap &LargeSide = Small ? RHS : *this;

                                                                       
    LargeRep TmpRep = std::move(*LargeSide.getLargeRep());
    LargeSide.getLargeRep()->~LargeRep();
    LargeSide.Small = true;
                                                                            
                                                                          
                                                                             
                                    
    for (unsigned i = 0, e = InlineBuckets; i != e; ++i) {
      BucketT *NewB = &LargeSide.getInlineBuckets()[i],
              *OldB = &SmallSide.getInlineBuckets()[i];
      ::new (&NewB->getFirst()) KeyT(std::move(OldB->getFirst()));
      OldB->getFirst().~KeyT();
      if (!KeyInfoT::isEqual(NewB->getFirst(), EmptyKey) &&
          !KeyInfoT::isEqual(NewB->getFirst(), TombstoneKey)) {
        ::new (&NewB->getSecond()) ValueT(std::move(OldB->getSecond()));
        OldB->getSecond().~ValueT();
      }
    }

                                                                          
                                    
    SmallSide.Small = false;
    new (SmallSide.getLargeRep()) LargeRep(std::move(TmpRep));
  }

  SmallDenseMap& operator=(const SmallDenseMap& other) {
    if (&other != this)
      copyFrom(other);
    return *this;
  }

  SmallDenseMap& operator=(SmallDenseMap &&other) {
    this->destroyAll();
    deallocateBuckets();
    init(0);
    swap(other);
    return *this;
  }

  void copyFrom(const SmallDenseMap& other) {
    this->destroyAll();
    deallocateBuckets();
    Small = true;
    if (other.getNumBuckets() > InlineBuckets) {
      Small = false;
      new (getLargeRep()) LargeRep(allocateBuckets(other.getNumBuckets()));
    }
    this->BaseT::copyFrom(other);
  }

  void init(unsigned InitBuckets) {
    Small = true;
    if (InitBuckets > InlineBuckets) {
      Small = false;
      new (getLargeRep()) LargeRep(allocateBuckets(InitBuckets));
    }
    this->BaseT::initEmpty();
  }

  void grow(unsigned AtLeast) {
    if (AtLeast >= InlineBuckets)
      AtLeast = std::max<unsigned>(64, NextPowerOf2(AtLeast-1));

    if (Small) {
      if (AtLeast < InlineBuckets)
        return;                  

                                                                
      AlignedCharArrayUnion<BucketT[InlineBuckets]> TmpStorage;
      BucketT *TmpBegin = reinterpret_cast<BucketT *>(TmpStorage.buffer);
      BucketT *TmpEnd = TmpBegin;

                                                                         
                                                                             
      const KeyT EmptyKey = this->getEmptyKey();
      const KeyT TombstoneKey = this->getTombstoneKey();
      for (BucketT *P = getBuckets(), *E = P + InlineBuckets; P != E; ++P) {
        if (!KeyInfoT::isEqual(P->getFirst(), EmptyKey) &&
            !KeyInfoT::isEqual(P->getFirst(), TombstoneKey)) {
          assert(size_t(TmpEnd - TmpBegin) < InlineBuckets &&
                 "Too many inline buckets!");
          ::new (&TmpEnd->getFirst()) KeyT(std::move(P->getFirst()));
          ::new (&TmpEnd->getSecond()) ValueT(std::move(P->getSecond()));
          ++TmpEnd;
          P->getSecond().~ValueT();
        }
        P->getFirst().~KeyT();
      }

                                                                           
                 
      Small = false;
      new (getLargeRep()) LargeRep(allocateBuckets(AtLeast));
      this->moveFromOldBuckets(TmpBegin, TmpEnd);
      return;
    }

    LargeRep OldRep = std::move(*getLargeRep());
    getLargeRep()->~LargeRep();
    if (AtLeast <= InlineBuckets) {
      Small = true;
    } else {
      new (getLargeRep()) LargeRep(allocateBuckets(AtLeast));
    }

    this->moveFromOldBuckets(OldRep.Buckets, OldRep.Buckets+OldRep.NumBuckets);

                          
    operator delete(OldRep.Buckets);
  }

  void shrink_and_clear() {
    unsigned OldSize = this->size();
    this->destroyAll();

                                    
    unsigned NewNumBuckets = 0;
    if (OldSize) {
      NewNumBuckets = 1 << (Log2_32_Ceil(OldSize) + 1);
      if (NewNumBuckets > InlineBuckets && NewNumBuckets < 64u)
        NewNumBuckets = 64;
    }
    if ((Small && NewNumBuckets <= InlineBuckets) ||
        (!Small && NewNumBuckets == getLargeRep()->NumBuckets)) {
      this->BaseT::initEmpty();
      return;
    }

    deallocateBuckets();
    init(NewNumBuckets);
  }

private:
  unsigned getNumEntries() const {
    return NumEntries;
  }

  void setNumEntries(unsigned Num) {
                                                  
    assert(Num < (1U << 31) && "Cannot support more than 1<<31 entries");
    NumEntries = Num;
  }

  unsigned getNumTombstones() const {
    return NumTombstones;
  }

  void setNumTombstones(unsigned Num) {
    NumTombstones = Num;
  }

  const BucketT *getInlineBuckets() const {
    assert(Small);
                                                                            
                                                                            
                                                
    return reinterpret_cast<const BucketT *>(storage.buffer);
  }

  BucketT *getInlineBuckets() {
    return const_cast<BucketT *>(
      const_cast<const SmallDenseMap *>(this)->getInlineBuckets());
  }

  const LargeRep *getLargeRep() const {
    assert(!Small);
                                                               
    return reinterpret_cast<const LargeRep *>(storage.buffer);
  }

  LargeRep *getLargeRep() {
    return const_cast<LargeRep *>(
      const_cast<const SmallDenseMap *>(this)->getLargeRep());
  }

  const BucketT *getBuckets() const {
    return Small ? getInlineBuckets() : getLargeRep()->Buckets;
  }

  BucketT *getBuckets() {
    return const_cast<BucketT *>(
      const_cast<const SmallDenseMap *>(this)->getBuckets());
  }

  unsigned getNumBuckets() const {
    return Small ? InlineBuckets : getLargeRep()->NumBuckets;
  }

  void deallocateBuckets() {
    if (Small)
      return;

    operator delete(getLargeRep()->Buckets);
    getLargeRep()->~LargeRep();
  }

  LargeRep allocateBuckets(unsigned Num) {
    assert(Num > InlineBuckets && "Must allocate more buckets than are inline");
    LargeRep Rep = {
      static_cast<BucketT*>(operator new(sizeof(BucketT) * Num)), Num
    };
    return Rep;
  }
};

template <typename KeyT, typename ValueT, typename KeyInfoT, typename Bucket,
          bool IsConst>
class DenseMapIterator : DebugEpochBase::HandleBase {
  friend class DenseMapIterator<KeyT, ValueT, KeyInfoT, Bucket, true>;
  friend class DenseMapIterator<KeyT, ValueT, KeyInfoT, Bucket, false>;

  using ConstIterator = DenseMapIterator<KeyT, ValueT, KeyInfoT, Bucket, true>;
  using NonConstIterator = DenseMapIterator<KeyT, ValueT, KeyInfoT, Bucket, false>;

public:
  using difference_type = ptrdiff_t;
  using value_type =
      typename std::conditional<IsConst, const Bucket, Bucket>::type;
  using pointer = value_type *;
  using reference = value_type &;
  using iterator_category = std::forward_iterator_tag;

private:
  pointer Ptr = nullptr;
  pointer End = nullptr;

public:
  DenseMapIterator() = default;

  DenseMapIterator(pointer Pos, pointer E, const DebugEpochBase &Epoch,
                   bool NoAdvance = false)
      : DebugEpochBase::HandleBase(&Epoch), Ptr(Pos), End(E) {
    assert(isHandleInSync() && "invalid construction!");

    if (NoAdvance) return;
    if (shouldReverseIterate<KeyT>()) {
      RetreatPastEmptyBuckets();
      return;
    }
    AdvancePastEmptyBuckets();
  }

                                                                              
                                                                                
                 
  template <bool IsConstSrc,
            typename = typename std::enable_if<!IsConstSrc && IsConst>::type>
  DenseMapIterator(
      const DenseMapIterator<KeyT, ValueT, KeyInfoT, Bucket, IsConstSrc> &I)
      : DebugEpochBase::HandleBase(I), Ptr(I.Ptr), End(I.End) {}

  reference operator*() const {
    assert(isHandleInSync() && "invalid iterator access!");
    if (shouldReverseIterate<KeyT>())
      return Ptr[-1];
    return *Ptr;
  }
  pointer operator->() const {
    assert(isHandleInSync() && "invalid iterator access!");
    if (shouldReverseIterate<KeyT>())
      return &(Ptr[-1]);
    return Ptr;
  }

  bool operator==(const ConstIterator &RHS) const {
    assert((!Ptr || isHandleInSync()) && "handle not in sync!");
    assert((!RHS.Ptr || RHS.isHandleInSync()) && "handle not in sync!");
    assert(getEpochAddress() == RHS.getEpochAddress() &&
           "comparing incomparable iterators!");
    return Ptr == RHS.Ptr;
  }
  bool operator==(const NonConstIterator &RHS) const {
    assert((!Ptr || isHandleInSync()) && "handle not in sync!");
    assert((!RHS.Ptr || RHS.isHandleInSync()) && "handle not in sync!");
    assert(getEpochAddress() == RHS.getEpochAddress() &&
           "comparing incomparable iterators!");
    return Ptr == RHS.Ptr;
  }
  bool operator!=(const ConstIterator &RHS) const {
    return !(*this == RHS);
  }
  bool operator!=(const NonConstIterator &RHS) const {
    return !(*this == RHS);
  }

  inline DenseMapIterator& operator++() {                 
    assert(isHandleInSync() && "invalid iterator access!");
    if (shouldReverseIterate<KeyT>()) {
      --Ptr;
      RetreatPastEmptyBuckets();
      return *this;
    }
    ++Ptr;
    AdvancePastEmptyBuckets();
    return *this;
  }
  DenseMapIterator operator++(int) {                  
    assert(isHandleInSync() && "invalid iterator access!");
    DenseMapIterator tmp = *this; ++*this; return tmp;
  }

private:
  void AdvancePastEmptyBuckets() {
    assert(Ptr <= End);
    const KeyT Empty = KeyInfoT::getEmptyKey();
    const KeyT Tombstone = KeyInfoT::getTombstoneKey();

    while (Ptr != End && (KeyInfoT::isEqual(Ptr->getFirst(), Empty) ||
                          KeyInfoT::isEqual(Ptr->getFirst(), Tombstone)))
      ++Ptr;
  }

  void RetreatPastEmptyBuckets() {
    assert(Ptr >= End);
    const KeyT Empty = KeyInfoT::getEmptyKey();
    const KeyT Tombstone = KeyInfoT::getTombstoneKey();

    while (Ptr != End && (KeyInfoT::isEqual(Ptr[-1].getFirst(), Empty) ||
                          KeyInfoT::isEqual(Ptr[-1].getFirst(), Tombstone)))
      --Ptr;
  }
};

template <typename KeyT, typename ValueT, typename KeyInfoT>
inline size_t capacity_in_bytes(const DenseMap<KeyT, ValueT, KeyInfoT> &X) {
  return X.getMemorySize();
}

}                      
#pragma GCC diagnostic pop

#endif                       

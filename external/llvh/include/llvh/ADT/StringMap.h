//===- StringMap.h - String Hash table map interface ------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the StringMap class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_STRINGMAP_H
#define LLVM_ADT_STRINGMAP_H

#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/iterator.h"
#include "llvh/ADT/iterator_range.h"
#include "llvh/Support/Allocator.h"
#include "llvh/Support/PointerLikeTypeTraits.h"
#include "llvh/Support/ErrorHandling.h"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <iterator>
#include <utility>

namespace llvh {

template<typename ValueTy> class StringMapConstIterator;
template<typename ValueTy> class StringMapIterator;
template<typename ValueTy> class StringMapKeyIterator;

                                                                       
class StringMapEntryBase {
  size_t StrLen;

public:
  explicit StringMapEntryBase(size_t Len) : StrLen(Len) {}

  size_t getKeyLength() const { return StrLen; }
};

                                                                            
                              
class StringMapImpl {
protected:
                                                                      
                                                                                
                                                                
  StringMapEntryBase **TheTable = nullptr;
  unsigned NumBuckets = 0;
  unsigned NumItems = 0;
  unsigned NumTombstones = 0;
  unsigned ItemSize;

protected:
  explicit StringMapImpl(unsigned itemSize)
      : ItemSize(itemSize) {}
  StringMapImpl(StringMapImpl &&RHS)
      : TheTable(RHS.TheTable), NumBuckets(RHS.NumBuckets),
        NumItems(RHS.NumItems), NumTombstones(RHS.NumTombstones),
        ItemSize(RHS.ItemSize) {
    RHS.TheTable = nullptr;
    RHS.NumBuckets = 0;
    RHS.NumItems = 0;
    RHS.NumTombstones = 0;
  }

  StringMapImpl(unsigned InitSize, unsigned ItemSize);
  unsigned RehashTable(unsigned BucketNo = 0);

                                                                               
                                                                                
                                                                                
                                                                               
                    
  unsigned LookupBucketFor(StringRef Key);

                                                                                
                                                                            
                                   
  int FindKey(StringRef Key) const;

                                                                                
                                                              
  void RemoveKey(StringMapEntryBase *V);

                                                                          
                                                                              
  StringMapEntryBase *RemoveKey(StringRef Key);

                                                                           
                             
  void init(unsigned Size);

public:
  static StringMapEntryBase *getTombstoneVal() {
    uintptr_t Val = static_cast<uintptr_t>(-1);
    Val <<= PointerLikeTypeTraits<StringMapEntryBase *>::NumLowBitsAvailable;
    return reinterpret_cast<StringMapEntryBase *>(Val);
  }

  unsigned getNumBuckets() const { return NumBuckets; }
  unsigned getNumItems() const { return NumItems; }

  bool empty() const { return NumItems == 0; }
  unsigned size() const { return NumItems; }

  void swap(StringMapImpl &Other) {
    std::swap(TheTable, Other.TheTable);
    std::swap(NumBuckets, Other.NumBuckets);
    std::swap(NumItems, Other.NumItems);
    std::swap(NumTombstones, Other.NumTombstones);
  }
};

                                                                              
                                                                             
             
template<typename ValueTy>
class StringMapEntry : public StringMapEntryBase {
public:
  ValueTy second;

  explicit StringMapEntry(size_t strLen)
    : StringMapEntryBase(strLen), second() {}
  template <typename... InitTy>
  StringMapEntry(size_t strLen, InitTy &&... InitVals)
      : StringMapEntryBase(strLen), second(std::forward<InitTy>(InitVals)...) {}
  StringMapEntry(StringMapEntry &E) = delete;

  StringRef getKey() const {
    return StringRef(getKeyData(), getKeyLength());
  }

  const ValueTy &getValue() const { return second; }
  ValueTy &getValue() { return second; }

  void setValue(const ValueTy &V) { second = V; }

                                                                               
                                                                    
                            
  const char *getKeyData() const {return reinterpret_cast<const char*>(this+1);}

  StringRef first() const { return StringRef(getKeyData(), getKeyLength()); }

                                                                             
                   
  template <typename AllocatorTy, typename... InitTy>
  static StringMapEntry *Create(StringRef Key, AllocatorTy &Allocator,
                                InitTy &&... InitVals) {
    size_t KeyLength = Key.size();

                                                                          
                  
    size_t AllocSize = sizeof(StringMapEntry) + KeyLength + 1;
    size_t Alignment = alignof(StringMapEntry);

    StringMapEntry *NewItem =
      static_cast<StringMapEntry*>(Allocator.Allocate(AllocSize,Alignment));
    assert(NewItem && "Unhandled out-of-memory");

                           
    new (NewItem) StringMapEntry(KeyLength, std::forward<InitTy>(InitVals)...);

                                   
    char *StrBuffer = const_cast<char*>(NewItem->getKeyData());
    if (KeyLength > 0)
      memcpy(StrBuffer, Key.data(), KeyLength);
    StrBuffer[KeyLength] = 0;                                               
    return NewItem;
  }

                                                               
  template <typename... InitType>
  static StringMapEntry *Create(StringRef Key, InitType &&... InitVal) {
    MallocAllocator A;
    return Create(Key, A, std::forward<InitType>(InitVal)...);
  }

  static StringMapEntry *Create(StringRef Key) {
    return Create(Key, ValueTy());
  }

                                                                                
                                                              
  static StringMapEntry &GetStringMapEntryFromKeyData(const char *KeyData) {
    char *Ptr = const_cast<char*>(KeyData) - sizeof(StringMapEntry<ValueTy>);
    return *reinterpret_cast<StringMapEntry*>(Ptr);
  }

                                                                         
                          
  template<typename AllocatorTy>
  void Destroy(AllocatorTy &Allocator) {
                                          
    size_t AllocSize = sizeof(StringMapEntry) + getKeyLength() + 1;
    this->~StringMapEntry();
    Allocator.Deallocate(static_cast<void *>(this), AllocSize);
  }

                                                                         
  void Destroy() {
    MallocAllocator A;
    Destroy(A);
  }
};

                                                                              
                                                                                
                                                                              
                                                         
template<typename ValueTy, typename AllocatorTy = MallocAllocator>
class StringMap : public StringMapImpl {
  AllocatorTy Allocator;

public:
  using MapEntryTy = StringMapEntry<ValueTy>;

  StringMap() : StringMapImpl(static_cast<unsigned>(sizeof(MapEntryTy))) {}

  explicit StringMap(unsigned InitialSize)
    : StringMapImpl(InitialSize, static_cast<unsigned>(sizeof(MapEntryTy))) {}

  explicit StringMap(AllocatorTy A)
    : StringMapImpl(static_cast<unsigned>(sizeof(MapEntryTy))), Allocator(A) {}

  StringMap(unsigned InitialSize, AllocatorTy A)
    : StringMapImpl(InitialSize, static_cast<unsigned>(sizeof(MapEntryTy))),
      Allocator(A) {}

  StringMap(std::initializer_list<std::pair<StringRef, ValueTy>> List)
      : StringMapImpl(List.size(), static_cast<unsigned>(sizeof(MapEntryTy))) {
    for (const auto &P : List) {
      insert(P);
    }
  }

  StringMap(StringMap &&RHS)
      : StringMapImpl(std::move(RHS)), Allocator(std::move(RHS.Allocator)) {}

  StringMap(const StringMap &RHS) :
    StringMapImpl(static_cast<unsigned>(sizeof(MapEntryTy))),
    Allocator(RHS.Allocator) {
    if (RHS.empty())
      return;

                                                                        
                                               
    init(RHS.NumBuckets);
    unsigned *HashTable = (unsigned *)(TheTable + NumBuckets + 1),
             *RHSHashTable = (unsigned *)(RHS.TheTable + NumBuckets + 1);

    NumItems = RHS.NumItems;
    NumTombstones = RHS.NumTombstones;
    for (unsigned I = 0, E = NumBuckets; I != E; ++I) {
      StringMapEntryBase *Bucket = RHS.TheTable[I];
      if (!Bucket || Bucket == getTombstoneVal()) {
        TheTable[I] = Bucket;
        continue;
      }

      TheTable[I] = MapEntryTy::Create(
          static_cast<MapEntryTy *>(Bucket)->getKey(), Allocator,
          static_cast<MapEntryTy *>(Bucket)->getValue());
      HashTable[I] = RHSHashTable[I];
    }

                                                                            
                                                                             
                                                                     
                                                                             
                                                                              
                      
  }

  StringMap &operator=(StringMap RHS) {
    StringMapImpl::swap(RHS);
    std::swap(Allocator, RHS.Allocator);
    return *this;
  }

  ~StringMap() {
                                                                       
                                                                            
                                           
    if (!empty()) {
      for (unsigned I = 0, E = NumBuckets; I != E; ++I) {
        StringMapEntryBase *Bucket = TheTable[I];
        if (Bucket && Bucket != getTombstoneVal()) {
          static_cast<MapEntryTy*>(Bucket)->Destroy(Allocator);
        }
      }
    }
    free(TheTable);
  }

  AllocatorTy &getAllocator() { return Allocator; }
  const AllocatorTy &getAllocator() const { return Allocator; }

  using key_type = const char*;
  using mapped_type = ValueTy;
  using value_type = StringMapEntry<ValueTy>;
  using size_type = size_t;

  using const_iterator = StringMapConstIterator<ValueTy>;
  using iterator = StringMapIterator<ValueTy>;

  iterator begin() {
    return iterator(TheTable, NumBuckets == 0);
  }
  iterator end() {
    return iterator(TheTable+NumBuckets, true);
  }
  const_iterator begin() const {
    return const_iterator(TheTable, NumBuckets == 0);
  }
  const_iterator end() const {
    return const_iterator(TheTable+NumBuckets, true);
  }

  iterator_range<StringMapKeyIterator<ValueTy>> keys() const {
    return make_range(StringMapKeyIterator<ValueTy>(begin()),
                      StringMapKeyIterator<ValueTy>(end()));
  }

  iterator find(StringRef Key) {
    int Bucket = FindKey(Key);
    if (Bucket == -1) return end();
    return iterator(TheTable+Bucket, true);
  }

  const_iterator find(StringRef Key) const {
    int Bucket = FindKey(Key);
    if (Bucket == -1) return end();
    return const_iterator(TheTable+Bucket, true);
  }

                                                                   
                                                
  ValueTy lookup(StringRef Key) const {
    const_iterator it = find(Key);
    if (it != end())
      return it->second;
    return ValueTy();
  }

                                                                              
                                   
  ValueTy &operator[](StringRef Key) { return try_emplace(Key).first->second; }

                                                                 
  size_type count(StringRef Key) const {
    return find(Key) == end() ? 0 : 1;
  }

                                                                            
                                                                               
                                
  bool insert(MapEntryTy *KeyValue) {
    unsigned BucketNo = LookupBucketFor(KeyValue->getKey());
    StringMapEntryBase *&Bucket = TheTable[BucketNo];
    if (Bucket && Bucket != getTombstoneVal())
      return false;                           

    if (Bucket == getTombstoneVal())
      --NumTombstones;
    Bucket = KeyValue;
    ++NumItems;
    assert(NumItems + NumTombstones <= NumBuckets);

    RehashTable();
    return true;
  }

                                                                           
                                                                               
                                                                             
                                                                                
  std::pair<iterator, bool> insert(std::pair<StringRef, ValueTy> KV) {
    return try_emplace(KV.first, std::move(KV.second));
  }

                                                                               
                                                                         
                                                                             
                                                                                
  template <typename... ArgsTy>
  std::pair<iterator, bool> try_emplace(StringRef Key, ArgsTy &&... Args) {
    unsigned BucketNo = LookupBucketFor(Key);
    StringMapEntryBase *&Bucket = TheTable[BucketNo];
    if (Bucket && Bucket != getTombstoneVal())
      return std::make_pair(iterator(TheTable + BucketNo, false),
                            false);                          

    if (Bucket == getTombstoneVal())
      --NumTombstones;
    Bucket = MapEntryTy::Create(Key, Allocator, std::forward<ArgsTy>(Args)...);
    ++NumItems;
    assert(NumItems + NumTombstones <= NumBuckets);

    BucketNo = RehashTable(BucketNo);
    return std::make_pair(iterator(TheTable + BucketNo, false), true);
  }

                                      
  void clear() {
    if (empty()) return;

                                                                              
                                                         
    for (unsigned I = 0, E = NumBuckets; I != E; ++I) {
      StringMapEntryBase *&Bucket = TheTable[I];
      if (Bucket && Bucket != getTombstoneVal()) {
        static_cast<MapEntryTy*>(Bucket)->Destroy(Allocator);
      }
      Bucket = nullptr;
    }

    NumItems = 0;
    NumTombstones = 0;
  }

                                                                           
                                                          
  void remove(MapEntryTy *KeyValue) {
    RemoveKey(KeyValue);
  }

  void erase(iterator I) {
    MapEntryTy &V = *I;
    remove(&V);
    V.Destroy(Allocator);
  }

  bool erase(StringRef Key) {
    iterator I = find(Key);
    if (I == end()) return false;
    erase(I);
    return true;
  }
};

template <typename DerivedTy, typename ValueTy>
class StringMapIterBase
    : public iterator_facade_base<DerivedTy, std::forward_iterator_tag,
                                  ValueTy> {
protected:
  StringMapEntryBase **Ptr = nullptr;

public:
  StringMapIterBase() = default;

  explicit StringMapIterBase(StringMapEntryBase **Bucket,
                             bool NoAdvance = false)
      : Ptr(Bucket) {
    if (!NoAdvance) AdvancePastEmptyBuckets();
  }

  DerivedTy &operator=(const DerivedTy &Other) {
    Ptr = Other.Ptr;
    return static_cast<DerivedTy &>(*this);
  }

  bool operator==(const DerivedTy &RHS) const { return Ptr == RHS.Ptr; }

  DerivedTy &operator++() {                
    ++Ptr;
    AdvancePastEmptyBuckets();
    return static_cast<DerivedTy &>(*this);
  }

  DerivedTy operator++(int) {                  
    DerivedTy Tmp(Ptr);
    ++*this;
    return Tmp;
  }

private:
  void AdvancePastEmptyBuckets() {
    while (*Ptr == nullptr || *Ptr == StringMapImpl::getTombstoneVal())
      ++Ptr;
  }
};

template <typename ValueTy>
class StringMapConstIterator
    : public StringMapIterBase<StringMapConstIterator<ValueTy>,
                               const StringMapEntry<ValueTy>> {
  using base = StringMapIterBase<StringMapConstIterator<ValueTy>,
                                 const StringMapEntry<ValueTy>>;

public:
  StringMapConstIterator() = default;
  explicit StringMapConstIterator(StringMapEntryBase **Bucket,
                                  bool NoAdvance = false)
      : base(Bucket, NoAdvance) {}

  const StringMapEntry<ValueTy> &operator*() const {
    return *static_cast<const StringMapEntry<ValueTy> *>(*this->Ptr);
  }
};

template <typename ValueTy>
class StringMapIterator : public StringMapIterBase<StringMapIterator<ValueTy>,
                                                   StringMapEntry<ValueTy>> {
  using base =
      StringMapIterBase<StringMapIterator<ValueTy>, StringMapEntry<ValueTy>>;

public:
  StringMapIterator() = default;
  explicit StringMapIterator(StringMapEntryBase **Bucket,
                             bool NoAdvance = false)
      : base(Bucket, NoAdvance) {}

  StringMapEntry<ValueTy> &operator*() const {
    return *static_cast<StringMapEntry<ValueTy> *>(*this->Ptr);
  }

  operator StringMapConstIterator<ValueTy>() const {
    return StringMapConstIterator<ValueTy>(this->Ptr, true);
  }
};

template <typename ValueTy>
class StringMapKeyIterator
    : public iterator_adaptor_base<StringMapKeyIterator<ValueTy>,
                                   StringMapConstIterator<ValueTy>,
                                   std::forward_iterator_tag, StringRef> {
  using base = iterator_adaptor_base<StringMapKeyIterator<ValueTy>,
                                     StringMapConstIterator<ValueTy>,
                                     std::forward_iterator_tag, StringRef>;

public:
  StringMapKeyIterator() = default;
  explicit StringMapKeyIterator(StringMapConstIterator<ValueTy> Iter)
      : base(std::move(Iter)) {}

  StringRef &operator*() {
    Key = this->wrapped()->getKey();
    return Key;
  }

private:
  StringRef Key;
};

}                      

#endif                        

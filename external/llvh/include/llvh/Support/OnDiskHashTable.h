//===--- OnDiskHashTable.h - On-Disk Hash Table Implementation --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// Defines facilities for reading and writing on-disk hash tables.
///
//===----------------------------------------------------------------------===//
#ifndef LLVM_SUPPORT_ONDISKHASHTABLE_H
#define LLVM_SUPPORT_ONDISKHASHTABLE_H

#include "llvh/Support/Allocator.h"
#include "llvh/Support/DataTypes.h"
#include "llvh/Support/EndianStream.h"
#include "llvh/Support/Host.h"
#include "llvh/Support/MathExtras.h"
#include "llvh/Support/raw_ostream.h"
#include <cassert>
#include <cstdlib>

namespace llvh {

                                    
   
                                                                           
                                                                          
                        
   
         
                       
           
                                                                  
                                       
                                                                  
                                         
                                                                              
                                                                           
   
                                    
                                                           
                                                                   
                                                
                                                                                
                                                                         
                                                             
                                              
                                                                           
                                                              
                                                                    
                                                                             
                                                                 
      
            
template <typename Info> class OnDiskChainedHashTableGenerator {
                                      
  class Item {
  public:
    typename Info::key_type Key;
    typename Info::data_type Data;
    Item *Next;
    const typename Info::hash_value_type Hash;

    Item(typename Info::key_type_ref Key, typename Info::data_type_ref Data,
         Info &InfoObj)
        : Key(Key), Data(Data), Next(nullptr), Hash(InfoObj.ComputeHash(Key)) {}
  };

  typedef typename Info::offset_type offset_type;
  offset_type NumBuckets;
  offset_type NumEntries;
  llvh::SpecificBumpPtrAllocator<Item> BA;

                                                          
  struct Bucket {
    offset_type Off;
    unsigned Length;
    Item *Head;
  };

  Bucket *Buckets;

private:
                                                      
  void insert(Bucket *Buckets, size_t Size, Item *E) {
    Bucket &B = Buckets[E->Hash & (Size - 1)];
    E->Next = B.Head;
    ++B.Length;
    B.Head = E;
  }

                                                                         
  void resize(size_t NewSize) {
    Bucket *NewBuckets = static_cast<Bucket *>(
        safe_calloc(NewSize, sizeof(Bucket)));
                                                
    for (size_t I = 0; I < NumBuckets; ++I)
      for (Item *E = Buckets[I].Head; E;) {
        Item *N = E->Next;
        E->Next = nullptr;
        insert(NewBuckets, NewSize, E);
        E = N;
      }

    free(Buckets);
    NumBuckets = NewSize;
    Buckets = NewBuckets;
  }

public:
                                     
  void insert(typename Info::key_type_ref Key,
              typename Info::data_type_ref Data) {
    Info InfoObj;
    insert(Key, Data, InfoObj);
  }

                                     
     
                                                              
  void insert(typename Info::key_type_ref Key,
              typename Info::data_type_ref Data, Info &InfoObj) {
    ++NumEntries;
    if (4 * NumEntries >= 3 * NumBuckets)
      resize(NumBuckets * 2);
    insert(Buckets, NumBuckets, new (BA.Allocate()) Item(Key, Data, InfoObj));
  }

                                                   
  bool contains(typename Info::key_type_ref Key, Info &InfoObj) {
    unsigned Hash = InfoObj.ComputeHash(Key);
    for (Item *I = Buckets[Hash & (NumBuckets - 1)].Head; I; I = I->Next)
      if (I->Hash == Hash && InfoObj.EqualKey(I->Key, Key))
        return true;
    return false;
  }

                                                           
  offset_type Emit(raw_ostream &Out) {
    Info InfoObj;
    return Emit(Out, InfoObj);
  }

                                                           
     
                                                              
  offset_type Emit(raw_ostream &Out, Info &InfoObj) {
    using namespace llvh::support;
    endian::Writer LE(Out, little);

                                                                    
                                                                   
                                                                  
                                                                
      
                                                                 
                                                                    
                                                                
                                                                    
      
                                                                  
    unsigned TargetNumBuckets =
        NumEntries <= 2 ? 1 : NextPowerOf2(NumEntries * 4 / 3);
    if (TargetNumBuckets != NumBuckets)
      resize(TargetNumBuckets);

                                     
    for (offset_type I = 0; I < NumBuckets; ++I) {
      Bucket &B = Buckets[I];
      if (!B.Head)
        continue;

                                                      
      B.Off = Out.tell();
      assert(B.Off && "Cannot write a bucket at offset 0. Please add padding.");

                                                     
      LE.write<uint16_t>(B.Length);
      assert(B.Length != 0 && "Bucket has a head but zero length?");

                                             
      for (Item *I = B.Head; I; I = I->Next) {
        LE.write<typename Info::hash_value_type>(I->Hash);
        const std::pair<offset_type, offset_type> &Len =
            InfoObj.EmitKeyDataLength(Out, I->Key, I->Data);
#ifdef NDEBUG
        InfoObj.EmitKey(Out, I->Key, Len.first);
        InfoObj.EmitData(Out, I->Key, I->Data, Len.second);
#else
                                                                             
                 
        uint64_t KeyStart = Out.tell();
        InfoObj.EmitKey(Out, I->Key, Len.first);
        uint64_t DataStart = Out.tell();
        InfoObj.EmitData(Out, I->Key, I->Data, Len.second);
        uint64_t End = Out.tell();
        assert(offset_type(DataStart - KeyStart) == Len.first &&
               "key length does not match bytes written");
        assert(offset_type(End - DataStart) == Len.second &&
               "data length does not match bytes written");
#endif
      }
    }

                                                                               
    offset_type TableOff = Out.tell();
    uint64_t N = llvh::OffsetToAlignment(TableOff, alignof(offset_type));
    TableOff += N;
    while (N--)
      LE.write<uint8_t>(0);

                                 
    LE.write<offset_type>(NumBuckets);
    LE.write<offset_type>(NumEntries);
    for (offset_type I = 0; I < NumBuckets; ++I)
      LE.write<offset_type>(Buckets[I].Off);

    return TableOff;
  }

  OnDiskChainedHashTableGenerator() {
    NumEntries = 0;
    NumBuckets = 64;
                                                                         
                                                                  
    Buckets = static_cast<Bucket *>(safe_calloc(NumBuckets, sizeof(Bucket)));
  }

  ~OnDiskChainedHashTableGenerator() { std::free(Buckets); }
};

                                             
   
                                                                           
                                                                          
                        
   
         
                             
           
                                    
                                                                           
                                                                          
                                                                              
                                                                           
   
                                        
                                                                             
                                               
                                                                  
                                                                            
                                                                            
                                                                                
                                                
                                                                              
                                                                              
                         
                                                
                                                      
                                                                     
                            
                                                                   
                                                           
                                                                               
                            
                                                                    
                                              
      
            
template <typename Info> class OnDiskChainedHashTable {
  const typename Info::offset_type NumBuckets;
  const typename Info::offset_type NumEntries;
  const unsigned char *const Buckets;
  const unsigned char *const Base;
  Info InfoObj;

public:
  typedef Info InfoType;
  typedef typename Info::internal_key_type internal_key_type;
  typedef typename Info::external_key_type external_key_type;
  typedef typename Info::data_type data_type;
  typedef typename Info::hash_value_type hash_value_type;
  typedef typename Info::offset_type offset_type;

  OnDiskChainedHashTable(offset_type NumBuckets, offset_type NumEntries,
                         const unsigned char *Buckets,
                         const unsigned char *Base,
                         const Info &InfoObj = Info())
      : NumBuckets(NumBuckets), NumEntries(NumEntries), Buckets(Buckets),
        Base(Base), InfoObj(InfoObj) {
    assert((reinterpret_cast<uintptr_t>(Buckets) & 0x3) == 0 &&
           "'buckets' must have a 4-byte alignment");
  }

                                                                            
                                                                         
                        
  static std::pair<offset_type, offset_type>
  readNumBucketsAndEntries(const unsigned char *&Buckets) {
    assert((reinterpret_cast<uintptr_t>(Buckets) & 0x3) == 0 &&
           "buckets should be 4-byte aligned.");
    using namespace llvh::support;
    offset_type NumBuckets =
        endian::readNext<offset_type, little, aligned>(Buckets);
    offset_type NumEntries =
        endian::readNext<offset_type, little, aligned>(Buckets);
    return std::make_pair(NumBuckets, NumEntries);
  }

  offset_type getNumBuckets() const { return NumBuckets; }
  offset_type getNumEntries() const { return NumEntries; }
  const unsigned char *getBase() const { return Base; }
  const unsigned char *getBuckets() const { return Buckets; }

  bool isEmpty() const { return NumEntries == 0; }

  class iterator {
    internal_key_type Key;
    const unsigned char *const Data;
    const offset_type Len;
    Info *InfoObj;

  public:
    iterator() : Key(), Data(nullptr), Len(0), InfoObj(nullptr) {}
    iterator(const internal_key_type K, const unsigned char *D, offset_type L,
             Info *InfoObj)
        : Key(K), Data(D), Len(L), InfoObj(InfoObj) {}

    data_type operator*() const { return InfoObj->ReadData(Key, Data, Len); }

    const unsigned char *getDataPtr() const { return Data; }
    offset_type getDataLen() const { return Len; }

    bool operator==(const iterator &X) const { return X.Data == Data; }
    bool operator!=(const iterator &X) const { return X.Data != Data; }
  };

                                                   
  iterator find(const external_key_type &EKey, Info *InfoPtr = nullptr) {
    const internal_key_type &IKey = InfoObj.GetInternalKey(EKey);
    hash_value_type KeyHash = InfoObj.ComputeHash(IKey);
    return find_hashed(IKey, KeyHash, InfoPtr);
  }

                                                                     
  iterator find_hashed(const internal_key_type &IKey, hash_value_type KeyHash,
                       Info *InfoPtr = nullptr) {
    using namespace llvh::support;

    if (!InfoPtr)
      InfoPtr = &InfoObj;

                                                              
    offset_type Idx = KeyHash & (NumBuckets - 1);
    const unsigned char *Bucket = Buckets + sizeof(offset_type) * Idx;

    offset_type Offset = endian::readNext<offset_type, little, aligned>(Bucket);
    if (Offset == 0)
      return iterator();                 
    const unsigned char *Items = Base + Offset;

                                                                     
                                      
    unsigned Len = endian::readNext<uint16_t, little, unaligned>(Items);

    for (unsigned i = 0; i < Len; ++i) {
                       
      hash_value_type ItemHash =
          endian::readNext<hash_value_type, little, unaligned>(Items);

                                                      
      const std::pair<offset_type, offset_type> &L =
          Info::ReadKeyDataLength(Items);
      offset_type ItemLen = L.first + L.second;

                                                                                
      if (ItemHash != KeyHash) {
        Items += ItemLen;
        continue;
      }

                      
      const internal_key_type &X =
          InfoPtr->ReadKey((const unsigned char *const)Items, L.first);

                                                              
      if (!InfoPtr->EqualKey(X, IKey)) {
        Items += ItemLen;
        continue;
      }

                         
      return iterator(X, Items + L.first, L.second, InfoPtr);
    }

    return iterator();
  }

  iterator end() const { return iterator(); }

  Info &getInfoObj() { return InfoObj; }

                            
     
                                                                             
                                                                    
                                     
     
                                                                            
                                                                           
            
  static OnDiskChainedHashTable *Create(const unsigned char *Buckets,
                                        const unsigned char *const Base,
                                        const Info &InfoObj = Info()) {
    assert(Buckets > Base);
    auto NumBucketsAndEntries = readNumBucketsAndEntries(Buckets);
    return new OnDiskChainedHashTable<Info>(NumBucketsAndEntries.first,
                                            NumBucketsAndEntries.second,
                                            Buckets, Base, InfoObj);
  }
};

                                                             
   
                                             
template <typename Info>
class OnDiskIterableChainedHashTable : public OnDiskChainedHashTable<Info> {
  const unsigned char *Payload;

public:
  typedef OnDiskChainedHashTable<Info>          base_type;
  typedef typename base_type::internal_key_type internal_key_type;
  typedef typename base_type::external_key_type external_key_type;
  typedef typename base_type::data_type         data_type;
  typedef typename base_type::hash_value_type   hash_value_type;
  typedef typename base_type::offset_type       offset_type;

private:
                                                 
  class iterator_base {
    const unsigned char *Ptr;
    offset_type NumItemsInBucketLeft;
    offset_type NumEntriesLeft;

  public:
    typedef external_key_type value_type;

    iterator_base(const unsigned char *const Ptr, offset_type NumEntries)
        : Ptr(Ptr), NumItemsInBucketLeft(0), NumEntriesLeft(NumEntries) {}
    iterator_base()
        : Ptr(nullptr), NumItemsInBucketLeft(0), NumEntriesLeft(0) {}

    friend bool operator==(const iterator_base &X, const iterator_base &Y) {
      return X.NumEntriesLeft == Y.NumEntriesLeft;
    }
    friend bool operator!=(const iterator_base &X, const iterator_base &Y) {
      return X.NumEntriesLeft != Y.NumEntriesLeft;
    }

                              
    void advance() {
      using namespace llvh::support;
      if (!NumItemsInBucketLeft) {
                                                                         
                                          
        NumItemsInBucketLeft =
            endian::readNext<uint16_t, little, unaligned>(Ptr);
      }
      Ptr += sizeof(hash_value_type);                  
                                                      
      const std::pair<offset_type, offset_type> &L =
          Info::ReadKeyDataLength(Ptr);
      Ptr += L.first + L.second;
      assert(NumItemsInBucketLeft);
      --NumItemsInBucketLeft;
      assert(NumEntriesLeft);
      --NumEntriesLeft;
    }

                                                                             
                                                     
    const unsigned char *getItem() const {
      return Ptr + (NumItemsInBucketLeft ? 0 : 2) + sizeof(hash_value_type);
    }
  };

public:
  OnDiskIterableChainedHashTable(offset_type NumBuckets, offset_type NumEntries,
                                 const unsigned char *Buckets,
                                 const unsigned char *Payload,
                                 const unsigned char *Base,
                                 const Info &InfoObj = Info())
      : base_type(NumBuckets, NumEntries, Buckets, Base, InfoObj),
        Payload(Payload) {}

                                                 
  class key_iterator : public iterator_base {
    Info *InfoObj;

  public:
    typedef external_key_type value_type;

    key_iterator(const unsigned char *const Ptr, offset_type NumEntries,
                 Info *InfoObj)
        : iterator_base(Ptr, NumEntries), InfoObj(InfoObj) {}
    key_iterator() : iterator_base(), InfoObj() {}

    key_iterator &operator++() {
      this->advance();
      return *this;
    }
    key_iterator operator++(int) {                 
      key_iterator tmp = *this;
      ++*this;
      return tmp;
    }

    internal_key_type getInternalKey() const {
      auto *LocalPtr = this->getItem();

                                                      
      auto L = Info::ReadKeyDataLength(LocalPtr);

                      
      return InfoObj->ReadKey(LocalPtr, L.first);
    }

    value_type operator*() const {
      return InfoObj->GetExternalKey(getInternalKey());
    }
  };

  key_iterator key_begin() {
    return key_iterator(Payload, this->getNumEntries(), &this->getInfoObj());
  }
  key_iterator key_end() { return key_iterator(); }

  iterator_range<key_iterator> keys() {
    return make_range(key_begin(), key_end());
  }

                                                                     
  class data_iterator : public iterator_base {
    Info *InfoObj;

  public:
    typedef data_type value_type;

    data_iterator(const unsigned char *const Ptr, offset_type NumEntries,
                  Info *InfoObj)
        : iterator_base(Ptr, NumEntries), InfoObj(InfoObj) {}
    data_iterator() : iterator_base(), InfoObj() {}

    data_iterator &operator++() {                
      this->advance();
      return *this;
    }
    data_iterator operator++(int) {                 
      data_iterator tmp = *this;
      ++*this;
      return tmp;
    }

    value_type operator*() const {
      auto *LocalPtr = this->getItem();

                                                      
      auto L = Info::ReadKeyDataLength(LocalPtr);

                      
      const internal_key_type &Key = InfoObj->ReadKey(LocalPtr, L.first);
      return InfoObj->ReadData(Key, LocalPtr + L.first, L.second);
    }
  };

  data_iterator data_begin() {
    return data_iterator(Payload, this->getNumEntries(), &this->getInfoObj());
  }
  data_iterator data_end() { return data_iterator(); }

  iterator_range<data_iterator> data() {
    return make_range(data_begin(), data_end());
  }

                            
     
                                                                             
                                                                    
                                     
     
                                                                               
                                                                             
                                               
     
                                                                            
                                                                           
            
  static OnDiskIterableChainedHashTable *
  Create(const unsigned char *Buckets, const unsigned char *const Payload,
         const unsigned char *const Base, const Info &InfoObj = Info()) {
    assert(Buckets > Base);
    auto NumBucketsAndEntries =
        OnDiskIterableChainedHashTable<Info>::readNumBucketsAndEntries(Buckets);
    return new OnDiskIterableChainedHashTable<Info>(
        NumBucketsAndEntries.first, NumBucketsAndEntries.second,
        Buckets, Payload, Base, InfoObj);
  }
};

}                      

#endif

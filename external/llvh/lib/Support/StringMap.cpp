//===--- StringMap.cpp - String Hash table map implementation -------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the StringMap class.
//
//===----------------------------------------------------------------------===//

#include "llvh/ADT/StringMap.h"
#include "llvh/ADT/StringExtras.h"
#include "llvh/Support/Compiler.h"
#include "llvh/Support/DJB.h"
#include "llvh/Support/MathExtras.h"
#include <cassert>

using namespace llvh;

                                                                             
                                                     
static unsigned getMinBucketToReserveForEntries(unsigned NumEntries) {
                                                  
  if (NumEntries == 0)
    return 0;
                                                   
                                                            
  return NextPowerOf2(NumEntries * 4 / 3 + 1);
}

StringMapImpl::StringMapImpl(unsigned InitSize, unsigned itemSize) {
  ItemSize = itemSize;

                                                                         
  if (InitSize) {
                                                                                
                                                                              
                                                                          
    init(getMinBucketToReserveForEntries(InitSize));
    return;
  }

                                                                        
  TheTable = nullptr;
  NumBuckets = 0;
  NumItems = 0;
  NumTombstones = 0;
}

void StringMapImpl::init(unsigned InitSize) {
  assert((InitSize & (InitSize-1)) == 0 &&
         "Init Size must be a power of 2 or zero!");

  unsigned NewNumBuckets = InitSize ? InitSize : 16;
  NumItems = 0;
  NumTombstones = 0;

  TheTable = static_cast<StringMapEntryBase **>(
      safe_calloc(NewNumBuckets+1,
                  sizeof(StringMapEntryBase **) + sizeof(unsigned)));

                                                               
  NumBuckets = NewNumBuckets;

                                                                              
         
  TheTable[NumBuckets] = (StringMapEntryBase*)2;
}

                                                                             
                                                                              
                                                                              
                                                                             
                  
unsigned StringMapImpl::LookupBucketFor(StringRef Name) {
  unsigned HTSize = NumBuckets;
  if (HTSize == 0) {                                   
    init(16);
    HTSize = NumBuckets;
  }
  unsigned FullHashValue = djbHash(Name, 0);
  unsigned BucketNo = FullHashValue & (HTSize-1);
  unsigned *HashTable = (unsigned *)(TheTable + NumBuckets + 1);

  unsigned ProbeAmt = 1;
  int FirstTombstone = -1;
  while (true) {
    StringMapEntryBase *BucketItem = TheTable[BucketNo];
                                                                               
    if (LLVM_LIKELY(!BucketItem)) {
                                                                              
                                             
      if (FirstTombstone != -1) {
        HashTable[FirstTombstone] = FullHashValue;
        return FirstTombstone;
      }

      HashTable[BucketNo] = FullHashValue;
      return BucketNo;
    }

    if (BucketItem == getTombstoneVal()) {
                                                                       
      if (FirstTombstone == -1) FirstTombstone = BucketNo;
    } else if (LLVM_LIKELY(HashTable[BucketNo] == FullHashValue)) {
                                                                              
                                                                            
                                                                            
                                         

                                                                   
                         
      char *ItemStr = (char*)BucketItem+ItemSize;
      if (Name == StringRef(ItemStr, BucketItem->getKeyLength())) {
                            
        return BucketNo;
      }
    }

                                                                
    BucketNo = (BucketNo+ProbeAmt) & (HTSize-1);

                                                                         
                                                              
    ++ProbeAmt;
  }
}

                                                                              
                                                                          
                                 
int StringMapImpl::FindKey(StringRef Key) const {
  unsigned HTSize = NumBuckets;
  if (HTSize == 0) return -1;                        
  unsigned FullHashValue = djbHash(Key, 0);
  unsigned BucketNo = FullHashValue & (HTSize-1);
  unsigned *HashTable = (unsigned *)(TheTable + NumBuckets + 1);

  unsigned ProbeAmt = 1;
  while (true) {
    StringMapEntryBase *BucketItem = TheTable[BucketNo];
                                                                            
    if (LLVM_LIKELY(!BucketItem))
      return -1;

    if (BucketItem == getTombstoneVal()) {
                           
    } else if (LLVM_LIKELY(HashTable[BucketNo] == FullHashValue)) {
                                                                              
                                                                            
                                                                            
                                         

                                                                        
                         
      char *ItemStr = (char*)BucketItem+ItemSize;
      if (Key == StringRef(ItemStr, BucketItem->getKeyLength())) {
                            
        return BucketNo;
      }
    }

                                                                
    BucketNo = (BucketNo+ProbeAmt) & (HTSize-1);

                                                                         
                                                              
    ++ProbeAmt;
  }
}

                                                                              
                                                            
void StringMapImpl::RemoveKey(StringMapEntryBase *V) {
  const char *VStr = (char*)V + ItemSize;
  StringMapEntryBase *V2 = RemoveKey(StringRef(VStr, V->getKeyLength()));
  (void)V2;
  assert(V == V2 && "Didn't find key?");
}

                                                                        
                                                                            
StringMapEntryBase *StringMapImpl::RemoveKey(StringRef Key) {
  int Bucket = FindKey(Key);
  if (Bucket == -1) return nullptr;

  StringMapEntryBase *Result = TheTable[Bucket];
  TheTable[Bucket] = getTombstoneVal();
  --NumItems;
  ++NumTombstones;
  assert(NumItems + NumTombstones <= NumBuckets);

  return Result;
}

                                                                             
                                          
unsigned StringMapImpl::RehashTable(unsigned BucketNo) {
  unsigned NewSize;
  unsigned *HashTable = (unsigned *)(TheTable + NumBuckets + 1);

                                                                         
                                                                          
                           
  if (LLVM_UNLIKELY(NumItems * 4 > NumBuckets * 3)) {
    NewSize = NumBuckets*2;
  } else if (LLVM_UNLIKELY(NumBuckets - (NumItems + NumTombstones) <=
                           NumBuckets / 8)) {
    NewSize = NumBuckets;
  } else {
    return BucketNo;
  }

  unsigned NewBucketNo = BucketNo;
                                                                               
                              
  auto NewTableArray = static_cast<StringMapEntryBase **>(
      safe_calloc(NewSize+1, sizeof(StringMapEntryBase *) + sizeof(unsigned)));

  unsigned *NewHashArray = (unsigned *)(NewTableArray + NewSize + 1);
  NewTableArray[NewSize] = (StringMapEntryBase*)2;

                                                                             
                                                                       
  for (unsigned I = 0, E = NumBuckets; I != E; ++I) {
    StringMapEntryBase *Bucket = TheTable[I];
    if (Bucket && Bucket != getTombstoneVal()) {
                                     
      unsigned FullHash = HashTable[I];
      unsigned NewBucket = FullHash & (NewSize-1);
      if (!NewTableArray[NewBucket]) {
        NewTableArray[FullHash & (NewSize-1)] = Bucket;
        NewHashArray[FullHash & (NewSize-1)] = FullHash;
        if (I == BucketNo)
          NewBucketNo = NewBucket;
        continue;
      }

                                    
      unsigned ProbeSize = 1;
      do {
        NewBucket = (NewBucket + ProbeSize++) & (NewSize-1);
      } while (NewTableArray[NewBucket]);

                                           
      NewTableArray[NewBucket] = Bucket;
      NewHashArray[NewBucket] = FullHash;
      if (I == BucketNo)
        NewBucketNo = NewBucket;
    }
  }

  free(TheTable);

  TheTable = NewTableArray;
  NumBuckets = NewSize;
  NumTombstones = 0;
  return NewBucketNo;
}

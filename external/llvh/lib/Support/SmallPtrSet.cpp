//===- llvm/ADT/SmallPtrSet.cpp - 'Normally small' pointer set ------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the SmallPtrSet class.  See SmallPtrSet.h for an
// overview of the algorithm.
//
//===----------------------------------------------------------------------===//

#include "llvh/ADT/SmallPtrSet.h"
#include "llvh/ADT/DenseMapInfo.h"
#include "llvh/Support/MathExtras.h"
#include "llvh/Support/ErrorHandling.h"
#include <algorithm>
#include <cassert>
#include <cstdlib>

using namespace llvh;

void SmallPtrSetImplBase::shrink_and_clear() {
  assert(!isSmall() && "Can't shrink a small set!");
  free(CurArray);

                                  
  unsigned Size = size();
  CurArraySize = Size > 16 ? 1 << (Log2_32_Ceil(Size) + 1) : 32;
  NumNonEmpty = NumTombstones = 0;

                                                            
  CurArray = (const void**)safe_malloc(sizeof(void*) * CurArraySize);

  memset(CurArray, -1, CurArraySize*sizeof(void*));
}

std::pair<const void *const *, bool>
SmallPtrSetImplBase::insert_imp_big(const void *Ptr) {
  if (LLVM_UNLIKELY(size() * 4 >= CurArraySize * 3)) {
                                                   
    Grow(CurArraySize < 64 ? 128 : CurArraySize * 2);
  } else if (LLVM_UNLIKELY(CurArraySize - NumNonEmpty < CurArraySize / 8)) {
                                                                               
                           
    Grow(CurArraySize);
  }

                                                      
  const void **Bucket = const_cast<const void**>(FindBucketFor(Ptr));
  if (*Bucket == Ptr)
    return std::make_pair(Bucket, false);                           

                          
  if (*Bucket == getTombstoneMarker())
    --NumTombstones;
  else
    ++NumNonEmpty;                  
  *Bucket = Ptr;
  incrementEpoch();
  return std::make_pair(Bucket, true);
}

const void * const *SmallPtrSetImplBase::FindBucketFor(const void *Ptr) const {
  unsigned Bucket = DenseMapInfo<void *>::getHashValue(Ptr) & (CurArraySize-1);
  unsigned ArraySize = CurArraySize;
  unsigned ProbeAmt = 1;
  const void *const *Array = CurArray;
  const void *const *Tombstone = nullptr;
  while (true) {
                                                                         
                                                                          
           
    if (LLVM_LIKELY(Array[Bucket] == getEmptyMarker()))
      return Tombstone ? Tombstone : Array+Bucket;

                          
    if (LLVM_LIKELY(Array[Bucket] == Ptr))
      return Array+Bucket;

                                                                              
                                                                          
    if (Array[Bucket] == getTombstoneMarker() && !Tombstone)
      Tombstone = Array+Bucket;                                        

                                                     
    Bucket = (Bucket + ProbeAmt++) & (ArraySize-1);
  }
}

                                                                            
   
void SmallPtrSetImplBase::Grow(unsigned NewSize) {
  const void **OldBuckets = CurArray;
  const void **OldEnd = EndPointer();
  bool WasSmall = isSmall();

                                                            
  const void **NewBuckets = (const void**) safe_malloc(sizeof(void*) * NewSize);

                                                           
  CurArray = NewBuckets;
  CurArraySize = NewSize;
  memset(CurArray, -1, NewSize*sizeof(void*));

                                 
  for (const void **BucketPtr = OldBuckets; BucketPtr != OldEnd; ++BucketPtr) {
                                            
    const void *Elt = *BucketPtr;
    if (Elt != getTombstoneMarker() && Elt != getEmptyMarker())
      *const_cast<void**>(FindBucketFor(Elt)) = const_cast<void*>(Elt);
  }

  if (!WasSmall)
    free(OldBuckets);
  NumNonEmpty -= NumTombstones;
  NumTombstones = 0;
}

SmallPtrSetImplBase::SmallPtrSetImplBase(const void **SmallStorage,
                                         const SmallPtrSetImplBase &that) {
  SmallArray = SmallStorage;

                                                                    
  if (that.isSmall()) {
    CurArray = SmallArray;
                                                                      
  } else {
    CurArray = (const void**)safe_malloc(sizeof(void*) * that.CurArraySize);
  }

                              
  CopyHelper(that);
}

SmallPtrSetImplBase::SmallPtrSetImplBase(const void **SmallStorage,
                                         unsigned SmallSize,
                                         SmallPtrSetImplBase &&that) {
  SmallArray = SmallStorage;
  MoveHelper(SmallSize, std::move(that));
}

void SmallPtrSetImplBase::CopyFrom(const SmallPtrSetImplBase &RHS) {
  assert(&RHS != this && "Self-copy should be handled by the caller.");

  if (isSmall() && RHS.isSmall())
    assert(CurArraySize == RHS.CurArraySize &&
           "Cannot assign sets with different small sizes");

                                                                    
  if (RHS.isSmall()) {
    if (!isSmall())
      free(CurArray);
    CurArray = SmallArray;
                                                                      
  } else if (CurArraySize != RHS.CurArraySize) {
    if (isSmall())
      CurArray = (const void**)safe_malloc(sizeof(void*) * RHS.CurArraySize);
    else {
      const void **T = (const void**)safe_realloc(CurArray,
                                             sizeof(void*) * RHS.CurArraySize);
      CurArray = T;
    }
  }

  CopyHelper(RHS);
}

void SmallPtrSetImplBase::CopyHelper(const SmallPtrSetImplBase &RHS) {
                                 
  CurArraySize = RHS.CurArraySize;

                                              
  std::copy(RHS.CurArray, RHS.EndPointer(), CurArray);

  NumNonEmpty = RHS.NumNonEmpty;
  NumTombstones = RHS.NumTombstones;
}

void SmallPtrSetImplBase::MoveFrom(unsigned SmallSize,
                                   SmallPtrSetImplBase &&RHS) {
  if (!isSmall())
    free(CurArray);
  MoveHelper(SmallSize, std::move(RHS));
}

void SmallPtrSetImplBase::MoveHelper(unsigned SmallSize,
                                     SmallPtrSetImplBase &&RHS) {
  assert(&RHS != this && "Self-move should be handled by the caller.");

  if (RHS.isSmall()) {
                                           
    CurArray = SmallArray;
    std::copy(RHS.CurArray, RHS.CurArray + RHS.NumNonEmpty, CurArray);
  } else {
    CurArray = RHS.CurArray;
    RHS.CurArray = RHS.SmallArray;
  }

                                          
  CurArraySize = RHS.CurArraySize;
  NumNonEmpty = RHS.NumNonEmpty;
  NumTombstones = RHS.NumTombstones;

                                  
  RHS.CurArraySize = SmallSize;
  assert(RHS.CurArray == RHS.SmallArray);
  RHS.NumNonEmpty = 0;
  RHS.NumTombstones = 0;
}

void SmallPtrSetImplBase::swap(SmallPtrSetImplBase &RHS) {
  if (this == &RHS) return;

                                                                
  if (!this->isSmall() && !RHS.isSmall()) {
    std::swap(this->CurArray, RHS.CurArray);
    std::swap(this->CurArraySize, RHS.CurArraySize);
    std::swap(this->NumNonEmpty, RHS.NumNonEmpty);
    std::swap(this->NumTombstones, RHS.NumTombstones);
    return;
  }

                                                                           

                                                                                
                     
  if (!this->isSmall() && RHS.isSmall()) {
    assert(RHS.CurArray == RHS.SmallArray);
    std::copy(RHS.CurArray, RHS.CurArray + RHS.NumNonEmpty, this->SmallArray);
    std::swap(RHS.CurArraySize, this->CurArraySize);
    std::swap(this->NumNonEmpty, RHS.NumNonEmpty);
    std::swap(this->NumTombstones, RHS.NumTombstones);
    RHS.CurArray = this->CurArray;
    this->CurArray = this->SmallArray;
    return;
  }

                                                                                
                     
  if (this->isSmall() && !RHS.isSmall()) {
    assert(this->CurArray == this->SmallArray);
    std::copy(this->CurArray, this->CurArray + this->NumNonEmpty,
              RHS.SmallArray);
    std::swap(RHS.CurArraySize, this->CurArraySize);
    std::swap(RHS.NumNonEmpty, this->NumNonEmpty);
    std::swap(RHS.NumTombstones, this->NumTombstones);
    this->CurArray = RHS.CurArray;
    RHS.CurArray = RHS.SmallArray;
    return;
  }

                                                
  assert(this->isSmall() && RHS.isSmall());
  unsigned MinNonEmpty = std::min(this->NumNonEmpty, RHS.NumNonEmpty);
  std::swap_ranges(this->SmallArray, this->SmallArray + MinNonEmpty,
                   RHS.SmallArray);
  if (this->NumNonEmpty > MinNonEmpty) {
    std::copy(this->SmallArray + MinNonEmpty,
              this->SmallArray + this->NumNonEmpty,
              RHS.SmallArray + MinNonEmpty);
  } else {
    std::copy(RHS.SmallArray + MinNonEmpty, RHS.SmallArray + RHS.NumNonEmpty,
              this->SmallArray + MinNonEmpty);
  }
  assert(this->CurArraySize == RHS.CurArraySize);
  std::swap(this->NumNonEmpty, RHS.NumNonEmpty);
  std::swap(this->NumTombstones, RHS.NumTombstones);
}

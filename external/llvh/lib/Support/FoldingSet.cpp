//===-- Support/FoldingSet.cpp - Uniquing Hash Set --------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements a hash set that can be used to remove duplication of
// nodes in a graph.
//
//===----------------------------------------------------------------------===//

#include "llvh/ADT/FoldingSet.h"
#include "llvh/ADT/Hashing.h"
#include "llvh/Support/Allocator.h"
#include "llvh/Support/ErrorHandling.h"
#include "llvh/Support/Host.h"
#include "llvh/Support/MathExtras.h"
#include <cassert>
#include <cstring>
using namespace llvh;

                                                                                
                                     

                                                                           
                                                  
unsigned FoldingSetNodeIDRef::ComputeHash() const {
  return static_cast<unsigned>(hash_combine_range(Data, Data+Size));
}

bool FoldingSetNodeIDRef::operator==(FoldingSetNodeIDRef RHS) const {
  if (Size != RHS.Size) return false;
  return memcmp(Data, RHS.Data, Size*sizeof(*Data)) == 0;
}

                                                                 
                                                         
bool FoldingSetNodeIDRef::operator<(FoldingSetNodeIDRef RHS) const {
  if (Size != RHS.Size)
    return Size < RHS.Size;
  return memcmp(Data, RHS.Data, Size*sizeof(*Data)) < 0;
}

                                                                                
                                  

                                              
   
void FoldingSetNodeID::AddPointer(const void *Ptr) {
                                                                         
                                                                       
                                                                        
                                          
  static_assert(sizeof(uintptr_t) <= sizeof(unsigned long long),
                "unexpected pointer size");
  AddInteger(reinterpret_cast<uintptr_t>(Ptr));
}
void FoldingSetNodeID::AddInteger(signed I) {
  Bits.push_back(I);
}
void FoldingSetNodeID::AddInteger(unsigned I) {
  Bits.push_back(I);
}
void FoldingSetNodeID::AddInteger(long I) {
  AddInteger((unsigned long)I);
}
void FoldingSetNodeID::AddInteger(unsigned long I) {
  if (sizeof(long) == sizeof(int))
    AddInteger(unsigned(I));
  else if (sizeof(long) == sizeof(long long)) {
    AddInteger((unsigned long long)I);
  } else {
    llvm_unreachable("unexpected sizeof(long)");
  }
}
void FoldingSetNodeID::AddInteger(long long I) {
  AddInteger((unsigned long long)I);
}
void FoldingSetNodeID::AddInteger(unsigned long long I) {
  AddInteger(unsigned(I));
  AddInteger(unsigned(I >> 32));
}

void FoldingSetNodeID::AddString(StringRef String) {
  unsigned Size =  String.size();
  Bits.push_back(Size);
  if (!Size) return;

  unsigned Units = Size / 4;
  unsigned Pos = 0;
  const unsigned *Base = (const unsigned*) String.data();

                                                 
  if (!((intptr_t)Base & 3)) {
    Bits.append(Base, Base + Units);
    Pos = (Units + 1) * 4;
  } else {
                                    
                                                                            
                    
    static_assert(sys::IsBigEndianHost || sys::IsLittleEndianHost,
                  "Unexpected host endianness");
    if (sys::IsBigEndianHost) {
      for (Pos += 4; Pos <= Size; Pos += 4) {
        unsigned V = ((unsigned char)String[Pos - 4] << 24) |
                     ((unsigned char)String[Pos - 3] << 16) |
                     ((unsigned char)String[Pos - 2] << 8) |
                      (unsigned char)String[Pos - 1];
        Bits.push_back(V);
      }
    } else {                       
      for (Pos += 4; Pos <= Size; Pos += 4) {
        unsigned V = ((unsigned char)String[Pos - 1] << 24) |
                     ((unsigned char)String[Pos - 2] << 16) |
                     ((unsigned char)String[Pos - 3] << 8) |
                      (unsigned char)String[Pos - 4];
        Bits.push_back(V);
      }
    }
  }

                            
  unsigned V = 0;
                                                         
                                                                            
  switch (Pos - Size) {
  case 1: V = (V << 8) | (unsigned char)String[Size - 3]; LLVM_FALLTHROUGH;
  case 2: V = (V << 8) | (unsigned char)String[Size - 2]; LLVM_FALLTHROUGH;
  case 3: V = (V << 8) | (unsigned char)String[Size - 1]; break;
  default: return;                 
  }

  Bits.push_back(V);
}

                                                        
void FoldingSetNodeID::AddNodeID(const FoldingSetNodeID &ID) {
  Bits.append(ID.Bits.begin(), ID.Bits.end());
}

                                                                                
                                          
unsigned FoldingSetNodeID::ComputeHash() const {
  return FoldingSetNodeIDRef(Bits.data(), Bits.size()).ComputeHash();
}

                                                         
   
bool FoldingSetNodeID::operator==(const FoldingSetNodeID &RHS) const {
  return *this == FoldingSetNodeIDRef(RHS.Bits.data(), RHS.Bits.size());
}

                                                         
   
bool FoldingSetNodeID::operator==(FoldingSetNodeIDRef RHS) const {
  return FoldingSetNodeIDRef(Bits.data(), Bits.size()) == RHS;
}

                                                                 
                                                         
bool FoldingSetNodeID::operator<(const FoldingSetNodeID &RHS) const {
  return *this < FoldingSetNodeIDRef(RHS.Bits.data(), RHS.Bits.size());
}

bool FoldingSetNodeID::operator<(FoldingSetNodeIDRef RHS) const {
  return FoldingSetNodeIDRef(Bits.data(), Bits.size()) < RHS;
}

                                                                        
                                                                   
                  
FoldingSetNodeIDRef
FoldingSetNodeID::Intern(BumpPtrAllocator &Allocator) const {
  unsigned *New = Allocator.Allocate<unsigned>(Bits.size());
  std::uninitialized_copy(Bits.begin(), Bits.end(), New);
  return FoldingSetNodeIDRef(New, Bits.size());
}

                                                                                
                                        

                                                         
                                                                         
                                                                          
                                                                       
                                                                             
                                       
static FoldingSetBase::Node *GetNextPtr(void *NextInBucketPtr) {
                                                                  
  if (reinterpret_cast<intptr_t>(NextInBucketPtr) & 1)
    return nullptr;

  return static_cast<FoldingSetBase::Node*>(NextInBucketPtr);
}


            
static void **GetBucketPtr(void *NextInBucketPtr) {
  intptr_t Ptr = reinterpret_cast<intptr_t>(NextInBucketPtr);
  assert((Ptr & 1) && "Not a bucket pointer");
  return reinterpret_cast<void**>(Ptr & ~intptr_t(1));
}

                                                                            
                     
static void **GetBucketFor(unsigned Hash, void **Buckets, unsigned NumBuckets) {
                                       
  unsigned BucketNum = Hash & (NumBuckets-1);
  return Buckets + BucketNum;
}

                                                          
static void **AllocateBuckets(unsigned NumBuckets) {
  void **Buckets = static_cast<void**>(safe_calloc(NumBuckets + 1,
                                                   sizeof(void*)));
                                                         
  Buckets[NumBuckets] = reinterpret_cast<void*>(-1);
  return Buckets;
}

                                                                                
                                

void FoldingSetBase::anchor() {}

FoldingSetBase::FoldingSetBase(unsigned Log2InitSize) {
  assert(5 < Log2InitSize && Log2InitSize < 32 &&
         "Initial hash table size out of range");
  NumBuckets = 1 << Log2InitSize;
  Buckets = AllocateBuckets(NumBuckets);
  NumNodes = 0;
}

FoldingSetBase::FoldingSetBase(FoldingSetBase &&Arg)
    : Buckets(Arg.Buckets), NumBuckets(Arg.NumBuckets), NumNodes(Arg.NumNodes) {
  Arg.Buckets = nullptr;
  Arg.NumBuckets = 0;
  Arg.NumNodes = 0;
}

FoldingSetBase &FoldingSetBase::operator=(FoldingSetBase &&RHS) {
  free(Buckets);                                                         
  Buckets = RHS.Buckets;
  NumBuckets = RHS.NumBuckets;
  NumNodes = RHS.NumNodes;
  RHS.Buckets = nullptr;
  RHS.NumBuckets = 0;
  RHS.NumNodes = 0;
  return *this;
}

FoldingSetBase::~FoldingSetBase() {
  free(Buckets);
}

void FoldingSetBase::clear() {
                                                  
  memset(Buckets, 0, NumBuckets*sizeof(void*));

                                                         
  Buckets[NumBuckets] = reinterpret_cast<void*>(-1);

                                  
  NumNodes = 0;
}

void FoldingSetBase::GrowBucketCount(unsigned NewBucketCount) {
  assert((NewBucketCount > NumBuckets) && "Can't shrink a folding set with GrowBucketCount");
  assert(isPowerOf2_32(NewBucketCount) && "Bad bucket count!");
  void **OldBuckets = Buckets;
  unsigned OldNumBuckets = NumBuckets;

                           
  Buckets = AllocateBuckets(NewBucketCount);
                                                                     
  NumBuckets = NewBucketCount;
  NumNodes = 0;

                                                                
  FoldingSetNodeID TempID;
  for (unsigned i = 0; i != OldNumBuckets; ++i) {
    void *Probe = OldBuckets[i];
    if (!Probe) continue;
    while (Node *NodeInBucket = GetNextPtr(Probe)) {
                                                                         
      Probe = NodeInBucket->getNextInBucket();
      NodeInBucket->SetNextInBucket(nullptr);

                                                                         
      InsertNode(NodeInBucket,
                 GetBucketFor(ComputeNodeHash(NodeInBucket, TempID),
                              Buckets, NumBuckets));
      TempID.clear();
    }
  }

  free(OldBuckets);
}

                                                                            
   
void FoldingSetBase::GrowHashTable() {
  GrowBucketCount(NumBuckets * 2);
}

void FoldingSetBase::reserve(unsigned EltCount) {
                                                         
                                                       
                        
  if(EltCount < capacity())
    return;
  GrowBucketCount(PowerOf2Floor(EltCount));
}

                                                                          
                                                                           
           
FoldingSetBase::Node *
FoldingSetBase::FindNodeOrInsertPos(const FoldingSetNodeID &ID,
                                    void *&InsertPos) {
  unsigned IDHash = ID.ComputeHash();
  void **Bucket = GetBucketFor(IDHash, Buckets, NumBuckets);
  void *Probe = *Bucket;

  InsertPos = nullptr;

  FoldingSetNodeID TempID;
  while (Node *NodeInBucket = GetNextPtr(Probe)) {
    if (NodeEquals(NodeInBucket, ID, IDHash, TempID))
      return NodeInBucket;
    TempID.clear();

    Probe = NodeInBucket->getNextInBucket();
  }

                                                                        
  InsertPos = Bucket;
  return nullptr;
}

                                                                                
                                                               
                        
void FoldingSetBase::InsertNode(Node *N, void *InsertPos) {
  assert(!N->getNextInBucket());
                                      
  if (NumNodes+1 > capacity()) {
    GrowHashTable();
    FoldingSetNodeID TempID;
    InsertPos = GetBucketFor(ComputeNodeHash(N, TempID), Buckets, NumBuckets);
  }

  ++NumNodes;

                                                       
  void **Bucket = static_cast<void**>(InsertPos);

  void *Next = *Bucket;

                                                                              
                                                                               
                                        
  if (!Next)
    Next = reinterpret_cast<void*>(reinterpret_cast<intptr_t>(Bucket)|1);

                                                                        
  N->SetNextInBucket(Next);
  *Bucket = N;
}

                                                                              
                                                            
bool FoldingSetBase::RemoveNode(Node *N) {
                                                                              
                  
  void *Ptr = N->getNextInBucket();
  if (!Ptr) return false;                        

  --NumNodes;
  N->SetNextInBucket(nullptr);

                                                                            
  void *NodeNextPtr = Ptr;

                                                                                
  while (true) {
    if (Node *NodeInBucket = GetNextPtr(Ptr)) {
                         
      Ptr = NodeInBucket->getNextInBucket();

                                                                               
                                  
      if (Ptr == N) {
        NodeInBucket->SetNextInBucket(NodeNextPtr);
        return true;
      }
    } else {
      void **Bucket = GetBucketPtr(Ptr);
      Ptr = *Bucket;

                                                                               
                          
      if (Ptr == N) {
        *Bucket = NodeNextPtr;
        return true;
      }
    }
  }
}

                                                                 
                                                                         
            
FoldingSetBase::Node *FoldingSetBase::GetOrInsertNode(FoldingSetBase::Node *N) {
  FoldingSetNodeID ID;
  GetNodeProfile(N, ID);
  void *IP;
  if (Node *E = FindNodeOrInsertPos(ID, IP))
    return E;
  InsertNode(N, IP);
  return N;
}

                                                                                
                                        

FoldingSetIteratorImpl::FoldingSetIteratorImpl(void **Bucket) {
                                                      
  while (*Bucket != reinterpret_cast<void*>(-1) &&
         (!*Bucket || !GetNextPtr(*Bucket)))
    ++Bucket;

  NodePtr = static_cast<FoldingSetNode*>(*Bucket);
}

void FoldingSetIteratorImpl::advance() {
                                                           
  void *Probe = NodePtr->getNextInBucket();

  if (FoldingSetNode *NextNodeInBucket = GetNextPtr(Probe))
    NodePtr = NextNodeInBucket;
  else {
                                                       
    void **Bucket = GetBucketPtr(Probe);

                                                       
    do {
      ++Bucket;
    } while (*Bucket != reinterpret_cast<void*>(-1) &&
             (!*Bucket || !GetNextPtr(*Bucket)));

    NodePtr = static_cast<FoldingSetNode*>(*Bucket);
  }
}

                                                                                
                                              

FoldingSetBucketIteratorImpl::FoldingSetBucketIteratorImpl(void **Bucket) {
  Ptr = (!*Bucket || !GetNextPtr(*Bucket)) ? (void*) Bucket : *Bucket;
}

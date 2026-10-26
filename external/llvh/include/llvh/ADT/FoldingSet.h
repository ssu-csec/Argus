//===- llvm/ADT/FoldingSet.h - Uniquing Hash Set ----------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines a hash set that can be used to remove duplication of nodes
// in a graph.  This code was originally created by Chris Lattner for use with
// SelectionDAGCSEMap, but was isolated to provide use across the llvm code set.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_FOLDINGSET_H
#define LLVM_ADT_FOLDINGSET_H

#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/iterator.h"
#include "llvh/Support/Allocator.h"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace llvh {

                                           
                                                                             
                                                                             
                                                                    
                                                                            
   
                                                                            
                                                                           
                                                                             
   
                                                                            
                                                                             
                                                                          
                                                                            
                                                                               
                                                                   
                                                       
   
       
                                             
               
                          
                        
              
                                                                 
             
                                                   
                              
                                
          
            
         
   
                                                                 
   
       
                                       
   
                                                                    
   
                                                                           
                                                
   
                                                   
   
                                                                        
                                                                          
                                                    
   
                                                                           
                                                                                
          
   
                          
                         
                           
                        
   
                                                                     
   
                                                                             
                                        
   
                                                                              
                                  
   
                                  
   
                                                                       
   
                                       
   
                                                                     

class FoldingSetNodeID;
class StringRef;

                                                                                
                                                                        
                                                                            
                                                                           
                                                                             
                                                  
   
class FoldingSetBase {
  virtual void anchor();                               

protected:
                                       
  void **Buckets;

                                                                     
  unsigned NumBuckets;

                                                                                
                                                  
  unsigned NumNodes;

  explicit FoldingSetBase(unsigned Log2InitSize = 6);
  FoldingSetBase(FoldingSetBase &&Arg);
  FoldingSetBase &operator=(FoldingSetBase &&RHS);
  ~FoldingSetBase();

public:
                                                                                
                                                                            
                    
  class Node {
  private:
                                                             
    void *NextInFoldingSetBucket = nullptr;

  public:
    Node() = default;

                
    void *getNextInBucket() const { return NextInFoldingSetBucket; }
    void SetNextInBucket(void *N) { NextInFoldingSetBucket = N; }
  };

                                                    
  void clear();

                                                            
  unsigned size() const { return NumNodes; }

                                                                    
  bool empty() const { return NumNodes == 0; }

                                                                   
                                                                             
                                                        
  void reserve(unsigned EltCount);

                                                                         
                                               
  unsigned capacity() {
                                           
                                                   
    return NumBuckets * 2;
  }

private:
                                                                              
  void GrowHashTable();

                                                                    
                                                                             
                   
  void GrowBucketCount(unsigned NewBucketCount);

protected:
                                                                          
                                                           
  virtual void GetNodeProfile(Node *N, FoldingSetNodeID &ID) const = 0;

                                                                      
                                                                
  virtual bool NodeEquals(Node *N, const FoldingSetNodeID &ID, unsigned IDHash,
                          FoldingSetNodeID &TempID) const=0;

                                                                           
                                                               
  virtual unsigned ComputeNodeHash(Node *N, FoldingSetNodeID &TempID) const = 0;

                                                                              
                   

                                                                            
                                                                  
  bool RemoveNode(Node *N);

                                                                   
                                                                               
                 
  Node *GetOrInsertNode(Node *N);

                                                                            
                                                                             
             
  Node *FindNodeOrInsertPos(const FoldingSetNodeID &ID, void *&InsertPos);

                                                                               
                                                                            
                          
  void InsertNode(Node *N, void *InsertPos);
};

                                                                                

                                                                        
                                        
template<typename T> struct DefaultFoldingSetTrait {
  static void Profile(const T &X, FoldingSetNodeID &ID) {
    X.Profile(ID);
  }
  static void Profile(T &X, FoldingSetNodeID &ID) {
    X.Profile(ID);
  }

                                                                    
                                                                       
                                                                      
                                                                 
  static inline bool Equals(T &X, const FoldingSetNodeID &ID, unsigned IDHash,
                            FoldingSetNodeID &TempID);

                                                              
                                                                    
                                                            
                                                                
                     
  static inline unsigned ComputeHash(T &X, FoldingSetNodeID &TempID);
};

                                                                        
                                                                        
                                                                          
                                                                             
                                                                              
                                                                           
template<typename T> struct FoldingSetTrait
  : public DefaultFoldingSetTrait<T> {};

                                                                       
                              
template<typename T, typename Ctx>
struct DefaultContextualFoldingSetTrait {
  static void Profile(T &X, FoldingSetNodeID &ID, Ctx Context) {
    X.Profile(ID, Context);
  }

  static inline bool Equals(T &X, const FoldingSetNodeID &ID, unsigned IDHash,
                            FoldingSetNodeID &TempID, Ctx Context);
  static inline unsigned ComputeHash(T &X, FoldingSetNodeID &TempID,
                                     Ctx Context);
};

                                                             
                          
template<typename T, typename Ctx> struct ContextualFoldingSetTrait
  : public DefaultContextualFoldingSetTrait<T, Ctx> {};

                                                                              
                                                                         
                                                                        
                                                                        
                                                                    
                                                               
class FoldingSetNodeIDRef {
  const unsigned *Data = nullptr;
  size_t Size = 0;

public:
  FoldingSetNodeIDRef() = default;
  FoldingSetNodeIDRef(const unsigned *D, size_t S) : Data(D), Size(S) {}

                                                                             
                                                    
  unsigned ComputeHash() const;

  bool operator==(FoldingSetNodeIDRef) const;

  bool operator!=(FoldingSetNodeIDRef RHS) const { return !(*this == RHS); }

                                                                   
                                                           
  bool operator<(FoldingSetNodeIDRef) const;

  const unsigned *getData() const { return Data; }
  size_t getSize() const { return Size; }
};

                                                                              
                                                                               
                                                                           
                            
class FoldingSetNodeID {
                                                                   
                                                                      
  SmallVector<unsigned, 32> Bits;

public:
  FoldingSetNodeID() = default;

  FoldingSetNodeID(FoldingSetNodeIDRef Ref)
    : Bits(Ref.getData(), Ref.getData() + Ref.getSize()) {}

                                                
  void AddPointer(const void *Ptr);
  void AddInteger(signed I);
  void AddInteger(unsigned I);
  void AddInteger(long I);
  void AddInteger(unsigned long I);
  void AddInteger(long long I);
  void AddInteger(unsigned long long I);
  void AddBoolean(bool B) { AddInteger(B ? 1U : 0U); }
  void AddString(StringRef String);
  void AddNodeID(const FoldingSetNodeID &ID);

  template <typename T>
  inline void Add(const T &x) { FoldingSetTrait<T>::Profile(x, *this); }

                                                                           
                                                 
  inline void clear() { Bits.clear(); }

                                                                               
                                               
  unsigned ComputeHash() const;

                                                           
  bool operator==(const FoldingSetNodeID &RHS) const;
  bool operator==(const FoldingSetNodeIDRef RHS) const;

  bool operator!=(const FoldingSetNodeID &RHS) const { return !(*this == RHS); }
  bool operator!=(const FoldingSetNodeIDRef RHS) const { return !(*this ==RHS);}

                                                                   
                                                           
  bool operator<(const FoldingSetNodeID &RHS) const;
  bool operator<(const FoldingSetNodeIDRef RHS) const;

                                                                          
                                                                     
                    
  FoldingSetNodeIDRef Intern(BumpPtrAllocator &Allocator) const;
};

                                                                  
using FoldingSetNode = FoldingSetBase::Node;
template<class T> class FoldingSetIterator;
template<class T> class FoldingSetBucketIterator;

                                                                                
                                              
template<typename T>
inline bool
DefaultFoldingSetTrait<T>::Equals(T &X, const FoldingSetNodeID &ID,
                                  unsigned           ,
                                  FoldingSetNodeID &TempID) {
  FoldingSetTrait<T>::Profile(X, TempID);
  return TempID == ID;
}
template<typename T>
inline unsigned
DefaultFoldingSetTrait<T>::ComputeHash(T &X, FoldingSetNodeID &TempID) {
  FoldingSetTrait<T>::Profile(X, TempID);
  return TempID.ComputeHash();
}
template<typename T, typename Ctx>
inline bool
DefaultContextualFoldingSetTrait<T, Ctx>::Equals(T &X,
                                                 const FoldingSetNodeID &ID,
                                                 unsigned           ,
                                                 FoldingSetNodeID &TempID,
                                                 Ctx Context) {
  ContextualFoldingSetTrait<T, Ctx>::Profile(X, TempID, Context);
  return TempID == ID;
}
template<typename T, typename Ctx>
inline unsigned
DefaultContextualFoldingSetTrait<T, Ctx>::ComputeHash(T &X,
                                                      FoldingSetNodeID &TempID,
                                                      Ctx Context) {
  ContextualFoldingSetTrait<T, Ctx>::Profile(X, TempID, Context);
  return TempID.ComputeHash();
}

                                                                                
                                                                             
                                        
template <class T> class FoldingSetImpl : public FoldingSetBase {
protected:
  explicit FoldingSetImpl(unsigned Log2InitSize)
      : FoldingSetBase(Log2InitSize) {}

  FoldingSetImpl(FoldingSetImpl &&Arg) = default;
  FoldingSetImpl &operator=(FoldingSetImpl &&RHS) = default;
  ~FoldingSetImpl() = default;

public:
  using iterator = FoldingSetIterator<T>;

  iterator begin() { return iterator(Buckets); }
  iterator end() { return iterator(Buckets+NumBuckets); }

  using const_iterator = FoldingSetIterator<const T>;

  const_iterator begin() const { return const_iterator(Buckets); }
  const_iterator end() const { return const_iterator(Buckets+NumBuckets); }

  using bucket_iterator = FoldingSetBucketIterator<T>;

  bucket_iterator bucket_begin(unsigned hash) {
    return bucket_iterator(Buckets + (hash & (NumBuckets-1)));
  }

  bucket_iterator bucket_end(unsigned hash) {
    return bucket_iterator(Buckets + (hash & (NumBuckets-1)), true);
  }

                                                                            
                                                                  
  bool RemoveNode(T *N) { return FoldingSetBase::RemoveNode(N); }

                                                                   
                                                                        
                        
  T *GetOrInsertNode(T *N) {
    return static_cast<T *>(FoldingSetBase::GetOrInsertNode(N));
  }

                                                                            
                                                                             
             
  T *FindNodeOrInsertPos(const FoldingSetNodeID &ID, void *&InsertPos) {
    return static_cast<T *>(FoldingSetBase::FindNodeOrInsertPos(ID, InsertPos));
  }

                                                                               
                                                                            
                          
  void InsertNode(T *N, void *InsertPos) {
    FoldingSetBase::InsertNode(N, InsertPos);
  }

                                                                               
                                           
  void InsertNode(T *N) {
    T *Inserted = GetOrInsertNode(N);
    (void)Inserted;
    assert(Inserted == N && "Node already inserted!");
  }
};

                                                                                
                                                                         
                                                                       
                                                                
   
                                                                        
                                                                 
                                                                           
                                   
template <class T> class FoldingSet final : public FoldingSetImpl<T> {
  using Super = FoldingSetImpl<T>;
  using Node = typename Super::Node;

                                                                                
                                                   
  void GetNodeProfile(Node *N, FoldingSetNodeID &ID) const override {
    T *TN = static_cast<T *>(N);
    FoldingSetTrait<T>::Profile(*TN, ID);
  }

                                                                           
                               
  bool NodeEquals(Node *N, const FoldingSetNodeID &ID, unsigned IDHash,
                  FoldingSetNodeID &TempID) const override {
    T *TN = static_cast<T *>(N);
    return FoldingSetTrait<T>::Equals(*TN, ID, IDHash, TempID);
  }

                                                                                
                                      
  unsigned ComputeNodeHash(Node *N, FoldingSetNodeID &TempID) const override {
    T *TN = static_cast<T *>(N);
    return FoldingSetTrait<T>::ComputeHash(*TN, TempID);
  }

public:
  explicit FoldingSet(unsigned Log2InitSize = 6) : Super(Log2InitSize) {}
  FoldingSet(FoldingSet &&Arg) = default;
  FoldingSet &operator=(FoldingSet &&RHS) = default;
};

                                                                                
                                                                      
                                                                
                                                               
                        
   
                                                                  
                           
                                            
template <class T, class Ctx>
class ContextualFoldingSet final : public FoldingSetImpl<T> {
                                                                    
                                                          
                                                                    
                                             

  using Super = FoldingSetImpl<T>;
  using Node = typename Super::Node;

  Ctx Context;

                                                                                
                                                   
  void GetNodeProfile(Node *N, FoldingSetNodeID &ID) const override {
    T *TN = static_cast<T *>(N);
    ContextualFoldingSetTrait<T, Ctx>::Profile(*TN, ID, Context);
  }

  bool NodeEquals(Node *N, const FoldingSetNodeID &ID, unsigned IDHash,
                  FoldingSetNodeID &TempID) const override {
    T *TN = static_cast<T *>(N);
    return ContextualFoldingSetTrait<T, Ctx>::Equals(*TN, ID, IDHash, TempID,
                                                     Context);
  }

  unsigned ComputeNodeHash(Node *N, FoldingSetNodeID &TempID) const override {
    T *TN = static_cast<T *>(N);
    return ContextualFoldingSetTrait<T, Ctx>::ComputeHash(*TN, TempID, Context);
  }

public:
  explicit ContextualFoldingSet(Ctx Context, unsigned Log2InitSize = 6)
      : Super(Log2InitSize), Context(Context) {}

  Ctx getContext() const { return Context; }
};

                                                                                
                                                                             
                                                                           
                                                                              
                                     
template <class T, class VectorT = SmallVector<T*, 8>>
class FoldingSetVector {
  FoldingSet<T> Set;
  VectorT Vector;

public:
  explicit FoldingSetVector(unsigned Log2InitSize = 6) : Set(Log2InitSize) {}

  using iterator = pointee_iterator<typename VectorT::iterator>;

  iterator begin() { return Vector.begin(); }
  iterator end()   { return Vector.end(); }

  using const_iterator = pointee_iterator<typename VectorT::const_iterator>;

  const_iterator begin() const { return Vector.begin(); }
  const_iterator end()   const { return Vector.end(); }

                                                    
  void clear() { Set.clear(); Vector.clear(); }

                                                                            
                                                                             
             
  T *FindNodeOrInsertPos(const FoldingSetNodeID &ID, void *&InsertPos) {
    return Set.FindNodeOrInsertPos(ID, InsertPos);
  }

                                                                   
                                                                        
                        
  T *GetOrInsertNode(T *N) {
    T *Result = Set.GetOrInsertNode(N);
    if (Result == N) Vector.push_back(N);
    return Result;
  }

                                                                               
                                                                            
                          
  void InsertNode(T *N, void *InsertPos) {
    Set.InsertNode(N, InsertPos);
    Vector.push_back(N);
  }

                                                                               
                                           
  void InsertNode(T *N) {
    Set.InsertNode(N);
    Vector.push_back(N);
  }

                                                            
  unsigned size() const { return Set.size(); }

                                                                    
  bool empty() const { return Set.empty(); }
};

                                                                                
                                                                              
                                                                     
class FoldingSetIteratorImpl {
protected:
  FoldingSetNode *NodePtr;

  FoldingSetIteratorImpl(void **Bucket);

  void advance();

public:
  bool operator==(const FoldingSetIteratorImpl &RHS) const {
    return NodePtr == RHS.NodePtr;
  }
  bool operator!=(const FoldingSetIteratorImpl &RHS) const {
    return NodePtr != RHS.NodePtr;
  }
};

template <class T> class FoldingSetIterator : public FoldingSetIteratorImpl {
public:
  explicit FoldingSetIterator(void **Bucket) : FoldingSetIteratorImpl(Bucket) {}

  T &operator*() const {
    return *static_cast<T*>(NodePtr);
  }

  T *operator->() const {
    return static_cast<T*>(NodePtr);
  }

  inline FoldingSetIterator &operator++() {                         
    advance();
    return *this;
  }
  FoldingSetIterator operator++(int) {                        
    FoldingSetIterator tmp = *this; ++*this; return tmp;
  }
};

                                                                                
                                                                             
                                                                           
                                
class FoldingSetBucketIteratorImpl {
protected:
  void *Ptr;

  explicit FoldingSetBucketIteratorImpl(void **Bucket);

  FoldingSetBucketIteratorImpl(void **Bucket, bool) : Ptr(Bucket) {}

  void advance() {
    void *Probe = static_cast<FoldingSetNode*>(Ptr)->getNextInBucket();
    uintptr_t x = reinterpret_cast<uintptr_t>(Probe) & ~0x1;
    Ptr = reinterpret_cast<void*>(x);
  }

public:
  bool operator==(const FoldingSetBucketIteratorImpl &RHS) const {
    return Ptr == RHS.Ptr;
  }
  bool operator!=(const FoldingSetBucketIteratorImpl &RHS) const {
    return Ptr != RHS.Ptr;
  }
};

template <class T>
class FoldingSetBucketIterator : public FoldingSetBucketIteratorImpl {
public:
  explicit FoldingSetBucketIterator(void **Bucket) :
    FoldingSetBucketIteratorImpl(Bucket) {}

  FoldingSetBucketIterator(void **Bucket, bool) :
    FoldingSetBucketIteratorImpl(Bucket, true) {}

  T &operator*() const { return *static_cast<T*>(Ptr); }
  T *operator->() const { return static_cast<T*>(Ptr); }

  inline FoldingSetBucketIterator &operator++() {                
    advance();
    return *this;
  }
  FoldingSetBucketIterator operator++(int) {                      
    FoldingSetBucketIterator tmp = *this; ++*this; return tmp;
  }
};

                                                                                
                                                                           
                                                                               
template <typename T>
class FoldingSetNodeWrapper : public FoldingSetNode {
  T data;

public:
  template <typename... Ts>
  explicit FoldingSetNodeWrapper(Ts &&... Args)
      : data(std::forward<Ts>(Args)...) {}

  void Profile(FoldingSetNodeID &ID) { FoldingSetTrait<T>::Profile(data, ID); }

  T &getValue() { return data; }
  const T &getValue() const { return data; }

  operator T&() { return data; }
  operator const T&() const { return data; }
};

                                                                                
                                                                          
                                                                           
                                                                     
                                                                     
                                                                            
class FastFoldingSetNode : public FoldingSetNode {
  FoldingSetNodeID FastID;

protected:
  explicit FastFoldingSetNode(const FoldingSetNodeID &ID) : FastID(ID) {}

public:
  void Profile(FoldingSetNodeID &ID) const { ID.AddNodeID(FastID); }
};

                                                                                
                                              

template<typename T> struct FoldingSetTrait<T*> {
  static inline void Profile(T *X, FoldingSetNodeID &ID) {
    ID.AddPointer(X);
  }
};
template <typename T1, typename T2>
struct FoldingSetTrait<std::pair<T1, T2>> {
  static inline void Profile(const std::pair<T1, T2> &P,
                             FoldingSetNodeID &ID) {
    ID.Add(P.first);
    ID.Add(P.second);
  }
};

}                      

#endif                         

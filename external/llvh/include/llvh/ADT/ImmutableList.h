//==--- ImmutableList.h - Immutable (functional) list interface --*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the ImmutableList class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_IMMUTABLELIST_H
#define LLVM_ADT_IMMUTABLELIST_H

#include "llvh/ADT/FoldingSet.h"
#include "llvh/Support/Allocator.h"
#include <cassert>
#include <cstdint>
#include <new>

namespace llvh {

template <typename T> class ImmutableListFactory;

template <typename T>
class ImmutableListImpl : public FoldingSetNode {
  friend class ImmutableListFactory<T>;

  T Head;
  const ImmutableListImpl* Tail;

  template <typename ElemT>
  ImmutableListImpl(ElemT &&head, const ImmutableListImpl *tail = nullptr)
    : Head(std::forward<ElemT>(head)), Tail(tail) {}

public:
  ImmutableListImpl(const ImmutableListImpl &) = delete;
  ImmutableListImpl &operator=(const ImmutableListImpl &) = delete;

  const T& getHead() const { return Head; }
  const ImmutableListImpl* getTail() const { return Tail; }

  static inline void Profile(FoldingSetNodeID& ID, const T& H,
                             const ImmutableListImpl* L){
    ID.AddPointer(L);
    ID.Add(H);
  }

  void Profile(FoldingSetNodeID& ID) {
    Profile(ID, Head, Tail);
  }
};

                                                                         
                                                                          
                                                                         
                                                                         
                                                                        
                                                                        
                                                                          
                                                  
template <typename T>
class ImmutableList {
public:
  using value_type = T;
  using Factory = ImmutableListFactory<T>;

  static_assert(std::is_trivially_destructible<T>::value,
                "T must be trivially destructible!");

private:
  const ImmutableListImpl<T>* X;

public:
                                                                                
                                                                                
                                                     
  ImmutableList(const ImmutableListImpl<T>* x = nullptr) : X(x) {}

  const ImmutableListImpl<T>* getInternalPointer() const {
    return X;
  }

  class iterator {
    const ImmutableListImpl<T>* L = nullptr;

  public:
    iterator() = default;
    iterator(ImmutableList l) : L(l.getInternalPointer()) {}

    iterator& operator++() { L = L->getTail(); return *this; }
    bool operator==(const iterator& I) const { return L == I.L; }
    bool operator!=(const iterator& I) const { return L != I.L; }
    const value_type& operator*() const { return L->getHead(); }
    const typename std::remove_reference<value_type>::type* operator->() const {
      return &L->getHead();
    }

    ImmutableList getList() const { return L; }
  };

                                                                       
                                                                     
  iterator begin() const { return iterator(X); }

                                                                            
                                              
  iterator end() const { return iterator(); }

                                                  
  bool isEmpty() const { return !X; }

  bool contains(const T& V) const {
    for (iterator I = begin(), E = end(); I != E; ++I) {
      if (*I == V)
        return true;
    }
    return false;
  }

                                                                               
                                                                               
                                                                            
                                                                   
                            
  bool isEqual(const ImmutableList& L) const { return X == L.X; }

  bool operator==(const ImmutableList& L) const { return isEqual(L); }

                                             
  const T& getHead() const {
    assert(!isEmpty() && "Cannot get the head of an empty list.");
    return X->getHead();
  }

                                                                               
                     
  ImmutableList getTail() const {
    return X ? X->getTail() : nullptr;
  }

  void Profile(FoldingSetNodeID& ID) const {
    ID.AddPointer(X);
  }
};

template <typename T>
class ImmutableListFactory {
  using ListTy = ImmutableListImpl<T>;
  using CacheTy = FoldingSet<ListTy>;

  CacheTy Cache;
  uintptr_t Allocator;

  bool ownsAllocator() const {
    return (Allocator & 0x1) == 0;
  }

  BumpPtrAllocator& getAllocator() const {
    return *reinterpret_cast<BumpPtrAllocator*>(Allocator & ~0x1);
  }

public:
  ImmutableListFactory()
    : Allocator(reinterpret_cast<uintptr_t>(new BumpPtrAllocator())) {}

  ImmutableListFactory(BumpPtrAllocator& Alloc)
  : Allocator(reinterpret_cast<uintptr_t>(&Alloc) | 0x1) {}

  ~ImmutableListFactory() {
    if (ownsAllocator()) delete &getAllocator();
  }

  template <typename ElemT>
  LLVM_NODISCARD ImmutableList<T> concat(ElemT &&Head, ImmutableList<T> Tail) {
                                                                     
    FoldingSetNodeID ID;
    void* InsertPos;

    const ListTy* TailImpl = Tail.getInternalPointer();
    ListTy::Profile(ID, Head, TailImpl);
    ListTy* L = Cache.FindNodeOrInsertPos(ID, InsertPos);

    if (!L) {
                                                          
      BumpPtrAllocator& A = getAllocator();
      L = (ListTy*) A.Allocate<ListTy>();
      new (L) ListTy(std::forward<ElemT>(Head), TailImpl);

                                            
      Cache.InsertNode(L, InsertPos);
    }

    return L;
  }

  template <typename ElemT>
  LLVM_NODISCARD ImmutableList<T> add(ElemT &&Data, ImmutableList<T> L) {
    return concat(std::forward<ElemT>(Data), L);
  }

  template <typename ...CtorArgs>
  LLVM_NODISCARD ImmutableList<T> emplace(ImmutableList<T> Tail,
                                          CtorArgs &&...Args) {
    return concat(T(std::forward<CtorArgs>(Args)...), Tail);
  }

  ImmutableList<T> getEmptyList() const {
    return ImmutableList<T>(nullptr);
  }

  template <typename ElemT>
  ImmutableList<T> create(ElemT &&Data) {
    return concat(std::forward<ElemT>(Data), getEmptyList());
  }
};

                                                                                
                                
                                                                                

template<typename T> struct DenseMapInfo;
template<typename T> struct DenseMapInfo<ImmutableList<T>> {
  static inline ImmutableList<T> getEmptyKey() {
    return reinterpret_cast<ImmutableListImpl<T>*>(-1);
  }

  static inline ImmutableList<T> getTombstoneKey() {
    return reinterpret_cast<ImmutableListImpl<T>*>(-2);
  }

  static unsigned getHashValue(ImmutableList<T> X) {
    uintptr_t PtrVal = reinterpret_cast<uintptr_t>(X.getInternalPointer());
    return (unsigned((uintptr_t)PtrVal) >> 4) ^
           (unsigned((uintptr_t)PtrVal) >> 9);
  }

  static bool isEqual(ImmutableList<T> X1, ImmutableList<T> X2) {
    return X1 == X2;
  }
};

template <typename T> struct isPodLike;
template <typename T>
struct isPodLike<ImmutableList<T>> { static const bool value = true; };

}                      

#endif                            

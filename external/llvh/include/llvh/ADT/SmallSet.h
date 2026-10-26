//===- llvm/ADT/SmallSet.h - 'Normally small' sets --------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the SmallSet class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_SMALLSET_H
#define LLVM_ADT_SMALLSET_H

#include "llvh/ADT/None.h"
#include "llvh/ADT/SmallPtrSet.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/iterator.h"
#include "llvh/Support/Compiler.h"
#include "llvh/Support/type_traits.h"
#include <cstddef>
#include <functional>
#include <set>
#include <type_traits>
#include <utility>

namespace llvh {

                                                                             
                                                              
template <typename T, unsigned N, typename C>
class SmallSetIterator
    : public iterator_facade_base<SmallSetIterator<T, N, C>,
                                  std::forward_iterator_tag, T> {
private:
  using SetIterTy = typename std::set<T, C>::const_iterator;
  using VecIterTy = typename SmallVector<T, N>::const_iterator;
  using SelfTy = SmallSetIterator<T, N, C>;

                                                                              
                           
  union {
    SetIterTy SetIter;
    VecIterTy VecIter;
  };

  bool isSmall;

public:
  SmallSetIterator(SetIterTy SetIter) : SetIter(SetIter), isSmall(false) {}

  SmallSetIterator(VecIterTy VecIter) : VecIter(VecIter), isSmall(true) {}

                                                                             
                                                                                
  ~SmallSetIterator() {
    if (isSmall)
      VecIter.~VecIterTy();
    else
      SetIter.~SetIterTy();
  }

  SmallSetIterator(const SmallSetIterator &Other) : isSmall(Other.isSmall) {
    if (isSmall)
      VecIter = Other.VecIter;
    else
                                                                              
                                                         
      new (&SetIter) SetIterTy(Other.SetIter);
  }

  SmallSetIterator(SmallSetIterator &&Other) : isSmall(Other.isSmall) {
    if (isSmall)
      VecIter = std::move(Other.VecIter);
    else
                                                                              
                                                         
      new (&SetIter) SetIterTy(std::move(Other.SetIter));
  }

  SmallSetIterator& operator=(const SmallSetIterator& Other) {
                                                                          
                                                                 
    if (!isSmall)
      SetIter.~SetIterTy();

    isSmall = Other.isSmall;
    if (isSmall)
      VecIter = Other.VecIter;
    else
      new (&SetIter) SetIterTy(Other.SetIter);
    return *this;
  }

  SmallSetIterator& operator=(SmallSetIterator&& Other) {
                                                                          
                                                                 
    if (!isSmall)
      SetIter.~SetIterTy();

    isSmall = Other.isSmall;
    if (isSmall)
      VecIter = std::move(Other.VecIter);
    else
      new (&SetIter) SetIterTy(std::move(Other.SetIter));
    return *this;
  }

  bool operator==(const SmallSetIterator &RHS) const {
    if (isSmall != RHS.isSmall)
      return false;
    if (isSmall)
      return VecIter == RHS.VecIter;
    return SetIter == RHS.SetIter;
  }

  SmallSetIterator &operator++() {                
    if (isSmall)
      VecIter++;
    else
      SetIter++;
    return *this;
  }

  const T &operator*() const { return isSmall ? *VecIter : *SetIter; }
};

                                                                             
                                                                      
                                                                             
                                                 
template <typename T, unsigned N, typename C = std::less<T>>
class SmallSet {
                                                                            
                                                                             
                        
  SmallVector<T, N> Vector;
  std::set<T, C> Set;

  using VIterator = typename SmallVector<T, N>::const_iterator;
  using mutable_iterator = typename SmallVector<T, N>::iterator;

                                                                            
                                                                            
                                                               
  static_assert(N <= 32, "N should be small");

public:
  using size_type = size_t;
  using const_iterator = SmallSetIterator<T, N, C>;

  SmallSet() = default;

  LLVM_NODISCARD bool empty() const {
    return Vector.empty() && Set.empty();
  }

  size_type size() const {
    return isSmall() ? Vector.size() : Set.size();
  }

                                                                 
  size_type count(const T &V) const {
    if (isSmall()) {
                                                                
      return vfind(V) == Vector.end() ? 0 : 1;
    } else {
      return Set.count(V);
    }
  }

                                                                        
                                                                             
                                                                     
                                                                                
              
                                                                               
                       
  std::pair<NoneType, bool> insert(const T &V) {
    if (!isSmall())
      return std::make_pair(None, Set.insert(V).second);

    VIterator I = vfind(V);
    if (I != Vector.end())                                           
      return std::make_pair(None, false);
    if (Vector.size() < N) {
      Vector.push_back(V);
      return std::make_pair(None, true);
    }

                                          
    while (!Vector.empty()) {
      Set.insert(Vector.back());
      Vector.pop_back();
    }
    Set.insert(V);
    return std::make_pair(None, true);
  }

  template <typename IterT>
  void insert(IterT I, IterT E) {
    for (; I != E; ++I)
      insert(*I);
  }

  bool erase(const T &V) {
    if (!isSmall())
      return Set.erase(V);
    for (mutable_iterator I = Vector.begin(), E = Vector.end(); I != E; ++I)
      if (*I == V) {
        Vector.erase(I);
        return true;
      }
    return false;
  }

  void clear() {
    Vector.clear();
    Set.clear();
  }

  const_iterator begin() const {
    if (isSmall())
      return {Vector.begin()};
    return {Set.begin()};
  }

  const_iterator end() const {
    if (isSmall())
      return {Vector.end()};
    return {Set.end()};
  }

private:
  bool isSmall() const { return Set.empty(); }

  VIterator vfind(const T &V) const {
    for (VIterator I = Vector.begin(), E = Vector.end(); I != E; ++I)
      if (*I == V)
        return I;
    return Vector.end();
  }
};

                                                                        
                                
template <typename PointeeType, unsigned N>
class SmallSet<PointeeType*, N> : public SmallPtrSet<PointeeType*, N> {};

}                      

#endif                       

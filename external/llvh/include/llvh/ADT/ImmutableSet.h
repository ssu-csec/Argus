//===--- ImmutableSet.h - Immutable (functional) set interface --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the ImutAVLTree and ImmutableSet classes.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_IMMUTABLESET_H
#define LLVM_ADT_IMMUTABLESET_H

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/FoldingSet.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/iterator.h"
#include "llvh/Support/Allocator.h"
#include "llvh/Support/ErrorHandling.h"
#include <cassert>
#include <cstdint>
#include <functional>
#include <iterator>
#include <new>
#include <vector>

namespace llvh {

                                                                                
                                 
                                                                                

template <typename ImutInfo> class ImutAVLFactory;
template <typename ImutInfo> class ImutIntervalAVLFactory;
template <typename ImutInfo> class ImutAVLTreeInOrderIterator;
template <typename ImutInfo> class ImutAVLTreeGenericIterator;

template <typename ImutInfo >
class ImutAVLTree {
public:
  using key_type_ref = typename ImutInfo::key_type_ref;
  using value_type = typename ImutInfo::value_type;
  using value_type_ref = typename ImutInfo::value_type_ref;
  using Factory = ImutAVLFactory<ImutInfo>;
  using iterator = ImutAVLTreeInOrderIterator<ImutInfo>;

  friend class ImutAVLFactory<ImutInfo>;
  friend class ImutIntervalAVLFactory<ImutInfo>;
  friend class ImutAVLTreeGenericIterator<ImutInfo>;

                                                                
                      
                                                                

                                                       
                                           
  ImutAVLTree *getLeft() const { return left; }

                                                           
                                         
  ImutAVLTree *getRight() const { return right; }

                                                                          
                         
  unsigned getHeight() const { return height; }

                                                                      
  const value_type& getValue() const { return value; }

                                                                       
                                                                
  ImutAVLTree* find(key_type_ref K) {
    ImutAVLTree *T = this;
    while (T) {
      key_type_ref CurrentKey = ImutInfo::KeyOfValue(T->getValue());
      if (ImutInfo::isEqual(K,CurrentKey))
        return T;
      else if (ImutInfo::isLess(K,CurrentKey))
        T = T->getLeft();
      else
        T = T->getRight();
    }
    return nullptr;
  }

                                                                         
                 
  ImutAVLTree* getMaxElement() {
    ImutAVLTree *T = this;
    ImutAVLTree *Right = T->getRight();
    while (Right) { T = Right; Right = T->getRight(); }
    return T;
  }

                                                                    
                                      
  unsigned size() const {
    unsigned n = 1;
    if (const ImutAVLTree* L = getLeft())
      n += L->size();
    if (const ImutAVLTree* R = getRight())
      n += R->size();
    return n;
  }

                                                                          
                                                                         
                                                   
  iterator begin() const { return iterator(this); }

                                                                       
                         
  iterator end() const { return iterator(); }

  bool isElementEqual(value_type_ref V) const {
                        
    if (!ImutInfo::isEqual(ImutInfo::KeyOfValue(getValue()),
                           ImutInfo::KeyOfValue(V)))
      return false;

                                    
    if (!ImutInfo::isDataEqual(ImutInfo::DataOfValue(getValue()),
                               ImutInfo::DataOfValue(V)))
      return false;

    return true;
  }

  bool isElementEqual(const ImutAVLTree* RHS) const {
    return isElementEqual(RHS->getValue());
  }

                                                                           
                                                                            
                                         
  bool isEqual(const ImutAVLTree& RHS) const {
    if (&RHS == this)
      return true;

    iterator LItr = begin(), LEnd = end();
    iterator RItr = RHS.begin(), REnd = RHS.end();

    while (LItr != LEnd && RItr != REnd) {
      if (&*LItr == &*RItr) {
        LItr.skipSubTree();
        RItr.skipSubTree();
        continue;
      }

      if (!LItr->isElementEqual(&*RItr))
        return false;

      ++LItr;
      ++RItr;
    }

    return LItr == LEnd && RItr == REnd;
  }

                                                                             
                              
  bool isNotEqual(const ImutAVLTree& RHS) const { return !isEqual(RHS); }

                                                                         
                                                                      
                                              
  bool contains(key_type_ref K) { return (bool) find(K); }

                                                                             
                                                                        
                                                    
  template <typename Callback>
  void foreach(Callback& C) {
    if (ImutAVLTree* L = getLeft())
      L->foreach(C);

    C(value);

    if (ImutAVLTree* R = getRight())
      R->foreach(C);
  }

                                                                        
                                                                        
                                                                         
                                                                              
                                                                        
                     
  unsigned validateTree() const {
    unsigned HL = getLeft() ? getLeft()->validateTree() : 0;
    unsigned HR = getRight() ? getRight()->validateTree() : 0;
    (void) HL;
    (void) HR;

    assert(getHeight() == ( HL > HR ? HL : HR ) + 1
            && "Height calculation wrong");

    assert((HL > HR ? HL-HR : HR-HL) <= 2
           && "Balancing invariant violated");

    assert((!getLeft() ||
            ImutInfo::isLess(ImutInfo::KeyOfValue(getLeft()->getValue()),
                             ImutInfo::KeyOfValue(getValue()))) &&
           "Value in left child is not less that current value");


    assert(!(getRight() ||
             ImutInfo::isLess(ImutInfo::KeyOfValue(getValue()),
                              ImutInfo::KeyOfValue(getRight()->getValue()))) &&
           "Current value is not less that value of right child");

    return getHeight();
  }

                                                                
                     
                                                                

private:
  Factory *factory;
  ImutAVLTree *left;
  ImutAVLTree *right;
  ImutAVLTree *prev = nullptr;
  ImutAVLTree *next = nullptr;

  unsigned height : 28;
  bool IsMutable : 1;
  bool IsDigestCached : 1;
  bool IsCanonicalized : 1;

  value_type value;
  uint32_t digest = 0;
  uint32_t refCount = 0;

                                                                
                                                           
                                                                

private:
                                                               
                       
  ImutAVLTree(Factory *f, ImutAVLTree* l, ImutAVLTree* r, value_type_ref v,
              unsigned height)
    : factory(f), left(l), right(r), height(height), IsMutable(true),
      IsDigestCached(false), IsCanonicalized(false), value(v)
  {
    if (left) left->retain();
    if (right) right->retain();
  }

                                                                       
                                                                         
                                                                          
                                                                           
                                                                        
                                                                          
  bool isMutable() const { return IsMutable; }

                                                                           
                                                      
  bool hasCachedDigest() const { return IsDigestCached; }

                                                                
                                                            
                                                          
                                                          
                                                       
                                                       
                                                            
                                                             
               
                                                                

                                                                              
                                                                      
  void markImmutable() {
    assert(isMutable() && "Mutable flag already removed.");
    IsMutable = false;
  }

                                                                     
  void markedCachedDigest() {
    assert(!hasCachedDigest() && "NoCachedDigest flag already removed.");
    IsDigestCached = true;
  }

                                                                     
                      
  void setHeight(unsigned h) {
    assert(isMutable() && "Only a mutable tree can have its height changed.");
    height = h;
  }

  static uint32_t computeDigest(ImutAVLTree *L, ImutAVLTree *R,
                                value_type_ref V) {
    uint32_t digest = 0;

    if (L)
      digest += L->computeDigest();

                                     
    FoldingSetNodeID ID;
    ImutInfo::Profile(ID,V);
    digest += ID.ComputeHash();

    if (R)
      digest += R->computeDigest();

    return digest;
  }

  uint32_t computeDigest() {
                                                                    
                    
    if (hasCachedDigest())
      return digest;

    uint32_t X = computeDigest(getLeft(), getRight(), getValue());
    digest = X;
    markedCachedDigest();
    return X;
  }

                                                                
                                
                                                                

public:
  void retain() { ++refCount; }

  void release() {
    assert(refCount > 0);
    if (--refCount == 0)
      destroy();
  }

  void destroy() {
    if (left)
      left->release();
    if (right)
      right->release();
    if (IsCanonicalized) {
      if (next)
        next->prev = prev;

      if (prev)
        prev->next = next;
      else
        factory->Cache[factory->maskCacheIndex(computeDigest())] = next;
    }

                                                         
                                                                                
    IsMutable = false;
    factory->freeNodes.push_back(this);
  }
};

                                                                                
                                    
                                                                                

template <typename ImutInfo >
class ImutAVLFactory {
  friend class ImutAVLTree<ImutInfo>;

  using TreeTy = ImutAVLTree<ImutInfo>;
  using value_type_ref = typename TreeTy::value_type_ref;
  using key_type_ref = typename TreeTy::key_type_ref;
  using CacheTy = DenseMap<unsigned, TreeTy*>;

  CacheTy Cache;
  uintptr_t Allocator;
  std::vector<TreeTy*> createdNodes;
  std::vector<TreeTy*> freeNodes;

  bool ownsAllocator() const {
    return (Allocator & 0x1) == 0;
  }

  BumpPtrAllocator& getAllocator() const {
    return *reinterpret_cast<BumpPtrAllocator*>(Allocator & ~0x1);
  }

                                                              
                      
                                                              

public:
  ImutAVLFactory()
    : Allocator(reinterpret_cast<uintptr_t>(new BumpPtrAllocator())) {}

  ImutAVLFactory(BumpPtrAllocator& Alloc)
    : Allocator(reinterpret_cast<uintptr_t>(&Alloc) | 0x1) {}

  ~ImutAVLFactory() {
    if (ownsAllocator()) delete &getAllocator();
  }

  TreeTy* add(TreeTy* T, value_type_ref V) {
    T = add_internal(V,T);
    markImmutable(T);
    recoverNodes();
    return T;
  }

  TreeTy* remove(TreeTy* T, key_type_ref V) {
    T = remove_internal(V,T);
    markImmutable(T);
    recoverNodes();
    return T;
  }

  TreeTy* getEmptyTree() const { return nullptr; }

protected:
                                                              
                                                         
                                                      
                                                         
                                            
                                                              

  bool            isEmpty(TreeTy* T) const { return !T; }
  unsigned        getHeight(TreeTy* T) const { return T ? T->getHeight() : 0; }
  TreeTy*         getLeft(TreeTy* T) const { return T->getLeft(); }
  TreeTy*         getRight(TreeTy* T) const { return T->getRight(); }
  value_type_ref  getValue(TreeTy* T) const { return T->value; }

                                                                           
  static unsigned maskCacheIndex(unsigned I) { return (I & ~0x02); }

  unsigned incrementHeight(TreeTy* L, TreeTy* R) const {
    unsigned hl = getHeight(L);
    unsigned hr = getHeight(R);
    return (hl > hr ? hl : hr) + 1;
  }

  static bool compareTreeWithSection(TreeTy* T,
                                     typename TreeTy::iterator& TI,
                                     typename TreeTy::iterator& TE) {
    typename TreeTy::iterator I = T->begin(), E = T->end();
    for ( ; I!=E ; ++I, ++TI) {
      if (TI == TE || !I->isElementEqual(&*TI))
        return false;
    }
    return true;
  }

                                                              
                                                              
                                                            
                                                              
                                                           
                                                        
                                                     
                            
                                                              

  TreeTy* createNode(TreeTy* L, value_type_ref V, TreeTy* R) {
    BumpPtrAllocator& A = getAllocator();
    TreeTy* T;
    if (!freeNodes.empty()) {
      T = freeNodes.back();
      freeNodes.pop_back();
      assert(T != L);
      assert(T != R);
    } else {
      T = (TreeTy*) A.Allocate<TreeTy>();
    }
    new (T) TreeTy(this, L, R, V, incrementHeight(L,R));
    createdNodes.push_back(T);
    return T;
  }

  TreeTy* createNode(TreeTy* newLeft, TreeTy* oldTree, TreeTy* newRight) {
    return createNode(newLeft, getValue(oldTree), newRight);
  }

  void recoverNodes() {
    for (unsigned i = 0, n = createdNodes.size(); i < n; ++i) {
      TreeTy *N = createdNodes[i];
      if (N->isMutable() && N->refCount == 0)
        N->destroy();
    }
    createdNodes.clear();
  }

                                                               
                                    
  TreeTy* balanceTree(TreeTy* L, value_type_ref V, TreeTy* R) {
    unsigned hl = getHeight(L);
    unsigned hr = getHeight(R);

    if (hl > hr + 2) {
      assert(!isEmpty(L) && "Left tree cannot be empty to have a height >= 2");

      TreeTy *LL = getLeft(L);
      TreeTy *LR = getRight(L);

      if (getHeight(LL) >= getHeight(LR))
        return createNode(LL, L, createNode(LR,V,R));

      assert(!isEmpty(LR) && "LR cannot be empty because it has a height >= 1");

      TreeTy *LRL = getLeft(LR);
      TreeTy *LRR = getRight(LR);

      return createNode(createNode(LL,L,LRL), LR, createNode(LRR,V,R));
    }

    if (hr > hl + 2) {
      assert(!isEmpty(R) && "Right tree cannot be empty to have a height >= 2");

      TreeTy *RL = getLeft(R);
      TreeTy *RR = getRight(R);

      if (getHeight(RR) >= getHeight(RL))
        return createNode(createNode(L,V,RL), R, RR);

      assert(!isEmpty(RL) && "RL cannot be empty because it has a height >= 1");

      TreeTy *RLL = getLeft(RL);
      TreeTy *RLR = getRight(RL);

      return createNode(createNode(L,V,RLL), RL, createNode(RLR,R,RR));
    }

    return createNode(L,V,R);
  }

                                                                   
                                                                      
                                                                      
  TreeTy* add_internal(value_type_ref V, TreeTy* T) {
    if (isEmpty(T))
      return createNode(T, V, T);
    assert(!T->isMutable());

    key_type_ref K = ImutInfo::KeyOfValue(V);
    key_type_ref KCurrent = ImutInfo::KeyOfValue(getValue(T));

    if (ImutInfo::isEqual(K,KCurrent))
      return createNode(getLeft(T), V, getRight(T));
    else if (ImutInfo::isLess(K,KCurrent))
      return balanceTree(add_internal(V, getLeft(T)), getValue(T), getRight(T));
    else
      return balanceTree(getLeft(T), getValue(T), add_internal(V, getRight(T)));
  }

                                                                     
                                                                
                                                                      
                        
  TreeTy* remove_internal(key_type_ref K, TreeTy* T) {
    if (isEmpty(T))
      return T;

    assert(!T->isMutable());

    key_type_ref KCurrent = ImutInfo::KeyOfValue(getValue(T));

    if (ImutInfo::isEqual(K,KCurrent)) {
      return combineTrees(getLeft(T), getRight(T));
    } else if (ImutInfo::isLess(K,KCurrent)) {
      return balanceTree(remove_internal(K, getLeft(T)),
                                            getValue(T), getRight(T));
    } else {
      return balanceTree(getLeft(T), getValue(T),
                         remove_internal(K, getRight(T)));
    }
  }

  TreeTy* combineTrees(TreeTy* L, TreeTy* R) {
    if (isEmpty(L))
      return R;
    if (isEmpty(R))
      return L;
    TreeTy* OldNode;
    TreeTy* newRight = removeMinBinding(R,OldNode);
    return balanceTree(L, getValue(OldNode), newRight);
  }

  TreeTy* removeMinBinding(TreeTy* T, TreeTy*& Noderemoved) {
    assert(!isEmpty(T));
    if (isEmpty(getLeft(T))) {
      Noderemoved = T;
      return getRight(T);
    }
    return balanceTree(removeMinBinding(getLeft(T), Noderemoved),
                       getValue(T), getRight(T));
  }

                                                                      
                   
  void markImmutable(TreeTy* T) {
    if (!T || !T->isMutable())
      return;
    T->markImmutable();
    markImmutable(getLeft(T));
    markImmutable(getRight(T));
  }

public:
  TreeTy *getCanonicalTree(TreeTy *TNew) {
    if (!TNew)
      return nullptr;

    if (TNew->IsCanonicalized)
      return TNew;

                                                                      
                                                                 
    unsigned digest = TNew->computeDigest();
    TreeTy *&entry = Cache[maskCacheIndex(digest)];
    do {
      if (!entry)
        break;
      for (TreeTy *T = entry ; T != nullptr; T = T->next) {
                                                          
        typename TreeTy::iterator TI = T->begin(), TE = T->end();
        if (!compareTreeWithSection(TNew, TI, TE))
          continue;
        if (TI != TE)
          continue;                                  
                                        
        if (TNew->refCount == 0)
          TNew->destroy();
        return T;
      }
      entry->prev = TNew;
      TNew->next = entry;
    }
    while (false);

    entry = TNew;
    TNew->IsCanonicalized = true;
    return TNew;
  }
};

                                                                                
                                
                                                                                

template <typename ImutInfo> class ImutAVLTreeGenericIterator {
  SmallVector<uintptr_t,20> stack;

public:
  using iterator_category = std::bidirectional_iterator_tag;
  using value_type = ImutAVLTree<ImutInfo>;
  using difference_type = std::ptrdiff_t;
  using pointer = value_type *;
  using reference = value_type &;

  enum VisitFlag { VisitedNone=0x0, VisitedLeft=0x1, VisitedRight=0x3,
                   Flags=0x3 };

  using TreeTy = ImutAVLTree<ImutInfo>;

  ImutAVLTreeGenericIterator() = default;
  ImutAVLTreeGenericIterator(const TreeTy *Root) {
    if (Root) stack.push_back(reinterpret_cast<uintptr_t>(Root));
  }

  TreeTy &operator*() const {
    assert(!stack.empty());
    return *reinterpret_cast<TreeTy *>(stack.back() & ~Flags);
  }
  TreeTy *operator->() const { return &*this; }

  uintptr_t getVisitState() const {
    assert(!stack.empty());
    return stack.back() & Flags;
  }

  bool atEnd() const { return stack.empty(); }

  bool atBeginning() const {
    return stack.size() == 1 && getVisitState() == VisitedNone;
  }

  void skipToParent() {
    assert(!stack.empty());
    stack.pop_back();
    if (stack.empty())
      return;
    switch (getVisitState()) {
      case VisitedNone:
        stack.back() |= VisitedLeft;
        break;
      case VisitedLeft:
        stack.back() |= VisitedRight;
        break;
      default:
        llvm_unreachable("Unreachable.");
    }
  }

  bool operator==(const ImutAVLTreeGenericIterator &x) const {
    return stack == x.stack;
  }

  bool operator!=(const ImutAVLTreeGenericIterator &x) const {
    return !(*this == x);
  }

  ImutAVLTreeGenericIterator &operator++() {
    assert(!stack.empty());
    TreeTy* Current = reinterpret_cast<TreeTy*>(stack.back() & ~Flags);
    assert(Current);
    switch (getVisitState()) {
      case VisitedNone:
        if (TreeTy* L = Current->getLeft())
          stack.push_back(reinterpret_cast<uintptr_t>(L));
        else
          stack.back() |= VisitedLeft;
        break;
      case VisitedLeft:
        if (TreeTy* R = Current->getRight())
          stack.push_back(reinterpret_cast<uintptr_t>(R));
        else
          stack.back() |= VisitedRight;
        break;
      case VisitedRight:
        skipToParent();
        break;
      default:
        llvm_unreachable("Unreachable.");
    }
    return *this;
  }

  ImutAVLTreeGenericIterator &operator--() {
    assert(!stack.empty());
    TreeTy* Current = reinterpret_cast<TreeTy*>(stack.back() & ~Flags);
    assert(Current);
    switch (getVisitState()) {
      case VisitedNone:
        stack.pop_back();
        break;
      case VisitedLeft:
        stack.back() &= ~Flags;                               
        if (TreeTy* L = Current->getLeft())
          stack.push_back(reinterpret_cast<uintptr_t>(L) | VisitedRight);
        break;
      case VisitedRight:
        stack.back() &= ~Flags;
        stack.back() |= VisitedLeft;
        if (TreeTy* R = Current->getRight())
          stack.push_back(reinterpret_cast<uintptr_t>(R) | VisitedRight);
        break;
      default:
        llvm_unreachable("Unreachable.");
    }
    return *this;
  }
};

template <typename ImutInfo> class ImutAVLTreeInOrderIterator {
  using InternalIteratorTy = ImutAVLTreeGenericIterator<ImutInfo>;

  InternalIteratorTy InternalItr;

public:
  using iterator_category = std::bidirectional_iterator_tag;
  using value_type = ImutAVLTree<ImutInfo>;
  using difference_type = std::ptrdiff_t;
  using pointer = value_type *;
  using reference = value_type &;

  using TreeTy = ImutAVLTree<ImutInfo>;

  ImutAVLTreeInOrderIterator(const TreeTy* Root) : InternalItr(Root) {
    if (Root)
      ++*this;                             
  }

  ImutAVLTreeInOrderIterator() : InternalItr() {}

  bool operator==(const ImutAVLTreeInOrderIterator &x) const {
    return InternalItr == x.InternalItr;
  }

  bool operator!=(const ImutAVLTreeInOrderIterator &x) const {
    return !(*this == x);
  }

  TreeTy &operator*() const { return *InternalItr; }
  TreeTy *operator->() const { return &*InternalItr; }

  ImutAVLTreeInOrderIterator &operator++() {
    do ++InternalItr;
    while (!InternalItr.atEnd() &&
           InternalItr.getVisitState() != InternalIteratorTy::VisitedLeft);

    return *this;
  }

  ImutAVLTreeInOrderIterator &operator--() {
    do --InternalItr;
    while (!InternalItr.atBeginning() &&
           InternalItr.getVisitState() != InternalIteratorTy::VisitedLeft);

    return *this;
  }

  void skipSubTree() {
    InternalItr.skipToParent();

    while (!InternalItr.atEnd() &&
           InternalItr.getVisitState() != InternalIteratorTy::VisitedLeft)
      ++InternalItr;
  }
};

                                                                 
                                        
template <typename T>
struct ImutAVLValueIterator
    : iterator_adaptor_base<
          ImutAVLValueIterator<T>, typename T::TreeTy::iterator,
          typename std::iterator_traits<
              typename T::TreeTy::iterator>::iterator_category,
          const typename T::value_type> {
  ImutAVLValueIterator() = default;
  explicit ImutAVLValueIterator(typename T::TreeTy *Tree)
      : ImutAVLValueIterator::iterator_adaptor_base(Tree) {}

  typename ImutAVLValueIterator::reference operator*() const {
    return this->I->getValue();
  }
};

                                                                                
                                         
                                                                                

                                                                    
                                                                        
                                                   
template <typename T>
struct ImutProfileInfo {
  using value_type = const T;
  using value_type_ref = const T&;

  static void Profile(FoldingSetNodeID &ID, value_type_ref X) {
    FoldingSetTrait<T>::Profile(X,ID);
  }
};

                                
template <typename T>
struct ImutProfileInteger {
  using value_type = const T;
  using value_type_ref = const T&;

  static void Profile(FoldingSetNodeID &ID, value_type_ref X) {
    ID.AddInteger(X);
  }
};

#define PROFILE_INTEGER_INFO(X)\
template<> struct ImutProfileInfo<X> : ImutProfileInteger<X> {};

PROFILE_INTEGER_INFO(char)
PROFILE_INTEGER_INFO(unsigned char)
PROFILE_INTEGER_INFO(short)
PROFILE_INTEGER_INFO(unsigned short)
PROFILE_INTEGER_INFO(unsigned)
PROFILE_INTEGER_INFO(signed)
PROFILE_INTEGER_INFO(long)
PROFILE_INTEGER_INFO(unsigned long)
PROFILE_INTEGER_INFO(long long)
PROFILE_INTEGER_INFO(unsigned long long)

#undef PROFILE_INTEGER_INFO

                                
template <>
struct ImutProfileInfo<bool> {
  using value_type = const bool;
  using value_type_ref = const bool&;

  static void Profile(FoldingSetNodeID &ID, value_type_ref X) {
    ID.AddBoolean(X);
  }
};

                                                                  
                                 
template <typename T>
struct ImutProfileInfo<T*> {
  using value_type = const T*;
  using value_type_ref = value_type;

  static void Profile(FoldingSetNodeID &ID, value_type_ref X) {
    ID.AddPointer(X);
  }
};

                                                                                
                                                                   
                                                                           
                                                                           
                          
                                                                                

                                                                       
                                                             
                                                                        
template <typename T>
struct ImutContainerInfo : public ImutProfileInfo<T> {
  using value_type = typename ImutProfileInfo<T>::value_type;
  using value_type_ref = typename ImutProfileInfo<T>::value_type_ref;
  using key_type = value_type;
  using key_type_ref = value_type_ref;
  using data_type = bool;
  using data_type_ref = bool;

  static key_type_ref KeyOfValue(value_type_ref D) { return D; }
  static data_type_ref DataOfValue(value_type_ref) { return true; }

  static bool isEqual(key_type_ref LHS, key_type_ref RHS) {
    return std::equal_to<key_type>()(LHS,RHS);
  }

  static bool isLess(key_type_ref LHS, key_type_ref RHS) {
    return std::less<key_type>()(LHS,RHS);
  }

  static bool isDataEqual(data_type_ref, data_type_ref) { return true; }
};

                                                                           
                                                                    
                     
template <typename T>
struct ImutContainerInfo<T*> : public ImutProfileInfo<T*> {
  using value_type = typename ImutProfileInfo<T*>::value_type;
  using value_type_ref = typename ImutProfileInfo<T*>::value_type_ref;
  using key_type = value_type;
  using key_type_ref = value_type_ref;
  using data_type = bool;
  using data_type_ref = bool;

  static key_type_ref KeyOfValue(value_type_ref D) { return D; }
  static data_type_ref DataOfValue(value_type_ref) { return true; }

  static bool isEqual(key_type_ref LHS, key_type_ref RHS) { return LHS == RHS; }

  static bool isLess(key_type_ref LHS, key_type_ref RHS) { return LHS < RHS; }

  static bool isDataEqual(data_type_ref, data_type_ref) { return true; }
};

                                                                                
                
                                                                                

template <typename ValT, typename ValInfo = ImutContainerInfo<ValT>>
class ImmutableSet {
public:
  using value_type = typename ValInfo::value_type;
  using value_type_ref = typename ValInfo::value_type_ref;
  using TreeTy = ImutAVLTree<ValInfo>;

private:
  TreeTy *Root;

public:
                                                                     
                                                                    
                                                                   
                                   
  explicit ImmutableSet(TreeTy* R) : Root(R) {
    if (Root) { Root->retain(); }
  }

  ImmutableSet(const ImmutableSet &X) : Root(X.Root) {
    if (Root) { Root->retain(); }
  }

  ~ImmutableSet() {
    if (Root) { Root->release(); }
  }

  ImmutableSet &operator=(const ImmutableSet &X) {
    if (Root != X.Root) {
      if (X.Root) { X.Root->retain(); }
      if (Root) { Root->release(); }
      Root = X.Root;
    }
    return *this;
  }

  class Factory {
    typename TreeTy::Factory F;
    const bool Canonicalize;

  public:
    Factory(bool canonicalize = true)
      : Canonicalize(canonicalize) {}

    Factory(BumpPtrAllocator& Alloc, bool canonicalize = true)
      : F(Alloc), Canonicalize(canonicalize) {}

    Factory(const Factory& RHS) = delete;
    void operator=(const Factory& RHS) = delete;

                                                                         
    ImmutableSet getEmptySet() {
      return ImmutableSet(F.getEmptyTree());
    }

                                                                         
                                                                          
                                                                              
                                                                            
                                                                          
                                                                       
                                                          
    LLVM_NODISCARD ImmutableSet add(ImmutableSet Old, value_type_ref V) {
      TreeTy *NewT = F.add(Old.Root, V);
      return ImmutableSet(Canonicalize ? F.getCanonicalTree(NewT) : NewT);
    }

                                                                            
                                                                           
                                                                        
                                                                            
                                                                          
                                                                       
                                                          
    LLVM_NODISCARD ImmutableSet remove(ImmutableSet Old, value_type_ref V) {
      TreeTy *NewT = F.remove(Old.Root, V);
      return ImmutableSet(Canonicalize ? F.getCanonicalTree(NewT) : NewT);
    }

    BumpPtrAllocator& getAllocator() { return F.getAllocator(); }

    typename TreeTy::Factory *getTreeFactory() const {
      return const_cast<typename TreeTy::Factory *>(&F);
    }
  };

  friend class Factory;

                                                           
  bool contains(value_type_ref V) const {
    return Root ? Root->contains(V) : false;
  }

  bool operator==(const ImmutableSet &RHS) const {
    return Root && RHS.Root ? Root->isEqual(*RHS.Root) : Root == RHS.Root;
  }

  bool operator!=(const ImmutableSet &RHS) const {
    return Root && RHS.Root ? Root->isNotEqual(*RHS.Root) : Root != RHS.Root;
  }

  TreeTy *getRoot() {
    if (Root) { Root->retain(); }
    return Root;
  }

  TreeTy *getRootWithoutRetain() const {
    return Root;
  }

                                                            
  bool isEmpty() const { return !Root; }

                                                                        
                                          
  bool isSingleton() const { return getHeight() == 1; }

  template <typename Callback>
  void foreach(Callback& C) { if (Root) Root->foreach(C); }

  template <typename Callback>
  void foreach() { if (Root) { Callback C; Root->foreach(C); } }

                                                              
               
                                                              

  using iterator = ImutAVLValueIterator<ImmutableSet>;

  iterator begin() const { return iterator(Root); }
  iterator end() const { return iterator(); }

                                                              
                     
                                                              

  unsigned getHeight() const { return Root ? Root->getHeight() : 0; }

  static void Profile(FoldingSetNodeID &ID, const ImmutableSet &S) {
    ID.AddPointer(S.Root);
  }

  void Profile(FoldingSetNodeID &ID) const { return Profile(ID, *this); }

                                                              
                 
                                                              

  void validateTree() const { if (Root) Root->validateTree(); }
};

                                                            
template <typename ValT, typename ValInfo = ImutContainerInfo<ValT>>
class ImmutableSetRef {
public:
  using value_type = typename ValInfo::value_type;
  using value_type_ref = typename ValInfo::value_type_ref;
  using TreeTy = ImutAVLTree<ValInfo>;
  using FactoryTy = typename TreeTy::Factory;

private:
  TreeTy *Root;
  FactoryTy *Factory;

public:
                                                                     
                                                                    
                                                                   
                                   
  explicit ImmutableSetRef(TreeTy* R, FactoryTy *F)
    : Root(R),
      Factory(F) {
    if (Root) { Root->retain(); }
  }

  ImmutableSetRef(const ImmutableSetRef &X)
    : Root(X.Root),
      Factory(X.Factory) {
    if (Root) { Root->retain(); }
  }

  ~ImmutableSetRef() {
    if (Root) { Root->release(); }
  }

  ImmutableSetRef &operator=(const ImmutableSetRef &X) {
    if (Root != X.Root) {
      if (X.Root) { X.Root->retain(); }
      if (Root) { Root->release(); }
      Root = X.Root;
      Factory = X.Factory;
    }
    return *this;
  }

  static ImmutableSetRef getEmptySet(FactoryTy *F) {
    return ImmutableSetRef(0, F);
  }

  ImmutableSetRef add(value_type_ref V) {
    return ImmutableSetRef(Factory->add(Root, V), Factory);
  }

  ImmutableSetRef remove(value_type_ref V) {
    return ImmutableSetRef(Factory->remove(Root, V), Factory);
  }

                                                           
  bool contains(value_type_ref V) const {
    return Root ? Root->contains(V) : false;
  }

  ImmutableSet<ValT> asImmutableSet(bool canonicalize = true) const {
    return ImmutableSet<ValT>(canonicalize ?
                              Factory->getCanonicalTree(Root) : Root);
  }

  TreeTy *getRootWithoutRetain() const {
    return Root;
  }

  bool operator==(const ImmutableSetRef &RHS) const {
    return Root && RHS.Root ? Root->isEqual(*RHS.Root) : Root == RHS.Root;
  }

  bool operator!=(const ImmutableSetRef &RHS) const {
    return Root && RHS.Root ? Root->isNotEqual(*RHS.Root) : Root != RHS.Root;
  }

                                                            
  bool isEmpty() const { return !Root; }

                                                                        
                                          
  bool isSingleton() const { return getHeight() == 1; }

                                                              
               
                                                              

  using iterator = ImutAVLValueIterator<ImmutableSetRef>;

  iterator begin() const { return iterator(Root); }
  iterator end() const { return iterator(); }

                                                              
                     
                                                              

  unsigned getHeight() const { return Root ? Root->getHeight() : 0; }

  static void Profile(FoldingSetNodeID &ID, const ImmutableSetRef &S) {
    ID.AddPointer(S.Root);
  }

  void Profile(FoldingSetNodeID &ID) const { return Profile(ID, *this); }

                                                              
                 
                                                              

  void validateTree() const { if (Root) Root->validateTree(); }
};

}                      

#endif                           

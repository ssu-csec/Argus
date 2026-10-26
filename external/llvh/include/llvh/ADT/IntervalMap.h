//===- llvm/ADT/IntervalMap.h - A sorted interval map -----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements a coalescing interval map for small objects.
//
// KeyT objects are mapped to ValT objects. Intervals of keys that map to the
// same value are represented in a compressed form.
//
// Iterators provide ordered access to the compressed intervals rather than the
// individual keys, and insert and erase operations use key intervals as well.
//
// Like SmallVector, IntervalMap will store the first N intervals in the map
// object itself without any allocations. When space is exhausted it switches to
// a B+-tree representation with very small overhead for small key and value
// objects.
//
// A Traits class specifies how keys are compared. It also allows IntervalMap to
// work with both closed and half-open intervals.
//
// Keys and values are not stored next to each other in a std::pair, so we don't
// provide such a value_type. Dereferencing iterators only returns the mapped
// value. The interval bounds are accessible through the start() and stop()
// iterator methods.
//
// IntervalMap is optimized for small key and value objects, 4 or 8 bytes each
// is the optimal size. For large objects use std::map instead.
//
//===----------------------------------------------------------------------===//
//
// Synopsis:
//
// template <typename KeyT, typename ValT, unsigned N, typename Traits>
// class IntervalMap {
// public:
//   typedef KeyT key_type;
//   typedef ValT mapped_type;
//   typedef RecyclingAllocator<...> Allocator;
//   class iterator;
//   class const_iterator;
//
//   explicit IntervalMap(Allocator&);
//   ~IntervalMap():
//
//   bool empty() const;
//   KeyT start() const;
//   KeyT stop() const;
//   ValT lookup(KeyT x, Value NotFound = Value()) const;
//
//   const_iterator begin() const;
//   const_iterator end() const;
//   iterator begin();
//   iterator end();
//   const_iterator find(KeyT x) const;
//   iterator find(KeyT x);
//
//   void insert(KeyT a, KeyT b, ValT y);
//   void clear();
// };
//
// template <typename KeyT, typename ValT, unsigned N, typename Traits>
// class IntervalMap::const_iterator {
// public:
//   using iterator_category = std::bidirectional_iterator_tag;
//   using value_type = ValT;
//   using difference_type = std::ptrdiff_t;
//   using pointer = value_type *;
//   using reference = value_type &;
//   bool operator==(const const_iterator &) const;
//   bool operator!=(const const_iterator &) const;
//   bool valid() const;
//
//   const KeyT &start() const;
//   const KeyT &stop() const;
//   const ValT &value() const;
//   const ValT &operator*() const;
//   const ValT *operator->() const;
//
//   const_iterator &operator++();
//   const_iterator &operator++(int);
//   const_iterator &operator--();
//   const_iterator &operator--(int);
//   void goToBegin();
//   void goToEnd();
//   void find(KeyT x);
//   void advanceTo(KeyT x);
// };
//
// template <typename KeyT, typename ValT, unsigned N, typename Traits>
// class IntervalMap::iterator : public const_iterator {
// public:
//   void insert(KeyT a, KeyT b, Value y);
//   void erase();
// };
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_INTERVALMAP_H
#define LLVM_ADT_INTERVALMAP_H

#include "llvh/ADT/PointerIntPair.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/bit.h"
#include "llvh/Support/AlignOf.h"
#include "llvh/Support/Allocator.h"
#include "llvh/Support/RecyclingAllocator.h"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iterator>
#include <new>
#include <utility>

namespace llvh {

                                                                                
                                                                                
                                                                                
  
                                                            
                                                               
  
                                                                              
                                                                              
                                                                             
                                       
  
                                                                              
  
                                                                           
                                                                          
                     
  
                                                                                

template <typename T>
struct IntervalMapInfo {
                                                   
                                                                                
  static inline bool startLess(const T &x, const T &a) {
    return x < a;
  }

                                                  
                                                                                
  static inline bool stopLess(const T &b, const T &x) {
    return b < x;
  }

                                                                             
                                                                            
  static inline bool adjacent(const T &a, const T &b) {
    return a+1 == b;
  }

                                                   
                                                                                
  static inline bool nonEmpty(const T &a, const T &b) {
    return a <= b;
  }
};

template <typename T>
struct IntervalMapHalfOpenInfo {
                                                   
  static inline bool startLess(const T &x, const T &a) {
    return x < a;
  }

                                                  
  static inline bool stopLess(const T &b, const T &x) {
    return b <= x;
  }

                                                                             
  static inline bool adjacent(const T &a, const T &b) {
    return a == b;
  }

                                                   
  static inline bool nonEmpty(const T &a, const T &b) {
    return a < b;
  }
};

                                                                            
                                                          
namespace IntervalMapImpl {

using IdxPair = std::pair<unsigned,unsigned>;

                                                                                
                                                                                
                                                                                
  
                                                     
                                                                         
  
                                                                           
                                                                             
                           
  
                                                                            
                                                                               
                                                
  
                                                                            
                                                                             
  
                              
                                                  
                                           
                                           
                                
                                
  
                                                                                

template <typename T1, typename T2, unsigned N>
class NodeBase {
public:
  enum { Capacity = N };

  T1 first[N];
  T2 second[N];

                                             
                                                 
                                                          
                                                              
                                              
  template <unsigned M>
  void copy(const NodeBase<T1, T2, M> &Other, unsigned i,
            unsigned j, unsigned Count) {
    assert(i + Count <= M && "Invalid source range");
    assert(j + Count <= N && "Invalid dest range");
    for (unsigned e = i + Count; i != e; ++i, ++j) {
      first[j]  = Other.first[i];
      second[j] = Other.second[i];
    }
  }

                                           
                                                 
                                                      
                                              
  void moveLeft(unsigned i, unsigned j, unsigned Count) {
    assert(j <= i && "Use moveRight shift elements right");
    copy(*this, i, j, Count);
  }

                                             
                                                 
                                                      
                                              
  void moveRight(unsigned i, unsigned j, unsigned Count) {
    assert(i <= j && "Use moveLeft shift elements left");
    assert(j + Count <= N && "Invalid range");
    while (Count--) {
      first[j + Count]  = first[i + Count];
      second[j + Count] = second[i + Count];
    }
  }

                                   
                                                  
                                                
                                             
  void erase(unsigned i, unsigned j, unsigned Size) {
    moveLeft(j, i, Size - j);
  }

                                 
                                            
                                             
  void erase(unsigned i, unsigned Size) {
    erase(i, i+1, Size);
  }

                                                              
                                                 
                                             
  void shift(unsigned i, unsigned Size) {
    moveRight(i, i + 1, Size - i);
  }

                                                                   
                                              
                                     
                                             
                                                  
  void transferToLeftSib(unsigned Size, NodeBase &Sib, unsigned SSize,
                         unsigned Count) {
    Sib.copy(*this, 0, SSize, Count);
    erase(0, Count, Size);
  }

                                                                     
                                              
                                      
                                             
                                                  
  void transferToRightSib(unsigned Size, NodeBase &Sib, unsigned SSize,
                          unsigned Count) {
    Sib.moveRight(0, Count, SSize);
    Sib.copy(*this, Size-Count, 0, Count);
  }

                                                                              
                                              
                                              
                                      
                                             
                                                                            
                                                                            
  int adjustFromLeftSib(unsigned Size, NodeBase &Sib, unsigned SSize, int Add) {
    if (Add > 0) {
                                        
      unsigned Count = std::min(std::min(unsigned(Add), SSize), N - Size);
      Sib.transferToRightSib(SSize, *this, Size, Count);
      return Count;
    } else {
                                        
      unsigned Count = std::min(std::min(unsigned(-Add), Size), N - SSize);
      transferToLeftSib(Size, Sib, SSize, Count);
      return -Count;
    }
  }
};

                                                                              
                                                    
                                 
                                                                    
                                               
template <typename NodeT>
void adjustSiblingSizes(NodeT *Node[], unsigned Nodes,
                        unsigned CurSize[], const unsigned NewSize[]) {
                         
  for (int n = Nodes - 1; n; --n) {
    if (CurSize[n] == NewSize[n])
      continue;
    for (int m = n - 1; m != -1; --m) {
      int d = Node[n]->adjustFromLeftSib(CurSize[n], *Node[m], CurSize[m],
                                         NewSize[n] - CurSize[n]);
      CurSize[m] -= d;
      CurSize[n] += d;
                                                      
      if (CurSize[n] >= NewSize[n])
          break;
    }
  }

  if (Nodes == 0)
    return;

                        
  for (unsigned n = 0; n != Nodes - 1; ++n) {
    if (CurSize[n] == NewSize[n])
      continue;
    for (unsigned m = n + 1; m != Nodes; ++m) {
      int d = Node[m]->adjustFromLeftSib(CurSize[m], *Node[n], CurSize[n],
                                        CurSize[n] -  NewSize[n]);
      CurSize[m] += d;
      CurSize[n] -= d;
                                                      
      if (CurSize[n] >= NewSize[n])
          break;
    }
  }

#ifndef NDEBUG
  for (unsigned n = 0; n != Nodes; n++)
    assert(CurSize[n] == NewSize[n] && "Insufficient element shuffle");
#endif
}

                                                                             
                                                                                
                                                                          
             
   
                       
   
                                   
                                          
   
                                          
   
                                   
                             
   
                                                              
   
                                        
                                        
   
                                                                             
                                                                            
                                                                             
              
   
                                        
                                                
                                              
                                                                
                                                               
                                    
                                                                
                                                
IdxPair distribute(unsigned Nodes, unsigned Elements, unsigned Capacity,
                   const unsigned *CurSize, unsigned NewSize[],
                   unsigned Position, bool Grow);

                                                                                
                                                                                
                                                                                
  
                                               
  
                                                                           
                                                                                
                                                                                
  
                                                                                

enum {
                                                                        
                                                                     
  Log2CacheLine = 6,
  CacheLineBytes = 1 << Log2CacheLine,
  DesiredNodeBytes = 3 * CacheLineBytes
};

template <typename KeyT, typename ValT>
struct NodeSizer {
  enum {
                                                                            
                                                                            
                                       
                                                                            
                                      
    DesiredLeafSize = DesiredNodeBytes /
      static_cast<unsigned>(2*sizeof(KeyT)+sizeof(ValT)),
    MinLeafSize = 3,
    LeafSize = DesiredLeafSize > MinLeafSize ? DesiredLeafSize : MinLeafSize
  };

  using LeafBase = NodeBase<std::pair<KeyT, KeyT>, ValT, LeafSize>;

  enum {
                                                                                
                                                                 
    AllocBytes = (sizeof(LeafBase) + CacheLineBytes-1) & ~(CacheLineBytes-1),

                                                       
    BranchSize = AllocBytes /
      static_cast<unsigned>(sizeof(KeyT) + sizeof(void*))
  };

                                                                              
                                                                           
                                                                         
                              
  using Allocator =
      RecyclingAllocator<BumpPtrAllocator, char, AllocBytes, CacheLineBytes>;
};

                                                                                
                                                                                
                                                                                
  
                                                                         
                                        
  
                                                                            
                                                                       
                                                                           
                                                                                
                                    
  
                                                                             
                                                                   
  
                                                                               
                                                       
  
                                                                                

class NodeRef {
  struct CacheAlignedPointerTraits {
    static inline void *getAsVoidPointer(void *P) { return P; }
    static inline void *getFromVoidPointer(void *P) { return P; }
    enum { NumLowBitsAvailable = Log2CacheLine };
  };
  PointerIntPair<void*, Log2CacheLine, unsigned, CacheAlignedPointerTraits> pip;

public:
                                  
  NodeRef() = default;

                                        
  explicit operator bool() const { return pip.getOpaqueValue(); }

                                                                 
  template <typename NodeT>
  NodeRef(NodeT *p, unsigned n) : pip(p, n - 1) {
    assert(n <= NodeT::Capacity && "Size too big for node");
  }

                                                                  
  unsigned size() const { return pip.getInt() + 1; }

                                     
  void setSize(unsigned n) { pip.setInt(n - 1); }

                                                                   
                                                                           
             
  NodeRef &subtree(unsigned i) const {
    return reinterpret_cast<NodeRef*>(pip.getPointer())[i];
  }

                                             
  template <typename NodeT>
  NodeT &get() const {
    return *reinterpret_cast<NodeT*>(pip.getPointer());
  }

  bool operator==(const NodeRef &RHS) const {
    if (pip == RHS.pip)
      return true;
    assert(pip.getPointer() != RHS.pip.getPointer() && "Inconsistent NodeRefs");
    return false;
  }

  bool operator!=(const NodeRef &RHS) const {
    return !operator==(RHS);
  }
};

                                                                                
                                                                                
                                                                                
  
                                                                         
  
                                                                             
                                       
  
                                          
  
                                                                        
  
                                                     
  
                                                                         
                                                              
  
                                                                                

template <typename KeyT, typename ValT, unsigned N, typename Traits>
class LeafNode : public NodeBase<std::pair<KeyT, KeyT>, ValT, N> {
public:
  const KeyT &start(unsigned i) const { return this->first[i].first; }
  const KeyT &stop(unsigned i) const { return this->first[i].second; }
  const ValT &value(unsigned i) const { return this->second[i]; }

  KeyT &start(unsigned i) { return this->first[i].first; }
  KeyT &stop(unsigned i) { return this->first[i].second; }
  ValT &value(unsigned i) { return this->second[i]; }

                                                                    
                                                
                                             
                                    
                                                                      
                                                                         
  unsigned findFrom(unsigned i, unsigned Size, KeyT x) const {
    assert(i <= Size && Size <= N && "Bad indices");
    assert((i == 0 || Traits::stopLess(stop(i - 1), x)) &&
           "Index is past the needed point");
    while (i != Size && Traits::stopLess(stop(i), x)) ++i;
    return i;
  }

                                                                             
                                                                               
               
                                             
                                 
                                                                      
                                                                      
  unsigned safeFind(unsigned i, KeyT x) const {
    assert(i < N && "Bad index");
    assert((i == 0 || Traits::stopLess(stop(i - 1), x)) &&
           "Index is past the needed point");
    while (Traits::stopLess(stop(i), x)) ++i;
    assert(i < N && "Unsafe intervals");
    return i;
  }

                                                      
                                                             
                                        
                                                                  
                                                        
  ValT safeLookup(KeyT x, ValT NotFound) const {
    unsigned i = safeFind(0, x);
    return Traits::startLess(x, start(i)) ? NotFound : value(i);
  }

  unsigned insertFrom(unsigned &Pos, unsigned Size, KeyT a, KeyT b, ValT y);
};

                                                                             
                                                                            
                                    
                                                       
                                           
                               
                              
                                
                                                                            
template <typename KeyT, typename ValT, unsigned N, typename Traits>
unsigned LeafNode<KeyT, ValT, N, Traits>::
insertFrom(unsigned &Pos, unsigned Size, KeyT a, KeyT b, ValT y) {
  unsigned i = Pos;
  assert(i <= Size && Size <= N && "Invalid index");
  assert(!Traits::stopLess(b, a) && "Invalid interval");

                                   
  assert((i == 0 || Traits::stopLess(stop(i - 1), a)));
  assert((i == Size || !Traits::stopLess(stop(i), a)));
  assert((i == Size || Traits::stopLess(b, start(i))) && "Overlapping insert");

                                     
  if (i && value(i - 1) == y && Traits::adjacent(stop(i - 1), a)) {
    Pos = i - 1;
                                        
    if (i != Size && value(i) == y && Traits::adjacent(b, start(i))) {
      stop(i - 1) = stop(i);
      this->erase(i, Size);
      return Size - 1;
    }
    stop(i - 1) = b;
    return Size;
  }

                     
  if (i == N)
    return N + 1;

                             
  if (i == Size) {
    start(i) = a;
    stop(i) = b;
    value(i) = y;
    return Size + 1;
  }

                                             
  if (value(i) == y && Traits::adjacent(b, start(i))) {
    start(i) = a;
    return Size;
  }

                                              
  if (Size == N)
    return N + 1;

                     
  this->shift(i, Size);
  start(i) = a;
  stop(i) = b;
  value(i) = y;
  return Size + 1;
}

                                                                                
                                                                                
                                                                                
  
                                                                           
  
                                                                               
                                                                          
                                                                
  
                                                                              
                                                           
  
                                                                               
                                                                           
                             
  
                                                                                

template <typename KeyT, typename ValT, unsigned N, typename Traits>
class BranchNode : public NodeBase<NodeRef, KeyT, N> {
public:
  const KeyT &stop(unsigned i) const { return this->second[i]; }
  const NodeRef &subtree(unsigned i) const { return this->first[i]; }

  KeyT &stop(unsigned i) { return this->second[i]; }
  NodeRef &subtree(unsigned i) { return this->first[i]; }

                                                                   
                                                
                                             
                                    
                                                                 
                                                                        
  unsigned findFrom(unsigned i, unsigned Size, KeyT x) const {
    assert(i <= Size && Size <= N && "Bad indices");
    assert((i == 0 || Traits::stopLess(stop(i - 1), x)) &&
           "Index to findFrom is past the needed point");
    while (i != Size && Traits::stopLess(stop(i), x)) ++i;
    return i;
  }

                                                                           
                                                       
                                             
                                 
                                                                 
                                                                     
  unsigned safeFind(unsigned i, KeyT x) const {
    assert(i < N && "Bad index");
    assert((i == 0 || Traits::stopLess(stop(i - 1), x)) &&
           "Index is past the needed point");
    while (Traits::stopLess(stop(i), x)) ++i;
    assert(i < N && "Unsafe intervals");
    return i;
  }

                                                                             
                                 
                                   
  NodeRef safeLookup(KeyT x) const {
    return subtree(safeFind(0, x));
  }

                                                 
                                                                     
                                             
                                    
                                      
  void insert(unsigned i, unsigned Size, NodeRef Node, KeyT Stop) {
    assert(Size < N && "branch node overflow");
    assert(i <= Size && "Bad insert position");
    this->shift(i, Size);
    subtree(i) = Node;
    stop(i) = Stop;
  }
};

                                                                                
                                                                                
                                                                                
  
                                                                            
                                   
  
                                                                             
                  
  
                                                                                

class Path {
                                                                             
           
  struct Entry {
    void *node;
    unsigned size;
    unsigned offset;

    Entry(void *Node, unsigned Size, unsigned Offset)
      : node(Node), size(Size), offset(Offset) {}

    Entry(NodeRef Node, unsigned Offset)
      : node(&Node.subtree(0)), size(Node.size()), offset(Offset) {}

    NodeRef &subtree(unsigned i) const {
      return reinterpret_cast<NodeRef*>(node)[i];
    }
  };

                                                                               
  SmallVector<Entry, 4> path;

public:
                    
  template <typename NodeT> NodeT &node(unsigned Level) const {
    return *reinterpret_cast<NodeT*>(path[Level].node);
  }
  unsigned size(unsigned Level) const { return path[Level].size; }
  unsigned offset(unsigned Level) const { return path[Level].offset; }
  unsigned &offset(unsigned Level) { return path[Level].offset; }

                    
  template <typename NodeT> NodeT &leaf() const {
    return *reinterpret_cast<NodeT*>(path.back().node);
  }
  unsigned leafSize() const { return path.back().size; }
  unsigned leafOffset() const { return path.back().offset; }
  unsigned &leafOffset() { return path.back().offset; }

                                                                   
  bool valid() const {
    return !path.empty() && path.front().offset < path.front().size;
  }

                                                                        
                                              
  unsigned height() const { return path.size() - 1; }

                                                                       
                                                    
                                                            
  NodeRef &subtree(unsigned Level) const {
    return path[Level].subtree(path[Level].offset);
  }

                                                                                
                                                                           
  void reset(unsigned Level) {
    path[Level] = Entry(subtree(Level - 1), offset(Level));
  }

                               
                                                                
                                     
  void push(NodeRef Node, unsigned Offset) {
    path.push_back(Entry(Node, Offset));
  }

                                       
  void pop() {
    path.pop_back();
  }

                                                                        
                                                                          
                                 
                                
  void setSize(unsigned Level, unsigned Size) {
    path[Level].size = Size;
    if (Level)
      subtree(Level - 1).setSize(Size);
  }

                                                       
                                
                                
                                          
  void setRoot(void *Node, unsigned Size, unsigned Offset) {
    path.clear();
    path.push_back(Entry(Node, Size, Offset));
  }

                                                                                
                                
                                    
                                                    
                                                                  
  void replaceRoot(void *Root, unsigned Size, IdxPair Offsets);

                                                                             
                                                  
                                         
  NodeRef getLeftSibling(unsigned Level) const;

                                                                                
                
                                    
  void moveLeft(unsigned Level);

                                                                 
                                      
  void fillLeft(unsigned Height) {
    while (height() < Height)
      push(subtree(height()), 0);
  }

                                                                             
                                                   
                                         
  NodeRef getRightSibling(unsigned Level) const;

                                                                           
                      
                                    
  void moveRight(unsigned Level);

                                                  
  bool atBegin() const {
    for (unsigned i = 0, e = path.size(); i != e; ++i)
      if (path[i].offset != 0)
        return false;
    return true;
  }

                                                                               
            
                                   
  bool atLastEntry(unsigned Level) const {
    return path[Level].offset == path[Level].size - 1;
  }

                                                                              
                                                                              
                                                                                
                                                           
                                                                       
  void legalizeForInsert(unsigned Level) {
    if (valid())
      return;
    moveLeft(Level);
    ++path[Level].offset;
  }
};

}                                 

                                                                                
                                                                                
                                                                                

template <typename KeyT, typename ValT,
          unsigned N = IntervalMapImpl::NodeSizer<KeyT, ValT>::LeafSize,
          typename Traits = IntervalMapInfo<KeyT>>
class IntervalMap {
  using Sizer = IntervalMapImpl::NodeSizer<KeyT, ValT>;
  using Leaf = IntervalMapImpl::LeafNode<KeyT, ValT, Sizer::LeafSize, Traits>;
  using Branch =
      IntervalMapImpl::BranchNode<KeyT, ValT, Sizer::BranchSize, Traits>;
  using RootLeaf = IntervalMapImpl::LeafNode<KeyT, ValT, N, Traits>;
  using IdxPair = IntervalMapImpl::IdxPair;

                                                                                
                                       
  enum {
    DesiredRootBranchCap = (sizeof(RootLeaf) - sizeof(KeyT)) /
      (sizeof(KeyT) + sizeof(IntervalMapImpl::NodeRef)),
    RootBranchCap = DesiredRootBranchCap ? DesiredRootBranchCap : 1
  };

  using RootBranch =
      IntervalMapImpl::BranchNode<KeyT, ValT, RootBranchCap, Traits>;

                                                                           
  struct RootBranchData {
    KeyT start;
    RootBranch node;
  };

public:
  using Allocator = typename Sizer::Allocator;
  using KeyType = KeyT;
  using ValueType = ValT;
  using KeyTraits = Traits;

private:
                                                                     
  AlignedCharArrayUnion<RootLeaf, RootBranchData> data;

                 
                       
                            
                              
  unsigned height;

                                        
  unsigned rootSize;

                                                
  Allocator &allocator;

                                                                    
  template <typename T>
  T &dataAs() const {
    return *bit_cast<T *>(const_cast<char *>(data.buffer));
  }

  const RootLeaf &rootLeaf() const {
    assert(!branched() && "Cannot acces leaf data in branched root");
    return dataAs<RootLeaf>();
  }
  RootLeaf &rootLeaf() {
    assert(!branched() && "Cannot acces leaf data in branched root");
    return dataAs<RootLeaf>();
  }

  RootBranchData &rootBranchData() const {
    assert(branched() && "Cannot access branch data in non-branched root");
    return dataAs<RootBranchData>();
  }
  RootBranchData &rootBranchData() {
    assert(branched() && "Cannot access branch data in non-branched root");
    return dataAs<RootBranchData>();
  }

  const RootBranch &rootBranch() const { return rootBranchData().node; }
  RootBranch &rootBranch()             { return rootBranchData().node; }
  KeyT rootBranchStart() const { return rootBranchData().start; }
  KeyT &rootBranchStart()      { return rootBranchData().start; }

  template <typename NodeT> NodeT *newNode() {
    return new(allocator.template Allocate<NodeT>()) NodeT();
  }

  template <typename NodeT> void deleteNode(NodeT *P) {
    P->~NodeT();
    allocator.Deallocate(P);
  }

  IdxPair branchRoot(unsigned Position);
  IdxPair splitRoot(unsigned Position);

  void switchRootToBranch() {
    rootLeaf().~RootLeaf();
    height = 1;
    new (&rootBranchData()) RootBranchData();
  }

  void switchRootToLeaf() {
    rootBranchData().~RootBranchData();
    height = 0;
    new(&rootLeaf()) RootLeaf();
  }

  bool branched() const { return height > 0; }

  ValT treeSafeLookup(KeyT x, ValT NotFound) const;
  void visitNodes(void (IntervalMap::*f)(IntervalMapImpl::NodeRef,
                  unsigned Level));
  void deleteNode(IntervalMapImpl::NodeRef Node, unsigned Level);

public:
  explicit IntervalMap(Allocator &a) : height(0), rootSize(0), allocator(a) {
    assert((uintptr_t(data.buffer) & (alignof(RootLeaf) - 1)) == 0 &&
           "Insufficient alignment");
    new(&rootLeaf()) RootLeaf();
  }

  ~IntervalMap() {
    clear();
    rootLeaf().~RootLeaf();
  }

                                                        
  bool empty() const {
    return rootSize == 0;
  }

                                                                
  KeyT start() const {
    assert(!empty() && "Empty IntervalMap has no start");
    return !branched() ? rootLeaf().start(0) : rootBranchStart();
  }

                                                              
  KeyT stop() const {
    assert(!empty() && "Empty IntervalMap has no stop");
    return !branched() ? rootLeaf().stop(rootSize - 1) :
                         rootBranch().stop(rootSize - 1);
  }

                                                        
  ValT lookup(KeyT x, ValT NotFound = ValT()) const {
    if (empty() || Traits::startLess(x, start()) || Traits::stopLess(stop(), x))
      return NotFound;
    return branched() ? treeSafeLookup(x, NotFound) :
                        rootLeaf().safeLookup(x, NotFound);
  }

                                                                             
                                                                               
                                                                  
  void insert(KeyT a, KeyT b, ValT y) {
    if (branched() || rootSize == RootLeaf::Capacity)
      return find(a).insert(a, b, y);

                                  
    unsigned p = rootLeaf().findFrom(0, rootSize, a);
    rootSize = rootLeaf().insertFrom(p, rootSize, a, b, y);
  }

                                 
  void clear();

  class const_iterator;
  class iterator;
  friend class const_iterator;
  friend class iterator;

  const_iterator begin() const {
    const_iterator I(*this);
    I.goToBegin();
    return I;
  }

  iterator begin() {
    iterator I(*this);
    I.goToBegin();
    return I;
  }

  const_iterator end() const {
    const_iterator I(*this);
    I.goToEnd();
    return I;
  }

  iterator end() {
    iterator I(*this);
    I.goToEnd();
    return I;
  }

                                                                           
                        
  const_iterator find(KeyT x) const {
    const_iterator I(*this);
    I.find(x);
    return I;
  }

  iterator find(KeyT x) {
    iterator I(*this);
    I.find(x);
    return I;
  }
};

                                                                         
                  
template <typename KeyT, typename ValT, unsigned N, typename Traits>
ValT IntervalMap<KeyT, ValT, N, Traits>::
treeSafeLookup(KeyT x, ValT NotFound) const {
  assert(branched() && "treeLookup assumes a branched root");

  IntervalMapImpl::NodeRef NR = rootBranch().safeLookup(x);
  for (unsigned h = height-1; h; --h)
    NR = NR.get<Branch>().safeLookup(x);
  return NR.get<Leaf>().safeLookup(x, NotFound);
}

                                                           
                                                                       
template <typename KeyT, typename ValT, unsigned N, typename Traits>
IntervalMapImpl::IdxPair IntervalMap<KeyT, ValT, N, Traits>::
branchRoot(unsigned Position) {
  using namespace IntervalMapImpl;
                                                     
  const unsigned Nodes = RootLeaf::Capacity / Leaf::Capacity + 1;

                                                  
  unsigned size[Nodes];
  IdxPair NewOffset(0, Position);

                                                                           
  if (Nodes == 1)
    size[0] = rootSize;
  else
    NewOffset = distribute(Nodes, rootSize, Leaf::Capacity,  nullptr, size,
                           Position, true);

                        
  unsigned pos = 0;
  NodeRef node[Nodes];
  for (unsigned n = 0; n != Nodes; ++n) {
    Leaf *L = newNode<Leaf>();
    L->copy(rootLeaf(), pos, 0, size[n]);
    node[n] = NodeRef(L, size[n]);
    pos += size[n];
  }

                                                              
  switchRootToBranch();
  for (unsigned n = 0; n != Nodes; ++n) {
    rootBranch().stop(n) = node[n].template get<Leaf>().stop(size[n]-1);
    rootBranch().subtree(n) = node[n];
  }
  rootBranchStart() = node[0].template get<Leaf>().start(0);
  rootSize = Nodes;
  return NewOffset;
}

                                                                       
                                                                       
template <typename KeyT, typename ValT, unsigned N, typename Traits>
IntervalMapImpl::IdxPair IntervalMap<KeyT, ValT, N, Traits>::
splitRoot(unsigned Position) {
  using namespace IntervalMapImpl;
                                                       
  const unsigned Nodes = RootBranch::Capacity / Branch::Capacity + 1;

                                                  
  unsigned Size[Nodes];
  IdxPair NewOffset(0, Position);

                                                                           
  if (Nodes == 1)
    Size[0] = rootSize;
  else
    NewOffset = distribute(Nodes, rootSize, Leaf::Capacity,  nullptr, Size,
                           Position, true);

                        
  unsigned Pos = 0;
  NodeRef Node[Nodes];
  for (unsigned n = 0; n != Nodes; ++n) {
    Branch *B = newNode<Branch>();
    B->copy(rootBranch(), Pos, 0, Size[n]);
    Node[n] = NodeRef(B, Size[n]);
    Pos += Size[n];
  }

  for (unsigned n = 0; n != Nodes; ++n) {
    rootBranch().stop(n) = Node[n].template get<Branch>().stop(Size[n]-1);
    rootBranch().subtree(n) = Node[n];
  }
  rootSize = Nodes;
  ++height;
  return NewOffset;
}

                                          
template <typename KeyT, typename ValT, unsigned N, typename Traits>
void IntervalMap<KeyT, ValT, N, Traits>::
visitNodes(void (IntervalMap::*f)(IntervalMapImpl::NodeRef, unsigned Height)) {
  if (!branched())
    return;
  SmallVector<IntervalMapImpl::NodeRef, 4> Refs, NextRefs;

                                         
  for (unsigned i = 0; i != rootSize; ++i)
    Refs.push_back(rootBranch().subtree(i));

                            
  for (unsigned h = height - 1; h; --h) {
    for (unsigned i = 0, e = Refs.size(); i != e; ++i) {
      for (unsigned j = 0, s = Refs[i].size(); j != s; ++j)
        NextRefs.push_back(Refs[i].subtree(j));
      (this->*f)(Refs[i], h);
    }
    Refs.clear();
    Refs.swap(NextRefs);
  }

                          
  for (unsigned i = 0, e = Refs.size(); i != e; ++i)
    (this->*f)(Refs[i], 0);
}

template <typename KeyT, typename ValT, unsigned N, typename Traits>
void IntervalMap<KeyT, ValT, N, Traits>::
deleteNode(IntervalMapImpl::NodeRef Node, unsigned Level) {
  if (Level)
    deleteNode(&Node.get<Branch>());
  else
    deleteNode(&Node.get<Leaf>());
}

template <typename KeyT, typename ValT, unsigned N, typename Traits>
void IntervalMap<KeyT, ValT, N, Traits>::
clear() {
  if (branched()) {
    visitNodes(&IntervalMap::deleteNode);
    switchRootToLeaf();
  }
  rootSize = 0;
}

                                                                                
                                                                                
                                                                                

template <typename KeyT, typename ValT, unsigned N, typename Traits>
class IntervalMap<KeyT, ValT, N, Traits>::const_iterator {
  friend class IntervalMap;

public:
  using iterator_category = std::bidirectional_iterator_tag;
  using value_type = ValT;
  using difference_type = std::ptrdiff_t;
  using pointer = value_type *;
  using reference = value_type &;

protected:
                         
  IntervalMap *map = nullptr;

                                                                
                                                                        
  IntervalMapImpl::Path path;

  explicit const_iterator(const IntervalMap &map) :
    map(const_cast<IntervalMap*>(&map)) {}

  bool branched() const {
    assert(map && "Invalid iterator");
    return map->branched();
  }

  void setRoot(unsigned Offset) {
    if (branched())
      path.setRoot(&map->rootBranch(), map->rootSize, Offset);
    else
      path.setRoot(&map->rootLeaf(), map->rootSize, Offset);
  }

  void pathFillFind(KeyT x);
  void treeFind(KeyT x);
  void treeAdvanceTo(KeyT x);

                                                            
  KeyT &unsafeStart() const {
    assert(valid() && "Cannot access invalid iterator");
    return branched() ? path.leaf<Leaf>().start(path.leafOffset()) :
                        path.leaf<RootLeaf>().start(path.leafOffset());
  }

                                                          
  KeyT &unsafeStop() const {
    assert(valid() && "Cannot access invalid iterator");
    return branched() ? path.leaf<Leaf>().stop(path.leafOffset()) :
                        path.leaf<RootLeaf>().stop(path.leafOffset());
  }

                                                            
  ValT &unsafeValue() const {
    assert(valid() && "Cannot access invalid iterator");
    return branched() ? path.leaf<Leaf>().value(path.leafOffset()) :
                        path.leaf<RootLeaf>().value(path.leafOffset());
  }

public:
                                                                       
  const_iterator() = default;

                                                                            
                                               
  void setMap(const IntervalMap &m) { map = const_cast<IntervalMap*>(&m); }

                                                                            
  bool valid() const { return path.valid(); }

                                                                           
  bool atBegin() const { return path.atBegin(); }

                                                           
  const KeyT &start() const { return unsafeStart(); }

                                                    
  const KeyT &stop() const { return unsafeStop(); }

                                                              
  const ValT &value() const { return unsafeValue(); }

  const ValT &operator*() const { return value(); }

  bool operator==(const const_iterator &RHS) const {
    assert(map == RHS.map && "Cannot compare iterators from different maps");
    if (!valid())
      return !RHS.valid();
    if (path.leafOffset() != RHS.path.leafOffset())
      return false;
    return &path.template leaf<Leaf>() == &RHS.path.template leaf<Leaf>();
  }

  bool operator!=(const const_iterator &RHS) const {
    return !operator==(RHS);
  }

                                                    
  void goToBegin() {
    setRoot(0);
    if (branched())
      path.fillLeft(map->height);
  }

                                                     
  void goToEnd() {
    setRoot(map->rootSize);
  }

                                               
  const_iterator &operator++() {
    assert(valid() && "Cannot increment end()");
    if (++path.leafOffset() == path.leafSize() && branched())
      path.moveRight(map->height);
    return *this;
  }

                                   
  const_iterator operator++(int) {
    const_iterator tmp = *this;
    operator++();
    return tmp;
  }

                                                   
  const_iterator &operator--() {
    if (path.leafOffset() && (valid() || !branched()))
      --path.leafOffset();
    else
      path.moveLeft(map->height);
    return *this;
  }

                                   
  const_iterator operator--(int) {
    const_iterator tmp = *this;
    operator--();
    return tmp;
  }

                                                                 
                                                                           
  void find(KeyT x) {
    if (branched())
      treeFind(x);
    else
      setRoot(map->rootLeaf().findFrom(0, map->rootSize, x));
  }

                                                                      
                                                                               
                                                                    
  void advanceTo(KeyT x) {
    if (!valid())
      return;
    if (branched())
      treeAdvanceTo(x);
    else
      path.leafOffset() =
        map->rootLeaf().findFrom(path.leafOffset(), map->rootSize, x);
  }
};

                                                    
                               
template <typename KeyT, typename ValT, unsigned N, typename Traits>
void IntervalMap<KeyT, ValT, N, Traits>::
const_iterator::pathFillFind(KeyT x) {
  IntervalMapImpl::NodeRef NR = path.subtree(path.height());
  for (unsigned i = map->height - path.height() - 1; i; --i) {
    unsigned p = NR.get<Branch>().safeFind(0, x);
    path.push(NR, p);
    NR = NR.subtree(p);
  }
  path.push(NR, NR.get<Leaf>().safeFind(0, x));
}

                                       
                               
template <typename KeyT, typename ValT, unsigned N, typename Traits>
void IntervalMap<KeyT, ValT, N, Traits>::
const_iterator::treeFind(KeyT x) {
  setRoot(map->rootBranch().findFrom(0, map->rootSize, x));
  if (valid())
    pathFillFind(x);
}

                                                        
                               
template <typename KeyT, typename ValT, unsigned N, typename Traits>
void IntervalMap<KeyT, ValT, N, Traits>::
const_iterator::treeAdvanceTo(KeyT x) {
                                       
  if (!Traits::stopLess(path.leaf<Leaf>().stop(path.leafSize() - 1), x)) {
    path.leafOffset() = path.leaf<Leaf>().safeFind(path.leafOffset(), x);
    return;
  }

                           
  path.pop();

                                                  
  if (path.height()) {
    for (unsigned l = path.height() - 1; l; --l) {
      if (!Traits::stopLess(path.node<Branch>(l).stop(path.offset(l)), x)) {
                                           
        path.offset(l + 1) =
          path.node<Branch>(l + 1).safeFind(path.offset(l + 1), x);
        return pathFillFind(x);
      }
      path.pop();
    }
                                    
    if (!Traits::stopLess(map->rootBranch().stop(path.offset(0)), x)) {
      path.offset(1) = path.node<Branch>(1).safeFind(path.offset(1), x);
      return pathFillFind(x);
    }
  }

                         
  setRoot(map->rootBranch().findFrom(path.offset(0), map->rootSize, x));
  if (valid())
    pathFillFind(x);
}

                                                                                
                                                                                
                                                                                

template <typename KeyT, typename ValT, unsigned N, typename Traits>
class IntervalMap<KeyT, ValT, N, Traits>::iterator : public const_iterator {
  friend class IntervalMap;

  using IdxPair = IntervalMapImpl::IdxPair;

  explicit iterator(IntervalMap &map) : const_iterator(map) {}

  void setNodeStop(unsigned Level, KeyT Stop);
  bool insertNode(unsigned Level, IntervalMapImpl::NodeRef Node, KeyT Stop);
  template <typename NodeT> bool overflow(unsigned Level);
  void treeInsert(KeyT a, KeyT b, ValT y);
  void eraseNode(unsigned Level);
  void treeErase(bool UpdateRoot = true);
  bool canCoalesceLeft(KeyT Start, ValT x);
  bool canCoalesceRight(KeyT Stop, ValT x);

public:
                                      
  iterator() = default;

                                                        
                                                           
                                                                     
  void setStart(KeyT a);

                                                     
                                                            
                                                                     
  void setStop(KeyT b);

                                                                 
                                                                          
                         
  void setValue(ValT x);

                                                                        
                                          
                                                                                
                             
  void setStartUnchecked(KeyT a) { this->unsafeStart() = a; }

                                                                              
                                 
                                                                                
                            
  void setStopUnchecked(KeyT b) {
    this->unsafeStop() = b;
                                           
    if (this->path.atLastEntry(this->path.height()))
      setNodeStop(this->path.height(), b);
  }

                                                                         
                                      
                         
  void setValueUnchecked(ValT x) { this->unsafeValue() = x; }

                                                                     
  void insert(KeyT a, KeyT b, ValT y);

                                         
  void erase();

  iterator &operator++() {
    const_iterator::operator++();
    return *this;
  }

  iterator operator++(int) {
    iterator tmp = *this;
    operator++();
    return tmp;
  }

  iterator &operator--() {
    const_iterator::operator--();
    return *this;
  }

  iterator operator--(int) {
    iterator tmp = *this;
    operator--();
    return tmp;
  }
};

                                                                         
                            
                                               
                                                
                                                                            
template <typename KeyT, typename ValT, unsigned N, typename Traits>
bool IntervalMap<KeyT, ValT, N, Traits>::
iterator::canCoalesceLeft(KeyT Start, ValT Value) {
  using namespace IntervalMapImpl;
  Path &P = this->path;
  if (!this->branched()) {
    unsigned i = P.leafOffset();
    RootLeaf &Node = P.leaf<RootLeaf>();
    return i && Node.value(i-1) == Value &&
                Traits::adjacent(Node.stop(i-1), Start);
  }
              
  if (unsigned i = P.leafOffset()) {
    Leaf &Node = P.leaf<Leaf>();
    return Node.value(i-1) == Value && Traits::adjacent(Node.stop(i-1), Start);
  } else if (NodeRef NR = P.getLeftSibling(P.height())) {
    unsigned i = NR.size() - 1;
    Leaf &Node = NR.get<Leaf>();
    return Node.value(i) == Value && Traits::adjacent(Node.stop(i), Start);
  }
  return false;
}

                                                                           
                           
                                             
                                                
                                                                            
template <typename KeyT, typename ValT, unsigned N, typename Traits>
bool IntervalMap<KeyT, ValT, N, Traits>::
iterator::canCoalesceRight(KeyT Stop, ValT Value) {
  using namespace IntervalMapImpl;
  Path &P = this->path;
  unsigned i = P.leafOffset() + 1;
  if (!this->branched()) {
    if (i >= P.leafSize())
      return false;
    RootLeaf &Node = P.leaf<RootLeaf>();
    return Node.value(i) == Value && Traits::adjacent(Stop, Node.start(i));
  }
              
  if (i < P.leafSize()) {
    Leaf &Node = P.leaf<Leaf>();
    return Node.value(i) == Value && Traits::adjacent(Stop, Node.start(i));
  } else if (NodeRef NR = P.getRightSibling(P.height())) {
    Leaf &Node = NR.get<Leaf>();
    return Node.value(0) == Value && Traits::adjacent(Stop, Node.start(0));
  }
  return false;
}

                                                                             
template <typename KeyT, typename ValT, unsigned N, typename Traits>
void IntervalMap<KeyT, ValT, N, Traits>::
iterator::setNodeStop(unsigned Level, KeyT Stop) {
                                                                    
  if (!Level)
    return;
  IntervalMapImpl::Path &P = this->path;
                                               
  while (--Level) {
    P.node<Branch>(Level).stop(P.offset(Level)) = Stop;
    if (!P.atLastEntry(Level))
      return;
  }
                                                            
  P.node<RootBranch>(Level).stop(P.offset(Level)) = Stop;
}

template <typename KeyT, typename ValT, unsigned N, typename Traits>
void IntervalMap<KeyT, ValT, N, Traits>::
iterator::setStart(KeyT a) {
  assert(Traits::nonEmpty(a, this->stop()) && "Cannot move start beyond stop");
  KeyT &CurStart = this->unsafeStart();
  if (!Traits::startLess(a, CurStart) || !canCoalesceLeft(a, this->value())) {
    CurStart = a;
    return;
  }
                                            
  --*this;
  a = this->start();
  erase();
  setStartUnchecked(a);
}

template <typename KeyT, typename ValT, unsigned N, typename Traits>
void IntervalMap<KeyT, ValT, N, Traits>::
iterator::setStop(KeyT b) {
  assert(Traits::nonEmpty(this->start(), b) && "Cannot move stop beyond start");
  if (Traits::startLess(b, this->stop()) ||
      !canCoalesceRight(b, this->value())) {
    setStopUnchecked(b);
    return;
  }
                                         
  KeyT a = this->start();
  erase();
  setStartUnchecked(a);
}

template <typename KeyT, typename ValT, unsigned N, typename Traits>
void IntervalMap<KeyT, ValT, N, Traits>::
iterator::setValue(ValT x) {
  setValueUnchecked(x);
  if (canCoalesceRight(this->stop(), x)) {
    KeyT a = this->start();
    erase();
    setStartUnchecked(a);
  }
  if (canCoalesceLeft(this->start(), x)) {
    --*this;
    KeyT a = this->start();
    erase();
    setStartUnchecked(a);
  }
}

                                                                
                                                    
                                                       
                                        
                                               
                                                  
template <typename KeyT, typename ValT, unsigned N, typename Traits>
bool IntervalMap<KeyT, ValT, N, Traits>::
iterator::insertNode(unsigned Level, IntervalMapImpl::NodeRef Node, KeyT Stop) {
  assert(Level && "Cannot insert next to the root");
  bool SplitRoot = false;
  IntervalMap &IM = *this->map;
  IntervalMapImpl::Path &P = this->path;

  if (Level == 1) {
                                        
    if (IM.rootSize < RootBranch::Capacity) {
      IM.rootBranch().insert(P.offset(0), IM.rootSize, Node, Stop);
      P.setSize(0, ++IM.rootSize);
      P.reset(Level);
      return SplitRoot;
    }

                                                            
    SplitRoot = true;
    IdxPair Offset = IM.splitRoot(P.offset(0));
    P.replaceRoot(&IM.rootBranch(), IM.rootSize, Offset);

    // Fall through to insert at the new higher level.
    ++Level;
  }

                                                                 
  P.legalizeForInsert(--Level);

                                            
  if (P.size(Level) == Branch::Capacity) {
                                                       
    assert(!SplitRoot && "Cannot overflow after splitting the root");
    SplitRoot = overflow<Branch>(Level);
    Level += SplitRoot;
  }
  P.node<Branch>(Level).insert(P.offset(Level), P.size(Level), Node, Stop);
  P.setSize(Level, P.size(Level) + 1);
  if (P.atLastEntry(Level))
    setNodeStop(Level, Stop);
  P.reset(Level + 1);
  return SplitRoot;
}

         
template <typename KeyT, typename ValT, unsigned N, typename Traits>
void IntervalMap<KeyT, ValT, N, Traits>::
iterator::insert(KeyT a, KeyT b, ValT y) {
  if (this->branched())
    return treeInsert(a, b, y);
  IntervalMap &IM = *this->map;
  IntervalMapImpl::Path &P = this->path;

                                 
  unsigned Size = IM.rootLeaf().insertFrom(P.leafOffset(), IM.rootSize, a, b, y);

                                         
  if (Size <= RootLeaf::Capacity) {
    P.setSize(0, IM.rootSize = Size);
    return;
  }

                                            
  IdxPair Offset = IM.branchRoot(P.leafOffset());
  P.replaceRoot(&IM.rootBranch(), IM.rootSize, Offset);

                                 
  treeInsert(a, b, y);
}

template <typename KeyT, typename ValT, unsigned N, typename Traits>
void IntervalMap<KeyT, ValT, N, Traits>::
iterator::treeInsert(KeyT a, KeyT b, ValT y) {
  using namespace IntervalMapImpl;
  Path &P = this->path;

  if (!P.valid())
    P.legalizeForInsert(this->map->height);

                                                              
  if (P.leafOffset() == 0 && Traits::startLess(a, P.leaf<Leaf>().start(0))) {
                                                                       
    if (NodeRef Sib = P.getLeftSibling(P.height())) {
      Leaf &SibLeaf = Sib.get<Leaf>();
      unsigned SibOfs = Sib.size() - 1;
      if (SibLeaf.value(SibOfs) == y &&
          Traits::adjacent(SibLeaf.stop(SibOfs), a)) {
                                                                              
                                 
                                                       
                                                                         
                                                                         
        Leaf &CurLeaf = P.leaf<Leaf>();
        P.moveLeft(P.height());
        if (Traits::stopLess(b, CurLeaf.start(0)) &&
            (y != CurLeaf.value(0) || !Traits::adjacent(b, CurLeaf.start(0)))) {
                                                      
          setNodeStop(P.height(), SibLeaf.stop(SibOfs) = b);
          return;
        } else {
                                                                                
                                                        
          a = SibLeaf.start(SibOfs);
          treeErase(                 false);
        }
      }
    } else {
                                                                      
      this->map->rootBranchStart() = a;
    }
  }

                                                                           
  unsigned Size = P.leafSize();
  bool Grow = P.leafOffset() == Size;
  Size = P.leaf<Leaf>().insertFrom(P.leafOffset(), Size, a, b, y);

                                                         
  if (Size > Leaf::Capacity) {
    overflow<Leaf>(P.height());
    Grow = P.leafOffset() == P.leafSize();
    Size = P.leaf<Leaf>().insertFrom(P.leafOffset(), P.leafSize(), a, b, y);
    assert(Size <= Leaf::Capacity && "overflow() didn't make room");
  }

                                           
  P.setSize(P.height(), Size);

                                                  
  if (Grow)
    setNodeStop(P.height(), b);
}

                                                                     
template <typename KeyT, typename ValT, unsigned N, typename Traits>
void IntervalMap<KeyT, ValT, N, Traits>::
iterator::erase() {
  IntervalMap &IM = *this->map;
  IntervalMapImpl::Path &P = this->path;
  assert(P.valid() && "Cannot erase end()");
  if (this->branched())
    return treeErase();
  IM.rootLeaf().erase(P.leafOffset(), IM.rootSize);
  P.setSize(0, --IM.rootSize);
}

                                            
template <typename KeyT, typename ValT, unsigned N, typename Traits>
void IntervalMap<KeyT, ValT, N, Traits>::
iterator::treeErase(bool UpdateRoot) {
  IntervalMap &IM = *this->map;
  IntervalMapImpl::Path &P = this->path;
  Leaf &Node = P.leaf<Leaf>();

                                           
  if (P.leafSize() == 1) {
    IM.deleteNode(&Node);
    eraseNode(IM.height);
                                                   
    if (UpdateRoot && IM.branched() && P.valid() && P.atBegin())
      IM.rootBranchStart() = P.leaf<Leaf>().start(0);
    return;
  }

                         
  Node.erase(P.leafOffset(), P.leafSize());
  unsigned NewSize = P.leafSize() - 1;
  P.setSize(IM.height, NewSize);
                                                                            
  if (P.leafOffset() == NewSize) {
    setNodeStop(IM.height, Node.stop(NewSize - 1));
    P.moveRight(IM.height);
  } else if (UpdateRoot && P.atBegin())
    IM.rootBranchStart() = P.leaf<Leaf>().start(0);
}

                                                                                
                                             
                                               
                                                           
template <typename KeyT, typename ValT, unsigned N, typename Traits>
void IntervalMap<KeyT, ValT, N, Traits>::
iterator::eraseNode(unsigned Level) {
  assert(Level && "Cannot erase root node");
  IntervalMap &IM = *this->map;
  IntervalMapImpl::Path &P = this->path;

  if (--Level == 0) {
    IM.rootBranch().erase(P.offset(0), IM.rootSize);
    P.setSize(0, --IM.rootSize);
                                                    
    if (IM.empty()) {
      IM.switchRootToLeaf();
      this->setRoot(0);
      return;
    }
  } else {
                                                 
    Branch &Parent = P.node<Branch>(Level);
    if (P.size(Level) == 1) {
                                                         
      IM.deleteNode(&Parent);
      eraseNode(Level);
    } else {
                                        
      Parent.erase(P.offset(Level), P.size(Level));
      unsigned NewSize = P.size(Level) - 1;
      P.setSize(Level, NewSize);
                                                                            
      if (P.offset(Level) == NewSize) {
        setNodeStop(Level, Parent.stop(NewSize - 1));
        P.moveRight(Level);
      }
    }
  }
                                                          
  if (P.valid()) {
    P.reset(Level + 1);
    P.offset(Level + 1) = 0;
  }
}

                                                                  
                                                              
                                           
                                                             
                                                    
                                                  
template <typename KeyT, typename ValT, unsigned N, typename Traits>
template <typename NodeT>
bool IntervalMap<KeyT, ValT, N, Traits>::
iterator::overflow(unsigned Level) {
  using namespace IntervalMapImpl;
  Path &P = this->path;
  unsigned CurSize[4];
  NodeT *Node[4];
  unsigned Nodes = 0;
  unsigned Elements = 0;
  unsigned Offset = P.offset(Level);

                               
  NodeRef LeftSib = P.getLeftSibling(Level);
  if (LeftSib) {
    Offset += Elements = CurSize[Nodes] = LeftSib.size();
    Node[Nodes++] = &LeftSib.get<NodeT>();
  }

                  
  Elements += CurSize[Nodes] = P.size(Level);
  Node[Nodes++] = &P.node<NodeT>(Level);

                                
  NodeRef RightSib = P.getRightSibling(Level);
  if (RightSib) {
    Elements += CurSize[Nodes] = RightSib.size();
    Node[Nodes++] = &RightSib.get<NodeT>();
  }

                                       
  unsigned NewNode = 0;
  if (Elements + 1 > Nodes * NodeT::Capacity) {
                                                                          
    NewNode = Nodes == 1 ? 1 : Nodes - 1;
    CurSize[Nodes] = CurSize[NewNode];
    Node[Nodes] = Node[NewNode];
    CurSize[NewNode] = 0;
    Node[NewNode] = this->map->template newNode<NodeT>();
    ++Nodes;
  }

                                          
  unsigned NewSize[4];
  IdxPair NewOffset = distribute(Nodes, Elements, NodeT::Capacity,
                                 CurSize, NewSize, Offset, true);
  adjustSiblingSizes(Node, Nodes, CurSize, NewSize);

                                                
  if (LeftSib)
    P.moveLeft(Level);

                                                                    
  bool SplitRoot = false;
  unsigned Pos = 0;
  while (true) {
    KeyT Stop = Node[Pos]->stop(NewSize[Pos]-1);
    if (NewNode && Pos == NewNode) {
      SplitRoot = insertNode(Level, NodeRef(Node[Pos], NewSize[Pos]), Stop);
      Level += SplitRoot;
    } else {
      P.setSize(Level, NewSize[Pos]);
      setNodeStop(Level, Stop);
    }
    if (Pos + 1 == Nodes)
      break;
    P.moveRight(Level);
    ++Pos;
  }

                                 
  while(Pos != NewOffset.first) {
    P.moveLeft(Level);
    --Pos;
  }
  P.offset(Level) = NewOffset.second;
  return SplitRoot;
}

                                                                                
                                                                                
                                                                                

                                                                              
                                                                          
                       
   
                 
   
                        
                                                        
   
                          
                                                                 
   
template <typename MapA, typename MapB>
class IntervalMapOverlaps {
  using KeyType = typename MapA::KeyType;
  using Traits = typename MapA::KeyTraits;

  typename MapA::const_iterator posA;
  typename MapB::const_iterator posB;

                                                                              
                       
                                                               
  void advance() {
    if (!valid())
      return;

    if (Traits::stopLess(posA.stop(), posB.start())) {
                                          
      posA.advanceTo(posB.start());
      if (!posA.valid() || !Traits::stopLess(posB.stop(), posA.start()))
        return;
    } else if (Traits::stopLess(posB.stop(), posA.start())) {
                                          
      posB.advanceTo(posA.start());
      if (!posB.valid() || !Traits::stopLess(posA.stop(), posB.start()))
        return;
    } else
                             
      return;

    while (true) {
                              
      posA.advanceTo(posB.start());
      if (!posA.valid() || !Traits::stopLess(posB.stop(), posA.start()))
        return;
                              
      posB.advanceTo(posA.start());
      if (!posB.valid() || !Traits::stopLess(posA.stop(), posB.start()))
        return;
    }
  }

public:
                                                                           
  IntervalMapOverlaps(const MapA &a, const MapB &b)
    : posA(b.empty() ? a.end() : a.find(b.start())),
      posB(posA.valid() ? b.find(posA.start()) : b.end()) { advance(); }

                                                       
  bool valid() const {
    return posA.valid() && posB.valid();
  }

                                                   
  const typename MapA::const_iterator &a() const { return posA; }

                                                    
  const typename MapB::const_iterator &b() const { return posB; }

                                                    
  KeyType start() const {
    KeyType ak = a().start();
    KeyType bk = b().start();
    return Traits::startLess(ak, bk) ? bk : ak;
  }

                                             
  KeyType stop() const {
    KeyType ak = a().stop();
    KeyType bk = b().stop();
    return Traits::startLess(ak, bk) ? ak : bk;
  }

                                                                
  void skipA() {
    ++posA;
    advance();
  }

                                                                
  void skipB() {
    ++posB;
    advance();
  }

                                              
  IntervalMapOverlaps &operator++() {
                                                                               
    if (Traits::startLess(posB.stop(), posA.stop()))
      skipB();
    else
      skipA();
    return *this;
  }

                                                             
                          
  void advanceTo(KeyType x) {
    if (!valid())
      return;
                                               
    if (Traits::stopLess(posA.stop(), x))
      posA.advanceTo(x);
    if (Traits::stopLess(posB.stop(), x))
      posB.advanceTo(x);
    advance();
  }
};

}                      

#endif                          

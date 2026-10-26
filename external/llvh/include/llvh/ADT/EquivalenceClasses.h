//===- llvm/ADT/EquivalenceClasses.h - Generic Equiv. Classes ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Generic implementation of equivalence classes through the use Tarjan's
// efficient union-find algorithm.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_EQUIVALENCECLASSES_H
#define LLVM_ADT_EQUIVALENCECLASSES_H

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <set>

namespace llvh {

                                                                                
                                                                              
                                                                       
                                                                              
                                                                  
   
                                                                                
                                                                               
                                                                     
   
                                            
   
         
                                
                                                                        
                                                                    
                                                                            
   
                                                                         
                                                                               
                                                                 
                                                                             
                                                                            
                                              
                                     
      
            
   
                        
       
           
   
template <class ElemTy>
class EquivalenceClasses {
                                                                             
                                                                           
                                                                               
                                                                               
                                                                                
                                                                            
                                                                              
                                                                              
                                                                           
                                                                    
  class ECValue {
    friend class EquivalenceClasses;

    mutable const ECValue *Leader, *Next;
    ElemTy Data;

                                                                             
                             
    ECValue(const ElemTy &Elt)
      : Leader(this), Next((ECValue*)(intptr_t)1), Data(Elt) {}

    const ECValue *getLeader() const {
      if (isLeader()) return this;
      if (Leader->isLeader()) return Leader;
                          
      return Leader = Leader->getLeader();
    }

    const ECValue *getEndOfList() const {
      assert(isLeader() && "Cannot get the end of a list for a non-leader!");
      return Leader;
    }

    void setNext(const ECValue *NewNext) const {
      assert(getNext() == nullptr && "Already has a next pointer!");
      Next = (const ECValue*)((intptr_t)NewNext | (intptr_t)isLeader());
    }

  public:
    ECValue(const ECValue &RHS) : Leader(this), Next((ECValue*)(intptr_t)1),
                                  Data(RHS.Data) {
                                                 
      assert(RHS.isLeader() && RHS.getNext() == nullptr && "Not a singleton!");
    }

    bool operator<(const ECValue &UFN) const { return Data < UFN.Data; }

    bool isLeader() const { return (intptr_t)Next & 1; }
    const ElemTy &getData() const { return Data; }

    const ECValue *getNext() const {
      return (ECValue*)((intptr_t)Next & ~(intptr_t)1);
    }

    template<typename T>
    bool operator<(const T &Val) const { return Data < Val; }
  };

                                                                               
                                                           
  std::set<ECValue> TheMapping;

public:
  EquivalenceClasses() = default;
  EquivalenceClasses(const EquivalenceClasses &RHS) {
    operator=(RHS);
  }

  const EquivalenceClasses &operator=(const EquivalenceClasses &RHS) {
    TheMapping.clear();
    for (iterator I = RHS.begin(), E = RHS.end(); I != E; ++I)
      if (I->isLeader()) {
        member_iterator MI = RHS.member_begin(I);
        member_iterator LeaderIt = member_begin(insert(*MI));
        for (++MI; MI != member_end(); ++MI)
          unionSets(LeaderIt, member_begin(insert(*MI)));
      }
    return *this;
  }

                                                                                
                       
    

                                                                       
  using iterator = typename std::set<ECValue>::const_iterator;

  iterator begin() const { return TheMapping.begin(); }
  iterator end() const { return TheMapping.end(); }

  bool empty() const { return TheMapping.empty(); }

                                                                
  class member_iterator;
  member_iterator member_begin(iterator I) const {
                                                     
    return member_iterator(I->isLeader() ? &*I : nullptr);
  }
  member_iterator member_end() const {
    return member_iterator(nullptr);
  }

                                                                            
                               
  iterator findValue(const ElemTy &V) const {
    return TheMapping.find(V);
  }

                                                                               
                                                                             
                                                         
  const ElemTy &getLeaderValue(const ElemTy &V) const {
    member_iterator MI = findLeader(V);
    assert(MI != member_end() && "Value is not in the set!");
    return *MI;
  }

                                                                                
                                                                        
               
  const ElemTy &getOrInsertLeaderValue(const ElemTy &V) {
    member_iterator MI = findLeader(insert(V));
    assert(MI != member_end() && "Value is not in the set!");
    return *MI;
  }

                                                                           
                                                
  unsigned getNumClasses() const {
    unsigned NC = 0;
    for (iterator I = begin(), E = end(); I != E; ++I)
      if (I->isLeader()) ++NC;
    return NC;
  }

                                                                                
                     

                                                                               
                                  
  iterator insert(const ElemTy &Data) {
    return TheMapping.insert(ECValue(Data)).first;
  }

                                                                             
                                                                           
                                                                                
                                      
  member_iterator findLeader(iterator I) const {
    if (I == TheMapping.end()) return member_end();
    return member_iterator(I->getLeader());
  }
  member_iterator findLeader(const ElemTy &V) const {
    return findLeader(TheMapping.find(V));
  }

                                                                                
                                                               
  member_iterator unionSets(const ElemTy &V1, const ElemTy &V2) {
    iterator V1I = insert(V1), V2I = insert(V2);
    return unionSets(findLeader(V1I), findLeader(V2I));
  }
  member_iterator unionSets(member_iterator L1, member_iterator L2) {
    assert(L1 != member_end() && L2 != member_end() && "Illegal inputs!");
    if (L1 == L2) return L1;                                       

                                                                                
                                   
    const ECValue &L1LV = *L1.Node, &L2LV = *L2.Node;
    L1LV.getEndOfList()->setNext(&L2LV);

                                         
    L1LV.Leader = L2LV.getEndOfList();

                              
    L2LV.Next = L2LV.getNext();

                             
    L2LV.Leader = &L1LV;
    return L1;
  }

                                                                             
                                                                  
  bool isEquivalent(const ElemTy &V1, const ElemTy &V2) const {
                                                      
    if (V1 == V2)
      return true;
    auto It = findLeader(V1);
    return It != member_end() && It == findLeader(V2);
  }

  class member_iterator {
    friend class EquivalenceClasses;

    const ECValue *Node;

  public:
    using iterator_category = std::forward_iterator_tag;
    using value_type = const ElemTy;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type *;
    using reference = value_type &;

    explicit member_iterator() = default;
    explicit member_iterator(const ECValue *N) : Node(N) {}

    reference operator*() const {
      assert(Node != nullptr && "Dereferencing end()!");
      return Node->getData();
    }
    pointer operator->() const { return &operator*(); }

    member_iterator &operator++() {
      assert(Node != nullptr && "++'d off the end of the list!");
      Node = Node->getNext();
      return *this;
    }

    member_iterator operator++(int) {                               
      member_iterator tmp = *this;
      ++*this;
      return tmp;
    }

    bool operator==(const member_iterator &RHS) const {
      return Node == RHS.Node;
    }
    bool operator!=(const member_iterator &RHS) const {
      return Node != RHS.Node;
    }
  };
};

}                      

#endif                                 

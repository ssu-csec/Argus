//===- llvm/ADT/SparseBitVector.h - Efficient Sparse BitVector --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the SparseBitVector class.  See the doxygen comment for
// SparseBitVector for more details on the algorithm used.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_SPARSEBITVECTOR_H
#define LLVM_ADT_SPARSEBITVECTOR_H

#include "llvh/Support/ErrorHandling.h"
#include "llvh/Support/MathExtras.h"
#include "llvh/Support/raw_ostream.h"
#include <cassert>
#include <climits>
#include <cstring>
#include <iterator>
#include <list>

namespace llvh {

                                                                              
                                                                            
                                                                              
                                                                       
                                                                              
                                                                           
                                                                             
                                                                            
                                                                                
                                                                                
                                                                               
                                                                        

template <unsigned ElementSize = 128> struct SparseBitVectorElement {
public:
  using BitWord = unsigned long;
  using size_type = unsigned;
  enum {
    BITWORD_SIZE = sizeof(BitWord) * CHAR_BIT,
    BITWORDS_PER_ELEMENT = (ElementSize + BITWORD_SIZE - 1) / BITWORD_SIZE,
    BITS_PER_ELEMENT = ElementSize
  };

private:
                                                         
  unsigned ElementIndex;
  BitWord Bits[BITWORDS_PER_ELEMENT];

  SparseBitVectorElement() {
    ElementIndex = ~0U;
    memset(&Bits[0], 0, sizeof (BitWord) * BITWORDS_PER_ELEMENT);
  }

public:
  explicit SparseBitVectorElement(unsigned Idx) {
    ElementIndex = Idx;
    memset(&Bits[0], 0, sizeof (BitWord) * BITWORDS_PER_ELEMENT);
  }

                
  bool operator==(const SparseBitVectorElement &RHS) const {
    if (ElementIndex != RHS.ElementIndex)
      return false;
    for (unsigned i = 0; i < BITWORDS_PER_ELEMENT; ++i)
      if (Bits[i] != RHS.Bits[i])
        return false;
    return true;
  }

  bool operator!=(const SparseBitVectorElement &RHS) const {
    return !(*this == RHS);
  }

                                                          
  BitWord word(unsigned Idx) const {
    assert(Idx < BITWORDS_PER_ELEMENT);
    return Bits[Idx];
  }

  unsigned index() const {
    return ElementIndex;
  }

  bool empty() const {
    for (unsigned i = 0; i < BITWORDS_PER_ELEMENT; ++i)
      if (Bits[i])
        return false;
    return true;
  }

  void set(unsigned Idx) {
    Bits[Idx / BITWORD_SIZE] |= 1L << (Idx % BITWORD_SIZE);
  }

  bool test_and_set(unsigned Idx) {
    bool old = test(Idx);
    if (!old) {
      set(Idx);
      return true;
    }
    return false;
  }

  void reset(unsigned Idx) {
    Bits[Idx / BITWORD_SIZE] &= ~(1L << (Idx % BITWORD_SIZE));
  }

  bool test(unsigned Idx) const {
    return Bits[Idx / BITWORD_SIZE] & (1L << (Idx % BITWORD_SIZE));
  }

  size_type count() const {
    unsigned NumBits = 0;
    for (unsigned i = 0; i < BITWORDS_PER_ELEMENT; ++i)
      NumBits += countPopulation(Bits[i]);
    return NumBits;
  }

                                                          
  int find_first() const {
    for (unsigned i = 0; i < BITWORDS_PER_ELEMENT; ++i)
      if (Bits[i] != 0)
        return i * BITWORD_SIZE + countTrailingZeros(Bits[i]);
    llvm_unreachable("Illegal empty element");
  }

                                                        
  int find_last() const {
    for (unsigned I = 0; I < BITWORDS_PER_ELEMENT; ++I) {
      unsigned Idx = BITWORDS_PER_ELEMENT - I - 1;
      if (Bits[Idx] != 0)
        return Idx * BITWORD_SIZE + BITWORD_SIZE -
               countLeadingZeros(Bits[Idx]) - 1;
    }
    llvm_unreachable("Illegal empty element");
  }

                                                                         
                                                              
  int find_next(unsigned Curr) const {
    if (Curr >= BITS_PER_ELEMENT)
      return -1;

    unsigned WordPos = Curr / BITWORD_SIZE;
    unsigned BitPos = Curr % BITWORD_SIZE;
    BitWord Copy = Bits[WordPos];
    assert(WordPos <= BITWORDS_PER_ELEMENT
           && "Word Position outside of element");

                              
    Copy &= ~0UL << BitPos;

    if (Copy != 0)
      return WordPos * BITWORD_SIZE + countTrailingZeros(Copy);

                              
    for (unsigned i = WordPos+1; i < BITWORDS_PER_ELEMENT; ++i)
      if (Bits[i] != 0)
        return i * BITWORD_SIZE + countTrailingZeros(Bits[i]);
    return -1;
  }

                                                                     
  bool unionWith(const SparseBitVectorElement &RHS) {
    bool changed = false;
    for (unsigned i = 0; i < BITWORDS_PER_ELEMENT; ++i) {
      BitWord old = changed ? 0 : Bits[i];

      Bits[i] |= RHS.Bits[i];
      if (!changed && old != Bits[i])
        changed = true;
    }
    return changed;
  }

                                                       
  bool intersects(const SparseBitVectorElement &RHS) const {
    for (unsigned i = 0; i < BITWORDS_PER_ELEMENT; ++i) {
      if (RHS.Bits[i] & Bits[i])
        return true;
    }
    return false;
  }

                                                                         
                                                                    
  bool intersectWith(const SparseBitVectorElement &RHS,
                     bool &BecameZero) {
    bool changed = false;
    bool allzero = true;

    BecameZero = false;
    for (unsigned i = 0; i < BITWORDS_PER_ELEMENT; ++i) {
      BitWord old = changed ? 0 : Bits[i];

      Bits[i] &= RHS.Bits[i];
      if (Bits[i] != 0)
        allzero = false;

      if (!changed && old != Bits[i])
        changed = true;
    }
    BecameZero = allzero;
    return changed;
  }

                                                                              
                                                                            
          
  bool intersectWithComplement(const SparseBitVectorElement &RHS,
                               bool &BecameZero) {
    bool changed = false;
    bool allzero = true;

    BecameZero = false;
    for (unsigned i = 0; i < BITWORDS_PER_ELEMENT; ++i) {
      BitWord old = changed ? 0 : Bits[i];

      Bits[i] &= ~RHS.Bits[i];
      if (Bits[i] != 0)
        allzero = false;

      if (!changed && old != Bits[i])
        changed = true;
    }
    BecameZero = allzero;
    return changed;
  }

                                                                      
                                   
  void intersectWithComplement(const SparseBitVectorElement &RHS1,
                               const SparseBitVectorElement &RHS2,
                               bool &BecameZero) {
    bool allzero = true;

    BecameZero = false;
    for (unsigned i = 0; i < BITWORDS_PER_ELEMENT; ++i) {
      Bits[i] = RHS1.Bits[i] & ~RHS2.Bits[i];
      if (Bits[i] != 0)
        allzero = false;
    }
    BecameZero = allzero;
  }
};

template <unsigned ElementSize = 128>
class SparseBitVector {
  using ElementList = std::list<SparseBitVectorElement<ElementSize>>;
  using ElementListIter = typename ElementList::iterator;
  using ElementListConstIter = typename ElementList::const_iterator;
  enum {
    BITWORD_SIZE = SparseBitVectorElement<ElementSize>::BITWORD_SIZE
  };

                                    
  ElementListIter CurrElementIter;
  ElementList Elements;

                                                                          
                      
  ElementListIter FindLowerBound(unsigned ElementIndex) {

    if (Elements.empty()) {
      CurrElementIter = Elements.begin();
      return Elements.begin();
    }

                                               
    if (CurrElementIter == Elements.end())
      --CurrElementIter;

                                                                      
                                                    
    ElementListIter ElementIter = CurrElementIter;
    if (CurrElementIter->index() == ElementIndex) {
      return ElementIter;
    } else if (CurrElementIter->index() > ElementIndex) {
      while (ElementIter != Elements.begin()
             && ElementIter->index() > ElementIndex)
        --ElementIter;
    } else {
      while (ElementIter != Elements.end() &&
             ElementIter->index() < ElementIndex)
        ++ElementIter;
    }
    CurrElementIter = ElementIter;
    return ElementIter;
  }

                                                                            
                                                
  class SparseBitVectorIterator {
  private:
    bool AtEnd;

    const SparseBitVector<ElementSize> *BitVector = nullptr;

                                        
    ElementListConstIter Iter;

                                               
    unsigned BitNumber;

                                                 
    unsigned WordNumber;

                                     
    typename SparseBitVectorElement<ElementSize>::BitWord Bits;

                                                                 
    void AdvanceToFirstNonZero() {
      if (AtEnd)
        return;
      if (BitVector->Elements.empty()) {
        AtEnd = true;
        return;
      }
      Iter = BitVector->Elements.begin();
      BitNumber = Iter->index() * ElementSize;
      unsigned BitPos = Iter->find_first();
      BitNumber += BitPos;
      WordNumber = (BitNumber % ElementSize) / BITWORD_SIZE;
      Bits = Iter->word(WordNumber);
      Bits >>= BitPos % BITWORD_SIZE;
    }

                                                  
    void AdvanceToNextNonZero() {
      if (AtEnd)
        return;

      while (Bits && !(Bits & 1)) {
        Bits >>= 1;
        BitNumber += 1;
      }

                                                
      if (!Bits) {
        int NextSetBitNumber = Iter->find_next(BitNumber % ElementSize) ;
                                                                           
        if (NextSetBitNumber == -1 || (BitNumber % ElementSize == 0)) {
          ++Iter;
          WordNumber = 0;

                                                      
          if (Iter == BitVector->Elements.end()) {
            AtEnd = true;
            return;
          }
                                                     
          BitNumber = Iter->index() * ElementSize;
          NextSetBitNumber = Iter->find_first();
          BitNumber += NextSetBitNumber;
          WordNumber = (BitNumber % ElementSize) / BITWORD_SIZE;
          Bits = Iter->word(WordNumber);
          Bits >>= NextSetBitNumber % BITWORD_SIZE;
        } else {
          WordNumber = (NextSetBitNumber % ElementSize) / BITWORD_SIZE;
          Bits = Iter->word(WordNumber);
          Bits >>= NextSetBitNumber % BITWORD_SIZE;
          BitNumber = Iter->index() * ElementSize;
          BitNumber += NextSetBitNumber;
        }
      }
    }

  public:
    SparseBitVectorIterator() = default;

    SparseBitVectorIterator(const SparseBitVector<ElementSize> *RHS,
                            bool end = false):BitVector(RHS) {
      Iter = BitVector->Elements.begin();
      BitNumber = 0;
      Bits = 0;
      WordNumber = ~0;
      AtEnd = end;
      AdvanceToFirstNonZero();
    }

                    
    inline SparseBitVectorIterator& operator++() {
      ++BitNumber;
      Bits >>= 1;
      AdvanceToNextNonZero();
      return *this;
    }

                     
    inline SparseBitVectorIterator operator++(int) {
      SparseBitVectorIterator tmp = *this;
      ++*this;
      return tmp;
    }

                                         
    unsigned operator*() const {
      return BitNumber;
    }

    bool operator==(const SparseBitVectorIterator &RHS) const {
                                                                    
      if (AtEnd && RHS.AtEnd)
        return true;
                                                                         
                
      return AtEnd == RHS.AtEnd && RHS.BitNumber == BitNumber;
    }

    bool operator!=(const SparseBitVectorIterator &RHS) const {
      return !(*this == RHS);
    }
  };

public:
  using iterator = SparseBitVectorIterator;

  SparseBitVector() {
    CurrElementIter = Elements.begin();
  }

                               
  SparseBitVector(const SparseBitVector &RHS) {
    ElementListConstIter ElementIter = RHS.Elements.begin();
    while (ElementIter != RHS.Elements.end()) {
      Elements.push_back(SparseBitVectorElement<ElementSize>(*ElementIter));
      ++ElementIter;
    }

    CurrElementIter = Elements.begin ();
  }

  ~SparseBitVector() = default;

           
  void clear() {
    Elements.clear();
  }

               
  SparseBitVector& operator=(const SparseBitVector& RHS) {
    if (this == &RHS)
      return *this;

    Elements.clear();

    ElementListConstIter ElementIter = RHS.Elements.begin();
    while (ElementIter != RHS.Elements.end()) {
      Elements.push_back(SparseBitVectorElement<ElementSize>(*ElementIter));
      ++ElementIter;
    }

    CurrElementIter = Elements.begin ();

    return *this;
  }

                                              
  bool test(unsigned Idx) {
    if (Elements.empty())
      return false;

    unsigned ElementIndex = Idx / ElementSize;
    ElementListIter ElementIter = FindLowerBound(ElementIndex);

                                                                              
                             
    if (ElementIter == Elements.end() ||
        ElementIter->index() != ElementIndex)
      return false;
    return ElementIter->test(Idx % ElementSize);
  }

  void reset(unsigned Idx) {
    if (Elements.empty())
      return;

    unsigned ElementIndex = Idx / ElementSize;
    ElementListIter ElementIter = FindLowerBound(ElementIndex);

                                                                              
                             
    if (ElementIter == Elements.end() ||
        ElementIter->index() != ElementIndex)
      return;
    ElementIter->reset(Idx % ElementSize);

                                                 
    if (ElementIter->empty()) {
      ++CurrElementIter;
      Elements.erase(ElementIter);
    }
  }

  void set(unsigned Idx) {
    unsigned ElementIndex = Idx / ElementSize;
    ElementListIter ElementIter;
    if (Elements.empty()) {
      ElementIter = Elements.emplace(Elements.end(), ElementIndex);
    } else {
      ElementIter = FindLowerBound(ElementIndex);

      if (ElementIter == Elements.end() ||
          ElementIter->index() != ElementIndex) {
                                                                               
                                                                                
                                                                               
        if (ElementIter != Elements.end() &&
            ElementIter->index() < ElementIndex)
          ++ElementIter;
        ElementIter = Elements.emplace(ElementIter, ElementIndex);
      }
    }
    CurrElementIter = ElementIter;

    ElementIter->set(Idx % ElementSize);
  }

  bool test_and_set(unsigned Idx) {
    bool old = test(Idx);
    if (!old) {
      set(Idx);
      return true;
    }
    return false;
  }

  bool operator!=(const SparseBitVector &RHS) const {
    return !(*this == RHS);
  }

  bool operator==(const SparseBitVector &RHS) const {
    ElementListConstIter Iter1 = Elements.begin();
    ElementListConstIter Iter2 = RHS.Elements.begin();

    for (; Iter1 != Elements.end() && Iter2 != RHS.Elements.end();
         ++Iter1, ++Iter2) {
      if (*Iter1 != *Iter2)
        return false;
    }
    return Iter1 == Elements.end() && Iter2 == RHS.Elements.end();
  }

                                                                 
  bool operator|=(const SparseBitVector &RHS) {
    if (this == &RHS)
      return false;

    bool changed = false;
    ElementListIter Iter1 = Elements.begin();
    ElementListConstIter Iter2 = RHS.Elements.begin();

                                   
    if (RHS.Elements.empty())
      return false;

    while (Iter2 != RHS.Elements.end()) {
      if (Iter1 == Elements.end() || Iter1->index() > Iter2->index()) {
        Elements.insert(Iter1, *Iter2);
        ++Iter2;
        changed = true;
      } else if (Iter1->index() == Iter2->index()) {
        changed |= Iter1->unionWith(*Iter2);
        ++Iter1;
        ++Iter2;
      } else {
        ++Iter1;
      }
    }
    CurrElementIter = Elements.begin();
    return changed;
  }

                                                                       
  bool operator&=(const SparseBitVector &RHS) {
    if (this == &RHS)
      return false;

    bool changed = false;
    ElementListIter Iter1 = Elements.begin();
    ElementListConstIter Iter2 = RHS.Elements.begin();

                                       
    if (Elements.empty() && RHS.Elements.empty())
      return false;

                                                                            
    while (Iter2 != RHS.Elements.end()) {
      if (Iter1 == Elements.end()) {
        CurrElementIter = Elements.begin();
        return changed;
      }

      if (Iter1->index() > Iter2->index()) {
        ++Iter2;
      } else if (Iter1->index() == Iter2->index()) {
        bool BecameZero;
        changed |= Iter1->intersectWith(*Iter2, BecameZero);
        if (BecameZero) {
          ElementListIter IterTmp = Iter1;
          ++Iter1;
          Elements.erase(IterTmp);
        } else {
          ++Iter1;
        }
        ++Iter2;
      } else {
        ElementListIter IterTmp = Iter1;
        ++Iter1;
        Elements.erase(IterTmp);
        changed = true;
      }
    }
    if (Iter1 != Elements.end()) {
      Elements.erase(Iter1, Elements.end());
      changed = true;
    }
    CurrElementIter = Elements.begin();
    return changed;
  }

                                                                        
                     
  bool intersectWithComplement(const SparseBitVector &RHS) {
    if (this == &RHS) {
      if (!empty()) {
        clear();
        return true;
      }
      return false;
    }

    bool changed = false;
    ElementListIter Iter1 = Elements.begin();
    ElementListConstIter Iter2 = RHS.Elements.begin();

                                                        
    if (Elements.empty() || RHS.Elements.empty())
      return false;

                                                                            
    while (Iter2 != RHS.Elements.end()) {
      if (Iter1 == Elements.end()) {
        CurrElementIter = Elements.begin();
        return changed;
      }

      if (Iter1->index() > Iter2->index()) {
        ++Iter2;
      } else if (Iter1->index() == Iter2->index()) {
        bool BecameZero;
        changed |= Iter1->intersectWithComplement(*Iter2, BecameZero);
        if (BecameZero) {
          ElementListIter IterTmp = Iter1;
          ++Iter1;
          Elements.erase(IterTmp);
        } else {
          ++Iter1;
        }
        ++Iter2;
      } else {
        ++Iter1;
      }
    }
    CurrElementIter = Elements.begin();
    return changed;
  }

  bool intersectWithComplement(const SparseBitVector<ElementSize> *RHS) const {
    return intersectWithComplement(*RHS);
  }

                                                        
                                                        
  void intersectWithComplement(const SparseBitVector<ElementSize> &RHS1,
                               const SparseBitVector<ElementSize> &RHS2)
  {
    if (this == &RHS1) {
      intersectWithComplement(RHS2);
      return;
    } else if (this == &RHS2) {
      SparseBitVector RHS2Copy(RHS2);
      intersectWithComplement(RHS1, RHS2Copy);
      return;
    }

    Elements.clear();
    CurrElementIter = Elements.begin();
    ElementListConstIter Iter1 = RHS1.Elements.begin();
    ElementListConstIter Iter2 = RHS2.Elements.begin();

                                    
                                                   
    if (RHS1.Elements.empty())
      return;

                                                                            
    while (Iter2 != RHS2.Elements.end()) {
      if (Iter1 == RHS1.Elements.end())
        return;

      if (Iter1->index() > Iter2->index()) {
        ++Iter2;
      } else if (Iter1->index() == Iter2->index()) {
        bool BecameZero = false;
        Elements.emplace_back(Iter1->index());
        Elements.back().intersectWithComplement(*Iter1, *Iter2, BecameZero);
        if (BecameZero)
          Elements.pop_back();
        ++Iter1;
        ++Iter2;
      } else {
        Elements.push_back(*Iter1++);
      }
    }

                                  
    std::copy(Iter1, RHS1.Elements.end(), std::back_inserter(Elements));
  }

  void intersectWithComplement(const SparseBitVector<ElementSize> *RHS1,
                               const SparseBitVector<ElementSize> *RHS2) {
    intersectWithComplement(*RHS1, *RHS2);
  }

  bool intersects(const SparseBitVector<ElementSize> *RHS) const {
    return intersects(*RHS);
  }

                                                        
  bool intersects(const SparseBitVector<ElementSize> &RHS) const {
    ElementListConstIter Iter1 = Elements.begin();
    ElementListConstIter Iter2 = RHS.Elements.begin();

                                       
    if (Elements.empty() && RHS.Elements.empty())
      return false;

                                                                      
    while (Iter2 != RHS.Elements.end()) {
      if (Iter1 == Elements.end())
        return false;

      if (Iter1->index() > Iter2->index()) {
        ++Iter2;
      } else if (Iter1->index() == Iter2->index()) {
        if (Iter1->intersects(*Iter2))
          return true;
        ++Iter1;
        ++Iter2;
      } else {
        ++Iter1;
      }
    }
    return false;
  }

                                                             
                     
  bool contains(const SparseBitVector<ElementSize> &RHS) const {
    SparseBitVector<ElementSize> Result(*this);
    Result &= RHS;
    return (Result == RHS);
  }

                                                                           
  int find_first() const {
    if (Elements.empty())
      return -1;
    const SparseBitVectorElement<ElementSize> &First = *(Elements.begin());
    return (First.index() * ElementSize) + First.find_first();
  }

                                                                          
  int find_last() const {
    if (Elements.empty())
      return -1;
    const SparseBitVectorElement<ElementSize> &Last = *(Elements.rbegin());
    return (Last.index() * ElementSize) + Last.find_last();
  }

                                                
  bool empty() const {
    return Elements.empty();
  }

  unsigned count() const {
    unsigned BitCount = 0;
    for (ElementListConstIter Iter = Elements.begin();
         Iter != Elements.end();
         ++Iter)
      BitCount += Iter->count();

    return BitCount;
  }

  iterator begin() const {
    return iterator(this);
  }

  iterator end() const {
    return iterator(this, true);
  }
};

                                                                              
        

template <unsigned ElementSize>
inline bool operator |=(SparseBitVector<ElementSize> &LHS,
                        const SparseBitVector<ElementSize> *RHS) {
  return LHS |= *RHS;
}

template <unsigned ElementSize>
inline bool operator |=(SparseBitVector<ElementSize> *LHS,
                        const SparseBitVector<ElementSize> &RHS) {
  return LHS->operator|=(RHS);
}

template <unsigned ElementSize>
inline bool operator &=(SparseBitVector<ElementSize> *LHS,
                        const SparseBitVector<ElementSize> &RHS) {
  return LHS->operator&=(RHS);
}

template <unsigned ElementSize>
inline bool operator &=(SparseBitVector<ElementSize> &LHS,
                        const SparseBitVector<ElementSize> *RHS) {
  return LHS &= *RHS;
}

                                                                             

template <unsigned ElementSize>
inline SparseBitVector<ElementSize>
operator|(const SparseBitVector<ElementSize> &LHS,
          const SparseBitVector<ElementSize> &RHS) {
  SparseBitVector<ElementSize> Result(LHS);
  Result |= RHS;
  return Result;
}

template <unsigned ElementSize>
inline SparseBitVector<ElementSize>
operator&(const SparseBitVector<ElementSize> &LHS,
          const SparseBitVector<ElementSize> &RHS) {
  SparseBitVector<ElementSize> Result(LHS);
  Result &= RHS;
  return Result;
}

template <unsigned ElementSize>
inline SparseBitVector<ElementSize>
operator-(const SparseBitVector<ElementSize> &LHS,
          const SparseBitVector<ElementSize> &RHS) {
  SparseBitVector<ElementSize> Result;
  Result.intersectWithComplement(LHS, RHS);
  return Result;
}

                                     
template <unsigned ElementSize>
void dump(const SparseBitVector<ElementSize> &LHS, raw_ostream &out) {
  out << "[";

  typename SparseBitVector<ElementSize>::iterator bi = LHS.begin(),
    be = LHS.end();
  if (bi != be) {
    out << *bi;
    for (++bi; bi != be; ++bi) {
      out << " " << *bi;
    }
  }
  out << "]\n";
}

}                      

#endif                              

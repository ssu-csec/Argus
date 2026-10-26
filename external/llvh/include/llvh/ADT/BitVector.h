//===- llvm/ADT/BitVector.h - Bit vectors -----------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the BitVector class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_BITVECTOR_H
#define LLVM_ADT_BITVECTOR_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/iterator_range.h"
#include "llvh/Support/MathExtras.h"
#include <algorithm>
#include <cassert>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <utility>

namespace llvh {

                                              
                                                              
template <typename BitVectorT> class const_set_bits_iterator_impl {
  const BitVectorT &Parent;
  int Current = 0;

  void advance() {
    assert(Current != -1 && "Trying to advance past end.");
    Current = Parent.find_next(Current);
  }

public:
  const_set_bits_iterator_impl(const BitVectorT &Parent, int Current)
      : Parent(Parent), Current(Current) {}
  explicit const_set_bits_iterator_impl(const BitVectorT &Parent)
      : const_set_bits_iterator_impl(Parent, Parent.find_first()) {}
  const_set_bits_iterator_impl(const const_set_bits_iterator_impl &) = default;

  const_set_bits_iterator_impl operator++(int) {
    auto Prev = *this;
    advance();
    return Prev;
  }

  const_set_bits_iterator_impl &operator++() {
    advance();
    return *this;
  }

  unsigned operator*() const { return Current; }

  bool operator==(const const_set_bits_iterator_impl &Other) const {
    assert(&Parent == &Other.Parent &&
           "Comparing iterators from different BitVectors");
    return Current == Other.Current;
  }

  bool operator!=(const const_set_bits_iterator_impl &Other) const {
    assert(&Parent == &Other.Parent &&
           "Comparing iterators from different BitVectors");
    return Current != Other.Current;
  }
};

class BitVector {
  typedef unsigned long BitWord;

  enum { BITWORD_SIZE = (unsigned)sizeof(BitWord) * CHAR_BIT };

  static_assert(BITWORD_SIZE == 64 || BITWORD_SIZE == 32,
                "Unsupported word size");

  MutableArrayRef<BitWord> Bits;                
  unsigned Size;                                              

public:
  typedef unsigned size_type;
                                   
  class reference {
    friend class BitVector;

    BitWord *WordRef;
    unsigned BitPos;

  public:
    reference(BitVector &b, unsigned Idx) {
      WordRef = &b.Bits[Idx / BITWORD_SIZE];
      BitPos = Idx % BITWORD_SIZE;
    }

    reference() = delete;
    reference(const reference&) = default;

    reference &operator=(reference t) {
      *this = bool(t);
      return *this;
    }

    reference& operator=(bool t) {
      if (t)
        *WordRef |= BitWord(1) << BitPos;
      else
        *WordRef &= ~(BitWord(1) << BitPos);
      return *this;
    }

    operator bool() const {
      return ((*WordRef) & (BitWord(1) << BitPos)) != 0;
    }
  };

  typedef const_set_bits_iterator_impl<BitVector> const_set_bits_iterator;
  typedef const_set_bits_iterator set_iterator;

  const_set_bits_iterator set_bits_begin() const {
    return const_set_bits_iterator(*this);
  }
  const_set_bits_iterator set_bits_end() const {
    return const_set_bits_iterator(*this, -1);
  }
  iterator_range<const_set_bits_iterator> set_bits() const {
    return make_range(set_bits_begin(), set_bits_end());
  }

                                                          
  BitVector() : Size(0) {}

                                                                           
                                                  
  explicit BitVector(unsigned s, bool t = false) : Size(s) {
    size_t Capacity = NumBitWords(s);
    Bits = allocate(Capacity);
    init_words(Bits, t);
    if (t)
      clear_unused_bits();
  }

                          
  BitVector(const BitVector &RHS) : Size(RHS.size()) {
    if (Size == 0) {
      Bits = MutableArrayRef<BitWord>();
      return;
    }

    size_t Capacity = NumBitWords(RHS.size());
    Bits = allocate(Capacity);
    std::memcpy(Bits.data(), RHS.Bits.data(), Capacity * sizeof(BitWord));
  }

  BitVector(BitVector &&RHS) : Bits(RHS.Bits), Size(RHS.Size) {
    RHS.Bits = MutableArrayRef<BitWord>();
    RHS.Size = 0;
  }

  ~BitVector() { std::free(Bits.data()); }

                                                                
  bool empty() const { return Size == 0; }

                                                          
  size_type size() const { return Size; }

                                                       
  size_type count() const {
    unsigned NumBits = 0;
    for (unsigned i = 0; i < NumBitWords(size()); ++i)
      NumBits += countPopulation(Bits[i]);
    return NumBits;
  }

                                           
  bool any() const {
    for (unsigned i = 0; i < NumBitWords(size()); ++i)
      if (Bits[i] != 0)
        return true;
    return false;
  }

                                             
  bool all() const {
    for (unsigned i = 0; i < Size / BITWORD_SIZE; ++i)
      if (Bits[i] != ~0UL)
        return false;

                                                                                
    if (unsigned Remainder = Size % BITWORD_SIZE)
      return Bits[Size / BITWORD_SIZE] == (1UL << Remainder) - 1;

    return true;
  }

                                                      
  bool none() const {
    return !any();
  }

                                                                         
                                                                   
  int find_first_in(unsigned Begin, unsigned End) const {
    assert(Begin <= End && End <= Size);
    if (Begin == End)
      return -1;

    unsigned FirstWord = Begin / BITWORD_SIZE;
    unsigned LastWord = (End - 1) / BITWORD_SIZE;

                              
    for (unsigned i = FirstWord; i <= LastWord; ++i) {
      BitWord Copy = Bits[i];

      if (i == FirstWord) {
        unsigned FirstBit = Begin % BITWORD_SIZE;
        Copy &= maskTrailingZeros<BitWord>(FirstBit);
      }

      if (i == LastWord) {
        unsigned LastBit = (End - 1) % BITWORD_SIZE;
        Copy &= maskTrailingOnes<BitWord>(LastBit + 1);
      }
      if (Copy != 0)
        return i * BITWORD_SIZE + countTrailingZeros(Copy);
    }
    return -1;
  }

                                                                       
                                                                   
  int find_last_in(unsigned Begin, unsigned End) const {
    assert(Begin <= End && End <= Size);
    if (Begin == End)
      return -1;

    unsigned LastWord = (End - 1) / BITWORD_SIZE;
    unsigned FirstWord = Begin / BITWORD_SIZE;

    for (unsigned i = LastWord + 1; i >= FirstWord + 1; --i) {
      unsigned CurrentWord = i - 1;

      BitWord Copy = Bits[CurrentWord];
      if (CurrentWord == LastWord) {
        unsigned LastBit = (End - 1) % BITWORD_SIZE;
        Copy &= maskTrailingOnes<BitWord>(LastBit + 1);
      }

      if (CurrentWord == FirstWord) {
        unsigned FirstBit = Begin % BITWORD_SIZE;
        Copy &= maskTrailingZeros<BitWord>(FirstBit);
      }

      if (Copy != 0)
        return (CurrentWord + 1) * BITWORD_SIZE - countLeadingZeros(Copy) - 1;
    }

    return -1;
  }

                                                                           
                                                                       
  int find_first_unset_in(unsigned Begin, unsigned End) const {
    assert(Begin <= End && End <= Size);
    if (Begin == End)
      return -1;

    unsigned FirstWord = Begin / BITWORD_SIZE;
    unsigned LastWord = (End - 1) / BITWORD_SIZE;

                              
    for (unsigned i = FirstWord; i <= LastWord; ++i) {
      BitWord Copy = Bits[i];

      if (i == FirstWord) {
        unsigned FirstBit = Begin % BITWORD_SIZE;
        Copy |= maskTrailingOnes<BitWord>(FirstBit);
      }

      if (i == LastWord) {
        unsigned LastBit = (End - 1) % BITWORD_SIZE;
        Copy |= maskTrailingZeros<BitWord>(LastBit + 1);
      }
      if (Copy != ~0UL) {
        unsigned Result = i * BITWORD_SIZE + countTrailingOnes(Copy);
        return Result < size() ? Result : -1;
      }
    }
    return -1;
  }

                                                                         
                                                                       
  int find_last_unset_in(unsigned Begin, unsigned End) const {
    assert(Begin <= End && End <= Size);
    if (Begin == End)
      return -1;

    unsigned LastWord = (End - 1) / BITWORD_SIZE;
    unsigned FirstWord = Begin / BITWORD_SIZE;

    for (unsigned i = LastWord + 1; i >= FirstWord + 1; --i) {
      unsigned CurrentWord = i - 1;

      BitWord Copy = Bits[CurrentWord];
      if (CurrentWord == LastWord) {
        unsigned LastBit = (End - 1) % BITWORD_SIZE;
        Copy |= maskTrailingZeros<BitWord>(LastBit + 1);
      }

      if (CurrentWord == FirstWord) {
        unsigned FirstBit = Begin % BITWORD_SIZE;
        Copy |= maskTrailingOnes<BitWord>(FirstBit);
      }

      if (Copy != ~0UL) {
        unsigned Result =
            (CurrentWord + 1) * BITWORD_SIZE - countLeadingOnes(Copy) - 1;
        return Result < Size ? Result : -1;
      }
    }
    return -1;
  }

                                                                     
                          
  int find_first() const { return find_first_in(0, Size); }

                                                                               
              
  int find_last() const { return find_last_in(0, Size); }

                                                                     
                                                              
  int find_next(unsigned Prev) const { return find_first_in(Prev + 1, Size); }

                                                                          
                                                                        
  int find_prev(unsigned PriorTo) const { return find_last_in(0, PriorTo); }

                                                                            
                          
  int find_first_unset() const { return find_first_unset_in(0, Size); }

                                                                             
                                                            
  int find_next_unset(unsigned Prev) const {
    return find_first_unset_in(Prev + 1, Size);
  }

                                                                             
                       
  int find_last_unset() const { return find_last_unset_in(0, Size); }

                                                                              
                                                                      
  int find_prev_unset(unsigned PriorTo) {
    return find_last_unset_in(0, PriorTo);
  }

                                                                            
  void clear() {
    Size = 0;
  }

                                            
  void resize(unsigned N, bool t = false) {
    if (N > getBitCapacity()) {
      unsigned OldCapacity = Bits.size();
      grow(N);
      init_words(Bits.drop_front(OldCapacity), t);
    }

                                                                           
                                                                              
                           
    if (N > Size)
      set_unused_bits(t);

                                                                  
    unsigned OldSize = Size;
    Size = N;
    if (t || N < OldSize)
      clear_unused_bits();
  }

  void reserve(unsigned N) {
    if (N > getBitCapacity())
      grow(N);
  }

                     
  BitVector &set() {
    init_words(Bits, true);
    clear_unused_bits();
    return *this;
  }

  BitVector &set(unsigned Idx) {
    assert(Bits.data() && "Bits never allocated");
    Bits[Idx / BITWORD_SIZE] |= BitWord(1) << (Idx % BITWORD_SIZE);
    return *this;
  }

                                                     
  BitVector &set(unsigned I, unsigned E) {
    assert(I <= E && "Attempted to set backwards range!");
    assert(E <= size() && "Attempted to set out-of-bounds range!");

    if (I == E) return *this;

    if (I / BITWORD_SIZE == E / BITWORD_SIZE) {
      BitWord EMask = 1UL << (E % BITWORD_SIZE);
      BitWord IMask = 1UL << (I % BITWORD_SIZE);
      BitWord Mask = EMask - IMask;
      Bits[I / BITWORD_SIZE] |= Mask;
      return *this;
    }

    BitWord PrefixMask = ~0UL << (I % BITWORD_SIZE);
    Bits[I / BITWORD_SIZE] |= PrefixMask;
    I = alignTo(I, BITWORD_SIZE);

    for (; I + BITWORD_SIZE <= E; I += BITWORD_SIZE)
      Bits[I / BITWORD_SIZE] = ~0UL;

    BitWord PostfixMask = (1UL << (E % BITWORD_SIZE)) - 1;
    if (I < E)
      Bits[I / BITWORD_SIZE] |= PostfixMask;

    return *this;
  }

  BitVector &reset() {
    init_words(Bits, false);
    return *this;
  }

  BitVector &reset(unsigned Idx) {
    Bits[Idx / BITWORD_SIZE] &= ~(BitWord(1) << (Idx % BITWORD_SIZE));
    return *this;
  }

                                                         
  BitVector &reset(unsigned I, unsigned E) {
    assert(I <= E && "Attempted to reset backwards range!");
    assert(E <= size() && "Attempted to reset out-of-bounds range!");

    if (I == E) return *this;

    if (I / BITWORD_SIZE == E / BITWORD_SIZE) {
      BitWord EMask = 1UL << (E % BITWORD_SIZE);
      BitWord IMask = 1UL << (I % BITWORD_SIZE);
      BitWord Mask = EMask - IMask;
      Bits[I / BITWORD_SIZE] &= ~Mask;
      return *this;
    }

    BitWord PrefixMask = ~0UL << (I % BITWORD_SIZE);
    Bits[I / BITWORD_SIZE] &= ~PrefixMask;
    I = alignTo(I, BITWORD_SIZE);

    for (; I + BITWORD_SIZE <= E; I += BITWORD_SIZE)
      Bits[I / BITWORD_SIZE] = 0UL;

    BitWord PostfixMask = (1UL << (E % BITWORD_SIZE)) - 1;
    if (I < E)
      Bits[I / BITWORD_SIZE] &= ~PostfixMask;

    return *this;
  }

  BitVector &flip() {
    for (unsigned i = 0; i < NumBitWords(size()); ++i)
      Bits[i] = ~Bits[i];
    clear_unused_bits();
    return *this;
  }

  BitVector &flip(unsigned Idx) {
    Bits[Idx / BITWORD_SIZE] ^= BitWord(1) << (Idx % BITWORD_SIZE);
    return *this;
  }

              
  reference operator[](unsigned Idx) {
    assert (Idx < Size && "Out-of-bounds Bit access.");
    return reference(*this, Idx);
  }

  bool operator[](unsigned Idx) const {
    assert (Idx < Size && "Out-of-bounds Bit access.");
    BitWord Mask = BitWord(1) << (Idx % BITWORD_SIZE);
    return (Bits[Idx / BITWORD_SIZE] & Mask) != 0;
  }

  bool test(unsigned Idx) const {
    return (*this)[Idx];
  }

                                      
  void push_back(bool Val) {
    unsigned OldSize = Size;
    unsigned NewSize = Size + 1;

                                       
                                                                   
    if (NewSize > getBitCapacity())
      resize(NewSize, false);
    else
      Size = NewSize;

                               
    if (Val)
      set(OldSize);
  }

                                      
  bool anyCommon(const BitVector &RHS) const {
    unsigned ThisWords = NumBitWords(size());
    unsigned RHSWords  = NumBitWords(RHS.size());
    for (unsigned i = 0, e = std::min(ThisWords, RHSWords); i != e; ++i)
      if (Bits[i] & RHS.Bits[i])
        return true;
    return false;
  }

                          
  bool operator==(const BitVector &RHS) const {
    unsigned ThisWords = NumBitWords(size());
    unsigned RHSWords  = NumBitWords(RHS.size());
    unsigned i;
    for (i = 0; i != std::min(ThisWords, RHSWords); ++i)
      if (Bits[i] != RHS.Bits[i])
        return false;

                                                 
    if (i != ThisWords) {
      for (; i != ThisWords; ++i)
        if (Bits[i])
          return false;
    } else if (i != RHSWords) {
      for (; i != RHSWords; ++i)
        if (RHS.Bits[i])
          return false;
    }
    return true;
  }

  bool operator!=(const BitVector &RHS) const {
    return !(*this == RHS);
  }

                                          
  BitVector &operator&=(const BitVector &RHS) {
    unsigned ThisWords = NumBitWords(size());
    unsigned RHSWords  = NumBitWords(RHS.size());
    unsigned i;
    for (i = 0; i != std::min(ThisWords, RHSWords); ++i)
      Bits[i] &= RHS.Bits[i];

                                                                                
                                                                             
                                   
    for (; i != ThisWords; ++i)
      Bits[i] = 0;

    return *this;
  }

                                                                    
  BitVector &reset(const BitVector &RHS) {
    unsigned ThisWords = NumBitWords(size());
    unsigned RHSWords  = NumBitWords(RHS.size());
    unsigned i;
    for (i = 0; i != std::min(ThisWords, RHSWords); ++i)
      Bits[i] &= ~RHS.Bits[i];
    return *this;
  }

                                           
                                               
  bool test(const BitVector &RHS) const {
    unsigned ThisWords = NumBitWords(size());
    unsigned RHSWords  = NumBitWords(RHS.size());
    unsigned i;
    for (i = 0; i != std::min(ThisWords, RHSWords); ++i)
      if ((Bits[i] & ~RHS.Bits[i]) != 0)
        return true;

    for (; i != ThisWords ; ++i)
      if (Bits[i] != 0)
        return true;

    return false;
  }

  BitVector &operator|=(const BitVector &RHS) {
    if (size() < RHS.size())
      resize(RHS.size());
    for (size_t i = 0, e = NumBitWords(RHS.size()); i != e; ++i)
      Bits[i] |= RHS.Bits[i];
    return *this;
  }

  BitVector &operator^=(const BitVector &RHS) {
    if (size() < RHS.size())
      resize(RHS.size());
    for (size_t i = 0, e = NumBitWords(RHS.size()); i != e; ++i)
      Bits[i] ^= RHS.Bits[i];
    return *this;
  }

  BitVector &operator>>=(unsigned N) {
    assert(N <= Size);
    if (LLVM_UNLIKELY(empty() || N == 0))
      return *this;

    unsigned NumWords = NumBitWords(Size);
    assert(NumWords >= 1);

    wordShr(N / BITWORD_SIZE);

    unsigned BitDistance = N % BITWORD_SIZE;
    if (BitDistance == 0)
      return *this;

                                                                           
                                                                             
                                                                      
                                                                             
                                   

                                                                            
                                                                              
                                                                             
                                                                        
                                                                           
                        

               
                                                                              
                   
                                                   
                                                   
                                                   
                                                   
                                                   
                                                     
    const BitWord Mask = maskTrailingOnes<BitWord>(BitDistance);
    const unsigned LSH = BITWORD_SIZE - BitDistance;

    for (unsigned I = 0; I < NumWords - 1; ++I) {
      Bits[I] >>= BitDistance;
      Bits[I] |= (Bits[I + 1] & Mask) << LSH;
    }

    Bits[NumWords - 1] >>= BitDistance;

    return *this;
  }

  BitVector &operator<<=(unsigned N) {
    assert(N <= Size);
    if (LLVM_UNLIKELY(empty() || N == 0))
      return *this;

    unsigned NumWords = NumBitWords(Size);
    assert(NumWords >= 1);

    wordShl(N / BITWORD_SIZE);

    unsigned BitDistance = N % BITWORD_SIZE;
    if (BitDistance == 0)
      return *this;

                                                                           
                                                                             
                                                                          
                                                                             
                                                                              
                                     

                                                                           
                                                                              
                                                                             
                                                                         
                                                                        
                    

               
                                                                             
                   
                                                   
                                                   
                                                   
                                                   
                                                   
                                                     
    const BitWord Mask = maskLeadingOnes<BitWord>(BitDistance);
    const unsigned RSH = BITWORD_SIZE - BitDistance;

    for (int I = NumWords - 1; I > 0; --I) {
      Bits[I] <<= BitDistance;
      Bits[I] |= (Bits[I - 1] & Mask) >> RSH;
    }
    Bits[0] <<= BitDistance;
    clear_unused_bits();

    return *this;
  }

                         
  const BitVector &operator=(const BitVector &RHS) {
    if (this == &RHS) return *this;

    Size = RHS.size();
    unsigned RHSWords = NumBitWords(Size);
    if (Size <= getBitCapacity()) {
      if (Size)
        std::memcpy(Bits.data(), RHS.Bits.data(), RHSWords * sizeof(BitWord));
      clear_unused_bits();
      return *this;
    }

                                                  
    unsigned NewCapacity = RHSWords;
    assert(NewCapacity > 0 && "negative capacity?");
    auto NewBits = allocate(NewCapacity);
    std::memcpy(NewBits.data(), RHS.Bits.data(), NewCapacity * sizeof(BitWord));

                            
    std::free(Bits.data());
    Bits = NewBits;

    return *this;
  }

  const BitVector &operator=(BitVector &&RHS) {
    if (this == &RHS) return *this;

    std::free(Bits.data());
    Bits = RHS.Bits;
    Size = RHS.Size;

    RHS.Bits = MutableArrayRef<BitWord>();
    RHS.Size = 0;

    return *this;
  }

  void swap(BitVector &RHS) {
    std::swap(Bits, RHS.Bits);
    std::swap(Size, RHS.Size);
  }

                                                                                
                                  
                                                                                
    
                                                                               
                                                                              
                      
    
                                                                             
                                                                            
                                                                  

                                                                          
                                    
  void setBitsInMask(const uint32_t *Mask, unsigned MaskWords = ~0u) {
    applyMask<true, false>(Mask, MaskWords);
  }

                                                                           
                                                   
  void clearBitsInMask(const uint32_t *Mask, unsigned MaskWords = ~0u) {
    applyMask<false, false>(Mask, MaskWords);
  }

                                                                            
                                                    
  void setBitsNotInMask(const uint32_t *Mask, unsigned MaskWords = ~0u) {
    applyMask<true, true>(Mask, MaskWords);
  }

                                                                                
                                                   
  void clearBitsNotInMask(const uint32_t *Mask, unsigned MaskWords = ~0u) {
    applyMask<false, true>(Mask, MaskWords);
  }

private:
                                                                         
                                            
     
                                                                            
                                                                           
                                                                            
                                                                          
                                                                         
              
                                                                
                                                                           
                                                                             
                                                                           
                                          
  void wordShl(uint32_t Count) {
    if (Count == 0)
      return;

    uint32_t NumWords = NumBitWords(Size);

    auto Src = Bits.take_front(NumWords).drop_back(Count);
    auto Dest = Bits.take_front(NumWords).drop_front(Count);

                                                                            
                                                                          
            
    std::memmove(Dest.begin(), Src.begin(), Dest.size() * sizeof(BitWord));
    std::memset(Bits.data(), 0, Count * sizeof(BitWord));
    clear_unused_bits();
  }

                                                                     
                                                                     
     
  void wordShr(uint32_t Count) {
    if (Count == 0)
      return;

    uint32_t NumWords = NumBitWords(Size);

    auto Src = Bits.take_front(NumWords).drop_front(Count);
    auto Dest = Bits.take_front(NumWords).drop_back(Count);
    assert(Dest.size() == Src.size());

    std::memmove(Dest.begin(), Src.begin(), Dest.size() * sizeof(BitWord));
    std::memset(Dest.end(), 0, Count * sizeof(BitWord));
  }

  MutableArrayRef<BitWord> allocate(size_t NumWords) {
    BitWord *RawBits = static_cast<BitWord *>(
        safe_malloc(NumWords * sizeof(BitWord)));
    return MutableArrayRef<BitWord>(RawBits, NumWords);
  }

  int next_unset_in_word(int WordIndex, BitWord Word) const {
    unsigned Result = WordIndex * BITWORD_SIZE + countTrailingOnes(Word);
    return Result < size() ? Result : -1;
  }

  unsigned NumBitWords(unsigned S) const {
    return (S + BITWORD_SIZE-1) / BITWORD_SIZE;
  }

                                           
  void set_unused_bits(bool t = true) {
                             
    unsigned UsedWords = NumBitWords(Size);
    if (Bits.size() > UsedWords)
      init_words(Bits.drop_front(UsedWords), t);

                                                           
    unsigned ExtraBits = Size % BITWORD_SIZE;
    if (ExtraBits) {
      BitWord ExtraBitMask = ~0UL << ExtraBits;
      if (t)
        Bits[UsedWords-1] |= ExtraBitMask;
      else
        Bits[UsedWords-1] &= ~ExtraBitMask;
    }
  }

                                             
  void clear_unused_bits() {
    set_unused_bits(false);
  }

  void grow(unsigned NewSize) {
    size_t NewCapacity = std::max<size_t>(NumBitWords(NewSize), Bits.size() * 2);
    assert(NewCapacity > 0 && "realloc-ing zero space");
    BitWord *NewBits = static_cast<BitWord *>(
        safe_realloc(Bits.data(), NewCapacity * sizeof(BitWord)));
    Bits = MutableArrayRef<BitWord>(NewBits, NewCapacity);
    clear_unused_bits();
  }

  void init_words(MutableArrayRef<BitWord> B, bool t) {
    if (B.size() > 0)
      memset(B.data(), 0 - (int)t, B.size() * sizeof(BitWord));
  }

  template<bool AddBits, bool InvertMask>
  void applyMask(const uint32_t *Mask, unsigned MaskWords) {
    static_assert(BITWORD_SIZE % 32 == 0, "Unsupported BitWord size.");
    MaskWords = std::min(MaskWords, (size() + 31) / 32);
    const unsigned Scale = BITWORD_SIZE / 32;
    unsigned i;
    for (i = 0; MaskWords >= Scale; ++i, MaskWords -= Scale) {
      BitWord BW = Bits[i];
                                                                         
      for (unsigned b = 0; b != BITWORD_SIZE; b += 32) {
        uint32_t M = *Mask++;
        if (InvertMask) M = ~M;
        if (AddBits) BW |=   BitWord(M) << b;
        else         BW &= ~(BitWord(M) << b);
      }
      Bits[i] = BW;
    }
    for (unsigned b = 0; MaskWords; b += 32, --MaskWords) {
      uint32_t M = *Mask++;
      if (InvertMask) M = ~M;
      if (AddBits) Bits[i] |=   BitWord(M) << b;
      else         Bits[i] &= ~(BitWord(M) << b);
    }
    if (AddBits)
      clear_unused_bits();
  }

public:
                                                   
  size_t getMemorySize() const { return Bits.size() * sizeof(BitWord); }
  size_t getBitCapacity() const { return Bits.size() * BITWORD_SIZE; }
};

inline size_t capacity_in_bytes(const BitVector &X) {
  return X.getMemorySize();
}

}                      

namespace std {
                                                     
  inline void
  swap(llvh::BitVector &LHS, llvh::BitVector &RHS) {
    LHS.swap(RHS);
  }
}                     

#endif                        

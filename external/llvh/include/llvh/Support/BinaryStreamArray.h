//===- BinaryStreamArray.h - Array backed by an arbitrary stream *- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_BINARYSTREAMARRAY_H
#define LLVM_SUPPORT_BINARYSTREAMARRAY_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/iterator.h"
#include "llvh/Support/BinaryStreamRef.h"
#include "llvh/Support/Error.h"
#include <cassert>
#include <cstdint>

                                                                               
                                                 
   
                                                                               
                                                                             
                                                            
   
                                                                              
                                                                              
                                                                          
namespace llvh {

                                                                               
                                                                             
                                                                               
                                                                              
                                                                           
                                                                             
                                                                              
                                                       
   
                                                                             
                                                                              
           
template <typename T> struct VarStreamArrayExtractor {
                                                                               
                                           
  Error operator()(BinaryStreamRef Stream, uint32_t &Len,
                   T &Item) const = delete;
};

                                                                             
                                                                             
                                                                            
                                                                            
                                                                          
                                                                       
                                                                             
                                                                       
                                                                              
                                                                             
                                                               
   
                                                                                
                                                                           
                                                  
   
                                                                            
                                                                            
                                                                           
                                                                       
                              
   
                                                                       
                                             
   
                                                                         
                                                           
   
                                                                    
                                                                        
                                     
                                                              
   

template <typename ValueType, typename Extractor> class VarStreamArrayIterator;

template <typename ValueType,
          typename Extractor = VarStreamArrayExtractor<ValueType>>
class VarStreamArray {
  friend class VarStreamArrayIterator<ValueType, Extractor>;

public:
  typedef VarStreamArrayIterator<ValueType, Extractor> Iterator;

  VarStreamArray() = default;

  explicit VarStreamArray(const Extractor &E) : E(E) {}

  explicit VarStreamArray(BinaryStreamRef Stream) : Stream(Stream) {}

  VarStreamArray(BinaryStreamRef Stream, const Extractor &E)
      : Stream(Stream), E(E) {}

  Iterator begin(bool *HadError = nullptr) const {
    return Iterator(*this, E, HadError);
  }

  bool valid() const { return Stream.valid(); }

  Iterator end() const { return Iterator(E); }

  bool empty() const { return Stream.getLength() == 0; }

                                                                   
                                                                       
                                                                        
                                  
  Iterator at(uint32_t Offset) const {
    return Iterator(*this, E, Offset, nullptr);
  }

  const Extractor &getExtractor() const { return E; }
  Extractor &getExtractor() { return E; }

  BinaryStreamRef getUnderlyingStream() const { return Stream; }
  void setUnderlyingStream(BinaryStreamRef S) { Stream = S; }

private:
  BinaryStreamRef Stream;
  Extractor E;
};

template <typename ValueType, typename Extractor>
class VarStreamArrayIterator
    : public iterator_facade_base<VarStreamArrayIterator<ValueType, Extractor>,
                                  std::forward_iterator_tag, ValueType> {
  typedef VarStreamArrayIterator<ValueType, Extractor> IterType;
  typedef VarStreamArray<ValueType, Extractor> ArrayType;

public:
  VarStreamArrayIterator(const ArrayType &Array, const Extractor &E,
                         bool *HadError)
      : VarStreamArrayIterator(Array, E, 0, HadError) {}

  VarStreamArrayIterator(const ArrayType &Array, const Extractor &E,
                         uint32_t Offset, bool *HadError)
      : IterRef(Array.Stream.drop_front(Offset)), Extract(E),
        Array(&Array), AbsOffset(Offset), HadError(HadError) {
    if (IterRef.getLength() == 0)
      moveToEnd();
    else {
      auto EC = Extract(IterRef, ThisLen, ThisValue);
      if (EC) {
        consumeError(std::move(EC));
        markError();
      }
    }
  }

  VarStreamArrayIterator() = default;
  explicit VarStreamArrayIterator(const Extractor &E) : Extract(E) {}
  ~VarStreamArrayIterator() = default;

  bool operator==(const IterType &R) const {
    if (Array && R.Array) {
                                                         
      assert(Array == R.Array);
      return IterRef == R.IterRef;
    }

                                     
    if (!Array && !R.Array)
      return true;

                                        
    return false;
  }

  const ValueType &operator*() const {
    assert(Array && !HasError);
    return ThisValue;
  }

  ValueType &operator*() {
    assert(Array && !HasError);
    return ThisValue;
  }

  IterType &operator+=(unsigned N) {
    for (unsigned I = 0; I < N; ++I) {
                                                                       
                                       
      AbsOffset += ThisLen;
      IterRef = IterRef.drop_front(ThisLen);
      if (IterRef.getLength() == 0) {
                                                                              
                    
        moveToEnd();
      } else {
                                                       
        auto EC = Extract(IterRef, ThisLen, ThisValue);
        if (EC) {
          consumeError(std::move(EC));
          markError();
        } else if (ThisLen == 0) {
                                                        
          moveToEnd();
        }
      }
    }
    return *this;
  }

  uint32_t offset() const { return AbsOffset; }
  uint32_t getRecordLength() const { return ThisLen; }

private:
  void moveToEnd() {
    Array = nullptr;
    ThisLen = 0;
  }
  void markError() {
    moveToEnd();
    HasError = true;
    if (HadError != nullptr)
      *HadError = true;
  }

  ValueType ThisValue;
  BinaryStreamRef IterRef;
  Extractor Extract;
  const ArrayType *Array{nullptr};
  uint32_t ThisLen{0};
  uint32_t AbsOffset{0};
  bool HasError{false};
  bool *HadError{nullptr};
};

template <typename T> class FixedStreamArrayIterator;

                                                                          
                                                                       
                                                                       
                                                                          
                        
template <typename T> class FixedStreamArray {
  friend class FixedStreamArrayIterator<T>;

public:
  typedef FixedStreamArrayIterator<T> Iterator;

  FixedStreamArray() = default;
  explicit FixedStreamArray(BinaryStreamRef Stream) : Stream(Stream) {
    assert(Stream.getLength() % sizeof(T) == 0);
  }

  bool operator==(const FixedStreamArray<T> &Other) const {
    return Stream == Other.Stream;
  }

  bool operator!=(const FixedStreamArray<T> &Other) const {
    return !(*this == Other);
  }

  FixedStreamArray &operator=(const FixedStreamArray &) = default;

  const T &operator[](uint32_t Index) const {
    assert(Index < size());
    uint32_t Off = Index * sizeof(T);
    ArrayRef<uint8_t> Data;
    if (auto EC = Stream.readBytes(Off, sizeof(T), Data)) {
      assert(false && "Unexpected failure reading from stream");
                                                                              
                                               
      consumeError(std::move(EC));
    }
    assert(llvh::alignmentAdjustment(Data.data(), alignof(T)) == 0);
    return *reinterpret_cast<const T *>(Data.data());
  }

  uint32_t size() const { return Stream.getLength() / sizeof(T); }

  bool empty() const { return size() == 0; }

  FixedStreamArrayIterator<T> begin() const {
    return FixedStreamArrayIterator<T>(*this, 0);
  }

  FixedStreamArrayIterator<T> end() const {
    return FixedStreamArrayIterator<T>(*this, size());
  }

  const T &front() const { return *begin(); }
  const T &back() const {
    FixedStreamArrayIterator<T> I = end();
    return *(--I);
  }

  BinaryStreamRef getUnderlyingStream() const { return Stream; }

private:
  BinaryStreamRef Stream;
};

template <typename T>
class FixedStreamArrayIterator
    : public iterator_facade_base<FixedStreamArrayIterator<T>,
                                  std::random_access_iterator_tag, const T> {

public:
  FixedStreamArrayIterator(const FixedStreamArray<T> &Array, uint32_t Index)
      : Array(Array), Index(Index) {}

  FixedStreamArrayIterator<T> &
  operator=(const FixedStreamArrayIterator<T> &Other) {
    Array = Other.Array;
    Index = Other.Index;
    return *this;
  }

  const T &operator*() const { return Array[Index]; }
  const T &operator*() { return Array[Index]; }

  bool operator==(const FixedStreamArrayIterator<T> &R) const {
    assert(Array == R.Array);
    return (Index == R.Index) && (Array == R.Array);
  }

  FixedStreamArrayIterator<T> &operator+=(std::ptrdiff_t N) {
    Index += N;
    return *this;
  }

  FixedStreamArrayIterator<T> &operator-=(std::ptrdiff_t N) {
    assert(std::ptrdiff_t(Index) >= N);
    Index -= N;
    return *this;
  }

  std::ptrdiff_t operator-(const FixedStreamArrayIterator<T> &R) const {
    assert(Array == R.Array);
    assert(Index >= R.Index);
    return Index - R.Index;
  }

  bool operator<(const FixedStreamArrayIterator<T> &RHS) const {
    assert(Array == RHS.Array);
    return Index < RHS.Index;
  }

private:
  FixedStreamArray<T> Array;
  uint32_t Index;
};

}                  

#endif                                    

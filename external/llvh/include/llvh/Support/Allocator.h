//===- Allocator.h - Simple memory allocation abstraction -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
/// \file
///
/// This file defines the MallocAllocator and BumpPtrAllocator interfaces. Both
/// of these conform to an LLVM "Allocator" concept which consists of an
/// Allocate method accepting a size and alignment, and a Deallocate accepting
/// a pointer and size. Further, the LLVM "Allocator" concept has overloads of
/// Allocate and Deallocate for setting size and alignment based on the final
/// type. These overloads are typically provided by a base class template \c
/// AllocatorBase.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_ALLOCATOR_H
#define LLVM_SUPPORT_ALLOCATOR_H

#include "llvh/ADT/Optional.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/Support/Compiler.h"
#include "llvh/Support/ErrorHandling.h"
#include "llvh/Support/MathExtras.h"
#include "llvh/Support/MemAlloc.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iterator>
#include <type_traits>
#include <utility>

namespace llvh {

                                                               
                                                
   
                                                                           
                                                                              
                                                       
template <typename DerivedT> class AllocatorBase {
public:
                                                                        
                                         
  void *Allocate(size_t Size, size_t Alignment) {
#ifdef __clang__
    static_assert(static_cast<void *(AllocatorBase::*)(size_t, size_t)>(
                      &AllocatorBase::Allocate) !=
                      static_cast<void *(DerivedT::*)(size_t, size_t)>(
                          &DerivedT::Allocate),
                  "Class derives from AllocatorBase without implementing the "
                  "core Allocate(size_t, size_t) overload!");
#endif
    return static_cast<DerivedT *>(this)->Allocate(Size, Alignment);
  }

                                                                    
                
  void Deallocate(const void *Ptr, size_t Size) {
#ifdef __clang__
    static_assert(static_cast<void (AllocatorBase::*)(const void *, size_t)>(
                      &AllocatorBase::Deallocate) !=
                      static_cast<void (DerivedT::*)(const void *, size_t)>(
                          &DerivedT::Deallocate),
                  "Class derives from AllocatorBase without implementing the "
                  "core Deallocate(void *) overload!");
#endif
    return static_cast<DerivedT *>(this)->Deallocate(Ptr, Size);
  }

                                                                            
                  

                                                                         
  template <typename T> T *Allocate(size_t Num = 1) {
    return static_cast<T *>(Allocate(Num * sizeof(T), alignof(T)));
  }

                                                                           
  template <typename T>
  typename std::enable_if<
      !std::is_same<typename std::remove_cv<T>::type, void>::value, void>::type
  Deallocate(T *Ptr, size_t Num = 1) {
    Deallocate(static_cast<const void *>(Ptr), Num * sizeof(T));
  }
};

class MallocAllocator : public AllocatorBase<MallocAllocator> {
public:
  void Reset() {}

  LLVM_ATTRIBUTE_RETURNS_NONNULL void *Allocate(size_t Size,
                                                size_t              ) {
    return safe_malloc(Size);
  }

                                  
  using AllocatorBase<MallocAllocator>::Allocate;

  void Deallocate(const void *Ptr, size_t         ) {
    free(const_cast<void *>(Ptr));
  }

                                  
  using AllocatorBase<MallocAllocator>::Deallocate;

  void PrintStats() const {}
};

namespace detail {

                                                                           
                                                        
void printBumpPtrAllocatorStats(unsigned NumSlabs, size_t BytesAllocated,
                                size_t TotalMemory);

}                        

                                                                   
   
                                                                            
                                                                              
                                                                               
                                                                            
                                                   
   
                                                                               
                             
   
                                                                         
                                                                            
                           
template <typename AllocatorT = MallocAllocator, size_t SlabSize = 4096,
          size_t SizeThreshold = SlabSize>
class BumpPtrAllocatorImpl
    : public AllocatorBase<
          BumpPtrAllocatorImpl<AllocatorT, SlabSize, SizeThreshold>> {
public:
  static_assert(SizeThreshold <= SlabSize,
                "The SizeThreshold must be at most the SlabSize to ensure "
                "that objects larger than a slab go into their own memory "
                "allocation.");

  BumpPtrAllocatorImpl() = default;

  template <typename T>
  BumpPtrAllocatorImpl(T &&Allocator)
      : Allocator(std::forward<T &&>(Allocator)) {}

                                                                               
                                      
  BumpPtrAllocatorImpl(BumpPtrAllocatorImpl &&Old)
      : CurPtr(Old.CurPtr), End(Old.End), Slabs(std::move(Old.Slabs)),
        CustomSizedSlabs(std::move(Old.CustomSizedSlabs)),
        BytesAllocated(Old.BytesAllocated), RedZoneSize(Old.RedZoneSize),
        Allocator(std::move(Old.Allocator)) {
    Old.CurPtr = Old.End = nullptr;
    Old.BytesAllocated = 0;
    Old.Slabs.clear();
    Old.CustomSizedSlabs.clear();
  }

  ~BumpPtrAllocatorImpl() {
    DeallocateSlabs(Slabs.begin(), Slabs.end());
    DeallocateCustomSizedSlabs();
  }

  BumpPtrAllocatorImpl &operator=(BumpPtrAllocatorImpl &&RHS) {
    DeallocateSlabs(Slabs.begin(), Slabs.end());
    DeallocateCustomSizedSlabs();

    CurPtr = RHS.CurPtr;
    End = RHS.End;
    BytesAllocated = RHS.BytesAllocated;
    RedZoneSize = RHS.RedZoneSize;
    Slabs = std::move(RHS.Slabs);
    CustomSizedSlabs = std::move(RHS.CustomSizedSlabs);
    Allocator = std::move(RHS.Allocator);

    RHS.CurPtr = RHS.End = nullptr;
    RHS.BytesAllocated = 0;
    RHS.Slabs.clear();
    RHS.CustomSizedSlabs.clear();
    return *this;
  }

                                                                       
                                                                  
  void Reset() {
                                                                                
    DeallocateCustomSizedSlabs();
    CustomSizedSlabs.clear();

    if (Slabs.empty())
      return;

                       
    BytesAllocated = 0;
    CurPtr = (char *)Slabs.front();
    End = CurPtr + SlabSize;

    __asan_poison_memory_region(*Slabs.begin(), computeSlabSize(0));
    DeallocateSlabs(std::next(Slabs.begin()), Slabs.end());
    Slabs.erase(std::next(Slabs.begin()), Slabs.end());
  }

                                                
  LLVM_ATTRIBUTE_RETURNS_NONNULL LLVM_ATTRIBUTE_RETURNS_NOALIAS void *
  Allocate(size_t Size, size_t Alignment) {
    assert(Alignment > 0 && "0-byte alignnment is not allowed. Use 1 instead.");

                                                    
    BytesAllocated += Size;

    size_t Adjustment = alignmentAdjustment(CurPtr, Alignment);
    assert(Adjustment + Size >= Size && "Adjustment + Size must not overflow");

    size_t SizeToAllocate = Size;
#if LLVM_ADDRESS_SANITIZER_BUILD
                                                     
    SizeToAllocate += RedZoneSize;
#endif

                                     
    if (Adjustment + SizeToAllocate <= size_t(End - CurPtr)) {
      char *AlignedPtr = CurPtr + Adjustment;
      CurPtr = AlignedPtr + SizeToAllocate;
                                                                             
                                                                               
                                                         
      __msan_allocated_memory(AlignedPtr, Size);
                                               
      __asan_unpoison_memory_region(AlignedPtr, Size);
      return AlignedPtr;
    }

                                                              
    size_t PaddedSize = SizeToAllocate + Alignment - 1;
    if (PaddedSize > SizeThreshold) {
      void *NewSlab = Allocator.Allocate(PaddedSize, 0);
                                                                             
                                                                     
      __asan_poison_memory_region(NewSlab, PaddedSize);
      CustomSizedSlabs.push_back(std::make_pair(NewSlab, PaddedSize));

      uintptr_t AlignedAddr = alignAddr(NewSlab, Alignment);
      assert(AlignedAddr + Size <= (uintptr_t)NewSlab + PaddedSize);
      char *AlignedPtr = (char*)AlignedAddr;
      __msan_allocated_memory(AlignedPtr, Size);
      __asan_unpoison_memory_region(AlignedPtr, Size);
      return AlignedPtr;
    }

                                                 
    StartNewSlab();
    uintptr_t AlignedAddr = alignAddr(CurPtr, Alignment);
    assert(AlignedAddr + SizeToAllocate <= (uintptr_t)End &&
           "Unable to allocate memory!");
    char *AlignedPtr = (char*)AlignedAddr;
    CurPtr = AlignedPtr + SizeToAllocate;
    __msan_allocated_memory(AlignedPtr, Size);
    __asan_unpoison_memory_region(AlignedPtr, Size);
    return AlignedPtr;
  }

                                  
  using AllocatorBase<BumpPtrAllocatorImpl>::Allocate;

                                                                          
                                                                            
                        
  void Deallocate(const void *Ptr, size_t Size) {
    __asan_poison_memory_region(Ptr, Size);
  }

                                  
  using AllocatorBase<BumpPtrAllocatorImpl>::Deallocate;

  size_t GetNumSlabs() const { return Slabs.size() + CustomSizedSlabs.size(); }

                                                            
                                                     
                                                                           
           
                                                                             
  llvh::Optional<int64_t> identifyObject(const void *Ptr) {
    const char *P = static_cast<const char *>(Ptr);
    int64_t InSlabIdx = 0;
    for (size_t Idx = 0, E = Slabs.size(); Idx < E; Idx++) {
      const char *S = static_cast<const char *>(Slabs[Idx]);
      if (P >= S && P < S + computeSlabSize(Idx))
        return InSlabIdx + static_cast<int64_t>(P - S);
      InSlabIdx += static_cast<int64_t>(computeSlabSize(Idx));
    }

                                                       
    int64_t InCustomSizedSlabIdx = -1;
    for (size_t Idx = 0, E = CustomSizedSlabs.size(); Idx < E; Idx++) {
      const char *S = static_cast<const char *>(CustomSizedSlabs[Idx].first);
      size_t Size = CustomSizedSlabs[Idx].second;
      if (P >= S && P < S + Size)
        return InCustomSizedSlabIdx - static_cast<int64_t>(P - S);
      InCustomSizedSlabIdx -= static_cast<int64_t>(Size);
    }
    return None;
  }

  size_t getTotalMemory() const {
    size_t TotalMemory = 0;
    for (auto I = Slabs.begin(), E = Slabs.end(); I != E; ++I)
      TotalMemory += computeSlabSize(std::distance(Slabs.begin(), I));
    for (auto &PtrAndSize : CustomSizedSlabs)
      TotalMemory += PtrAndSize.second;
    return TotalMemory;
  }

  size_t getBytesAllocated() const { return BytesAllocated; }

  void setRedZoneSize(size_t NewSize) {
    RedZoneSize = NewSize;
  }

  void PrintStats() const {
    detail::printBumpPtrAllocatorStats(Slabs.size(), BytesAllocated,
                                       getTotalMemory());
  }

private:
                                                
     
                                                    
  char *CurPtr = nullptr;

                                  
  char *End = nullptr;

                                 
  SmallVector<void *, 4> Slabs;

                                                                     
  SmallVector<std::pair<void *, size_t>, 0> CustomSizedSlabs;

                                     
     
                                                            
  size_t BytesAllocated = 0;

                                                                       
                  
  size_t RedZoneSize = 1;

                                                           
  AllocatorT Allocator;

  static size_t computeSlabSize(unsigned SlabIdx) {
                                                                        
                                                                            
                                                                                
            
    return SlabSize * ((size_t)1 << std::min<size_t>(30, SlabIdx / 128));
  }

                                                                      
                                     
  void StartNewSlab() {
    size_t AllocatedSlabSize = computeSlabSize(Slabs.size());

    void *NewSlab = Allocator.Allocate(AllocatedSlabSize, 0);
                                                                            
                                                                   
    __asan_poison_memory_region(NewSlab, AllocatedSlabSize);

    Slabs.push_back(NewSlab);
    CurPtr = (char *)(NewSlab);
    End = ((char *)NewSlab) + AllocatedSlabSize;
  }

                                     
  void DeallocateSlabs(SmallVectorImpl<void *>::iterator I,
                       SmallVectorImpl<void *>::iterator E) {
    for (; I != E; ++I) {
      size_t AllocatedSlabSize =
          computeSlabSize(std::distance(Slabs.begin(), I));
      Allocator.Deallocate(*I, AllocatedSlabSize);
    }
  }

                                                   
  void DeallocateCustomSizedSlabs() {
    for (auto &PtrAndSize : CustomSizedSlabs) {
      void *Ptr = PtrAndSize.first;
      size_t Size = PtrAndSize.second;
      Allocator.Deallocate(Ptr, Size);
    }
  }

  template <typename T> friend class SpecificBumpPtrAllocator;
};

                                                                      
               
typedef BumpPtrAllocatorImpl<> BumpPtrAllocator;

                                                                         
              
   
                                                                                
              
template <typename T> class SpecificBumpPtrAllocator {
  BumpPtrAllocator Allocator;

public:
  SpecificBumpPtrAllocator() {
                                                                             
                                                   
    Allocator.setRedZoneSize(0);
  }
  SpecificBumpPtrAllocator(SpecificBumpPtrAllocator &&Old)
      : Allocator(std::move(Old.Allocator)) {}
  ~SpecificBumpPtrAllocator() { DestroyAll(); }

  SpecificBumpPtrAllocator &operator=(SpecificBumpPtrAllocator &&RHS) {
    Allocator = std::move(RHS.Allocator);
    return *this;
  }

                                                                             
                                                                                
                                  
  void DestroyAll() {
    auto DestroyElements = [](char *Begin, char *End) {
      assert(Begin == (char *)alignAddr(Begin, alignof(T)));
      for (char *Ptr = Begin; Ptr + sizeof(T) <= End; Ptr += sizeof(T))
        reinterpret_cast<T *>(Ptr)->~T();
    };

    for (auto I = Allocator.Slabs.begin(), E = Allocator.Slabs.end(); I != E;
         ++I) {
      size_t AllocatedSlabSize = BumpPtrAllocator::computeSlabSize(
          std::distance(Allocator.Slabs.begin(), I));
      char *Begin = (char *)alignAddr(*I, alignof(T));
      char *End = *I == Allocator.Slabs.back() ? Allocator.CurPtr
                                               : (char *)*I + AllocatedSlabSize;

      DestroyElements(Begin, End);
    }

    for (auto &PtrAndSize : Allocator.CustomSizedSlabs) {
      void *Ptr = PtrAndSize.first;
      size_t Size = PtrAndSize.second;
      DestroyElements((char *)alignAddr(Ptr, alignof(T)), (char *)Ptr + Size);
    }

    Allocator.Reset();
  }

                                                                       
  T *Allocate(size_t num = 1) { return Allocator.Allocate<T>(num); }
};

}                      

template <typename AllocatorT, size_t SlabSize, size_t SizeThreshold>
void *operator new(size_t Size,
                   llvh::BumpPtrAllocatorImpl<AllocatorT, SlabSize,
                                              SizeThreshold> &Allocator) {
  struct S {
    char c;
    union {
      double D;
      long double LD;
      long long L;
      void *P;
    } x;
  };
  return Allocator.Allocate(
      Size, std::min((size_t)llvh::NextPowerOf2(Size), offsetof(S, x)));
}

template <typename AllocatorT, size_t SlabSize, size_t SizeThreshold>
void operator delete(
    void *, llvh::BumpPtrAllocatorImpl<AllocatorT, SlabSize, SizeThreshold> &) {
}

#endif                            

//==- llvm/Support/ArrayRecycler.h - Recycling of Arrays ---------*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the ArrayRecycler class template which can recycle small
// arrays allocated from one of the allocators in Allocator.h
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_ARRAYRECYCLER_H
#define LLVM_SUPPORT_ARRAYRECYCLER_H

#include "llvh/ADT/SmallVector.h"
#include "llvh/Support/Allocator.h"
#include "llvh/Support/MathExtras.h"

namespace llvh {

                                                           
   
                                                                             
                                                                        
   
template <class T, size_t Align = alignof(T)> class ArrayRecycler {
                                                                         
                                                                              
  struct FreeList {
    FreeList *Next;
  };

  static_assert(Align >= alignof(FreeList), "Object underaligned");
  static_assert(sizeof(T) >= sizeof(FreeList), "Objects are too small");

                                          
  SmallVector<FreeList*, 8> Bucket;

                                                                     
                                             
  T *pop(unsigned Idx) {
    if (Idx >= Bucket.size())
      return nullptr;
    FreeList *Entry = Bucket[Idx];
    if (!Entry)
      return nullptr;
    __asan_unpoison_memory_region(Entry, Capacity::get(Idx).getSize());
    Bucket[Idx] = Entry->Next;
    __msan_allocated_memory(Entry, Capacity::get(Idx).getSize());
    return reinterpret_cast<T*>(Entry);
  }

                                                  
  void push(unsigned Idx, T *Ptr) {
    assert(Ptr && "Cannot recycle NULL pointer");
    FreeList *Entry = reinterpret_cast<FreeList*>(Ptr);
    if (Idx >= Bucket.size())
      Bucket.resize(size_t(Idx) + 1);
    Entry->Next = Bucket[Idx];
    Bucket[Idx] = Entry;
    __asan_poison_memory_region(Ptr, Capacity::get(Idx).getSize());
  }

public:
                                                                           
     
                                                                               
                                             
  class Capacity {
    uint8_t Index;
    explicit Capacity(uint8_t idx) : Index(idx) {}

  public:
    Capacity() : Index(0) {}

                                                                       
    static Capacity get(size_t N) {
      return Capacity(N ? Log2_64_Ceil(N) : 0);
    }

                                                                  
    size_t getSize() const { return size_t(1u) << Index; }

                                                
    unsigned getBucket() const { return Index; }

                                                                             
                                                                             
                                 
    Capacity getNext() const { return Capacity(Index + 1); }
  };

  ~ArrayRecycler() {
                                                                               
                        
    assert(Bucket.empty() && "Non-empty ArrayRecycler deleted!");
  }

                                                                             
                                                              
  template<class AllocatorType>
  void clear(AllocatorType &Allocator) {
    for (; !Bucket.empty(); Bucket.pop_back())
      while (T *Ptr = pop(Bucket.size() - 1))
        Allocator.Deallocate(Ptr);
  }

                                                                       
               
     
                                                                               
            
  void clear(BumpPtrAllocator&) {
    Bucket.clear();
  }

                                                           
     
                                                                          
                                       
     
  template<class AllocatorType>
  T *allocate(Capacity Cap, AllocatorType &Allocator) {
                                        
    if (T *Ptr = pop(Cap.getBucket()))
      return Ptr;
                             
    return static_cast<T*>(Allocator.Allocate(sizeof(T)*Cap.getSize(), Align));
  }

                                                      
     
                                                                 
     
  void deallocate(Capacity Cap, T *Ptr) {
    push(Cap.getBucket(), Ptr);
  }
};

}                      

#endif

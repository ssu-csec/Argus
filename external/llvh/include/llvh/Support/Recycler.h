//==- llvm/Support/Recycler.h - Recycling Allocator --------------*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the Recycler class template.  See the doxygen comment for
// Recycler for more details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_RECYCLER_H
#define LLVM_SUPPORT_RECYCLER_H

#include "llvh/ADT/ilist.h"
#include "llvh/Support/Allocator.h"
#include "llvh/Support/ErrorHandling.h"
#include <cassert>

namespace llvh {

                                                                    
                        
   
void PrintRecyclerStats(size_t Size, size_t Align, size_t FreeListSize);

                                                                    
                                                                     
               
   
template <class T, size_t Size = sizeof(T), size_t Align = alignof(T)>
class Recycler {
  struct FreeNode {
    FreeNode *Next;
  };

                                                                         
  FreeNode *FreeList = nullptr;

  FreeNode *pop_val() {
    auto *Val = FreeList;
    __asan_unpoison_memory_region(Val, Size);
    FreeList = FreeList->Next;
    __msan_allocated_memory(Val, Size);
    return Val;
  }

  void push(FreeNode *N) {
    N->Next = FreeList;
    FreeList = N;
    __asan_poison_memory_region(N, Size);
  }

public:
  ~Recycler() {
                                                                          
                                                                    
                                            
    assert(!FreeList && "Non-empty recycler deleted!");
  }

                                                                       
                                                                   
                                                       
  template<class AllocatorType>
  void clear(AllocatorType &Allocator) {
    while (FreeList) {
      T *t = reinterpret_cast<T *>(pop_val());
      Allocator.Deallocate(t);
    }
  }

                                                                       
               
     
                                                                              
            
  void clear(BumpPtrAllocator &) { FreeList = nullptr; }

  template<class SubClass, class AllocatorType>
  SubClass *Allocate(AllocatorType &Allocator) {
    static_assert(alignof(SubClass) <= Align,
                  "Recycler allocation alignment is less than object align!");
    static_assert(sizeof(SubClass) <= Size,
                  "Recycler allocation size is less than object size!");
    return FreeList ? reinterpret_cast<SubClass *>(pop_val())
                    : static_cast<SubClass *>(Allocator.Allocate(Size, Align));
  }

  template<class AllocatorType>
  T *Allocate(AllocatorType &Allocator) {
    return Allocate<T>(Allocator);
  }

  template<class SubClass, class AllocatorType>
  void Deallocate(AllocatorType &              , SubClass* Element) {
    push(reinterpret_cast<FreeNode *>(Element));
  }

  void PrintStats();
};

template <class T, size_t Size, size_t Align>
void Recycler<T, Size, Align>::PrintStats() {
  size_t S = 0;
  for (auto *I = FreeList; I; I = I->Next)
    ++S;
  PrintRecyclerStats(Size, Align, S);
}

}

#endif

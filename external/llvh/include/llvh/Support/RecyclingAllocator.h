//==- llvm/Support/RecyclingAllocator.h - Recycling Allocator ----*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the RecyclingAllocator class.  See the doxygen comment for
// RecyclingAllocator for more details on the implementation.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_RECYCLINGALLOCATOR_H
#define LLVM_SUPPORT_RECYCLINGALLOCATOR_H

#include "llvh/Support/Recycler.h"

namespace llvh {

                                                                  
                                               
   
template <class AllocatorType, class T, size_t Size = sizeof(T),
          size_t Align = alignof(T)>
class RecyclingAllocator {
private:
                                    
     
  Recycler<T, Size, Align> Base;

                                        
     
  AllocatorType Allocator;

public:
  ~RecyclingAllocator() { Base.clear(Allocator); }

                                                                  
                                                                      
     
  template<class SubClass>
  SubClass *Allocate() { return Base.template Allocate<SubClass>(Allocator); }

  T *Allocate() { return Base.Allocate(Allocator); }

                                                                 
                                                        
     
  template<class SubClass>
  void Deallocate(SubClass* E) { return Base.Deallocate(Allocator, E); }

  void PrintStats() {
    Allocator.PrintStats();
    Base.PrintStats();
  }
};

}

template<class AllocatorType, class T, size_t Size, size_t Align>
inline void *operator new(size_t size,
                          llvh::RecyclingAllocator<AllocatorType,
                                                   T, Size, Align> &Allocator) {
  assert(size <= Size && "allocation size exceeded");
  return Allocator.Allocate();
}

template<class AllocatorType, class T, size_t Size, size_t Align>
inline void operator delete(void *E,
                            llvh::RecyclingAllocator<AllocatorType,
                                                     T, Size, Align> &A) {
  A.Deallocate(E);
}

#endif

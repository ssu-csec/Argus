/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_ALLOCATOR_H
#define HERMES_SUPPORT_ALLOCATOR_H

#include "hermes/Support/CheckedMalloc.h"

#include "llvh/ADT/STLExtras.h"
#include "llvh/Support/Compiler.h"
#include "llvh/Support/MathExtras.h"

#include <cstdint>
#include <memory>
#include <vector>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {

                                                                              
class BacktrackingBumpPtrAllocator {
 private:
                                    
                                                                             
                                                                              
                                                                             
  static const unsigned SlabSize = 256 << 10;

                                   
  static const unsigned kDefaultPlatformAlignment = sizeof(double);

                                             
  struct Slab {
    char data[SlabSize];
  };
                                             
  std::vector<std::unique_ptr<Slab>> slabs_{};

                                                                              
                            
  class State {
   public:
                                
    unsigned slab;
                                           
    uintptr_t offset;
                                                                           
    llvh::SmallVector<std::unique_ptr<void, decltype(free) *>, 0> hugeAllocs{};
                                        
    State *previous;

                                                       
    State(State *previous)
        : slab(previous->slab), offset(previous->offset), previous(previous) {}
                                    
    State() : slab(0), offset(0), previous(nullptr) {}
  };

                                            
  State *state_;

                                                          
  void *allocateHuge(size_t size) {
    auto *ptr = checkedMalloc(size);
    state_->hugeAllocs.push_back(
        std::unique_ptr<void, decltype(free) *>(ptr, free));
    return ptr;
  }

                                          
  static uintptr_t
  alignOffset(uintptr_t base, uintptr_t offset, uintptr_t alignment) {
    return llvh::alignTo(base + offset, alignment) - base;
  }

                                                                    
  void *allocateNewSlab(size_t size, size_t alignment = sizeof(double));

 public:
  explicit BacktrackingBumpPtrAllocator() {
    state_ = new State();
    slabs_.push_back(std::make_unique<Slab>());
  }
  ~BacktrackingBumpPtrAllocator() {
    while (state_)
      popScope();
  }

                                                                               
                                                         
  void pushScope() {
    state_ = new State(state_);
  }

                                                        
  void popScope() {
    assert(state_ && "No previous allocation scope pushed");
    auto *top = state_;
    state_ = state_->previous;
    delete top;
                                                                         
                                  
  }

                                              
  template <typename T>
  inline T *Allocate(size_t num = 1, size_t alignment = sizeof(double)) {
                                                                  
    constexpr size_t maxNum = std::numeric_limits<size_t>::max() / sizeof(T);
    if (LLVM_UNLIKELY(num > maxNum))
      hermes_fatal("Allocation size overflow.");
    size_t size = sizeof(T) * num;
    return static_cast<T *>(Allocate(size, alignment));
  }

                                       
  inline void *Allocate(
      size_t size,
      size_t alignment = kDefaultPlatformAlignment) {
    auto currentSlab =
        reinterpret_cast<uintptr_t>(&slabs_[state_->slab].get()->data);
    state_->offset = alignOffset(currentSlab, state_->offset, alignment);

    if (LLVM_UNLIKELY(size > SlabSize || state_->offset + size > SlabSize)) {
      return allocateNewSlab(size, alignment);
    }

    auto *ptr = (void *)(currentSlab + state_->offset);
    state_->offset += size;
    return ptr;
  }
};

                                                                                
class AllocationScope {
 private:
                                              
  BacktrackingBumpPtrAllocator &allocator_;

 public:
  AllocationScope(BacktrackingBumpPtrAllocator &allocator)
      : allocator_(allocator) {
    allocator_.pushScope();
  }
  ~AllocationScope() {
    allocator_.popScope();
  }
};

                                                       
using BumpPtrAllocator = BacktrackingBumpPtrAllocator;
}                    
#pragma GCC diagnostic pop

#endif                              

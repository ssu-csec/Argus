//===- llvm/ADT/SmallVector.cpp - 'Normally small' vectors ----------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the SmallVector class.
//
//===----------------------------------------------------------------------===//

#include "llvh/ADT/SmallVector.h"
using namespace llvh;

                                                                 
namespace {
struct Struct16B {
  alignas(16) void *X;
};
struct Struct32B {
  alignas(32) void *X;
};
}
static_assert(sizeof(SmallVector<void *, 0>) ==
                  sizeof(unsigned) * 2 + sizeof(void *),
              "wasted space in SmallVector size 0");
static_assert(alignof(SmallVector<Struct16B, 0>) >= alignof(Struct16B),
              "wrong alignment for 16-byte aligned T");
static_assert(alignof(SmallVector<Struct32B, 0>) >= alignof(Struct32B),
              "wrong alignment for 32-byte aligned T");
static_assert(sizeof(SmallVector<Struct16B, 0>) >= alignof(Struct16B),
              "missing padding for 16-byte aligned T");
static_assert(sizeof(SmallVector<Struct32B, 0>) >= alignof(Struct32B),
              "missing padding for 32-byte aligned T");
static_assert(sizeof(SmallVector<void *, 1>) ==
                  sizeof(unsigned) * 2 + sizeof(void *) * 2,
              "wasted space in SmallVector size 1");

                                                                              
                                                                        
void SmallVectorBase::grow_pod(void *FirstEl, size_t MinCapacity,
                               size_t TSize) {
  constexpr size_t MinGrowth = 1;
  size_t NewCapacity = 2 * capacity() + MinGrowth;                
  NewCapacity = static_cast<unsigned>(std::max(NewCapacity, MinCapacity));

                                                              
                                                               
  if (NewCapacity <= this->capacity() ||
      NewCapacity < MinCapacity ||
      NewCapacity > size_t(-1) / TSize)
    report_bad_alloc_error("SmallVector capacity overflow during allocation");

  void *NewElts;
  if (BeginX == FirstEl) {
    NewElts = safe_malloc(NewCapacity * TSize);

                                                             
    memcpy(NewElts, this->BeginX, size() * TSize);
  } else {
                                                                           
    NewElts = safe_realloc(this->BeginX, NewCapacity * TSize);
  }

  this->BeginX = NewElts;
  this->Capacity = NewCapacity;
}

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_MARKBITARRAYNC_H
#define HERMES_VM_MARKBITARRAYNC_H

#include "hermes/ADT/BitArray.h"
#include "hermes/Support/OSCompat.h"
#include "hermes/VM/AlignedStorage.h"
#include "hermes/VM/ExpectedPageSize.h"
#include "hermes/VM/HeapAlign.h"

namespace hermes {
namespace vm {

                                                                               
                                                                      
                                                                                
class MarkBitArrayNC {
 public:
  MarkBitArrayNC() = default;

                                                                       
               
  MarkBitArrayNC(const MarkBitArrayNC &) = delete;
  MarkBitArrayNC(MarkBitArrayNC &&) = delete;
  MarkBitArrayNC &operator=(const MarkBitArrayNC &) = delete;
  MarkBitArrayNC &operator=(MarkBitArrayNC &&) = delete;

                                                                     
     
                                                                              
                                                                                
                                                                           
  static constexpr size_t size();

                                                                     
                                                                  
                                                           
  inline size_t addressToIndex(const void *p) const;

                                                                   
                                                 
  inline char *indexToAddress(size_t ind) const;

                                                                             
                         
  inline bool at(size_t ind) const;

                                                                           
                         
  inline void mark(size_t ind);

                           
  inline void clear();

                            
  inline void markAll();

                                                                              
                                                                            
                                                                   
  inline size_t findNextMarkedBitFrom(size_t ind);

                                                                              
                                                                            
                                                                   
  inline size_t findNextUnmarkedBitFrom(size_t ind);

                                                                              
         
                                                                            
                                                                   
  inline size_t findPrevMarkedBitFrom(size_t ind);

                                                                              
                                                                                
                                                                   
  inline size_t findPrevUnmarkedBitFrom(size_t ind);

                                                                    
                                                                  
#if defined(UNIT_TEST) || defined(_MSC_VER)
 public:
#else
 private:
#endif

                                                                           
                                  
     
                                     
     
                                                                       
                                                                                
                             
  inline char *base() const;

                                                                                
                            
  static constexpr size_t kNumBits = AlignedStorage::size() >> LogHeapAlign;
                                                                             
           
  BitArray<kNumBits> bitArray_;
};

             constexpr size_t MarkBitArrayNC::size() {
  return kNumBits;
}

size_t MarkBitArrayNC::addressToIndex(const void *p) const {
  assert(
      base() <= p && p < AlignedStorage::end(base()) &&
      "precondition: argument must be within the covered range");
  auto cp = reinterpret_cast<const char *>(p);
  return (cp - base()) >> LogHeapAlign;
}

char *MarkBitArrayNC::indexToAddress(size_t ind) const {
  assert(ind < kNumBits && "ind must be within the index range");
  char *res = base() + (ind << LogHeapAlign);

  assert(
      base() <= res && res < AlignedStorage::end(base()) &&
      "result must be within the covered range.");
  return res;
}

bool MarkBitArrayNC::at(size_t ind) const {
  assert(ind < kNumBits && "precondition: ind must be within the index range");
  return bitArray_.at(ind);
}

void MarkBitArrayNC::mark(size_t ind) {
  assert(ind < kNumBits && "precondition: ind must be within the index range");
  bitArray_.set(ind, true);
}

void MarkBitArrayNC::clear() {
  bitArray_.reset();
}

void MarkBitArrayNC::markAll() {
  bitArray_.set();
}

size_t MarkBitArrayNC::findNextMarkedBitFrom(size_t ind) {
  return bitArray_.findNextSetBitFrom(ind);
}

size_t MarkBitArrayNC::findNextUnmarkedBitFrom(size_t ind) {
  return bitArray_.findNextZeroBitFrom(ind);
}

size_t MarkBitArrayNC::findPrevMarkedBitFrom(size_t ind) {
  return bitArray_.findPrevSetBitFrom(ind);
}

size_t MarkBitArrayNC::findPrevUnmarkedBitFrom(size_t ind) {
  return bitArray_.findPrevZeroBitFrom(ind);
}

char *MarkBitArrayNC::base() const {
                                                                           
                                                                               
                                                                             
                                                                                
                                
  return const_cast<char *>(reinterpret_cast<const char *>(this));
}

}                
}                    

#endif                              

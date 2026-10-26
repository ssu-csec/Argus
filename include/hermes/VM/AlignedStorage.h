/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_ALIGNED_STORAGE_H
#define HERMES_VM_ALIGNED_STORAGE_H

#include "hermes/VM/AllocSource.h"
#include "llvh/Support/ErrorOr.h"
#include "llvh/Support/PointerLikeTypeTraits.h"

#include <cstddef>
#include <cstdint>

namespace hermes {
namespace vm {

class StorageProvider;

#ifndef HERMESVM_HEAP_SEGMENT_SIZE_KB
#error Heap segment size must be defined.
#endif

                                                                               
                                 
struct AlignedStorage {
                                                          
  static constexpr unsigned kLogSize{
      llvh::detail::ConstantLog2<HERMESVM_HEAP_SEGMENT_SIZE_KB * 1024>::value};
  static constexpr size_t kSize{1 << kLogSize};
  static_assert(
      kSize == HERMESVM_HEAP_SEGMENT_SIZE_KB * 1024,
      "Heap segment size must be a power of 2.");

                                                                           
                                                            
     
                                                                    
     
                                                                              
                                             
  inline static void *start(const void *ptr);

                                                                     
                                                            
     
                                                                 
     
                                                                              
                                             
  inline static const void *end(const void *ptr);

                                                                      
  inline static bool containedInSame(const void *a, const void *b);

                                                                            
                                                        
     
                                                                   
     
                                                                              
                                             
  inline static size_t offset(const char *ptr);

                                                          
  inline static constexpr size_t size();

  friend void swap(AlignedStorage &, AlignedStorage &);

  static llvh::ErrorOr<AlignedStorage> create(StorageProvider *provider);
  static llvh::ErrorOr<AlignedStorage> create(
      StorageProvider *provider,
      const char *name);

                                                                         
  AlignedStorage() = default;

                                                                     
  AlignedStorage(AlignedStorage &&);
  AlignedStorage &operator=(AlignedStorage);
  AlignedStorage(const AlignedStorage &) = delete;

  ~AlignedStorage();

                                                                   
  explicit inline operator bool() const;

                                                                          
     
                                                                 
                                                         
     
                                                  
                                              
                                                                  
     
                                                                               
                                           
  void markUnused(char *from, char *to);

                                                                                
                                  
  inline char *lowLim() const;

                                                                           
                                                  
  inline char *hiLim() const;

                                                                               
                                 
  inline bool contains(const void *ptr) const;

 private:
                                 
                                                                               
                
                                               
  AlignedStorage(StorageProvider *provider, void *lowLim);

                                                                 
  static constexpr size_t kLowMask{kSize - 1};

                                                                     
  static constexpr size_t kHighMask{~kLowMask};

                                       
  char *lowLim_{nullptr};

                                                                         
                   
  StorageProvider *provider_{nullptr};
};

             void *AlignedStorage::start(const void *ptr) {
  return reinterpret_cast<char *>(reinterpret_cast<uintptr_t>(ptr) & kHighMask);
}

             const void *AlignedStorage::end(const void *ptr) {
  return reinterpret_cast<char *>(start(ptr)) + kSize;
}

             bool AlignedStorage::containedInSame(
    const void *a,
    const void *b) {
  return (reinterpret_cast<uintptr_t>(a) ^ reinterpret_cast<uintptr_t>(b)) <
      kSize;
}

             size_t AlignedStorage::offset(const char *ptr) {
  return reinterpret_cast<size_t>(ptr) & kLowMask;
}

             constexpr size_t AlignedStorage::size() {
  return kSize;
}

AlignedStorage::operator bool() const {
  return lowLim_;
}

char *AlignedStorage::lowLim() const {
  return lowLim_;
}

char *AlignedStorage::hiLim() const {
  return lowLim_ + kSize;
}

bool AlignedStorage::contains(const void *ptr) const {
  return AlignedStorage::start(ptr) == lowLim();
}

}                
}                    

#endif                               

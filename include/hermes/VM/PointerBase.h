/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_POINTERBASE_H
#define HERMES_VM_POINTERBASE_H

#include "hermes/VM/AlignedStorage.h"
#include "hermes/VM/SegmentInfo.h"
#include "llvh/Support/Compiler.h"
#include "llvh/Support/MathExtras.h"

#include <cassert>
#include <cstdint>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

#ifdef HERMESVM_COMPRESSED_POINTERS
class BasedPointer final {
 public:
  using StorageType = uint32_t;
  explicit operator bool() const;

  inline bool operator==(BasedPointer other) const;

  inline bool operator!=(BasedPointer other) const;

  BasedPointer() = default;

                                                              
  explicit BasedPointer(std::nullptr_t);
  explicit BasedPointer(StorageType raw);

  BasedPointer &operator=(std::nullptr_t);

  inline StorageType getRawValue() const;

 private:
#ifndef HERMESVM_CONTIGUOUS_HEAP
                                                                              
                                                                      
  friend class PointerBase;
  inline uint32_t getSegmentIndex() const;
  inline uint32_t getOffset() const;
#endif

  StorageType raw_;
};
#endif

                                                                     
                                                                          
                                       
class PointerBase {
 public:
                                 
  inline PointerBase();

                                                                          
  inline void setSegment(unsigned idx, void *segStart);

#ifdef HERMESVM_COMPRESSED_POINTERS
 private:
  friend class CompressedPointer;

                                               
                                      
                                                                            
  inline BasedPointer pointerToBased(const void *ptr) const;
                                                                         
                           
  inline BasedPointer pointerToBasedNonNull(const void *ptr) const;

                                                                             
                    
                                                      
  inline void *basedToPointer(BasedPointer ptr) const;

                                                                         
                           
  inline void *basedToPointerNonNull(BasedPointer ptr) const;

#ifndef HERMESVM_CONTIGUOUS_HEAP
  static constexpr unsigned kNullPtrSegmentIndex = 0;
                                                              
                                                                  
                                                                               
                                                                            
                                                                      
                                                                     
                                                              
              
                                          
                                              
                                                    
                                          
     
                                                                          
                                                      
                                
                                           
                                                    
                                                        
                                                  
                                                                  
                                                                    
                                      
     
                                                                      
                                                                  
                                                                 
                                                        
                     
  using SegmentPtr = void *;
  static constexpr unsigned kSegmentMapSize = 1
      << (32 - AlignedStorage::kLogSize);
                                                                                
  static constexpr unsigned kMaxSegments = kSegmentMapSize - 1;
  SegmentPtr segmentMap_[kSegmentMapSize];
#endif
#endif                                
};

                                 
      

#ifdef HERMESVM_COMPRESSED_POINTERS
inline BasedPointer::BasedPointer(std::nullptr_t) : raw_(0) {}
inline BasedPointer::BasedPointer(StorageType raw) : raw_(raw) {}

inline BasedPointer &BasedPointer::operator=(std::nullptr_t) {
  raw_ = 0;
  return *this;
}

inline BasedPointer::StorageType BasedPointer::getRawValue() const {
  return raw_;
}

inline BasedPointer::operator bool() const {
  return raw_ != 0;
}

inline bool BasedPointer::operator==(BasedPointer other) const {
  return raw_ == other.raw_;
}

inline bool BasedPointer::operator!=(BasedPointer other) const {
  return raw_ != other.raw_;
}

#ifdef HERMESVM_CONTIGUOUS_HEAP
inline void *PointerBase::basedToPointerNonNull(BasedPointer ptr) const {
  assert(ptr && "Null pointer given to basedToPointerNonNull");
  uintptr_t addr = reinterpret_cast<uintptr_t>(this) + ptr.getRawValue();
  return reinterpret_cast<void *>(addr);
}

inline PointerBase::PointerBase() {
                                                                            
                                                                     
  assert(llvh::alignmentAdjustment(this, AlignedStorage::size()) == 0);
}

inline void *PointerBase::basedToPointer(BasedPointer ptr) const {
  return ptr ? basedToPointerNonNull(ptr) : nullptr;
}

inline BasedPointer PointerBase::pointerToBasedNonNull(const void *ptr) const {
  assert(ptr && "Null pointer given to pointerToBasedNonNull");
  uintptr_t offset = (uintptr_t)ptr - (uintptr_t)this;
  assert(llvh::isUInt<32>(offset) && "Pointer out of range");
  return BasedPointer{static_cast<uint32_t>(offset)};
}

inline BasedPointer PointerBase::pointerToBased(const void *ptr) const {
  return ptr ? pointerToBasedNonNull(ptr) : BasedPointer{nullptr};
}

inline void PointerBase::setSegment(unsigned idx, void *segStart) {
  assert(segStart == AlignedStorage::start(segStart) && "Precondition");
  SegmentInfo::setSegmentIndexFromStart(segStart, idx);
}
#else
inline void *PointerBase::basedToPointerNonNull(BasedPointer ptr) const {
  assert(ptr && "Null pointer given to basedToPointerNonNull");
                                                                    
  return basedToPointer(ptr);
}

inline PointerBase::PointerBase() {
  segmentMap_[kNullPtrSegmentIndex] = nullptr;
}

inline uint32_t BasedPointer::getSegmentIndex() const {
  return raw_ >> AlignedStorage::kLogSize;
}

inline uint32_t BasedPointer::getOffset() const {
  return raw_ & ((1 << AlignedStorage::kLogSize) - 1);
}

inline void *PointerBase::basedToPointer(BasedPointer ptr) const {
  char *segBase = reinterpret_cast<char *>(segmentMap_[ptr.getSegmentIndex()]);
  return segBase + ptr.getRawValue();
}

inline BasedPointer PointerBase::pointerToBased(const void *ptr) const {
  if (!ptr) {
                                                                      
                                                                     
    return BasedPointer{};
  }
  return pointerToBasedNonNull(ptr);
}

inline BasedPointer PointerBase::pointerToBasedNonNull(const void *ptr) const {
  assert(ptr && "Null pointer given to pointerToBasedNonNull");
  uintptr_t addrAsInt = reinterpret_cast<uintptr_t>(ptr);
  void *segStart = AlignedStorage::start(ptr);
                                                            
                                                         
                                                               
                                                                
  uintptr_t offset = addrAsInt - reinterpret_cast<uintptr_t>(segStart);
                                                                     
                                   
  uint32_t raw = (SegmentInfo::segmentIndexFromStart(segStart)
                  << AlignedStorage::kLogSize) |
      offset;
  return BasedPointer{raw};
}

inline void PointerBase::setSegment(unsigned idx, void *segStart) {
  assert(segStart == AlignedStorage::start(segStart) && "Precondition");
                                                                
                                  
  char *bias =
      reinterpret_cast<char *>(segStart) - (idx << AlignedStorage::kLogSize);
  segmentMap_[idx] = bias;
  SegmentInfo::setSegmentIndexFromStart(segStart, idx);
}
#endif                            
#else
inline PointerBase::PointerBase() {}

inline void PointerBase::setSegment(unsigned idx, void *segStart) {
  assert(segStart == AlignedStorage::start(segStart) && "Precondition");
  SegmentInfo::setSegmentIndexFromStart(segStart, idx);
}
#endif                                

      

}                
}                    
#pragma GCC diagnostic pop
#endif

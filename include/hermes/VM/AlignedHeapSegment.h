/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_SEGMENT_H
#define HERMES_VM_SEGMENT_H

#include "hermes/Support/OSCompat.h"
#include "hermes/VM/AdviseUnused.h"
#include "hermes/VM/AlignedStorage.h"
#include "hermes/VM/AllocResult.h"
#include "hermes/VM/AllocSource.h"
#include "hermes/VM/CardTableNC.h"
#include "hermes/VM/GCBase.h"
#include "hermes/VM/GCCell.h"
#include "hermes/VM/HeapAlign.h"
#include "hermes/VM/MarkBitArrayNC.h"
#include "hermes/VM/PointerBase.h"
#include "hermes/VM/SegmentInfo.h"

#include "llvh/Support/MathExtras.h"

#include <cstdint>
#include <vector>

namespace hermes {
namespace vm {

                 
                               
                                

                                                                               
                                                                              
                                                       
   
                                              
                                              
                                              
                                              
                                              
                                              
                                              
                                              
                                              
                                              
                                              
   
                                                                        
                                          
class AlignedHeapSegment {
 public:
  explicit AlignedHeapSegment(AlignedStorage storage);

                                                                         
  AlignedHeapSegment() = default;
  AlignedHeapSegment(AlignedHeapSegment &&) = default;
  AlignedHeapSegment &operator=(AlignedHeapSegment &&) = default;

  ~AlignedHeapSegment();

                                                            
  class Contents {
    friend class AlignedHeapSegment;

                                                                            
                                                                               
               
    CardTable cardTable_;

    MarkBitArrayNC markBitArray_;

    static constexpr size_t kMetadataSize =
        sizeof(cardTable_) + sizeof(markBitArray_);
                                                                            
    static constexpr size_t kGuardPagePadding =
        llvh::alignTo<pagesize::kExpectedPageSize>(kMetadataSize) -
        kMetadataSize;

                                                                           
                                                                            
                     
    char paddedGuardPage_[pagesize::kExpectedPageSize + kGuardPagePadding];

    static constexpr size_t kMetadataAndGuardSize =
        kMetadataSize + sizeof(paddedGuardPage_);

                                                                                
                                                                     
    char allocRegion_[1];

   public:
                                                                               
            
    void protectGuardPage(oscompat::ProtectMode mode);
  };

  static_assert(
      offsetof(Contents, paddedGuardPage_) == Contents::kMetadataSize,
      "Should not need padding after metadata.");

                                                                                
                                        
  static constexpr size_t kCardTableUnusedPrefixBytes =
      Contents::kMetadataAndGuardSize / CardTable::kHeapBytesPerCardByte;
  static_assert(
      sizeof(SegmentInfo) < kCardTableUnusedPrefixBytes,
      "SegmentInfo does not fit in available unused CardTable space.");

                                                                           
  static constexpr size_t offsetOfAllocRegion{offsetof(Contents, allocRegion_)};

  static_assert(
      isSizeHeapAligned(offsetOfAllocRegion),
      "Allocation region must start at a heap aligned offset");

  static_assert(
      (offsetof(Contents, paddedGuardPage_) + Contents::kGuardPagePadding) %
              pagesize::kExpectedPageSize ==
          0,
      "Guard page must be aligned to likely page size");

  class HeapCellIterator : public llvh::iterator_facade_base<
                               HeapCellIterator,
                               std::forward_iterator_tag,
                               GCCell *> {
   public:
    HeapCellIterator(GCCell *cell) : cell_(cell) {}

    bool operator==(const HeapCellIterator &R) const {
      return cell_ == R.cell_;
    }

    GCCell *const &operator*() const {
      return cell_;
    }

    HeapCellIterator &operator++() {
      cell_ = cell_->nextCell();
      return *this;
    }

   private:
    GCCell *cell_{nullptr};
  };

                                                                          
                                                                               
                                                                             
                                      
  inline AllocResult alloc(uint32_t size);

                                                                               
                                                                             
                         
  inline static Contents *contents(void *lowLim);
  inline static const Contents *contents(const void *lowLim);

                                                                              
                                                                            
              
     
                                                                             
  inline static CardTable *cardTableCovering(const void *ptr);

                                                                              
                                                                             
                  
     
                                                                             
  inline static MarkBitArrayNC *markBitArrayCovering(const void *ptr);

                                                                                
  inline static void setCellMarkBit(const GCCell *cell);

                                                                               
                          
  inline static bool getCellMarkBit(const GCCell *cell);

                                                                             
         
  inline static constexpr size_t maxSize();

                                                                             
                                             
  inline size_t size() const;

                                                                      
  inline size_t used() const;

                                                                           
  inline size_t available() const;

                                                                 
                                                                         
                 
  inline char *lowLim() const;

                                                                 
  inline char *hiLim() const;

                                                                             
            
                                                                          
  inline char *start() const LLVM_NO_SANITIZE("undefined");

                                                                                
                                                                                
           
  inline char *effectiveEnd() const;

                                                                               
                                                                   
                                                                         
              
  void setEffectiveEnd(char *effectiveEnd);

                                                                                
                                                 
  void clearExternalMemoryCharge();

                                                                                
                                       
  inline char *end() const;

                                                                           
  inline char *level() const;

                                                                           
  inline llvh::iterator_range<HeapCellIterator> cells();

                                                             
                         
  inline static bool containedInSame(const void *a, const void *b);

                                                                                
                   
                                                                   
  inline CardTable &cardTable() const LLVM_NO_SANITIZE("null");

                                                                         
                              
  inline MarkBitArrayNC &markBitArray() const;

  explicit inline operator bool() const;

                                                                               
                                     
  inline bool contains(const void *ptr) const;

                                    
     
                                                              
  void markUnused(char *start, char *end);

                                                       
     
                                                                                
     
                                   
  template <AdviseUnused MU = AdviseUnused::No>
  void setLevel(char *level);

                                        
     
                                                                                
     
                                           
  template <AdviseUnused MU = AdviseUnused::No>
  void resetLevel();

#ifndef NDEBUG
                                                                         
  bool dbgContainsLevel(const void *lvl) const;

                                                                             
                             
  bool validPointer(const void *p) const;

                                                      
  void clear();
                                                       
  static void clear(char *start, char *end);
                                                                    
  static void checkUnwritten(char *start, char *end);
#endif

 protected:
                                                                           
              
  inline Contents *contents() const;

  AlignedStorage storage_;

  char *level_{start()};

                                                                        
                                                                           
                                       
  char *effectiveEnd_{end()};
};

AllocResult AlignedHeapSegment::alloc(uint32_t size) {
  assert(lowLim() != nullptr && "Cannot allocate in a null segment");
  assert(size >= sizeof(GCCell) && "cell must be larger than GCCell");
  assert(isSizeHeapAligned(size) && "size must be heap aligned");

  char *cellPtr;                                

                                                                             
                                                                                
                                       
                                                                          
  if (sizeof(void *) == 8) {
                                     
    char *newLevel = level_ + size;
    if (LLVM_UNLIKELY(newLevel > effectiveEnd())) {
      return {nullptr, false};
    }
    cellPtr = level_;
    level_ = newLevel;
  } else {
    if (LLVM_UNLIKELY(available() < size)) {
      return {nullptr, false};
    }
    cellPtr = level_;
    level_ += size;
  }

  __asan_unpoison_memory_region(cellPtr, size);
#ifndef NDEBUG
  checkUnwritten(cellPtr, cellPtr + size);
#endif

  auto *cell = reinterpret_cast<GCCell *>(cellPtr);
  return {cell, true};
}

          
MarkBitArrayNC *AlignedHeapSegment::markBitArrayCovering(const void *ptr) {
  return &contents(AlignedStorage::start(ptr))->markBitArray_;
}

          
void AlignedHeapSegment::setCellMarkBit(const GCCell *cell) {
  MarkBitArrayNC *markBits = markBitArrayCovering(cell);
  size_t ind = markBits->addressToIndex(cell);
  markBits->mark(ind);
}

          
bool AlignedHeapSegment::getCellMarkBit(const GCCell *cell) {
  MarkBitArrayNC *markBits = markBitArrayCovering(cell);
  size_t ind = markBits->addressToIndex(cell);
  return markBits->at(ind);
}

             AlignedHeapSegment::Contents *AlignedHeapSegment::contents(
    void *lowLim) {
  return reinterpret_cast<Contents *>(lowLim);
}

             const AlignedHeapSegment::Contents *AlignedHeapSegment::contents(
    const void *lowLim) {
  return reinterpret_cast<const Contents *>(lowLim);
}

             CardTable *AlignedHeapSegment::cardTableCovering(const void *ptr) {
  return &AlignedHeapSegment::contents(AlignedStorage::start(ptr))->cardTable_;
}

             constexpr size_t AlignedHeapSegment::maxSize() {
  return AlignedStorage::size() - offsetof(Contents, allocRegion_);
}

size_t AlignedHeapSegment::size() const {
  return end() - start();
}

size_t AlignedHeapSegment::used() const {
  return level() - start();
}

size_t AlignedHeapSegment::available() const {
  return effectiveEnd() - level();
}

char *AlignedHeapSegment::lowLim() const {
  return storage_.lowLim();
}

char *AlignedHeapSegment::hiLim() const {
  return storage_.hiLim();
}

char *AlignedHeapSegment::start() const {
  return contents()->allocRegion_;
}

char *AlignedHeapSegment::effectiveEnd() const {
  return effectiveEnd_;
}

char *AlignedHeapSegment::end() const {
  return start() + maxSize();
}

char *AlignedHeapSegment::level() const {
  return level_;
}

llvh::iterator_range<AlignedHeapSegment::HeapCellIterator>
AlignedHeapSegment::cells() {
  return {
      HeapCellIterator(reinterpret_cast<GCCell *>(start())),
      HeapCellIterator(reinterpret_cast<GCCell *>(level()))};
}

            
bool AlignedHeapSegment::containedInSame(const void *a, const void *b) {
  return AlignedStorage::containedInSame(a, b);
}

CardTable &AlignedHeapSegment::cardTable() const {
  return contents()->cardTable_;
}

MarkBitArrayNC &AlignedHeapSegment::markBitArray() const {
  return contents()->markBitArray_;
}

AlignedHeapSegment::Contents *AlignedHeapSegment::contents() const {
  return contents(lowLim());
}

AlignedHeapSegment::operator bool() const {
  return static_cast<bool>(storage_);
}

bool AlignedHeapSegment::contains(const void *ptr) const {
  return storage_.contains(ptr);
}

}                
}                    

#endif                       

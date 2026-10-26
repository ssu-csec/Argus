/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_SEGMENTEDARRAY_H
#define HERMES_VM_SEGMENTEDARRAY_H

#include "hermes/VM/CellKind.h"
#include "hermes/VM/Runtime.h"
#include "hermes/VM/SmallHermesValue-inline.h"

#include "llvh/Support/TrailingObjects.h"

#include <limits>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

                                                         
   
                                                                           
                   
                                                                             
                                                                            
                                                                      
                                                                             
                                                        
                                                                              
                                                                 
                                                                         
                                                      
                                                                             
                                         
   
                                                                      
                                                         
                                             
   
                                   
                                                             
template <typename HVType>
class SegmentedArrayBase final : public VariableSizeRuntimeCell,
                                 private llvh::TrailingObjects<
                                     SegmentedArrayBase<HVType>,
                                     GCHermesValueBase<HVType>> {
  using GCHVType = GCHermesValueBase<HVType>;

 public:
                                                               
  class Segment final : public GCCell {
   public:
                                                                 
    static constexpr uint32_t kMaxLength = 1024;

                                                 
    static PseudoHandle<Segment> create(Runtime &runtime);

    static constexpr CellKind getCellKind() {
      static_assert(
          std::is_same<HVType, HermesValue>::value ||
              std::is_same<HVType, SmallHermesValue>::value,
          "Illegal HVType.");
      return std::is_same<HVType, HermesValue>::value
          ? CellKind::SegmentKind
          : CellKind::SegmentSmallKind;
    }
    static bool classof(const GCCell *cell) {
      return cell->getKind() == getCellKind();
    }

    GCHVType &at(uint32_t index) {
      assert(
          index < length() &&
          "Cannot get an index outside of the length of a segment");
      return data_[index];
    }

                                  
    const GCHVType &at(uint32_t index) const {
      assert(
          index < length() &&
          "Cannot get an index outside of the length of a segment");
      return data_[index];
    }

    uint32_t length() const {
      return length_.load(std::memory_order_relaxed);
    }

                                                                        
                                                                               
                                      
    void setLength(Runtime &runtime, uint32_t newLength);

    friend void SegmentBuildMeta(const GCCell *cell, Metadata::Builder &mb);
    friend void SegmentSmallBuildMeta(
        const GCCell *cell,
        Metadata::Builder &mb);

   private:
    static const VTable vt;

    AtomicIfConcurrentGC<uint32_t> length_{0};
    GCHVType data_[kMaxLength];
  };

  using size_type = uint32_t;

                                                                           
               
     
                                                                             
                                                                           
  static constexpr size_type kValueToSegmentThreshold = 4 * Segment::kMaxLength;

                                                                             
                                                                              
                                                                        
                                                                                
                        
  enum class Inline { No, Yes };

 private:
                                                                               
                                                                                
                                                                       
                                                                               
                                                        
  using TotalIndex = uint32_t;
                                                                               
                                                                              
              
  using SegmentNumber = uint32_t;
                                                                              
                                            
  using InteriorIndex = uint32_t;

                                                                                
           
  static constexpr size_type slotCapacityForAllocationSize(uint32_t allocSize) {
    return (allocSize - allocationSizeForSlots(0)) / sizeof(HVType);
  }

                                                                         
                                                                        
                                                  
  size_type slotCapacity() const {
    return slotCapacityForAllocationSize(getAllocatedSize());
  }

                                                                              
                            
  AtomicIfConcurrentGC<size_type> numSlotsUsed_{0};

  struct iterator {
    using iterator_category = std::bidirectional_iterator_tag;
    using value_type = GCHVType;
    using difference_type = ptrdiff_t;
    using pointer = GCHVType *;
    using reference = GCHVType &;

                                                                               
                                                                               
                                        
    SegmentedArrayBase *const owner_;
                                                      
    TotalIndex index_;
    PointerBase &base_;

    explicit iterator(
        SegmentedArrayBase *owner,
        TotalIndex index,
        PointerBase &base)
        : owner_(owner), index_(index), base_(base) {
      assert(
          index_ <= owner_->size(base_) &&
          "Cannot make an iterator that points outside of the storage");
    }

    iterator(const iterator &) = default;

    iterator &operator=(const iterator &that) {
      assert(
          owner_ == that.owner_ &&
          "Cannot assign to an iterator from a different SegmentedArray");
      index_ = that.index_;
      assert(
          index_ <= owner_->size(base_) &&
          "Cannot make an iterator that points outside of the storage");
      return *this;
    }

    bool operator==(const iterator &that) const {
      assert(
          owner_ == that.owner_ &&
          "Cannot compare to an iterator from a different SegmentedArray");
      return index_ == that.index_;
    }
    bool operator!=(const iterator &that) const {
      return !(*this == that);
    }
    iterator operator+(TotalIndex index) const {
      assert(
          index_ <= std::numeric_limits<TotalIndex>::max() - index &&
          "Overflow in addition");
      return iterator(owner_, index_ + index, base_);
    }
    iterator operator-(TotalIndex index) const {
      assert(index_ >= index && "Overflow in subtraction");
      return iterator(owner_, index_ - index, base_);
    }
    iterator &operator+=(TotalIndex index) {
      return *this = *this + index;
    }
    iterator &operator-=(TotalIndex index) {
      return *this = *this - index;
    }
    iterator &operator++() {
      return *this += 1;
    }
    iterator &operator--() {
      return *this -= 1;
    }

    reference operator*() {
      assert(
          index_ < owner_->size(base_) &&
          "Trying to read from an index outside the size");
                                                              
      if (LLVM_LIKELY(index_ < kValueToSegmentThreshold)) {
        return owner_->inlineStorage()[index_];
      } else {
        return owner_->segmentAt(base_, toSegment(index_))
            ->at(toInterior(index_));
      }
    }

    pointer operator->() {
      return &**this;
    }
  };

 public:
  static constexpr size_type maxElements();

                                                                               
                                                  
  static CallResult<PseudoHandle<SegmentedArrayBase>> create(
      Runtime &runtime,
      size_type capacity);
  static CallResult<PseudoHandle<SegmentedArrayBase>> createLongLived(
      Runtime &runtime,
      size_type capacity);
                                                                            
                                                          
  static CallResult<PseudoHandle<SegmentedArrayBase>>
  create(Runtime &runtime, size_type capacity, size_type size);

                                                                         
              
  template <Inline inl = Inline::No>
  GCHVType &atRef(PointerBase &base, TotalIndex index) {
    if (inl == Inline::Yes) {
      assert(
          index < kValueToSegmentThreshold && index < size(base) &&
          "Using the inline storage accessor when the index is larger than the "
          "inline storage");
      return inlineStorage()[index];
    } else {
      return *(begin(base) + index);
    }
  }

                                           
  template <Inline inl = Inline::No>
  HVType at(PointerBase &base, size_type index) const {
    assert(index < size(base) && "Invalid index.");
    if (inl == Inline::Yes || index < kValueToSegmentThreshold) {
      return inlineStorage()[index];
    } else {
      return segmentAt(base, toSegment(index))->at(toInterior(index));
    }
  }

                                                     
  template <Inline inl = Inline::No>
  void set(Runtime &runtime, TotalIndex index, HVType val) {
    atRef<inl>(runtime, index).set(val, runtime.getHeap());
  }
  template <Inline inl = Inline::No>
  void setNonPtr(Runtime &runtime, TotalIndex index, HVType val) {
    atRef<inl>(runtime, index).setNonPtr(val, runtime.getHeap());
  }

                                                                             
                                    
  size_type size(PointerBase &base) const {
    const auto numSlotsUsed = numSlotsUsed_.load(std::memory_order_relaxed);
    if (LLVM_LIKELY(numSlotsUsed <= kValueToSegmentThreshold)) {
      return numSlotsUsed;
    } else {
      const SegmentNumber numSegments = numSlotsUsed - kValueToSegmentThreshold;
      const size_type numBeforeLastSegment =
          kValueToSegmentThreshold + (numSegments - 1) * Segment::kMaxLength;
      const uint32_t numInLastSegment =
          segmentAt(base, numSegments - 1)->length();
      return numBeforeLastSegment + numInLastSegment;
    }
  }

                                                                            
                                          
  size_type capacity() const;

                                                                         
                                              
  size_type totalCapacityOfSpine() const;

                                                                        
                                                   
  static constexpr uint32_t allocationSizeForCapacity(size_type capacity) {
    return allocationSizeForSlots(numSlotsForCapacity(capacity));
  }

                                                                   
  static ExecutionStatus push_back(
      MutableHandle<SegmentedArrayBase> &self,
      Runtime &runtime,
      Handle<> value);

                                                                              
                                                                                
               
  static ExecutionStatus resize(
      MutableHandle<SegmentedArrayBase> &self,
      Runtime &runtime,
      size_type newSize);

                                                                            
     
                                                                          
                                                                          
                                                                              
                   
  static ExecutionStatus resizeLeft(
      MutableHandle<SegmentedArrayBase> &self,
      Runtime &runtime,
      size_type newSize);

                                                                
                                                                                
                         
  static void resizeWithinCapacity(
      SegmentedArrayBase *self,
      Runtime &runtime,
      size_type newSize);

                                
  void clear(Runtime &runtime) {
    shrinkRight(runtime, size(runtime));
  }

  static constexpr CellKind getCellKind() {
    static_assert(
        std::is_same<HVType, HermesValue>::value ||
            std::is_same<HVType, SmallHermesValue>::value,
        "Illegal HVType.");
    return std::is_same<HVType, HermesValue>::value
        ? CellKind::SegmentedArrayKind
        : CellKind::SegmentedArraySmallKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == getCellKind();
  }

 private:
  static const VTable vt;

  friend llvh::
      TrailingObjects<SegmentedArrayBase<HVType>, GCHermesValueBase<HVType>>;
  friend void SegmentBuildMeta(const GCCell *cell, Metadata::Builder &mb);
  friend void SegmentedArrayBuildMeta(
      const GCCell *cell,
      Metadata::Builder &mb);
  friend void SegmentSmallBuildMeta(const GCCell *cell, Metadata::Builder &mb);
  friend void SegmentedArraySmallBuildMeta(
      const GCCell *cell,
      Metadata::Builder &mb);

 private:
                                                                             
                                                      
                                                 
  static ExecutionStatus throwExcessiveCapacityError(
      Runtime &runtime,
      size_type capacity);

  iterator begin(PointerBase &base) {
    return iterator(this, 0, base);
  }
  iterator end(PointerBase &base) {
    return iterator(this, size(base), base);
  }
  iterator inlineStorageEnd(PointerBase &base) {
    return iterator(
        this, std::min(size(base), toRValue(kValueToSegmentThreshold)), base);
  }

                                                                                
                                                                                
                 
  static size_type calculateNewCapacity(
      size_type currentSize,
      size_type newSize) {
                                                                             
                                              
                                                                            
                                                                        
    return std::max(currentSize * 2, newSize);
  }

                                                                                
               
  static constexpr SegmentNumber numSlotsForCapacity(size_type capacity) {
    if (capacity <= kValueToSegmentThreshold)
      return capacity;
                                                                     
    const size_t numSegments = llvh::alignTo<Segment::kMaxLength>(
                                   capacity - kValueToSegmentThreshold) /
        Segment::kMaxLength;
                                                                   
                                                     
    return kValueToSegmentThreshold + numSegments;
  }

                                                                               
                                                                                
                                                                          
                     
  static SegmentNumber toSegment(TotalIndex index) {
    assert(
        index >= kValueToSegmentThreshold &&
        "Cannot get the segment of an element in the inline storage");
    return (index - kValueToSegmentThreshold) / Segment::kMaxLength;
  }

                                                                               
              
                                                          
  static InteriorIndex toInterior(TotalIndex index) {
    assert(
        index >= kValueToSegmentThreshold &&
        "Cannot get the interior index of an element in the inline storage");
    return (index - kValueToSegmentThreshold) % Segment::kMaxLength;
  }

                                                         
  static void allocateSegment(
      Runtime &runtime,
      Handle<SegmentedArrayBase> self,
      SegmentNumber segment);

                                                                              
                     
  static constexpr uint32_t allocationSizeForSlots(SegmentNumber numSlots) {
    return SegmentedArrayBase::template totalSizeToAlloc<GCHVType>(numSlots);
  }

                                                                                
                                                                              
                      
                                                                              
                     
  Segment *segmentAt(PointerBase &base, SegmentNumber segment) {
    return const_cast<Segment *>(
        static_cast<const SegmentedArrayBase *>(this)->segmentAt(
            base, segment));
  }
                                    
  const Segment *segmentAt(PointerBase &base, SegmentNumber segment) const {
    assert(
        segment < numUsedSegments() &&
        "Trying to get a segment that does not exist");
    return vmcast<Segment>(
        segmentAtPossiblyUnallocated(segment)->getObject(base));
  }

                                                                          
                                       
  GCHVType *segmentAtPossiblyUnallocated(SegmentNumber segment) {
    return const_cast<GCHVType *>(static_cast<const SegmentedArrayBase *>(this)
                                      ->segmentAtPossiblyUnallocated(segment));
  }
                                                       
  const GCHVType *segmentAtPossiblyUnallocated(SegmentNumber segment) const {
    assert(
        segment < numSegments() &&
        "Trying to get a segment that does not exist");
    return segments() + segment;
  }

                                                                                
  GCHVType *inlineStorage() {
    return SegmentedArrayBase::template getTrailingObjects<GCHVType>();
  }

                             
  const GCHVType *inlineStorage() const {
    return SegmentedArrayBase::template getTrailingObjects<GCHVType>();
  }

                                                                               
  GCHVType *segments() {
    return SegmentedArrayBase::template getTrailingObjects<GCHVType>() +
        kValueToSegmentThreshold;
  }

                             
  const GCHVType *segments() const {
    return SegmentedArrayBase::template getTrailingObjects<GCHVType>() +
        kValueToSegmentThreshold;
  }

                                                                               
                                                                               
                                                
  SegmentNumber numSegments() const {
    const auto slotCap = slotCapacity();
    return slotCap <= kValueToSegmentThreshold
        ? 0
        : slotCap - kValueToSegmentThreshold;
  }

                                                                          
  SegmentNumber numUsedSegments() const {
    const auto numSlotsUsed = numSlotsUsed_.load(std::memory_order_relaxed);
    return numSlotsUsed <= kValueToSegmentThreshold
        ? 0
        : numSlotsUsed - kValueToSegmentThreshold;
  }

                                   
        

                                                                                
                                                                                
                               
  static ExecutionStatus growRight(
      MutableHandle<SegmentedArrayBase> &self,
      Runtime &runtime,
      size_type amount);

                                                                           
                                                                               
                                                                              
                   
  static ExecutionStatus growLeft(
      MutableHandle<SegmentedArrayBase> &self,
      Runtime &runtime,
      size_type amount);

                                                                       
  static void growLeftWithinCapacity(
      Runtime &runtime,
      PseudoHandle<SegmentedArrayBase> self,
      size_type amount);

                                                                              
                              
  void shrinkRight(Runtime &runtime, size_type amount);

                                                                            
                    
                              
  void shrinkLeft(Runtime &runtime, size_type amount);

                                                                    
  void increaseSizeWithinCapacity(Runtime &runtime, size_type amount);

                                                                
                  
                                                                  
  static PseudoHandle<SegmentedArrayBase> increaseSize(
      Runtime &runtime,
      PseudoHandle<SegmentedArrayBase> self,
      size_type amount);

                                                                             
                         
  void decreaseSize(Runtime &runtime, size_type amount);

        

                                                                                
                          
  static constexpr SegmentNumber maxNumSegments();
                                                                               
                             
  static constexpr SegmentNumber maxNumSegmentsWithoutOverflow();

  static gcheapsize_t _trimSizeCallback(const GCCell *self);
};

template <typename HVType>
constexpr typename SegmentedArrayBase<HVType>::size_type
SegmentedArrayBase<HVType>::maxElements() {
  return maxNumSegments() * Segment::kMaxLength + kValueToSegmentThreshold;
}

template <typename HVType>
constexpr typename SegmentedArrayBase<HVType>::SegmentNumber
SegmentedArrayBase<HVType>::maxNumSegments() {
  const SegmentedArrayBase::SegmentNumber maxAllocSlots =
      slotCapacityForAllocationSize(GC::maxAllocationSize());
  const SegmentedArrayBase::SegmentNumber maxAllocSegments =
      maxAllocSlots - kValueToSegmentThreshold;
  return std::min(maxAllocSegments, maxNumSegmentsWithoutOverflow());
}

template <typename HVType>
constexpr typename SegmentedArrayBase<HVType>::SegmentNumber
SegmentedArrayBase<HVType>::maxNumSegmentsWithoutOverflow() {
  return (
      (std::numeric_limits<uint32_t>::max() - kValueToSegmentThreshold) /
      Segment::kMaxLength);
}

using SegmentedArray = SegmentedArrayBase<HermesValue>;
using SegmentedArraySmall = SegmentedArrayBase<SmallHermesValue>;

template <>
struct IsGCObject<SegmentedArray::Segment> : public std::true_type {};
template <>
struct IsGCObject<SegmentedArraySmall::Segment> : public std::true_type {};

static_assert(
    SegmentedArray::allocationSizeForCapacity(SegmentedArray::maxElements()) <=
        GC::maxAllocationSize(),
    "maxElements() is too big");
static_assert(
    SegmentedArraySmall::allocationSizeForCapacity(
        SegmentedArraySmall::maxElements()) <= GC::maxAllocationSize(),
    "maxElements() is too big");

}                
}                    
#pragma GCC diagnostic pop

#endif

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/SegmentedArray.h"

#include "hermes/VM/GCPointer-inline.h"
#include "hermes/VM/HermesValue-inline.h"

namespace hermes {
namespace vm {

template <typename HVType>
const VTable SegmentedArrayBase<HVType>::Segment::vt(
    getCellKind(),
    cellSize<SegmentedArrayBase::Segment>(),
    nullptr,
    nullptr,
    nullptr
#ifdef HERMES_MEMORY_INSTRUMENTATION
    ,
    VTable::HeapSnapshotMetadata{
        HeapSnapshot::NodeType::Array,
        nullptr,
        nullptr,
        nullptr,
        nullptr}
#endif
);

void SegmentBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  const auto *self = static_cast<const SegmentedArray::Segment *>(cell);
  mb.setVTable(&SegmentedArray::Segment::vt);
  mb.addArray("data", self->data_, &self->length_, sizeof(GCHermesValue));
}
void SegmentSmallBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  const auto *self = static_cast<const SegmentedArraySmall::Segment *>(cell);
  mb.setVTable(&SegmentedArraySmall::Segment::vt);
  mb.addArray("data", self->data_, &self->length_, sizeof(GCSmallHermesValue));
}

template <typename HVType>
PseudoHandle<typename SegmentedArrayBase<HVType>::Segment>
SegmentedArrayBase<HVType>::Segment::create(Runtime &runtime) {
                                                                              
                                                                             
                        
  return createPseudoHandle(runtime.makeAFixed<Segment>());
}

template <typename HVType>
void SegmentedArrayBase<HVType>::Segment::setLength(
    Runtime &runtime,
    uint32_t newLength) {
  const auto len = length();
  if (newLength > len) {
                                              
    GCHVType::uninitialized_fill(
        data_ + len,
        data_ + newLength,
        HVType::encodeEmptyValue(),
        runtime.getHeap());
    length_.store(newLength, std::memory_order_release);
  } else if (newLength < len) {
                                                                
    GCHVType::rangeUnreachableWriteBarrier(
        data_ + newLength, data_ + len, runtime.getHeap());
    length_.store(newLength, std::memory_order_release);
  }
}

template <typename HVType>
const VTable SegmentedArrayBase<HVType>::vt(
    getCellKind(),
                     0,
    nullptr,
    nullptr,
    _trimSizeCallback
#ifdef HERMES_MEMORY_INSTRUMENTATION
    ,
    VTable::HeapSnapshotMetadata{
        HeapSnapshot::NodeType::Array,
        nullptr,
        nullptr,
        nullptr,
        nullptr}
#endif
);

void SegmentedArrayBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  const auto *self = static_cast<const SegmentedArray *>(cell);
  mb.setVTable(&SegmentedArray::vt);
  mb.addArray(
      "slots",
      self->inlineStorage(),
      &self->numSlotsUsed_,
      sizeof(GCHermesValue));
}

void SegmentedArraySmallBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  const auto *self = static_cast<const SegmentedArraySmall *>(cell);
  mb.setVTable(&SegmentedArraySmall::vt);
  mb.addArray(
      "slots",
      self->inlineStorage(),
      &self->numSlotsUsed_,
      sizeof(GCSmallHermesValue));
}

template <typename HVType>
CallResult<PseudoHandle<SegmentedArrayBase<HVType>>>
SegmentedArrayBase<HVType>::create(Runtime &runtime, size_type capacity) {
  if (LLVM_UNLIKELY(capacity > maxElements())) {
    return throwExcessiveCapacityError(runtime, capacity);
  }
                                                                           
                                                                           
                                                                           
                                                                            
                                         
  const auto allocSize = allocationSizeForCapacity(capacity);
  return createPseudoHandle(
      runtime.makeAVariable<SegmentedArrayBase>(allocSize));
}

template <typename HVType>
CallResult<PseudoHandle<SegmentedArrayBase<HVType>>> SegmentedArrayBase<
    HVType>::createLongLived(Runtime &runtime, size_type capacity) {
  if (LLVM_UNLIKELY(capacity > maxElements())) {
    return throwExcessiveCapacityError(runtime, capacity);
  }
                                                                           
                       
  const auto allocSize = allocationSizeForCapacity(capacity);
  return createPseudoHandle(
      runtime
          .makeAVariable<SegmentedArrayBase, HasFinalizer::No, LongLived::Yes>(
              allocSize));
}

template <typename HVType>
CallResult<PseudoHandle<SegmentedArrayBase<HVType>>> SegmentedArrayBase<
    HVType>::create(Runtime &runtime, size_type capacity, size_type size) {
  auto arrRes = create(runtime, capacity);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  PseudoHandle<SegmentedArrayBase> self = std::move(*arrRes);
                                                                        
                                                
  self = increaseSize(runtime, std::move(self), size);
  return self;
}

template <typename HVType>
typename SegmentedArrayBase<HVType>::size_type
SegmentedArrayBase<HVType>::capacity() const {
  const auto numSlotsUsed = numSlotsUsed_.load(std::memory_order_relaxed);
  if (numSlotsUsed <= kValueToSegmentThreshold) {
                                                                             
                                                                             
                                 
    return std::min(slotCapacity(), size_type{kValueToSegmentThreshold});
  } else {
                                                             
    return kValueToSegmentThreshold +
        (numSlotsUsed - kValueToSegmentThreshold) * Segment::kMaxLength;
  }
}

template <typename HVType>
typename SegmentedArrayBase<HVType>::size_type
SegmentedArrayBase<HVType>::totalCapacityOfSpine() const {
  const auto slotCap = slotCapacity();
  if (slotCap <= kValueToSegmentThreshold) {
    return slotCap;
  } else {
    return kValueToSegmentThreshold +
        (slotCap - kValueToSegmentThreshold) * Segment::kMaxLength;
  }
}

template <typename HVType>
ExecutionStatus SegmentedArrayBase<HVType>::push_back(
    MutableHandle<SegmentedArrayBase> &self,
    Runtime &runtime,
    Handle<> value) {
  auto oldSize = self->size(runtime);
  if (growRight(self, runtime, 1) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  const auto shv = HVType::encodeHermesValue(*value, runtime);
  auto &elm = self->atRef(runtime, oldSize);
  new (&elm) GCHVType(shv, runtime.getHeap());
  return ExecutionStatus::RETURNED;
}

template <typename HVType>
ExecutionStatus SegmentedArrayBase<HVType>::resize(
    MutableHandle<SegmentedArrayBase> &self,
    Runtime &runtime,
    size_type newSize) {
  if (newSize > self->size(runtime)) {
    return growRight(self, runtime, newSize - self->size(runtime));
  } else if (newSize < self->size(runtime)) {
    self->shrinkRight(runtime, self->size(runtime) - newSize);
  }
  return ExecutionStatus::RETURNED;
}

template <typename HVType>
ExecutionStatus SegmentedArrayBase<HVType>::resizeLeft(
    MutableHandle<SegmentedArrayBase> &self,
    Runtime &runtime,
    size_type newSize) {
  if (newSize == self->size(runtime)) {
    return ExecutionStatus::RETURNED;
  } else if (newSize > self->size(runtime)) {
    return growLeft(self, runtime, newSize - self->size(runtime));
  } else {
    self->shrinkLeft(runtime, self->size(runtime) - newSize);
    return ExecutionStatus::RETURNED;
  }
}

template <typename HVType>
void SegmentedArrayBase<HVType>::resizeWithinCapacity(
    SegmentedArrayBase *self,
    Runtime &runtime,
    size_type newSize) {
  const size_type currSize = self->size(runtime);
  assert(
      newSize <= self->capacity() &&
      "Cannot resizeWithinCapacity to a size not within capacity");
  if (newSize > currSize) {
    self->increaseSizeWithinCapacity(runtime, newSize - currSize);
  } else if (newSize < currSize) {
    self->shrinkRight(runtime, currSize - newSize);
  }
}

template <typename HVType>
ExecutionStatus SegmentedArrayBase<HVType>::throwExcessiveCapacityError(
    Runtime &runtime,
    size_type capacity) {
  assert(
      capacity > maxElements() &&
      "Shouldn't call this without first checking that capacity is big");
  return runtime.raiseRangeError(
      TwineChar16(
          "Requested an array size larger than the max allowable: Requested elements = ") +
      capacity + ", max elements = " + maxElements());
}

template <typename HVType>
void SegmentedArrayBase<HVType>::allocateSegment(
    Runtime &runtime,
    Handle<SegmentedArrayBase> self,
    SegmentNumber segment) {
  assert(
      self->segmentAtPossiblyUnallocated(segment)->isEmpty() &&
      "Allocating into a non-empty segment");
  PseudoHandle<Segment> c = Segment::create(runtime);
  self->segmentAtPossiblyUnallocated(segment)->set(
      HVType::encodeObjectValue(c.get(), runtime), runtime.getHeap());
}

template <typename HVType>
ExecutionStatus SegmentedArrayBase<HVType>::growRight(
    MutableHandle<SegmentedArrayBase> &self,
    Runtime &runtime,
    size_type amount) {
  if (self->size(runtime) + amount <= self->totalCapacityOfSpine()) {
    increaseSize(runtime, self, amount);
    return ExecutionStatus::RETURNED;
  }
  const auto newSize = self->size(runtime) + amount;
                                                                  
  auto arrRes =
      create(runtime, calculateNewCapacity(self->size(runtime), newSize));
  if (arrRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  PseudoHandle<SegmentedArrayBase> newSegmentedArray = std::move(*arrRes);
                                           
                                                                      
  const auto numSlotsUsed = self->numSlotsUsed_.load(std::memory_order_relaxed);
  GCHVType::uninitialized_copy(
      self->inlineStorage(),
      self->inlineStorage() + numSlotsUsed,
      newSegmentedArray->inlineStorage(),
      runtime.getHeap());
                                                                          
  newSegmentedArray->numSlotsUsed_.store(
      numSlotsUsed, std::memory_order_release);
  newSegmentedArray =
      increaseSize(runtime, std::move(newSegmentedArray), amount);
                         
  self = newSegmentedArray.get();
  return ExecutionStatus::RETURNED;
}

template <typename HVType>
ExecutionStatus SegmentedArrayBase<HVType>::growLeft(
    MutableHandle<SegmentedArrayBase> &self,
    Runtime &runtime,
    size_type amount) {
  if (self->size(runtime) + amount <= self->totalCapacityOfSpine()) {
    growLeftWithinCapacity(runtime, self, amount);
    return ExecutionStatus::RETURNED;
  }
  const auto newSize = self->size(runtime) + amount;
  auto arrRes = create(
      runtime, calculateNewCapacity(self->size(runtime), newSize), newSize);
  if (arrRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  PseudoHandle<SegmentedArrayBase> newSegmentedArray = std::move(*arrRes);
                                                                        
                                                                             
           
  GCHVType::copy(
      self->begin(runtime),
      self->end(runtime),
      newSegmentedArray->begin(runtime) + amount,
      runtime.getHeap());
                         
  self = newSegmentedArray.get();
  return ExecutionStatus::RETURNED;
}

template <typename HVType>
void SegmentedArrayBase<HVType>::growLeftWithinCapacity(
    Runtime &runtime,
    PseudoHandle<SegmentedArrayBase> self,
    size_type amount) {
  assert(
      self->size(runtime) + amount <= self->totalCapacityOfSpine() &&
      "Cannot grow higher than capacity");
                                                                     
  self = increaseSize(runtime, std::move(self), amount);
                                                  
  GCHVType::copy_backward(
      self->begin(runtime),
      self->end(runtime) - amount,
      self->end(runtime),
      runtime.getHeap());
                                          
  GCHVType::fill(
      self->begin(runtime),
      self->begin(runtime) + amount,
      HVType::encodeEmptyValue(),
      runtime.getHeap());
}

template <typename HVType>
void SegmentedArrayBase<HVType>::shrinkRight(
    Runtime &runtime,
    size_type amount) {
  decreaseSize(runtime, amount);
}

template <typename HVType>
void SegmentedArrayBase<HVType>::shrinkLeft(
    Runtime &runtime,
    size_type amount) {
                                                    
  GCHVType::copy(
      begin(runtime) + amount, end(runtime), begin(runtime), runtime.getHeap());
                                                                            
  decreaseSize(runtime, amount);
}

template <typename HVType>
void SegmentedArrayBase<HVType>::increaseSizeWithinCapacity(
    Runtime &runtime,
    size_type amount) {
                                                                       
                                                        
  const auto currSize = size(runtime);
  const auto finalSize = currSize + amount;
  assert(
      finalSize <= capacity() &&
      "Cannot use increaseSizeWithinCapacity without checking for capacity first");

  if (finalSize <= kValueToSegmentThreshold) {
                                                                       
    GCHVType::uninitialized_fill(
        inlineStorage() + currSize,
        inlineStorage() + finalSize,
        HVType::encodeEmptyValue(),
        runtime.getHeap());
                          
    numSlotsUsed_.store(finalSize, std::memory_order_release);
    return;
  }
                                                                            
             
  const SegmentNumber segment = toSegment(finalSize - 1);
  const auto segmentLength = toInterior(finalSize - 1) + 1;
                                                                
  if (currSize < kValueToSegmentThreshold) {
    GCHVType::uninitialized_fill(
        inlineStorage() + currSize,
        inlineStorage() + kValueToSegmentThreshold,
        HVType::encodeEmptyValue(),
        runtime.getHeap());
  }
  segmentAt(runtime, segment)->setLength(runtime, segmentLength);
}

template <typename HVType>
PseudoHandle<SegmentedArrayBase<HVType>>
SegmentedArrayBase<HVType>::increaseSize(
    Runtime &runtime,
    PseudoHandle<SegmentedArrayBase> self,
    size_type amount) {
  const auto currSize = self->size(runtime);
  const auto finalSize = currSize + amount;

  if (finalSize <= self->capacity()) {
    self->increaseSizeWithinCapacity(runtime, amount);
    return self;
  }

                                                                            
                                                                     
  assert(finalSize > kValueToSegmentThreshold);

                                                                        
              
                                                            
  if (currSize <= kValueToSegmentThreshold) {
                                                                          
                                                
    GCHVType::uninitialized_fill(
        self->inlineStorage() + currSize,
        self->inlineStorage() + kValueToSegmentThreshold,
        HVType::encodeEmptyValue(),
        runtime.getHeap());
                                                    
    self->numSlotsUsed_.store(
        kValueToSegmentThreshold, std::memory_order_release);
  }

                                                        
                                                                              
                                                                          
                                                                           
                                                                         
                                                                             
                                                                        
                                                                              
                                   
  const SegmentNumber startSegment =
      currSize <= kValueToSegmentThreshold ? 0 : toSegment(currSize - 1);
  const SegmentNumber lastSegment = toSegment(finalSize - 1);
  const auto newNumSlotsUsed = numSlotsForCapacity(finalSize);
                                                                           
                                  
  GCHVType::uninitialized_fill(
      self->inlineStorage() +
          self->numSlotsUsed_.load(std::memory_order_relaxed),
      self->inlineStorage() + newNumSlotsUsed,
      HVType::encodeEmptyValue(),
      runtime.getHeap());
  self->numSlotsUsed_.store(newNumSlotsUsed, std::memory_order_release);

                                                  
  auto selfHandle = runtime.makeHandle(std::move(self));
                           
  if (startSegment <= lastSegment &&
      selfHandle->segmentAtPossiblyUnallocated(startSegment)->isEmpty()) {
                                                                            
                            
    allocateSegment(runtime, selfHandle, startSegment);
  }
  for (auto i = startSegment + 1; i <= lastSegment; ++i) {
                                                              
    allocateSegment(runtime, selfHandle, i);
  }

                                                                        
                                  
  for (auto i = startSegment; i <= lastSegment; ++i) {
                                                                        
                
    const auto segmentLength =
        i == lastSegment ? toInterior(finalSize - 1) + 1 : Segment::kMaxLength;
    selfHandle->segmentAt(runtime, i)->setLength(runtime, segmentLength);
  }
  self = selfHandle;
  return self;
}

template <typename HVType>
void SegmentedArrayBase<HVType>::decreaseSize(
    Runtime &runtime,
    size_type amount) {
  const auto initialSize = size(runtime);
  const auto initialNumSlots = numSlotsUsed_.load(std::memory_order_relaxed);
  assert(amount <= initialSize && "Cannot decrease size past zero");
  const auto finalSize = initialSize - amount;
  const auto finalNumSlots = numSlotsForCapacity(finalSize);
  assert(
      finalNumSlots <= initialNumSlots &&
      "Should not be increasing the number of slots");
  if (finalSize > kValueToSegmentThreshold) {
                                                                 
    segmentAt(runtime, toSegment(finalSize - 1))
        ->setLength(runtime, toInterior(finalSize - 1) + 1);
  }
                                                                         
             
  GCHVType::rangeUnreachableWriteBarrier(
      inlineStorage() + finalNumSlots,
      inlineStorage() + initialNumSlots,
      runtime.getHeap());
  numSlotsUsed_.store(finalNumSlots, std::memory_order_release);
}

template <typename HVType>
gcheapsize_t SegmentedArrayBase<HVType>::_trimSizeCallback(const GCCell *cell) {
  const auto *self = reinterpret_cast<const SegmentedArrayBase *>(cell);
                                                                             
          
  return allocationSizeForSlots(
      self->numSlotsUsed_.load(std::memory_order_relaxed));
}

template class SegmentedArrayBase<HermesValue>;
template class SegmentedArrayBase<SmallHermesValue>;

}                
}                    

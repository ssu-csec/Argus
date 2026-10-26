/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/ArrayStorage.h"

#include "hermes/Support/Algorithms.h"
#include "hermes/Support/ErrorHandling.h"
#include "hermes/VM/GCPointer-inline.h"
#include "hermes/VM/Metadata.h"

namespace hermes {
namespace vm {

template <typename HVType>
const VTable ArrayStorageBase<HVType>::vt(
    ArrayStorageBase<HVType>::getCellKind(),
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

void ArrayStorageBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  const auto *self = static_cast<const ArrayStorage *>(cell);
  mb.setVTable(&ArrayStorage::vt);
  mb.addArray("storage", self->data(), &self->size_, sizeof(GCHermesValue));
}

void ArrayStorageSmallBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  const auto *self = static_cast<const ArrayStorageSmall *>(cell);
  mb.setVTable(&ArrayStorageSmall::vt);
  mb.addArray(
      "storage", self->data(), &self->size_, sizeof(GCSmallHermesValue));
}

template <typename HVType>
ExecutionStatus ArrayStorageBase<HVType>::ensureCapacity(
    MutableHandle<ArrayStorageBase<HVType>> &selfHandle,
    Runtime &runtime,
    size_type capacity) {
  assert(capacity <= maxElements() && "capacity overflows 32-bit storage");

  if (capacity <= selfHandle->capacity())
    return ExecutionStatus::RETURNED;

  return reallocateToLarger(
      selfHandle, runtime, capacity, 0, 0, selfHandle->size());
}

template <typename HVType>
ExecutionStatus ArrayStorageBase<HVType>::reallocateToLarger(
    MutableHandle<ArrayStorageBase<HVType>> &selfHandle,
    Runtime &runtime,
    size_type capacity,
    size_type fromFirst,
    size_type toFirst,
    size_type toLast) {
  assert(capacity <= maxElements() && "capacity overflows 32-bit storage");

  assert(
      capacity > selfHandle->capacity() &&
      "reallocateToLarger must be called with a larger capacity");

  auto arrRes = create(runtime, capacity);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto newSelfHandle = runtime.makeHandle<ArrayStorageBase<HVType>>(*arrRes);

  auto *newSelf = newSelfHandle.get();

                            
  auto *self = selfHandle.get();
  size_type copySize = std::min(self->size() - fromFirst, toLast - toFirst);

  {
    GCHVType *from = self->data() + fromFirst;
    GCHVType *to = newSelf->data() + toFirst;
    GCHVType::uninitialized_copy(from, from + copySize, to, runtime.getHeap());
  }

                                                             
  GCHVType::uninitialized_fill(
      newSelf->data(),
      newSelf->data() + toFirst,
      HVType::encodeEmptyValue(),
      runtime.getHeap());

                                                                      
  if (toFirst + copySize < toLast) {
    GCHVType::uninitialized_fill(
        newSelf->data() + toFirst + copySize,
        newSelf->data() + toLast,
        HVType::encodeEmptyValue(),
        runtime.getHeap());
  }

  newSelf->size_.store(toLast, std::memory_order_release);

                       
  selfHandle = newSelfHandle.get();

  return ExecutionStatus::RETURNED;
}

template <typename HVType>
void ArrayStorageBase<HVType>::resizeWithinCapacity(
    ArrayStorageBase<HVType> *self,
    GC &gc,
    size_type newSize) {
  assert(
      newSize <= self->capacity() &&
      "newSize must be <= capacity in resizeWithinCapacity()");
                                          
  const auto sz = self->size();
  if (newSize > sz) {
                                                      
                                                                            
                                                                         
                                                                           
                                                                              
                                                         
    GCHVType::uninitialized_fill(
        self->data() + sz,
        self->data() + newSize,
        HVType::encodeEmptyValue(),
        gc);
  } else if (newSize < sz) {
                                                                             
            
                                                                            
                               
    GCHVType::rangeUnreachableWriteBarrier(
        self->data() + newSize, self->data() + sz, gc);
  }
  self->size_.store(newSize, std::memory_order_release);
}

template <typename HVType>
ExecutionStatus ArrayStorageBase<HVType>::shift(
    MutableHandle<ArrayStorageBase<HVType>> &selfHandle,
    Runtime &runtime,
    size_type fromFirst,
    size_type toFirst,
    size_type toLast) {
  assert(toLast <= maxElements() && "size overflows 32-bit storage");
  assert(toFirst <= toLast && "First must be before last");
  assert(fromFirst <= selfHandle->size() && "fromFirst must be before size");

                                             
  if (toLast <= selfHandle->capacity()) {
    auto *self = selfHandle.get();
    size_type copySize = std::min(self->size() - fromFirst, toLast - toFirst);

                                                  
    if (fromFirst > toFirst) {
      GCHVType::copy(
          self->data() + fromFirst,
          self->data() + fromFirst + copySize,
          self->data() + toFirst,
          runtime.getHeap());
    } else if (fromFirst < toFirst) {
                                                                               
                         
      GCHVType::copy_backward(
          self->data() + fromFirst,
          self->data() + fromFirst + copySize,
          self->data() + toFirst + copySize,
          runtime.getHeap());
    }

                                                           
    GCHVType::fill(
        self->data(),
        self->data() + toFirst,
        HVType::encodeEmptyValue(),
        runtime.getHeap());

                                                                          
    if (toFirst + copySize < toLast) {
      GCHVType::uninitialized_fill(
          self->data() + toFirst + copySize,
          self->data() + toLast,
          HVType::encodeEmptyValue(),
          runtime.getHeap());
    }
    if (toLast < self->size()) {
                                                                 
      GCHVType::rangeUnreachableWriteBarrier(
          self->data() + toLast,
          self->data() + self->size(),
          runtime.getHeap());
    }
    self->size_.store(toLast, std::memory_order_release);
    return ExecutionStatus::RETURNED;
  }

                                
  size_type capacity = selfHandle->capacity();
  if (capacity < maxElements() / 2)
    capacity = std::max(capacity * 2, toLast);
  else
    capacity = maxElements();

  return reallocateToLarger(
      selfHandle, runtime, capacity, fromFirst, toFirst, toLast);
}

template <typename HVType>
ExecutionStatus ArrayStorageBase<HVType>::throwExcessiveCapacityError(
    Runtime &runtime,
    size_type capacity) {
  assert(
      capacity > maxElements() &&
      "Shouldn't call this without first checking that capacity is big");
                                              
  HERMES_EXTRA_DEBUG(runtime.getCrashManager().setCustomData(
      "Hermes_ArrayStorage_overflow", "1"));
  return runtime.raiseRangeError(
      TwineChar16(
          "Requested an array size larger than the max allowable: Requested elements = ") +
      capacity + ", max elements = " + maxElements());
}

template <typename HVType>
ExecutionStatus ArrayStorageBase<HVType>::pushBackSlowPath(
    MutableHandle<ArrayStorageBase<HVType>> &selfHandle,
    Runtime &runtime,
    Handle<> value) {
  const auto size = selfHandle->size();
  if (resize(selfHandle, runtime, size + 1) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto hv = HVType::encodeHermesValue(*value, runtime);
  selfHandle->set(size, hv, runtime.getHeap());
  return ExecutionStatus::RETURNED;
}

template <typename HVType>
gcheapsize_t ArrayStorageBase<HVType>::_trimSizeCallback(const GCCell *cell) {
  const auto *self = reinterpret_cast<const ArrayStorageBase<HVType> *>(cell);
  return allocationSize(self->size());
}

template class ArrayStorageBase<HermesValue>;
template class ArrayStorageBase<SmallHermesValue>;

}                
}                    

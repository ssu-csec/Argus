/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_ARRAYSTORAGE_H
#define HERMES_VM_ARRAYSTORAGE_H

#include "hermes/VM/HermesValue-inline.h"
#include "hermes/VM/Metadata.h"
#include "hermes/VM/Runtime.h"
#include "hermes/VM/SmallHermesValue-inline.h"

#include "llvh/Support/TrailingObjects.h"
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

                                                                               
                                                                             
                                                                               
                                                       
template <typename HVType>
class ArrayStorageBase final
    : public VariableSizeRuntimeCell,
      private llvh::
          TrailingObjects<ArrayStorageBase<HVType>, GCHermesValueBase<HVType>> {
  using GCHVType = GCHermesValueBase<HVType>;
  friend llvh::TrailingObjects<ArrayStorageBase<HVType>, GCHVType>;
  friend void ArrayStorageBuildMeta(const GCCell *cell, Metadata::Builder &mb);
  friend void ArrayStorageSmallBuildMeta(
      const GCCell *cell,
      Metadata::Builder &mb);

  friend void ArrayStorageSerialize(Serializer &s, const GCCell *cell);
  friend void ArrayStorageDeserialize(Deserializer &d, CellKind kind);
  friend void ArrayStorageSmallSerialize(Serializer &s, const GCCell *cell);
  friend void ArrayStorageSmallDeserialize(Deserializer &d, CellKind kind);

 public:
  using size_type = uint32_t;
  using iterator = GCHVType *;

  static const VTable vt;

                                                                            
  static constexpr uint32_t allocationSize(size_type capacity) {
    return ArrayStorageBase::template totalSizeToAlloc<GCHVType>(capacity);
  }

                                                                    
                                                    
  static constexpr size_type capacityForAllocationSize(uint32_t allocSize) {
    return (allocSize - allocationSize(0)) / sizeof(HVType);
  }

                                                                                
                 
  static constexpr size_type maxElements() {
    return capacityForAllocationSize(GC::maxAllocationSize());
  }

  static bool classof(const GCCell *cell) {
    return cell->getKind() == getCellKind();
  }

  static constexpr CellKind getCellKind() {
    static_assert(
        std::is_same<HVType, HermesValue>::value ||
            std::is_same<HVType, SmallHermesValue>::value,
        "Illegal HVType.");
    return std::is_same<HVType, HermesValue>::value
        ? CellKind::ArrayStorageKind
        : CellKind::ArrayStorageSmallKind;
  }

                                                                    
  static CallResult<HermesValue> create(Runtime &runtime, size_type capacity) {
    if (LLVM_UNLIKELY(capacity > maxElements())) {
      return throwExcessiveCapacityError(runtime, capacity);
    }
    const auto allocSize = allocationSize(capacity);
    auto *cell = runtime.makeAVariable<ArrayStorageBase<HVType>>(allocSize);
    return HermesValue::encodeObjectValue(cell);
  }

#ifdef UNIT_TEST
                                                                           
                                                                               
                                    
  static ArrayStorageBase *createForTest(GC &gc, size_type capacity) {
    assert(capacity <= maxElements());
    const auto allocSize = allocationSize(capacity);
    auto *cell = gc.makeAVariable<ArrayStorageBase>(allocSize);
    ArrayStorageBase::resizeWithinCapacity(cell, gc, capacity);
    return cell;
  }
#endif

                                                                               
  static CallResult<HermesValue> createLongLived(
      Runtime &runtime,
      size_type capacity) {
    if (LLVM_UNLIKELY(capacity > maxElements())) {
      return throwExcessiveCapacityError(runtime, capacity);
    }
    const auto allocSize = allocationSize(capacity);
    return HermesValue::encodeObjectValue(runtime.makeAVariable<
                                          ArrayStorageBase<HVType>,
                                          HasFinalizer::No,
                                          LongLived::Yes>(allocSize));
  }

                                                                              
                                                       
  static CallResult<HermesValue>
  create(Runtime &runtime, size_type capacity, size_type size) {
    auto arrRes = create(runtime, capacity);
    if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }

    resizeWithinCapacity(
        vmcast<ArrayStorageBase<HVType>>(*arrRes), runtime, size);
    return arrRes;
  }

                                                       
  GCHVType *data() {
    return ArrayStorageBase<HVType>::template getTrailingObjects<GCHVType>();
  }
  const GCHVType *data() const {
    return ArrayStorageBase<HVType>::template getTrailingObjects<GCHVType>();
  }

                                                                     
                                                                             
                                                                          
  enum class Inline { No, Yes };

                                           
  template <Inline inl = Inline::No>
  HVType at(size_type index) const {
    assert(index < size() && "index out of range");
    return data()[index];
  }

                                           
  template <Inline inl = Inline::No>
  void set(size_type index, HVType val, GC &gc) {
    assert(index < size() && "index out of range");
    data()[index].set(val, gc);
  }

                                           
  template <Inline inl = Inline::No>
  void setNonPtr(size_type index, HVType val, GC &gc) {
    assert(index < size() && "index out of range");
    data()[index].setNonPtr(val, gc);
  }

  size_type capacity() const {
    return capacityForAllocationSize(getAllocatedSize());
  }
  size_type size() const {
    return size_.load(std::memory_order_relaxed);
  }

  iterator begin() {
    return data();
  }
  iterator end() {
    return data() + size();
  }

                                                                 
  static ExecutionStatus push_back(
      MutableHandle<ArrayStorageBase<HVType>> &selfHandle,
      Runtime &runtime,
      Handle<> value) {
    auto *self = selfHandle.get();
    const auto currSz = self->size();
                                                                             
                                                                           
                                                                              
                        
    auto hv = HVType::encodeHermesValue(value.get(), runtime);
                                                                    
    if (std::is_same<HVType, SmallHermesValue>::value)
      self = selfHandle.get();
    if (LLVM_LIKELY(currSz < self->capacity())) {
                                                                              
                                  
      new (&self->data()[currSz]) GCHVType(hv, runtime.getHeap());
      self->size_.store(currSz + 1, std::memory_order_release);
      return ExecutionStatus::RETURNED;
    }
    return pushBackSlowPath(selfHandle, runtime, value);
  }

                                                       
  HVType pop_back(Runtime &runtime) {
    const size_type sz = size();
    assert(sz > 0 && "Can't pop from empty ArrayStorage");
    HVType val = data()[sz - 1];
                                                                               
                                                                               
                                                           
    data()[sz - 1].unreachableWriteBarrier(runtime.getHeap());
                                                                                
                                                                             
                                                                              
                                                  
    size_.store(sz - 1, std::memory_order_relaxed);
    return val;
  }

                                                                    
                             
  static ExecutionStatus ensureCapacity(
      MutableHandle<ArrayStorageBase<HVType>> &selfHandle,
      Runtime &runtime,
      size_type capacity);

                                                                              
                                                                                
               
  static ExecutionStatus resize(
      MutableHandle<ArrayStorageBase<HVType>> &selfHandle,
      Runtime &runtime,
      size_type newSize) {
    return shift(selfHandle, runtime, 0, 0, newSize);
  }

                                                                            
     
                                                                          
                                                                          
                                                                              
                   
  static ExecutionStatus resizeLeft(
      MutableHandle<ArrayStorageBase<HVType>> &selfHandle,
      Runtime &runtime,
      size_type newSize) {
    return shift(selfHandle, runtime, 0, newSize - selfHandle->size(), newSize);
  }

                                                                
                                                                                
                         
  static void resizeWithinCapacity(
      ArrayStorageBase<HVType> *self,
      GC &gc,
      size_type newSize);

  static void resizeWithinCapacity(
      ArrayStorageBase<HVType> *self,
      Runtime &runtime,
      size_type newSize) {
    resizeWithinCapacity(self, runtime.getHeap(), newSize);
  }

 private:
  AtomicIfConcurrentGC<size_type> size_{0};

 public:
  ArrayStorageBase() = default;
  ArrayStorageBase(const ArrayStorageBase &) = delete;
  void operator=(const ArrayStorageBase &) = delete;
  ~ArrayStorageBase() = delete;

 private:
                                                                             
                                                      
                                                 
  static ExecutionStatus throwExcessiveCapacityError(
      Runtime &runtime,
      size_type capacity);

                                                                              
                                   
  static ExecutionStatus pushBackSlowPath(
      MutableHandle<ArrayStorageBase<HVType>> &selfHandle,
      Runtime &runtime,
      Handle<> value);

                                                                             
               
                                                                        
  static gcheapsize_t _trimSizeCallback(const GCCell *self);

                                                                         
                                                                              
                     
                                                         
                                                                           
  static ExecutionStatus reallocateToLarger(
      MutableHandle<ArrayStorageBase<HVType>> &selfHandle,
      Runtime &runtime,
      size_type capacity,
      size_type fromFirst,
      size_type toFirst,
      size_type toLast);

                                                                    
                                                                  
#if defined(UNIT_TEST) || defined(_MSC_VER)
 public:
#endif
                                                                          
                                                                             
                                                                                
                                                                                
                 
                                                         
                                                                                
                               
                                                                               
                
  static ExecutionStatus shift(
      MutableHandle<ArrayStorageBase<HVType>> &selfHandle,
      Runtime &runtime,
      size_type fromFirst,
      size_type toFirst,
      size_type toLast);
};

using ArrayStorage = ArrayStorageBase<HermesValue>;
using ArrayStorageSmall = ArrayStorageBase<SmallHermesValue>;

static_assert(
    ArrayStorage::allocationSize(ArrayStorage::maxElements()) <=
        GC::maxAllocationSize(),
    "maxElements() is too big");

static_assert(
    GC::maxAllocationSize() -
            ArrayStorage::allocationSize(ArrayStorage::maxElements()) <
        HeapAlign,
    "maxElements() is too small");

static_assert(
    ArrayStorageSmall::allocationSize(ArrayStorageSmall::maxElements()) <=
        GC::maxAllocationSize(),
    "maxElements() is too big");

static_assert(
    GC::maxAllocationSize() -
            ArrayStorageSmall::allocationSize(
                ArrayStorageSmall::maxElements()) <
        HeapAlign,
    "maxElements() is too small");

}                
}                    
#pragma GCC diagnostic pop

#endif                            

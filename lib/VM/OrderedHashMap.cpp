/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/OrderedHashMap.h"

#include "hermes/Support/ErrorHandling.h"
#include "hermes/VM/BuildMetadata.h"
#include "hermes/VM/GCPointer-inline.h"
#include "hermes/VM/Operations.h"

namespace hermes {
namespace vm {
                                                                                
                     

const VTable HashMapEntry::vt{
    CellKind::HashMapEntryKind,
    cellSize<HashMapEntry>()};

void HashMapEntryBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  const auto *self = static_cast<const HashMapEntry *>(cell);
  mb.setVTable(&HashMapEntry::vt);
  mb.addField("key", &self->key);
  mb.addField("value", &self->value);
  mb.addField("prevIterationEntry", &self->prevIterationEntry);
  mb.addField("nextIterationEntry", &self->nextIterationEntry);
  mb.addField("nextEntryInBucket", &self->nextEntryInBucket);
}

CallResult<PseudoHandle<HashMapEntry>> HashMapEntry::create(Runtime &runtime) {
  return createPseudoHandle(runtime.makeAFixed<HashMapEntry>());
}

                                                                                
                       

const VTable OrderedHashMap::vt{
    CellKind::OrderedHashMapKind,
    cellSize<OrderedHashMap>()};

void OrderedHashMapBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  const auto *self = static_cast<const OrderedHashMap *>(cell);
  mb.setVTable(&OrderedHashMap::vt);
  mb.addField("hashTable", &self->hashTable_);
  mb.addField("firstIterationEntry", &self->firstIterationEntry_);
  mb.addField("lastIterationEntry", &self->lastIterationEntry_);
}

OrderedHashMap::OrderedHashMap(
    Runtime &runtime,
    Handle<ArrayStorageSmall> hashTableStorage)
    : hashTable_(runtime, hashTableStorage.get(), runtime.getHeap()) {}

CallResult<PseudoHandle<OrderedHashMap>> OrderedHashMap::create(
    Runtime &runtime) {
  auto arrRes =
      ArrayStorageSmall::create(runtime, INITIAL_CAPACITY, INITIAL_CAPACITY);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto hashTableStorage = runtime.makeHandle<ArrayStorageSmall>(*arrRes);

  return createPseudoHandle(
      runtime.makeAFixed<OrderedHashMap>(runtime, hashTableStorage));
}

void OrderedHashMap::removeLinkedListNode(
    Runtime &runtime,
    HashMapEntry *entry,
    GC &gc) {
  assert(
      entry != lastIterationEntry_.get(runtime) &&
      "Cannot remove the last entry");
  if (entry->prevIterationEntry) {
    entry->prevIterationEntry.getNonNull(runtime)->nextIterationEntry.set(
        runtime, entry->nextIterationEntry, gc);
  }
  if (entry->nextIterationEntry) {
    entry->nextIterationEntry.getNonNull(runtime)->prevIterationEntry.set(
        runtime, entry->prevIterationEntry, gc);
  }
  if (entry == firstIterationEntry_.get(runtime)) {
    firstIterationEntry_.set(runtime, entry->nextIterationEntry, gc);
  }
  entry->prevIterationEntry.setNull(runtime.getHeap());
}

static HashMapEntry *castToMapEntry(SmallHermesValue shv, PointerBase &base) {
  if (shv.isEmpty())
    return nullptr;
  return vmcast<HashMapEntry>(shv.getObject(base));
}

HashMapEntry *OrderedHashMap::lookupInBucket(
    Runtime &runtime,
    uint32_t bucket,
    HermesValue key) {
  assert(
      hashTable_.getNonNull(runtime)->size() == capacity_ &&
      "Inconsistent capacity");
  auto *entry =
      castToMapEntry(hashTable_.getNonNull(runtime)->at(bucket), runtime);
  while (entry && !isSameValueZero(entry->key, key)) {
    entry = entry->nextEntryInBucket.get(runtime);
  }
  return entry;
}

ExecutionStatus OrderedHashMap::rehashIfNecessary(
    Handle<OrderedHashMap> self,
    Runtime &runtime) {
  uint32_t newCapacity = self->capacity_;
                                                                               
                                                                            
                                                             
  static_assert(
      MAX_CAPACITY < UINT32_MAX / 4,
      "Avoid overflow checks on multiplying capacity by 4");
  if (self->size_ * 4 > self->capacity_ * 3) {
                                                                    
    newCapacity = self->capacity_ * 2;
    if (LLVM_UNLIKELY(newCapacity > MAX_CAPACITY)) {
                                                                        
                                                                      
                                                                  
      assert(
          (self->capacity_ & (self->capacity_ - 1)) == 0 &&
          "capacity_ must be power of 2");
      newCapacity = self->capacity_;
    }
  } else if (
      self->size_ * 4 < self->capacity_ && self->capacity_ > INITIAL_CAPACITY) {
                                                                    
    newCapacity = self->capacity_ / 2;
  }
  if (newCapacity == self->capacity_) {
                         
    return ExecutionStatus::RETURNED;
  }
  assert(
      self->size_ && self->firstIterationEntry_ && self->lastIterationEntry_ &&
      "We should never be rehashing when there are no elements");

                                                        
  self->capacity_ = newCapacity;

                             
  auto arrRes = ArrayStorageSmall::create(runtime, newCapacity, newCapacity);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto newHashTable = runtime.makeHandle<ArrayStorageSmall>(*arrRes);

                                              
  MutableHandle<HashMapEntry> entry{runtime};
  MutableHandle<HashMapEntry> oldNextInBucket{runtime};
  MutableHandle<> keyHandle{runtime};
  GCScopeMarkerRAII marker{runtime};
  for (unsigned i = 0, len = self->hashTable_.getNonNull(runtime)->size();
       i < len;
       ++i) {
    entry =
        castToMapEntry(self->hashTable_.getNonNull(runtime)->at(i), runtime);
    while (entry) {
      marker.flush();
      keyHandle = entry->key;
      uint32_t bucket = hashToBucket(self, runtime, keyHandle);
      oldNextInBucket = entry->nextEntryInBucket.get(runtime);
      if (newHashTable->at(bucket).isEmpty()) {
                        
        entry->nextEntryInBucket.setNull(runtime.getHeap());
      } else {
                                           
        entry->nextEntryInBucket.set(
            runtime,
            vmcast<HashMapEntry>(newHashTable->at(bucket).getObject(runtime)),
            runtime.getHeap());
      }
                                             
      newHashTable->set(
          bucket,
          SmallHermesValue::encodeObjectValue(*entry, runtime),
          runtime.getHeap());

      entry = *oldNextInBucket;
    }
  }

  self->hashTable_.setNonNull(runtime, newHashTable.get(), runtime.getHeap());
  assert(
      self->hashTable_.getNonNull(runtime)->size() == self->capacity_ &&
      "Inconsistent capacity");
  return ExecutionStatus::RETURNED;
}

bool OrderedHashMap::has(
    Handle<OrderedHashMap> self,
    Runtime &runtime,
    Handle<> key) {
  auto bucket = hashToBucket(self, runtime, key);
  return self->lookupInBucket(runtime, bucket, key.getHermesValue());
}

HashMapEntry *OrderedHashMap::find(
    Handle<OrderedHashMap> self,
    Runtime &runtime,
    Handle<> key) {
  auto bucket = hashToBucket(self, runtime, key);
  return self->lookupInBucket(runtime, bucket, key.getHermesValue());
}

HermesValue OrderedHashMap::get(
    Handle<OrderedHashMap> self,
    Runtime &runtime,
    Handle<> key) {
  auto *entry = find(self, runtime, key);
  if (!entry) {
    return HermesValue::encodeUndefinedValue();
  }
  return entry->value;
}

ExecutionStatus OrderedHashMap::insert(
    Handle<OrderedHashMap> self,
    Runtime &runtime,
    Handle<> key,
    Handle<> value) {
  uint32_t bucket = hashToBucket(self, runtime, key);
  if (auto *entry =
          self->lookupInBucket(runtime, bucket, key.getHermesValue())) {
                                                       
    entry->value.set(value.get(), runtime.getHeap());
    return ExecutionStatus::RETURNED;
  }
                                               
  auto crtRes = HashMapEntry::create(runtime);
  if (LLVM_UNLIKELY(crtRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto newMapEntry = runtime.makeHandle(std::move(*crtRes));
  newMapEntry->key.set(key.get(), runtime.getHeap());
  newMapEntry->value.set(value.get(), runtime.getHeap());
  auto *curBucketFront =
      castToMapEntry(self->hashTable_.getNonNull(runtime)->at(bucket), runtime);
  if (curBucketFront) {
                                                                      
                            
    newMapEntry->nextEntryInBucket.set(
        runtime, curBucketFront, runtime.getHeap());
  }
                                                                    
  self->hashTable_.getNonNull(runtime)->set(
      bucket,
      SmallHermesValue::encodeObjectValue(*newMapEntry, runtime),
      runtime.getHeap());

  if (!self->firstIterationEntry_) {
                                                         
                                     
    self->firstIterationEntry_.set(
        runtime, newMapEntry.get(), runtime.getHeap());
    self->lastIterationEntry_.set(
        runtime, newMapEntry.get(), runtime.getHeap());
  } else {
                                                 
    self->lastIterationEntry_.getNonNull(runtime)->nextIterationEntry.set(
        runtime, newMapEntry.get(), runtime.getHeap());
    newMapEntry->prevIterationEntry.set(
        runtime, self->lastIterationEntry_, runtime.getHeap());

    HashMapEntry *previousLastEntry = self->lastIterationEntry_.get(runtime);
    self->lastIterationEntry_.set(
        runtime, newMapEntry.get(), runtime.getHeap());

    if (previousLastEntry && previousLastEntry->isDeleted()) {
                                                                             
      self->removeLinkedListNode(runtime, previousLastEntry, runtime.getHeap());
    }
  }

  self->size_++;
  return self->rehashIfNecessary(self, runtime);
}

bool OrderedHashMap::erase(
    Handle<OrderedHashMap> self,
    Runtime &runtime,
    Handle<> key) {
  uint32_t bucket = hashToBucket(self, runtime, key);
  HashMapEntry *prevEntry = nullptr;
  auto *entry =
      castToMapEntry(self->hashTable_.getNonNull(runtime)->at(bucket), runtime);
  while (entry && !isSameValueZero(entry->key, key.getHermesValue())) {
    prevEntry = entry;
    entry = entry->nextEntryInBucket.get(runtime);
  }
  if (!entry) {
                              
    return false;
  }

  if (prevEntry) {
                                                                       
    prevEntry->nextEntryInBucket.set(
        runtime, entry->nextEntryInBucket, runtime.getHeap());
  } else {
                                                                         
                                                                        
                               
    self->hashTable_.getNonNull(runtime)->set(
        bucket,
        entry->nextEntryInBucket
            ? SmallHermesValue::encodeObjectValue(entry->nextEntryInBucket)
            : SmallHermesValue::encodeEmptyValue(),
        runtime.getHeap());
  }

  entry->markDeleted(runtime);
  self->size_--;

                                                         
                                                                          
                                                                             
                                                                          
            
  if (entry != self->lastIterationEntry_.get(runtime)) {
    self->removeLinkedListNode(runtime, entry, runtime.getHeap());
  }

  self->rehashIfNecessary(self, runtime);

  return true;
}

HashMapEntry *OrderedHashMap::iteratorNext(
    Runtime &runtime,
    HashMapEntry *entry) const {
  if (entry == nullptr) {
                                                     
    entry = firstIterationEntry_.get(runtime);
  } else {
                                 
    entry = entry->nextIterationEntry.get(runtime);
  }

                                                                          
  while (entry && entry->isDeleted()) {
    entry = entry->nextIterationEntry.get(runtime);
  }
  return entry;
}

void OrderedHashMap::clear(Runtime &runtime) {
  if (!firstIterationEntry_) {
                 
    return;
  }

                          
  for (unsigned i = 0; i < capacity_; ++i) {
    auto entry = castToMapEntry(hashTable_.getNonNull(runtime)->at(i), runtime);
                                                          
    while (entry) {
      entry->markDeleted(runtime);
      entry = entry->nextEntryInBucket.get(runtime);
    }
                                             
    hashTable_.getNonNull(runtime)->setNonPtr(
        i, SmallHermesValue::encodeEmptyValue(), runtime.getHeap());
  }
                                               
  ArrayStorageSmall::resizeWithinCapacity(
      hashTable_.getNonNull(runtime), runtime, INITIAL_CAPACITY);
  capacity_ = INITIAL_CAPACITY;

                                                              
                                           
                                                                    
                                   
  firstIterationEntry_.set(runtime, lastIterationEntry_, runtime.getHeap());
  firstIterationEntry_.getNonNull(runtime)->prevIterationEntry.setNull(
      runtime.getHeap());
  size_ = 0;
}

}                
}                    

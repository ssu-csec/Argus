/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_ORDERED_HASHMAP_H
#define HERMES_VM_ORDERED_HASHMAP_H

#include "hermes/Support/ErrorHandling.h"
#include "hermes/VM/ArrayStorage.h"
#include "hermes/VM/Runtime.h"

#include <vector>

namespace hermes {
namespace vm {

                                                             
                                                          
                                                                  
                                                                          
class HashMapEntry final : public GCCell {
 public:
  static const VTable vt;

              
  GCHermesValue key;

                
  GCHermesValue value;

                                        
  GCPointer<HashMapEntry> prevIterationEntry{nullptr};

                                    
  GCPointer<HashMapEntry> nextIterationEntry{nullptr};

                                          
  GCPointer<HashMapEntry> nextEntryInBucket{nullptr};

  static constexpr CellKind getCellKind() {
    return CellKind::HashMapEntryKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::HashMapEntryKind;
  }

  static CallResult<PseudoHandle<HashMapEntry>> create(Runtime &runtime);

                                                    
  bool isDeleted() const {
    assert(key.isEmpty() == value.isEmpty() && "Inconsistent deleted status");
    return value.isEmpty();
  }

                                 
  void markDeleted(Runtime &runtime) {
    key.setNonPtr(HermesValue::encodeEmptyValue(), runtime.getHeap());
    value.setNonPtr(HermesValue::encodeEmptyValue(), runtime.getHeap());
  }
};                

                                                                           
                                                                         
                                                                            
          
                                                                           
                                                                         
                                                       
                                                                            
                       
                                                                       
                                                                        
                                                                          
                                                                         
                                                                       
               
class OrderedHashMap final : public GCCell {
  friend void OrderedHashMapBuildMeta(
      const GCCell *cell,
      Metadata::Builder &mb);

 public:
  static const VTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::OrderedHashMapKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::OrderedHashMapKind;
  }

  static CallResult<PseudoHandle<OrderedHashMap>> create(Runtime &runtime);

                                                           
  static bool has(Handle<OrderedHashMap> self, Runtime &runtime, Handle<> key);

                                                                 
                                  
  static HermesValue
  get(Handle<OrderedHashMap> self, Runtime &runtime, Handle<> key);

                                                                 
                                
  static HashMapEntry *
  find(Handle<OrderedHashMap> self, Runtime &runtime, Handle<> key);

                                                                    
  static ExecutionStatus insert(
      Handle<OrderedHashMap> self,
      Runtime &runtime,
      Handle<> key,
      Handle<> value);

                                                                
  static bool
  erase(Handle<OrderedHashMap> self, Runtime &runtime, Handle<> key);

                                                                          
  void clear(Runtime &runtime);

                                  
  uint32_t size() const {
    return size_;
  }

                                                  
                                                                          
                                
                                                                        
              
  HashMapEntry *iteratorNext(Runtime &runtime, HashMapEntry *entry = nullptr)
      const;

  OrderedHashMap(Runtime &runtime, Handle<ArrayStorageSmall> hashTableStorage);

 private:
                                                                       
                                                                 
  GCPointer<ArrayStorageSmall> hashTable_{nullptr};

                                                                              
  GCPointer<HashMapEntry> firstIterationEntry_{nullptr};

                                                                         
  GCPointer<HashMapEntry> lastIterationEntry_{nullptr};

                                         
  static constexpr uint32_t INITIAL_CAPACITY = 16;

                                                                           
                   
                                                                             
                                             
  static constexpr uint32_t MAX_CAPACITY =
      std::min(ArrayStorageSmall::maxElements(), UINT32_MAX / 4);

                                 
  uint32_t capacity_{INITIAL_CAPACITY};

                                             
  uint32_t size_{0};

                                                       
  static uint32_t
  hashToBucket(Handle<OrderedHashMap> self, Runtime &runtime, Handle<> key) {
    auto hash = runtime.gcStableHashHermesValue(key);
    assert(
        (self->capacity_ & (self->capacity_ - 1)) == 0 &&
        "capacity_ must be power of 2");
    return hash & (self->capacity_ - 1);
  }

                                         
  void removeLinkedListNode(Runtime &runtime, HashMapEntry *entry, GC &gc);

                                                              
  HashMapEntry *
  lookupInBucket(Runtime &runtime, uint32_t bucket, HermesValue key);

                                                                   
                                                                   
                                                                    
  static ExecutionStatus rehashIfNecessary(
      Handle<OrderedHashMap> self,
      Runtime &runtime);
};                  
}                
}                    
#endif                               

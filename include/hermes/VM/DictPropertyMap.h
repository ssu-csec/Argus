/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_DICTPROPERTYMAP_H
#define HERMES_VM_DICTPROPERTYMAP_H

#include "hermes/VM/IdentifierTable.h"
#include "hermes/VM/PropertyDescriptor.h"
#include "hermes/VM/Runtime.h"
#include "hermes/VM/SymbolID.h"

#include "llvh/Support/TrailingObjects.h"
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

                                                                            
                                                                     
                                 
   
                                            
                                                                              
                                                                             
                                                                              
                                
   
                                                                              
                                                                             
                                                                            
                                                             
   
                                                                              
                                                                                
   
                                                                                
                                                                               
                                                                                
                                                                               
                                                                          
                                      
   
                                                                           
                                                                            
   
                                                                        
                                                                           
                                                                                
                                               
   
                                                                            
                                                                                
                                                                              
                                                            
   
                                                           
                                                       
                                                            
                                                                          
                    
                                                                        
                                                
   
namespace detail {

                                                                            
                                                                            
                                             
class DPMHashPair {
 public:
  DPMHashPair() : idpart_(0), desc_(0) {}
  bool isEmpty() const {
    return desc_ == EMPTY;
  }
  bool isDeleted() const {
    return desc_ == DELETED;
  }
  bool isValid() const {
    return desc_ >= FIRST_VALID;
  }
  uint32_t getDescIndex() const {
    assert(isValid() && "asked for descriptor of invalid pair");
    return desc_ - FIRST_VALID;
  }
                                                       
  bool mayBe(SymbolID id) const {
    assert(isValid() && "tried to match invalid pair");
    return idpart_ == (id.unsafeGetRaw() & ID_MASK);
  }
                                                          
                                                      
  bool setDescIndex(uint32_t idx, SymbolID id) {
    assert(!isValid() && "overwriting a valid entry");
    assert(canStore(idx) && "impossibly large descriptor index");
    bool ret = isDeleted();
    desc_ = idx + FIRST_VALID;
    idpart_ = (id.unsafeGetRaw() & ID_MASK);
    assert(isValid() && "failed to make a valid entry");
    return ret;
  }
                                                  
                                           
  uint32_t setDeleted() {
    assert(isValid() && "tried to delete an empty/deleted entry");
    uint32_t ret = getDescIndex();
    desc_ = DELETED;
    return ret;
  }
                                                                            
                    
  static constexpr bool canStore(uint32_t idx) {
    return idx < ((1 << DESC_BITS) - FIRST_VALID);
  }

 private:
                                                                          
  enum { EMPTY = 0, DELETED, FIRST_VALID };

                                                                      
                                                                        
#ifdef HERMESVM_GC_MALLOC
                                                                           
                                                                       
  static constexpr size_t ID_BITS = 4;
#else
                                                                       
  static constexpr size_t ID_BITS = 8;
#endif
  static constexpr size_t ID_MASK = (1 << ID_BITS) - 1;

                                                                       
  static constexpr size_t DESC_BITS = 32 - ID_BITS;

  struct {
                           
    uint32_t idpart_ : ID_BITS;
                                                    
    uint32_t desc_ : DESC_BITS;
  };
};

}                    

class DictPropertyMap final
    : public VariableSizeRuntimeCell,
      private llvh::TrailingObjects<
          DictPropertyMap,
          std::pair<GCSymbolID, NamedPropertyDescriptor>,
          detail::DPMHashPair> {
  friend TrailingObjects;
  friend void DictPropertyMapBuildMeta(
      const GCCell *cell,
      Metadata::Builder &mb);

 public:
  using size_type = uint32_t;

  using DescriptorPair = std::pair<GCSymbolID, NamedPropertyDescriptor>;

  static const size_type DEFAULT_CAPACITY = 2;

                                                                         
                   
  class PropertyPos {
    friend class DictPropertyMap;
    size_type hashPairIndex;

    PropertyPos(size_type hashPairIndex) : hashPairIndex(hashPairIndex) {}
                                                                  
    PropertyPos() = default;
    friend class OptValue<PropertyPos>;
  };

  static const VTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::DictPropertyMapKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::DictPropertyMapKind;
  }

                                                          
  static size_type getMaxCapacity();

                                                                        
  static CallResult<PseudoHandle<DictPropertyMap>> create(
      Runtime &runtime,
      size_type capacity = DEFAULT_CAPACITY);

                                                             
  size_type size() const {
    return numProperties_;
  }

                                                                        
                                            
                                                                             
                                                                        
                                                                           
                                            
  template <typename CallbackFunction>
  static void forEachProperty(
      Handle<DictPropertyMap> selfHandle,
      Runtime &runtime,
      const CallbackFunction &callback);

                                                                          
                                                             
                                                                              
                                                      
  template <typename CallbackFunction>
  static void forEachPropertyNoAlloc(
      DictPropertyMap *self,
      const CallbackFunction &callback);

                                                                            
                                
                                                                           
                                            
                                                                   
  template <typename CallbackFunction>
  static bool forEachPropertyWhile(
      Handle<DictPropertyMap> selfHandle,
      Runtime &runtime,
      const CallbackFunction &callback);

                                                                                
                                                                            
                                     
  template <typename CallbackFunction>
  static void forEachMutablePropertyDescriptor(
      Handle<DictPropertyMap> selfHandle,
      Runtime &runtime,
      const CallbackFunction &callback);

  static DescriptorPair *getDescriptorPair(
      DictPropertyMap *self,
      PropertyPos pos);

                                                                          
               
  static OptValue<PropertyPos> find(const DictPropertyMap *self, SymbolID id);

                                                                         
                    
                                                                                
                                                  
  static CallResult<std::pair<NamedPropertyDescriptor *, bool>> findOrAdd(
      MutableHandle<DictPropertyMap> &selfHandleRef,
      Runtime &runtime,
      SymbolID id);

                                                                             
                                                                              
                                                  
                                                                              
                                 
  static ExecutionStatus add(
      MutableHandle<DictPropertyMap> &selfHandleRef,
      Runtime &runtime,
      SymbolID id,
      NamedPropertyDescriptor desc);

                                                                         
                
  static void erase(DictPropertyMap *self, Runtime &runtime, PropertyPos pos);

                                                                             
                                                                            
                                                                           
  static SlotIndex allocatePropertySlot(
      DictPropertyMap *self,
      Runtime &runtime);

  void dump();

 private:
  using HashPair = detail::DPMHashPair;

                                         
  const size_type descriptorCapacity_;
                                                                   
  const size_type hashCapacity_;

                                                                         
               
  AtomicIfConcurrentGC<size_type> numDescriptors_{0};

                                            
  size_type numProperties_{0};

                                                     
  static constexpr size_type END_OF_LIST =
      std::numeric_limits<size_type>::max();

                                                                            
                            
  static_assert(
      std::is_same<decltype(NamedPropertyDescriptor::_altFlags), size_type>::
          value,
      "size_type must correspond to NamedPropertyDescriptor::_altFlags");

                                                                     
                                                                       
  size_type deletedListHead_{END_OF_LIST};

                                            
  size_type deletedListSize_{0};

                                                                              
                                                            
  static size_type calcHashCapacity(size_type cap) {
    assert(
        (cap <= std::numeric_limits<size_type>::max() / 4) &&
        "size will cause integer overflow in calcHashCapacity");

    return llvh::PowerOf2Ceil(cap * 4 / 3 + 1);
  }

                                                                            
                                                                  
  static constexpr uint64_t constCalcHashCapacity64(uint64_t cap) {
    return constPowerOf2Ceil(cap * 4 / 3 + 1);
  }

                                                             
                                                                  
  static constexpr uint64_t constPowerOf2Ceil(uint64_t A, uint64_t ceil = 1) {
    return ceil >= A ? ceil : constPowerOf2Ceil(A, ceil << 1);
  }

                                                        
  static unsigned hash(SymbolID symbolID) {
    return symbolID.unsafeGetRaw();
  }

 public:
  DictPropertyMap(size_type descriptorCapacity, size_type hashCapacity)
      : descriptorCapacity_(descriptorCapacity), hashCapacity_(hashCapacity) {
                            
    std::fill_n(getHashPairs(), hashCapacity_, HashPair{});
  }

 private:
  DescriptorPair *getDescriptorPairs() {
    return getTrailingObjects<DescriptorPair>();
  }
  const DescriptorPair *getDescriptorPairs() const {
    return getTrailingObjects<DescriptorPair>();
  }
  HashPair *getHashPairs() {
    return getTrailingObjects<HashPair>();
  }

                                                                          
                                           
  static void setNextDeletedIndex(
      DescriptorPair *descPair,
      size_type nextIndex) {
    assert(
        descPair->first == SymbolID::deleted() &&
        "Descriptor pair is not deleted");
    descPair->second._altFlags = nextIndex;
  }

                                                                           
                                               
  static size_type getNextDeletedIndex(const DescriptorPair *descPair) {
    assert(
        descPair->first == SymbolID::deleted() &&
        "Descriptor pair is not deleted");
    return descPair->second._altFlags;
  }

                                                                           
                                                                 
  LLVM_ATTRIBUTE_ALWAYS_INLINE void incDeletedHashCount() {}
                                                                           
                                                                 
  LLVM_ATTRIBUTE_ALWAYS_INLINE void decDeletedHashCount() {}

                                                                          
                                                                              
                                                     
  std::pair<bool, HashPair *> static lookupEntryFor(
      DictPropertyMap *self,
      SymbolID symbolID);

                                                                            
  bool isMatch(const HashPair *entry, SymbolID symbolID) const {
    return entry->mayBe(symbolID) &&
        getDescriptorPairs()[entry->getDescIndex()].first == symbolID;
  }

                                                                                
                                                                          
                                                     
                                                                               
                                
                                                                           
  static ExecutionStatus grow(
      MutableHandle<DictPropertyMap> &selfHandleRef,
      Runtime &runtime,
      size_type newCapacity);

                                                                             
  static uint32_t allocationSize(
      size_type descriptorCapacity,
      size_type hashCapacity) {
    return totalSizeToAlloc<DescriptorPair, HashPair>(
        descriptorCapacity, hashCapacity);
  }

                                                                             
                                                                            
               
        

                                                                                
                                                                          
                                                    
  static constexpr uint64_t kAlignPadding = alignof(std::max_align_t) - 1;

                                                                            
                                                                               
                     
                                                                  
  static constexpr uint64_t constApproxAllocSize64(uint32_t cap) {
    static_assert(
        alignof(DictPropertyMap) <= kAlignPadding + 1,
        "DictPropertyMap exceeds supported alignment");
    static_assert(
        alignof(DictPropertyMap::DescriptorPair) <= kAlignPadding + 1,
        "DictPropertyMap::DescriptorPair exceeds supported alignment");
    static_assert(
        alignof(DictPropertyMap::HashPair) <= kAlignPadding + 1,
        "DictPropertyMap::HashPair exceeds supported alignment");

    return sizeof(DictPropertyMap) + kAlignPadding +
        sizeof(DictPropertyMap::DescriptorPair) * (uint64_t)cap +
        kAlignPadding +
        sizeof(DictPropertyMap::HashPair) * constCalcHashCapacity64(cap) +
        kAlignPadding;
  }

                                                                              
                                                                                
                                                                    
                                                                  
  static constexpr bool constWouldFitAllocation(uint32_t cap) {
    return constApproxAllocSize64(cap) <= GC::maxAllocationSize();
  }

                                                                         
                                                        
                                                                  
  static constexpr uint32_t constFindMaxCapacity(
      uint32_t lower,
      uint32_t upper) {
    assert(constWouldFitAllocation(lower) && "lower must always fit");
    if (upper - lower <= 1)
      return lower;
    const auto mid = (lower + upper) / 2;
    return constWouldFitAllocation(mid) ? constFindMaxCapacity(mid, upper)
                                        : constFindMaxCapacity(lower, mid);
  }

                                                                             
                                           
  struct detail;
  friend struct detail;

        

 protected:
  size_t numTrailingObjects(OverloadToken<DescriptorPair>) const {
    return descriptorCapacity_;
  }
};

                                                                                
                                  

template <typename CallbackFunction>
void DictPropertyMap::forEachProperty(
    Handle<DictPropertyMap> selfHandle,
    Runtime &runtime,
    const CallbackFunction &callback) {
                                                                    
                                            
  NoRJSScope scope{runtime};
  GCScopeMarkerRAII gcMarker{runtime};
  for (size_type
           i = 0,
           e = selfHandle->numDescriptors_.load(std::memory_order_relaxed);
       i != e;
       ++i) {
    auto const *descPair = selfHandle->getDescriptorPairs() + i;
    if (descPair->first.isValid()) {
      callback(descPair->first, descPair->second);
      gcMarker.flush();
    }
  }
}

template <typename CallbackFunction>
void DictPropertyMap::forEachPropertyNoAlloc(
    DictPropertyMap *self,
    const CallbackFunction &callback) {
  for (size_type i = 0,
                 e = self->numDescriptors_.load(std::memory_order_relaxed);
       i != e;
       ++i) {
    auto const *descPair = self->getDescriptorPairs() + i;
    if (descPair->first.isValid()) {
      callback(descPair->first, descPair->second);
    }
  }
}

template <typename CallbackFunction>
bool DictPropertyMap::forEachPropertyWhile(
    Handle<DictPropertyMap> selfHandle,
    Runtime &runtime,
    const CallbackFunction &callback) {
                                                                    
                                            
  NoRJSScope scope{runtime};
  GCScopeMarkerRAII gcMarker{runtime};
  for (size_type
           i = 0,
           e = selfHandle->numDescriptors_.load(std::memory_order_relaxed);
       i != e;
       ++i) {
    auto const *descPair = selfHandle->getDescriptorPairs() + i;
    if (descPair->first.isValid()) {
      if (!callback(runtime, descPair->first, descPair->second))
        return false;
      gcMarker.flush();
    }
  }
  return true;
}

template <typename CallbackFunction>
void DictPropertyMap::forEachMutablePropertyDescriptor(
    Handle<DictPropertyMap> selfHandle,
    Runtime &runtime,
    const CallbackFunction &callback) {
  for (size_type
           i = 0,
           e = selfHandle->numDescriptors_.load(std::memory_order_relaxed);
       i != e;
       ++i) {
    auto *descPair = selfHandle->getDescriptorPairs() + i;
    if (descPair->first.isValid()) {
      callback(descPair->second);
    }
  }
}

inline DictPropertyMap::DescriptorPair *DictPropertyMap::getDescriptorPair(
    DictPropertyMap *self,
    PropertyPos pos) {
  assert(
      pos.hashPairIndex < self->hashCapacity_ && "property pos out of range");

  auto *hashPair = self->getHashPairs() + pos.hashPairIndex;
  auto descIndex = hashPair->getDescIndex();
  assert(
      descIndex < self->numDescriptors_.load(std::memory_order_relaxed) &&
      "descriptor index out of range");

  auto *res = self->getDescriptorPairs() + descIndex;
  assert(hashPair->mayBe(res->first) && "accessing incorrect descriptor pair");
  return res;
}

inline OptValue<DictPropertyMap::PropertyPos> DictPropertyMap::find(
    const DictPropertyMap *self,
    SymbolID id) {
                                                                          
                                                                           
                                                                             
                      
  auto *mutableSelf = const_cast<DictPropertyMap *>(self);
  auto found = lookupEntryFor(mutableSelf, id);
  if (!found.first)
    return llvh::None;
  return PropertyPos{(size_type)(found.second - mutableSelf->getHashPairs())};
}

inline ExecutionStatus DictPropertyMap::add(
    MutableHandle<DictPropertyMap> &selfHandleRef,
    Runtime &runtime,
    SymbolID id,
    NamedPropertyDescriptor desc) {
  auto found = findOrAdd(selfHandleRef, runtime, id);
  if (LLVM_UNLIKELY(found == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  assert(found->second && "trying to add an existing property");
  *found->first = desc;
  return ExecutionStatus::RETURNED;
}

}                
}                    

#pragma GCC diagnostic pop
#endif                               

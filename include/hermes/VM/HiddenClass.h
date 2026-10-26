/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_HIDDENCLASS_H
#define HERMES_VM_HIDDENCLASS_H

#include "hermes/Support/OptValue.h"
#include "hermes/VM/ArrayStorage.h"
#include "hermes/VM/DictPropertyMap.h"
#include "hermes/VM/GCPointer-inline.h"
#include "hermes/VM/PropertyDescriptor.h"
#include "hermes/VM/SegmentedArray.h"
#include "hermes/VM/WeakValueMap.h"

#include <functional>
#include "llvh/ADT/ArrayRef.h"

namespace hermes {
namespace vm {

                                                                              
                                                                             
                 
using PropStorage = ArrayStorageSmall;

                                                                          
                        
using BigStorage = SegmentedArray;

                                         
struct ClassFlags {
                                                                               
                                                                             
                                                                     
  uint8_t dictionaryMode : 1;

                                                                           
                                                                                
                                                                    
                                                                   
                                                                  
                                                                     
                                                                     
                                                       
  uint8_t dictionaryNoCacheMode : 1;

                                                                               
                                                                          
                                                                             
                                                                           
                                      
  uint8_t hasIndexLikeProperties : 1;

                                                                               
                                                                               
                                                                         
                                                                       
  uint8_t mayHaveAccessor : 1;

  ClassFlags() {
    ::memset(this, 0, sizeof(*this));
  }
};

                                                                              
                                                                              
                                                          
   
            
            
                                                                              
                                                                               
                                                                      
                                                                       
                                  
   
                                                                                
                                                                               
                                         
   
                                                                          
                                                                           
                                                                              
                                                                            
                                                                          
                                                                            
                                                                              
                                
   
                                                                               
                                                                             
                                                                              
                                                                            
                                                           
   
                   
                   
                                                                  
                                                                             
                                                                            
                                                                               
                                                 
   
                 
                 
                                                                             
                                                                       
   
                                                                             
                                                                           
                                                                              
                                                                              
                                                                           
                                                     
   
                                                                                
                                                                              
                            
class HiddenClass;
namespace detail {
                                                                    
                                                
                                                                       
                                        
class Transition {
 public:
  SymbolID symbolID;
  PropertyFlags propertyFlags;

                                                                    
  explicit Transition(SymbolID symbolID)
      : symbolID(symbolID), propertyFlags() {}
  Transition(SymbolID symbolID, PropertyFlags flags)
      : symbolID(symbolID), propertyFlags(flags) {}

  bool operator==(const Transition &a) const {
    return symbolID == a.symbolID && propertyFlags == a.propertyFlags;
  }
};

                                                                             
                                                                           
class TransitionMap {
 public:
  ~TransitionMap() {
    if (isLarge())
      delete large();
    else if (!isClean())
      smallValue().releaseSlot();
  }

                                                                            
  bool containsKey(const Transition &key, GC &gc) {
    return (smallKey_ == key && smallValue().isValid()) ||
        (isLarge() && large()->containsKey(key));
  }

                                                                               
                      
  HiddenClass *lookup(Runtime &runtime, const Transition &key) {
    if (smallKey_ == key) {
      return smallValue().get(runtime);
    } else if (isLarge()) {
      return large()->lookup(runtime, key);
    } else {
      return nullptr;
    }
  }

                                                                      
                                                                          
  bool insertNew(
      Runtime &runtime,
      const Transition &key,
      Handle<HiddenClass> value) {
    assert(
        key.symbolID != SymbolID::empty() &&
        "Should never insert an empty key");
    if (smallKey_ == key && smallValue().isValid()) {
      return false;
    }
    if (isClean()) {
      smallKey_ = key;
      smallValue() = WeakRef<HiddenClass>(runtime, value);
      return true;
    }
    if (!isLarge())
      uncleanMakeLarge(runtime);
    return large()->insertNew(runtime, key, value);
  }

                                                                       
  size_t getMemorySize() const;

                                                                             
  bool isKnownEmpty() const {
    return isClean() || (isLarge() && large()->isKnownEmpty());
  }

                                                                              
  template <typename CallbackFunction>
  void forEachEntry(const CallbackFunction &callback) const {
    if (isLarge()) {
      large()->forEachEntry(callback);
    } else if (!isClean()) {
      callback(smallKey_, smallValue());
    }
  }

#ifdef HERMES_MEMORY_INSTRUMENTATION
  void snapshotAddNodes(GC &gc, HeapSnapshot &snap);
  void snapshotAddEdges(GC &gc, HeapSnapshot &snap);
  void snapshotUntrackMemory(GC &gc);
#endif

 private:
                                                                 
  bool isClean() const {
    return smallKey_.symbolID == SymbolID::empty();
  }

                                                              
  bool isLarge() const {
    return smallKey_.symbolID == SymbolID::deleted();
  }

                                                     
  void uncleanMakeLarge(Runtime &runtime);

                                                                  
  WeakRef<HiddenClass> &smallValue() {
    assert(!isLarge());
    return u.smallValue_;
  }
  const WeakRef<HiddenClass> &smallValue() const {
    assert(!isLarge());
    return u.smallValue_;
  }
  WeakValueMap<Transition, HiddenClass> *large() const {
    assert(isLarge());
    return u.large_;
  }

  Transition smallKey_{SymbolID::empty()};
  union U {
    U() : smallValue_((WeakRefSlot *)nullptr) {}
    WeakRef<HiddenClass> smallValue_;
    WeakValueMap<Transition, HiddenClass> *large_;
  } u;
};

}                    

class HiddenClass final : public GCCell {
  friend void HiddenClassBuildMeta(const GCCell *cell, Metadata::Builder &mb);

 public:
  using Transition = detail::Transition;
                                                                           
            
  static constexpr unsigned kDictionaryThreshold = 64;

  static const VTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::HiddenClassKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::HiddenClassKind;
  }

                                                                                
                                          
  static CallResult<HermesValue> createRoot(Runtime &runtime);

                                                                   
                                                                        
                         
  bool isKnownLeaf() const {
    return transitionMap_.isKnownEmpty();
  }

                                                                          
                                                                             
  unsigned getNumProperties() const {
    return numProperties_;
  }

                                                                             
                                                         
  bool isDictionary() const {
    return flags_.dictionaryMode;
  }

                                                                      
                                                                      
                                                                     
                                                            
  bool isDictionaryNoCache() const {
    assert(
        (!flags_.dictionaryNoCacheMode || flags_.dictionaryMode) &&
        "dictionaryNoCacheMode should only be set if dictionaryMode is set.");
    return flags_.dictionaryNoCacheMode;
  }

  bool getHasIndexLikeProperties() const {
    return flags_.hasIndexLikeProperties;
  }

  bool getMayHaveAccessor() const {
    return flags_.mayHaveAccessor;
  }

                                                                      
  BigStorage *getForInCache(Runtime &runtime) const {
    return forInCache_.get(runtime);
  }

  void setForInCache(BigStorage *arr, Runtime &runtime) {
    forInCache_.set(runtime, arr, runtime.getHeap());
  }

  void clearForInCache(Runtime &runtime) {
    forInCache_.setNull(runtime.getHeap());
  }

                                                                      
                                                                  
  void clearPropertyMap(GC &gc) {
    if (!isDictionary())
      propertyMap_.setNull(gc);
  }

                                                                         
                   
  using PropertyPos = DictPropertyMap::PropertyPos;

                                                                        
                                            
                                                                             
                                                                        
                                                                           
                                            
  template <typename CallbackFunction>
  static void forEachProperty(
      Handle<HiddenClass> selfHandle,
      Runtime &runtime,
      const CallbackFunction &callback);

                                                                               
                                                                         
                                                                             
                                                              
  static void forEachPropertyNoAlloc(
      HiddenClass *self,
      PointerBase &base,
      std::function<void(SymbolID, NamedPropertyDescriptor)> callback);

                                                                            
                                
                                                                           
                                            
                                                                   
  template <typename CallbackFunction>
  static bool forEachPropertyWhile(
      Handle<HiddenClass> selfHandle,
      Runtime &runtime,
      const CallbackFunction &callback);

                                                                               
                                                                          
                                                                                
                                                                            
                                               
                                                       
  static OptValue<PropertyPos> findProperty(
      PseudoHandle<HiddenClass> self,
      Runtime &runtime,
      SymbolID name,
      PropertyFlags expectedFlags,
      NamedPropertyDescriptor &desc);

                                                                         
                                                                               
                                           
  static llvh::Optional<NamedPropertyDescriptor>
  findPropertyNoAlloc(HiddenClass *self, PointerBase &base, SymbolID name);

                                                                             
                                                                          
                                                                                
                                                                              
                   
  static OptValue<bool> tryFindPropertyFast(
      const HiddenClass *self,
      PointerBase &base,
      SymbolID name,
      NamedPropertyDescriptor &desc);

                                                                                
                                                                             
                                                     
                                                               
  static bool
  debugIsPropertyDefined(HiddenClass *self, PointerBase &base, SymbolID name);

                                                                     
                                      
  static Handle<HiddenClass> deleteProperty(
      Handle<HiddenClass> selfHandle,
      Runtime &runtime,
      PropertyPos pos);

                                                    
                                                                        
  static CallResult<std::pair<Handle<HiddenClass>, SlotIndex>> addProperty(
      Handle<HiddenClass> selfHandle,
      Runtime &runtime,
      SymbolID name,
      PropertyFlags propertyFlags);

                                                                         
                                                                       
  static Handle<HiddenClass> updateProperty(
      Handle<HiddenClass> selfHandle,
      Runtime &runtime,
      PropertyPos pos,
      PropertyFlags newFlags);

                                              
                                 
  static Handle<HiddenClass> makeAllNonConfigurable(
      Handle<HiddenClass> selfHandle,
      Runtime &runtime);

                                                               
                                 
  static Handle<HiddenClass> makeAllReadOnly(
      Handle<HiddenClass> selfHandle,
      Runtime &runtime);

                                                                      
                                                                               
                                                                              
                                                                              
                                            
                                                                           
            
                                                                            
                                                                            
                                                                                
                                           
                                         
  static Handle<HiddenClass> updatePropertyFlagsWithoutTransitions(
      Handle<HiddenClass> selfHandle,
      Runtime &runtime,
      PropertyFlags flagsToClear,
      PropertyFlags flagsToSet,
      OptValue<llvh::ArrayRef<SymbolID>> props);

                                                                                
                                                                     
                                                                       
                                                       
                                                                         
  static CallResult<std::pair<Handle<HiddenClass>, SlotIndex>> reserveSlot(
      Handle<HiddenClass> selfHandle,
      Runtime &runtime);

                                                         
  static bool areAllNonConfigurable(
      Handle<HiddenClass> selfHandle,
      Runtime &runtime);

                                                                          
  static bool areAllReadOnly(Handle<HiddenClass> selfHandle, Runtime &runtime);

  HiddenClass(
      Runtime &runtime,
      ClassFlags flags,
      Handle<HiddenClass> parent,
      SymbolID symbolID,
      PropertyFlags propertyFlags,
      unsigned numProperties)
      : symbolID_(symbolID),
        propertyFlags_(propertyFlags),
        flags_(flags),
        numProperties_(numProperties),
        parent_(runtime, *parent, runtime.getHeap()) {
    assert(propertyFlags.isValid() && "propertyFlags must be valid");
  }

 private:
                                                                        
  static CallResult<HermesValue> create(
      Runtime &runtime,
      ClassFlags flags,
      Handle<HiddenClass> parent,
      SymbolID symbolID,
      PropertyFlags propertyFlags,
      unsigned numProperties);

                                                                      
                                                                   
                                                            
                                                                 
                                                                      
                                                                     
                                                                   
                                                                   
                                                                     
                                     
  static Handle<HiddenClass> copyToNewDictionary(
      Handle<HiddenClass> selfHandle,
      Runtime &runtime,
      bool noCache = false);

                                                                              
                                  
  static ExecutionStatus addToPropertyMap(
      Handle<HiddenClass> selfHandle,
      Runtime &runtime,
      SymbolID name,
      NamedPropertyDescriptor desc);

                                                                              
                                  
  static void initializeMissingPropertyMap(
      Handle<HiddenClass> selfHandle,
      Runtime &runtime);

                                                                               
                                                                                
                                                                          
  static void stealPropertyMapFromParent(
      Handle<HiddenClass> selfHandle,
      Runtime &runtime);

                                                                   
  static void _finalizeImpl(GCCell *cell, GC &gc);

                                                                                
                                     
  static size_t _mallocSizeImpl(GCCell *cell);

#ifdef HERMES_MEMORY_INSTRUMENTATION
  static std::string _snapshotNameImpl(GCCell *cell, GC &gc);
  static void _snapshotAddEdgesImpl(GCCell *cell, GC &gc, HeapSnapshot &snap);
  static void _snapshotAddNodesImpl(GCCell *cell, GC &gc, HeapSnapshot &snap);
#endif

 private:
                                                                        
  const GCSymbolID symbolID_;
                                    
  const PropertyFlags propertyFlags_;

                                              
  ClassFlags flags_{};

                                                                            
                                                                              
                                                                    
                                                                            
               
  unsigned numProperties_;

                                                                           
                                                           
                                                               
                                                                                
                                                                       
     
                                                                         
  GCPointer<DictPropertyMap> propertyMap_{};

                                                                              
                                                                   
  detail::TransitionMap transitionMap_;

                                                                             
                                                                             
             
  GCPointer<HiddenClass> parent_;

                                                                          
                                    
  GCPointer<BigStorage> forInCache_{};

                                                                               
                                                                           
                                                       
                                                                              
                                                                             
                                                                    
  static ClassFlags
  computeFlags(ClassFlags flags, PropertyFlags pf, bool addedIndexLike);
};

                                                                                
                              

template <typename CallbackFunction>
void HiddenClass::forEachProperty(
    Handle<HiddenClass> selfHandle,
    Runtime &runtime,
    const CallbackFunction &callback) {
  if (LLVM_UNLIKELY(!selfHandle->propertyMap_))
    initializeMissingPropertyMap(selfHandle, runtime);

  return DictPropertyMap::forEachProperty(
      runtime.makeHandle(selfHandle->propertyMap_), runtime, callback);
}

template <typename CallbackFunction>
bool HiddenClass::forEachPropertyWhile(
    Handle<HiddenClass> selfHandle,
    Runtime &runtime,
    const CallbackFunction &callback) {
  if (LLVM_UNLIKELY(!selfHandle->propertyMap_))
    initializeMissingPropertyMap(selfHandle, runtime);

  return DictPropertyMap::forEachPropertyWhile(
      runtime.makeHandle(selfHandle->propertyMap_), runtime, callback);
}

inline OptValue<bool> HiddenClass::tryFindPropertyFast(
    const HiddenClass *self,
    PointerBase &base,
    SymbolID name,
    NamedPropertyDescriptor &desc) {
  if (LLVM_LIKELY(self->propertyMap_)) {
    auto found =
        DictPropertyMap::find(self->propertyMap_.getNonNull(base), name);
    if (LLVM_LIKELY(found)) {
      desc = DictPropertyMap::getDescriptorPair(
                 self->propertyMap_.getNonNull(base), *found)
                 ->second;
    }
    return found.hasValue();
  } else if (self->numProperties_ == 0) {
    return false;
  }
  return llvh::None;
}
inline ClassFlags HiddenClass::computeFlags(
    ClassFlags flags,
    PropertyFlags pf,
    bool addedIndexLike) {
  flags.hasIndexLikeProperties |= addedIndexLike;
                                                                                
                                                                         
  flags.mayHaveAccessor |= pf.accessor;
  return flags;
}

}                
}                    

                                                    
namespace llvh {

using namespace hermes::vm;

template <>
struct DenseMapInfo<HiddenClass::Transition> {
  static inline HiddenClass::Transition getEmptyKey() {
    return HiddenClass::Transition(SymbolID::empty());
  }

  static inline HiddenClass::Transition getTombstoneKey() {
    return HiddenClass::Transition(SymbolID::deleted());
  }

  static inline unsigned getHashValue(HiddenClass::Transition transition) {
    return transition.symbolID.unsafeGetRaw() ^ transition.propertyFlags._flags;
  }

  static inline bool isEqual(
      const HiddenClass::Transition &a,
      const HiddenClass::Transition &b) {
    return a == b;
  }
};

}                  

#endif                           

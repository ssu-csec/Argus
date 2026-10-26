/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_JSOBJECT_H
#define HERMES_VM_JSOBJECT_H

#include "hermes/VM/CallResult.h"
#include "hermes/VM/Handle.h"
#include "hermes/VM/HermesValue-inline.h"
#include "hermes/VM/HiddenClass.h"
#include "hermes/VM/Operations.h"
#include "hermes/VM/PropertyDescriptor.h"
#include "hermes/VM/SmallHermesValue-inline.h"
#include "hermes/VM/StringView.h"
#include "hermes/VM/TypesafeFlags.h"
#include "hermes/VM/VTable.h"

#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

union DefinePropertyFlags {
  struct {
    uint32_t enumerable : 1;
    uint32_t writable : 1;
    uint32_t configurable : 1;

    uint32_t setEnumerable : 1;
    uint32_t setWritable : 1;
    uint32_t setConfigurable : 1;
    uint32_t setGetter : 1;
    uint32_t setSetter : 1;
    uint32_t setValue : 1;
                                                                              
                                                                        
    uint32_t enableInternalSetter : 1;
  };

  uint32_t _flags;

                                      
  DefinePropertyFlags() {
    _flags = 0;
  }

                                          
  bool isEmpty() const {
    return _flags == 0;
  }

                     
  void clear() {
    _flags = 0;
  }

                                          
  bool isAccessor() const {
    return setGetter || setSetter;
  }

                                                                          
                                                                           
                         
  static DefinePropertyFlags getDefaultNewPropertyFlags() {
    DefinePropertyFlags dpf{};
    dpf.setEnumerable = 1;
    dpf.enumerable = 1;
    dpf.setWritable = 1;
    dpf.writable = 1;
    dpf.setConfigurable = 1;
    dpf.configurable = 1;
    dpf.setValue = 1;
    return dpf;
  }

                                                                          
                                                                              
                             
  static DefinePropertyFlags getNewNonEnumerableFlags() {
    DefinePropertyFlags dpf{};
    dpf.setEnumerable = 1;
    dpf.enumerable = 0;
    dpf.setWritable = 1;
    dpf.writable = 1;
    dpf.setConfigurable = 1;
    dpf.configurable = 1;
    dpf.setValue = 1;
    return dpf;
  }
};

                                    
struct ObjectFlags {
                                     
  uint32_t noExtend : 1;

                                                                              
                                                                                
  uint32_t sealed : 1;

                                                                                
                                                                                
                                          
  uint32_t frozen : 1;

                                                                               
                                                                            
  uint32_t indexedStorage : 1;

                                                                 
                                                                                
                         
  uint32_t fastIndexProperties : 1;

                                                                       
                                                                    
                 
  uint32_t hostObject : 1;

                                                                             
                                                                           
  uint32_t lazyObject : 1;

                                                       
  uint32_t proxyObject : 1;

  static constexpr unsigned kHashWidth = 24;
                                                                       
                                                                          
                                                             
  uint32_t objectID : kHashWidth;

  ObjectFlags() {
    ::memset(this, 0, sizeof(*this));
  }
};

static_assert(
    sizeof(ObjectFlags) == sizeof(uint32_t),
    "ObjectFlags must be a single word");

                     
      
                                                          
   
                      
                                                                       
                
                                     
                                               
                                                      
                                            
   
                   
                                                     
   
                       
                                                                              
      
#define HERMES_VM__LIST_PropOpFlags(FLAG) \
  FLAG(ThrowOnError)                      \
  FLAG(MustExist)                         \
  FLAG(InternalForce)

HERMES_VM__DECLARE_FLAGS_CLASS(PropOpFlags, HERMES_VM__LIST_PropOpFlags);

                      
      
                                                             
   
                        
                                                                             
            
   
                           
                                                                  
                                                                               
          
   
                              
                                                                              
                                                                            
                                       
   
                                                                 
                                                                    
                                      
      
#define HERMES_VM__LIST_OwnKeysFlags(FLAG) \
  FLAG(IncludeSymbols)                     \
  FLAG(IncludeNonSymbols)                  \
  FLAG(IncludeNonEnumerable)

HERMES_VM__DECLARE_FLAGS_CLASS(OwnKeysFlags, HERMES_VM__LIST_OwnKeysFlags);

                                                                              
                                                                       
                    

struct ObjectVTable : public VTable {
                                                                             
  std::pair<uint32_t, uint32_t> (
      *getOwnIndexedRange)(JSObject *self, Runtime &runtime);

                                                                              
                              
  bool (*haveOwnIndexed)(JSObject *self, Runtime &runtime, uint32_t index);

                                                                              
                                                                               
                                                                
                                                      
                                                   
  OptValue<PropertyFlags> (*getOwnIndexedPropertyFlags)(
      JSObject *self,
      Runtime &runtime,
      uint32_t index);

                                                                              
                                         
                                                                              
  HermesValue (*getOwnIndexed)(
      PseudoHandle<JSObject> self,
      Runtime &runtime,
      uint32_t index);

                                                                              
                                                                            
                                                                                
                                    
                                                                           
                                                                               
                                                       
                                                                               
                                                                              
                                                                            
                                                          
                                                                          
                                                      
  CallResult<bool> (*setOwnIndexed)(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      uint32_t index,
      Handle<> value);

                                                                             
                                                                              
                                                                             
                                
                                                                          
                                                                               
                                                                              
  bool (*deleteOwnIndexed)(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      uint32_t index);

                                                        
  enum class CheckAllOwnIndexedMode {
    NonConfigurable,
                                               
    ReadOnly,
  };

                                                                               
                                                                                
                                                 
  bool (*checkAllOwnIndexed)(
      JSObject *self,
      Runtime &runtime,
      CheckAllOwnIndexedMode mode);
};

                                                                                
                                                                             
                                                                         
                                                                     
   
                                                                             
                                                                        
                                                                           
                                                                              
             
   
                                                                              
                                                                              
                                                                           
                                                                               
                                                                              
                             
   
                                                                            
                                               
   
                                                                          
                                         
                                                                       
                                  
                                                  
   
                                                                               
                                                                            
                                                                      
                                         
   
                                                                       
                                                                             
                                                                       
                                                                       
              
class JSObject : public GCCell {
  friend void JSObjectBuildMeta(const GCCell *cell, Metadata::Builder &mb);

 public:
                                                                              
                                                                              
                    
  template <typename NeedsBarriers>
  JSObject(
      Runtime &runtime,
      JSObject *parent,
      HiddenClass *clazz,
      NeedsBarriers needsBarriers)
      : parent_(runtime, parent, runtime.getHeap(), needsBarriers),
        clazz_(runtime, clazz, runtime.getHeap(), needsBarriers),
        propStorage_(nullptr) {
                                                                      
  }

  template <typename NeedsBarriers>
  JSObject(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz,
      NeedsBarriers needsBarriers)
      : parent_(runtime, *parent, runtime.getHeap(), needsBarriers),
        clazz_(runtime, *clazz, runtime.getHeap(), needsBarriers),
        propStorage_(nullptr) {
                                                                      
  }

                                                                              
                                                                         
                                 
  JSObject(Runtime &runtime, JSObject *parent, HiddenClass *clazz)
      : JSObject(runtime, parent, clazz, GCPointerBase::NoBarriers()) {
                                                                      
  }

 public:
                                                                   
                                                                     
                                                               
                                                                      
                              
  struct Helper;

  static const ObjectVTable vt;

                                                    
  static constexpr PropStorage::size_type DEFAULT_PROPERTY_CAPACITY = 4;

                                                                         
                                                                               
                                                                            
  static constexpr PropStorage::size_type NAMED_PROPERTY_SLOTS = 0;

                                                                    
  static constexpr PropStorage::size_type DIRECT_PROPERTY_SLOTS = 5;

  static constexpr CellKind getCellKind() {
    return CellKind::JSObjectKind;
  }
  static bool classof(const GCCell *cell) {
    return kindInRange(
        cell->getKind(), CellKind::ObjectKind_first, CellKind::ObjectKind_last);
  }

                                                               
                                                  
  static PseudoHandle<JSObject> create(
      Runtime &runtime,
      Handle<JSObject> parentHandle);

                                                                         
                                                  
  static PseudoHandle<JSObject> create(Runtime &runtime);

                                                                            
                                                                            
          
                                                                         
  static PseudoHandle<JSObject> create(
      Runtime &runtime,
      unsigned propertyCount);

                                                                           
                                                           
          
                                                       
  static PseudoHandle<JSObject> create(
      Runtime &runtime,
      Handle<HiddenClass> clazz);

                                                                     
                                                  
  static PseudoHandle<JSObject> create(
      Runtime &runtime,
      Handle<JSObject> parentHandle,
      Handle<HiddenClass> clazz);

  ~JSObject() = default;

                                                                        
                                                                      
                                                                  
                            
                                             
  template <typename T>
  static inline T *initDirectPropStorage(Runtime &runtime, T *self);

                                            
  bool isExtensible() const {
    return !flags_.noExtend;
  }

                                                                       
  bool isLazy() const {
    return flags_.lazyObject;
  }

                                           
  bool isHostObject() const {
    return flags_.hostObject;
  }

                                                    
  bool isProxyObject() const {
    return flags_.proxyObject;
  }

                                                                               
                                                             
  bool hasFastIndexProperties() const {
    return flags_.fastIndexProperties;
  }

                                                                      
  JSObject *getParent(Runtime &runtime) const {
    return parent_.get(runtime);
  }

                                              
  HiddenClass *getClass(PointerBase &base) const {
    return clazz_.getNonNull(base);
  }

                                              
  const GCPointer<HiddenClass> &getClassGCPtr() const {
    return clazz_;
  }

                                                                             
                                                                           
                                                                             
                                                                            
                              
  static ObjectID getObjectID(JSObject *self, Runtime &runtime);

  static void initializeLazyObject(
      Runtime &runtime,
      Handle<JSObject> lazyObject);

                                                                      
                    
  ObjectID getAlreadyAssignedObjectID() const {
    assert(flags_.objectID && "ObjectID hasn't been assigned yet");
    return flags_.objectID;
  }

                                                                            
                                          
  inline bool shouldCacheForIn(Runtime &runtime) const;

                                                                           
                             
                                                 
                                            
                                              
                                                                               
                                                                           
                                                                      
                                                              
  static CallResult<bool> setParent(
      JSObject *self,
      Runtime &runtime,
      JSObject *parent,
      PropOpFlags opFlags = PropOpFlags());

                                                                              
                                                                        
  static SmallHermesValue
  getInternalProperty(JSObject *self, PointerBase &base, SlotIndex index) {
    assert(
        HiddenClass::debugIsPropertyDefined(
            self->clazz_.get(base),
            base,
            InternalProperty::getSymbolID(index)) &&
        "internal slot must be reserved");
    return getNamedSlotValueUnsafe<PropStorage::Inline::Yes>(self, base, index);
  }

  static void setInternalProperty(
      JSObject *self,
      Runtime &runtime,
      SlotIndex index,
      SmallHermesValue value) {
    assert(
        HiddenClass::debugIsPropertyDefined(
            self->clazz_.get(runtime),
            runtime,
            InternalProperty::getSymbolID(index)) &&
        "internal slot must be reserved");
    return setNamedSlotValueUnsafe<PropStorage::Inline::Yes>(
        self, runtime, index, value);
  }

                                                              
                                                                 
                                                                    
                                                     
  static CallResult<PseudoHandle<JSObject>> getPrototypeOf(
      PseudoHandle<JSObject> selfHandle,
      Runtime &runtime);

                                                                         
                                                                             
                                                                            
                                                                             
                                                                        
                                                                     
                                
                                              
  static CallResult<Handle<JSArray>> getOwnPropertyKeys(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      OwnKeysFlags okFlags);

                                                                                
                                                                       
                                                                               
                                                                   
                                                                       
                 
                                              
  static CallResult<Handle<JSArray>> getOwnPropertyNames(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      bool onlyEnumerable) {
    return getOwnPropertyKeys(
        selfHandle,
        runtime,
        OwnKeysFlags().plusIncludeNonSymbols().setIncludeNonEnumerable(
            !onlyEnumerable));
  }

                                                                      
                                                               
                                                
  static CallResult<Handle<JSArray>> getOwnPropertySymbols(
      Handle<JSObject> selfHandle,
      Runtime &runtime) {
    return getOwnPropertyKeys(
        selfHandle,
        runtime,
        OwnKeysFlags().plusIncludeSymbols().plusIncludeNonEnumerable());
  }

                                                                      
                                         
  template <SlotIndex index>
  inline static SmallHermesValue getDirectSlotValue(const JSObject *self);

                                                                     
                                         
  template <SlotIndex index>
  inline static void
  setDirectSlotValue(JSObject *self, SmallHermesValue value, GC &gc);

                                                                    
                                                     
                                            
  template <PropStorage::Inline inl = PropStorage::Inline::No>
  inline static SmallHermesValue getNamedSlotValueUnsafe(
      JSObject *self,
      PointerBase &runtime,
      SlotIndex index);

                                                                                
                                      
                                                                              
                                                                       
                        
  static SmallHermesValue getNamedSlotValueUnsafe(
      JSObject *self,
      PointerBase &runtime,
      NamedPropertyDescriptor desc) {
    assert(
        !self->flags_.proxyObject && !desc.flags.proxyObject &&
        "getNamedSlotValueUnsafe called on a Proxy");
    assert(
        !desc.flags.hostObject &&
        "getNamedSlotValueUnsafe called on a HostObject");
    return getNamedSlotValueUnsafe(self, runtime, desc.slot);
  }

                                                                                
                                      
  static inline CallResult<PseudoHandle<>> getNamedSlotValue(
      PseudoHandle<JSObject> self,
      Runtime &runtime,
      NamedPropertyDescriptor desc);

                                                                                
                                      
  static inline CallResult<PseudoHandle<>> getNamedSlotValue(
      Handle<JSObject> self,
      Runtime &runtime,
      NamedPropertyDescriptor desc);

                                                                               
                                      
                                                         
  static inline CallResult<bool> setNamedSlotValue(
      PseudoHandle<JSObject> self,
      Runtime &runtime,
      NamedPropertyDescriptor desc,
      PseudoHandle<> value);

                                                                   
                                                     
                                            
  template <PropStorage::Inline inl = PropStorage::Inline::No>
  static void setNamedSlotValueUnsafe(
      JSObject *self,
      Runtime &runtime,
      SlotIndex index,
      SmallHermesValue value);

                                                                               
              
  static void setNamedSlotValueUnsafe(
      JSObject *self,
      Runtime &runtime,
      NamedPropertyDescriptor desc,
      SmallHermesValue value) {
    assert(!desc.flags.proxyObject && "setNamedSlotValue called on a Proxy");
    assert(
        !desc.flags.hostObject && "setNamedSlotValue called on a HostObject");
    setNamedSlotValueUnsafe(self, runtime, desc.slot, value);
  }

                                                                       
                                                                       
                                                               
                                                                   
                                                                         
                                            
                                          
  static CallResult<PseudoHandle<>> getNamedPropertyValue_RJS(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<JSObject> propObj,
      NamedPropertyDescriptor desc);

                                                                          
                                                                       
                                                                       
                                     
  static CallResult<PseudoHandle<>> getComputedSlotValue(
      PseudoHandle<JSObject> self,
      Runtime &runtime,
      MutableHandle<SymbolID> &tmpSymbolStorage,
      ComputedPropertyDescriptor desc);

                                                                          
                                                                       
                                                                       
                                     
                                                             
  static HermesValue getComputedSlotValueUnsafe(
      PseudoHandle<JSObject> self,
      Runtime &runtime,
      ComputedPropertyDescriptor desc);

                                                                          
                                                                       
                                                                       
                                                                            
               
  LLVM_NODISCARD static CallResult<bool> setComputedSlotValue(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      MutableHandle<SymbolID> &tmpSymbolStorage,
      ComputedPropertyDescriptor desc,
      Handle<> value);

                                                                          
                                                                       
                                                                       
                                                                            
               
                                                             
  LLVM_NODISCARD static ExecutionStatus setComputedSlotValueUnsafe(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      ComputedPropertyDescriptor desc,
      Handle<> value);

                                                                          
                                                                       
                                                                  
                                          
                                                                   
                                                                         
                                            
                                          
                                                             
  static CallResult<PseudoHandle<>> getComputedPropertyValueInternal_RJS(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<JSObject> propObj,
      ComputedPropertyDescriptor desc);

                                                                     
                                                                     
                                                                  
                                                                   
                                                                      
                                                                   
                                                
  static CallResult<PseudoHandle<>> getComputedPropertyValue_RJS(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<JSObject> propObj,
      MutableHandle<SymbolID> &tmpSymbolStorage,
      ComputedPropertyDescriptor desc,
      Handle<> nameValHandle);

                   
                                                                    
                                                      
  static bool getOwnNamedDescriptor(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      NamedPropertyDescriptor &desc);

                   
                                                                          
                                                                            
                                                            
                                           
                                                                              
                               
  static OptValue<bool> tryGetOwnNamedDescriptorFast(
      JSObject *self,
      Runtime &runtime,
      SymbolID name,
      NamedPropertyDescriptor &desc);

                                                                               
                      
                                                                              
                                                                                
                    
  static OptValue<SmallHermesValue>
  tryGetNamedNoAlloc(JSObject *self, PointerBase &base, SymbolID name);

                                                    
  enum class IgnoreProxy { No, Yes };

                   
                                                                            
                                                                     
                                                                              
                                                                        
                                                                              
                                                                             
                                               
  static CallResult<bool> getOwnComputedPrimitiveDescriptor(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<> nameValHandle,
      IgnoreProxy ignoreProxy,
      MutableHandle<SymbolID> &tmpSymbolStorage,
      ComputedPropertyDescriptor &desc);

                                                                             
                                                                   
                                                                             
                                                                           
                                                                               
                                                                          
                                               
  static CallResult<bool> getOwnComputedDescriptor(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<> nameValHandle,
      MutableHandle<SymbolID> &tmpSymbolStorage,
      ComputedPropertyDescriptor &desc);

                                                                               
                                                      
  static CallResult<bool> getOwnComputedDescriptor(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<> nameValHandle,
      MutableHandle<SymbolID> &tmpSymbolStorage,
      ComputedPropertyDescriptor &desc,
      MutableHandle<> &valueOrAccessor);

                   
                                                                   
                                                  
                                                                      
  static JSObject *getNamedDescriptorPredefined(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Predefined::Str name,
      NamedPropertyDescriptor &desc);

                   
                                                                 
                                                  
                                                                      
  static JSObject *getNamedDescriptorPredefined(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Predefined::Sym name,
      NamedPropertyDescriptor &desc);

                   
                                                                             
                                   
                                                                               
                                                                             
                                                    
                                                                              
                                                                            
                                                                             
                                                                      
  static JSObject *getNamedDescriptorUnsafe(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      PropertyFlags expectedFlags,
      NamedPropertyDescriptor &desc);

                   
                                                                         
                  
  static JSObject *getNamedDescriptorUnsafe(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      NamedPropertyDescriptor &desc);

                   
                                                                             
                                   
                                                                            
                                                                          
                                                                        
                                                                                
                                                                       
                                                                        
                                                                           
                                                                     
                   
  static ExecutionStatus getComputedPrimitiveDescriptor(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<> nameValHandle,
      MutableHandle<JSObject> &propObj,
      MutableHandle<SymbolID> &tmpSymbolStorage,
      ComputedPropertyDescriptor &desc);

                                                                    
                                                                      
                                                                          
                                               
                                                                                
                        
                                                    
                                                                          
                                                                        
                                                                                
                                                                       
                                                                              
                                                                             
                                                
                                                                     
                   
  static ExecutionStatus getComputedDescriptor(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<> nameValHandle,
      MutableHandle<JSObject> &propObj,
      MutableHandle<SymbolID> &tmpSymbolStorage,
      ComputedPropertyDescriptor &desc);

                                                         
                                                                               
                                                                 
                                                                           
                                         
  static CallResult<PseudoHandle<>> getNamed_RJS(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      PropOpFlags opFlags = PropOpFlags(),
      PropertyCacheEntry *cacheEntry = nullptr);

                                                             
                                                                      
                                                                  
                                                                      
                                                                    
                                                                
  static CallResult<PseudoHandle<>> getNamedWithReceiver_RJS(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      Handle<> receiver,
      PropOpFlags opFlags = PropOpFlags(),
      PropertyCacheEntry *cacheEntry = nullptr);

                                                                        
                
  static CallResult<PseudoHandle<>> getNamedOrIndexed(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      PropOpFlags opFlags = PropOpFlags());

                                                                                
                                      
  static CallResult<PseudoHandle<>> getComputed_RJS(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<> nameValHandle);

                                                                      
                     
  static CallResult<PseudoHandle<>> getComputedWithReceiver_RJS(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<> nameValHandle,
      Handle<> receiver);

                                                        
                                                                        
                                                                        
                 
  static CallResult<bool>
  hasNamed(Handle<JSObject> selfHandle, Runtime &runtime, SymbolID name);

                                                                               
                    
  static CallResult<bool> hasNamedOrIndexed(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name);

                                                                         
  static CallResult<bool> hasComputed(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<> nameValHandle);

                                                        
                                                                               
                                                                 
  static CallResult<bool> putNamed_RJS(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      Handle<> valueHandle,
      PropOpFlags opFlags = PropOpFlags());

                                        
  static CallResult<bool> putNamedWithReceiver_RJS(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      Handle<> valueHandle,
      Handle<> receiver,
      PropOpFlags opFlags = PropOpFlags());

                                                                                
  static CallResult<bool> putNamedOrIndexed(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      Handle<> valueHandle,
      PropOpFlags opFlags = PropOpFlags());

                                                               
  static CallResult<bool> putComputed_RJS(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<> nameValHandle,
      Handle<> valueHandle,
      PropOpFlags opFlags = PropOpFlags());

                                                                           
           
  static CallResult<bool> putComputedWithReceiver_RJS(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<> nameValHandle,
      Handle<> valueHandle,
      Handle<> receiver,
      PropOpFlags opFlags = PropOpFlags());

                   
  static CallResult<bool> deleteNamed(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      PropOpFlags opFlags = PropOpFlags());
                   
  static CallResult<bool> deleteComputed(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<> nameValHandle,
      PropOpFlags opFlags = PropOpFlags());

                                        
  static HermesValue
  getOwnIndexed(PseudoHandle<JSObject> self, Runtime &runtime, uint32_t index) {
    const auto *vtable = self->getVT();
    return vtable->getOwnIndexed(std::move(self), runtime, index);
  }

                                        
  static CallResult<bool> setOwnIndexed(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      uint32_t index,
      Handle<> value) {
    return selfHandle->getVT()->setOwnIndexed(
        selfHandle, runtime, index, value);
  }

                                           
  static bool deleteOwnIndexed(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      uint32_t index) {
    return selfHandle->getVT()->deleteOwnIndexed(selfHandle, runtime, index);
  }

                                             
  static bool checkAllOwnIndexed(
      JSObject *self,
      Runtime &runtime,
      ObjectVTable::CheckAllOwnIndexedMode mode) {
    return self->getVT()->checkAllOwnIndexed(self, runtime, mode);
  }

                                                                         
                                
                                                                             
                                                                           
                                                                     
                                                                              
                                                                     
                                                                   
                                                                            
                                                                    
                                                         
                                                                
                                                               
                                                                              
                                                          
  static CallResult<bool> defineOwnProperty(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      DefinePropertyFlags dpFlags,
      Handle<> valueOrAccessor,
      PropOpFlags opFlags = PropOpFlags()) {
#ifdef HERMES_SLOW_DEBUG
                                                                              
                                                              
    auto nameView = runtime.getIdentifierTable().getStringView(runtime, name);
    assert(
        !toArrayIndex(nameView) &&
        "Array index property should use defineOwnComputed instead");
#endif
    return defineOwnPropertyInternal(
        selfHandle, runtime, name, dpFlags, valueOrAccessor, opFlags);
  }

                                                                               
                                                                            
  static CallResult<bool> defineOwnPropertyInternal(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      DefinePropertyFlags dpFlags,
      Handle<> valueOrAccessor,
      PropOpFlags opFlags = PropOpFlags());

                                                                         
                                                                               
                                                                            
                                                                     
                                                                              
                                                                               
     
                                                                              
                                                                              
                                                                        
                      
                                                                             
                                                                                
     
                                                                            
                                                  
                                                           
  LLVM_NODISCARD static ExecutionStatus defineNewOwnProperty(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      PropertyFlags propertyFlags,
      Handle<> valueOrAccessor);

                   
                                                                            
  static CallResult<bool> defineOwnComputedPrimitive(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<> nameValHandle,
      DefinePropertyFlags dpFlags,
      Handle<> valueOrAccessor,
      PropOpFlags opFlags = PropOpFlags());

                   
                                                                              
                
                                                                          
                                                                             
           
  static CallResult<bool> defineOwnComputed(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      Handle<> nameValHandle,
      DefinePropertyFlags dpFlags,
      Handle<> valueOrAccessor,
      PropOpFlags opFlags = PropOpFlags());

                     
                                               
                                  
  static ExecutionStatus seal(Handle<JSObject> selfHandle, Runtime &runtime);
                     
                                               
                                                                
                                  
  static ExecutionStatus freeze(Handle<JSObject> selfHandle, Runtime &runtime);
                      
                                                                               
                      
  static void preventExtensions(JSObject *self);
                                                                    
                                                                   
                                                                
                                       
  static CallResult<bool> preventExtensions(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      PropOpFlags opFlags = PropOpFlags());

                                                
                                                                        
  static CallResult<bool> isExtensible(
      PseudoHandle<JSObject> self,
      Runtime &runtime);
                      
                                     
                              
  static bool isSealed(PseudoHandle<JSObject> self, Runtime &runtime);
                      
                                     
                                                      
                              
  static bool isFrozen(PseudoHandle<JSObject> self, Runtime &runtime);

                                                                      
                                                                       
                                      
                                                                            
                                                                             
                                                                        
                                                                           
            
                                                                    
                                                                         
                                                                               
                            
  static void updatePropertyFlagsWithoutTransitions(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      PropertyFlags flagsToClear,
      PropertyFlags flagsToSet,
      OptValue<llvh::ArrayRef<SymbolID>> props);

                                                                          
                                                                                
                                                                     
                 
                                                                         
     
                                                                              
                                                                        
     
                                                                           
                                            
                                                                   
  template <typename IndexedCB, typename NamedCB>
  static bool forEachOwnPropertyWhile(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      const IndexedCB &indexedCB,
      const NamedCB &namedCB);

#ifdef HERMES_MEMORY_INSTRUMENTATION
                                                                            
                                                                            
                                                           
  std::string getHeuristicTypeName(GC &gc);
#endif

                                                                             
                                      
  std::string getNameIfExists(PointerBase &base);

 protected:
                                            
        

#ifdef HERMES_MEMORY_INSTRUMENTATION
                                                                          
                
  static std::string _snapshotNameImpl(GCCell *cell, GC &gc);

                                                    
  static void _snapshotAddEdgesImpl(GCCell *cell, GC &gc, HeapSnapshot &snap);

                                                                               
  static void
  _snapshotAddLocationsImpl(GCCell *cell, GC &gc, HeapSnapshot &snap);
#endif

                                                                             
  static std::pair<uint32_t, uint32_t> _getOwnIndexedRangeImpl(
      JSObject *self,
      Runtime &runtime);

                                                                              
                              
  static bool
  _haveOwnIndexedImpl(JSObject *self, Runtime &runtime, uint32_t index);

                                                                              
                                                                               
                        
                                                   
  static OptValue<PropertyFlags> _getOwnIndexedPropertyFlagsImpl(
      JSObject *self,
      Runtime &runtime,
      uint32_t index);

                                                                              
                                         
                                                                              
  static HermesValue _getOwnIndexedImpl(
      PseudoHandle<JSObject> self,
      Runtime &runtime,
      uint32_t index);

                                                                              
                                                                            
                                                                                
                                    
                                                                      
  static CallResult<bool> _setOwnIndexedImpl(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      uint32_t index,
      Handle<> value);

                                                 
                                                                          
                                                                               
                                               
  static bool _deleteOwnIndexedImpl(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      uint32_t index);

                                                                               
                                                                                
                                                 
  static bool _checkAllOwnIndexedImpl(
      JSObject *self,
      Runtime &runtime,
      ObjectVTable::CheckAllOwnIndexedMode mode);

                                                                       
  static inline ExecutionStatus allocatePropStorage(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      PropStorage::size_type size);

                                                                       
                                                                            
                                                                           
                            
  static inline CallResult<PseudoHandle<JSObject>> allocatePropStorage(
      PseudoHandle<JSObject> self,
      Runtime &runtime,
      PropStorage::size_type size);

        

 private:
                 

  const ObjectVTable *getVT() const {
    return static_cast<const ObjectVTable *>(GCCell::getVT());
  }

                                                                          
                                    
                                                                             
                                             
  static void allocateNewSlotStorage(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SlotIndex newSlotIndex,
      Handle<> valueHandle);

                                                                              
                                
                                                                              
                                                                            
                                                                             
  static OptValue<HiddenClass::PropertyPos> findProperty(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      PropertyFlags expectedFlags,
      NamedPropertyDescriptor &desc);

                                                                              
                                
  static OptValue<HiddenClass::PropertyPos> findProperty(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      NamedPropertyDescriptor &desc);

                   
  static CallResult<bool> addOwnProperty(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      DefinePropertyFlags dpFlags,
      Handle<> valueOrAccessor,
      PropOpFlags opFlags);
                                                                        
  static ExecutionStatus addOwnPropertyImpl(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      PropertyFlags propertyFlags,
      Handle<> valueOrAccessor);

                   
  static CallResult<bool> updateOwnProperty(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      HiddenClass::PropertyPos propertyPos,
      NamedPropertyDescriptor desc,
      DefinePropertyFlags dpFlags,
      Handle<> valueOrAccessor,
      PropOpFlags opFlags);

                                           
  enum class PropertyUpdateStatus {
                                       
    failed,
                                                                             
    done,
                                                                             
                                            
    needSet
  };

                                                                   
                                                                             
                                                                                
                                                                                
                                                                  
     
                                                     
                                                                  
                                                                          
                         
                                                                            
                                                                                
                         
                                                                               
                                                        
  static CallResult<std::pair<PropertyUpdateStatus, PropertyFlags>>
  checkPropertyUpdate(
      Runtime &runtime,
      PropertyFlags currentFlags,
      DefinePropertyFlags dpFlags,
      HermesValue curValueOrAccessor,
      Handle<> valueOrAccessor,
      PropOpFlags opFlags);

                                             
  static std::pair<uint32_t, uint32_t> getOwnIndexedRange(
      JSObject *self,
      Runtime &runtime);

                                         
  static bool haveOwnIndexed(JSObject *self, Runtime &runtime, uint32_t index);

                                                     
  static OptValue<PropertyFlags>
  getOwnIndexedPropertyFlags(JSObject *self, Runtime &runtime, uint32_t index);

                                                                            
                                                                           
                                                                                
                                                
                                                                            
  static CallResult<bool> internalSetter(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      SymbolID name,
      NamedPropertyDescriptor desc,
      Handle<> value,
      PropOpFlags opFlags);

 protected:
                                        
  ObjectFlags flags_{};

                                   
  GCPointer<JSObject> parent_;

                                                                             
            
  GCPointer<HiddenClass> clazz_{};

                                  
  GCPointer<PropStorage> propStorage_{};

                                        
  inline GCSmallHermesValue *directProps();
  inline const GCSmallHermesValue *directProps() const;

 private:
                                                                  
  static inline constexpr size_t directPropsOffset();

                                                                             
                             
  static inline constexpr size_t cellSizeJSObject();

 public:
                                                          
  template <class C>
  static constexpr uint32_t cellSizeImpl() {
    static_assert(
        std::is_convertible<C *, JSObject *>::value, "must be a JSObject");
    return sizeof(C) < cellSizeJSObject() ? cellSizeJSObject() : sizeof(C);
  }

                                                                             
                                      
     
                                                                   
                          
                                             
                                             
  template <typename Derived>
  static constexpr unsigned numOverlapSlots() {
    static_assert(
        std::is_convertible<Derived *, JSObject *>::value, "must be subclass");
    auto aligned = llvh::alignTo<sizeof(GCSmallHermesValue)>(sizeof(Derived));
    auto excess = (aligned - directPropsOffset()) / sizeof(GCSmallHermesValue);
    return std::min<size_t>(excess, DIRECT_PROPERTY_SLOTS);
  }
};

                                                                            
class JSObjectAndDirectProps : public JSObject {
 public:
  GCSmallHermesValue directProps_[DIRECT_PROPERTY_SLOTS];
};

GCSmallHermesValue *JSObject::directProps() {
  return static_cast<JSObjectAndDirectProps *>(this)->directProps_;
}

const GCSmallHermesValue *JSObject::directProps() const {
  return static_cast<const JSObjectAndDirectProps *>(this)->directProps_;
}

constexpr size_t JSObject::directPropsOffset() {
  return llvh::alignTo<alignof(GCSmallHermesValue)>(sizeof(JSObject));
}

constexpr size_t JSObject::cellSizeJSObject() {
  static_assert(
      sizeof(JSObjectAndDirectProps) ==
          directPropsOffset() +
              sizeof(GCSmallHermesValue) * DIRECT_PROPERTY_SLOTS,
      "unexpected padding");
  static_assert(
      heapAlignSize(sizeof(JSObjectAndDirectProps)) ==
          sizeof(JSObjectAndDirectProps),
      "Wasted direct slot due to alignment");
  return sizeof(JSObjectAndDirectProps);
}

                                                                              
                                                                           
                                                       
                                                                          
                                                                              
CallResult<Handle<BigStorage>> getForInPropertyNames(
    Runtime &runtime,
    Handle<JSObject> obj,
    uint32_t &beginIndex,
    uint32_t &endIndex);

                                                                          
                                                                                
                                                                               
   
                                                             
                                                      
   
namespace JSObjectInit {
                                                                  
template <typename JSObjectType>
static Handle<JSObjectType> initToHandle(Runtime &runtime, JSObjectType *obj) {
                                             
  assert(JSObjectType::classof(obj) && "Mismatched CellKind");
  return runtime.makeHandle(JSObjectType::initDirectPropStorage(runtime, obj));
}

                                                                         
template <typename JSObjectType>
static PseudoHandle<JSObjectType> initToPseudoHandle(
    Runtime &runtime,
    JSObjectType *obj) {
  assert(JSObjectType::classof(obj) && "Mismatched CellKind");
  return createPseudoHandle(JSObjectType::initDirectPropStorage(runtime, obj));
}

                                                                           
template <typename JSObjectType>
static HermesValue initToHermesValue(Runtime &runtime, JSObjectType *obj) {
  assert(JSObjectType::classof(obj) && "Mismatched CellKind");
  return HermesValue::encodeObjectValue(
      JSObjectType::initDirectPropStorage(runtime, obj));
}
};                          

                                                                                
                         

template <typename IndexedCB, typename NamedCB>
bool JSObject::forEachOwnPropertyWhile(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    const IndexedCB &indexedCB,
    const NamedCB &namedCB) {
  auto range = getOwnIndexedRange(*selfHandle, runtime);
  GCScopeMarkerRAII gcMarker{runtime};
  for (auto i = range.first; i != range.second; ++i) {
    auto optPF = getOwnIndexedPropertyFlags(*selfHandle, runtime, i);
    if (!optPF)
      continue;
    ComputedPropertyDescriptor desc{*optPF, i};
    desc.flags.indexed = true;
    if (!indexedCB(runtime, i, desc))
      return false;
    gcMarker.flush();
  }

  return HiddenClass::forEachPropertyWhile(
      runtime.makeHandle(selfHandle->clazz_), runtime, namedCB);
}

inline ExecutionStatus JSObject::allocatePropStorage(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    PropStorage::size_type size) {
  if (LLVM_LIKELY(size <= DIRECT_PROPERTY_SLOTS))
    return ExecutionStatus::RETURNED;

  auto res = PropStorage::create(
      runtime, size - DIRECT_PROPERTY_SLOTS, size - DIRECT_PROPERTY_SLOTS);
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION))
    return ExecutionStatus::EXCEPTION;

  selfHandle->propStorage_.setNonNull(
      runtime, vmcast<PropStorage>(*res), runtime.getHeap());
  return ExecutionStatus::RETURNED;
}

inline CallResult<PseudoHandle<JSObject>> JSObject::allocatePropStorage(
    PseudoHandle<JSObject> self,
    Runtime &runtime,
    PropStorage::size_type size) {
  if (LLVM_LIKELY(size <= DIRECT_PROPERTY_SLOTS))
    return self;

  Handle<JSObject> selfHandle = runtime.makeHandle(std::move(self));
  if (LLVM_UNLIKELY(
          allocatePropStorage(selfHandle, runtime, size) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  return PseudoHandle<JSObject>{selfHandle};
}

template <typename T>
inline T *JSObject::initDirectPropStorage(Runtime &runtime, T *self) {
  constexpr auto count = numOverlapSlots<T>() + T::NAMED_PROPERTY_SLOTS;
  static_assert(
      count <= DIRECT_PROPERTY_SLOTS,
      "smallPropStorage size must fit in direct properties");
  GCSmallHermesValue::uninitialized_fill(
      self->directProps() + numOverlapSlots<T>(),
      self->directProps() + DIRECT_PROPERTY_SLOTS,
      SmallHermesValue::encodeUndefinedValue(),
      runtime.getHeap());
  return self;
}

template <SlotIndex index>
inline SmallHermesValue JSObject::getDirectSlotValue(const JSObject *self) {
  static_assert(index < DIRECT_PROPERTY_SLOTS, "Must be a direct property");
  return self->directProps()[index];
}

template <SlotIndex index>
inline void
JSObject::setDirectSlotValue(JSObject *self, SmallHermesValue value, GC &gc) {
  static_assert(index < DIRECT_PROPERTY_SLOTS, "Must be a direct property");
  self->directProps()[index].set(value, gc);
}

template <PropStorage::Inline inl>
inline SmallHermesValue JSObject::getNamedSlotValueUnsafe(
    JSObject *self,
    PointerBase &runtime,
    SlotIndex index) {
  assert(!self->flags_.proxyObject && "getNamedSlotValue called on a Proxy");

  if (LLVM_LIKELY(index < DIRECT_PROPERTY_SLOTS))
    return self->directProps()[index];

  return self->propStorage_.getNonNull(runtime)->at<inl>(
      index - DIRECT_PROPERTY_SLOTS);
}

inline CallResult<PseudoHandle<>> JSObject::getNamedSlotValue(
    PseudoHandle<JSObject> self,
    Runtime &runtime,
    NamedPropertyDescriptor desc) {
  if (LLVM_UNLIKELY(desc.flags.proxyObject) ||
      LLVM_UNLIKELY(desc.flags.hostObject)) {
    SymbolID name = SymbolID::unsafeCreate(desc.slot);
    assert(name.isValid() && "invalid SymbolID in descriptor");
    return getNamed_RJS(runtime.makeHandle(std::move(self)), runtime, name);
  }
  return createPseudoHandle(
      getNamedSlotValueUnsafe(self.get(), runtime, desc).unboxToHV(runtime));
}

inline CallResult<PseudoHandle<>> JSObject::getNamedSlotValue(
    Handle<JSObject> self,
    Runtime &runtime,
    NamedPropertyDescriptor desc) {
  if (LLVM_UNLIKELY(desc.flags.proxyObject) ||
      LLVM_UNLIKELY(desc.flags.hostObject)) {
    SymbolID name = SymbolID::unsafeCreate(desc.slot);
    assert(name.isValid() && "invalid SymbolID in descriptor");
    return getNamed_RJS(self, runtime, name);
  }
  return createPseudoHandle(
      getNamedSlotValueUnsafe(self.get(), runtime, desc).unboxToHV(runtime));
}

inline CallResult<bool> JSObject::setNamedSlotValue(
    PseudoHandle<JSObject> self,
    Runtime &runtime,
    NamedPropertyDescriptor desc,
    PseudoHandle<> value) {
  if (LLVM_UNLIKELY(desc.flags.proxyObject) ||
      LLVM_UNLIKELY(desc.flags.hostObject)) {
    SymbolID name = SymbolID::unsafeCreate(desc.slot);
    assert(name.isValid() && "invalid SymbolID in descriptor");
    return putNamed_RJS(
        runtime.makeHandle(std::move(self)),
        runtime,
        name,
        runtime.makeHandle(std::move(value)));
  }
  auto shv = SmallHermesValue::encodeHermesValue(value.get(), runtime);
  setNamedSlotValueUnsafe(self.get(), runtime, desc, shv);
  return true;
}

template <PropStorage::Inline inl>
inline void JSObject::setNamedSlotValueUnsafe(
    JSObject *self,
    Runtime &runtime,
    SlotIndex index,
    SmallHermesValue value) {
                                                                              
                                                                           
                         
  if (LLVM_LIKELY(index < DIRECT_PROPERTY_SLOTS))
    return self->directProps()[index].set(value, runtime.getHeap());

  self->propStorage_.getNonNull(runtime)->set<inl>(
      index - DIRECT_PROPERTY_SLOTS, value, runtime.getHeap());
}

inline CallResult<PseudoHandle<>> JSObject::getComputedSlotValue(
    PseudoHandle<JSObject> self,
    Runtime &runtime,
    MutableHandle<SymbolID> &tmpSymbolStorage,
    ComputedPropertyDescriptor desc) {
  if (LLVM_LIKELY(desc.flags.indexed)) {
    assert(
        self->flags_.indexedStorage &&
        "indexed flag set but no indexed storage");
    return createPseudoHandle(
        getOwnIndexed(std::move(self), runtime, desc.slot));
  }
  if (LLVM_UNLIKELY(desc.flags.proxyObject) ||
      LLVM_UNLIKELY(desc.flags.hostObject)) {
    SymbolID name = SymbolID::unsafeCreate(desc.slot);
    assert(name.isValid() && "invalid SymbolID in descriptor");
    return getComputed_RJS(
        runtime.makeHandle(std::move(self)),
        runtime,
        runtime.makeHandle(HermesValue::encodeSymbolValue(name)));
  }
  return createPseudoHandle(
      getNamedSlotValueUnsafe(
          self.get(), runtime, desc.castToNamedPropertyDescriptorRef())
          .unboxToHV(runtime));
}

inline HermesValue JSObject::getComputedSlotValueUnsafe(
    PseudoHandle<JSObject> self,
    Runtime &runtime,
    ComputedPropertyDescriptor desc) {
  if (LLVM_LIKELY(desc.flags.indexed)) {
    assert(
        self->flags_.indexedStorage &&
        "indexed flag set but no indexed storage");
    return getOwnIndexed(std::move(self), runtime, desc.slot);
  }
                                                                       
  return getNamedSlotValueUnsafe(
             self.get(), runtime, desc.castToNamedPropertyDescriptorRef())
      .unboxToHV(runtime);
}

inline CallResult<bool> JSObject::setComputedSlotValue(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    MutableHandle<SymbolID> &tmpSymbolStorage,
    ComputedPropertyDescriptor desc,
    Handle<> value) {
  if (LLVM_LIKELY(desc.flags.indexed)) {
    assert(
        selfHandle->flags_.indexedStorage &&
        "indexed flag set but no indexed storage");
    return setOwnIndexed(selfHandle, runtime, desc.slot, value);
  }
  if (LLVM_UNLIKELY(desc.flags.proxyObject) ||
      LLVM_UNLIKELY(desc.flags.hostObject)) {
    SymbolID name = SymbolID::unsafeCreate(desc.slot);
    assert(name.isValid() && "invalid SymbolID in descriptor");
    return putComputed_RJS(
        selfHandle,
        runtime,
        runtime.makeHandle(HermesValue::encodeSymbolValue(name)),
        value);
  }
  auto shv = SmallHermesValue::encodeHermesValue(value.get(), runtime);
  setNamedSlotValueUnsafe(
      selfHandle.get(), runtime, desc.castToNamedPropertyDescriptorRef(), shv);
  return true;
}

inline ExecutionStatus JSObject::setComputedSlotValueUnsafe(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    ComputedPropertyDescriptor desc,
    Handle<> value) {
  if (LLVM_LIKELY(desc.flags.indexed)) {
    assert(
        selfHandle->flags_.indexedStorage &&
        "indexed flag set but no indexed storage");
    return setOwnIndexed(selfHandle, runtime, desc.slot, value).getStatus();
  }
  auto shv = SmallHermesValue::encodeHermesValue(value.get(), runtime);
  setNamedSlotValueUnsafe(
      selfHandle.get(), runtime, desc.castToNamedPropertyDescriptorRef(), shv);
  return ExecutionStatus::RETURNED;
}

inline bool JSObject::getOwnNamedDescriptor(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    SymbolID name,
    NamedPropertyDescriptor &desc) {
  return findProperty(selfHandle, runtime, name, desc).hasValue();
}

inline OptValue<bool> JSObject::tryGetOwnNamedDescriptorFast(
    JSObject *self,
    Runtime &runtime,
    SymbolID name,
    NamedPropertyDescriptor &desc) {
  return HiddenClass::tryFindPropertyFast(
      self->clazz_.getNonNull(runtime), runtime, name, desc);
}

inline OptValue<SmallHermesValue>
JSObject::tryGetNamedNoAlloc(JSObject *self, PointerBase &base, SymbolID name) {
  for (JSObject *curr = self; curr; curr = curr->parent_.get(base)) {
    if (LLVM_UNLIKELY(curr->isProxyObject()) ||
        LLVM_UNLIKELY(curr->isHostObject())) {
                                                              
                                                                              
      return llvh::None;
    }
    auto found =
        HiddenClass::findPropertyNoAlloc(curr->getClass(base), base, name);
    if (found) {
      return getNamedSlotValueUnsafe(curr, base, found.getValue());
    }
  }
                                                                     
                 
  return llvh::None;
}

inline JSObject *JSObject::getNamedDescriptorPredefined(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    Predefined::Str name,
    NamedPropertyDescriptor &desc) {
  return getNamedDescriptorUnsafe(
      selfHandle,
      runtime,
      Predefined::getSymbolID(name),
      PropertyFlags::invalid(),
      desc);
}

inline JSObject *JSObject::getNamedDescriptorPredefined(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    Predefined::Sym name,
    NamedPropertyDescriptor &desc) {
  return getNamedDescriptorUnsafe(
      selfHandle,
      runtime,
      Predefined::getSymbolID(name),
      PropertyFlags::invalid(),
      desc);
}

inline JSObject *JSObject::getNamedDescriptorUnsafe(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    SymbolID name,
    NamedPropertyDescriptor &desc) {
  return getNamedDescriptorUnsafe(
      selfHandle, runtime, name, PropertyFlags::invalid(), desc);
}

inline CallResult<PseudoHandle<>> JSObject::getNamed_RJS(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    SymbolID name,
    PropOpFlags opFlags,
    PropertyCacheEntry *cacheEntry) {
  return getNamedWithReceiver_RJS(
      selfHandle, runtime, name, selfHandle, opFlags, cacheEntry);
}

inline CallResult<PseudoHandle<>> JSObject::getComputed_RJS(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    Handle<> nameValHandle) {
  return getComputedWithReceiver_RJS(
      selfHandle, runtime, nameValHandle, selfHandle);
}

inline CallResult<bool> JSObject::putNamed_RJS(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    SymbolID name,
    Handle<> valueHandle,
    PropOpFlags opFlags) {
  return putNamedWithReceiver_RJS(
      selfHandle, runtime, name, valueHandle, selfHandle, opFlags);
}

inline CallResult<bool> JSObject::putComputed_RJS(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    Handle<> nameValHandle,
    Handle<> valueHandle,
    PropOpFlags opFlags) {
  return putComputedWithReceiver_RJS(
      selfHandle, runtime, nameValHandle, valueHandle, selfHandle, opFlags);
}

inline std::pair<uint32_t, uint32_t> JSObject::getOwnIndexedRange(
    JSObject *self,
    Runtime &runtime) {
  return self->getVT()->getOwnIndexedRange(self, runtime);
};

inline bool
JSObject::haveOwnIndexed(JSObject *self, Runtime &runtime, uint32_t index) {
  return self->getVT()->haveOwnIndexed(self, runtime, index);
}

inline OptValue<PropertyFlags> JSObject::getOwnIndexedPropertyFlags(
    JSObject *self,
    Runtime &runtime,
    uint32_t index) {
  return self->getVT()->getOwnIndexedPropertyFlags(self, runtime, index);
}

inline OptValue<HiddenClass::PropertyPos> JSObject::findProperty(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    SymbolID name,
    NamedPropertyDescriptor &desc) {
  return findProperty(
      selfHandle, runtime, name, PropertyFlags::invalid(), desc);
}

inline OptValue<HiddenClass::PropertyPos> JSObject::findProperty(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    SymbolID name,
    PropertyFlags expectedFlags,
    NamedPropertyDescriptor &desc) {
  auto ret = HiddenClass::findProperty(
      createPseudoHandle(selfHandle->clazz_.getNonNull(runtime)),
      runtime,
      name,
      expectedFlags,
      desc);
  assert(
      !(selfHandle->flags_.proxyObject && ret) &&
      "Proxy objects should never have own properties");
  return ret;
}

inline bool JSObject::shouldCacheForIn(Runtime &runtime) const {
  return !clazz_.getNonNull(runtime)->isDictionary() &&
      !flags_.indexedStorage && !flags_.hostObject && !flags_.proxyObject;
}

}                
}                    
#pragma GCC diagnostic pop

#endif                        

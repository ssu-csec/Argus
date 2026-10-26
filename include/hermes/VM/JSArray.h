/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_JSARRAY_H
#define HERMES_VM_JSARRAY_H

#include "hermes/VM/IterationKind.h"
#include "hermes/VM/JSObject.h"
#include "hermes/VM/SegmentedArray.h"

namespace hermes {
namespace vm {

                                                    
class ArrayImpl : public JSObject {
  using Super = JSObject;
  friend void ArrayImplBuildMeta(const GCCell *cell, Metadata::Builder &mb);

 public:
  static bool classof(const GCCell *cell) {
    return kindInRange(
        cell->getKind(),
        CellKind::ArrayImplKind_first,
        CellKind::ArrayImplKind_last);
  }

                              
        
  using size_type = uint32_t;
                                                                               
           
  using StorageType = SegmentedArraySmall;

                                                                             
                                                 
  static ExecutionStatus setStorageEndIndex(
      Handle<ArrayImpl> selfHandle,
      Runtime &runtime,
      uint32_t newLength);

                                                                           
                                                                            
                  
                                                                               
                                                                
  static void setElementAt(
      Handle<ArrayImpl> selfHandle,
      Runtime &runtime,
      size_type index,
      Handle<> value) {
    auto result = _setOwnIndexedImpl(selfHandle, runtime, index, value);
    (void)result;
    assert(
        result != ExecutionStatus::EXCEPTION && *result &&
        "JSArrayImpl::setElementAt() failing");
  }

                                                                               
                                                                              
                                                                        
                                                                                
  static void unsafeSetExistingElementAt(
      ArrayImpl *self,
      Runtime &runtime,
      size_type index,
      SmallHermesValue value) {
                                                                                
                                                                           
    assert(!self->flags_.noExtend && "this array cannot be extended");

    assert(
        index >= self->beginIndex_ && index < self->endIndex_ &&
        "array index out of range");
    self->getIndexedStorage(runtime)->set(
        runtime, index - self->beginIndex_, value);
  }

                                                                          
                                   
                                                                              
  static bool deleteElementAt(
      Handle<ArrayImpl> selfHandle,
      Runtime &runtime,
      size_type index) {
    return _deleteOwnIndexedImpl(selfHandle, runtime, index);
  }

                                           
  size_type getBeginIndex() const {
    return beginIndex_;
  }

                                                                         
  size_type getEndIndex() const {
    return endIndex_;
  }

                                                                         
                               
  const SmallHermesValue at(Runtime &runtime, size_type index) const {
    return index >= beginIndex_ && index < endIndex_
        ? getIndexedStorage(runtime)->at(runtime, index - beginIndex_)
        : SmallHermesValue::encodeEmptyValue();
  }

                                         
  Handle<> handleAt(Runtime &runtime, size_type index) const {
    return runtime.makeHandle(at(runtime, index).unboxToHV(runtime));
  }

                                                                             
                                                 
  StorageType *getIndexedStorage(PointerBase &base) const {
    return indexedStorage_.get(base);
  }

                                                                              
                 
  void setIndexedStorage(PointerBase &base, StorageType *p, GC &gc) {
    indexedStorage_.set(base, p, gc);
  }

        

 protected:
                                                         
                                                                               
                                                                           
                                                                            
                                                  
                                                                       
                                                                      
                                                                   
                                                        
  template <typename NeedsBarriers>
  ArrayImpl(
      Runtime &runtime,
      JSObject *parent,
      HiddenClass *clazz,
      NeedsBarriers needsBarriers)
      : JSObject(runtime, parent, clazz, needsBarriers) {
    flags_.indexedStorage = true;
    flags_.fastIndexProperties = true;
  }

                                   
  ArrayImpl(Runtime &runtime, JSObject *parent, HiddenClass *clazz)
      : ArrayImpl(runtime, parent, clazz, GCPointerBase::YesBarriers()) {}

#ifdef HERMES_MEMORY_INSTRUMENTATION
                                                                           
              
  static void _snapshotAddEdgesImpl(GCCell *cell, GC &gc, HeapSnapshot &snap);
#endif

                                                                              
                              
  static bool
  _haveOwnIndexedImpl(JSObject *selfObj, Runtime &runtime, uint32_t index);

                                                                              
                                                                               
                        
                                                   
  static OptValue<PropertyFlags> _getOwnIndexedPropertyFlagsImpl(
      JSObject *selfObj,
      Runtime &runtime,
      uint32_t index);

                                                                
  static std::pair<uint32_t, uint32_t> _getOwnIndexedRangeImpl(
      JSObject *selfObj,
      Runtime &runtime);

                                                                              
                                         
                                                                              
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
      JSObject *selfObj,
      Runtime &runtime,
      ObjectVTable::CheckAllOwnIndexedMode mode);

                                                              
  const SmallHermesValue unsafeAt(Runtime &runtime, size_type index) const {
    return getIndexedStorage(runtime)->at(runtime, index - beginIndex_);
  }

 private:
                                               
  uint32_t beginIndex_{0};
                                                       
  uint32_t endIndex_{0};
                                         
  GCPointer<StorageType> indexedStorage_;
};

class Arguments final : public ArrayImpl {
  using Super = ArrayImpl;

 public:
  static const ObjectVTable vt;

                                                      
  static const PropStorage::size_type NAMED_PROPERTY_SLOTS =
      Super::NAMED_PROPERTY_SLOTS + 1;

  static constexpr CellKind getCellKind() {
    return CellKind::ArgumentsKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::ArgumentsKind;
  }

                                                                                
                                                        
  static CallResult<Handle<Arguments>> create(
      Runtime &runtime,
      size_type length,
      Handle<Callable> curFunction,
      bool strictMode);

  Arguments(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz)
      : ArrayImpl(runtime, *parent, *clazz) {}
};

class JSArray final : public ArrayImpl {
  using Super = ArrayImpl;

                                               
  friend class JSObject;

  static constexpr SlotIndex jsArrayPropertyCount() {
    return numOverlapSlots<JSArray>() + NAMED_PROPERTY_SLOTS;
  }

  static constexpr inline SlotIndex lengthPropIndex() {
    return jsArrayPropertyCount() - 1;
  }

 public:
  static const ObjectVTable vt;

                                                      
  static const PropStorage::size_type NAMED_PROPERTY_SLOTS =
      Super::NAMED_PROPERTY_SLOTS + 1;

                                                                                
                
  static Handle<HiddenClass> createClass(
      Runtime &runtime,
      Handle<JSObject> prototypeHandle);

  static constexpr CellKind getCellKind() {
    return CellKind::JSArrayKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::JSArrayKind;
  }

  static uint32_t getLength(const JSArray *self, PointerBase &pb) {
    return getDirectSlotValue<lengthPropIndex()>(self).getNumber(pb);
  }

                                                                      
                                                                                
                                                                              
  static CallResult<Handle<JSArray>> createNoAllocPropStorage(
      Runtime &runtime,
      Handle<JSObject> prototypeHandle,
      Handle<HiddenClass> classHandle,
      size_type capacity = 0,
      size_type length = 0);

                                                                      
                                                                                
                                                                             
                                               
  static CallResult<Handle<JSArray>> createAndAllocPropStorage(
      Runtime &runtime,
      Handle<JSObject> prototypeHandle,
      Handle<HiddenClass> classHandle,
      size_type capacity = 0,
      size_type length = 0);

  static CallResult<Handle<JSArray>> create(
      Runtime &runtime,
      Handle<JSObject> prototypeHandle,
      size_type capacity,
      size_type length) {
    return createNoAllocPropStorage(
        runtime,
        prototypeHandle,
        *prototypeHandle == runtime.arrayPrototype.getObject()
            ? Handle<HiddenClass>::vmcast(&runtime.arrayClass)
            : createClass(runtime, prototypeHandle),
        capacity,
        length);
  }
  static CallResult<Handle<JSArray>> create(
      Runtime &runtime,
      Handle<JSObject> prototypeHandle) {
    return create(runtime, prototypeHandle, 0, 0);
  }

                                                                           
                                                                  
  static CallResult<Handle<JSArray>>
  create(Runtime &runtime, size_type capacity, size_type length);

                                                                            
                                                                              
                                                                          
                                                                    
  static CallResult<bool> setLengthProperty(
      Handle<JSArray> selfHandle,
      Runtime &runtime,
      uint32_t newValue,
      PropOpFlags opFlags = PropOpFlags{}) {
                                                                           
    return putNamed_RJS(
        selfHandle,
        runtime,
        Predefined::getSymbolID(Predefined::length),
        runtime.makeHandle(HermesValue::encodeTrustedNumberValue(newValue)));
  }

  template <typename NeedsBarrier>
  JSArray(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz,
      NeedsBarrier needsBarrier)
      : ArrayImpl(runtime, *parent, *clazz, needsBarrier) {}

 private:
                                                      
  static void
  putLength(JSArray *self, Runtime &runtime, SmallHermesValue newLength) {
    setDirectSlotValue<lengthPropIndex()>(self, newLength, runtime.getHeap());
  }

                                                                             
                                                                        
                                     
  static CallResult<bool> setLength(
      Handle<JSArray> selfHandle,
      Runtime &runtime,
      Handle<> newLength,
      PropOpFlags opFlags) LLVM_NO_SANITIZE("float-cast-overflow");

                                                                             
                                                                        
                                     
  static CallResult<bool> setLength(
      Handle<JSArray> selfHandle,
      Runtime &runtime,
      uint32_t newLength,
      PropOpFlags opFlags);
};

                                                                           
           
                 
class JSArrayIterator : public JSObject {
  using Super = JSObject;

  friend void JSArrayIteratorBuildMeta(
      const GCCell *cell,
      Metadata::Builder &mb);

 public:
  static const ObjectVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::JSArrayIteratorKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::JSArrayIteratorKind;
  }

  static PseudoHandle<JSArrayIterator>
  create(Runtime &runtime, Handle<JSObject> array, IterationKind iterationKind);

                                             
  static CallResult<HermesValue> nextElement(
      Handle<JSArrayIterator> self,
      Runtime &runtime);

 public:
  JSArrayIterator(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz,
      Handle<JSObject> iteratedObject,
      IterationKind iterationKind)
      : JSObject(runtime, *parent, *clazz),
        iteratedObject_(runtime, *iteratedObject, runtime.getHeap()),
        iterationKind_(iterationKind) {}

 private:
                        
                                                   
  GCPointer<JSObject> iteratedObject_;

                                
  uint64_t nextIndex_{0};

                            
  IterationKind iterationKind_;
};

}                
}                    

#endif                       

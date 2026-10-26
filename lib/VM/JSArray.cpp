/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/JSArray.h"

#include "hermes/VM/BuildMetadata.h"
#include "hermes/VM/Callable.h"
#include "hermes/VM/JSTypedArray.h"
#include "hermes/VM/Operations.h"
#include "hermes/VM/PropertyAccessor.h"

namespace hermes {
namespace vm {

                                                                                
                  

void ArrayImplBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  mb.addJSObjectOverlapSlots(JSObject::numOverlapSlots<ArrayImpl>());
  JSObjectBuildMeta(cell, mb);
  const auto *self = static_cast<const ArrayImpl *>(cell);
                                                                           
                                                                           
  mb.addField("elements", &self->indexedStorage_);
}

#ifdef HERMES_MEMORY_INSTRUMENTATION
void ArrayImpl::_snapshotAddEdgesImpl(
    GCCell *cell,
    GC &gc,
    HeapSnapshot &snap) {
  auto *const self = vmcast<ArrayImpl>(cell);
                                    
  JSObject::_snapshotAddEdgesImpl(self, gc, snap);
  if (!self->getIndexedStorage(gc.getPointerBase())) {
    return;
  }

                                                                           
                                                                           
  snap.addNamedEdge(
      HeapSnapshot::EdgeType::Internal,
      "elements",
      gc.getObjectID(self->getIndexedStorage(gc.getPointerBase())));
  auto *const indexedStorage = self->getIndexedStorage(gc.getPointerBase());
  const auto beginIndex = self->beginIndex_;
  const auto endIndex = self->endIndex_;
  for (uint32_t i = beginIndex; i < endIndex; i++) {
    const auto &elem = indexedStorage->at(gc.getPointerBase(), i - beginIndex);
    const llvh::Optional<HeapSnapshot::NodeID> elemID =
        gc.getSnapshotID(elem.toHV(gc.getPointerBase()));
    if (!elemID) {
      continue;
    }
    snap.addIndexedEdge(HeapSnapshot::EdgeType::Element, i, elemID.getValue());
  }
}
#endif

bool ArrayImpl::_haveOwnIndexedImpl(
    JSObject *selfObj,
    Runtime &runtime,
    uint32_t index) {
  auto *self = vmcast<ArrayImpl>(selfObj);

                                                   
  if (index >= self->beginIndex_ && index < self->endIndex_)
    return !self->getIndexedStorage(runtime)
                ->at(runtime, index - self->beginIndex_)
                .isEmpty();

  return false;
}

OptValue<PropertyFlags> ArrayImpl::_getOwnIndexedPropertyFlagsImpl(
    JSObject *selfObj,
    Runtime &runtime,
    uint32_t index) {
  auto *self = vmcast<ArrayImpl>(selfObj);

                                                   
  if (index >= self->beginIndex_ && index < self->endIndex_ &&
      !self->getIndexedStorage(runtime)
           ->at(runtime, index - self->beginIndex_)
           .isEmpty()) {
    PropertyFlags indexedElementFlags{};
    indexedElementFlags.enumerable = 1;
    indexedElementFlags.writable = 1;
    indexedElementFlags.configurable = 1;

    if (LLVM_UNLIKELY(self->flags_.sealed)) {
      indexedElementFlags.configurable = 0;
      if (LLVM_UNLIKELY(self->flags_.frozen))
        indexedElementFlags.writable = 0;
    }

    return indexedElementFlags;
  }

  return llvh::None;
}

std::pair<uint32_t, uint32_t> ArrayImpl::_getOwnIndexedRangeImpl(
    JSObject *selfObj,
    Runtime &runtime) {
  auto *self = vmcast<ArrayImpl>(selfObj);
  return {self->beginIndex_, self->endIndex_};
}

HermesValue ArrayImpl::_getOwnIndexedImpl(
    PseudoHandle<JSObject> selfObj,
    Runtime &runtime,
    uint32_t index) {
  NoAllocScope noAllocs{runtime};

  return vmcast<ArrayImpl>(selfObj.get())
      ->at(runtime, index)
      .unboxToHV(runtime);
}

ExecutionStatus ArrayImpl::setStorageEndIndex(
    Handle<ArrayImpl> selfHandle,
    Runtime &runtime,
    uint32_t newLength) {
  auto *self = selfHandle.get();

  if (LLVM_UNLIKELY(
          newLength > self->beginIndex_ &&
          newLength - self->beginIndex_ > StorageType::maxElements())) {
    return runtime.raiseRangeError("Out of memory for array elements");
  }

                                                  
  if (LLVM_UNLIKELY(!self->getIndexedStorage(runtime))) {
    if (newLength == 0) {
      return ExecutionStatus::RETURNED;
    }
    auto arrRes = StorageType::create(runtime, newLength, newLength);
    if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    auto newStorage = runtime.makeHandle<StorageType>(std::move(*arrRes));
    selfHandle->setIndexedStorage(runtime, newStorage.get(), runtime.getHeap());
    selfHandle->beginIndex_ = 0;
    selfHandle->endIndex_ = newLength;
    return ExecutionStatus::RETURNED;
  }

  auto beginIndex = self->beginIndex_;

  {
    NoAllocScope scope{runtime};
    auto *const indexedStorage = self->getIndexedStorage(runtime);

    if (newLength <= beginIndex) {
                                                                     
      selfHandle->endIndex_ = beginIndex;
                                                                              
      self->setIndexedStorage(runtime, nullptr, runtime.getHeap());
      return ExecutionStatus::RETURNED;
    } else if (newLength - beginIndex <= indexedStorage->capacity()) {
      selfHandle->endIndex_ = newLength;
      StorageType::resizeWithinCapacity(
          indexedStorage, runtime, newLength - beginIndex);
      return ExecutionStatus::RETURNED;
    }
  }

  auto indexedStorage =
      runtime.makeMutableHandle(selfHandle->getIndexedStorage(runtime));

  if (StorageType::resize(indexedStorage, runtime, newLength - beginIndex) ==
      ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  selfHandle->endIndex_ = newLength;
  selfHandle->setIndexedStorage(
      runtime, indexedStorage.get(), runtime.getHeap());
  return ExecutionStatus::RETURNED;
}

CallResult<bool> ArrayImpl::_setOwnIndexedImpl(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    uint32_t index,
    Handle<> value) {
  auto *self = vmcast<ArrayImpl>(selfHandle.get());
  auto beginIndex = self->beginIndex_;
  auto endIndex = self->endIndex_;

  if (LLVM_UNLIKELY(self->flags_.frozen))
    return false;

                                                   
  if (LLVM_LIKELY(index >= beginIndex && index < endIndex)) {
    const auto shv = SmallHermesValue::encodeHermesValue(*value, runtime);
    Handle<ArrayImpl>::vmcast(selfHandle)
        ->getIndexedStorage(runtime)
        ->set(runtime, index - beginIndex, shv);
    return true;
  }

                                                  
  if (LLVM_UNLIKELY(!self->getIndexedStorage(runtime))) {
                                                                  
    auto arrRes = StorageType::create(runtime, 4, 1);
    if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    auto newStorage = runtime.makeHandle<StorageType>(std::move(*arrRes));
    const auto shv = SmallHermesValue::encodeHermesValue(*value, runtime);
    self = vmcast<ArrayImpl>(selfHandle.get());

    self->setIndexedStorage(runtime, newStorage.get(), runtime.getHeap());
    self->beginIndex_ = index;
    self->endIndex_ = index + 1;
    newStorage->set(runtime, 0, shv);
    return true;
  }

  {
    const auto shv = SmallHermesValue::encodeHermesValue(*value, runtime);
    NoAllocScope scope{runtime};
    self = vmcast<ArrayImpl>(selfHandle.get());
    auto *const indexedStorage = self->getIndexedStorage(runtime);

                                                  
    if (index >= endIndex && index - beginIndex < indexedStorage->capacity()) {
      self->endIndex_ = index + 1;
      StorageType::resizeWithinCapacity(
          indexedStorage, runtime, index - beginIndex + 1);
                                                                            
      indexedStorage->set(runtime, index - beginIndex, shv);
      return true;
    }
  }

  auto indexedStorageHandle =
      runtime.makeMutableHandle(self->getIndexedStorage(runtime));
                                                                    
  constexpr uint32_t shiftLimit = (1 << 20);

                        
  if (LLVM_UNLIKELY(endIndex == beginIndex)) {
    if (StorageType::resize(indexedStorageHandle, runtime, 1) ==
        ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    const auto shv = SmallHermesValue::encodeHermesValue(*value, runtime);
    indexedStorageHandle->set(runtime, 0, shv);
    self = vmcast<ArrayImpl>(selfHandle.get());
    self->beginIndex_ = index;
    self->endIndex_ = index + 1;
  } else if (LLVM_UNLIKELY(
                 (index > endIndex && index - endIndex > shiftLimit) ||
                 (index < beginIndex && beginIndex - index > shiftLimit))) {
                                                                  
                                                     
                                                                          
                                                             
                         
    auto vr = valueToSymbolID(
        runtime,
        runtime.makeHandle(HermesValue::encodeUntrustedNumberValue(index)));
    assert(
        vr != ExecutionStatus::EXCEPTION &&
        "valueToIdentifier() failed for uint32_t value");

    if (LLVM_UNLIKELY(
            JSObject::defineNewOwnProperty(
                selfHandle,
                runtime,
                **vr,
                PropertyFlags::defaultNewNamedPropertyFlags(),
                value) == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
                                                                      
    return true;
  } else if (index >= endIndex) {
                              
    if (StorageType::resize(
            indexedStorageHandle, runtime, index - beginIndex + 1) ==
        ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    const auto shv = SmallHermesValue::encodeHermesValue(*value, runtime);
    self = vmcast<ArrayImpl>(selfHandle.get());
    self->endIndex_ = index + 1;
    indexedStorageHandle->set(runtime, index - beginIndex, shv);
  } else {
                                                                       
    assert(index < beginIndex);

    if (StorageType::resizeLeft(
            indexedStorageHandle,
            runtime,
            indexedStorageHandle->size(runtime) + beginIndex - index) ==
        ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    const auto shv = SmallHermesValue::encodeHermesValue(*value, runtime);
    self = vmcast<ArrayImpl>(selfHandle.get());
    self->beginIndex_ = index;
    indexedStorageHandle->set(runtime, 0, shv);
  }

                                            
  self->setIndexedStorage(
      runtime, indexedStorageHandle.get(), runtime.getHeap());
  return true;
}

bool ArrayImpl::_deleteOwnIndexedImpl(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    uint32_t index) {
  auto *self = vmcast<ArrayImpl>(selfHandle.get());
  NoAllocScope noAlloc{runtime};
  if (index >= self->beginIndex_ && index < self->endIndex_) {
    auto *indexedStorage = self->getIndexedStorage(runtime);
                                                       
    if (LLVM_UNLIKELY(self->flags_.sealed)) {
      SmallHermesValue elem =
          indexedStorage->at(runtime, index - self->beginIndex_);
      if (!elem.isEmpty())
        return false;
    }

    indexedStorage->setNonPtr(
        runtime,
        index - self->beginIndex_,
        SmallHermesValue::encodeEmptyValue());
  }

  return true;
}

bool ArrayImpl::_checkAllOwnIndexedImpl(
    JSObject *selfObj,
    Runtime &runtime,
    ObjectVTable::CheckAllOwnIndexedMode         
) {
  auto *self = vmcast<ArrayImpl>(selfObj);

                                                                     
                  
  for (uint32_t i = 0, e = self->endIndex_ - self->beginIndex_; i != e; ++i) {
    if (!self->getIndexedStorage(runtime)->at(runtime, i).isEmpty())
      return false;
  }
  return true;
}

                                                                                
                  

const ObjectVTable Arguments::vt{
    VTable(
        CellKind::ArgumentsKind,
        cellSize<Arguments>(),
        nullptr,
        nullptr,
        nullptr
#ifdef HERMES_MEMORY_INSTRUMENTATION
        ,
        VTable::HeapSnapshotMetadata{
            HeapSnapshot::NodeType::Object,
            nullptr,
            Arguments::_snapshotAddEdgesImpl,
            nullptr,
            nullptr}
#endif
        ),
    Arguments::_getOwnIndexedRangeImpl,
    Arguments::_haveOwnIndexedImpl,
    Arguments::_getOwnIndexedPropertyFlagsImpl,
    Arguments::_getOwnIndexedImpl,
    Arguments::_setOwnIndexedImpl,
    Arguments::_deleteOwnIndexedImpl,
    Arguments::_checkAllOwnIndexedImpl,
};

void ArgumentsBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  mb.addJSObjectOverlapSlots(JSObject::numOverlapSlots<Arguments>());
  ArrayImplBuildMeta(cell, mb);
  mb.setVTable(&Arguments::vt);
}

CallResult<Handle<Arguments>> Arguments::create(
    Runtime &runtime,
    size_type length,
    Handle<Callable> curFunction,
    bool strictMode) {
  auto clazz = runtime.getHiddenClassForPrototype(
      runtime.objectPrototypeRawPtr, numOverlapSlots<Arguments>());
  auto obj = runtime.makeAFixed<Arguments>(
      runtime, Handle<JSObject>::vmcast(&runtime.objectPrototype), clazz);
  auto selfHandle = JSObjectInit::initToHandle(runtime, obj);

  {
    auto arrRes = StorageType::create(runtime, length);
    if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION))
      return ExecutionStatus::EXCEPTION;
    selfHandle->setIndexedStorage(runtime, arrRes->get(), runtime.getHeap());
  }
  Arguments::setStorageEndIndex(selfHandle, runtime, length);

  PropertyFlags pf{};
  namespace P = Predefined;

                                                                                
                                                                             
                                                                       
                                     
#define DEFINE_PROP(OBJ_HANDLE, SYMBOL, HANDLE)                            \
  do {                                                                     \
    auto status = JSObject::defineNewOwnProperty(                          \
        OBJ_HANDLE, runtime, Predefined::getSymbolID(SYMBOL), pf, HANDLE); \
    if (LLVM_UNLIKELY(status == ExecutionStatus::EXCEPTION)) {             \
      return ExecutionStatus::EXCEPTION;                                   \
    }                                                                      \
  } while (false)

                                
  pf.enumerable = 0;
  pf.writable = 1;
  pf.configurable = 1;

  DEFINE_PROP(
      selfHandle,
      P::length,
      runtime.makeHandle(HermesValue::encodeUntrustedNumberValue(length)));

  DEFINE_PROP(
      selfHandle, P::SymbolIterator, Handle<>(&runtime.arrayPrototypeValues));

  if (strictMode ||
      LLVM_UNLIKELY(vmisa<GeneratorInnerFunction>(*curFunction))) {
                                                                         
                                                                          
                        
    auto accessor =
        Handle<PropertyAccessor>::vmcast(&runtime.throwTypeErrorAccessor);

    pf.clear();
    pf.enumerable = 0;
    pf.writable = 0;
    pf.configurable = 0;
    pf.accessor = 1;

    DEFINE_PROP(selfHandle, P::callee, accessor);
    DEFINE_PROP(selfHandle, P::caller, accessor);
  } else {
                                                                          
                                                                         
    assert(
        vmisa<Callable>(curFunction.getHermesValue()) &&
        "attempt to reify arguments with a non-callable callee");

    pf.clear();
    pf.enumerable = 0;
    pf.writable = 1;
    pf.configurable = 1;

    DEFINE_PROP(selfHandle, P::callee, curFunction);
  }

  return selfHandle;

#undef DEFINE_PROP
}

                                                                                
                

const ObjectVTable JSArray::vt{
    VTable(
        CellKind::JSArrayKind,
        cellSize<JSArray>(),
        nullptr,
        nullptr,
        nullptr
#ifdef HERMES_MEMORY_INSTRUMENTATION
        ,
        VTable::HeapSnapshotMetadata{
            HeapSnapshot::NodeType::Object,
            nullptr,
            JSArray::_snapshotAddEdgesImpl,
            nullptr,
            nullptr}
#endif
        ),
    JSArray::_getOwnIndexedRangeImpl,
    JSArray::_haveOwnIndexedImpl,
    JSArray::_getOwnIndexedPropertyFlagsImpl,
    JSArray::_getOwnIndexedImpl,
    JSArray::_setOwnIndexedImpl,
    JSArray::_deleteOwnIndexedImpl,
    JSArray::_checkAllOwnIndexedImpl,
};

void JSArrayBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  mb.addJSObjectOverlapSlots(JSObject::numOverlapSlots<JSArray>());
  ArrayImplBuildMeta(cell, mb);
  mb.setVTable(&JSArray::vt);
}

Handle<HiddenClass> JSArray::createClass(
    Runtime &runtime,
    Handle<JSObject> prototypeHandle) {
  Handle<HiddenClass> classHandle = runtime.getHiddenClassForPrototype(
      *prototypeHandle, numOverlapSlots<JSArray>());

  PropertyFlags pf{};
  pf.enumerable = 0;
  pf.writable = 1;
  pf.configurable = 0;
  pf.internalSetter = 1;

  auto added = HiddenClass::addProperty(
      classHandle, runtime, Predefined::getSymbolID(Predefined::length), pf);
  assert(
      added != ExecutionStatus::EXCEPTION &&
      "Adding the first properties shouldn't cause overflow");
  assert(
      added->second == lengthPropIndex() && "JSArray.length has invalid index");
  classHandle = added->first;

  assert(
      classHandle->getNumProperties() == jsArrayPropertyCount() &&
      "JSArray class defined with incorrect number of properties");

  return classHandle;
}

CallResult<Handle<JSArray>> JSArray::createNoAllocPropStorage(
    Runtime &runtime,
    Handle<JSObject> prototypeHandle,
    Handle<HiddenClass> classHandle,
    size_type capacity,
    size_type length) {
  assert(length <= capacity && "length must be <= capacity");

  assert(
      classHandle->getNumProperties() >= jsArrayPropertyCount() &&
      "invalid number of properties in JSArray hidden class");

  auto self = JSObjectInit::initToHandle(
      runtime,
      runtime.makeAFixed<JSArray>(
          runtime, prototypeHandle, classHandle, GCPointerBase::NoBarriers()));

                                                       
  if (capacity) {
    if (LLVM_UNLIKELY(capacity > StorageType::maxElements()))
      return runtime.raiseRangeError("Out of memory for array elements");
    auto arrRes = StorageType::create(runtime, capacity);
    if (arrRes == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    self->setIndexedStorage(runtime, arrRes->get(), runtime.getHeap());
  }
  auto shv = SmallHermesValue::encodeNumberValue(length, runtime);
  putLength(self.get(), runtime, shv);

  return self;
}

CallResult<Handle<JSArray>> JSArray::createAndAllocPropStorage(
    Runtime &runtime,
    Handle<JSObject> prototypeHandle,
    Handle<HiddenClass> classHandle,
    size_type capacity,
    size_type length) {
  CallResult<Handle<JSArray>> res = createNoAllocPropStorage(
      runtime, prototypeHandle, classHandle, capacity, length);
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

                                                                              
                         
  Handle<JSArray> arr = std::move(*res);
  runtime.ignoreAllocationFailure(
      JSObject::allocatePropStorage(
          arr, runtime, classHandle->getNumProperties()));

  return arr;
}

CallResult<Handle<JSArray>>
JSArray::create(Runtime &runtime, size_type capacity, size_type length) {
  return JSArray::createNoAllocPropStorage(
      runtime,
      Handle<JSObject>::vmcast(&runtime.arrayPrototype),
      Handle<HiddenClass>::vmcast(&runtime.arrayClass),
      capacity,
      length);
}

CallResult<bool> JSArray::setLength(
    Handle<JSArray> selfHandle,
    Runtime &runtime,
    Handle<> newLength,
    PropOpFlags opFlags) {
                                                                          
                                            
                                                                           
                                                                          
                                     
                                                                             
                                                                         
               

  uint32_t ulen;
  double d;
  if (LLVM_LIKELY(newLength->isNumber())) {
    d = newLength->getNumber();
    ulen = truncateToUInt32(d);
  } else {
                                                                
                                                                                                       
                                 
                                                                                
                                                                             
                                                                   
    auto res = toNumber_RJS(runtime, newLength);
    if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION))
      return ExecutionStatus::EXCEPTION;
    d = res->getNumber();
    ulen = truncateToUInt32(d);
                                                                      
                                                                               
                                           
                                                                                
                                                                            
                          
    if (!newLength->isString()) {
      res = toNumber_RJS(runtime, newLength);
      if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION))
        return ExecutionStatus::EXCEPTION;
      d = res->getNumber();
    }
  }

  if (ulen != d)
    return runtime.raiseRangeError("Invalid array length");

  return setLength(selfHandle, runtime, ulen, opFlags);
}

CallResult<bool> JSArray::setLength(
    Handle<JSArray> selfHandle,
    Runtime &runtime,
    uint32_t newLength,
    PropOpFlags opFlags) {
                                                
  const auto currentLength = getLength(*selfHandle, runtime);
  if (LLVM_LIKELY(newLength >= currentLength)) {
    auto shv = SmallHermesValue::encodeNumberValue(newLength, runtime);
    putLength(*selfHandle, runtime, shv);
    return true;
  }

                                                                            
                                            
  uint32_t adjustedLength = newLength;

                                                                 
  if (LLVM_UNLIKELY(selfHandle->flags_.sealed)) {
                                                                            
                                                                          
                                                               
                                                   
                                             
                                             
                                     
                                    
                                    
                                    
                                    
                                         
      

    auto *self = selfHandle.get();
    auto range = _getOwnIndexedRangeImpl(self, runtime);
    uint32_t lowestScanLen = std::max(range.first, newLength);
    uint32_t highestLen = std::min(range.second, currentLength);

    for (; highestLen > lowestScanLen; --highestLen) {
      if (!self->unsafeAt(runtime, highestLen - 1).isEmpty()) {
        adjustedLength = highestLen;
        break;
      }
    }
  }

  if (LLVM_UNLIKELY(selfHandle->clazz_.getNonNull(runtime)
                        ->getHasIndexLikeProperties())) {
                                                                          
                                                                             
                            

                                                                               
                                                                                
                                                                                
                                                                        

    using IndexProp = std::pair<uint32_t, SymbolID>;
    llvh::SmallVector<IndexProp, 8> toBeDeleted;

    GCScope scope{runtime};

    HiddenClass::forEachProperty(
        runtime.makeHandle(selfHandle->clazz_),
        runtime,
        [&runtime, &adjustedLength, &toBeDeleted, &scope](
            SymbolID id, NamedPropertyDescriptor desc) {
          GCScopeMarkerRAII marker{scope};
                                                                               
                                                                   
          auto propNameAsIndex = toArrayIndex(
              runtime.getIdentifierTable().getStringView(runtime, id));
          if (!propNameAsIndex || *propNameAsIndex < adjustedLength)
            return;

          if (!desc.flags.configurable) {
            adjustedLength = *propNameAsIndex + 1;
          } else {
            toBeDeleted.push_back({*propNameAsIndex, id});
          }
        });

                                                                                
                                                     
    for (auto it = toBeDeleted.rbegin(), e = toBeDeleted.rend(); it != e;
         ++it) {
      if (it->first >= adjustedLength) {
        GCScopeMarkerRAII marker{scope};
        auto cr = JSObject::deleteNamed(selfHandle, runtime, it->second);
        assert(
            cr != ExecutionStatus::EXCEPTION && *cr &&
            "Failed to delete a configurable property");
        (void)cr;
      }
    }
  }

  if (adjustedLength < selfHandle->getEndIndex()) {
    auto cr = setStorageEndIndex(selfHandle, runtime, adjustedLength);
    if (cr == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
  }
  auto shv = SmallHermesValue::encodeNumberValue(adjustedLength, runtime);
  putLength(*selfHandle, runtime, shv);

  if (adjustedLength != newLength) {
    if (opFlags.getThrowOnError()) {
      return runtime.raiseTypeError(
          TwineChar16("Cannot delete property '") + (adjustedLength - 1) + "'");
    }
    return false;
  }

  return true;
}

                                                                                
                        

const ObjectVTable JSArrayIterator::vt{
    VTable(CellKind::JSArrayIteratorKind, cellSize<JSArrayIterator>()),
    JSArrayIterator::_getOwnIndexedRangeImpl,
    JSArrayIterator::_haveOwnIndexedImpl,
    JSArrayIterator::_getOwnIndexedPropertyFlagsImpl,
    JSArrayIterator::_getOwnIndexedImpl,
    JSArrayIterator::_setOwnIndexedImpl,
    JSArrayIterator::_deleteOwnIndexedImpl,
    JSArrayIterator::_checkAllOwnIndexedImpl,
};

void JSArrayIteratorBuildMeta(const GCCell *cell, Metadata::Builder &mb) {
  mb.addJSObjectOverlapSlots(JSObject::numOverlapSlots<JSArrayIterator>());
  JSObjectBuildMeta(cell, mb);
  const auto *self = static_cast<const JSArrayIterator *>(cell);
  mb.setVTable(&JSArrayIterator::vt);
  mb.addField("iteratedObject", &self->iteratedObject_);
}

PseudoHandle<JSArrayIterator> JSArrayIterator::create(
    Runtime &runtime,
    Handle<JSObject> array,
    IterationKind iterationKind) {
  auto proto = Handle<JSObject>::vmcast(&runtime.arrayIteratorPrototype);
  auto clazz = runtime.getHiddenClassForPrototype(
      *proto, numOverlapSlots<JSArrayIterator>());
  auto *obj = runtime.makeAFixed<JSArrayIterator>(
      runtime, proto, clazz, array, iterationKind);
  return JSObjectInit::initToPseudoHandle(runtime, obj);
}

                                           
CallResult<HermesValue> JSArrayIterator::nextElement(
    Handle<JSArrayIterator> self,
    Runtime &runtime) {
  if (!self->iteratedObject_) {
                                                                            
    return createIterResultObject(runtime, Runtime::getUndefinedValue(), true)
        .getHermesValue();
  }

                                                                        
  Handle<JSObject> a = runtime.makeHandle(self->iteratedObject_);
                                                                              
          
  uint64_t index = self->nextIndex_;

  uint64_t len;
  if (auto ta = Handle<JSTypedArrayBase>::dyn_vmcast(a)) {
                                                           
                                                               
                                      
                                                                    
    if (LLVM_UNLIKELY(!ta->attached(runtime))) {
      return runtime.raiseTypeError("TypedArray detached during iteration");
    }
    len = ta->getLength();
  } else {
               
                                                
    auto propRes = JSObject::getNamed_RJS(
        a, runtime, Predefined::getSymbolID(Predefined::length));
    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    auto lenRes = toLength(runtime, runtime.makeHandle(std::move(*propRes)));
    if (LLVM_UNLIKELY(lenRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    len = lenRes->getNumber();
  }

  if (index >= len) {
                               
                                                                       
                 
    self->iteratedObject_.setNull(runtime.getHeap());
                                                         
    return createIterResultObject(runtime, Runtime::getUndefinedValue(), true)
        .getHermesValue();
  }

                                                                              
             
  ++self->nextIndex_;

  auto indexHandle =
      runtime.makeHandle(HermesValue::encodeUntrustedNumberValue(index));

  if (self->iterationKind_ == IterationKind::Key) {
                                                                             
    return createIterResultObject(runtime, indexHandle, false).getHermesValue();
  }

                                           
                                                
  CallResult<PseudoHandle<>> valueRes =
      JSObject::getComputed_RJS(a, runtime, indexHandle);
  if (LLVM_UNLIKELY(valueRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<> valueHandle = runtime.makeHandle(std::move(*valueRes));

  switch (self->iterationKind_) {
    case IterationKind::Key:
      llvm_unreachable("Early return already occurred in Key case");
      return HermesValue::encodeEmptyValue();
    case IterationKind::Value:
                                                                
      return createIterResultObject(runtime, valueHandle, false)
          .getHermesValue();
    case IterationKind::Entry: {
                                                                         
      auto resultRes = JSArray::create(runtime, 2, 2);
      if (LLVM_UNLIKELY(resultRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      Handle<JSArray> result = *resultRes;
      JSArray::setElementAt(result, runtime, 0, indexHandle);
      JSArray::setElementAt(result, runtime, 1, valueHandle);
                                                          
      return createIterResultObject(runtime, result, false).getHermesValue();
    }
    case IterationKind::NumKinds:
      llvm_unreachable("Invalid iteration kind");
      return HermesValue::encodeEmptyValue();
  }

  llvm_unreachable("Invalid iteration kind");
  return HermesValue::encodeEmptyValue();
}

}                
}                    

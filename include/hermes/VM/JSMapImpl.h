/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_JSMAPIMPL_H
#define HERMES_VM_JSMAPIMPL_H

#include "hermes/VM/Callable.h"
#include "hermes/VM/GCPointer.h"
#include "hermes/VM/IterationKind.h"
#include "hermes/VM/JSArray.h"
#include "hermes/VM/OrderedHashMap.h"

namespace hermes {
namespace vm {

                                                                              
                                                                       
                       
template <CellKind C>
class JSMapImpl final : public JSObject {
  using Super = JSObject;

 public:
  static const ObjectVTable vt;

  static constexpr CellKind getCellKind() {
    return C;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == C;
  }

  static PseudoHandle<JSMapImpl<C>> create(
      Runtime &runtime,
      Handle<JSObject> parentHandle);

                                            
  static ExecutionStatus initializeStorage(
      Handle<JSMapImpl> self,
      Runtime &runtime) {
    auto crtRes = OrderedHashMap::create(runtime);
    if (LLVM_UNLIKELY(crtRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    auto storageHandle = runtime.makeHandle<OrderedHashMap>(std::move(*crtRes));
    self->storage_.set(runtime, storageHandle.get(), runtime.getHeap());
    return ExecutionStatus::RETURNED;
  }

                                           
  HashMapEntry *iteratorNext(Runtime &runtime, HashMapEntry *entry) {
    return storage_.getNonNull(runtime)->iteratorNext(runtime, entry);
  }

                  
  static void addValue(
      Handle<JSMapImpl> self,
      Runtime &runtime,
      Handle<> key,
      Handle<> value) {
    self->assertInitialized();
    OrderedHashMap::insert(
        runtime.makeHandle<OrderedHashMap>(self->storage_),
        runtime,
        key,
        value);
  }

                                   
  static bool hasKey(Handle<JSMapImpl> self, Runtime &runtime, Handle<> key) {
    self->assertInitialized();
    return OrderedHashMap::has(
        runtime.makeHandle<OrderedHashMap>(self->storage_), runtime, key);
  }

  static HermesValue
  getValue(Handle<JSMapImpl> self, Runtime &runtime, Handle<> key) {
    self->assertInitialized();
    return OrderedHashMap::get(
        runtime.makeHandle<OrderedHashMap>(self->storage_), runtime, key);
  }

                                              
  static bool
  deleteKey(Handle<JSMapImpl> self, Runtime &runtime, Handle<> key) {
    self->assertInitialized();
    return OrderedHashMap::erase(
        runtime.makeHandle<OrderedHashMap>(self->storage_), runtime, key);
  }

                        
  static uint32_t getSize(JSMapImpl *self, Runtime &runtime) {
    self->assertInitialized();
    return self->storage_.getNonNull(runtime)->size();
  }

                                          
  static void clear(Handle<JSMapImpl> self, Runtime &runtime) {
    self->assertInitialized();
    self->storage_.getNonNull(runtime)->clear(runtime);
  }

                                                                 
  static ExecutionStatus forEach(
      Handle<JSMapImpl> self,
      Runtime &runtime,
      Handle<Callable> callbackfn,
      Handle<> thisArg) {
    self->assertInitialized();
    MutableHandle<HashMapEntry> entry{runtime};
    GCScopeMarkerRAII marker{runtime};
    for (entry = self->storage_.getNonNull(runtime)->iteratorNext(runtime);
         entry;
         entry = self->storage_.getNonNull(runtime)->iteratorNext(
             runtime, entry.get())) {
      marker.flush();
      HermesValue key = entry->key;
      HermesValue value = entry->value;
      assert(!key.isEmpty() && "Invalid key encountered");
      assert(!value.isEmpty() && "Invalid value encountered");
      if (LLVM_UNLIKELY(
              Callable::executeCall3(
                  callbackfn,
                  runtime,
                  thisArg,
                  value,
                  key,
                  self.getHermesValue()) == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
    }
    return ExecutionStatus::RETURNED;
  }

                                                                              
  static void MapOrSetBuildMeta(const GCCell *cell, Metadata::Builder &mb);

  JSMapImpl(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz)
      : JSObject(runtime, *parent, *clazz) {}

 private:
                             
  GCPointer<OrderedHashMap> storage_{nullptr};

  void assertInitialized() {
    assert(storage_ && "Element storage uninitialized.");
  }
};

                                                                             
template <CellKind T>
struct JSMapTypeTraits;
template <>
struct JSMapTypeTraits<CellKind::JSSetIteratorKind> {
  static constexpr CellKind ContainerKind = CellKind::JSSetKind;
};
template <>
struct JSMapTypeTraits<CellKind::JSMapIteratorKind> {
  static constexpr CellKind ContainerKind = CellKind::JSMapKind;
};

template <CellKind C>
class JSMapIteratorImpl final : public JSObject {
  using Super = JSObject;

 public:
  static const ObjectVTable vt;

  static constexpr CellKind getCellKind() {
    return C;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == C;
  }

                                       
  static PseudoHandle<JSMapIteratorImpl<C>> create(
      Runtime &runtime,
      Handle<JSObject> prototype);

                                                                             
                                                          
  void initializeIterator(
      Runtime &runtime,
      Handle<JSMapImpl<JSMapTypeTraits<C>::ContainerKind>> data,
      IterationKind kind) {
    data_.set(runtime, data.get(), runtime.getHeap());
    iterationKind_ = kind;

    assert(data_ && "Invalid storage data");
  }

                                                          
                                                                   
                                
  bool isInitialized() const {
    return data_ || iterationFinished_;
  }

                                             
  static CallResult<HermesValue> nextElement(
      Handle<JSMapIteratorImpl> self,
      Runtime &runtime) {
    MutableHandle<> value{runtime};
    if (!self->iterationFinished_) {
                                                          
      assert(self->data_ && "Storage uninitialized");
                              
      self->itr_.set(
          runtime,
          self->data_.getNonNull(runtime)->iteratorNext(
              runtime, self->itr_.get(runtime)),
          runtime.getHeap());
      if (self->itr_) {
        switch (self->iterationKind_) {
          case IterationKind::Key:
            value = self->itr_.getNonNull(runtime)->key;
            break;
          case IterationKind::Value:
            value = self->itr_.getNonNull(runtime)->value;
            break;
          case IterationKind::Entry: {
                                                                           
                     
            auto arrRes = JSArray::create(runtime, 2, 2);
            if (arrRes == ExecutionStatus::EXCEPTION) {
              return ExecutionStatus::EXCEPTION;
            }
            auto arrHandle = *arrRes;
            value = self->itr_.getNonNull(runtime)->key;
            JSArray::setElementAt(arrHandle, runtime, 0, value);
            value = self->itr_.getNonNull(runtime)->value;
            JSArray::setElementAt(arrHandle, runtime, 1, value);
            value = arrHandle.getHermesValue();
            break;
          };
          case IterationKind::NumKinds:
            llvm_unreachable("Invalid iteration kind");
            return HermesValue::encodeEmptyValue();
        }
      } else {
                                                                  
                           
        self->iterationFinished_ = true;
        self->data_.setNull(runtime.getHeap());
      }
    }
    return createIterResultObject(runtime, value, self->iterationFinished_)
        .getHermesValue();
  }

                                                                              
  static void MapOrSetIteratorBuildMeta(
      const GCCell *cell,
      Metadata::Builder &mb);

  JSMapIteratorImpl(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz)
      : JSObject(runtime, *parent, *clazz) {}

 private:
                                                                                
                                             
  GCPointer<JSMapImpl<JSMapTypeTraits<C>::ContainerKind>> data_{nullptr};

                                                          
  GCPointer<HashMapEntry> itr_{nullptr};

  IterationKind iterationKind_;

                                                       
  bool iterationFinished_{false};
};

using JSMap = JSMapImpl<CellKind::JSMapKind>;
using JSSet = JSMapImpl<CellKind::JSSetKind>;
using JSMapIterator = JSMapIteratorImpl<CellKind::JSMapIteratorKind>;
using JSSetIterator = JSMapIteratorImpl<CellKind::JSSetIteratorKind>;

}                
}                    

#endif                         

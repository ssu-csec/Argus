/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_PRIMITIVEBOX_H
#define HERMES_VM_PRIMITIVEBOX_H

#include "hermes/VM/BigIntPrimitive.h"
#include "hermes/VM/JSObject.h"

namespace hermes {
namespace vm {

                  
class JSString final : public JSObject {
 public:
  using Super = JSObject;

  friend void JSStringBuildMeta(const GCCell *, Metadata::Builder &);

                                                   
  static const PropStorage::size_type NAMED_PROPERTY_SLOTS =
      Super::NAMED_PROPERTY_SLOTS + 1;
  static const ObjectVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::JSStringKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::JSStringKind;
  }

  static CallResult<Handle<JSString>> create(
      Runtime &runtime,
      Handle<StringPrimitive> value,
      Handle<JSObject> prototype);

  static CallResult<Handle<JSString>> create(
      Runtime &runtime,
      Handle<JSObject> prototype) {
    return create(
        runtime,
        runtime.getPredefinedStringHandle(Predefined::emptyString),
        prototype);
  }

                                                                 
  static void setPrimitiveString(
      Handle<JSString> selfHandle,
      Runtime &runtime,
      Handle<StringPrimitive> string);

                                                                  
  static StringPrimitive *getPrimitiveString(
      const JSString *self,
      Runtime &runtime) {
    return self->primitiveValue_.get(runtime);
  }

  JSString(
      Runtime &runtime,
      Handle<StringPrimitive> value,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz)
      : JSObject(runtime, *parent, *clazz),
        primitiveValue_(runtime, *value, runtime.getHeap()) {
    flags_.indexedStorage = true;
    flags_.fastIndexProperties = true;
  }

 protected:
                                                                              
                              
  static bool
  _haveOwnIndexedImpl(JSObject *self, Runtime &runtime, uint32_t index);

                                                                              
                                                                               
                        
                                                   
  static OptValue<PropertyFlags> _getOwnIndexedPropertyFlagsImpl(
      JSObject *self,
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

 private:
  GCPointer<StringPrimitive> primitiveValue_;
};

                          
                                                                 
class JSStringIterator : public JSObject {
  using Super = JSObject;

  friend void JSStringIteratorBuildMeta(
      const GCCell *cell,
      Metadata::Builder &mb);

 public:
  static const ObjectVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::JSStringIteratorKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::JSStringIteratorKind;
  }

  static PseudoHandle<JSStringIterator> create(
      Runtime &runtime,
      Handle<StringPrimitive> string);

                                             
  static CallResult<HermesValue> nextElement(
      Handle<JSStringIterator> self,
      Runtime &runtime);

  JSStringIterator(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz,
      Handle<StringPrimitive> iteratedString)
      : JSObject(runtime, *parent, *clazz),
        iteratedString_(runtime, *iteratedString, runtime.getHeap()) {}

 private:
                        
                                                   
  GCPointer<StringPrimitive> iteratedString_;

                                 
  uint32_t nextIndex_{0};
};

                  
                                             
                             
                                              
                           
                                     
class JSBigInt final : public JSObject {
 public:
  using Super = JSObject;

  friend void JSBigIntBuildMeta(const GCCell *, Metadata::Builder &);

  static const PropStorage::size_type NAMED_PROPERTY_SLOTS =
      Super::NAMED_PROPERTY_SLOTS;
  static const ObjectVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::JSBigIntKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::JSBigIntKind;
  }

  static Handle<JSBigInt> create(
      Runtime &runtime,
      Handle<BigIntPrimitive> value,
      Handle<JSObject> prototype);

  static CallResult<Handle<JSBigInt>> create(
      Runtime &runtime,
      Handle<JSObject> prototype) {
    auto bigIntRes = BigIntPrimitive::fromSigned(runtime, 0);
    if (LLVM_UNLIKELY(bigIntRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }

    return create(
        runtime, runtime.makeHandle(bigIntRes->getBigInt()), prototype);
  }

                                                                  
  static BigIntPrimitive *getPrimitiveBigInt(
      const JSBigInt *self,
      Runtime &runtime) {
    return self->primitiveValue_.get(runtime);
  }

  JSBigInt(
      Runtime &runtime,
      Handle<BigIntPrimitive> value,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz)
      : JSObject(runtime, *parent, *clazz),
        primitiveValue_(runtime, *value, runtime.getHeap()) {}

 private:
  GCPointer<BigIntPrimitive> primitiveValue_;
};

                  
class JSNumber final : public JSObject {
 public:
  static const ObjectVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::JSNumberKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::JSNumberKind;
  }

  static PseudoHandle<JSNumber>
  create(Runtime &runtime, double value, Handle<JSObject> prototype);

  static PseudoHandle<JSNumber> create(
      Runtime &runtime,
      Handle<JSObject> prototype) {
    return create(runtime, 0.0, prototype);
  }

  JSNumber(
      Runtime &runtime,
      double value,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz)
      : JSObject(runtime, *parent, *clazz), primitiveValue_(value) {}

  double getPrimitiveNumber() const {
    return primitiveValue_;
  }

  void setPrimitiveNumber(double value) {
    primitiveValue_ = value;
  }

 private:
  double primitiveValue_;
};

                   
class JSBoolean final : public JSObject {
 public:
  static const ObjectVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::JSBooleanKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::JSBooleanKind;
  }

  static PseudoHandle<JSBoolean>
  create(Runtime &runtime, bool value, Handle<JSObject> prototype);

  static PseudoHandle<JSBoolean> create(
      Runtime &runtime,
      Handle<JSObject> prototype) {
    return create(runtime, false, prototype);
  }

  JSBoolean(
      Runtime &runtime,
      bool value,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz)
      : JSObject(runtime, *parent, *clazz), primitiveValue_(value) {}

  void setPrimitiveBoolean(bool b) {
    primitiveValue_ = b;
  }

  bool getPrimitiveBoolean() const {
    return primitiveValue_;
  }

 private:
  bool primitiveValue_;
};

                  
class JSSymbol final : public JSObject {
  friend void JSSymbolBuildMeta(const GCCell *cell, Metadata::Builder &mb);

 public:
  static const ObjectVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::JSSymbolKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::JSSymbolKind;
  }

  static PseudoHandle<JSSymbol>
  create(Runtime &runtime, SymbolID value, Handle<JSObject> prototype);

  static PseudoHandle<JSSymbol> create(
      Runtime &runtime,
      Handle<JSObject> prototype) {
    return create(runtime, SymbolID{}, prototype);
  }

                                                                    
  PseudoHandle<SymbolID> getPrimitiveSymbol() const {
    return PseudoHandle<SymbolID>::create(primitiveValue_);
  }

  JSSymbol(
      Runtime &runtime,
      SymbolID value,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz)
      : JSObject(runtime, *parent, *clazz), primitiveValue_(value) {}

 private:
  const GCSymbolID primitiveValue_;
};

}                
}                    

#endif                            

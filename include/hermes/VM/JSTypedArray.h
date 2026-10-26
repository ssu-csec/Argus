/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_JSTYPEDARRAY_H
#define HERMES_VM_JSTYPEDARRAY_H

#include "hermes/VM/GCPointer.h"
#include "hermes/VM/JSArrayBuffer.h"

namespace hermes {
namespace vm {

                                                                           
                                                       
class JSTypedArrayBase : public JSObject {
 public:
                                                                     
                                                                   
                                                                    
                             
  using size_type = uint32_t;
  using Super = JSObject;

  CallResult<Handle<JSTypedArrayBase>> allocate(
      Runtime &runtime,
      size_type length = 0);

                                                                          
                            
                                                                              
             
                                                                      
                                                                   
  static CallResult<Handle<JSTypedArrayBase>> allocateToSameBuffer(
      Runtime &runtime,
      Handle<JSTypedArrayBase> src,
      size_type beginIndex,
      size_type endIndex);

  static CallResult<Handle<JSTypedArrayBase>> allocateSpecies(
      Runtime &runtime,
      Handle<JSTypedArrayBase> self,
      size_type length);

                    
                                                    
                                                                              
               
  static ExecutionStatus validateTypedArray(
      Runtime &runtime,
      Handle<> thisArg,
      bool checkAttached = true);
  static bool classof(const GCCell *cell) {
    return kindInRange(
        cell->getKind(),
        CellKind::TypedArrayBaseKind_first,
        CellKind::TypedArrayBaseKind_last);
  }

                                                                            
                         
  size_type getLength() const {
    return length_;
  }

                                                                         
                                     
  JSArrayBuffer::size_type getByteLength() const {
    return length_ * getByteWidth();
  }

                                                                             
                                         
  uint8_t getByteWidth() const;

                                                                           
              
                                                          
  JSArrayBuffer *getBuffer(Runtime &runtime) const {
    assert(buffer_ && "Must have some JSArrayBuffer");
    return buffer_.get(runtime);
  }

  uint8_t *begin(Runtime &runtime) {
    return buffer_.getNonNull(runtime)->getDataBlock(runtime) + offset_;
  }
  uint8_t *end(Runtime &runtime) {
    return begin(runtime) + getByteLength();
  }

                                                                       
  bool attached(Runtime &runtime) const {
    return buffer_ && buffer_.getNonNull(runtime)->attached();
  }

                                                                          
                      
  JSArrayBuffer::size_type getByteOffset() const {
    return offset_;
  }

                                                                  
                                                   
  static ExecutionStatus createBuffer(
      Runtime &runtime,
      Handle<JSTypedArrayBase> selfObj,
      uint64_t length);

                                                               
                                                         
          
                                      
                                           
  static ExecutionStatus setToCopyOfBuffer(
      Runtime &runtime,
      Handle<JSTypedArrayBase> dst,
      JSArrayBuffer::size_type dstByteOffset,
      Handle<JSArrayBuffer> src,
      JSArrayBuffer::size_type srcByteOffset,
      JSArrayBuffer::size_type count);

                                                  
                                                                        
                                                           
                                         
  static ExecutionStatus setToCopyOfTypedArray(
      Runtime &runtime,
      Handle<JSTypedArrayBase> dst,
      size_type dstIndex,
      Handle<JSTypedArrayBase> src,
      size_type srcIndex,
      size_type count);

                                                                           
                                                                             
                                                                             
               
          
                                                                
                                               
                                               
  static void setBuffer(
      Runtime &runtime,
      JSTypedArrayBase *self,
      JSArrayBuffer *buf,
      size_type offset,
      size_type size,
      uint8_t byteWidth);

 protected:
                                                                         
                                                                       
  GCPointer<JSArrayBuffer> buffer_;
                                                                               
  size_type length_;
                                                                                
  size_type offset_;

  explicit JSTypedArrayBase(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz);

                                                                         
                                
                                                                      
                                                      
          
                                                                     
                                                                      
  static void setToCopyOfBytes(
      Runtime &runtime,
      Handle<JSTypedArrayBase> dst,
      size_type dstIndex,
      Handle<JSTypedArrayBase> src,
      size_type srcIndex,
      size_type count);

  static std::pair<uint32_t, uint32_t> _getOwnIndexedRangeImpl(
      JSObject *selfObj,
      Runtime &runtime);

  static bool
  _haveOwnIndexedImpl(JSObject *selfObj, Runtime &runtime, uint32_t index);
  static OptValue<PropertyFlags> _getOwnIndexedPropertyFlagsImpl(
      JSObject *selfObj,
      Runtime &runtime,
      uint32_t index);
  static bool _deleteOwnIndexedImpl(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      uint32_t index);
                                                                               
                                                                                
                                                 
  static bool _checkAllOwnIndexedImpl(
      JSObject *selfObj,
      Runtime &runtime,
      ObjectVTable::CheckAllOwnIndexedMode mode);

  friend void TypedArrayBaseBuildMeta(
      const GCCell *cell,
      Metadata::Builder &mb);
};

                                                                               
                                                                            
   
                                                                    
                                                                          
template <typename T, CellKind C>
class JSTypedArray final : public JSTypedArrayBase {
 public:
  using iterator = T *;

  static const ObjectVTable vt;

  static constexpr CellKind getCellKind() {
    return C;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == C;
  }

  static PseudoHandle<JSTypedArray<T, C>> create(
      Runtime &runtime,
      Handle<JSObject> prototype);

  iterator begin(Runtime &runtime) {
    return reinterpret_cast<T *>(JSTypedArrayBase::begin(runtime));
  }
  iterator end(Runtime &runtime) {
    return begin(runtime) + length_;
  }

                                                 
          
                                                       
                                                         
  T &at(Runtime &runtime, size_type i) {
    assert(attached(runtime) && "at() requires a JSArrayBuffer");
    assert(i < getLength() && "That index is out of bounds of this TypedArray");
    return begin(runtime)[i];
  }

  static Handle<JSObject> getPrototype(const Runtime &runtime);
  static Handle<Callable> getConstructor(const Runtime &runtime);
  static SymbolID getName(Runtime &runtime);

                                                           
                                                       
  static CallResult<Handle<JSTypedArrayBase>> allocate(
      Runtime &runtime,
      size_type length = 0);

                                                                          
                                                                       
                  
  static CallResult<Handle<JSTypedArrayBase>> allocateSpecies(
      Handle<JSTypedArrayBase> self,
      Runtime &runtime,
      size_type length);

                                                                 
                                                                         
                                                                           
                      
  static inline T toDestType(const HermesValue &numeric) {
    return hermes::truncateToInt32(numeric.getNumber());
  }

 protected:
                                   
  static HermesValue _getOwnIndexedImpl(
      PseudoHandle<JSObject> self,
      Runtime &runtime,
      uint32_t index);
  static CallResult<bool> _setOwnIndexedImpl(
      Handle<JSObject> selfHandle,
      Runtime &runtime,
      uint32_t index,
      Handle<> value);

 public:
                                                                       
                                                                          

  explicit JSTypedArray(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz);
};

                                    
      

template <>
inline uint8_t
JSTypedArray<uint8_t, CellKind::Uint8ClampedArrayKind>::toDestType(
    const HermesValue &numeric) {
  return toUInt8Clamp(numeric.getNumber());
}

template <>
inline float JSTypedArray<float, CellKind::Float32ArrayKind>::toDestType(
    const HermesValue &numeric) LLVM_NO_SANITIZE("float-cast-overflow");

template <>
inline float JSTypedArray<float, CellKind::Float32ArrayKind>::toDestType(
    const HermesValue &numeric) {
                                                                   
                                                    
  return numeric.getNumber();
}

template <>
inline double JSTypedArray<double, CellKind::Float64ArrayKind>::toDestType(
    const HermesValue &numeric) {
  return numeric.getNumber();
}

template <>
int64_t JSTypedArray<int64_t, CellKind::BigInt64ArrayKind>::toDestType(
    const HermesValue &numeric);

template <>
uint64_t JSTypedArray<uint64_t, CellKind::BigUint64ArrayKind>::toDestType(
    const HermesValue &numeric);

      
#define TYPED_ARRAY(name, type) \
  using name##Array = JSTypedArray<type, CellKind::name##ArrayKind>;
#include "hermes/VM/TypedArrays.def"

}                
}                    

#endif

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_JSDATAVIEW_H
#define HERMES_VM_JSDATAVIEW_H

#include "hermes/VM/GCPointer-inline.h"
#include "hermes/VM/GCPointer.h"
#include "hermes/VM/JSArrayBuffer.h"
#include "hermes/VM/JSObject.h"

#include "llvh/Support/Endian.h"
#include "llvh/Support/SwapByteOrder.h"

namespace hermes {
namespace vm {

class JSDataView final : public JSObject {
 public:
  using size_type = JSArrayBuffer::size_type;
  using Super = JSObject;

  static const ObjectVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::JSDataViewKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::JSDataViewKind;
  }

  static PseudoHandle<JSDataView> create(
      Runtime &runtime,
      Handle<JSObject> prototype);

                                             
  Handle<JSArrayBuffer> getBuffer(Runtime &runtime) {
    assert(buffer_ && "Cannot get a null buffer");
    return runtime.makeHandle(buffer_);
  }

                                                          
  size_type byteLength() const {
    return length_;
  }

                                                                          
  size_type byteOffset() const {
    return offset_;
  }

                                                                             
                                        
                                                                             
                
                                                                               
                                      
                                                                               
                                  
  template <typename T>
  T get(Runtime &runtime, size_type offset, bool littleEndian) const;

                                                                             
                                        
                                                                             
                
                                                                     
                                                                         
                                  
  template <typename T>
  void set(Runtime &runtime, size_type offset, T value, bool littleEndian);

                                                        
                                                                           
                                 
  bool attached(Runtime &runtime) const {
    assert(
        buffer_ &&
        "Cannot call attached() when there is not even a buffer set");
    return buffer_.getNonNull(runtime)->attached();
  }

  void setBuffer(
      Runtime &runtime,
      JSArrayBuffer *buffer,
      size_type offset,
      size_type length) {
    assert(
        offset + length <= buffer->size() &&
        "A DataView cannot be looking outside of the storage");
    buffer_.setNonNull(runtime, buffer, runtime.getHeap());
    offset_ = offset;
    length_ = length;
  }

 public:
  friend void JSDataViewBuildMeta(const GCCell *cell, Metadata::Builder &mb);

 private:
                                                                    
  GCPointer<JSArrayBuffer> buffer_;
                                                                            
  size_type offset_;
                                                                           
  size_type length_;

 public:
  JSDataView(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz);
};

                         
      

template <typename T>
T JSDataView::get(
    Runtime &runtime,
    JSDataView::size_type offset,
    bool littleEndian) const {
  assert(attached(runtime) && "Cannot get on a detached buffer");
  assert(
      offset + sizeof(T) <= length_ &&
      "Trying to read past the end of the storage");
  T result;
  ::memcpy(
      &result,
      buffer_.getNonNull(runtime)->getDataBlock(runtime) + offset_ + offset,
      sizeof(T));
  return llvh::support::endian::byte_swap(
      result,
      littleEndian ? llvh::support::endianness::little
                   : llvh::support::endianness::big);
}

template <typename T>
void JSDataView::set(
    Runtime &runtime,
    JSDataView::size_type offset,
    T value,
    bool littleEndian) {
  assert(attached(runtime) && "Cannot set on a detached buffer");
  assert(
      offset + sizeof(T) <= length_ &&
      "Trying to write past the end of the storage");
  value = llvh::support::endian::byte_swap(
      value,
      littleEndian ? llvh::support::endianness::little
                   : llvh::support::endianness::big);
  memcpy(
      buffer_.getNonNull(runtime)->getDataBlock(runtime) + offset_ + offset,
      &value,
      sizeof(T));
}

      

}                
}                    

#endif

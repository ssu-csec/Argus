/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_JSARRAYBUFFER_H
#define HERMES_VM_JSARRAYBUFFER_H

#include "hermes/VM/JSObject.h"
#include "hermes/VM/NativeState.h"
#include "hermes/VM/Runtime.h"

namespace hermes {
namespace vm {

                                                                
   
                                                                              
                                                          
class JSArrayBuffer final : public JSObject {
 public:
                                                                           
                                      
  using size_type = std::uint32_t;

  static const ObjectVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::JSArrayBufferKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::JSArrayBufferKind;
  }

  static PseudoHandle<JSArrayBuffer> create(
      Runtime &runtime,
      Handle<JSObject> prototype);

                  
                                                                         
                                                                   
  static CallResult<Handle<JSArrayBuffer>> clone(
      Runtime &runtime,
      Handle<JSArrayBuffer> src,
      size_type srcByteOffset,
      size_type srcSize);

                 
  static void copyDataBlockBytes(
      Runtime &runtime,
      JSArrayBuffer *dst,
      size_type dstIndex,
      JSArrayBuffer *src,
      size_type srcIndex,
      size_type count);

                                                                          
                                             
                                                                    
                      
                                                                          
  static ExecutionStatus createDataBlock(
      Runtime &runtime,
      Handle<JSArrayBuffer> self,
      size_type size,
      bool zero = true);

                                                                             
                                                                              
                                                                        
                                                                                
  static ExecutionStatus setExternalDataBlock(
      Runtime &runtime,
      Handle<JSArrayBuffer> self,
      uint8_t *data,
      size_type size,
      void *context,
      FinalizeNativeStatePtr finalizePtr);

                                             
                                                                            
                                    
                                  
  uint8_t *getDataBlock(Runtime &runtime) {
                                                                         
                                                                                
    if (!runtime.hasArrayBuffer())
      hermes_fatal("Illegal access to ArrayBuffer");
    assert(attached() && "Cannot get a data block from a detached ArrayBuffer");
    return data_.get(runtime);
  }

                                  
  size_type size() const {
    assert(attached() && "Cannot get size from a detached ArrayBuffer");
    return size_;
  }

                                                                
                                                                              
                                                                      
  bool attached() const {
    return attached_;
  }

                                                      
  void freeInternalBuffer(GC &gc);

                                                                               
                                                                                
                                                             
  static ExecutionStatus detach(Runtime &runtime, Handle<JSArrayBuffer> self);

 protected:
  static void _finalizeImpl(GCCell *cell, GC &gc);
  static size_t _mallocSizeImpl(GCCell *cell);
#ifdef HERMES_MEMORY_INSTRUMENTATION
  static void _snapshotAddEdgesImpl(GCCell *cell, GC &gc, HeapSnapshot &snap);
  static void _snapshotAddNodesImpl(GCCell *cell, GC &gc, HeapSnapshot &snap);
#endif

 private:
                                                                                
                         
  static ExecutionStatus setExternalFinalizer(
      Runtime &runtime,
      Handle<JSArrayBuffer> self,
      Handle<> value);

                                                                        
  XorPtr<uint8_t, XorPtrKeyID::ArrayBufferData> data_;
  size_type size_;
  bool external_;
  bool attached_;

 public:
  JSArrayBuffer(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz);

  ~JSArrayBuffer() = default;
};

}                
}                    

#endif

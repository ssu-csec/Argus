/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_JSCALLSITE_H
#define HERMES_VM_JSCALLSITE_H

#include "hermes/VM/JSError.h"
#include "hermes/VM/JSObject.h"
#include "hermes/VM/Runtime.h"

namespace hermes {
namespace vm {

                                                                          
                            
class JSCallSite final : public JSObject {
 public:
  using Super = JSObject;
  static const ObjectVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::JSCallSiteKind;
  }

  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::JSCallSiteKind;
  }

                                                                 
                                                                 
                                                                               
                          
  static CallResult<HermesValue>
  create(Runtime &runtime, Handle<JSError> error, uint32_t stackFrameIndex);

                                                                                
                  
  static CallResult<HermesValue> getFunctionName(
      Runtime &runtime,
      Handle<JSCallSite> selfHandle);

                                                               
                  
  static CallResult<HermesValue> getFileName(
      Runtime &runtime,
      Handle<JSCallSite> selfHandle);

                                                                         
                  
  static CallResult<HermesValue> getLineNumber(
      Runtime &runtime,
      Handle<JSCallSite> selfHandle);

                                                                           
                  
  static CallResult<HermesValue> getColumnNumber(
      Runtime &runtime,
      Handle<JSCallSite> selfHandle);

                                     
                                                                            
                  
  static CallResult<HermesValue> getBytecodeAddress(
      Runtime &runtime,
      Handle<JSCallSite> selfHandle);

                                                                           
  static CallResult<HermesValue> isNative(
      Runtime &runtime,
      Handle<JSCallSite> selfHandle);

                      
                           
  static CallResult<HermesValue> getThis(
      Runtime &runtime,
      Handle<JSCallSite> selfHandle);

                      
                      
  static CallResult<HermesValue> getTypeName(
      Runtime &runtime,
      Handle<JSCallSite> selfHandle);

                      
                           
  static CallResult<HermesValue> getFunction(
      Runtime &runtime,
      Handle<JSCallSite> selfHandle);

                      
                      
  static CallResult<HermesValue> getMethodName(
      Runtime &runtime,
      Handle<JSCallSite> selfHandle);

                      
                      
  static CallResult<HermesValue> getEvalOrigin(
      Runtime &runtime,
      Handle<JSCallSite> selfHandle);

                      
                      
  static CallResult<HermesValue> isToplevel(
      Runtime &runtime,
      Handle<JSCallSite> selfHandle);

                      
                      
  static CallResult<HermesValue> isEval(
      Runtime &runtime,
      Handle<JSCallSite> selfHandle);

                      
                      
  static CallResult<HermesValue> isConstructor(
      Runtime &runtime,
      Handle<JSCallSite> selfHandle);

                                                          
                                                                          
  static CallResult<HermesValue> isAsync(
      Runtime &runtime,
      Handle<JSCallSite> selfHandle);

                                             
                                                                          
  static CallResult<HermesValue> isPromiseAll(
      Runtime &runtime,
      Handle<JSCallSite> selfHandle);

                      
                      
  static CallResult<HermesValue> getPromiseIndex(
      Runtime &runtime,
      Handle<JSCallSite> selfHandle);

  JSCallSite(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz,
      Handle<JSError> error,
      size_t stackFrameIndex);

 private:
  friend void JSCallSiteBuildMeta(const GCCell *cell, Metadata::Builder &mb);

                                                             
  static const StackTraceInfo *getStackTraceInfo(
      Runtime &runtime,
      Handle<JSCallSite> selfHandle);

  GCPointer<JSError> error_;
  size_t stackFrameIndex_;
};

}                
}                    
#endif

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_JSERROR_H
#define HERMES_VM_JSERROR_H

#include "hermes/VM/JSObject.h"
#include "hermes/VM/NativeArgs.h"
#include "hermes/VM/SmallXString.h"

namespace hermes {
namespace vm {

                                                                       
                                                                       
                                                                     
                                           
                                                                             
                                                                          
          
struct StackTraceInfo {
                                     
  CodeBlock *codeBlock;

                                                     
  uint32_t bytecodeOffset;

  StackTraceInfo(CodeBlock *codeBlock, uint32_t bytecodeOffset)
      : codeBlock(codeBlock), bytecodeOffset(bytecodeOffset) {}

  StackTraceInfo(const StackTraceInfo &) = default;

  StackTraceInfo(StackTraceInfo &&) = default;
};
using StackTrace = std::vector<StackTraceInfo>;
using StackTracePtr = std::unique_ptr<StackTrace>;

                 
class JSError final : public JSObject {
 public:
  using Super = JSObject;
  static const ObjectVTable vt;

  static constexpr CellKind getCellKind() {
    return CellKind::JSErrorKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::JSErrorKind;
  }

                             
  static PseudoHandle<JSError> create(
      Runtime &runtime,
      Handle<JSObject> prototype);
                                                                            
                                              
                                                                               
                                                                               
                                                                             
  static PseudoHandle<JSError> createUncatchable(
      Runtime &runtime,
      Handle<JSObject> prototype);

                                                                                
                                                                               
                                                                               
                                                                     
     
                                                                           
                                                       
                                                  
                                                                         
                          
  static ExecutionStatus recordStackTrace(
      Handle<JSError> selfHandle,
      Runtime &runtime,
      bool skipTopFrame = false,
      CodeBlock *codeBlock = nullptr,
      const Inst *ip = nullptr);

                                                                         
                                                                     
                                
  static ExecutionStatus setupStack(
      Handle<JSObject> selfHandle,
      Runtime &runtime);

                                                                                
  static CallResult<Handle<StringPrimitive>> toString(
      Handle<JSObject> O,
      Runtime &runtime);

                               
  static ExecutionStatus
  setMessage(Handle<JSError> selfHandle, Runtime &runtime, Handle<> message);

                                                                               
                              
  const StackTrace *getStackTrace() const {
    return stacktrace_.get();
  }

  bool catchable() const {
    return catchable_;
  }

                                                                        
                                                                         
  friend CallResult<HermesValue>
  errorStackGetter(void *, Runtime &runtime, NativeArgs args);

                                                                    
                                                                  
                                                          
  friend CallResult<HermesValue>
  errorStackSetter(void *, Runtime &runtime, NativeArgs args);

                                                                              
                                                                              
                        
                                                   
  static void popFramesUntilInclusive(
      Runtime &runtime,
      Handle<JSError> selfHandle,
      Handle<Callable> callableHandle);

                                                                          
  static OptValue<hbc::DebugSourceLocation> getDebugInfo(
      CodeBlock *codeBlock,
      uint32_t bytecodeOffset);

                                                   
  static Handle<StringPrimitive> getFunctionNameAtIndex(
      Runtime &runtime,
      Handle<JSError> selfHandle,
      size_t index);

  JSError(
      Runtime &runtime,
      Handle<JSObject> parent,
      Handle<HiddenClass> clazz,
      bool catchable)
      : JSObject(runtime, *parent, *clazz), catchable_{catchable} {}

 private:
  friend void JSErrorBuildMeta(const GCCell *cell, Metadata::Builder &mb);
  static void _finalizeImpl(GCCell *cell, GC &gc);
  static size_t _mallocSizeImpl(GCCell *cell);

  static PseudoHandle<JSError>
  create(Runtime &runtime, Handle<JSObject> prototype, bool catchable);

                                                                      
  StackTracePtr stacktrace_;

                                                                          
                                                              
                                                             
  size_t firstExposedFrameIndex_{0};

                                                                
  GCPointer<ArrayStorageSmall> domains_;

                                                                           
                                                           
  GCPointer<PropStorage> funcNames_;

                                                                          
                                                                         
                                                                                
                                                                            
                                     
  bool catchable_{true};

                                                          
                                                                        
                                   
     
                                                              
                                                                            
     
                                                                            
                               
                                                                               
                                                                        
  static ExecutionStatus constructStackTraceString_RJS(
      Runtime &runtime,
      Handle<JSError> selfHandle,
      Handle<JSObject> targetHandle,
      SmallU16String<32> &stack);

                                                                
  static CallResult<HermesValue> constructCallSitesArray(
      Runtime &runtime,
      Handle<JSError> selfHandle);

                                                                      
                                                                               
  static bool appendFunctionNameAtIndex(
      Runtime &runtime,
      Handle<JSError> selfHandle,
      size_t index,
      llvh::SmallVectorImpl<char16_t> &str);
};

}                
}                    
#endif

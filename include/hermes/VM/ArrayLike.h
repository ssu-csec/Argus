/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_ARRAYLIKE_H
#define HERMES_VM_ARRAYLIKE_H

#include "hermes/VM/CallResult.h"
#include "hermes/VM/Handle.h"
#include "hermes/VM/JSArray.h"
#include "hermes/VM/JSObject.h"
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

                                      
                                  
inline CallResult<uint64_t> getArrayLikeLength_RJS(
    Handle<JSObject> arrayLikeHandle,
    Runtime &runtime) {
  auto propRes = JSObject::getNamed_RJS(
      arrayLikeHandle, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return toLengthU64(runtime, runtime.makeHandle(std::move(*propRes)));
}

                                      
                                                                 
                                                                     
                                                               
                                                                      
                    
template <typename ElementCB>
ExecutionStatus createListFromArrayLike_RJS(
    Handle<JSObject> arrayLikeHandle,
    Runtime &runtime,
    uint64_t length,
    const ElementCB &elementCB) {
  GCScope gcScope(runtime);
  Handle<ArrayImpl> elemArray = Handle<ArrayImpl>::dyn_vmcast(arrayLikeHandle);
  MutableHandle<> iHandle{runtime, HermesValue::encodeTrustedNumberValue(0)};
  auto marker = gcScope.createMarker();
  if (LLVM_LIKELY(elemArray)) {
    for (uint64_t elemIdx = 0; elemIdx < length; ++elemIdx) {
      gcScope.flushToMarker(marker);
                                                                               
                                                                           
                                                           
      PseudoHandle<> elem = createPseudoHandle(
          elemArray->at(runtime, elemIdx).unboxToHV(runtime));
      if (LLVM_LIKELY(!elem->isEmpty())) {
        if (LLVM_UNLIKELY(
                elementCB(runtime, elemIdx, std::move(elem)) ==
                ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }
        continue;
      }
                                                            
                                                                
      iHandle = HermesValue::encodeTrustedNumberValue(elemIdx);
      CallResult<PseudoHandle<>> propRes =
          JSObject::getComputed_RJS(arrayLikeHandle, runtime, iHandle);
      if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      if (LLVM_UNLIKELY(
              elementCB(runtime, elemIdx, std::move(*propRes)) ==
              ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
    }
  } else {
                                        
    for (uint64_t elemIdx = 0; elemIdx < length; ++elemIdx) {
      gcScope.flushToMarker(marker);
      iHandle = HermesValue::encodeTrustedNumberValue(elemIdx);
      CallResult<PseudoHandle<>> propRes =
          JSObject::getComputed_RJS(arrayLikeHandle, runtime, iHandle);
      if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      if (LLVM_UNLIKELY(
              elementCB(runtime, elemIdx, std::move(*propRes)) ==
              ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
    }
  }
  return ExecutionStatus::RETURNED;
}

}                
}                    
#pragma GCC diagnostic pop

#endif                         

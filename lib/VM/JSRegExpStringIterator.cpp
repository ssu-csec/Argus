/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/JSRegExpStringIterator.h"

#include "hermes/VM/BuildMetadata.h"
#include "hermes/VM/StringPrimitive.h"

#include "JSLib/JSLibInternal.h"

namespace hermes {
namespace vm {

                                                                                
                               

const ObjectVTable JSRegExpStringIterator::vt{
    VTable(
        CellKind::JSRegExpStringIteratorKind,
        cellSize<JSRegExpStringIterator>()),
    JSRegExpStringIterator::_getOwnIndexedRangeImpl,
    JSRegExpStringIterator::_haveOwnIndexedImpl,
    JSRegExpStringIterator::_getOwnIndexedPropertyFlagsImpl,
    JSRegExpStringIterator::_getOwnIndexedImpl,
    JSRegExpStringIterator::_setOwnIndexedImpl,
    JSRegExpStringIterator::_deleteOwnIndexedImpl,
    JSRegExpStringIterator::_checkAllOwnIndexedImpl,
};

void JSRegExpStringIteratorBuildMeta(
    const GCCell *cell,
    Metadata::Builder &mb) {
  mb.addJSObjectOverlapSlots(
      JSObject::numOverlapSlots<JSRegExpStringIterator>());
  JSObjectBuildMeta(cell, mb);
  const auto *self = static_cast<const JSRegExpStringIterator *>(cell);
  mb.setVTable(&JSRegExpStringIterator::vt);
  mb.addField("iteratedRegExp", &self->iteratedRegExp_);
  mb.addField("iteratedString", &self->iteratedString_);
}

                                                                            
PseudoHandle<JSRegExpStringIterator> JSRegExpStringIterator::create(
    Runtime &runtime,
    Handle<JSObject> R,
    Handle<StringPrimitive> S,
    bool global,
    bool fullUnicode) {
  auto proto = Handle<JSObject>::vmcast(&runtime.regExpStringIteratorPrototype);

  auto *cell = runtime.makeAFixed<JSRegExpStringIterator>(
      runtime,
      proto,
      runtime.getHiddenClassForPrototype(
          *proto, numOverlapSlots<JSRegExpStringIterator>()),
      R,
      S,
      global,
      fullUnicode);
  return JSObjectInit::initToPseudoHandle(runtime, cell);
}

                                                                 
CallResult<HermesValue> JSRegExpStringIterator::nextElement(
    Handle<JSRegExpStringIterator> O,
    Runtime &runtime) {
                                   
  if (O->done_) {
                                                           
    return createIterResultObject(runtime, Runtime::getUndefinedValue(), true)
        .getHermesValue();
  }
                                       
  auto R = runtime.makeHandle(O->iteratedRegExp_);
                                      
  auto S = runtime.makeHandle(O->iteratedString_);

                                   
                                         
                                                                            

                                        
  auto matchRes = regExpExec(runtime, R, S);
  if (LLVM_UNLIKELY(matchRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto match = matchRes.getValue();

                               
  if (match.isNull()) {
                                 
    O->done_ = true;
                                                           
    return createIterResultObject(runtime, Runtime::getUndefinedValue(), true)
        .getHermesValue();
  } else {
                
    auto matchObj = runtime.makeHandle<JSObject>(match);
                                 
    if (O->global_) {
                                                           
      Handle<> zeroHandle = HandleRootOwner::getZeroValue();
      auto propRes = JSObject::getComputed_RJS(matchObj, runtime, zeroHandle);
      if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      auto matchStrRes =
          toString_RJS(runtime, runtime.makeHandle(std::move(*propRes)));
      if (matchStrRes == ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
      auto matchStr = runtime.makeHandle(std::move(*matchStrRes));

                                                   
      if (matchStr->getStringLength() == 0) {
                                                                 
        auto lastIndexRes = runtime.getNamed(R, PropCacheID::RegExpLastIndex);
        if (lastIndexRes == ExecutionStatus::EXCEPTION) {
          return ExecutionStatus::EXCEPTION;
        }
        auto lastIndex = runtime.makeHandle(std::move(*lastIndexRes));
        auto thisIndex = toLength(runtime, lastIndex);
        if (thisIndex == ExecutionStatus::EXCEPTION) {
          return ExecutionStatus::EXCEPTION;
        }
                                                                               
        double nextIndex = advanceStringIndex(
            S.get(), thisIndex->getNumberAs<uint64_t>(), O->unicode_);
                                                             
        if (setLastIndex(R, runtime, nextIndex) == ExecutionStatus::EXCEPTION) {
          return ExecutionStatus::EXCEPTION;
        }
      }
                                                            
      return createIterResultObject(runtime, matchObj, false).getHermesValue();
    }
               
    else {
                                   
      O->done_ = true;
                                                           
      return createIterResultObject(runtime, matchObj, false).getHermesValue();
    }
  }
}

}                
}                    

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_JSLIB_OBJECT_H
#define HERMES_JSLIB_OBJECT_H

#include "hermes/VM/CallResult.h"
#include "hermes/VM/HermesValue.h"
#include "hermes/VM/JSObject.h"
#include "hermes/VM/NativeArgs.h"
#include "hermes/VM/Runtime.h"

namespace hermes {
namespace vm {

                                                                     
           

CallResult<bool>
defineProperty(Runtime &runtime, NativeArgs args, PropOpFlags opFlags);

CallResult<HermesValue> getOwnPropertyDescriptor(
    Runtime &runtime,
    Handle<JSObject> object,
    Handle<> key);

CallResult<HermesValue> getPrototypeOf(Runtime &runtime, Handle<JSObject> obj);

CallResult<HermesValue> getOwnPropertyKeysAsStrings(
    Handle<JSObject> selfHandle,
    Runtime &runtime,
    OwnKeysFlags okFlags);

                                                                   
                                                   
enum class EnumerableOwnPropertiesKind {
  Key,
  Value,
  KeyValue,
};

                 
                                                                           
CallResult<HermesValue> enumerableOwnProperties_RJS(
    Runtime &runtime,
    Handle<JSObject> objHandle,
    EnumerableOwnPropertiesKind kind);

}                
}                    

#endif

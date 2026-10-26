/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_JSLIB_RUNTIMEJSONPARSER_H
#define HERMES_VM_JSLIB_RUNTIMEJSONPARSER_H

#include "hermes/Support/UTF16Stream.h"
#include "hermes/VM/Runtime.h"

namespace hermes {
namespace vm {

                                                                           
CallResult<HermesValue> runtimeJSONParse(
    Runtime &runtime,
    Handle<StringPrimitive> jsonString,
    Handle<Callable> reviver);

                                                                              
CallResult<HermesValue> runtimeJSONParseRef(Runtime &runtime, UTF16Stream &&s);

                                                                     
                         
CallResult<HermesValue> runtimeJSONStringify(
    Runtime &runtime,
    Handle<> value,
    Handle<> replacer,
    Handle<> space);

}                
}                    

#endif

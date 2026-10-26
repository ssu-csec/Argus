/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifdef HERMES_RUN_WASM
#ifndef HERMES_INST_WASM_INTRINSICS_H
#define HERMES_INST_WASM_INTRINSICS_H

#include <cassert>

namespace hermes {

namespace WasmIntrinsics {
enum Enum : unsigned char {
#define WASM_INTRINSICS(name, numArgs) __uasm##_##name,
#include "WasmIntrinsics.def"
  _count,
};

}                            

                                                          
const char *getWasmIntrinsicsName(unsigned intrinsics);

}                    

#endif                                 
#endif                   

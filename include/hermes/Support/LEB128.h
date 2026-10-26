/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_LEB128_H
#define HERMES_SUPPORT_LEB128_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/Support/raw_ostream.h"

namespace hermes {

                                                                              
                                     
void appendSignedLEB128(std::vector<uint8_t> &vector, int64_t value);
unsigned readSignedLEB128(
    llvh::ArrayRef<uint8_t> data,
    unsigned offset,
    int64_t *output);

                                                                         
                                      
void encodeSLEB128(int32_t input, llvh::raw_ostream &os, size_t minBytes = 0);

}                    

#endif                           

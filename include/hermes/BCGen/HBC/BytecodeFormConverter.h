/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BYTECODEDELTAPREPARER_H
#define HERMES_BYTECODEDELTAPREPARER_H

#include <string>
#include "hermes/BCGen/HBC/BytecodeFileFormat.h"
#include "llvh/ADT/ArrayRef.h"

namespace hermes {
namespace hbc {

                                                                              
                                                                          
                                                        
bool convertBytecodeToForm(
    llvh::MutableArrayRef<uint8_t> buffer,
    BytecodeForm targetForm,
    std::string *outError);

}                 
}                    

#endif                                  

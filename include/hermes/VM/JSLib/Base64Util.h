/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_JSLIB_BASE64UTIL_H
#define HERMES_VM_JSLIB_BASE64UTIL_H

#include "hermes/Support/OptValue.h"
#include "hermes/VM/Runtime.h"

namespace hermes {
namespace vm {

                                                                          
                                               
template <typename T>
bool base64Encode(llvh::ArrayRef<T> str, StringBuilder &builder);

                                                                          
                                                                                
                                            
template <typename T>
OptValue<uint32_t> base64DecodeOutputLength(llvh::ArrayRef<T> str);

                                                     
                                                          
                                                                             
                                            
                                   
                                                       
                                               
template <typename T>
bool base64Decode(llvh::ArrayRef<T> str, StringBuilder &builder);

}                
}                    

#endif                                

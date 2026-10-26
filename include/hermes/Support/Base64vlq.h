/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_BASE64VLQ_H
#define HERMES_SUPPORT_BASE64VLQ_H

#include "hermes/Support/OptValue.h"

#include "llvh/Support/raw_ostream.h"

#include <vector>

namespace hermes {

                                                                  
                               
namespace base64vlq {

                                                                    
               
llvh::raw_ostream &encode(llvh::raw_ostream &OS, int32_t value);

                                                                                
                                                       
                                                                       
                                                                              
               
OptValue<int32_t> decode(const char *&begin, const char *end);

}                       

}                    

#endif

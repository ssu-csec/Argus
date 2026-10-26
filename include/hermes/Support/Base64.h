/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BASE64_H
#define HERMES_BASE64_H

#include "llvh/ADT/Optional.h"
#include "llvh/ADT/StringRef.h"

namespace hermes {

                                                             
                                                                       
llvh::Optional<std::string> base64Decode(llvh::StringRef input);

                                                                          
                                    
                                                                          
llvh::Optional<std::string> parseJSONBase64DataURL(llvh::StringRef url);

}                    

#endif                   

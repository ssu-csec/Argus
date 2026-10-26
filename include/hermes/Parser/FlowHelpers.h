/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PARSER_FLOWHELPERS_H
#define HERMES_PARSER_FLOWHELPERS_H

#include "hermes/Parser/JSLexer.h"

#include <cstdint>
#include <string>
#include <vector>

namespace hermes {
class Context;
}

namespace hermes {
namespace parser {

                                                                
                                                                  
std::vector<StoredComment> getCommentsInDocBlock(
    Context &context,
    uint32_t bufferId);

                                                                         
             
bool hasFlowPragma(llvh::ArrayRef<StoredComment> comments);

                                            
                                                                    
std::string getDocBlock(llvh::ArrayRef<StoredComment> comments);

}                    
}                    

#endif

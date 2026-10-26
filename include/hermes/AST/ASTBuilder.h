/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_AST_ASTBUILDER_H
#define HERMES_AST_ASTBUILDER_H

#include "Context.h"
#include "ESTree.h"
#include "hermes/Parser/JSONParser.h"
#include "hermes/Support/SourceErrorManager.h"

#include "llvh/ADT/Optional.h"
#include "llvh/Support/Allocator.h"

namespace llvh {
class MemoryBuffer;
}                  

namespace hermes {
namespace ESTree {

using Allocator = llvh::BumpPtrAllocator;

                                                                              
                             
                                                      
                                                       
                                                                              
                                                                    
                                             
llvh::Optional<Node *> buildAST(
    Context &context,
    const parser::JSONValue *node,
    const llvh::MemoryBuffer *jsSource = nullptr);

}                    
}                    

#endif                           

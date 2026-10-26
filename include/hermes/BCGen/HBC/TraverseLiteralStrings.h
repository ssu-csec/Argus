/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_HBC_TRAVERSELITERALSTRINGS_H
#define HERMES_BCGEN_HBC_TRAVERSELITERALSTRINGS_H

#include "hermes/IR/IR.h"

#include "llvh/ADT/DenseSet.h"
#include "llvh/ADT/StringRef.h"

#include <functional>

namespace hermes {
namespace hbc {

                                                                       
                                                                             
                                                                          
                                                                          
                                                                               
                                                                               
                  

                                                                                
                                                                   
                                                             
void traverseFunctions(
    Module *M,
    std::function<bool(Function *)> shouldVisitFunction,
    std::function<void(llvh::StringRef)> traversal,
    std::function<void(llvh::StringRef)> functionSourceTraversal,
    bool stripFunctionNames);

                                                                             
                                                                             
void traverseCJSModuleNames(
    Module *M,
    std::function<bool(Function *)> shouldVisitFunction,
    std::function<void(llvh::StringRef)> traversal);

                                                                             
                                                                             
                                                                             
                                                                                
                                                                               
                                                                            
void traverseLiteralStrings(
    Module *M,
    std::function<bool(Function *)> shouldVisitFunction,
    std::function<void(llvh::StringRef, bool)> traversal);

}                 
}                    

#endif                                             

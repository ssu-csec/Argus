/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_IRGEN_IRGEN_H
#define HERMES_IRGEN_IRGEN_H

#include "hermes/AST/Context.h"
#include "hermes/AST/ESTree.h"
#include "hermes/IR/IR.h"
#include "hermes/IR/IRBuilder.h"

#include <vector>

namespace hermes {

using DeclarationFileListTy = std::vector<ESTree::ProgramNode *>;

namespace hbc {

struct LazyCompilationData {
                                
  std::shared_ptr<Context> context;

                                                                        
  SerializedScopePtr parentScope;

                                                                
  Identifier originalName;
                                                                             
                                                                                
                                                                          
                                                                             
                                              
  Identifier closureAlias;

                                                                    
  uint32_t bufferId;

                                      
  SMRange span;

                                                         
  ESTree::NodeKind nodeKind;

                                            
  bool strictMode;

                                              
  bool paramYield;

                                              
  bool paramAwait;
};
}                 

                                                    
                                                                          
                                                                            
                                                                      
bool generateIRFromESTree(
    ESTree::NodePtr node,
    Module *M,
    const DeclarationFileListTy &declFileList,
    const ScopeChain &scopeChain);

                                                                       
                                                          
                                                                                
                                                                                
                                                                  
                                                                         
                                                                
                                                                 
void generateIRForCJSModule(
    ESTree::FunctionExpressionNode *node,
    uint32_t segmentID,
    uint32_t id,
    llvh::StringRef filename,
    Module *M,
    Function *topLevelFunction,
    const DeclarationFileListTy &declFileList);

                                                                          
                                                                              
                                          
                                                                  
std::pair<Function *, Function *> generateLazyFunctionIR(
    hbc::LazyCompilationData *lazyData,
    Module *M);

}                    

#endif

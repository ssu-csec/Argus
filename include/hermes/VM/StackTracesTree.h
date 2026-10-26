/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_STACK_TRACES_TREE_H
#define HERMES_STACK_TRACES_TREE_H

#include "hermes/VM/Runtime.h"
#include "hermes/VM/StackTracesTree-NoRuntime.h"

#include <memory>

namespace hermes {
namespace vm {

#ifdef HERMES_MEMORY_INSTRUMENTATION

                                                                              
                                                                              
                                                                              
                                                                     
                                                                        
                     
   
                                                                      
                                                                             
                                                                            
   
                            
                                                         
                                                                                
                                                                        
                                       
                                                                                
                                                                       
                                                                         
                                                                              
                        
   
                                                                         
                                                                            
                                                                               
                                                                           
                                                                  
   
                                                                          
                                                                             
                                                                                
                     
struct StackTracesTree {
  StackTracesTree();

                                                                     
  void syncWithRuntimeStack(Runtime &runtime);

                               
  StackTracesTreeNode *getRootNode() const;

                                                                 
  void
  pushCallStack(Runtime &runtime, const CodeBlock *codeBlock, const Inst *ip);
                                                       
  void popCallStack();

                                                                       
                  
  StackTracesTreeNode *
  getStackTrace(Runtime &runtime, const CodeBlock *codeBlock, const Inst *ip);

                                                                              
                                                                                
                                              
  std::shared_ptr<StringSetVector> getStringTable() const {
    return strings_;
  }

                                                                         
  bool isHeadAtRoot() {
    return head_ == root_.get();
  }

 private:
  StackTracesTreeNode::SourceLoc computeSourceLoc(
      Runtime &runtime,
      const CodeBlock *codeBlock,
      uint32_t bytecodeOffset);

                                                                               
                                
  std::shared_ptr<StringSetVector> strings_;

                             
  const StringSetVector::size_type rootFunctionID_;
  const StringSetVector::size_type rootScriptNameID_;
  const StringSetVector::size_type nativeFunctionID_;
  const StringSetVector::size_type anonymousFunctionID_;

                                                                              
                      
  size_t nextNodeID_{1};

                                                                             
                                      
  std::unique_ptr<StackTracesTreeNode> root_{new StackTracesTreeNode(
      nextNodeID_++,
      nullptr,             
      {rootScriptNameID_, 0, 0, 0},
      nullptr,                
      nullptr,         
      rootFunctionID_)};

                                                                               
                            
  StackTracesTreeNode *head_;

                                                                              
                                                                         
                                                                      
                                                 
  llvh::SmallVector<std::unique_ptr<StackTracesTreeNode>, 1024> nodes_;
};

#endif                                 

}                
}                    
#endif                              

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_AST_SEMVALIDATE_H
#define HERMES_AST_SEMVALIDATE_H

#include "hermes/AST/Context.h"
#include "hermes/AST/ESTree.h"
#include "hermes/FrontEndDefs/JavaScriptDeclKind.h"
#include "hermes/Support/SourceErrorManager.h"

#include <deque>

namespace hermes {
namespace sem {

                                                                             
class FunctionInfo {
 public:
  struct VarDecl {
    using Kind = JavaScriptDeclKind;

    Kind kind;
    ESTree::IdentifierNode *identifier;

                                                                      
                                                                    
    bool needsInitializer;

                                                                         
                                         
    VarDecl(Kind k, ESTree::IdentifierNode *id)
        : kind(k), identifier(id), needsInitializer(true) {}

                                                                                
    static VarDecl withoutInitializer(
        Kind k,
        ESTree::IdentifierNode *identifier) {
      VarDecl v{k, identifier};
      v.needsInitializer = false;
      return v;
    }
  };

  using BlockDecls = llvh::SmallVector<VarDecl, 4>;

                      
  BlockDecls paramNames{};

                                         
  BlockDecls varScoped;

                                                                
  llvh::DenseMap<ESTree::Node *, std::unique_ptr<BlockDecls>> lexicallyScoped{};

  using BlockClosures = llvh::SmallVector<ESTree::FunctionDeclarationNode *, 2>;
                                                       
  llvh::DenseMap<ESTree::Node *, std::unique_ptr<BlockClosures>> closures{};

                                                                          
                                            
                                                       
  llvh::SmallVector<ESTree::ImportDeclarationNode *, 2> imports{};

                                                                            
                                                                              
                                                                              
                                                               
                                                                                
                                                                         
  bool usesArguments = false;

                                                     
  bool containsArrowFunctions = false;

                                                                         
                                                                      
                                                                          
                       
  bool containsArrowFunctionsUsingArguments = false;

                                                                      
                                         
  unsigned labelCount = 0;

                                                       
  bool hoisted{};

                                                
  unsigned allocateLabel() {
    return labelCount++;
  }
};

                                                                               
                                                                             
                                
class SemContext {
 public:
                                               
  FunctionInfo *createFunction() {
    functions_.emplace_back();
    return &functions_.back();
  }

 private:
  std::deque<FunctionInfo> functions_{};
};

                                                                              
                                      
bool validateAST(Context &astContext, SemContext &semCtx, ESTree::NodePtr root);

                                                                                
                                                                              
                                                                  
bool validateASTForParser(
    Context &astContext,
    SemContext &semCtx,
    ESTree::NodePtr root);

                                                                              
                                           
                                              
bool validateFunctionAST(
    Context &astContext,
    SemContext &semCtx,
    ESTree::NodePtr function,
    bool strict);

}                 
}                    

#endif                            

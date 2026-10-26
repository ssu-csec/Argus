/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_AST_SEMANTICVALIDATOR_H
#define HERMES_AST_SEMANTICVALIDATOR_H

#include "hermes/AST/SemValidate.h"

#include "hermes/AST/RecursiveVisitor.h"
#include "llvh/ADT/MapVector.h"

namespace hermes {
namespace sem {

using namespace hermes::ESTree;

                                                                      
void canonicalizeForBlockScoping(Context &astContext, Node *root);

                       
class FunctionContext;
class SemanticValidator;

                                                                                
           

class Keywords {
 public:
                                 
  const UniqueString *const identArguments;
                            
  const UniqueString *const identEval;
                              
  const UniqueString *const identDelete;
                            
  const UniqueString *const identThis;
                                  
  const UniqueString *const identUseStrict;
                                    
  const UniqueString *const identShowSource;
                                    
  const UniqueString *const identHideSource;
                                 
  const UniqueString *const identSensitive;
                           
  const UniqueString *const identVar;
                           
  const UniqueString *const identLet;
                             
  const UniqueString *const identConst;
          
  const UniqueString *const identPlus;
          
  const UniqueString *const identMinus;
          
  const UniqueString *const identAssign;

  Keywords(Context &astContext);
};

                                                                                
                    

                                              
class SemanticValidator {
  friend class BlockContext;
  friend class FunctionContext;

  Context &astContext_;
                                                   
  SourceErrorManager &sm_;

                                                                     
  SourceErrorManager::SaveAndBufferMessages bufferMessages_;

                                             
  SemContext &semCtx_;

                                                                              
  const unsigned initialErrorCount_;

                                       
  Keywords kw_;

                                   
  FunctionContext *funcCtx_{};

                                                  
  bool forbidAwaitExpression_{false};

                                                       
  bool forbidArguments_{false};

                                                        
  bool isFormalParams_{false};

                                                                          
                                                                            
                                                         
  bool compile_;

                                                                             
           
  static constexpr unsigned MAX_RECURSION_DEPTH =
#if defined(HERMES_LIMIT_STACK_DEPTH) && !defined(_MSC_VER)
      512
#elif defined(_MSC_VER) && defined(HERMES_SLOW_DEBUG)
      256
#elif defined(_MSC_VER)
      512
#else
      1024
#endif
      ;
                                                                              
                                                  
  unsigned recursionDepth_ = MAX_RECURSION_DEPTH;

 public:
  explicit SemanticValidator(
      Context &astContext,
      sem::SemContext &semCtx,
      bool compile);

                                         
  bool doIt(Node *rootNode);

                                                       
  bool doFunction(Node *function, bool strict);

                                                                      
                                                                              
                                                        
                                                                            
                                                                            
                           
  bool incRecursionDepth(Node *n) {
    if (LLVM_UNLIKELY(recursionDepth_ == 0))
      return false;
    --recursionDepth_;
    if (LLVM_UNLIKELY(recursionDepth_ == 0)) {
      recursionDepthExceeded(n);
      return false;
    }
    return true;
  }

                                                                          
                                                                                
                                      
  void decRecursionDepth() {
    assert(
        recursionDepth_ < MAX_RECURSION_DEPTH &&
        "recursionDepth_ cannot go negative");
    if (LLVM_LIKELY(recursionDepth_ != 0))
      ++recursionDepth_;
  }

                                                                              
                              
  void visit(Node *node) {
    visitESTreeChildren(*this, node);
  }

  void visit(ProgramNode *node);
  void visit(FunctionDeclarationNode *funcDecl);
  void visit(FunctionExpressionNode *funcExpr);
  void visit(ArrowFunctionExpressionNode *arrowFunc);

  void visit(VariableDeclaratorNode *varDecl, Node *parent);

  void visit(MetaPropertyNode *metaProp);
  void visit(IdentifierNode *identifier);

  void visit(ForInStatementNode *forIn);
  void visit(ForOfStatementNode *forOf);
  void visitForInOf(LoopStatementNode *loopNode, Node *left);

  void visit(BinaryExpressionNode *bin);
  void visit(AssignmentExpressionNode *assignment);
  void visit(UpdateExpressionNode *update);

  void visit(LabeledStatementNode *labelStmt);

  void visit(RegExpLiteralNode *regexp);

  void visit(TryStatementNode *tryStatement);

  void visit(BlockStatementNode *block);
  void visit(DoWhileStatementNode *loop);
  void visit(ForStatementNode *loop);
  void visit(WhileStatementNode *loop);
  void visit(SwitchStatementNode *switchStmt);

  void visit(BreakStatementNode *breakStmt);
  void visit(ContinueStatementNode *continueStmt);

  void visit(ReturnStatementNode *returnStmt);
  void visit(YieldExpressionNode *yieldExpr);
  void visit(AwaitExpressionNode *awaitExpr);

  void visit(UnaryExpressionNode *unaryExpr);

  void visit(ArrayPatternNode *arrayPat);

  void visit(SpreadElementNode *S, Node *parent);

  void visit(ClassExpressionNode *node);
  void visit(ClassDeclarationNode *node);
  void visit(PrivateNameNode *node);
  void visit(ClassPrivatePropertyNode *node);
  void visit(ClassPropertyNode *node);
  void visit(StaticBlockNode *node);

  void visit(ImportDeclarationNode *importDecl);
  void visit(ImportDefaultSpecifierNode *importDecl);
  void visit(ImportNamespaceSpecifierNode *importDecl);
  void visit(ImportSpecifierNode *importDecl);

  void visit(ExportNamedDeclarationNode *exportDecl);
  void visit(ExportDefaultDeclarationNode *exportDecl);
  void visit(ExportAllDeclarationNode *exportDecl);

  void visit(CoverEmptyArgsNode *CEA);
  void visit(CoverTrailingCommaNode *CTC);
  void visit(CoverInitializerNode *CI);
  void visit(CoverRestElementNode *R);
#if HERMES_PARSE_FLOW
  void visit(CoverTypedIdentifierNode *R);
  void visit(ComponentDeclarationNode *componentDecl);
  void visit(HookDeclarationNode *hookDecl);
#endif

 private:
  inline bool haveActiveContext() const {
    return funcCtx_ != nullptr;
  }

  inline FunctionContext *curFunction() {
    assert(funcCtx_ && "No active function context");
    return funcCtx_;
  }
  inline const FunctionContext *curFunction() const {
    assert(funcCtx_ && "No active function context");
    return funcCtx_;
  }

                                                                              
                                                      
                                  
                                                                 
                                      
                                                                             
                                                                         
  void
  visitFunction(FunctionLikeNode *node, Node *id, NodeList &params, Node *body);

                                                                         
                                                                        
                      
                                                                         
                                                          
  Node *scanDirectivePrologue(NodeList &body);

                                                                       
                                                                               
                                                                           
  bool isLValue(const Node *node) const;

                                                                           
  bool isValidDeclarationName(const IdentifierNode *idNode) const;

                                                                     
                                                        
                                                                            
                                                                           
            
                                                                                
            
  void validateDeclarationNames(
      FunctionInfo::VarDecl::Kind declKind,
      Node *node,
      FunctionInfo::BlockDecls *varIdents,
      FunctionInfo::BlockDecls *scopedIdents);

                                                                       
                                                                               
  void validateCatchClause(const Node *catchClause);

                                                                            
                                                                               
                        
  void validateAssignmentTarget(const Node *node);

                                                                             
                              
                                              
  void setDirectiveDerivedInfo(FunctionLikeNode *node);

                                                                       
                                                                              
                                                                
  void tryOverrideSourceVisibility(SourceVisibility newSourceVisibility);

                                                             
  static LabelDecorationBase *getLabelDecorationBase(StatementNode *node);

                                                                       
                
  void visitParamsAndBody(FunctionLikeNode *node);

                                                                           
                                           
  void visitBody(Node *body, FunctionLikeNode *func);

                                                                              
                                                               
  void visitTryHandler(TryStatementNode *tryStatement);

                                                              
  void recursionDepthExceeded(Node *n);

                                                                               
                                                                 
  void reportRedeclaredIdentifier(
      const IdentifierNode &id1,
      const IdentifierNode &id2);

                                               
  bool blockScopingEnabled() const {
    return astContext_.getCodeGenerationSettings().enableBlockScoping;
  }
};

                                                                                
               

                                                                              
          
class BlockContext {
  BlockContext(const BlockContext &) = delete;
  void operator=(const BlockContext &) = delete;

  SemanticValidator *validator_;
  FunctionContext *curFunction_;
  FunctionInfo::BlockDecls *previousScopedDecls_;
  FunctionInfo::BlockClosures *previousScopedClosures_;

                                                                        
                                                                              
                                                                                
                                                                
                                                                            
                  
  size_t varDeclaredBegin_;

 public:
  explicit BlockContext(
      SemanticValidator *validator,
      FunctionContext *curFunction,
      Node *nextScopeNode);
  ~BlockContext();

  enum class IsFunctionBody { No, Yes };
                                                                             
                                                              
                                     
                                     
     
                                                                             
                                                                              
                                                                     
  void ensureScopedNamesAreUnique(
      IsFunctionBody isFunctionBody,
      IdentifierNode *catchParam = nullptr);

 private:
                                                                         
                                                                  
                                                                
  void stopHoisting(IdentifierNode *id);
};

                                                                                
                  

                                                                             
                             
class FunctionContext {
  friend class BlockContext;

  SemanticValidator *validator_;
  FunctionContext *oldContextValue_;

 public:
  struct Label {
                              
    IdentifierNode *declarationNode;

                                                                          
                         
    StatementNode *targetStatement;
  };

                                    
  FunctionLikeNode *node;

                                                                             
                                     
  Node *body;

                                   
  sem::FunctionInfo *const semInfo;

                                              
  FunctionInfo::BlockDecls *varDecls{};

                                                                              
               
  FunctionInfo::BlockDecls *scopedDecls{};

                                                                                
                   
  FunctionInfo::BlockClosures *scopedClosures{};

                                            
  LoopStatementNode *activeLoop = nullptr;
                                                      
  StatementNode *activeSwitchOrLoop = nullptr;
                                      
  bool strictMode = false;
                                         
  SourceVisibility sourceVisibility{SourceVisibility::Default};

                                                  
  llvh::DenseMap<NodeLabel, Label> labelMap;

  explicit FunctionContext(
      SemanticValidator *validator,
      bool strictMode,
      FunctionLikeNode *node,
      Node *body,
      SourceVisibility sourceVisibility = SourceVisibility::Default);

  ~FunctionContext();

                                                                           
                                
  bool isGlobalScope() const {
    return !oldContextValue_;
  }

                                                  
  unsigned allocateLabel() {
    return semInfo->allocateLabel();
  }

                                                                             
                                                                              
                                
  void addHoistingCandidate(FunctionDeclarationNode *funDecl);

 private:
                                                    
  BlockContext functionScope_;

  using HoistingCandidateList = llvh::SmallVector<FunctionDeclarationNode *, 4>;

                                                                       
                  
  llvh::MapVector<const UniqueString *, HoistingCandidateList>
      hoistingCandidates_;

                                                                         
              
  bool functionHoistingEnabled() const {
    return !strictMode && validator_->blockScopingEnabled();
  }

                                                                           
                                                                          
                                                                                
              
  void finalizeHoisting();
};

}                 
}                    

#endif                                  

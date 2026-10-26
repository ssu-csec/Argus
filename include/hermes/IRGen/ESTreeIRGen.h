/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_IRGEN_ESTREEIRGEN_H
#define HERMES_IRGEN_ESTREEIRGEN_H

#include "IRInstrument.h"
#include "hermes/ADT/ScopedHashTable.h"
#include "hermes/AST/SemValidate.h"
#include "hermes/FrontEndDefs/NativeErrorTypes.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/IRGen/IRGen.h"
#include "hermes/Support/InternalIdentifierMaker.h"

#include "llvh/ADT/StringRef.h"
#include "llvh/Support/Debug.h"

#include <optional>

                                                                
#define DEBUG_TYPE "irgen"

using llvh::dyn_cast_or_null;

namespace hermes {
namespace irgen {

                       
class SurroundingTry;
class FunctionContext;
class ESTreeIRGen;

using VarDecl = sem::FunctionInfo::VarDecl;

                                                                                
                         

                                                                    
Instruction *loadGlobalObjectProperty(
    IRBuilder &builder,
    GlobalObjectProperty *prop,
    bool inhibitThrow = false);

                                        
inline Identifier getNameFieldFromID(const ESTree::Node *ID) {
  return Identifier::getFromPointer(cast<ESTree::IdentifierNode>(ID)->_name);
}

                                                                  
bool isConstantExpr(ESTree::Node *node);

                                                
using NameTableTy = hermes::ScopedHashTable<Identifier, Value *>;
using NameTableScopeTy = hermes::ScopedHashTableScope<Identifier, Value *>;

                                                                                
                  

                                                                              
              
class EnterBlockScope {
  friend class FunctionContext;

 public:
  explicit EnterBlockScope(FunctionContext *currentContext);
  ~EnterBlockScope();

 private:
  FunctionContext *const currentContext_;
  ScopeDesc *const oldIRScopeDesc_;
  ScopeCreationInst *const oldIRScope_;
  NameTableScopeTy *const oldBlockScope_;
  NameTableScopeTy blockScope_;
};

                                                                                
                  

                                                                
                                                                 
                                                                           
                                                                          
                                                                            
                                                                        
struct GotoLabel {
  BasicBlock *breakTarget = nullptr;
  BasicBlock *continueTarget = nullptr;
                                                                      
                                                                  
  SurroundingTry *surroundingTry = nullptr;
};

                                                                              
                                                                         
                     
class FunctionContext {
  friend class EnterBlockScope;

                                                            
  ESTreeIRGen *const irGen_;

                                                    
  sem::FunctionInfo *const semInfo_;

                                                                  
  FunctionContext *oldContext_;

                                                                         
                                                                            
  IRBuilder::SaveRestore builderSaveState_;

                                                                      
                  
  llvh::SmallVector<GotoLabel, 2> labels_;

                                                                               
                     
  void setupFunctionScope(EnterBlockScope *enterBlockScope);

 public:
                                                               
  Function *const function;
  bool asyncGeneratorBody = false;

                                                            
  SurroundingTry *surroundingTry = nullptr;

                                                                            
  NameTableScopeTy *functionScope;

                                                              
  NameTableScopeTy *blockScope;

                                                                         
  AllocStackInst *globalReturnRegister{nullptr};

  InternalIdentifierMaker anonymousIDs_;

                                                                            
                                                               
  CreateArgumentsInst *createArgumentsInst{};

                                                                              
                                                                              
                                                                           
                                                                       
  Variable *capturedThis{};
                                                                           
  Variable *derivedThis{};

                                                                            
                                                                             
                                                               
                                                                       
                        
  Value *capturedNewTarget{};

                                                                             
                                             
  Variable *capturedArguments{};

                                                                                
                                            
  EnterBlockScope enterFunctionScope;

                                                                            
                                                                
  using SeparateFunctionScope = std::optional<EnterBlockScope>;

                                                         
  SeparateFunctionScope enterParamScope;

                                                               
  SeparateFunctionScope enterVarScope;

                                                                    
                       
  SeparateFunctionScope enterTopLevelLexicalDeclarationsScope;

                                                                           
                                                                               
               
  void enterOptionalFunctionScope(
      SeparateFunctionScope FunctionContext::*optScope) {
    assert(!(this->*optScope) && "can't enter scope twice.");
    (this->*optScope).emplace(this);
    setupFunctionScope(&*(this->*optScope));
  }

                                                                           
                                                     
                                                         
                                                              
  FunctionContext(
      ESTreeIRGen *irGen,
      Function *function,
      sem::FunctionInfo *semInfo);

  ~FunctionContext();

                                                         
  FunctionContext *getPreviousContext() const {
    return oldContext_;
  }

                                                                       
              
  sem::FunctionInfo *getSemInfo() {
    assert(semInfo_ && "semInfo is not set");
    return semInfo_;
  }

                                                                            
                                  
  Identifier genAnonymousLabelName(llvh::StringRef const hint);

                                                                               
                                                                            
                                                                               
                                                                               
                                                    
  void initLabel(
      ESTree::LabelDecorationBase *LDB,
      BasicBlock *breakTarget,
      BasicBlock *continueTarget) {
    auto &label = labels_[LDB->getLabelIndex()];
    label.breakTarget = breakTarget;
    label.continueTarget = continueTarget;
    label.surroundingTry = surroundingTry;
  }

                                          
  const GotoLabel &label(ESTree::LabelDecorationBase *LDB) {
    auto &label = labels_[LDB->getLabelIndex()];
    assert(
        (label.breakTarget || label.continueTarget) &&
        "accessing an uninitialized label");
    return label;
  }
};

enum class ControlFlowChange { Break, Continue };

                                                                              
                
class SurroundingTry {
  FunctionContext *const functionContext_;

 public:
                                                              
  SurroundingTry *const outer;
                                                               
                                                                         
                                                
  ESTree::Node *const node;
                                                                    
  SMLoc const tryEndLoc{};

                                                                       
                                                                            
                                   
  using GenFinalizerCB = std::function<
      void(ESTree::Node *, ControlFlowChange cfc, BasicBlock *continueTarget)>;

                                                                            
                
  GenFinalizerCB genFinalizer{};

  SurroundingTry(
      FunctionContext *functionContext,
      ESTree::Node *node,
      SMLoc tryEndLoc = {},
      GenFinalizerCB genFinalizer = {})
      : functionContext_(functionContext),
        outer(functionContext->surroundingTry),
        node(node),
        tryEndLoc(tryEndLoc),
        genFinalizer(std::move(genFinalizer)) {
            
    functionContext->surroundingTry = this;
  }

  ~SurroundingTry() {
           
    functionContext_->surroundingTry = outer;
  }
};

                                                                                
             

                                                                            
                                                             
class LReference {
 public:
  enum class Kind {
                                         
    Empty,
                                         
    Member,
                                                     
    VarOrGlobal,
                                                                       
    Error,
                                        
    Destructuring,
                                                                                
    PrivateField,
  };

  LReference(
      Kind kind,
      ESTreeIRGen *irgen,
      bool declInit,
      Value *base,
      Value *property,
      SMLoc loadLoc)
      : kind_(kind), irgen_(irgen), declInit_(declInit) {
    base_ = base;
    property_ = property;
    loadLoc_ = loadLoc;
  }

  LReference(ESTreeIRGen *irgen, bool declInit, ESTree::PatternNode *target)
      : kind_(Kind::Destructuring), irgen_(irgen), declInit_(declInit) {
    destructuringTarget_ = target;
  }

  bool isEmpty() const {
    return kind_ == Kind::Empty;
  }

  Value *emitLoad();
  void emitStore(Value *value);

                                                                            
                                                                            
                                            
  bool canStoreWithoutSideEffects() const;

  Variable *castAsVariable() const;
  GlobalObjectProperty *castAsGlobalObjectProperty() const;

 private:
                       
  Kind kind_;

                                             
  ESTreeIRGen *irgen_;

                                                                              
                   
  bool declInit_;

  union {
    struct {
                                                               
      Value *base_;
                                                                              
                               
      Value *property_;
    };

                                        
    ESTree::PatternNode *destructuringTarget_;
  };

                                                                             
                  
  SMLoc loadLoc_;

                                             
  IRBuilder &getBuilder();
};

                                                                                
              

                                                           
class ESTreeIRGen {
  friend class EnterBlockScope;
  friend class FunctionContext;
  friend class LReference;

  using BasicBlockListType = llvh::SmallVector<BasicBlock *, 4>;

                                     
  Module *Mod;
                                                   
  IRBuilder Builder;
                              
  IRInstrument instrumentIR_;
                             
  ESTree::Node *Root;
                                                                 
  const DeclarationFileListTy &DeclarationFileList;
                                                                    
                        
  FunctionContext *topLevelContext{};
                                                                             
                                          
  FunctionContext *functionContext_{};
                                                                               
                                                               
  NameTableTy nameTable_{};

                                                                                
           
  SerializedScopePtr lexicalScopeChain;

                                                
  const Identifier identEval_;

                                               
  const Identifier identLet_;

                                                    
  const Identifier identDefaultExport_;

                                                                       
                                                                     
  ScopeDesc *currentIRScopeDesc_{};

                                                           
  ScopeCreationInst *currentIRScope_{};

                                                                               
                               
  Identifier genAnonymousLabelName(llvh::StringRef hint) {
    return curFunction()->genAnonymousLabelName(hint);
  }

                                                                               
                               
  Identifier genAnonymousLabelName(Identifier hint) {
    return genAnonymousLabelName(hint.isValid() ? hint.str() : "anonymous");
  }

 public:
  explicit ESTreeIRGen(
      ESTree::Node *root,
      const DeclarationFileListTy &declFileList,
      Module *M,
      const ScopeChain &scopeChain);

                                                
  void doIt();

                                                   
  void doCJSModule(
      Function *topLevelFunction,
      sem::FunctionInfo *semInfo,
      uint32_t segmentID,
      uint32_t id,
      llvh::StringRef filename);

                                                
                                                                        
  std::pair<Function *, Function *> doLazyFunction(
      hbc::LazyCompilationData *lazyData);

                                                                                
                                                                               
                                                   
     
           
                      
                                            
                           
              
     
                                                                                
                                                                              
                                     
  static Instruction *genRaiseNativeError(
      IRBuilder &builder,
      NativeErrorTypes id,
      llvh::StringRef msg);

                                                                            
              
  static Function *genSyntaxErrorFunction(
      Module *M,
      ScopeDesc *scopeDesc,
      Identifier originalName,
      SMRange sourceRange,
      llvh::StringRef error);

 private:
                      
        

                                                                              
                                 
  void genBody(ESTree::NodeList &Body);

                                                                        
  void genFunctionBody(ESTree::Node *stmt);

                                                                        
  void genCatchHandler(ESTree::Node *stmt);

                                                                                
                                   
  void genScopelessBlockOrStatement(ESTree::Node *stmt);

  enum class IsLoopBody { No, Yes };

                                                   
  void genBlockStatement(ESTree::BlockStatementNode *BS, IsLoopBody isLoopBody);

                                              
  void genStatement(ESTree::Node *stmt, IsLoopBody isLoopBody);

                                                                         
                                               
  void genExpressionWrapper(ESTree::Node *expr);

  void genVariableDeclaration(ESTree::VariableDeclarationNode *declaration);
  void genVariableDeclarator(
      ESTree::NodeLabel kind,
      ESTree::VariableDeclaratorNode *declarator);

  void genIfStatement(ESTree::IfStatementNode *IfStmt);
  void genReturnStatement(ESTree::ReturnStatementNode *RetStmt);
  void genForInStatement(ESTree::ForInStatementNode *ForInStmt);
  void genForOfStatement(ESTree::ForOfStatementNode *forOfStmt);
  void genForAwaitOfStatement(ESTree::ForOfStatementNode *forOfStmt);

                                                     
                                     
                                                      
                                                              
                                                      
                                                                       
                                   
  void genForWhileLoops(
      ESTree::LoopStatementNode *loop,
      ESTree::Node *init,
      ESTree::Node *preTest,
      ESTree::Node *postTest,
      ESTree::Node *update,
      ESTree::Node *body);

  void genSwitchStatement(ESTree::SwitchStatementNode *switchStmt);

                                                               
                                                                              
                                             
                                              
  bool areAllCasesConstant(
      ESTree::SwitchStatementNode *switchStmt,
      llvh::SmallVectorImpl<Literal *> &caseLiterals);

                                                                     
  void genConstSwitchStmt(
      ESTree::SwitchStatementNode *switchStmt,
      llvh::SmallVectorImpl<Literal *> &caseLiterals);

  void genImportDeclaration(ESTree::ImportDeclarationNode *importDecl);

  void genExportNamedDeclaration(
      ESTree::ExportNamedDeclarationNode *exportDecl);
  void genExportDefaultDeclaration(
      ESTree::ExportDefaultDeclarationNode *exportDecl);
  void genExportAllDeclaration(ESTree::ExportAllDeclarationNode *exportDecl);

        

 private:
                       
        

                                             
                                                                   
                                                                               
                                                                            
                             
  Value *genExpression(ESTree::Node *expr, Identifier nameHint = Identifier{});

                                                                          
                                                                     
                                                                       
                                                                                
                                                                             
                                                            
  void genExpressionBranch(
      ESTree::Node *expr,
      BasicBlock *onTrue,
      BasicBlock *onFalse,
      BasicBlock *onNullish);

                                                                  
                                       
                                                                      
  Value *genArrayFromElements(ESTree::NodeList &list);

  Value *genObjectExpr(ESTree::ObjectExpressionNode *Expr);
  Value *genArrayExpr(ESTree::ArrayExpressionNode *Expr);
  Value *genCallExpr(ESTree::CallExpressionNode *call);

                                                       
                                                                       
                                                                       
                                                                  
                        
  Value *genOptionalCallExpr(
      ESTree::OptionalCallExpressionNode *call,
      BasicBlock *shortCircuitBB);

                                                                             
                                          
                                           
  Value *
  emitCall(ESTree::CallExpressionLikeNode *call, Value *callee, Value *thisVal);

  struct MemberExpressionResult {
                                        
    Value *result;
                                                  
    Value *base;
  };

  enum class MemberExpressionOperation {
    Load,
    Delete,
  };

                                          
                                                                      
                                                                 
                                                                   
                                                  
  MemberExpressionResult genMemberExpression(
      ESTree::MemberExpressionNode *Mem,
      MemberExpressionOperation op);

                                                                             
                                                                       
                                                                       
                                                                  
                        
                                                                      
                                                                 
                                                                   
                                                  
  MemberExpressionResult genOptionalMemberExpression(
      ESTree::OptionalMemberExpressionNode *mem,
      BasicBlock *shortCircuitBB,
      MemberExpressionOperation op);

                                                                   
                    
  Value *genCallEvalExpr(ESTree::CallExpressionNode *call);

  Value *genNewExpr(ESTree::NewExpressionNode *N);
  Value *genAssignmentExpr(ESTree::AssignmentExpressionNode *AE);
  Value *genLogicalAssignmentExpr(
      ESTree::AssignmentExpressionNode *AE,
      BinaryOperatorInst::OpKind AssignmentKind,
      LReference lref,
      Identifier nameHint);
  Value *genConditionalExpr(ESTree::ConditionalExpressionNode *C);
  Value *genSequenceExpr(ESTree::SequenceExpressionNode *Sq);
  Value *genYieldExpr(ESTree::YieldExpressionNode *Y);
  Value *genYieldStarExpr(ESTree::YieldExpressionNode *Y);
  Value *genAwaitExpr(ESTree::AwaitExpressionNode *A);
  Value *genBinaryExpression(ESTree::BinaryExpressionNode *bin);
  Value *genUnaryExpression(ESTree::UnaryExpressionNode *U);
  Value *genUpdateExpr(ESTree::UpdateExpressionNode *updateExpr);
  Value *genLogicalExpression(ESTree::LogicalExpressionNode *logical);

                                                                                
                          
                                                                           
  Value *genYieldOrAwaitExpr(Value *value);
  Value *genAwaitValue(Value *value);

                                                                       
                                                 
  void genLogicalExpressionBranch(
      ESTree::LogicalExpressionNode *logical,
      BasicBlock *onTrue,
      BasicBlock *onFalse,
      BasicBlock *onNullish);

                                                
                                                                 
                                              
  Value *genIdentifierExpression(
      ESTree::IdentifierNode *Iden,
      bool afterTypeOf);

  Value *genMetaProperty(ESTree::MetaPropertyNode *MP);

                                                                           
                                                      
  Value *genTemplateLiteralExpr(ESTree::TemplateLiteralNode *Expr);

                                                                             
                                                                             
                                                            
  Value *genTaggedTemplateExpr(ESTree::TaggedTemplateExpressionNode *Expr);

                                                                         
  enum class GenFinally { No, Yes };

                                                              
                                                                             
                                                                                
                                                                    
                                                                              
                                                                            
               
                                                                           
                                                                                
  Value *genResumeGenerator(
      GenFinally genFinally,
      AllocStackInst *isReturn,
      BasicBlock *nextBB,
      AllocStackInst *received = nullptr);

  Value *genRegExpLiteral(ESTree::RegExpLiteralNode *RE);

        

 private:
                               
        

                                                  
  void genTryStatement(ESTree::TryStatementNode *tryStmt);

                                                
                                                                       
                                                                         
                                                   
                                                                               
                                                                                
                         
                                                                           
                                                                               
                                                                              
                                 
                                                       
                                                                                
                                                                       
                    
                                            
  template <typename EB, typename EF, typename EH>
  BasicBlock *emitTryCatchScaffolding(
      BasicBlock *nextBlock,
      EB emitBody,
      EF emitNormalCleanup,
      EH emitHandler);

                                                                         
                                                     
                            
  CatchInst *prepareCatch(ESTree::CatchClauseNode *catchHandler);

                                                                   
                                                                
                               
                                                                             
                                          
                                                                                
                                                                 
                                                                             
                   
  void genFinallyBeforeControlChange(
      SurroundingTry *sourceTry,
      SurroundingTry *targetTry,
      ControlFlowChange cfc,
      BasicBlock *continueTarget = nullptr);

        

 private:
                     
        

                                            
  void genFunctionDeclaration(ESTree::FunctionDeclarationNode *func);

                                         
  Value *genFunctionExpression(
      ESTree::FunctionExpressionNode *FE,
      Identifier nameHint);

                                              
  Value *genArrowFunctionExpression(
      ESTree::ArrowFunctionExpressionNode *AF,
      Identifier nameHint);

                                                                           
                                      
                                                                               
                                                  
                                                                          
                                                                          
                                                                        
                                                                    
                                                                               
                       
                                                                               
                              
  Function *genES5Function(
      Identifier originalName,
      Variable *lazyClosureAlias,
      ESTree::FunctionLikeNode *functionNode,
      bool isGeneratorInnerFunction = false);

                                                                                
                                                                            
                                            
                                                                               
                                                  
                                                                          
                                                                          
                                                                        
                                                                    
                                                                               
                       
                                 
  Function *genGeneratorFunction(
      Identifier originalName,
      Variable *lazyClosureAlias,
      ESTree::FunctionLikeNode *functionNode);

                                                            
                                                                     
                                         
                                                                              
  void setupLazyScope(
      ESTree::FunctionLikeNode *functionNode,
      Function *function,
      ESTree::BlockStatementNode *bodyBlock);

                                                                            
                                                                             
                                         
                                          
                               
                                                                               
                                                                               
                                                  
                                                                          
                                                                          
                                                                        
                                                                    
                                                                               
                       
                                 
  Function *genAsyncFunction(
      Identifier originalName,
      Variable *lazyClosureAlias,
      ESTree::FunctionLikeNode *functionNode);

                                                                                  
                               
    
                                           
                
                         
                              
    
                                                                              
                                                                         
                                                                                
                                                                

                                                                         
                                                                              
                                                                              
                                                                             
                
                             
     
                                                               
  void emitFunctionPreamble(BasicBlock *entry);

                                                                          
                                                                              
                                                                                
                                                
  void initCaptureStateInES5Function();

                                                                         
                                                                                
                                                                         
                                                                           
                                                                            
                                                  
  enum class DoEmitParameters { No, Yes, YesMultiScopes };

                                                                  
     
                                                                           
                               
                                     
                
                                                                    
                                                                         
     
                                                                              
                                        
  void emitTopLevelDeclarations(
      ESTree::FunctionLikeNode *funcNode,
      ESTree::Node *body,
      DoEmitParameters doEmitParameters);

    
                                                                                  

                                                                            
                                                                            
                          
  void createNewBinding(
      ScopeDesc *scopeDesc,
      VarDecl::Kind kind,
      ESTree::Node *id,
      bool needsInitializer,
      Value *init = nullptr);

                                                                             
                   
  void createScopeBindings(ScopeDesc *scopeDesc, ESTree::Node *containingNode);

                                                                            
                
  void genFunctionDeclarations(ESTree::Node *containingNode);

                                                                       
               
                                                                         
                                                                             
                                                                  
             
                                         
                
  void emitParameters(
      ESTree::FunctionLikeNode *funcNode,
      bool hasParamExpressions);

                                                           
                                                                                
                               
  uint32_t countExpectedArgumentsIncludingThis(
      ESTree::FunctionLikeNode *funcNode);

                                                                              
                                                                               
                                                         
                                                                               
                                                           
  void emitFunctionEpilogue(Value *returnValue);

                                                                       
                               
  static void genDummyFunction(Function *dummy);

        

 private:
  inline FunctionContext *curFunction() {
    assert(functionContext_ && "No active function context");
    return functionContext_;
  }

                                                                             
                                                                             
                                                    
                                                                                
                                                        
  std::pair<Value *, bool> declareVariableOrGlobalProperty(
      ScopeDesc *inScope,
      VarDecl::Kind declKind,
      Identifier name);

                                                                     
  GlobalObjectProperty *declareAmbientGlobalProperty(Identifier name);

                                                                           
                                        
  void processDeclarationFile(ESTree::ProgramNode *programNode);

                                                                             
                                                                               
                                                                          
                                        
                                                                            
                                                 
  Value *ensureVariableExists(ESTree::IdentifierNode *id);

                                                                         
                                                                             
  Value *genMemberExpressionProperty(ESTree::MemberExpressionLikeNode *Mem);

                                                                            
                                                                          
                                                                          
                                                                  
  bool canCreateLRefWithoutSideEffects(ESTree::Node *target);

                                                                  
                                     
                                                                       
                                                                        
                  
  LReference createLRef(ESTree::Node *node, bool declInit);

                                                                              
           
  Value *genHermesInternalCall(
      llvh::StringRef name,
      Value *thisValue,
      ArrayRef<Value *> args);

                              
  Value *genBuiltinCall(
      BuiltinMethod::Enum builtinIndex,
      ArrayRef<Value *> args);

                                                                               
                                              
  void emitEnsureObject(Value *value, llvh::StringRef message);

                                           
  Value *emitIteratorSymbol();

                                                           
  struct IteratorRecordSlow {
    Value *iterator;
    Value *nextMethod;
  };

                              
                                                                                
     
                                                                           
                                               
     
                                                                          
                                                             
     
                                    
  IteratorRecordSlow emitGetIteratorSlow(Value *obj);

                               
                                                                                 
     
                                                                         
             
     
                                
  Value *emitIteratorNextSlow(IteratorRecordSlow iteratorRecord);

                                   
                                                                                     
     
                                
  Value *emitIteratorCompleteSlow(Value *iterResult);

                                
                                                                                  
     
                                 
  Value *emitIteratorValueSlow(Value *iterResult);

                                
                                                                                  
     
                                                                     
                                                                             
                                          
  void emitIteratorCloseSlow(
      IteratorRecordSlow iteratorRecord,
      bool ignoreInnerException);

                                                           
  struct IteratorRecord {
                                              
                                                  
    AllocStackInst *iterStorage;
                                                                       
                                                     
    AllocStackInst *sourceOrNext;
  };

                                                                              
                  
  IteratorRecord emitGetIterator(Value *obj);

                                                                          
                                            
  Value *emitIteratorNext(IteratorRecord iteratorRecord) {
    return Builder.createIteratorNextInst(
        iteratorRecord.iterStorage, iteratorRecord.sourceOrNext);
  }

                                                                            
                                                                           
                                                      
  Value *emitIteratorComplete(IteratorRecord iteratorRecord) {
    return Builder.createBinaryOperatorInst(
        Builder.createLoadStackInst(iteratorRecord.iterStorage),
        Builder.getLiteralUndefined(),
        BinaryOperatorInst::OpKind::StrictlyEqualKind);
  }

                                                                         
                                  
                                                                              
  Value *emitIteratorClose(
      IteratorRecord iteratorRecord,
      bool ignoreInnerException) {
    return Builder.createIteratorCloseInst(
        iteratorRecord.iterStorage, ignoreInnerException);
  }

                                                                   
                    
  void emitDestructuringAssignment(
      bool declInit,
      ESTree::PatternNode *target,
      Value *source);

                                                                 
  void emitDestructuringArray(
      bool declInit,
      ESTree::ArrayPatternNode *targetPat,
      Value *source);

                                                                               
                                                                               
                      
  struct SharedExceptionHandler {
                                                           
    AllocStackInst *exc = nullptr;
                                                    
    BasicBlock *exceptionBlock = nullptr;
                                                                           
    bool emittedTry = false;
  };

  void emitRestElement(
      bool declInit,
      ESTree::RestElementNode *rest,
      IteratorRecord iteratorRecord,
      AllocStackInst *iteratorDone,
      SharedExceptionHandler *handler);

                                                                       
  template <typename EB>
  void emitTryWithSharedHandler(SharedExceptionHandler *handler, EB emitBody);

                                                                  
  void emitDestructuringObject(
      bool declInit,
      ESTree::ObjectPatternNode *target,
      Value *source);

                                                                     
                                                                             
                                                                               
  void emitRestProperty(
      bool declInit,
      ESTree::RestElementNode *rest,
      const llvh::SmallVectorImpl<Value *> &excludedItems,
      Value *source);

                                                                  
                                                                            
                                                       
                                                                    
  Value *emitOptionalInitialization(
      Value *value,
      ESTree::Node *init,
      Identifier nameHint);

 private:
                                                                              
                  
  SerializedScopePtr resolveScopeIdentifiers(const ScopeChain &chain);

                                                                  
  SerializedScopePtr saveScopeChain(ScopeDesc *S) {
    return serializeScope(S, true);
  }

                                                                  
                                                                    
  SerializedScopePtr serializeScope(ScopeDesc *S, bool includeGlobal);

  ScopeDesc *newScopeDesc() {
    return currentIRScopeDesc_->createInnerScope();
  }

                                                                             
                                                          
  Identifier genAnonymousFunctionNameIfNeeded(Identifier name) {
    if (LLVM_LIKELY(
            name.isValid() ||
            !Mod->getContext()
                 .getCodeGenerationSettings()
                 .generateNameForUnnamedFunctions)) {
      return name;
    }

                                                                          
    return genAnonymousLabelName(
        std::string("anonFunc@") +
        curFunction()->function->getOriginalOrInferredName().c_str());
  }

  enum class AlreadyEmitted { No, Yes };
  llvh::DenseMap<
      ESTree::FunctionDeclarationNode *,
      std::pair<Function *, AlreadyEmitted>>
      functionForDecl;

                                                                               
                                                                               
                                                             
  void emitCreateFunction(ESTree::FunctionDeclarationNode *func);

                                                                             
                                                                
                                                 
             
                                 
               
                                                                            
     
                                                                         
                                                      
  void hoistCreateFunctions(ESTree::Node *containingNode);

                                                                    
                                                             
                               
                                                                          
                            
                                                  
  Instruction *emitLoad(Value *from, bool inhibitThrow = false);

                                                                         
                                       
                                                             
                               
                                                                           
                                  
                                                   
  Instruction *emitStore(Value *storedValue, Value *ptr, bool declInit);

                                                                           
                                                                              
                                             
                                                     
                                   
  void newDeclarativeEnvironment();

                            
     
                                                
                                                                 
                                                                     
                                                                                
     
                             
                                                                
  void blockDeclarationInstantiation(ESTree::Node *containingNode);
};

template <typename EB, typename EF, typename EH>
BasicBlock *ESTreeIRGen::emitTryCatchScaffolding(
    BasicBlock *nextBlock,
    EB emitBody,
    EF emitNormalCleanup,
    EH emitHandler) {
  auto *function = Builder.getFunction();

  auto *catchBlock = Builder.createBasicBlock(function);
  if (!nextBlock)
    nextBlock = Builder.createBasicBlock(function);
  auto *tryBodyBlock = Builder.createBasicBlock(function);

                                                           
  Builder.createTryStartInst(tryBodyBlock, catchBlock);
  Builder.setInsertionBlock(tryBodyBlock);

                                    
  emitBody();

                                
  auto *tryEndBlock = Builder.createBasicBlock(function);
  Builder.createBranchInst(tryEndBlock);
  Builder.setInsertionBlock(tryEndBlock);
  Builder.createTryEndInst();

  emitNormalCleanup();

  Builder.createBranchInst(nextBlock);

                                      
  Builder.setInsertionBlock(catchBlock);

  emitHandler(nextBlock);

  return nextBlock;
}

template <typename EB>
void ESTreeIRGen::emitTryWithSharedHandler(
    hermes::irgen::ESTreeIRGen::SharedExceptionHandler *handler,
    EB emitBody) {
  emitTryCatchScaffolding(
      nullptr,
                  
      emitBody,
                           
      []() {},
                     
      [this, handler](BasicBlock *nextBlock) {
        Builder.createStoreStackInst(Builder.createCatchInst(), handler->exc);
        Builder.createBranchInst(handler->exceptionBlock);
        Builder.setInsertionBlock(nextBlock);
      });
  handler->emittedTry = true;
}

}                   
}                    

#endif                              

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "ESTreeIRGen.h"

#include "llvh/ADT/SmallString.h"

#include <variant>

namespace hermes {
namespace irgen {

                                                                                
                  

FunctionContext::FunctionContext(
    ESTreeIRGen *irGen,
    Function *function,
    sem::FunctionInfo *semInfo)
    : irGen_(irGen),
      semInfo_(semInfo),
      oldContext_(irGen->functionContext_),
      builderSaveState_(irGen->Builder),
      function(function),
      anonymousIDs_(function->getContext().getStringTable()),
      enterFunctionScope(this) {
  setupFunctionScope(&enterFunctionScope);
  irGen->functionContext_ = this;
  irGen->currentIRScopeDesc_ = function->getFunctionScopeDesc();

                                                                              
                                                    
  irGen->currentIRScope_ = nullptr;

                                                                        
  this->capturedNewTarget = irGen->Builder.getLiteralUndefined();

                                                                            
                                                                            
                                                                               
  if (function->getDefinitionKind() == Function::DefinitionKind::ES6Arrow &&
      oldContext_) {
    capturedThis = oldContext_->capturedThis;
    derivedThis = oldContext_->derivedThis;
    capturedNewTarget = oldContext_->capturedNewTarget;
    capturedArguments = oldContext_->capturedArguments;
  }

  if (semInfo_) {
                                                                             
                                                                                
                                                                               
               
    labels_.resize(semInfo_->labelCount);
  }
}

void FunctionContext::setupFunctionScope(EnterBlockScope *scope) {
  functionScope = &scope->blockScope_;
  blockScope = functionScope;
}

FunctionContext::~FunctionContext() {
  irGen_->functionContext_ = oldContext_;
  irGen_->Builder.setCurrentSourceLevelScope(irGen_->currentIRScopeDesc_);
}

Identifier FunctionContext::genAnonymousLabelName(llvh::StringRef hint) {
  return anonymousIDs_.next(hint);
}

                                                                                
                  
EnterBlockScope::EnterBlockScope(FunctionContext *currentContext)
    : currentContext_(currentContext),
      oldIRScopeDesc_(currentContext->irGen_->currentIRScopeDesc_),
      oldIRScope_(currentContext->irGen_->currentIRScope_),
      oldBlockScope_(currentContext->blockScope),
      blockScope_(currentContext->irGen_->nameTable_) {
  currentContext->blockScope = &blockScope_;
}

EnterBlockScope::~EnterBlockScope() {
  ESTreeIRGen *irgen = currentContext_->irGen_;
  currentContext_->blockScope = oldBlockScope_;
  irgen->currentIRScope_ = oldIRScope_;
  irgen->currentIRScopeDesc_ = oldIRScopeDesc_;
  irgen->Builder.setCurrentSourceLevelScope(irgen->currentIRScopeDesc_);
}

                                                                                
              

void ESTreeIRGen::genFunctionDeclaration(
    ESTree::FunctionDeclarationNode *func) {
                                   
  Identifier functionName = getNameFieldFromID(func->_id);
  LLVM_DEBUG(llvh::dbgs() << "IRGen function \"" << functionName << "\".\n");

  Function *newFunc = func->_generator
      ? genGeneratorFunction(functionName, nullptr, func)
      : func->_async ? genAsyncFunction(functionName, nullptr, func)
                     : genES5Function(functionName, nullptr, func);

  functionForDecl[func] = {newFunc, AlreadyEmitted::No};
}

void ESTreeIRGen::emitCreateFunction(ESTree::FunctionDeclarationNode *func) {
  Identifier functionName = getNameFieldFromID(func->_id);

  auto it = functionForDecl.find(func);
  assert(it != functionForDecl.end() && "all inner functions should be known");

  if (it->second.second == AlreadyEmitted::Yes) {
    return;
  }

  it->second.second = AlreadyEmitted::Yes;

  auto *funcStorage = nameTable_.lookup(functionName);
  assert(
      funcStorage && "function declaration variable should have been hoisted");

                                                                              
  auto *newClosure =
      Builder.createCreateFunctionInst(it->second.first, currentIRScope_);

  emitStore(newClosure, funcStorage, true);
}

void ESTreeIRGen::hoistCreateFunctions(ESTree::Node *containingNode) {
  const auto &closures = curFunction()->getSemInfo()->closures;
  auto it = closures.find(containingNode);
  if (it == closures.end()) {
    return;
  }

  for (ESTree::FunctionDeclarationNode *funcDecl : *it->second) {
    emitCreateFunction(funcDecl);
  }
}

Value *ESTreeIRGen::genFunctionExpression(
    ESTree::FunctionExpressionNode *FE,
    Identifier nameHint) {
  LLVM_DEBUG(
      llvh::dbgs()
      << "Creating anonymous closure. "
      << Builder.getInsertionBlock()->getParent()->getInternalName() << ".\n");

  std::variant<std::monostate, NameTableScopeTy, EnterBlockScope> newScope;

  if (!Mod->getContext().getCodeGenerationSettings().enableBlockScoping) {
    newScope.emplace<NameTableScopeTy>(nameTable_);
  } else {
    newScope.emplace<EnterBlockScope>(curFunction());
    newDeclarativeEnvironment();
  }
  Variable *tempClosureVar = nullptr;

  Identifier originalNameIden = nameHint;
  if (FE->_id) {
    if (!Mod->getContext().getCodeGenerationSettings().enableBlockScoping) {
      auto closureName = genAnonymousLabelName("closure");
      tempClosureVar = Builder.createVariable(
          curFunction()->function->getFunctionScopeDesc(),
          Variable::DeclKind::Var,
          closureName);

                                                                          
                                      
      nameTable_.insertIntoScope(
          curFunction()->functionScope,
          tempClosureVar->getName(),
          tempClosureVar);

                                                            
      originalNameIden = getNameFieldFromID(FE->_id);
      nameTable_.insert(originalNameIden, tempClosureVar);
    } else {
                                                                              
                                                          
      originalNameIden = getNameFieldFromID(FE->_id);

      auto closureName = genAnonymousLabelName(originalNameIden.str());
      tempClosureVar = Builder.createVariable(
          currentIRScopeDesc_, Variable::DeclKind::Const, closureName);

                                                                               
                  
      tempClosureVar->setStrictImmutableBinding(false);

      nameTable_.insertIntoScope(
          curFunction()->blockScope, originalNameIden, tempClosureVar);
    }
  }

  Function *newFunc = FE->_generator
      ? genGeneratorFunction(originalNameIden, tempClosureVar, FE)
      : FE->_async
      ? genAsyncFunction(originalNameIden, tempClosureVar, FE)
      : genES5Function(originalNameIden, tempClosureVar, FE);

  Value *closure = Builder.createCreateFunctionInst(newFunc, currentIRScope_);

  if (tempClosureVar)
    emitStore(closure, tempClosureVar, true);

  return closure;
}

Value *ESTreeIRGen::genArrowFunctionExpression(
    ESTree::ArrowFunctionExpressionNode *AF,
    Identifier nameHint) {
  LLVM_DEBUG(
      llvh::dbgs()
      << "Creating arrow function. "
      << Builder.getInsertionBlock()->getParent()->getInternalName() << ".\n");

  if (AF->_async) {
    auto *asyncFn = genAsyncFunction(nameHint, nullptr, AF);
    return Builder.createCreateFunctionInst(asyncFn, currentIRScope_);
  }

  auto *newFunc = Builder.createFunction(
      newScopeDesc(),
      genAnonymousFunctionNameIfNeeded(nameHint),
      Function::DefinitionKind::ES6Arrow,
      ESTree::isStrict(AF->strictness),
      AF->sourceVisibility,
      AF->getSourceRange());

  {
    FunctionContext newFunctionContext{this, newFunc, AF->getSemInfo()};

                                                                            
    auto *prev = curFunction()->getPreviousContext();
    curFunction()->capturedThis = prev->capturedThis;
    curFunction()->capturedNewTarget = prev->capturedNewTarget;
    curFunction()->capturedArguments = prev->capturedArguments;

    emitFunctionPreamble(Builder.createBasicBlock(newFunc));
    emitTopLevelDeclarations(AF, AF->_body, DoEmitParameters::YesMultiScopes);

    genFunctionBody(AF->_body);
    emitFunctionEpilogue(Builder.getLiteralUndefined());
  }

                                                                      
  return Builder.createCreateFunctionInst(newFunc, currentIRScope_);
}

namespace {
ESTree::NodeKind getLazyFunctionKind(ESTree::FunctionLikeNode *node) {
  if (node->isMethodDefinition) {
                                                                   
                                                               
                                                    
    return ESTree::NodeKind::Property;
  }
  return node->getKind();
}
}             
Function *ESTreeIRGen::genES5Function(
    Identifier originalName,
    Variable *lazyClosureAlias,
    ESTree::FunctionLikeNode *functionNode,
    bool isGeneratorInnerFunction) {
  assert(functionNode && "Function AST cannot be null");

  auto *body = ESTree::getBlockStatement(functionNode);
  assert(body && "body of ES5 function cannot be null");

  auto preParameterInitializers =
      functionNode->loweredClassPreParameterInitializers;
                                                                         
                                                                               
                                                                                     
  const bool validPreParameterInitializers = [&]() {
    if (preParameterInitializers.empty())
      return true;
    if (functionNode->loweredClassFunctionKind !=
            ESTree::LoweredClassFunctionKind::Constructor ||
        functionNode->strictness != ESTree::Strictness::StrictMode ||
        isGeneratorInnerFunction || ESTree::isGenerator(functionNode) ||
        ESTree::isAsync(functionNode) || body->isLazyFunctionBody)
      return false;
    auto cursor = body->_body.begin();
    for (auto *recorded : preParameterInitializers) {
      if (cursor == body->_body.end() || &*cursor != recorded)
        return false;
      auto *statement =
          llvh::dyn_cast<ESTree::ExpressionStatementNode>(recorded);
      auto *privateInit = statement
          ? llvh::dyn_cast<ESTree::NativePrivateOperationNode>(statement->_expression)
          : nullptr;
      auto *publicInit = statement
          ? llvh::dyn_cast<ESTree::NativePublicFieldOperationNode>(statement->_expression)
          : nullptr;
      ESTree::NodeList *arguments = nullptr;
      if (privateInit && (privateInit->_operation->str()=="init" || privateInit->_operation->str()=="init_member"))
        arguments=&privateInit->_arguments;
      else if (publicInit && publicInit->_operation->str()=="define_instance")
        arguments=&publicInit->_arguments;
      if (!arguments || arguments->size()!=3) return false;
      auto argument=arguments->begin();
      if (!llvh::isa<ESTree::ThisExpressionNode>(&*argument++)) return false;
      auto *key=&*argument++;
      if (privateInit ? !llvh::isa<ESTree::IdentifierNode>(key)
          : !(llvh::isa<ESTree::StringLiteralNode>(key) ||
              llvh::isa<ESTree::NumericLiteralNode>(key) ||
              llvh::isa<ESTree::IdentifierNode>(key))) return false;
      auto *value=&*argument;
      ESTree::NodeList *evaluateArguments=nullptr;
      if (auto *evaluate=llvh::dyn_cast<ESTree::NativePrivateOperationNode>(value)) {
        if (!privateInit || evaluate->_operation->str()!="evaluate") return false;
        evaluateArguments=&evaluate->_arguments;
      } else if (auto *evaluate=llvh::dyn_cast<ESTree::NativePublicFieldOperationNode>(value)) {
        if (!publicInit || evaluate->_operation->str()!="evaluate") return false;
        evaluateArguments=&evaluate->_arguments;
      }
      if (evaluateArguments) {
        if (evaluateArguments->size()!=2) return false;
        auto operand=evaluateArguments->begin();
        if (!llvh::isa<ESTree::IdentifierNode>(&*operand++) ||
            !llvh::isa<ESTree::ThisExpressionNode>(&*operand)) return false;
      } else if (privateInit && privateInit->_operation->str()=="init_member") {
                                                                               
                                                                                
        if (!llvh::isa<ESTree::IdentifierNode>(value)) return false;
      } else {
        auto *undefinedValue=llvh::dyn_cast<ESTree::UnaryExpressionNode>(value);
        auto *zero=undefinedValue
            ? llvh::dyn_cast<ESTree::NumericLiteralNode>(undefinedValue->_argument)
            : nullptr;
        if (!undefinedValue || undefinedValue->_operator->str()!="void" ||
            !zero || zero->_value!=0.0) return false;
      }
      ++cursor;
    }
    return true;
  }();

                                                                           
                                                                              
                                                                             
  Function::DefinitionKind definitionKind=Function::DefinitionKind::ES5Function;
  switch (functionNode->loweredClassFunctionKind) {
    case ESTree::LoweredClassFunctionKind::DerivedConstructor:
      definitionKind=Function::DefinitionKind::ES6DerivedConstructor;break;
    case ESTree::LoweredClassFunctionKind::Constructor:
      definitionKind=Function::DefinitionKind::ES6Constructor;break;
    case ESTree::LoweredClassFunctionKind::Method:
      definitionKind=Function::DefinitionKind::ES6Method;break;
    case ESTree::LoweredClassFunctionKind::None:break;
  }
  assert(!isGeneratorInnerFunction ||
         functionNode->loweredClassFunctionKind==ESTree::LoweredClassFunctionKind::None);

  Function *newFunction = isGeneratorInnerFunction
      ? Builder.createGeneratorInnerFunction(
            newScopeDesc(),
            genAnonymousFunctionNameIfNeeded(originalName),
            llvh::isa<ESTree::ArrowFunctionExpressionNode>(functionNode)
                ? Function::DefinitionKind::ES6Arrow
                : Function::DefinitionKind::ES5Function,
            ESTree::isStrict(functionNode->strictness),
            functionNode->getSourceRange(),
                               nullptr)
      : Builder.createFunction(
            newScopeDesc(),
            genAnonymousFunctionNameIfNeeded(originalName),
            definitionKind,
            ESTree::isStrict(functionNode->strictness),
            functionNode->sourceVisibility,
            functionNode->getSourceRange(),
                           false,
                               nullptr);

  newFunction->setLazyClosureAlias(lazyClosureAlias);

  if (!validPreParameterInitializers) {
                                                                            
                                                                   
    Builder.getModule()->getContext().getSourceErrorManager().error(
        functionNode->getSourceRange(),
        "[NATIVE_PRIVATE_UNSUPPORTED] PRE_PARAMETER_METADATA");
    FunctionContext rejectedContext{
        this, newFunction, functionNode->getSemInfo()};
    emitFunctionPreamble(Builder.createBasicBlock(newFunction));
    emitFunctionEpilogue(Builder.getLiteralUndefined());
    return curFunction()->function;
  }

  if (auto *bodyBlock = llvh::dyn_cast<ESTree::BlockStatementNode>(body)) {
    if (bodyBlock->isLazyFunctionBody) {
      assert(
          !isGeneratorInnerFunction &&
          "generator inner function should be included with outer function");
      setupLazyScope(functionNode, newFunction, body);
      return newFunction;
    }
  }

  FunctionContext newFunctionContext{
      this, newFunction, functionNode->getSemInfo()};
  newFunctionContext.asyncGeneratorBody = isGeneratorInnerFunction &&
      ESTree::isAsync(functionNode) && ESTree::isGenerator(functionNode);

  if (isGeneratorInnerFunction) {
                         
                          
                                                                             
    auto *initGenBB = Builder.createBasicBlock(newFunction);
    Builder.setInsertionBlock(initGenBB);
    Builder.createStartGeneratorInst();
    auto *prologueBB = Builder.createBasicBlock(newFunction);
    auto *prologueResumeIsReturn = Builder.createAllocStackInst(
        genAnonymousLabelName("isReturn_prologue"));
    genResumeGenerator(GenFinally::No, prologueResumeIsReturn, prologueBB);

    if (hasSimpleParams(functionNode)) {
                                                                              
                                                                     
      Builder.setInsertionBlock(prologueBB);
      emitFunctionPreamble(prologueBB);
      initCaptureStateInES5Function();
      emitTopLevelDeclarations(
          functionNode, body, DoEmitParameters::YesMultiScopes);
    } else {
                                                                             
                                                                         
                                                                   
      auto *entryPointBB = Builder.createBasicBlock(newFunction);
      auto *entryPointResumeIsReturn =
          Builder.createAllocStackInst(genAnonymousLabelName("isReturn_entry"));

                               
      Builder.setInsertionBlock(prologueBB);
      emitFunctionPreamble(prologueBB);
      initCaptureStateInES5Function();
      emitTopLevelDeclarations(
          functionNode, body, DoEmitParameters::YesMultiScopes);
      Builder.createSaveAndYieldInst(
          Builder.getLiteralUndefined(), entryPointBB);

                                                                      
      Builder.setInsertionBlock(entryPointBB);
      genResumeGenerator(
          GenFinally::No,
          entryPointResumeIsReturn,
          Builder.createBasicBlock(newFunction));
    }
  } else {
    emitFunctionPreamble(Builder.createBasicBlock(newFunction));
    initCaptureStateInES5Function();
                                                                     
                                                                          
                                                                             
                                                                 
    for (auto *initializer : preParameterInitializers)
      genStatement(initializer, IsLoopBody::No);
    emitTopLevelDeclarations(
        functionNode, body, DoEmitParameters::YesMultiScopes);
  }

  if (preParameterInitializers.empty()) {
    genFunctionBody(body);
  } else {
                                                                            
                                                                          
                                                                            
    auto statement = body->_body.begin();
    for (auto *initializer : preParameterInitializers) {
      assert(statement != body->_body.end() && &*statement == initializer);
      ++statement;
    }
    for (; statement != body->_body.end(); ++statement)
      genStatement(&*statement, IsLoopBody::No);
  }
  emitFunctionEpilogue(Builder.getLiteralUndefined());

  return curFunction()->function;
}

Function *ESTreeIRGen::genGeneratorFunction(
    Identifier originalName,
    Variable *lazyClosureAlias,
    ESTree::FunctionLikeNode *functionNode) {
  assert(functionNode && "Function AST cannot be null");

  if (!Builder.getModule()->getContext().isGeneratorEnabled()) {
    Builder.getModule()->getContext().getSourceErrorManager().error(
        functionNode->getSourceRange(), "generator compilation is disabled");
  }

  const bool asyncGenerator = ESTree::isAsync(functionNode) && ESTree::isGenerator(functionNode);
                                                          
                                              
  auto *outerFn = Builder.createGeneratorFunction(
      newScopeDesc(),
      genAnonymousFunctionNameIfNeeded(originalName),
      asyncGenerator ? Function::DefinitionKind::ES6AsyncGenerator :
      llvh::isa<ESTree::ArrowFunctionExpressionNode>(functionNode)
          ? Function::DefinitionKind::ES6Arrow
          : Function::DefinitionKind::ES5Function,
      ESTree::isStrict(functionNode->strictness),
      functionNode->sourceVisibility,
      functionNode->getSourceRange(),
                         nullptr);
  outerFn->setLazyClosureAlias(lazyClosureAlias);

  auto *body = ESTree::getBlockStatement(functionNode);
  if (auto *bodyBlock = llvh::dyn_cast<ESTree::BlockStatementNode>(body)) {
    if (bodyBlock->isLazyFunctionBody) {
      setupLazyScope(functionNode, outerFn, body);
      return outerFn;
    }
  }

  {
    FunctionContext outerFnContext{this, outerFn, functionNode->getSemInfo()};

                                                                        
                                                        
                                                                           
                                                                      
                                                                        
    const auto savedClassKind = functionNode->loweredClassFunctionKind;
    functionNode->loweredClassFunctionKind = ESTree::LoweredClassFunctionKind::None;
    auto *innerFn = genES5Function(
        genAnonymousLabelName(originalName.isValid() ? originalName.str() : ""),
        nullptr,
        functionNode,
        true);
    functionNode->loweredClassFunctionKind = savedClassKind;

    emitFunctionPreamble(Builder.createBasicBlock(outerFn));
    initCaptureStateInES5Function();
    emitTopLevelDeclarations(
        functionNode,
        ESTree::getBlockStatement(functionNode),
        DoEmitParameters::No);

                                                                   
    auto *gen = Builder.createCreateGeneratorInst(innerFn, currentIRScope_);

    if (!hasSimpleParams(functionNode)) {
                                                                        
                         
      if (asyncGenerator) {
        genBuiltinCall(BuiltinMethod::HermesBuiltin_asyncGeneratorStart, {gen});
      } else {
        Value *next = Builder.createLoadPropertyInst(gen, "next");
        Builder.createCallInst(CallInst::kNoTextifiedCallee, next, gen, {});
      }
    }

    emitFunctionEpilogue(asyncGenerator
        ? genBuiltinCall(BuiltinMethod::HermesBuiltin_asyncGeneratorWrap, {gen}) : gen);
  }

  return outerFn;
}

void ESTreeIRGen::setupLazyScope(
    ESTree::FunctionLikeNode *functionNode,
    Function *function,
    ESTree::BlockStatementNode *bodyBlock) {
  assert(
      bodyBlock->isLazyFunctionBody &&
      "setupLazyScope can only be used with lazy function bodies");
                                                                        
                                                                         
                         
  function->setLazyScope(
      saveScopeChain(function->getFunctionScopeDesc()->getParent()));
  auto &lazySource = function->getLazySource();
  lazySource.bufferId = bodyBlock->bufferId;
  lazySource.nodeKind = getLazyFunctionKind(functionNode);
  lazySource.functionRange = functionNode->getSourceRange();
  lazySource.paramYield = bodyBlock->paramYield;
  lazySource.paramAwait = bodyBlock->paramAwait;

                                
  function->setExpectedParamCountIncludingThis(
      countExpectedArgumentsIncludingThis(functionNode));
}

Function *ESTreeIRGen::genAsyncFunction(
    Identifier originalName,
    Variable *lazyClosureAlias,
    ESTree::FunctionLikeNode *functionNode) {
  assert(functionNode && "Function AST cannot be null");

  if (!Builder.getModule()->getContext().isGeneratorEnabled()) {
    Builder.getModule()->getContext().getSourceErrorManager().error(
        functionNode->getSourceRange(),
        "async function compilation requires enabling generator");
  }

  auto *asyncFn = Builder.createAsyncFunction(
      newScopeDesc(),
      genAnonymousFunctionNameIfNeeded(originalName),
      llvh::isa<ESTree::ArrowFunctionExpressionNode>(functionNode)
          ? Function::DefinitionKind::ES6Arrow
          : functionNode->loweredClassFunctionKind ==
                    ESTree::LoweredClassFunctionKind::Method
          ? Function::DefinitionKind::ES6Method
          : Function::DefinitionKind::ES5Function,
      ESTree::isStrict(functionNode->strictness),
      functionNode->sourceVisibility,
      functionNode->getSourceRange(),
                         nullptr);

                           
  asyncFn->setLazyClosureAlias(lazyClosureAlias);

  auto *body = ESTree::getBlockStatement(functionNode);
  if (auto *bodyBlock = llvh::dyn_cast<ESTree::BlockStatementNode>(body)) {
    if (bodyBlock->isLazyFunctionBody) {
      setupLazyScope(functionNode, asyncFn, body);
      return asyncFn;
    }
  }

  {
    FunctionContext asyncFnContext{this, asyncFn, functionNode->getSemInfo()};

                                                                         
                                                        
                                                                     
                                                                             
                                                                          
    const auto savedClassKind = functionNode->loweredClassFunctionKind;
    functionNode->loweredClassFunctionKind = ESTree::LoweredClassFunctionKind::None;
    auto *gen = genGeneratorFunction(
        genAnonymousLabelName(originalName.isValid() ? originalName.str() : ""),
        lazyClosureAlias,
        functionNode);
    functionNode->loweredClassFunctionKind = savedClassKind;

                                                                  
                                                                           
                                                                    
    emitFunctionPreamble(Builder.createBasicBlock(asyncFn));
    initCaptureStateInES5Function();
    emitTopLevelDeclarations(
        functionNode,
        ESTree::getBlockStatement(functionNode),
        DoEmitParameters::No);

    auto *genClosure = Builder.createCreateFunctionInst(gen, currentIRScope_);
    auto *thisArg = curFunction()->function->getThisParameter();
    auto *argumentsList = curFunction()->createArgumentsInst;

    auto *spawnAsyncClosure = Builder.createGetBuiltinClosureInst(
        BuiltinMethod::HermesBuiltin_spawnAsync);

    auto *res = Builder.createCallInst(
        CallInst::kNoTextifiedCallee,
        spawnAsyncClosure,
        Builder.getLiteralUndefined(),
        {genClosure, thisArg, argumentsList});

    emitFunctionEpilogue(res);
  }
  return asyncFn;
}

void ESTreeIRGen::initCaptureStateInES5Function() {
                                                                            
                                               
  if (curFunction()->function->getDefinitionKind() ==
      Function::DefinitionKind::ES6Arrow)
    return;

                                                                            
  const bool derived = curFunction()->function->getDefinitionKind() ==
      Function::DefinitionKind::ES6DerivedConstructor;
  if (!derived && !curFunction()->getSemInfo()->containsArrowFunctions)
    return;

            
  curFunction()->capturedThis = Builder.createVariable(
      currentIRScopeDesc_,
      Variable::DeclKind::Var,
      genAnonymousLabelName("this"));
  if (derived)
    curFunction()->derivedThis = curFunction()->capturedThis;
  emitStore(
      derived ? static_cast<Value *>(Builder.getLiteralUndefined())
              : static_cast<Value *>(Builder.getFunction()->getThisParameter()),
      curFunction()->capturedThis, true);

                                                                     
                                                                     
                                                                         
                                                                             
  if (curFunction()->function->getDefinitionKind() == Function::DefinitionKind::ES6Method ||
      curFunction()->function->getDefinitionKind() == Function::DefinitionKind::ES6AsyncGenerator) {
    curFunction()->capturedNewTarget = Builder.getLiteralUndefined();
  } else {
    curFunction()->capturedNewTarget = Builder.createVariable(
        currentIRScopeDesc_,
        Variable::DeclKind::Var,
        genAnonymousLabelName("new.target"));
    emitStore(
        Builder.createGetNewTargetInst(), curFunction()->capturedNewTarget, true);
  }

                 
  if (curFunction()->getSemInfo()->containsArrowFunctionsUsingArguments) {
    curFunction()->capturedArguments = Builder.createVariable(
        currentIRScopeDesc_,
        Variable::DeclKind::Var,
        genAnonymousLabelName("arguments"));
    emitStore(
        curFunction()->createArgumentsInst,
        curFunction()->capturedArguments,
        true);
  }
}

void ESTreeIRGen::emitFunctionPreamble(BasicBlock *entry) {
  auto *newFunc = curFunction()->function;

  Builder.setLocation(newFunc->getSourceRange().Start);
  Builder.setCurrentSourceLevelScope(nullptr);

  BasicBlock *realEntry = &newFunc->front();
  if (realEntry->empty()) {
    Builder.setInsertionBlock(realEntry);
  } else {
    Builder.setInsertionPoint(&realEntry->front());
  }
                               
  currentIRScope_ =
      Builder.createCreateScopeInst(newFunc->getFunctionScopeDesc());

                                                           
  Builder.setInsertionBlock(entry);
  Builder.setCurrentSourceLevelScope(newFunc->getFunctionScopeDesc());

                                                                          
            
  curFunction()->createArgumentsInst = Builder.createCreateArgumentsInst();

                                                                         
                                       
  Builder.createThisParameter(newFunc);
}

void ESTreeIRGen::emitTopLevelDeclarations(
    ESTree::FunctionLikeNode *funcNode,
    ESTree::Node *body,
    DoEmitParameters doEmitParameters) {
                                                                               
                                  
    
                                                                  
                                    
    
                                             
                                                           
                                                                  
    
                                        
    
                               
                                              
                                                                  
    
                                   
    
                     
                                                                  
                                      
    
                                       
    
                                                                            
                     
    
                                           
                                               
                                                
                                        
                            
                                          
                                               
                                           
                                                   
                                                        
                                          
                                                
                                        
                            
                                
                                         
                                           
                                            
                                        
                                
    
                                                                 
  ScopeDesc *topLevelScope = currentIRScopeDesc_;
  ScopeDesc *paramExpressionScope{};
  ScopeDesc *varScope{};
  ScopeDesc *lexicalScope{};

  if (!Mod->getContext().getCodeGenerationSettings().enableBlockScoping) {
    if (doEmitParameters == DoEmitParameters::YesMultiScopes) {
                                                                            
                
      doEmitParameters = DoEmitParameters::Yes;
    }
  }

  const bool hasParamExpressions = ESTree::hasParamExpressions(funcNode);
  if (doEmitParameters == DoEmitParameters::YesMultiScopes) {
    if (!ESTree::isStrict(funcNode->strictness) && hasParamExpressions) {
      curFunction()->enterOptionalFunctionScope(
          &FunctionContext::enterParamScope);
      newDeclarativeEnvironment();
      paramExpressionScope = currentIRScopeDesc_;
    }
  }

  if (doEmitParameters != DoEmitParameters::No) {
                                                                             
                                     
    emitParameters(funcNode, hasParamExpressions);
  } else {
    curFunction()->function->setExpectedParamCountIncludingThis(
        countExpectedArgumentsIncludingThis(funcNode));
  }

  auto *semInfo = curFunction()->getSemInfo();
  if (doEmitParameters != DoEmitParameters::YesMultiScopes ||
      !hasParamExpressions) {
                                                                         
                                               
    for (const sem::FunctionInfo::VarDecl &decl : semInfo->varScoped) {
      createNewBinding(
          currentIRScopeDesc_,
          decl.kind,
          decl.identifier,
          decl.needsInitializer);
    }

  } else {
    curFunction()->enterOptionalFunctionScope(&FunctionContext::enterVarScope);
    newDeclarativeEnvironment();
    varScope = currentIRScopeDesc_;

    for (const sem::FunctionInfo::VarDecl &decl : semInfo->varScoped) {
      Value *init = nameTable_.lookup(getNameFieldFromID(decl.identifier));
      if (init) {
        init = emitLoad(init);
      }
      createNewBinding(
          currentIRScopeDesc_,
          decl.kind,
          decl.identifier,
          decl.needsInitializer,
          init);
    }
  }

  if (doEmitParameters == DoEmitParameters::YesMultiScopes) {
    if (!ESTree::isStrict(funcNode->strictness)) {
      curFunction()->enterOptionalFunctionScope(
          &FunctionContext::enterTopLevelLexicalDeclarationsScope);
      newDeclarativeEnvironment();
      lexicalScope = currentIRScopeDesc_;
    }
  }

                                                                             
  if (doEmitParameters == DoEmitParameters::YesMultiScopes) {
    (void)topLevelScope;
    (void)paramExpressionScope;
    (void)varScope;
    (void)lexicalScope;
    if (!ESTree::isStrict(funcNode->strictness)) {
      if (!hasParamExpressions) {
                                                 
        assert(currentIRScopeDesc_ == lexicalScope);
        assert(lexicalScope->getParent() == topLevelScope);
        assert(paramExpressionScope == nullptr);
        assert(varScope == nullptr);
      } else {
                                                
        assert(currentIRScopeDesc_ == lexicalScope);
        assert(lexicalScope->getParent() == varScope);
        assert(varScope->getParent() == paramExpressionScope);
        assert(paramExpressionScope->getParent() == topLevelScope);
      }
    } else {
      if (!hasParamExpressions) {
                                                
        assert(currentIRScopeDesc_ == topLevelScope);
        assert(paramExpressionScope == nullptr);
        assert(varScope == nullptr);
        assert(lexicalScope == nullptr);
      } else {
                                               
        assert(currentIRScopeDesc_ == varScope);
        assert(varScope->getParent() == topLevelScope);
        assert(paramExpressionScope == nullptr);
        assert(lexicalScope == nullptr);
      }
    }
  }

                                                                                
                                                                             
  createScopeBindings(currentIRScopeDesc_, body);

                                                                                
          
  for (ESTree::ImportDeclarationNode *importDecl : semInfo->imports) {
    genImportDeclaration(importDecl);
  }

                                                        
                                                            
  genFunctionDeclarations(body);

                                                                      
                           
  hoistCreateFunctions(body);
}

void ESTreeIRGen::genFunctionDeclarations(ESTree::Node *containingNode) {
  auto *semInfo = curFunction()->getSemInfo();

  auto it = semInfo->closures.find(containingNode);
  if (it != semInfo->closures.end()) {
    for (ESTree::FunctionDeclarationNode *fd : *it->second) {
      genFunctionDeclaration(fd);
    }
  }
}

void ESTreeIRGen::createScopeBindings(
    ScopeDesc *scopeDesc,
    ESTree::Node *containingNode) {
  auto *semInfo = curFunction()->getSemInfo();

  auto it = semInfo->lexicallyScoped.find(containingNode);
  if (it != semInfo->lexicallyScoped.end()) {
    for (const sem::FunctionInfo::VarDecl &decl : *it->second) {
      LLVM_DEBUG(
          llvh::dbgs() << "creating binding " << decl.identifier->_name
                       << " in scope " << scopeDesc << "\n");
      createNewBinding(
          scopeDesc, decl.kind, decl.identifier, decl.needsInitializer);
      if (Mod->getContext().getCodeGenerationSettings().enableBlockScoping) {
        if (decl.kind != VarDecl::Kind::Var && scopeDesc->isGlobalScope() &&
            llvh::isa<ESTree::ProgramNode>(containingNode)) {
                                                                          
                                                                                
            
                           
            
                                                                        
                                    
          IRBuilder::ScopedLocationChange slc(
              Builder, decl.identifier->getSourceRange().Start);
          Builder.createThrowIfHasRestrictedGlobalPropertyInst(
              decl.identifier->_name->str());
        }
      }
    }
  }
}

void ESTreeIRGen::createNewBinding(
    ScopeDesc *scopeDesc,
    VarDecl::Kind kind,
    ESTree::Node *id,
    bool needsInitializer,
    Value *init) {
  Identifier name = getNameFieldFromID(id);
  auto res = declareVariableOrGlobalProperty(scopeDesc, kind, name);
                                                                      
  auto *var = llvh::dyn_cast<Variable>(res.first);
  if (!needsInitializer || !var || !res.second)
    return;

  if (!init) {
    init = var->getObeysTDZ() ? (Literal *)Builder.getLiteralEmpty()
                              : (Literal *)Builder.getLiteralUndefined();
  }

                                                                      
  Builder.createStoreFrameInst(init, var, currentIRScope_);
}

void ESTreeIRGen::emitParameters(
    ESTree::FunctionLikeNode *funcNode,
    bool hasParamExpressions) {
  auto *newFunc = curFunction()->function;

  LLVM_DEBUG(llvh::dbgs() << "IRGen function parameters.\n");

  if (!Mod->getContext().getCodeGenerationSettings().enableBlockScoping) {
                                                                  
    hasParamExpressions = false;
  }

  llvh::SmallVector<Variable *, 4> tdzParams;

                                           
  Value *empty = Builder.getLiteralEmpty();
  Variable::DeclKind paramKind =
      hasParamExpressions ? Variable::DeclKind::Let : Variable::DeclKind::Var;
  for (auto paramDecl : funcNode->getSemInfo()->paramNames) {
    Identifier paramName = getNameFieldFromID(paramDecl.identifier);
    LLVM_DEBUG(llvh::dbgs() << "Adding parameter: " << paramName << "\n");
    auto *paramStorage = Builder.createVariable(
        newFunc->getFunctionScopeDesc(), paramKind, paramName);
    if (hasParamExpressions) {
                                                                          
                                                                       
      Builder.createStoreFrameInst(empty, paramStorage, currentIRScope_);

                                                                               
                      
      tdzParams.push_back(paramStorage);
    }
                                              
    nameTable_.insert(paramName, paramStorage);
  }

  uint32_t paramIndex = uint32_t{0} - 1;
  for (auto &elem : ESTree::getParams(funcNode)) {
    ESTree::Node *param = &elem;
    ESTree::Node *init = nullptr;
    ++paramIndex;

    if (auto *rest = llvh::dyn_cast<ESTree::RestElementNode>(param)) {
      createLRef(rest->_argument, true)
          .emitStore(genBuiltinCall(
              BuiltinMethod::HermesBuiltin_copyRestArgs,
              Builder.getLiteralNumber(paramIndex)));
      break;
    }

                                          
    if (auto *assign = llvh::dyn_cast<ESTree::AssignmentPatternNode>(param)) {
      param = assign->_left;
      init = assign->_right;
    }

    Identifier formalParamName = llvh::isa<ESTree::IdentifierNode>(param)
        ? getNameFieldFromID(param)
        : genAnonymousLabelName("param");

    auto *formalParam = Builder.createParameter(newFunc, formalParamName);
    createLRef(param, true)
        .emitStore(
            emitOptionalInitialization(formalParam, init, formalParamName));
  }

                                                                              
                                                       
  assert(
      (tdzParams.empty() || hasParamExpressions) &&
      "funcNode does not have param expressions, so it doesn't"
      " need tdz params.");
  for (Variable *oldParamStorage : tdzParams) {
    auto *paramStorage = Builder.createVariable(
        newFunc->getFunctionScopeDesc(),
        Variable::DeclKind::Let,
        oldParamStorage->getName());
    constexpr bool declInit = true;
    emitStore(emitLoad(oldParamStorage), paramStorage, declInit);
    nameTable_.setInCurrentScope(oldParamStorage->getName(), paramStorage);
  }

  newFunc->setExpectedParamCountIncludingThis(
      countExpectedArgumentsIncludingThis(funcNode));
}

uint32_t ESTreeIRGen::countExpectedArgumentsIncludingThis(
    ESTree::FunctionLikeNode *funcNode) {
                                      
  uint32_t count = 1;
  for (auto &param : ESTree::getParams(funcNode)) {
    if (llvh::isa<ESTree::AssignmentPatternNode>(param) ||
        llvh::isa<ESTree::RestElementNode>(param)) {
                                                                          
                                                                              
      break;
    }
    ++count;
  }
  return count;
}

void ESTreeIRGen::emitFunctionEpilogue(Value *returnValue) {
  if (returnValue) {
    Builder.setLocation(
        SourceErrorManager::convertEndToLocation(
            Builder.getFunction()->getSourceRange()));
    if (curFunction()->function->getDefinitionKind() ==
        Function::DefinitionKind::ES6DerivedConstructor) {
      assert(curFunction()->derivedThis);
      returnValue = genBuiltinCall(BuiltinMethod::HermesBuiltin_derivedConstructorReturn,
          {Builder.createLoadFrameInst(curFunction()->derivedThis, currentIRScope_),
           returnValue});
    }
    Builder.createReturnInst(returnValue);
  }

                                                
  if (!curFunction()->createArgumentsInst->hasUsers())
    curFunction()->createArgumentsInst->eraseFromParent();

  curFunction()->function->clearStatementCount();
}

void ESTreeIRGen::genDummyFunction(Function *dummy) {
  IRBuilder builder{dummy};

  builder.createThisParameter(dummy);
  BasicBlock *firstBlock = builder.createBasicBlock(dummy);
  builder.setInsertionBlock(firstBlock);
  builder.createUnreachableInst();
  builder.createReturnInst(builder.getLiteralUndefined());
}

                                                                          
            
Function *ESTreeIRGen::genSyntaxErrorFunction(
    Module *M,
    ScopeDesc *scopeDesc,
    Identifier originalName,
    SMRange sourceRange,
    llvh::StringRef error) {
  IRBuilder builder{M};

  Function *function = builder.createFunction(
      scopeDesc,
      originalName,
      Function::DefinitionKind::ES5Function,
      true,
      SourceVisibility::Sensitive,
      sourceRange,
      false);

  builder.createThisParameter(function);
  BasicBlock *firstBlock = builder.createBasicBlock(function);
  builder.setInsertionBlock(firstBlock);
  builder.createCreateScopeInst(scopeDesc);

  genRaiseNativeError(builder, NativeErrorTypes::SyntaxError, error);

  return function;
}

}                   
}                    

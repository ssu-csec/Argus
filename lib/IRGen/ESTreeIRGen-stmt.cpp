/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "ESTreeIRGen.h"

#include <optional>

namespace hermes {
namespace irgen {

void ESTreeIRGen::genBody(ESTree::NodeList &Body) {
  LLVM_DEBUG(llvh::dbgs() << "Compiling body.\n");

                                                   
  for (auto &Node : Body) {
    LLVM_DEBUG(
        llvh::dbgs() << "IRGen node of type " << Node.getNodeName() << ".\n");
    genStatement(&Node, IsLoopBody::No);
  }
}

void ESTreeIRGen::genScopelessBlockOrStatement(ESTree::Node *stmt) {
                                    
  if (auto *BS = llvh::dyn_cast<ESTree::BlockStatementNode>(stmt)) {
    for (auto &Node : BS->_body) {
      genStatement(&Node, IsLoopBody::No);
    }

    return;
  }

  genStatement(stmt, IsLoopBody::No);
}

void ESTreeIRGen::genFunctionBody(ESTree::Node *stmt) {
  genScopelessBlockOrStatement(stmt);
}

void ESTreeIRGen::genCatchHandler(ESTree::Node *stmt) {
  genScopelessBlockOrStatement(stmt);
}

void ESTreeIRGen::genBlockStatement(
    ESTree::BlockStatementNode *BS,
    IsLoopBody isLoopBody) {
                                                                   
                                                        
  std::optional<EnterBlockScope> enterBlockScope;

  if (Mod->getContext().getCodeGenerationSettings().enableBlockScoping) {
    enterBlockScope.emplace(curFunction());
    blockDeclarationInstantiation(BS);
                                                                              
                                                                                
    currentIRScopeDesc_->setDynamic(isLoopBody != IsLoopBody::No);
  }

  for (auto &Node : BS->_body) {
    genStatement(&Node, IsLoopBody::No);
  }
}

void ESTreeIRGen::genStatement(ESTree::Node *stmt, IsLoopBody isLoopBody) {
  LLVM_DEBUG(
      llvh::dbgs() << "IRGen statement of type " << stmt->getNodeName()
                   << "\n");
  IRBuilder::ScopedLocationChange slc(Builder, stmt->getDebugLoc());

  Builder.getFunction()->incrementStatementCount();

  if (auto *FD = llvh::dyn_cast<ESTree::FunctionDeclarationNode>(stmt)) {
                                                                             
                                                                               
                                                                               
    emitCreateFunction(FD);
    return;
  }

  if (                 llvh::dyn_cast<ESTree::ImportDeclarationNode>(stmt)) {
                                                                     
                                                                      
              
    return;
  }

  if (auto *IF = llvh::dyn_cast<ESTree::IfStatementNode>(stmt)) {
    return genIfStatement(IF);
  }

  if (auto *FIS = llvh::dyn_cast<ESTree::ForInStatementNode>(stmt)) {
    return genForInStatement(FIS);
  }

  if (auto *FOS = llvh::dyn_cast<ESTree::ForOfStatementNode>(stmt)) {
    return genForOfStatement(FOS);
  }

  if (auto *Ret = llvh::dyn_cast<ESTree::ReturnStatementNode>(stmt)) {
    return genReturnStatement(Ret);
  }

  if (auto *exprStmt = llvh::dyn_cast<ESTree::ExpressionStatementNode>(stmt)) {
    return genExpressionWrapper(exprStmt->_expression);
  }

  if (auto *SW = llvh::dyn_cast<ESTree::SwitchStatementNode>(stmt)) {
    return genSwitchStatement(SW);
  }

  if (auto *VDN = llvh::dyn_cast<ESTree::VariableDeclarationNode>(stmt)) {
    return genVariableDeclaration(VDN);
  }

                                    
  if (auto *BS = llvh::dyn_cast<ESTree::BlockStatementNode>(stmt)) {
    genBlockStatement(BS, isLoopBody);
    return;
  }

  if (auto *Label = llvh::dyn_cast<ESTree::LabeledStatementNode>(stmt)) {
                                                                              
                                        
    BasicBlock *next = Builder.createBasicBlock(curFunction()->function);

                                                         
    curFunction()->initLabel(Label, next, nullptr);

                                                                           
    genStatement(Label->_body, isLoopBody);

                                                                      
    Builder.createBranchInst(next);
    Builder.setInsertionBlock(next);

    return;
  }

                                                                             
                                                      
  if (auto *call = llvh::dyn_cast<ESTree::CallExpressionNode>(stmt)) {
    return genExpressionWrapper(call);
  }

  if (auto *W = llvh::dyn_cast<ESTree::WhileStatementNode>(stmt)) {
    LLVM_DEBUG(llvh::dbgs() << "IRGen 'while' statement\n");
    genForWhileLoops(W, nullptr, W->_test, W->_test, nullptr, W->_body);
    return;
  }

  if (auto *F = llvh::dyn_cast<ESTree::ForStatementNode>(stmt)) {
    LLVM_DEBUG(llvh::dbgs() << "IRGen 'for' statement\n");
    genForWhileLoops(F, F->_init, F->_test, F->_test, F->_update, F->_body);
    return;
  }

  if (auto *D = llvh::dyn_cast<ESTree::DoWhileStatementNode>(stmt)) {
    LLVM_DEBUG(llvh::dbgs() << "IRGen 'do..while' statement\n");
    genForWhileLoops(D, nullptr, nullptr, D->_test, nullptr, D->_body);
    return;
  }

  if (auto *breakStmt = llvh::dyn_cast<ESTree::BreakStatementNode>(stmt)) {
    LLVM_DEBUG(llvh::dbgs() << "IRGen 'break' statement\n");

    auto &label = curFunction()->label(breakStmt);
    assert(label.breakTarget && "breakTarget not set");

    genFinallyBeforeControlChange(
        curFunction()->surroundingTry,
        label.surroundingTry,
        ControlFlowChange::Break);
    Builder.createBranchInst(label.breakTarget);

                                                                              
                           
    auto newBlock = Builder.createBasicBlock(curFunction()->function);
    Builder.setInsertionBlock(newBlock);
    return;
  }

  if (auto *continueStmt =
          llvh::dyn_cast<ESTree::ContinueStatementNode>(stmt)) {
    LLVM_DEBUG(llvh::dbgs() << "IRGen 'continue' statement\n");

    auto &label = curFunction()->label(continueStmt);
    assert(label.continueTarget && "continueTarget not set");

    genFinallyBeforeControlChange(
        curFunction()->surroundingTry,
        label.surroundingTry,
        ControlFlowChange::Continue,
        label.continueTarget);
    Builder.createBranchInst(label.continueTarget);

                                                                              
                           
    auto newBlock = Builder.createBasicBlock(curFunction()->function);
    Builder.setInsertionBlock(newBlock);
    return;
  }

  if (auto *T = llvh::dyn_cast<ESTree::TryStatementNode>(stmt)) {
    genTryStatement(T);
    return;
  }

  if (auto *T = llvh::dyn_cast<ESTree::ThrowStatementNode>(stmt)) {
    LLVM_DEBUG(llvh::dbgs() << "IRGen 'throw' statement\n");
    Value *rightHandVal = genExpression(T->_argument);
    Builder.createThrowInst(rightHandVal);

                                                                     
    auto newBlock =
        Builder.createBasicBlock(Builder.getInsertionBlock()->getParent());
    Builder.setInsertionBlock(newBlock);
    return;
  }

                             
  if (llvh::isa<ESTree::EmptyStatementNode>(stmt)) {
    return;
  }

                                
  if (llvh::isa<ESTree::DebuggerStatementNode>(stmt)) {
    Builder.createDebuggerInst();
    return;
  }

  if (auto *importDecl = llvh::dyn_cast<ESTree::ImportDeclarationNode>(stmt)) {
    return genImportDeclaration(importDecl);
  }

  if (auto *exportDecl =
          llvh::dyn_cast<ESTree::ExportNamedDeclarationNode>(stmt)) {
    return genExportNamedDeclaration(exportDecl);
  }

  if (auto *exportDecl =
          llvh::dyn_cast<ESTree::ExportDefaultDeclarationNode>(stmt)) {
    return genExportDefaultDeclaration(exportDecl);
  }

  if (auto *exportDecl =
          llvh::dyn_cast<ESTree::ExportAllDeclarationNode>(stmt)) {
    return genExportAllDeclaration(exportDecl);
  }

  Builder.getModule()->getContext().getSourceErrorManager().error(
      stmt->getSourceRange(),
      Twine("invalid statement encountered. AST=") + stmt->getNodeName());
}

void ESTreeIRGen::genExpressionWrapper(ESTree::Node *expr) {
  Value *val = genExpression(expr);
  if (curFunction()->globalReturnRegister) {
    Builder.createStoreStackInst(val, curFunction()->globalReturnRegister);
  }
}

void ESTreeIRGen::genVariableDeclaration(
    ESTree::VariableDeclarationNode *declaration) {
  for (auto &decl : declaration->_declarations)
    genVariableDeclarator(
        declaration->_kind, cast<ESTree::VariableDeclaratorNode>(&decl));
}

void ESTreeIRGen::genVariableDeclarator(
    ESTree::NodeLabel kind,
    ESTree::VariableDeclaratorNode *declarator) {
  IRBuilder::ScopedLocationChange slc(Builder, declarator->getDebugLoc());
  Builder.getFunction()->incrementStatementCount();

  auto lref = createLRef(declarator->_id, true);
  if (declarator->_init) {
    Identifier nameHint{};
    if (llvh::isa<ESTree::IdentifierNode>(declarator->_id))
      nameHint = getNameFieldFromID(declarator->_id);
    lref.emitStore(genExpression(declarator->_init, nameHint));
  } else if (kind == identLet_.getUnderlyingPointer()) {
                                                                          
    lref.emitStore(Builder.getLiteralUndefined());
  }
}

void ESTreeIRGen::genIfStatement(ESTree::IfStatementNode *IfStmt) {
  LLVM_DEBUG(llvh::dbgs() << "IRGen IF-stmt.\n");

  auto Parent = Builder.getInsertionBlock()->getParent();
  auto ThenBlock = Builder.createBasicBlock(Parent);
  auto ElseBlock = Builder.createBasicBlock(Parent);
  auto ContinueBlock = Builder.createBasicBlock(Parent);

  genExpressionBranch(IfStmt->_test, ThenBlock, ElseBlock, nullptr);

                    
  Builder.setInsertionBlock(ThenBlock);
  genStatement(IfStmt->_consequent, IsLoopBody::No);
  Builder.createBranchInst(ContinueBlock);

                                  
  Builder.setInsertionBlock(ElseBlock);
  if (IfStmt->_alternate) {
    genStatement(IfStmt->_alternate, IsLoopBody::No);
  }

  Builder.createBranchInst(ContinueBlock);
  Builder.setInsertionBlock(ContinueBlock);
}

void ESTreeIRGen::genForWhileLoops(
    ESTree::LoopStatementNode *loop,
    ESTree::Node *init,
    ESTree::Node *preTest,
    ESTree::Node *postTest,
    ESTree::Node *update,
    ESTree::Node *body) {
                                                                          
                                                                      
                                          
                                                                         
                                                              

                          
                          
                          
                       \
                        \
                                                
                                       
                                       
                                      
                
    

                                                           
  Function *function = Builder.getInsertionBlock()->getParent();
  BasicBlock *bodyBlock = Builder.createBasicBlock(function);
  BasicBlock *exitBlock = Builder.createBasicBlock(function);
  BasicBlock *preTestBlock = Builder.createBasicBlock(function);
  BasicBlock *postTestBlock = Builder.createBasicBlock(function);
  BasicBlock *updateBlock = Builder.createBasicBlock(function);

                                
  curFunction()->initLabel(loop, exitBlock, updateBlock);

                                             
                                                                    
                                                                      
  if (init) {
    if (llvh::isa<ESTree::VariableDeclarationNode>(init)) {
      genStatement(init, IsLoopBody::No);
    } else {
      genExpression(init);
    }
  }

                                                                       
  Builder.createBranchInst(preTestBlock);
  Builder.setInsertionBlock(preTestBlock);

                                                      
  if (preTest)
    genExpressionBranch(preTest, bodyBlock, exitBlock, nullptr);
  else
    Builder.createBranchInst(bodyBlock);

                                                 
  Builder.setInsertionBlock(updateBlock);
  if (update) {
    genExpression(update);
  }

                                                                          
  Builder.createBranchInst(postTestBlock);
  Builder.setInsertionBlock(postTestBlock);

                                                      
  if (postTest)
    genExpressionBranch(postTest, bodyBlock, exitBlock, nullptr);
  else
    Builder.createBranchInst(bodyBlock);

                                              
                                                                            
                                                
  Builder.setInsertionBlock(bodyBlock);
  genStatement(body, IsLoopBody::Yes);
  Builder.createBranchInst(updateBlock);

                                                         
  Builder.setInsertionBlock(exitBlock);
}

void ESTreeIRGen::genForInStatement(ESTree::ForInStatementNode *ForInStmt) {
                                                                           
            
                                                                            
  auto *iteratorStorage =
      Builder.createAllocStackInst(genAnonymousLabelName("iter"));
  auto *baseStorage =
      Builder.createAllocStackInst(genAnonymousLabelName("base"));
  auto *indexStorage =
      Builder.createAllocStackInst(genAnonymousLabelName("idx"));
  auto *sizeStorage =
      Builder.createAllocStackInst(genAnonymousLabelName("size"));

                                                                       
                                                       
  if (auto *VD =
          llvh::dyn_cast<ESTree::VariableDeclarationNode>(ForInStmt->_left)) {
    assert(
        VD->_declarations.size() == 1 && "for-in must have a single binding");
    auto *declarator =
        cast<ESTree::VariableDeclaratorNode>(&VD->_declarations.front());
    if (declarator->_init) {
                                                                  
                                                                             
                                         
      LReference initRef = createLRef(VD, true);
      initRef.emitStore(genExpression(declarator->_init));
    }
  }

                                                                        
                                                                             
                       
  Value *object = genExpression(ForInStmt->_right);
  Builder.createStoreStackInst(object, baseStorage);

                                                                 
  auto *propertyStorage =
      Builder.createAllocStackInst(genAnonymousLabelName("prop"));

    
                                                                  

                         
                         
                         \
                          \
                                              
                            \
                             \
                              \
                                                 
                                
                               
                                             
                
    

  auto parent = Builder.getInsertionBlock()->getParent();
  auto *exitBlock = Builder.createBasicBlock(parent);
  auto *getNextBlock = Builder.createBasicBlock(parent);
  auto *bodyBlock = Builder.createBasicBlock(parent);

                                
  curFunction()->initLabel(ForInStmt, exitBlock, getNextBlock);

                           
  Builder.createGetPNamesInst(
      iteratorStorage,
      baseStorage,
      indexStorage,
      sizeStorage,
      exitBlock,
      getNextBlock);

                                            
  Builder.setInsertionBlock(getNextBlock);
  Builder.createGetNextPNameInst(
      propertyStorage,
      baseStorage,
      indexStorage,
      sizeStorage,
      iteratorStorage,
      exitBlock,
      bodyBlock);

                                                                                
                                                      
  Builder.setInsertionBlock(bodyBlock);

                                                                          
              
  auto propertyStringRepr = Builder.createLoadStackInst(propertyStorage);

                                                                      
                           
                             
                           
                               
                                           
  LReference lref = createLRef(ForInStmt->_left, false);
  lref.emitStore(propertyStringRepr);

  genStatement(ForInStmt->_body, IsLoopBody::Yes);

  Builder.createBranchInst(getNextBlock);

  Builder.setInsertionBlock(exitBlock);
}

void ESTreeIRGen::genForAwaitOfStatement(ESTree::ForOfStatementNode *node) {
  auto *function = Builder.getFunction();
  auto *nextBB = Builder.createBasicBlock(function);
  auto *bodyBB = Builder.createBasicBlock(function);
  auto *exitBB = Builder.createBasicBlock(function);
  curFunction()->initLabel(node, exitBB, nextBB);
  auto *record = genBuiltinCall(
      BuiltinMethod::HermesBuiltin_asyncIterator, {genExpression(node->_right)});
  Builder.createBranchInst(nextBB);
  Builder.setInsertionBlock(nextBB);
  auto *result = genAwaitValue(genBuiltinCall(
      BuiltinMethod::HermesBuiltin_asyncIteratorNext, {record}));
  emitEnsureObject(result, "async iterator.next() did not return an object");
  auto *done = emitIteratorCompleteSlow(result);
  auto *valueBB = Builder.createBasicBlock(function);
  Builder.createCondBranchInst(done, exitBB, valueBB);
  Builder.setInsertionBlock(valueBB);
  auto *value = emitIteratorValueSlow(result);
  Builder.createBranchInst(bodyBB);
  Builder.setInsertionBlock(bodyBB);
  emitTryCatchScaffolding(
      nextBB,
      [this, node, record, nextBB, value]() {
        SurroundingTry thisTry{
            curFunction(), node, {},
            [this, record, nextBB](ESTree::Node *, ControlFlowChange cfc,
                                  BasicBlock *continueTarget) {
              if (cfc == ControlFlowChange::Break || continueTarget != nextBB)
                genAwaitValue(genBuiltinCall(
                    BuiltinMethod::HermesBuiltin_asyncIteratorClose,
                    {record, Builder.getLiteralBool(false)}));
            }};
        createLRef(node->_left, false).emitStore(value);
        genStatement(node->_body, IsLoopBody::Yes);
        Builder.setLocation(SourceErrorManager::convertEndToLocation(
            node->_body->getSourceRange()));
      },
      []() {},
      [this, record](BasicBlock *) {
        auto *exception = Builder.createCatchInst();
        genAwaitValue(genBuiltinCall(
            BuiltinMethod::HermesBuiltin_asyncIteratorClose,
            {record, Builder.getLiteralBool(true)}));
        Builder.createThrowInst(exception);
      });
  Builder.setInsertionBlock(exitBB);
}

void ESTreeIRGen::genForOfStatement(ESTree::ForOfStatementNode *forOfStmt) {
  if (forOfStmt->_await) {
    genForAwaitOfStatement(forOfStmt);
    return;
  }
  auto *function = Builder.getInsertionBlock()->getParent();
  auto *getNextBlock = Builder.createBasicBlock(function);
  auto *bodyBlock = Builder.createBasicBlock(function);
  auto *exitBlock = Builder.createBasicBlock(function);

                                
  curFunction()->initLabel(forOfStmt, exitBlock, getNextBlock);

  auto *exprValue = genExpression(forOfStmt->_right);
  const IteratorRecord iteratorRecord = emitGetIterator(exprValue);

  Builder.createBranchInst(getNextBlock);

                                                                             
                                                                            
                                                           
  Builder.setInsertionBlock(getNextBlock);
  auto *nextValue = emitIteratorNext(iteratorRecord);
  auto *done = emitIteratorComplete(iteratorRecord);
  Builder.createCondBranchInst(done, exitBlock, bodyBlock);

  Builder.setInsertionBlock(bodyBlock);

  emitTryCatchScaffolding(
      getNextBlock,
                  
      [this, forOfStmt, nextValue, &iteratorRecord, getNextBlock]() {
                                          
        SurroundingTry thisTry{
            curFunction(),
            forOfStmt,
            {},
            [this, &iteratorRecord, getNextBlock](
                ESTree::Node *,
                ControlFlowChange cfc,
                BasicBlock *continueTarget) {
                                                         
                                                             
                                                       
                                                           
                              
              if (cfc == ControlFlowChange::Break ||
                  continueTarget != getNextBlock)
                emitIteratorClose(iteratorRecord, false);
            }};

                                                                         
        createLRef(forOfStmt->_left, false).emitStore(nextValue);

        genStatement(forOfStmt->_body, IsLoopBody::Yes);
        Builder.setLocation(
            SourceErrorManager::convertEndToLocation(
                forOfStmt->_body->getSourceRange()));
      },
                           
      []() {},
                     
      [this, &iteratorRecord](BasicBlock *) {
        auto *catchReg = Builder.createCatchInst();
        emitIteratorClose(iteratorRecord, true);
        Builder.createThrowInst(catchReg);
      });

  Builder.setInsertionBlock(exitBlock);
}

void ESTreeIRGen::genReturnStatement(ESTree::ReturnStatementNode *RetStmt) {
  LLVM_DEBUG(llvh::dbgs() << "IRGen Return-stmt.\n");

  Value *Value;
                                                                              
               
  if (auto *A = RetStmt->_argument) {
    Value = genExpression(A);
  } else {
    Value = Builder.getLiteralUndefined();
  }

  if (curFunction()->asyncGeneratorBody) Value = genAwaitValue(Value);
  genFinallyBeforeControlChange(
      curFunction()->surroundingTry, nullptr, ControlFlowChange::Break);
                                                                              
  if (curFunction()->function->getDefinitionKind() ==
      Function::DefinitionKind::ES6DerivedConstructor) {
    assert(curFunction()->derivedThis);
    Value = genBuiltinCall(BuiltinMethod::HermesBuiltin_derivedConstructorReturn,
        {Builder.createLoadFrameInst(curFunction()->derivedThis, currentIRScope_), Value});
  }
  Builder.createReturnInst(Value);

                                                                              
                                                                              
        
  auto Parent = Builder.getInsertionBlock()->getParent();
  Builder.setInsertionBlock(Builder.createBasicBlock(Parent));
}

                                                 
static inline bool isDefaultCase(ESTree::SwitchCaseNode *caseStmt) {
                                                              
  return !caseStmt->_test;
}

bool ESTreeIRGen::areAllCasesConstant(
    ESTree::SwitchStatementNode *switchStmt,
    llvh::SmallVectorImpl<Literal *> &caseLiterals) {
  for (auto &c : switchStmt->_cases) {
    auto *caseStmt = cast<ESTree::SwitchCaseNode>(&c);

    if (isDefaultCase(caseStmt)) {
      caseLiterals.push_back(nullptr);
      continue;
    }

    if (!isConstantExpr(caseStmt->_test))
      return false;

    auto *lit = llvh::dyn_cast<Literal>(genExpression(caseStmt->_test));
    assert(lit && "constant expression must compile to a literal");
    caseLiterals.push_back(lit);
  }

  return true;
}

void ESTreeIRGen::genSwitchStatement(ESTree::SwitchStatementNode *switchStmt) {
  LLVM_DEBUG(llvh::dbgs() << "IRGen 'switch' statement.\n");

  {
    llvh::SmallVector<Literal *, 8> caseLiterals{};
    if (areAllCasesConstant(switchStmt, caseLiterals) &&
        caseLiterals.size() > 1) {
      genConstSwitchStmt(switchStmt, caseLiterals);
      return;
    }
  }

  Function *function = Builder.getInsertionBlock()->getParent();
  BasicBlock *exitBlock = Builder.createBasicBlock(function);

                                                                                
  BasicBlock *defaultBlock = exitBlock;

                                                
  llvh::SmallVector<BasicBlock *, 8> caseBlocks;

                                
  curFunction()->initLabel(switchStmt, exitBlock, nullptr);

                                  
  Value *discr = genExpression(switchStmt->_discriminant);

  std::optional<EnterBlockScope> enterBlockScope;
  if (Mod->getContext().getCodeGenerationSettings().enableBlockScoping) {
    enterBlockScope.emplace(curFunction());
    blockDeclarationInstantiation(switchStmt);
  }

                                                                                
                                                                      
  int caseIndex = -1;                                            
  BasicBlock *elseBlock = nullptr;                              

  for (auto &c : switchStmt->_cases) {
    auto *caseStmt = cast<ESTree::SwitchCaseNode>(&c);
    ++caseIndex;
    caseBlocks.push_back(Builder.createBasicBlock(function));

    if (isDefaultCase(caseStmt)) {
      defaultBlock = caseBlocks.back();
      continue;
    }

    auto *caseVal = genExpression(caseStmt->_test);
    auto *pred = Builder.createBinaryOperatorInst(
        caseVal, discr, BinaryOperatorInst::OpKind::StrictlyEqualKind);

    elseBlock = Builder.createBasicBlock(function);
    Builder.createCondBranchInst(pred, caseBlocks[caseIndex], elseBlock);
    Builder.setInsertionBlock(elseBlock);
  }

  Builder.createBranchInst(defaultBlock);

                              
  bool isFirstCase = true;
  caseIndex = -1;
  for (auto &c : switchStmt->_cases) {
    auto *caseStmt = cast<ESTree::SwitchCaseNode>(&c);
    ++caseIndex;

    // Generate the fall-through from the previous block to this one.
    if (!isFirstCase)
      Builder.createBranchInst(caseBlocks[caseIndex]);

    Builder.setInsertionBlock(caseBlocks[caseIndex]);
    genBody(caseStmt->_consequent);
    isFirstCase = false;
  }

  if (!isFirstCase)
    Builder.createBranchInst(exitBlock);

  Builder.setInsertionBlock(exitBlock);
}

void ESTreeIRGen::genConstSwitchStmt(
    ESTree::SwitchStatementNode *switchStmt,
    llvh::SmallVectorImpl<Literal *> &caseLiterals) {
  Function *function = Builder.getInsertionBlock()->getParent();
  BasicBlock *exitBlock = Builder.createBasicBlock(function);

                                                                                
  BasicBlock *defaultBlock = exitBlock;

  curFunction()->initLabel(switchStmt, exitBlock, nullptr);

                                  
  Value *discr = genExpression(switchStmt->_discriminant);

  std::optional<EnterBlockScope> enterBlockScope;
  if (Mod->getContext().getCodeGenerationSettings().enableBlockScoping) {
    enterBlockScope.emplace(curFunction());
    blockDeclarationInstantiation(switchStmt);
  }

                                                                
  auto *startBlock = Builder.getInsertionBlock();

                                                                             
                                                                  
  llvh::SmallPtrSet<Literal *, 8> valueSet;

  SwitchInst::ValueListType values;
  SwitchInst::BasicBlockListType blocks;

  int caseIndex = -1;
  bool isFirstCase = true;

  for (auto &c : switchStmt->_cases) {
    auto *caseStmt = cast<ESTree::SwitchCaseNode>(&c);
    auto *caseBlock = Builder.createBasicBlock(function);
    ++caseIndex;

    if (isDefaultCase(caseStmt)) {
      defaultBlock = caseBlock;
    } else {
      auto *lit = caseLiterals[caseIndex];

                                                                               
               
      if (valueSet.insert(lit).second) {
        values.push_back(lit);
        blocks.push_back(caseBlock);
      }
    }

    if (!isFirstCase)
      Builder.createBranchInst(caseBlock);

    Builder.setInsertionBlock(caseBlock);
    genBody(caseStmt->_consequent);
    isFirstCase = false;
  }

  if (!isFirstCase)
    Builder.createBranchInst(exitBlock);

  Builder.setInsertionBlock(startBlock);
  Builder.createSwitchInst(discr, defaultBlock, values, blocks);

  Builder.setInsertionBlock(exitBlock);
};

void ESTreeIRGen::genImportDeclaration(
    ESTree::ImportDeclarationNode *importDecl) {
  assert(
      Mod->getContext().getUseCJSModules() &&
      "import/export requires module mode");
                                                             
  Parameter *require = Builder.getFunction()->getParameters()[1];
  assert(
      require->getName().str() == "require" &&
      "CJS module second parameter must be 'require'");
  auto *source = genExpression(importDecl->_source);
  auto *exports = Builder.createCallInst(
      CallInst::kNoTextifiedCallee,
      require,
      Builder.getLiteralUndefined(),
      {source});
                                                          
  for (ESTree::Node &spec : importDecl->_specifiers) {
    if (auto *ids = llvh::dyn_cast<ESTree::ImportDefaultSpecifierNode>(&spec)) {
                                               
      auto *local = nameTable_.lookup(getNameFieldFromID(ids->_local));
      assert(local && "imported name should have been hoisted");
      emitStore(
          Builder.createLoadPropertyInst(exports, identDefaultExport_),
          local,
          true);
    } else if (
        auto *ins =
            llvh::dyn_cast<ESTree::ImportNamespaceSpecifierNode>(&spec)) {
                                         
      auto *local = nameTable_.lookup(getNameFieldFromID(ins->_local));
      assert(local && "imported name should have been hoisted");
      emitStore(exports, local, true);
    } else {
                                                
                                           
      auto *is = cast<ESTree::ImportSpecifierNode>(&spec);

                                                            
      auto *local = nameTable_.lookup(getNameFieldFromID(is->_local));
      assert(local && "imported name should have been hoisted");

                                                                           
                                 
      emitStore(
          Builder.createLoadPropertyInst(
              exports, getNameFieldFromID(is->_imported)),
          local,
          true);
    }
  }
  return;
}

void ESTreeIRGen::genExportNamedDeclaration(
    ESTree::ExportNamedDeclarationNode *exportDecl) {
  assert(
      Mod->getContext().getUseCJSModules() &&
      "import/export requires module mode");
                                                             
  Parameter *exports = Builder.getFunction()->getParameters()[0];
  assert(
      exports->getName().str() == "exports" &&
      "CJS module first parameter must be 'exports'");
  Parameter *require = Builder.getFunction()->getParameters()[1];
  assert(
      require->getName().str() == "require" &&
      "CJS module second parameter must be 'require'");

                                             
  if (auto *decl = exportDecl->_declaration) {
                                                                            
                                                                     
    assert(
        !exportDecl->_source &&
        "ExportNamedDeclarationNode with Declaration cannot have a source");
    assert(
        exportDecl->_specifiers.empty() &&
        "ExportNamedDeclarationNode with Declaration cannot have specifiers");
    if (auto *varDecl = llvh::dyn_cast<ESTree::VariableDeclarationNode>(decl)) {
                                 
      for (auto &declarator : varDecl->_declarations) {
        auto *variableDeclarator =
            cast<ESTree::VariableDeclaratorNode>(&declarator);
        genVariableDeclarator(varDecl->_kind, variableDeclarator);
        Identifier name = getNameFieldFromID(variableDeclarator->_id);

        Builder.createStorePropertyInst(
            emitLoad(nameTable_.lookup(name)), exports, name);
      }
    } else if (
        auto *classDecl = llvh::dyn_cast<ESTree::ClassDeclarationNode>(decl)) {
      (void)classDecl;
                                                                      
      Builder.getModule()->getContext().getSourceErrorManager().error(
          exportDecl->getSourceRange(),
          Twine("class declaration exports are unsupported"));
    } else {
      auto *funDecl = llvh::dyn_cast<ESTree::FunctionDeclarationNode>(decl);
                               
      Identifier name = getNameFieldFromID(funDecl->_id);
      auto *fun = emitLoad(nameTable_.lookup(name));
      Builder.createStorePropertyInst(fun, exports, name);
    }

    return;
  }

  auto *source = exportDecl->_source ? Builder.createCallInst(
                                           CallInst::kNoTextifiedCallee,
                                           require,
                                           Builder.getLiteralUndefined(),
                                           {genExpression(exportDecl->_source)})
                                     : nullptr;

  for (ESTree::Node &spec : exportDecl->_specifiers) {
    auto *es = cast<ESTree::ExportSpecifierNode>(&spec);
    auto *localIdent = cast<ESTree::IdentifierNode>(es->_local);
    auto *exportedIdent = cast<ESTree::IdentifierNode>(es->_exported);
                                                                          
                                                                              
            
    auto *local = source
        ? Builder.createLoadPropertyInst(source, getNameFieldFromID(localIdent))
        : genIdentifierExpression(localIdent, false);
    Builder.createStorePropertyInst(
        local, exports, getNameFieldFromID(exportedIdent));
  }
}

void ESTreeIRGen::genExportDefaultDeclaration(
    ESTree::ExportDefaultDeclarationNode *exportDecl) {
                                                             
  Parameter *exports = Builder.getFunction()->getParameters()[0];
  assert(
      exports->getName().str() == "exports" &&
      "CJS module first parameter must be 'exports'");
  auto *decl = exportDecl->_declaration;
  if (auto *funDecl = llvh::dyn_cast<ESTree::FunctionDeclarationNode>(decl)) {
    assert(
        funDecl->_id &&
        "SemanticValidator should change anonymous FunctionDeclaration");
                                       
                                                         
                                                          
    Identifier name = getNameFieldFromID(funDecl->_id);
    auto *fun = emitLoad(nameTable_.lookup(name));
    Builder.createStorePropertyInst(fun, exports, name);
  } else if (
      auto *classDecl = llvh::dyn_cast<ESTree::ClassDeclarationNode>(decl)) {
    (void)classDecl;
                                                                            
    Builder.getModule()->getContext().getSourceErrorManager().error(
        exportDecl->getSourceRange(),
        "default class declaration exports are unsupported");
  } else {
                                   
    auto *value = genExpression(decl);
    Builder.createStorePropertyInst(value, exports, identDefaultExport_);
  }
}

void ESTreeIRGen::genExportAllDeclaration(
    ESTree::ExportAllDeclarationNode *exportDecl) {
  assert(
      Mod->getContext().getUseCJSModules() &&
      "import/export requires module mode");
                                                             
  Parameter *exports = Builder.getFunction()->getParameters()[0];
  assert(
      exports->getName().str() == "exports" &&
      "CJS module first parameter must be 'exports'");
  Parameter *require = Builder.getFunction()->getParameters()[1];
  assert(
      require->getName().str() == "require" &&
      "CJS module second parameter must be 'require'");
                             
  auto *source = Builder.createCallInst(
      CallInst::kNoTextifiedCallee,
      require,
      Builder.getLiteralUndefined(),
      {genExpression(exportDecl->_source)});
                                                                               
  genBuiltinCall(BuiltinMethod::HermesBuiltin_exportAll, {exports, source});
}

}                   
}                    

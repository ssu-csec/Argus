/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "ESTreeIRGen.h"

#include "llvh/Support/SaveAndRestore.h"

#include <variant>

namespace hermes {
namespace irgen {

void ESTreeIRGen::genTryStatement(ESTree::TryStatementNode *tryStmt) {
  LLVM_DEBUG(llvh::dbgs() << "IRGen 'try' statement\n");

                                                                             
                                                                        
  assert(
      (!tryStmt->_handler || !tryStmt->_finalizer) &&
      "Try statement can't have both catch and finally");

  auto *nextBlock = emitTryCatchScaffolding(
      nullptr,
                  
      [this, tryStmt]() {
        llvh::Optional<SurroundingTry> thisTry;

        if (tryStmt->_finalizer) {
          thisTry.emplace(
              curFunction(),
              tryStmt,
              tryStmt->_finalizer->getDebugLoc(),
              [this](ESTree::Node *node, ControlFlowChange, BasicBlock *) {
                genStatement(
                    cast<ESTree::TryStatementNode>(node)->_finalizer,
                    IsLoopBody::No);
              });
        } else {
          thisTry.emplace(curFunction(), tryStmt);
        }

        genStatement(tryStmt->_block, IsLoopBody::No);

        Builder.setLocation(
            SourceErrorManager::convertEndToLocation(
                tryStmt->_block->getSourceRange()));
      },
                           
      [this, tryStmt]() {
        if (tryStmt->_finalizer) {
          genStatement(tryStmt->_finalizer, IsLoopBody::No);
          Builder.setLocation(
              SourceErrorManager::convertEndToLocation(
                  tryStmt->_finalizer->getSourceRange()));
        }
      },
                     
      [this, tryStmt](BasicBlock *nextBlock) {
                                    
        if (tryStmt->_handler) {
          auto *catchClauseNode =
              llvh::dyn_cast<ESTree::CatchClauseNode>(tryStmt->_handler);

                                                                            
                                                                          
                                                                               
                                                                               
                                                                            
                                                       
          std::variant<std::monostate, NameTableScopeTy, EnterBlockScope>
              newScope;

          if (!Mod->getContext()
                   .getCodeGenerationSettings()
                   .enableBlockScoping) {
            newScope.emplace<NameTableScopeTy>(nameTable_);
          } else {
            newScope.emplace<EnterBlockScope>(curFunction());
          }

          Builder.setLocation(tryStmt->_handler->getDebugLoc());
          prepareCatch(catchClauseNode);

          genCatchHandler(catchClauseNode->_body);

          Builder.setLocation(
              SourceErrorManager::convertEndToLocation(
                  tryStmt->_handler->getSourceRange()));
          Builder.createBranchInst(nextBlock);
        } else {
                                                                   
          Builder.setLocation(tryStmt->_finalizer->getDebugLoc());
          auto *catchReg = Builder.createCatchInst();

          genStatement(tryStmt->_finalizer, IsLoopBody::No);

          Builder.setLocation(
              SourceErrorManager::convertEndToLocation(
                  tryStmt->_finalizer->getSourceRange()));
          Builder.createThrowInst(catchReg);
        }
      });

  Builder.setInsertionBlock(nextBlock);
}

CatchInst *ESTreeIRGen::prepareCatch(ESTree::CatchClauseNode *catchHandler) {
  auto *catchInst = Builder.createCatchInst();

  if (Mod->getContext().getCodeGenerationSettings().enableBlockScoping) {
                                                                              
                                                   
    blockDeclarationInstantiation(catchHandler);
  }

  ESTree::NodePtr catchParam = catchHandler->_param;
  if (!catchParam) {
                                                                            
    return catchInst;
  }

  if (!llvh::isa<ESTree::IdentifierNode>(catchParam)) {
    if (!Mod->getContext().getCodeGenerationSettings().enableBlockScoping) {
      Builder.getModule()->getContext().getSourceErrorManager().error(
          catchParam->getSourceRange(),
          "Catch destructuring requires block scoping");
      return nullptr;
    }
                                                                        
                                                                           
                                                                              
    createLRef(catchParam, true).emitStore(catchInst);
    return catchInst;
  }

  Variable *errorVar{};

  if (!Mod->getContext().getCodeGenerationSettings().enableBlockScoping) {
    auto catchVariableName =
        getNameFieldFromID(cast<ESTree::IdentifierNode>(catchParam));

                                                                                
                                                                             
                               
    auto uniquedCatchVariableName =
        genAnonymousLabelName(catchVariableName.str());

    errorVar = Builder.createVariable(
        curFunction()->function->getFunctionScopeDesc(),
        Variable::DeclKind::Var,
        uniquedCatchVariableName);

                                                                               
                                
    nameTable_.insertIntoScope(
        curFunction()->functionScope, errorVar->getName(), errorVar);

                                                          
    nameTable_.insert(catchVariableName, errorVar);
  } else {
    auto catchVariableName =
        getNameFieldFromID(cast<ESTree::IdentifierNode>(catchParam));

    errorVar = Builder.createVariable(
        currentIRScopeDesc_, Variable::DeclKind::Var, catchVariableName);

                                                                               
                                
    nameTable_.insertIntoScope(
        curFunction()->blockScope, errorVar->getName(), errorVar);
  }

  emitStore(catchInst, errorVar, true);
  return catchInst;
}

void ESTreeIRGen::genFinallyBeforeControlChange(
    SurroundingTry *sourceTry,
    SurroundingTry *targetTry,
    ControlFlowChange cfc,
    BasicBlock *continueTarget) {
  assert(
      (cfc == ControlFlowChange::Break || continueTarget != nullptr) &&
      "Continue ControlFlowChange must have a target");
                                                                               
                                                              
  for (; sourceTry != targetTry; sourceTry = sourceTry->outer) {
    assert(sourceTry && "invalid try chain");

                                        
    auto *tryEndBlock = Builder.createBasicBlock(curFunction()->function);
    Builder.createBranchInst(tryEndBlock);
    Builder.setInsertionBlock(tryEndBlock);

                                                                  
    if (sourceTry->tryEndLoc.isValid()) {
      hermes::IRBuilder::ScopedLocationChange slc(
          Builder, sourceTry->tryEndLoc);
      Builder.createTryEndInst();
    } else {
      Builder.createTryEndInst();
    }

    if (sourceTry->genFinalizer) {
                                                                              
      llvh::SaveAndRestore<SurroundingTry *> sr{
          curFunction()->surroundingTry, sourceTry->outer};
      sourceTry->genFinalizer(sourceTry->node, cfc, continueTarget);
    }
  }
}

}                   
}                    

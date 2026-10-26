/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "SemanticValidator.h"

#include "hermes/AST/RecursiveVisitor.h"
#include "hermes/Support/InternalIdentifierMaker.h"
#include "hermes/Support/StringTable.h"
#include "llvh/ADT/SetVector.h"
#include "llvh/Support/SaveAndRestore.h"

namespace hermes {
namespace sem {
namespace {

                                                                           
                             
class BlockScopingTransformations {
 public:
  explicit BlockScopingTransformations(Context &astContext)
      : astContext_(astContext),
        internalIDs_(astContext.getStringTable()),
        identAssign_(astContext.getIdentifier("=").getUnderlyingPointer()),
        identExclaim_(astContext.getIdentifier("!").getUnderlyingPointer()),
        identLet_(astContext.getIdentifier("let").getUnderlyingPointer()),
        identUndefined_(
            astContext.getIdentifier("undefined").getUnderlyingPointer()),
        identVar_(astContext.getIdentifier("var").getUnderlyingPointer()) {}

  void visit(Node *node) {
    visitESTreeChildren(*this, node);
  }

  ESTree::VisitResult visit(ForInStatementNode *forInStmt) {
    return visitAndRewriteForInOf(forInStmt, forInStmt);
  }

  ESTree::VisitResult visit(ForOfStatementNode *forOfStmt) {
    return visitAndRewriteForInOf(forOfStmt, forOfStmt);
  }

  ESTree::VisitResult visit(ForStatementNode *forStmt) {
    return visitAndRewriteFor(forStmt, forStmt);
  }

                                  
     
                                 
                                 
                                        
     
                                              
  ESTree::VisitResult visit(LabeledStatementNode *labeledStmt) {
    LabeledStatementNode *firstLabel = labeledStmt;
    LabeledStatementNode *lastLabel = labeledStmt;

    while (auto *bodyLabel =
               llvh::dyn_cast<LabeledStatementNode>(lastLabel->_body)) {
      lastLabel = bodyLabel;
    }

    Node *body = lastLabel->_body;
    switch (body->getKind()) {
      case NodeKind::ForInStatement:
      case NodeKind::ForOfStatement:
        return visitAndRewriteForInOf(body, firstLabel);

      case NodeKind::ForStatement:
        return visitAndRewriteFor(
            llvh::cast<ForStatementNode>(body), firstLabel);

      default:
        visitESTreeNode(*this, body, lastLabel);
        return ESTree::Unmodified;
    }
  }

  bool incRecursionDepth(Node *n) {
    if (LLVM_UNLIKELY(recursionDepth_ == 0)) {
      return false;
    }
    --recursionDepth_;
    if (LLVM_UNLIKELY(recursionDepth_ == 0)) {
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

 private:
  Context &astContext_;
  InternalIdentifierMaker internalIDs_;

              
     
                                       
                                                        
     
          
     
                       
                   
                                            
                                   
                 
           
                             
                                                 
         
  ESTree::VisitResult visitAndRewriteForInOf(Node *forInOfStmt, Node *current) {
    visitESTreeChildren(*this, forInOfStmt);

    Node **left{};
    VariableDeclarationNode *decl;
    Node **body;

    if (auto *forIn = llvh::dyn_cast<ForInStatementNode>(forInOfStmt)) {
      left = &forIn->_left;
      body = &forIn->_body;
    } else if (auto *forOf = llvh::dyn_cast<ForOfStatementNode>(forInOfStmt)) {
      left = &forOf->_left;
      body = &forOf->_body;
    } else {
      assert(false && "If not for-in or for-of, then what?");
    }

    decl = llvh::dyn_cast_or_null<VariableDeclarationNode>(*left);

    if (!decl) {
                                       
        
                             
        
                               
      return ESTree::Unmodified;
    }

                                                       
    assert(
        decl->_declarations.size() == 1 &&
        "for-in/of(let/const/var should have a single declaration");

    auto *varDecl =
        llvh::cast<VariableDeclaratorNode>(&decl->_declarations.front());

    if (varDecl->_init != nullptr) {
                                                                                
                           
      return ESTree::Unmodified;
    }

    UniqueString *temp = internalIDs_.next("forInOf").getUnderlyingPointer();

                          
      
                      
                  
                                          
                            
                          
        
    UniqueString *wrapperBlockLabel =
        internalIDs_.next("wrapperBlock").getUnderlyingPointer();
    BlockStatementNode *wrapperBlock = makeBlock();

    VariableDeclarationNode *tempDecl = makeVarDeclaration(identLet_);
    tempDecl->_declarations.push_back(*makeVarDeclarator(temp));
    wrapperBlock->_body.push_back(*tempDecl);

    wrapperBlock->_body.push_back(*current);

    if (decl->_kind != identVar_) {
                                  
        
                             
        
                                                                            
                                                        
      VariableDeclarationNode *xTDZDecl = makeVarDeclaration(identLet_);
      llvh::SetVector<UniqueString *> ids;
      collectAllIDs(varDecl->_id, ids);
      for (UniqueString *id : ids) {
        xTDZDecl->_declarations.push_back(*makeVarDeclarator(id));
      }
      wrapperBlock->_body.push_back(*makeBreak(wrapperBlockLabel));
      wrapperBlock->_body.push_back(*xTDZDecl);
    }

                                                                              
    *left = makeIdentifier(temp);

                                               
    varDecl->_init = makeIdentifier(temp);

                                    
      
        
                                
              
        
    BlockStatementNode *newBody = makeBlock();
    newBody->_body.push_back(*decl);
    newBody->_body.push_back(**body);
    *body = newBody;

    return makeLabel(wrapperBlockLabel, wrapperBlock);
  }

              
     
                                                             
     
          
     
        
                            
                        
                          
                   
                   
                                
                       
                           
                   
                    
            
                            
                          
                                                                   
                 
            
                              
          
        
     
                                                                
     
                                                                 
                                       
                                                         
     
                                                                 
  ESTree::VisitResult visitAndRewriteFor(
      ForStatementNode *forStmt,
      Node *current) {
    visitESTreeChildren(*this, forStmt);

    auto *init =
        llvh::dyn_cast_or_null<VariableDeclarationNode>(forStmt->_init);
    if (!init || init->_kind == identVar_) {
                   
        
                                  
                               
        
                                            
      return ESTree::Unmodified;
    }

    BlockStatementNode *wrapperBlock = makeBlock();

    BlockStatementNode *outerBlock = makeBlock();                   

    Node *test = forStmt->_test;
    Node *update = forStmt->_update;

                                                                           
                                                                             
                                                                                
             
    forStmt->_init = nullptr;
    forStmt->_test = nullptr;
    forStmt->_update = nullptr;

                                                                                
                                                                  
      
                                                                               
                                                                                
      
                                                                           
                                                                            
                                                                        
                     
      
                                                                          
                                                                             
                                                                             
    VariableDeclarationNode *tempsDecl = makeVarDeclaration(identLet_);
    VariableDeclarationNode *initFromTemps = makeVarDeclaration(init->_kind);
    SequenceExpressionNode *newUpdate = makeSequenceExpression();

    llvh::DenseMap<UniqueString *, UniqueString *> tempIds;
    for (Node &n : init->_declarations) {
      auto *decl = llvh::cast<VariableDeclaratorNode>(&n);
      traverseForLexicalDecl(
          decl->_id, tempIds, tempsDecl, initFromTemps, newUpdate);
    }

                                  
      
        
                            
                                             
                   
                                    
        
    wrapperBlock->_body.push_back(*init);
    wrapperBlock->_body.push_back(*tempsDecl);
    wrapperBlock->_body.push_back(
        *toStatement(makeIdentifier(identUndefined_)));
    wrapperBlock->_body.push_back(
        *makeFor(nullptr, nullptr, nullptr, outerBlock));

                           
        
                              
                                     
                                               
                                                         
                                     
                                               
                                                       
                        
                                                                 
                            
        
    outerBlock->_body.push_back(*initFromTemps);

    if (update) {
                   
                         
             
                  
      UniqueString *first = internalIDs_.next("first").getUnderlyingPointer();
      tempsDecl->_declarations.push_back(
          *makeVarDeclarator(first, makeBooleanLiteral(true)));

      IdentifierNode *firstIsTrue = makeIdentifier(first);
      Node *firstEqFalse = toStatement(
          makeAssignment(makeIdentifier(first), makeBooleanLiteral(false)));
      outerBlock->_body.push_back(
          *makeIf(firstIsTrue, firstEqFalse, toStatement(update)));
    }

    if (test) {
                          
      outerBlock->_body.push_back(*makeIf(makeNot(test), makeBreak()));
    }

                                                                              
    UniqueString *control =
        internalIDs_.next("forControl").getUnderlyingPointer();
    tempsDecl->_declarations.push_back(*makeVarDeclarator(control));
    outerBlock->_body.push_back(*toStatement(
        makeAssignment(makeIdentifier(control), makeBooleanLiteral(true))));

                                                         
    newUpdate->_expressions.push_front(
        *makeAssignment(makeIdentifier(control), makeBooleanLiteral(false)));

                                
      
                                                 
    forStmt->_test = makeIdentifier(control);
    forStmt->_update = newUpdate;
    outerBlock->_body.push_back(*current);

                          
    outerBlock->_body.push_back(*makeIf(makeIdentifier(control), makeBreak()));

    return wrapperBlock;
  }

                                                                             
           
  static constexpr unsigned MAX_RECURSION_DEPTH =
#if defined(HERMES_LIMIT_STACK_DEPTH) || defined(_MSC_VER)
      512
#else
      1024
#endif
      ;

                                                                              
                             
  unsigned recursionDepth_ = MAX_RECURSION_DEPTH;

  UniqueString *const identAssign_;
  UniqueString *const identExclaim_;
  UniqueString *const identLet_;
  UniqueString *const identUndefined_;
  UniqueString *const identVar_;

                                                                              
                                      
  void collectAllIDs(Node *node, llvh::SetVector<UniqueString *> &ids) {
    switch (node->getKind()) {
      case NodeKind::Empty: {
        break;
      }
      case NodeKind::AssignmentPattern: {
        auto *assignment = llvh::cast<AssignmentPatternNode>(node);
        collectAllIDs(assignment->_left, ids);
        break;
      }
      case NodeKind::RestElement: {
        auto *rest = llvh::cast<RestElementNode>(node);
        collectAllIDs(rest->_argument, ids);
        break;
      }
      case NodeKind::Property: {
        auto *prop = llvh::cast<PropertyNode>(node);
        collectAllIDs(prop->_value, ids);
        break;
      }
      case NodeKind::ObjectPattern: {
        auto *objectPattern = llvh::cast<ObjectPatternNode>(node);
        for (Node &prop : objectPattern->_properties) {
          collectAllIDs(&prop, ids);
        }
        break;
      }
      case NodeKind::ArrayPattern: {
        auto *arrayPattern = llvh::cast<ArrayPatternNode>(node);
        for (Node &element : arrayPattern->_elements) {
          collectAllIDs(&element, ids);
        }
        break;
      }
      case NodeKind::Identifier: {
        auto *id = llvh::cast<IdentifierNode>(node);
        ids.insert(id->_name);
        break;
      }
      default:
        llvm_unreachable("unhandled node in collectAllIDs");
    }
  }

                                                              
     
                                           
     
                                                                             
                         
  void traverseForLexicalDecl(
      Node *node,
      llvh::DenseMap<UniqueString *, UniqueString *> &tempIds,
      VariableDeclarationNode *tempsDecl,
      VariableDeclarationNode *initFromTemps,
      SequenceExpressionNode *newUpdate) {
    switch (node->getKind()) {
      case NodeKind::Empty: {
        break;
      }
      case NodeKind::AssignmentPattern: {
        auto *assignment = llvh::cast<AssignmentPatternNode>(node);
        traverseForLexicalDecl(
            assignment->_left, tempIds, tempsDecl, initFromTemps, newUpdate);
        break;
      }
      case NodeKind::RestElement: {
        auto *rest = llvh::dyn_cast<RestElementNode>(node);
        traverseForLexicalDecl(
            rest->_argument, tempIds, tempsDecl, initFromTemps, newUpdate);
        break;
      }
      case NodeKind::Property: {
        auto *prop = llvh::cast<PropertyNode>(node);
        traverseForLexicalDecl(
            prop->_value, tempIds, tempsDecl, initFromTemps, newUpdate);
        break;
      }
      case NodeKind::ObjectPattern: {
        auto *objectPattern = llvh::cast<ObjectPatternNode>(node);
        for (Node &prop : objectPattern->_properties) {
          traverseForLexicalDecl(
              &prop, tempIds, tempsDecl, initFromTemps, newUpdate);
        }
        break;
      }
      case NodeKind::ArrayPattern: {
        auto *arrayPattern = llvh::cast<ArrayPatternNode>(node);
        for (Node &elt : arrayPattern->_elements) {
          traverseForLexicalDecl(
              &elt, tempIds, tempsDecl, initFromTemps, newUpdate);
        }
        break;
      }
      case NodeKind::Identifier: {
        auto *id = llvh::cast<IdentifierNode>(node);
        auto res = tempIds.insert(std::make_pair(id->_name, nullptr));
        if (res.second) {
          res.first->second =
              internalIDs_.next("forDecl").getUnderlyingPointer();
        }

        UniqueString *temp = res.first->second;

                                            
        tempsDecl->_declarations.push_back(
            *makeVarDeclarator(temp, makeIdentifier(id->_name)));

                                               
        initFromTemps->_declarations.push_back(
            *makeVarDeclarator(id->_name, makeIdentifier(temp)));

                                          
        newUpdate->_expressions.push_back(
            *makeAssignment(makeIdentifier(temp), makeIdentifier(id->_name)));

        break;
      }
      default:
        llvm_unreachable("unhandled node in duplicateID");
    }
  }

                                                  

                                       
  IdentifierNode *makeIdentifier(UniqueString *name) {
    return new (astContext_) IdentifierNode(name, nullptr, false);
  }

                                                       
  VariableDeclarationNode *makeVarDeclaration(UniqueString *kind) {
    return new (astContext_) VariableDeclarationNode(kind, {});
  }

                                                                     
  VariableDeclaratorNode *makeVarDeclarator(
      UniqueString *name,
      Node *init = nullptr) {
    return new (astContext_) VariableDeclaratorNode(init, makeIdentifier(name));
  }

                                                                
  AssignmentExpressionNode *makeAssignment(Node *dst, Node *src) {
    return new (astContext_) AssignmentExpressionNode(identAssign_, dst, src);
  }

                                            
                                                            
  StatementNode *toStatement(Node *n) {
    if (auto *stmt = llvh::dyn_cast<StatementNode>(n)) {
      return stmt;
    }
    return new (astContext_) ExpressionStatementNode(n, nullptr);
  }

                                             
  UnaryExpressionNode *makeNot(Node *n) {
    return new (astContext_) UnaryExpressionNode(identExclaim_, n, false);
  }

                                                                    
  LabeledStatementNode *makeLabel(UniqueString *label, Node *body) {
    return new (astContext_) LabeledStatementNode(makeIdentifier(label), body);
  }

                                                          
  BreakStatementNode *makeBreak(UniqueString *label = nullptr) {
    Node *labelNode{};
    if (label) {
      labelNode = makeIdentifier(label);
    }
    return new (astContext_) BreakStatementNode(labelNode);
  }

                                            
  BooleanLiteralNode *makeBooleanLiteral(bool value) {
    return new (astContext_) BooleanLiteralNode(value);
  }

                                         
  BlockStatementNode *makeBlock() {
    return new (astContext_) BlockStatementNode({});
  }

                                             
  SequenceExpressionNode *makeSequenceExpression() {
    return new (astContext_) SequenceExpressionNode({});
  }

                                                                      
  IfStatementNode *
  makeIf(Node *test, Node *consequent, Node *alternate = nullptr) {
    return new (astContext_) IfStatementNode(test, consequent, alternate);
  }

                                                                         
  ForStatementNode *makeFor(Node *init, Node *test, Node *update, Node *body) {
    return new (astContext_) ForStatementNode(init, test, update, body);
  }
};

}             

void canonicalizeForBlockScoping(Context &astContext, Node *root) {
  BlockScopingTransformations BST{astContext};
  visitESTreeNode(BST, root);
}
}                 
}                    

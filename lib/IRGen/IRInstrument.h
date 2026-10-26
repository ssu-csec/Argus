/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_IRGEN_IR_INSTRUMENT_H
#define HERMES_IRGEN_IR_INSTRUMENT_H

#include "hermes/IR/IRBuilder.h"

namespace hermes {

                                                                            
                                                                            
                                                                                
                                                                            
                                                                         
class IRInstrument {
 public:
#ifdef HERMES_ENABLE_IR_INSTRUMENTATION
  IRInstrument(Module *M, IRBuilder &builder);
  ~IRInstrument();

                                                              
  Value *getIID(ESTree::Node *node);

                                                            
  Value *invokeHook(llvh::StringRef name, llvh::ArrayRef<Value *> args);

  Value *undefinedIfNull(Value *v) {
    return v ? v : builder_.getLiteralUndefined();
  }

                                                    
                                                        
  Value *preBinaryExpression(
      ESTree::BinaryExpressionNode *,
      Value *left,
      Value *right);

                                                         
                                                                  
  Value *postBinaryExpression(
      ESTree::BinaryExpressionNode *,
      Value *cookie,
      Value *result,
      Value *left,
      Value *right);

                                                   
                                                        
  Value *preUnaryExpression(ESTree::UnaryExpressionNode *, Value *operand);

                                                        
                                                                  
  Value *postUnaryExpression(
      ESTree::UnaryExpressionNode *,
      Value *cookie,
      Value *result,
      Value *operand);

                                                         
                                                              
                                                    
                                                        
  Value *
  preAssignment(ESTree::AssignmentExpressionNode *, Value *left, Value *right);

                                                              
                                  
  Value *postAssignment(
      ESTree::AssignmentExpressionNode *,
      Value *cookie,
      Value *result,
      Value *left,
      Value *right);

 private:
  IRBuilder &builder_;
                                                           
  LiteralString *globalName_;
                                     
  Module *M_;
                                  
  bool enabled_;

#else
                                                                              
  IRInstrument(Module *M, IRBuilder &builder) {}
  ~IRInstrument() = default;

  inline Value *preBinaryExpression(
      ESTree::BinaryExpressionNode *,
      Value *left,
      Value *right) {
    return nullptr;
  }
  inline Value *postBinaryExpression(
      ESTree::BinaryExpressionNode *,
      Value *cookie,
      Value *result,
      Value *left,
      Value *right) {
    return result;
  }

  inline Value *preUnaryExpression(
      ESTree::UnaryExpressionNode *,
      Value *operand) {
    return nullptr;
  }
  inline Value *postUnaryExpression(
      ESTree::UnaryExpressionNode *,
      Value *cookie,
      Value *result,
      Value *operand) {
    return result;
  }

  inline Value *preAssignment(
      ESTree::AssignmentExpressionNode *node,
      Value *left,
      Value *right) {
    return nullptr;
  }
  inline Value *postAssignment(
      ESTree::AssignmentExpressionNode *node,
      Value *cookie,
      Value *result,
      Value *left,
      Value *right) {
    return result;
  }
#endif
};

}                    

#endif                                

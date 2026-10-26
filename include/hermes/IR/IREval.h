/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_IR_IREVAL_H
#define HERMES_IR_IREVAL_H

#include "hermes/IR/IR.h"
#include "hermes/IR/Instrs.h"

namespace hermes {
class IRBuilder;

                                                          
                                                                          
                                                            
Literal *evalUnaryOperator(
    UnaryOperatorInst::OpKind kind,
    IRBuilder &builder,
    Literal *operand);

                                                           
                                                                           
                                                            
Literal *evalBinaryOperator(
    BinaryOperatorInst::OpKind kind,
    IRBuilder &builder,
    Literal *lhs,
    Literal *rhs);

                                            
                                                                              
LiteralBool *evalToBoolean(IRBuilder &builder, Literal *operand);

                                           
                                                                               
LiteralString *evalToString(IRBuilder &builder, Literal *operand);

                                           
                                                                               
LiteralNumber *evalToNumber(IRBuilder &builder, Literal *operand);

                                                          
                                                                               
LiteralNumber *evalToInt32(IRBuilder &builder, Literal *operand);

                                          
                                                                                
LiteralBool *evalToBoolean(IRBuilder &builder, Value *operand);

                                                    
                                                
bool evalIsTrue(IRBuilder &builder, Literal *operand);

                                                     
                                                
bool evalIsFalse(IRBuilder &builder, Literal *operand);

}                    

#endif

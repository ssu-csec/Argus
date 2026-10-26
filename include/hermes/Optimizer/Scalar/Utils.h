/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_OPTIMIZER_SCALAR_UTILS_H
#define HERMES_OPTIMIZER_SCALAR_UTILS_H

#include "hermes/IR/IR.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/Instrs.h"
#include "llvh/ADT/DenseSet.h"
#include "llvh/ADT/SmallVector.h"

namespace hermes {

                                                                     
                                                   
   
                                                                                
                                                                         
                                                                               
                                         
Value *isStoreOnceVariable(Variable *V);

                                                                           
                                                   
   
                                                                               
                                                                           
                                                                               
                                               
Value *isStoreOnceStackLocation(AllocStackInst *AS);

                                                                            
Function *getCallee(Value *callee);

                                                                              
                              
bool isDirectCallee(Value *C, CallInst *CI);

                                                             
                                                                        
bool getCallSites(Function *F, llvh::SmallVectorImpl<CallInst *> &callsites);

                                                                                
bool deleteIncomingBlockFromPhis(
    BasicBlock *blockToModify,
    BasicBlock *incoming);

                                                              
                                                                                
                                                                            
                                                                        
void splitCriticalEdge(IRBuilder *builder, BasicBlock *from, BasicBlock *to);

                                                                              
                                                                             
                                                          
bool isSimpleSideEffectFreeInstruction(Instruction *I);
}                    
#endif                                   

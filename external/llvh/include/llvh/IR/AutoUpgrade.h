//===- AutoUpgrade.h - AutoUpgrade Helpers ----------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  These functions are implemented by lib/IR/AutoUpgrade.cpp.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_AUTOUPGRADE_H
#define LLVM_IR_AUTOUPGRADE_H

#include "llvh/ADT/StringRef.h"

namespace llvh {
  class CallInst;
  class Constant;
  class Function;
  class Instruction;
  class MDNode;
  class Module;
  class GlobalVariable;
  class Type;
  class Value;

                                                                               
                                                                             
                                                                       
                                                              
  bool UpgradeIntrinsicFunction(Function *F, Function *&NewFn);

                                                                          
                                                                   
  void UpgradeIntrinsicCall(CallInst *CI, Function *NewFn);

                                                                            
          
  void UpgradeInlineAsmString(std::string *AsmStr);

                                                                          
                                                                               
                                                                               
                                                          
  void UpgradeCallsToIntrinsic(Function* F);

                                                                                
                               
  bool UpgradeGlobalVariable(GlobalVariable *GV);

                                                                               
                         
  bool UpgradeModuleFlags(Module &M);

                                                                             
                                         
  bool UpgradeRetainReleaseMarker(Module &M);

  void UpgradeSectionAttributes(Module &M);

                                                                          
                                                                        
                                              
  MDNode *UpgradeTBAANode(MDNode &TBAANode);

                                                                         
                                                                              
  Instruction *UpgradeBitCastInst(unsigned Opc, Value *V, Type *DestTy,
                                  Instruction *&Temp);

                                                                              
                                                                          
                        
  Value *UpgradeBitCastExpr(unsigned Opc, Constant *C, Type *DestTy);

                                                                             
                                              
  bool UpgradeDebugInfo(Module &M);

                                                                   
  inline bool mayBeOldLoopAttachmentTag(StringRef Name) {
    return Name.startswith("llvm.vectorizer.");
  }

                                                
  MDNode *upgradeInstructionLoopAttachment(MDNode &N);

}                      

#endif

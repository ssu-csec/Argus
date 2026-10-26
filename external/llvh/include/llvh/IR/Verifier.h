//===- Verifier.h - LLVM IR Verifier ----------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the function verifier interface, that can be used for some
// sanity checking of input to the system, and for checking that transformations
// haven't done something bad.
//
// Note that this does not provide full 'java style' security and verifications,
// instead it just tries to ensure that code is well formed.
//
// To see what specifically is checked, look at the top of Verifier.cpp
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_VERIFIER_H
#define LLVM_IR_VERIFIER_H

#include "llvh/ADT/DenseMap.h"
#include "llvh/IR/PassManager.h"
#include <utility>

namespace llvh {

class APInt;
class Function;
class FunctionPass;
class Instruction;
class MDNode;
class Module;
class raw_ostream;
struct VerifierSupport;

                                             
class TBAAVerifier {
  VerifierSupport *Diagnostic = nullptr;

                                  
  template <typename... Tys> void CheckFailed(Tys &&... Args);

                                                                                
                                                                        
     
                                                    
                                                                                
                                                                           
     
                                                         
  using TBAABaseNodeSummary = std::pair<bool, unsigned>;
  DenseMap<const MDNode *, TBAABaseNodeSummary> TBAABaseNodes;

                                                                            
                                                               
  DenseMap<const MDNode *, bool> TBAAScalarNodes;

                                                          
        
  MDNode *getFieldNodeFromTBAABaseNode(Instruction &I, const MDNode *BaseNode,
                                       APInt &Offset, bool IsNewFormat);
  TBAAVerifier::TBAABaseNodeSummary verifyTBAABaseNode(Instruction &I,
                                                       const MDNode *BaseNode,
                                                       bool IsNewFormat);
  TBAABaseNodeSummary verifyTBAABaseNodeImpl(Instruction &I,
                                             const MDNode *BaseNode,
                                             bool IsNewFormat);

  bool isValidScalarTBAANode(const MDNode *MD);
        

public:
  TBAAVerifier(VerifierSupport *Diagnostic = nullptr)
      : Diagnostic(Diagnostic) {}
                                                                             
                               
  bool visitTBAAMetadata(Instruction &I, const MDNode *MD);
};

                                                                
         
   
                                                                             
                                                                             
             
bool verifyFunction(const Function &F, raw_ostream *OS = nullptr);

                              
   
                                                                      
                                                              
                                   
   
                                                               
                                                                    
                                                                 
                                                                    
bool verifyModule(const Module &M, raw_ostream *OS = nullptr,
                  bool *BrokenDebugInfo = nullptr);

FunctionPass *createVerifierPass(bool FatalErrors = true);

                                                                      
                          
class VerifierAnalysis : public AnalysisInfoMixin<VerifierAnalysis> {
  friend AnalysisInfoMixin<VerifierAnalysis>;

  static AnalysisKey Key;

public:
  struct Result {
    bool IRBroken, DebugInfoBroken;
  };

  Result run(Module &M, ModuleAnalysisManager &);
  Result run(Function &F, FunctionAnalysisManager &);
};

                                                                       
                                                                          
                                                 
bool verifyModule(bool &BrokenDebugInfo, const Module &M, raw_ostream *OS);

                           
   
                                                                               
                                                                 
                                                                          
                                                                              
                                       
   
                                                                              
                                       
class VerifierPass : public PassInfoMixin<VerifierPass> {
  bool FatalErrors;

public:
  explicit VerifierPass(bool FatalErrors = true) : FatalErrors(FatalErrors) {}

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
};

}                      

#endif                      

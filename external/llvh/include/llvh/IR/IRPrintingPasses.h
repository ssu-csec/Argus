//===- IRPrintingPasses.h - Passes to print out IR constructs ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
/// \file
///
/// This file defines passes to print out IR in various granularities. The
/// PrintModulePass pass simply prints out the entire module when it is
/// executed. The PrintFunctionPass class is designed to be pipelined with
/// other FunctionPass's, and prints out the functions of the module as they
/// are processed.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_IRPRINTINGPASSES_H
#define LLVM_IR_IRPRINTINGPASSES_H

#include "llvh/ADT/StringRef.h"
#include <string>

namespace llvh {
class Pass;
class BasicBlockPass;
class Function;
class FunctionPass;
class Module;
class ModulePass;
class PreservedAnalyses;
class raw_ostream;
template <typename IRUnitT, typename... ExtraArgTs> class AnalysisManager;

                                                                    
                   
ModulePass *createPrintModulePass(raw_ostream &OS,
                                  const std::string &Banner = "",
                                  bool ShouldPreserveUseListOrder = false);

                                                                   
                                         
FunctionPass *createPrintFunctionPass(raw_ostream &OS,
                                      const std::string &Banner = "");

                                                                
                   
BasicBlockPass *createPrintBasicBlockPass(raw_ostream &OS,
                                          const std::string &Banner = "");

                                                           
   
                                                                         
                                   
void printLLVMNameWithoutPrefix(raw_ostream &OS, StringRef Name);

                                             
bool isIRPrintingPass(Pass *P);

                                                                            
                                                              
                                                              
extern bool isFunctionInPrintList(StringRef FunctionName);

                                                                  
                                                                           
                                                                               
                                                    
extern bool forcePrintModuleIR();

extern bool shouldPrintBeforePass();
extern bool shouldPrintBeforePass(StringRef);
extern bool shouldPrintAfterPass();
extern bool shouldPrintAfterPass(StringRef);

                                                          
   
                                                                               
                                                                          
class PrintModulePass {
  raw_ostream &OS;
  std::string Banner;
  bool ShouldPreserveUseListOrder;

public:
  PrintModulePass();
  PrintModulePass(raw_ostream &OS, const std::string &Banner = "",
                  bool ShouldPreserveUseListOrder = false);

  PreservedAnalyses run(Module &M, AnalysisManager<Module> &);

  static StringRef name() { return "PrintModulePass"; }
};

                                                            
   
                                                                               
                                                                          
class PrintFunctionPass {
  raw_ostream &OS;
  std::string Banner;

public:
  PrintFunctionPass();
  PrintFunctionPass(raw_ostream &OS, const std::string &Banner = "");

  PreservedAnalyses run(Function &F, AnalysisManager<Function> &);

  static StringRef name() { return "PrintFunctionPass"; }
};

}                      

#endif

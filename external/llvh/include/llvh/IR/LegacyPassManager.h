//===- LegacyPassManager.h - Legacy Container for Passes --------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the legacy PassManager class.  This class is used to hold,
// maintain, and optimize execution of Passes.  The PassManager class ensures
// that analysis results are available before a pass runs, and that Pass's are
// destroyed when the PassManager is destroyed.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_LEGACYPASSMANAGER_H
#define LLVM_IR_LEGACYPASSMANAGER_H

#include "llvh/Pass.h"
#include "llvh/Support/CBindingWrapping.h"

namespace llvh {

class Pass;
class Module;

namespace legacy {

class PassManagerImpl;
class FunctionPassManagerImpl;

                                                                          
                                                                        
          
class PassManagerBase {
public:
  virtual ~PassManagerBase();

                                                                         
                                                                               
                                                                              
                                                                               
                                                           
  virtual void add(Pass *P) = 0;
};

                                          
class PassManager : public PassManagerBase {
public:

  PassManager();
  ~PassManager() override;

  void add(Pass *P) override;

                                                                             
                                                                            
  bool run(Module &M);

private:
                                                                      
                                                     
  PassManagerImpl *PM;
};

                                                                          
class FunctionPassManager : public PassManagerBase {
public:
                                                                              
                                                           
  explicit FunctionPassManager(Module *M);
  ~FunctionPassManager() override;

  void add(Pass *P) override;

                                                                    
                                                                      
                      
     
  bool run(Function &F);

                                                                             
     
  bool doInitialization();

                                                                         
     
  bool doFinalization();

private:
  FunctionPassManagerImpl *FPM;
  Module *M;
};

}                        

                                                                
DEFINE_STDCXX_CONVERSION_FUNCTIONS(legacy::PassManagerBase, LLVMPassManagerRef)

}                      

#endif

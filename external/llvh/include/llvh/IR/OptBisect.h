//===- llvm/IR/OptBisect.h - LLVM Bisect support ----------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file declares the interface for bisecting optimizations.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_OPTBISECT_H
#define LLVM_IR_OPTBISECT_H

#include "llvh/ADT/StringRef.h"

namespace llvh {

class Pass;
class Module;
class Function;
class BasicBlock;
class Region;
class Loop;
class CallGraphSCC;

                                                                       
                                             
class OptPassGate {
public:
  virtual ~OptPassGate() = default;

  virtual bool shouldRunPass(const Pass *P, const Module &U) { return true; }
  virtual bool shouldRunPass(const Pass *P, const Function &U)  {return true; }
  virtual bool shouldRunPass(const Pass *P, const BasicBlock &U)  { return true; }
  virtual bool shouldRunPass(const Pass *P, const Region &U)  { return true; }
  virtual bool shouldRunPass(const Pass *P, const Loop &U)  { return true; }
  virtual bool shouldRunPass(const Pass *P, const CallGraphSCC &U)  { return true; }
};

                                                                      
                                                                
                                                                  
                                  
class OptBisect : public OptPassGate {
public:
                                                                       
                                              
     
                                        
     
                                                                               
                          
  OptBisect();

  virtual ~OptBisect() = default;

                                                                            
     
                                                                              
                                                                         
                                                                                
                                                                          
                                                                                
                                                                    
     
                                                                            
                                                                            
                                                                         
  bool shouldRunPass(const Pass *P, const Module &U) override;
  bool shouldRunPass(const Pass *P, const Function &U) override;
  bool shouldRunPass(const Pass *P, const BasicBlock &U) override;
  bool shouldRunPass(const Pass *P, const Region &U) override;
  bool shouldRunPass(const Pass *P, const Loop &U) override;
  bool shouldRunPass(const Pass *P, const CallGraphSCC &U) override;

private:
  bool checkPass(const StringRef PassName, const StringRef TargetDesc);

  bool BisectEnabled = false;
  unsigned LastBisectNum = 0;
};

}                      

#endif                       

//===- InitLLVM.h -----------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_LLVM_H
#define LLVM_SUPPORT_LLVM_H

#include "llvh/ADT/SmallVector.h"
#include "llvh/Support/Allocator.h"
#include "llvh/Support/PrettyStackTrace.h"

                                                                            
                                          
  
                                                                            
                            
  
                                                                   
                                                                     
                                                                       
                                               
  
                                                                 
                         
namespace llvh {
class InitLLVM {
public:
  InitLLVM(int &Argc, const char **&Argv);
  InitLLVM(int &Argc, char **&Argv)
      : InitLLVM(Argc, const_cast<const char **&>(Argv)) {}

  ~InitLLVM();

private:
  BumpPtrAllocator Alloc;
  SmallVector<const char *, 0> Args;
  PrettyStackTraceProgram StackPrinter;
};
}                  

#endif

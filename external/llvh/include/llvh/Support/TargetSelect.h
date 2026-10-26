//===- TargetSelect.h - Target Selection & Registration ---------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides utilities to make sure that certain classes of targets are
// linked into the main application executable, and initialize them as
// appropriate.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_TARGETSELECT_H
#define LLVM_SUPPORT_TARGETSELECT_H

#include "llvh/Config/llvm-config.h"

extern "C" {
                                                                           
#define LLVM_TARGET(TargetName) void LLVMInitialize##TargetName##TargetInfo();
#include "llvh/Config/Targets.def"

#define LLVM_TARGET(TargetName) void LLVMInitialize##TargetName##Target();
#include "llvh/Config/Targets.def"

                                                                              
#define LLVM_TARGET(TargetName) void LLVMInitialize##TargetName##TargetMC();
#include "llvh/Config/Targets.def"

                                                                            
#define LLVM_ASM_PRINTER(TargetName) void LLVMInitialize##TargetName##AsmPrinter();
#include "llvh/Config/AsmPrinters.def"

                                                                           
#define LLVM_ASM_PARSER(TargetName) void LLVMInitialize##TargetName##AsmParser();
#include "llvh/Config/AsmParsers.def"

                                                                        
#define LLVM_DISASSEMBLER(TargetName) \
  void LLVMInitialize##TargetName##Disassembler();
#include "llvh/Config/Disassemblers.def"
}

namespace llvh {
                                                                              
                                                                         
                                                             
     
                                                                       
  inline void InitializeAllTargetInfos() {
#define LLVM_TARGET(TargetName) LLVMInitialize##TargetName##TargetInfo();
#include "llvh/Config/Targets.def"
  }

                                                                             
                                                                              
                                                             
     
                                                                       
  inline void InitializeAllTargets() {
                                                
    InitializeAllTargetInfos();

#define LLVM_TARGET(TargetName) LLVMInitialize##TargetName##Target();
#include "llvh/Config/Targets.def"
  }

                                                                               
                                                                        
                                                             
     
                                                                       
  inline void InitializeAllTargetMCs() {
#define LLVM_TARGET(TargetName) LLVMInitialize##TargetName##TargetMC();
#include "llvh/Config/Targets.def"
  }

                                                                              
                                                                                
                                       
     
                                                                       
  inline void InitializeAllAsmPrinters() {
#define LLVM_ASM_PRINTER(TargetName) LLVMInitialize##TargetName##AsmPrinter();
#include "llvh/Config/AsmPrinters.def"
  }

                                                                                
                                                                            
                                       
     
                                                                       
  inline void InitializeAllAsmParsers() {
#define LLVM_ASM_PARSER(TargetName) LLVMInitialize##TargetName##AsmParser();
#include "llvh/Config/AsmParsers.def"
  }

                                                                                
                                                                            
                                            
     
                                                                       
  inline void InitializeAllDisassemblers() {
#define LLVM_DISASSEMBLER(TargetName) LLVMInitialize##TargetName##Disassembler();
#include "llvh/Config/Disassemblers.def"
  }

                                                                            
                                                                             
                                                                              
     
                                                                       
  inline bool InitializeNativeTarget() {
                                                                         
#ifdef LLVM_NATIVE_TARGET
    LLVM_NATIVE_TARGETINFO();
    LLVM_NATIVE_TARGET();
    LLVM_NATIVE_TARGETMC();
    return false;
#else
    return true;
#endif
  }

                                                                     
                                                                
  inline bool InitializeNativeTargetAsmPrinter() {
                                                                          
#ifdef LLVM_NATIVE_ASMPRINTER
    LLVM_NATIVE_ASMPRINTER();
    return false;
#else
    return true;
#endif
  }

                                                                    
                                                               
  inline bool InitializeNativeTargetAsmParser() {
                                                                         
#ifdef LLVM_NATIVE_ASMPARSER
    LLVM_NATIVE_ASMPARSER();
    return false;
#else
    return true;
#endif
  }

                                                                       
                                                                 
  inline bool InitializeNativeTargetDisassembler() {
                                                                           
#ifdef LLVM_NATIVE_DISASSEMBLER
    LLVM_NATIVE_DISASSEMBLER();
    return false;
#else
    return true;
#endif
  }
}

#endif

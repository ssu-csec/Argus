/*===-- llvm-c/Support.h - Support C Interface --------------------*- C -*-===*\
|*                                                                            *|
|*                     The LLVM Compiler Infrastructure                       *|
|*                                                                            *|
|* This file is distributed under the University of Illinois Open Source      *|
|* License. See LICENSE.TXT for details.                                      *|
|*                                                                            *|
|*===----------------------------------------------------------------------===*|
|*                                                                            *|
|* This file defines the C interface to the LLVM support library.             *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifndef LLVM_C_SUPPORT_H
#define LLVM_C_SUPPORT_H

#include "llvh-c/DataTypes.h"
#include "llvh-c/Types.h"

#ifdef __cplusplus
extern "C" {
#endif

   
                                                                         
                                                                        
  
                                                     
    
LLVMBool LLVMLoadLibraryPermanently(const char* Filename);

   
                                                                               
                                                                            
                                                                                
                                     
  
                                           
   
void LLVMParseCommandLineOptions(int argc, const char *const *argv,
                                 const char *Overview);

   
                                                                  
                                                                         
                                                     
  
                                                       
   
void *LLVMSearchForAddressOfSymbol(const char *symbolName);

   
                                                                    
                                                               
             
  
                                        
   
void LLVMAddSymbol(const char *symbolName, void *symbolValue);

#ifdef __cplusplus
}
#endif

#endif

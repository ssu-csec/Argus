/*===------- llvm-c/Error.h - llvh::Error class C Interface -------*- C -*-===*\
|*                                                                            *|
|*                     The LLVM Compiler Infrastructure                       *|
|*                                                                            *|
|* This file is distributed under the University of Illinois Open Source      *|
|* License. See LICENSE.TXT for details.                                      *|
|*                                                                            *|
|*===----------------------------------------------------------------------===*|
|*                                                                            *|
|* This file defines the C interface to LLVM's Error class.                   *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifndef LLVM_C_ERROR_H
#define LLVM_C_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

#define LLVMErrorSuccess 0

   
                                                                             
   
typedef struct LLVMOpaqueError *LLVMErrorRef;

   
                         
   
typedef const void *LLVMErrorTypeId;

   
                                                                            
                         
   
LLVMErrorTypeId LLVHGetErrorTypeId(LLVMErrorRef Err);

   
                                                                              
                                                                                
                                                                               
                                                               
   
void LLVHConsumeError(LLVMErrorRef Err);

   
                                                                               
                                                                         
                                                                   
                           
   
char *LLVHGetErrorMessage(LLVMErrorRef Err);

   
                                      
   
void LLVHDisposeErrorMessage(char *ErrMsg);

   
                                            
   
LLVMErrorTypeId LLVHGetStringErrorTypeId();

#ifdef __cplusplus
}
#endif

#endif

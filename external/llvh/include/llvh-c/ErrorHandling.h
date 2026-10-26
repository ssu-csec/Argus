/*===-- llvm-c/ErrorHandling.h - Error Handling C Interface -------*- C -*-===*\
|*                                                                            *|
|*                     The LLVM Compiler Infrastructure                       *|
|*                                                                            *|
|* This file is distributed under the University of Illinois Open Source      *|
|* License. See LICENSE.TXT for details.                                      *|
|*                                                                            *|
|*===----------------------------------------------------------------------===*|
|*                                                                            *|
|* This file defines the C interface to LLVM's error handling mechanism.      *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifndef LLVM_C_ERROR_HANDLING_H
#define LLVM_C_ERROR_HANDLING_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*LLVMFatalErrorHandler)(const char *Reason);

   
                                                                               
                                                                                
                                                                            
                                                                              
                   
   
void LLVHInstallFatalErrorHandler(LLVMFatalErrorHandler Handler);

   
                                                                         
                           
   
void LLVHResetFatalErrorHandler(void);

   
                                                                          
                                                                            
         
   
void LLVHEnablePrettyStackTrace(void);

#ifdef __cplusplus
}
#endif

#endif

/*===-- llvm-c/Support.h - C Interface Types declarations ---------*- C -*-===*\
|*                                                                            *|
|*                     The LLVM Compiler Infrastructure                       *|
|*                                                                            *|
|* This file is distributed under the University of Illinois Open Source      *|
|* License. See LICENSE.TXT for details.                                      *|
|*                                                                            *|
|*===----------------------------------------------------------------------===*|
|*                                                                            *|
|* This file defines types used by the C interface to LLVM.                   *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifndef LLVM_C_TYPES_H
#define LLVM_C_TYPES_H

#include "llvh-c/DataTypes.h"

#ifdef __cplusplus
extern "C" {
#endif

   
                                                     
  
     
   

typedef int LLVMBool;

                   

   
                                                                             
                                                                            
                                                                            
                                                                         
                                                                           
                                                                             
                                                                            
                                    
   

   
                                                          
  
                          
   
typedef struct LLVMOpaqueMemoryBuffer *LLVMMemoryBufferRef;

   
                                                                               
   
typedef struct LLVMOpaqueContext *LLVMContextRef;

   
                                                                              
           
  
                    
   
typedef struct LLVMOpaqueModule *LLVMModuleRef;

   
                                                        
  
                  
   
typedef struct LLVMOpaqueType *LLVMTypeRef;

   
                                             
  
                           
   
typedef struct LLVMOpaqueValue *LLVMValueRef;

   
                                                       
  
                                
   
typedef struct LLVMOpaqueBasicBlock *LLVMBasicBlockRef;

   
                               
  
                              
   
typedef struct LLVMOpaqueMetadata *LLVMMetadataRef;

   
                                          
  
                                 
   
typedef struct LLVMOpaqueNamedMDNode *LLVMNamedMDNodeRef;

   
                                                                 
  
                                            
   
typedef struct LLVMOpaqueValueMetadataEntry LLVMValueMetadataEntry;

   
                                          
  
                               
   
typedef struct LLVMOpaqueBuilder *LLVMBuilderRef;

   
                                         
  
                               
   
typedef struct LLVMOpaqueDIBuilder *LLVMDIBuilderRef;

   
                                                            
                                                                             
                                               
   
typedef struct LLVMOpaqueModuleProvider *LLVMModuleProviderRef;

                                 
typedef struct LLVMOpaquePassManager *LLVMPassManagerRef;

                              
typedef struct LLVMOpaquePassRegistry *LLVMPassRegistryRef;

   
                                              
  
                    
typedef struct LLVMOpaqueUse *LLVMUseRef;

   
                                   
  
                       
   
typedef struct LLVMOpaqueAttributeRef *LLVMAttributeRef;

   
                            
   
typedef struct LLVMOpaqueDiagnosticInfo *LLVMDiagnosticInfoRef;

   
                    
   
typedef struct LLVMComdat *LLVMComdatRef;

   
                                     
   
typedef struct LLVMOpaqueModuleFlagEntry LLVMModuleFlagEntry;

   
                              
   
typedef struct LLVMOpaqueJITEventListener *LLVMJITEventListenerRef;

   
     
   

#ifdef __cplusplus
}
#endif

#endif

//===- llvm/CallingConv.h - LLVM Calling Conventions ------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines LLVM's set of calling conventions.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_CALLINGCONV_H
#define LLVM_IR_CALLINGCONV_H

namespace llvh {

                                                                            
                                       
   
namespace CallingConv {

                                                                                
  using ID = unsigned;

                                                                             
                          
                                            
  enum {
                                                                         
                                                                              
                                                                        
                                                       
    C = 0,

                                                                           
                                                                       
                               

                                                                        
                                                       
    Fast = 8,

                                                                            
                                                                               
                                                                               
                                                              
    Cold = 9,

                                                                           
    GHC = 10,

                                                                             
              
    HiPE = 11,

                                                                      
    WebKit_JS = 12,

                                                                         
                                           
    AnyReg = 13,

                                                                              
                 
    PreserveMost = 14,

                                                                        
                              
    PreserveAll = 15,

                                            
    Swift = 16,

                                                              
    CXX_FAST_TLS = 17,

                                                                             
                                         
    FirstTargetCC = 64,

                                                                           
                                                                        
                                                                              
                       
    X86_StdCall = 64,

                                                                               
                                                                           
                       
    X86_FastCall = 65,

                                                                               
                                        
    ARM_APCS = 66,

                                                                       
                                                  
    ARM_AAPCS = 67,

                                                                            
    ARM_AAPCS_VFP = 68,

                                                                            
    MSP430_INTR = 69,

                                                                            
                                                                             
                                               
    X86_ThisCall = 70,

                                          
                                                
    PTX_Kernel = 71,

                                                   
                                                            
    PTX_Device = 72,

                                                                            
                                              
                                                                                
                                                                    
                                                          
                                                              
                                                                  
                                                  
    SPIR_FUNC = 75,

                                                                   
                                                      
                                           
                                       
                                       
                              
    SPIR_KERNEL = 76,

                                                                     
    Intel_OCL_BI = 77,

                                                                     
                                                       
    X86_64_SysV = 78,

                                                             
                                                             
                                                                      
                                                                       
                       
                                                                     
                                                                         
                                        
    Win64 = 79,

                                                                         
                         
    X86_VectorCall = 80,

                                                                   
                                                                        
                  
                                                                       
    HHVM = 81,

                                                           
    HHVM_C = 82,

                                                                             
                                                                                
                                                                             
                                                                            
                   
    X86_INTR = 83,

                                        
    AVR_INTR = 84,

                                                        
    AVR_SIGNAL = 85,

                                                               
                                                                   
    AVR_BUILTIN = 86,

                                                                              
                                                                              
                                                                   
    AMDGPU_VS = 87,

                                                                 
    AMDGPU_GS = 88,

                                                              
    AMDGPU_PS = 89,

                                                                
    AMDGPU_CS = 90,

                                                          
    AMDGPU_KERNEL = 91,

                                                                             
    X86_RegCall = 92,

                                                                            
                         
    AMDGPU_HS = 93,

                                                                  
                                                                        
    MSP430_BUILTIN = 94,

                                                                              
            
    AMDGPU_LS = 95,

                                                                              
                                                                               
                                                                         
    AMDGPU_ES = 96,

                                                                 
    AArch64_VectorCall = 97,

                                                                         
    MaxID = 1023
  };

}                             

}                      

#endif                         

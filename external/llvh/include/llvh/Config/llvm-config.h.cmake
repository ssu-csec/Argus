                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
/* License. See LICENSE.TXT for details.                                      */
                                                                                
                                                                                

                                                                          
                                                                             
                                                                    

#ifndef LLVM_CONFIG_H
#define LLVM_CONFIG_H

                                           
#cmakedefine LLVM_ENABLE_DUMP

                                          
#cmakedefine LINK_POLLY_INTO_TOOLS

                                                          
#cmakedefine LLVM_DEFAULT_TARGET_TRIPLE "${LLVM_DEFAULT_TARGET_TRIPLE}"

                               
#cmakedefine01 LLVM_ENABLE_THREADS

                                    
#cmakedefine01 LLVM_HAS_ATOMICS

                                          
#cmakedefine LLVM_HOST_TRIPLE "${LLVM_HOST_TRIPLE}"

                                                                      
#cmakedefine LLVM_NATIVE_ARCH ${LLVM_NATIVE_ARCH}

                                                                    
#cmakedefine LLVM_NATIVE_ASMPARSER LLVMInitialize${LLVM_NATIVE_ARCH}AsmParser

                                                                     
#cmakedefine LLVM_NATIVE_ASMPRINTER LLVMInitialize${LLVM_NATIVE_ARCH}AsmPrinter

                                                                       
#cmakedefine LLVM_NATIVE_DISASSEMBLER LLVMInitialize${LLVM_NATIVE_ARCH}Disassembler

                                                                 
#cmakedefine LLVM_NATIVE_TARGET LLVMInitialize${LLVM_NATIVE_ARCH}Target

                                                                     
#cmakedefine LLVM_NATIVE_TARGETINFO LLVMInitialize${LLVM_NATIVE_ARCH}TargetInfo

                                                                    
#cmakedefine LLVM_NATIVE_TARGETMC LLVMInitialize${LLVM_NATIVE_ARCH}TargetMC

                                        
#cmakedefine LLVM_ON_UNIX ${LLVM_ON_UNIX}

                                                                 
#cmakedefine01 LLVM_USE_INTEL_JITEVENTS

                                                        
#cmakedefine01 LLVM_USE_OPROFILE

                                                    
#cmakedefine01 LLVM_USE_PERF

                                   
#define LLVM_VERSION_MAJOR ${LLVM_VERSION_MAJOR}

                                   
#define LLVM_VERSION_MINOR ${LLVM_VERSION_MINOR}

                                   
#define LLVM_VERSION_PATCH ${LLVM_VERSION_PATCH}

                         
#define LLVM_VERSION_STRING "${PACKAGE_VERSION}"

                                                                
                                             
   
#cmakedefine01 LLVM_FORCE_ENABLE_STATS

#endif

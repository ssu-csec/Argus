//===- llvm/Support/Debug.h - Easy way to add debug output ------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements a handy way of adding debugging information to your
// code, without it being enabled all of the time, and without having to add
// command line options to enable it.
//
// In particular, just wrap your code with the LLVM_DEBUG() macro, and it will
// be enabled automatically if you specify '-debug' on the command-line.
// LLVM_DEBUG() requires the DEBUG_TYPE macro to be defined. Set it to "foo"
// specify that your debug code belongs to class "foo". Be careful that you only
// do this after including Debug.h and not around any #include of headers.
// Headers should define and undef the macro acround the code that needs to use
// the LLVM_DEBUG() macro. Then, on the command line, you can specify
// '-debug-only=foo' to enable JUST the debug information for the foo class.
//
// When compiling without assertions, the -debug-* options and all code in
// LLVM_DEBUG() statements disappears, so it does not affect the runtime of the
// code.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_DEBUG_H
#define LLVM_SUPPORT_DEBUG_H

namespace llvh {

class raw_ostream;

#ifndef NDEBUG

                                                                              
                                                                               
                                  
   
bool isCurrentDebugType(const char *Type);

                                                                             
                                                                                
                                
   
void setCurrentDebugType(const char *Type);

                                                                
                                                                
                                                                 
   
void setCurrentDebugTypes(const char **Types, unsigned Count);

                                                                             
                                                                                
                                                                             
                                                          
   
                                                                               
   
                                                                              
                                                  
#define DEBUG_WITH_TYPE(TYPE, X)                                        \
  do { if (::llvh::DebugFlag && ::llvh::isCurrentDebugType(TYPE)) { X; } \
  } while (false)

#else
#define isCurrentDebugType(X) (false)
#define setCurrentDebugType(X)
#define setCurrentDebugTypes(X, N)
#define DEBUG_WITH_TYPE(TYPE, X) do { } while (false)
#endif

                                                                   
                                                                                
                          
   
extern bool DebugFlag;

                             
   
                                                                              
                                                                         
                                                    
      

                                            
   
extern bool VerifyDomInfo;

                                      
   
extern bool VerifyLoopInfo;

                                      
   
extern bool VerifyMemorySSA;

     

                                                                      
                                                                  
                                                                    
                                                                   
             
   
extern bool EnableDebugBuffering;

                                                                    
                                                                  
                                   
raw_ostream &dbgs();

                                                                               
                                                                           
                                                                          
                                                 
  
                                                               
  
#define LLVM_DEBUG(X) DEBUG_WITH_TYPE(DEBUG_TYPE, X)

}                      

#endif                        

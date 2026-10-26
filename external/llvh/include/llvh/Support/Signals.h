//===- llvm/Support/Signals.h - Signal Handling support ----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines some helpful functions for dealing with the possibility of
// unix signals occurring while your program is running.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_SIGNALS_H
#define LLVM_SUPPORT_SIGNALS_H

#include <string>

namespace llvh {
class StringRef;
class raw_ostream;

namespace sys {

                                                                             
                                                        
  void RunInterruptHandlers();

                                                                             
                                               
                                             
  bool RemoveFileOnSignal(StringRef Filename, std::string* ErrMsg = nullptr);

                                                                          
                      
  void DontRemoveFileOnSignal(StringRef Filename);

                                                                           
                                                 
                                                   
                                                                       
                                                                          
                                                                  
                                                                       
                                                                     
  void PrintStackTraceOnErrorSignal(StringRef Argv0,
                                    bool DisableCrashReporting = false);

                                                                           
  void DisableSystemDialogsOnCrash();

                                                                  
  void PrintStackTrace(raw_ostream &OS);

                                        
  void RunSignalHandlers();

  using SignalHandlerCallback = void (*)(void *);

                                                                               
                                                                          
                                    
  void AddSignalHandler(SignalHandlerCallback FnPtr, void *Cookie);

                                                                                
                                                                               
                                                                                
                                                                            
                                                                        
                                                                         
                                                                          
                                         
                                                              
  void SetInterruptFunction(void (*IF)());
}                     
}                      

#endif

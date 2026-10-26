//===- llvm/Support/Program.h ------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the llvh::sys::Program class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_PROGRAM_H
#define LLVM_SUPPORT_PROGRAM_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/Optional.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/Config/llvm-config.h"
#include "llvh/Support/ErrorOr.h"
#include <system_error>

namespace llvh {
namespace sys {

                                                                            
                                               
#if defined(LLVM_ON_UNIX)
  const char EnvPathSeparator = ':';
#elif defined (_WIN32)
  const char EnvPathSeparator = ';';
#endif

#if defined(_WIN32)
  typedef unsigned long procid_t;                                            
  typedef void *process_t;                                                    
#else
  typedef pid_t procid_t;
  typedef procid_t process_t;
#endif

                                                           
  struct ProcessInfo {
    enum : procid_t { InvalidPid = 0 };

    procid_t Pid;                                 
    process_t Process;                                       

                                             
    int ReturnCode;

    ProcessInfo();
  };

                                                         
     
                                                                                
                                                                          
                                                                         
     
                                                                           
                                           
                                                                            
                                                     
     
                                                                              
                                                                         
  ErrorOr<std::string>
  findProgramByName(StringRef Name, ArrayRef<StringRef> Paths = {});

                                                                              
                                                                   
                                                                   
  std::error_code ChangeStdinToBinary();
  std::error_code ChangeStdoutToBinary();

                                                                           
                                                                     
                                                                          
                       
                                                                            
                                                                     
                              
                                                                           
                                                                        
                                     
                                                      
  int ExecuteAndWait(
      StringRef Program,                                               
                                                                       
      ArrayRef<StringRef> Args,                                                
                                                                         
                                                                        
      Optional<ArrayRef<StringRef>> Env = None,                           
                                                                             
                                                                         
                                                                     
      ArrayRef<Optional<StringRef>> Redirects = {},     
                                                                           
                                                                
                                                                               
                                                                              
                                          
                                                                             
                                                                    
      unsigned SecondsToWait = 0,                                            
                                                                     
                                                                       
                                                                         
                      
      unsigned MemoryLimit = 0,                                             
                                                                         
                                                                           
                             
      std::string *ErrMsg = nullptr,                                          
                                                                           
                                                                               
                   
      bool *ExecutionFailed = nullptr);

                                                         
                                                                 
                                                                        
                                                                               
                                                         
  ProcessInfo ExecuteNoWait(StringRef Program, ArrayRef<StringRef> Args,
                            Optional<ArrayRef<StringRef>> Env,
                            ArrayRef<Optional<StringRef>> Redirects = {},
                            unsigned MemoryLimit = 0,
                            std::string *ErrMsg = nullptr,
                            bool *ExecutionFailed = nullptr);

                                                                   
                             
  bool commandLineFitsWithinSystemLimits(StringRef Program,
                                         ArrayRef<StringRef> Args);

                                                                   
                             
  bool commandLineFitsWithinSystemLimits(StringRef Program,
                                         ArrayRef<const char *> Args);

                                                                           
                                                               
  enum WindowsEncodingMethod {
                                                                            
                             
    WEM_UTF8,
    WEM_CurrentCodePage,
    WEM_UTF16
  };

                                                                         
                                
     
                                                                            
                                                                         
                                                                              
                                                                           
                                                                          
                                                           
                                                                              
                           
                                                                                
                                                             
     
                                                                               
                                                                             
                                                                            
                                                                               
     
                                            
  std::error_code
  writeFileWithEncoding(StringRef FileName, StringRef Contents,
                        WindowsEncodingMethod Encoding = WEM_UTF8);

                                                                       
                                                         
                                                                              
            
                                                       
                                                                               
                                                       
  ProcessInfo Wait(
      const ProcessInfo &PI,                                                 
      unsigned SecondsToWait,                                               
                                                                               
                                                                            
                                                                 
      bool WaitUntilTerminates,                                                 
                                      
      std::string *ErrMsg = nullptr                                          
                                                                           
                                                                               
                   
      );

#if defined(_WIN32)
                                                                                
                                                                               
        
              
  std::string flattenWindowsCommandLine(ArrayRef<StringRef> Args);
#endif
  }
}

#endif

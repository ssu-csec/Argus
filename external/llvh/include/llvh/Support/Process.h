//===- llvm/Support/Process.h -----------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
/// \file
///
/// Provides a library for accessing information about this process and other
/// processes on the operating system. Also provides means of spawning
/// subprocess for commands. The design of this library is modeled after the
/// proposed design of the Boost.Process library, and is design specifically to
/// follow the style of standard libraries and potentially become a proposal
/// for a standard library.
///
/// This file declares the llvh::sys::Process class which contains a collection
/// of legacy static interfaces for extracting various information about the
/// current process. The goal is to migrate users of this API over to the new
/// interfaces.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_PROCESS_H
#define LLVM_SUPPORT_PROCESS_H

#include "llvh/ADT/Optional.h"
#include "llvh/Support/Allocator.h"
#include "llvh/Support/Chrono.h"
#include "llvh/Support/DataTypes.h"
#include <system_error>

namespace llvh {
template <typename T> class ArrayRef;
class StringRef;

namespace sys {


                                                                        
                              
class Process {
public:
  static unsigned getPageSize();

                                  
                                                                           
                                                                           
                                                                       
                      
  static size_t GetMallocUsage();

                                                                          
                                                                          
                                                                           
                                                                           
             
                                                                        
                                                                              
                                                                               
  static void GetTimeUsage(TimePoint<> &elapsed,
                           std::chrono::nanoseconds &user_time,
                           std::chrono::nanoseconds &sys_time);

                                                                        
                                                                         
                                 
                                   
  static void PreventCoreFiles();

                                                                
  static bool AreCoreFilesPrevented();

                                                                                
                                                              
  static Optional<std::string> GetEnv(StringRef name);

                                                                            
                                                                            
                                                                        
                                                                            
                                                                         
                 
  static Optional<std::string> FindInEnvPath(StringRef EnvName,
                                             StringRef FileName,
                                             ArrayRef<std::string> IgnoreList);

  static Optional<std::string> FindInEnvPath(StringRef EnvName,
                                             StringRef FileName);

                                                                              
                                                                             
                                                                      
                                     
  static std::error_code FixupStandardFileDescriptors();

                                                                            
                                                                             
                                                                             
            
    
                                                                             
                                                                       
  static std::error_code SafelyCloseFileDescriptor(int FD);

                                                                          
                                                                           
              
  static bool StandardInIsUserInput();

                                                                       
                                                                          
                                                                   
  static bool StandardOutIsDisplayed();

                                                                      
                                                                          
                                                                   
  static bool StandardErrIsDisplayed();

                                                                           
                                                                            
                                                                   
  static bool FileDescriptorIsDisplayed(int fd);

                                                                           
                      
  static bool FileDescriptorHasColors(int fd);

                                                                  
                                                             
                                                             
                                                                
                                
  static unsigned StandardOutColumns();

                                                                  
                                                            
                                                            
                                                                
                                
  static unsigned StandardErrColumns();

                                                                         
                                                                      
                                            
  static bool StandardOutHasColors();

                                                                         
                                                                    
                                            
  static bool StandardErrHasColors();

                                                                          
                                                 
                                                                          
                            
  static void UseANSIEscapeCodes(bool enable);

                                                                
                                                                       
                      
  static bool ColorNeedsFlush();

                                                           
                                                                            
                                                                 
                                                                      
                            
  static const char *OutputColor(char c, bool bold, bool bg);

                                                               
  static const char *OutputBold(bool bg);

                                                                        
                        
  static const char *OutputReverse();

                                                                          
  static const char *ResetColor();

                                                                   
                                                                          
  static unsigned GetRandomNumber();
};

}
}

#endif

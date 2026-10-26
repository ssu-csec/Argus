//===- ToolOutputFile.h - Output files for compiler-like tools -----------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file defines the ToolOutputFile class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_TOOLOUTPUTFILE_H
#define LLVM_SUPPORT_TOOLOUTPUTFILE_H

#include "llvh/Support/raw_ostream.h"

namespace llvh {

                                                                               
                                               
                                                                   
                                                                 
                                                           
class ToolOutputFile {
                                                                                
                                                                       
                                                                               
                                        
  class CleanupInstaller {
                             
    std::string Filename;
  public:
                                                                       
    bool Keep;

    explicit CleanupInstaller(StringRef Filename);
    ~CleanupInstaller();
  } Installer;

                                                                           
  raw_fd_ostream OS;

public:
                                                                 
                  
  ToolOutputFile(StringRef Filename, std::error_code &EC,
                 sys::fs::OpenFlags Flags);

  ToolOutputFile(StringRef Filename, int FD);

                                          
  raw_fd_ostream &os() { return OS; }

                                                                               
                                     
  void keep() { Installer.Keep = true; }
};

}                      

#endif

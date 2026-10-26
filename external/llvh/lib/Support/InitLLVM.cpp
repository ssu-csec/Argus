//===-- InitLLVM.cpp -----------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "llvh/Support/InitLLVM.h"
#include "llvh/Support/Error.h"
#include "llvh/Support/ManagedStatic.h"
#include "llvh/Support/PrettyStackTrace.h"
#include "llvh/Support/Process.h"
#include "llvh/Support/Signals.h"
#include <string>

#ifdef _WIN32
#include "Windows/WindowsSupport.h"
#endif

using namespace llvh;
using namespace llvh::sys;

InitLLVM::InitLLVM(int &Argc, const char **&Argv) : StackPrinter(Argc, Argv) {
  sys::PrintStackTraceOnErrorSignal(Argv[0]);

#ifdef _WIN32
                                                                 
                                                                     
                                                                     
                                                                     
                                        
    
                                                                
                                                                  
               
  std::string Banner = std::string(Argv[0]) + ": ";
  ExitOnError ExitOnErr(Banner);

  ExitOnErr(errorCodeToError(windows::GetCommandLineArguments(Args, Alloc)));

                                                                
                                                              
  Args.push_back(nullptr);

  Argc = Args.size() - 1;
  Argv = Args.data();
#endif
}

InitLLVM::~InitLLVM() { llvm_shutdown(); }

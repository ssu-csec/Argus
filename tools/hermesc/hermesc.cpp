/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/CompilerDriver/CompilerDriver.h"

#include "llvh/Support/CommandLine.h"
#include "llvh/Support/FileSystem.h"
#include "llvh/Support/InitLLVM.h"
#include "llvh/Support/PrettyStackTrace.h"
#include "llvh/Support/Program.h"
#include "llvh/Support/Signals.h"

using namespace hermes;

int main(int argc, char **argv) {
#ifndef HERMES_FBCODE_BUILD
                              
  llvh::InitLLVM initLLVM(argc, argv);
#else
                                                                                
                                                                               
                                                                                
                                                                            
                                                                                
  llvh::llvm_shutdown_obj Y;
#endif
  llvh::cl::AddExtraVersionPrinter(driver::printHermesCompilerVersion);
  llvh::cl::ParseCommandLineOptions(argc, argv, "Hermes driver\n");

  if (driver::outputFormatFromCommandLineOptions() ==
      OutputFormatKind::Execute) {
                                                             
    llvh::errs()
        << "Please choose output, e.g. -emit-binary. hermesc does not support -exec.\n";
    llvh::errs() << "Example: hermesc -emit-binary -out myfile.hbc myfile.js\n";
    return EXIT_FAILURE;
  }

  driver::CompileResult res = driver::compileFromCommandLineOptions();
  if (res.bytecodeProvider) {
    llvh::errs() << "Execution not supported with hermesc\n";
    assert(
        false &&
        "Execution mode was not checked prior to compileFromCommandLineOptions");
    return EXIT_FAILURE;
  }
  return res.status;
}

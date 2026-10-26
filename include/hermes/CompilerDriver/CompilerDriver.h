/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_COMPILERDRIVER_COMPILERDRIVER_H
#define HERMES_COMPILERDRIVER_COMPILERDRIVER_H

#include "hermes/BCGen/HBC/BytecodeDataProvider.h"
#include "hermes/BCGen/HBC/BytecodeProviderFromSrc.h"
#include "llvh/Support/raw_ostream.h"

namespace hermes {
namespace driver {

enum CompileStatus {
                            
  Success,
                                           
  InvalidFlags,
                                                                
  ParsingFailed,
                                   
  VerificationFailed,
                                                                     
  LoadGlobalsFailed,
                                      
  InputFileError,
                                          
  OutputFileError,
                                           
  OptimizationFailed,
                                                               
  BackendError,
};

                                                                   
struct BytecodeBufferInfo {
                                   
  bool bufferIsMmapped{false};
                                                      
  char *bufferStart{nullptr};
                                  
  size_t bufferSize{0};
                                
  std::string filename;

  BytecodeBufferInfo() = default;

  BytecodeBufferInfo(
      bool isMmapped,
      char *start,
      size_t size,
      std::string filename)
      : bufferIsMmapped(isMmapped),
        bufferStart(start),
        bufferSize(size),
        filename(std::move(filename)) {};
};

                                                            
struct CompileResult {
                                
  CompileStatus status;

                                                                              
                        
  std::unique_ptr<hermes::hbc::BCProvider> bytecodeProvider{};

                                                                        
                                                                              
  BytecodeBufferInfo bytecodeBufferInfo{};

                 CompileResult(CompileStatus status) : status(status) {}
};

                                                        
OutputFormatKind outputFormatFromCommandLineOptions();

                                                                    
                           
CompileResult compileFromCommandLineOptions();

                                                                
void printHermesCompilerVMVersion(llvh::raw_ostream &s);

                                                                   
void printHermesCompilerVersion(llvh::raw_ostream &s);

}                    
}                    

namespace cl {
                                                                        
extern llvh::cl::opt<bool> BasicBlockProfiling;
extern llvh::cl::opt<bool> EmitAsyncBreakCheck;
extern llvh::cl::opt<bool> EnableBlockScoping;
extern llvh::cl::opt<bool> EnableEval;
extern llvh::cl::list<std::string> InputFilenames;
extern llvh::cl::opt<bool> OptimizedEval;
extern llvh::cl::opt<bool> VerifyIR;
extern llvh::cl::opt<bool> ES6Class;

}                
#endif

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_UTILS_OPTIONS_H
#define HERMES_UTILS_OPTIONS_H

namespace hermes {

enum OutputFormatKind {
  DumpAST,
  DumpTransformedAST,
  DumpJS,
  DumpTransformedJS,
  ViewCFG,
  DumpIR,
  DumpLIR,
  DumpRA,
  DumpLRA,
  DumpPostRA,
  DumpBytecode,
  EmitBundle,
  Execute,
};

                                                       
struct BytecodeGenerationOptions {
                               
  OutputFormatKind format = Execute;

                                        
  bool optimizationEnabled = false;

                                                             
  bool stripDebugInfoSection = false;

                                                                         
             
  bool prettyDisassemble = true;

                                                     
  bool basicBlockProfiling = false;

                                          
  bool staticBuiltinsEnabled = false;

                                        
  bool verifyIR = false;

                                                           
  bool stripFunctionNames = false;

                                                                            
  unsigned padFunctionBodiesPercent = 0;

                               
  bool stripSourceMappingURL = false;

                 BytecodeGenerationOptions(OutputFormatKind format)
      : format(format) {}

  static BytecodeGenerationOptions defaults() {
    return {Execute};
  }
};

}                    

#endif

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_HBC_HBC_H
#define HERMES_BCGEN_HBC_HBC_H

#include "hermes/BCGen/HBC/Bytecode.h"
#include "hermes/BCGen/HBC/BytecodeDataProvider.h"
#include "hermes/BCGen/HBC/BytecodeProviderFromSrc.h"
#include "hermes/IR/IR.h"
#include "hermes/Support/OptValue.h"
#include "hermes/Support/SHA1.h"
#include "hermes/Utils/Dumper.h"
#include "hermes/Utils/Options.h"

namespace llvh {
class raw_ostream;
}                  

namespace hermes {
class SourceMapGenerator;
namespace hbc {

using llvh::raw_ostream;

                                                                               
                                                                                
                                                                         
                     
                                                                         
                                                                                
                                           
                                             
std::unique_ptr<BytecodeModule> generateBytecodeModule(
    Module *M,
    Function *entryPoint,
    const BytecodeGenerationOptions &options,
    hermes::OptValue<uint32_t> segment = llvh::None,
    SourceMapGenerator *sourceMap = nullptr,
    std::unique_ptr<BCProviderBase> baseBCProvider = nullptr);

std::unique_ptr<BytecodeModule> generateBytecodeModule(
    Module *M,
    Function *lexicalTopLevel,
    Function *entryPoint,
    const BytecodeGenerationOptions &options,
    hermes::OptValue<uint32_t> segment = llvh::None,
    SourceMapGenerator *sourceMap = nullptr,
    std::unique_ptr<BCProviderBase> baseBCProvider = nullptr);

                                                       
                                                               
                                                                     
                               
                                                                         
                                                                                
                                           
std::unique_ptr<BytecodeModule> generateBytecode(
    Module *M,
    raw_ostream &OS,
    const BytecodeGenerationOptions &options,
    const SHA1 &sourceHash,
    hermes::OptValue<uint32_t> segment = llvh::None,
    SourceMapGenerator *sourceMap = nullptr,
    std::unique_ptr<BCProviderBase> baseBCProvider = nullptr);
}                 
}                    

#endif

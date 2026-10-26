/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifdef HERMESVM_PROFILER_BB

#ifndef HERMES_VM_BASICBLOCKEXECUTIONINFO_H
#define HERMES_VM_BASICBLOCKEXECUTIONINFO_H

#include "llvh/ADT/DenseMap.h"
#include "llvh/Support/raw_ostream.h"

namespace hermes {
namespace vm {

class Runtime;
class CodeBlock;

                                                        
                                                            
                                                                             
                                                                     
                                                                         
class BasicBlockExecutionInfo {
                                                          
                                   
                                                                       
               
                                                                          
                                       
  using FunctionStatisticMap = std::vector<std::pair<uint64_t, uint64_t>>;
                                                                 
  using RuntimeStatisticMap = llvh::DenseMap<CodeBlock *, FunctionStatisticMap>;

 private:
                                                                        
                      
  uint64_t nextBasicBlockSequenceNumber_{1};

                                                                              
                 
  RuntimeStatisticMap basicBlockStats_;

                                     
  CodeBlock *lastCodeBlock_{nullptr};

                                                      
  FunctionStatisticMap *lastFuncStatMap_{nullptr};

                                                          
  FunctionStatisticMap &getFuncStat(CodeBlock *curCodeBlock) {
                                             
    if (LLVM_UNLIKELY(curCodeBlock != lastCodeBlock_)) {
      lastCodeBlock_ = curCodeBlock;
      lastFuncStatMap_ = &basicBlockStats_[curCodeBlock];
    }
    assert(
        lastFuncStatMap_ != nullptr && "lastFuncStatMap_ should not be null.");
    return *lastFuncStatMap_;
  }

                                                                               
                     
  void resizeFuncStatMap(
      FunctionStatisticMap &funcStat,
      uint16_t entrypointIndex);

 public:
                                                 
  void executeBlock(CodeBlock *curCodeBlock, uint16_t pointIndex) {
    FunctionStatisticMap &funcStat = getFuncStat(curCodeBlock);
                                                                
                                       
    if (LLVM_UNLIKELY(funcStat.empty())) {
      resizeFuncStatMap(funcStat, pointIndex);
    }
    assert(pointIndex < funcStat.size() && "Why is the table not big enough?");
    auto &blockStat = funcStat[pointIndex];
    if (blockStat.first == 0) {
                                                                 
      assert(blockStat.second == 0);
      assert(
          nextBasicBlockSequenceNumber_ != 0 &&
          "nextBasicBlockSequenceNumber overflows!");
      blockStat.second = nextBasicBlockSequenceNumber_++;
    }
    ++blockStat.first;
  }

                                                  
  void dump(llvh::raw_ostream &OS);
};

}                
}                    

#endif                                       
#endif                        

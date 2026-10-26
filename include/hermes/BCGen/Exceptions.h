/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_EXCEPTIONS_H
#define HERMES_BCGEN_EXCEPTIONS_H

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/SmallPtrSet.h"
#include "llvh/ADT/SmallVector.h"

namespace hermes {

class BasicBlock;
class Function;
class CatchInst;

                                                                             
                                                                     
                
class CatchCoverageInfo {
 public:
                                                     
  int catchLocation{0};

                                                     
  llvh::SmallVector<BasicBlock *, 8> coveredBlockList{};

                                         
  unsigned depth{0};

  explicit CatchCoverageInfo(int location) : catchLocation{location} {}
  explicit CatchCoverageInfo() = default;
};

                                                                                
                                   
                                                                                
struct ExceptionHandlerInfo {
  uint32_t start;
  uint32_t end;
  uint32_t target;
  uint32_t depth;

                                                                           
                                     
  bool operator<(const ExceptionHandlerInfo &rhs) const {
    assert(
        (this == &rhs || depth != rhs.depth || start != rhs.start) &&
        "two handlers with equal depth and start");
    return depth > rhs.depth || (depth == rhs.depth && start < rhs.start);
  }
};

                                                          
using CatchInfoMap = llvh::DenseMap<CatchInst *, CatchCoverageInfo>;

                                                                           
using BasicBlockInfoMap =
    llvh::DenseMap<BasicBlock *, std::pair<uint32_t, uint32_t>>;

                                              
using ExceptionEntryList = llvh::SmallVector<ExceptionHandlerInfo, 4>;

                                                                         
                                                                               
                                                        
                                         
                                                                       
                                                                     
                                                                   
                                        
                                                                        
                                                                
llvh::Optional<llvh::SmallPtrSet<BasicBlock *, 4>> constructCatchMap(
    Function *F,
    CatchInfoMap &catchInfoMap,
    llvh::SmallVectorImpl<CatchInst *> &aliveCatches,
    llvh::SmallPtrSetImpl<BasicBlock *> &visited,
    BasicBlock *startBlock,
    uint32_t maxRecursionDepth);

                                                                               
ExceptionEntryList generateExceptionHandlers(
    CatchInfoMap &catchInfoMap,
    BasicBlockInfoMap &bbMap,
    Function *F);

}                    

#endif

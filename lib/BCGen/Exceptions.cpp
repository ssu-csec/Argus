/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "exceptions"

#include "hermes/BCGen/Exceptions.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/IR.h"
#include "hermes/IR/IRBuilder.h"

#include "llvh/Support/raw_ostream.h"

using namespace hermes;

                                                                         
                                           
llvh::Optional<llvh::SmallPtrSet<BasicBlock *, 4>> hermes::constructCatchMap(
    Function *F,
    CatchInfoMap &catchInfoMap,
    llvh::SmallVectorImpl<CatchInst *> &aliveCatches,
    llvh::SmallPtrSetImpl<BasicBlock *> &visited,
    BasicBlock *startBlock,
    uint32_t maxRecursionDepth) {
  assert(
      !llvh::isa<CatchInst>(startBlock->front()) &&
      "Functions and try bodies should never start with a catch instruction.");
  if (maxRecursionDepth == 0) {
    F->getContext().getSourceErrorManager().error(
        F->getSourceRange(), "Too deeply nested try/catch");
    return llvh::None;
  }

                                  
  llvh::SmallVector<BasicBlock *, 4> stack;
                                                                              
                        
  llvh::SmallPtrSet<BasicBlock *, 4> tryEndBlocks;

  visited.insert(startBlock);
  stack.push_back(startBlock);
  while (!stack.empty()) {
    BasicBlock *currentBlock = stack.pop_back_val();
    assert(
        visited.count(currentBlock) &&
        "All blocks on the stack must be marked as visited.");

                                                                         
    for (const auto &aliveCatch : aliveCatches)
      catchInfoMap[aliveCatch].coveredBlockList.push_back(currentBlock);

    auto *tryStartInst =
        llvh::dyn_cast<TryStartInst>(currentBlock->getTerminator());

    if (!tryStartInst) {
                                                                      
      for (BasicBlock *successor : successors(currentBlock)) {
                                                                               
                                                                  
                                                        
        if (llvh::isa<TryEndInst>(&successor->front()))
          tryEndBlocks.insert(successor);
        else if (visited.insert(successor).second)
          stack.push_back(successor);
      }
      continue;
    }

                                                                 
                                                                         
    auto catchInst = cast<CatchInst>(&tryStartInst->getCatchTarget()->front());
    catchInfoMap[catchInst].depth = aliveCatches.size();

                                                                              
    aliveCatches.push_back(catchInst);
    auto endBlocks = constructCatchMap(
        F,
        catchInfoMap,
        aliveCatches,
        visited,
        tryStartInst->getTryBody(),
        maxRecursionDepth - 1);
    if (!endBlocks)
      return llvh::None;
    aliveCatches.pop_back();

    for (BasicBlock *endBlock : *endBlocks) {
      assert(
          visited.count(endBlock) == 0 &&
          "End blocks must be dominated by the try start.");
      assert(
          llvh::isa<TryEndInst>(&endBlock->front()) &&
          "End blocks must start with TryEndInst.");
      visited.insert(endBlock);
      stack.push_back(endBlock);
    }

                                                           
    BasicBlock *catchTarget = tryStartInst->getCatchTarget();
    assert(
        visited.count(catchTarget) == 0 &&
        "Catch block must be dominated by the try start.");
    visited.insert(catchTarget);
    stack.push_back(catchTarget);
  }
  assert(
      (aliveCatches.size() || !tryEndBlocks.size()) &&
      "Block without live catches cannot have TryEndInst.");
  return tryEndBlocks;
}

ExceptionEntryList hermes::generateExceptionHandlers(
    CatchInfoMap &catchInfoMap,
    BasicBlockInfoMap &bbMap,
    Function *F) {
                                                                      
  llvh::SmallVector<CatchInst *, 4> aliveCatches{};
  llvh::SmallPtrSet<BasicBlock *, 32> visited{};
  static constexpr uint32_t MAX_RECURSION_DEPTH = 1024;
  if (!constructCatchMap(
          F,
          catchInfoMap,
          aliveCatches,
          visited,
          &F->front(),
          MAX_RECURSION_DEPTH))
    return {};

  ExceptionEntryList exception_entries;
  for (auto I : catchInfoMap) {
    auto &catchInfo = I.second;
                                                                             
                                                                        
                                                             
    llvh::SmallVector<std::pair<uint32_t, uint32_t>, 4> catch_ranges;
    for (auto BB : catchInfo.coveredBlockList) {
      auto it = bbMap.find(BB);
      assert(it != bbMap.end() && "Basic Block missing.");

      auto resolved_loc = it->second;
      if (resolved_loc.first == resolved_loc.second) {
                                   
        continue;
      }
      catch_ranges.push_back(resolved_loc);
    }
    std::sort(catch_ranges.begin(), catch_ranges.end());
                                                                      
                                            
                                                                  
    int nextIndex = 0;
    for (auto resolved_loc : catch_ranges) {
                                                                  
                                                                
      if (nextIndex == 0 ||
          catch_ranges[nextIndex - 1].second != resolved_loc.first) {
        catch_ranges[nextIndex++] = resolved_loc;
        continue;
      }
                                                    
      catch_ranges[nextIndex - 1].second = resolved_loc.second;
    }
                                                                           
    catch_ranges.resize(nextIndex);
                                                                    
    for (auto range : catch_ranges) {
      exception_entries.push_back(
          {(uint32_t)range.first,
           (uint32_t)range.second,
           (uint32_t)catchInfo.catchLocation,
           catchInfo.depth});
    }
  }
                                                                             
                       
  std::sort(exception_entries.begin(), exception_entries.end());
  return exception_entries;
}

#undef DEBUG_TYPE

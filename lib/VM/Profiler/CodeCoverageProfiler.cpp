/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/Profiler/CodeCoverageProfiler.h"

#include "hermes/VM/Callable.h"

#include <assert.h>
#include <unordered_map>

namespace hermes {
namespace vm {

                                                                            
                                                     
             std::unordered_set<CodeCoverageProfiler *> &
CodeCoverageProfiler::allProfilers() {
  static auto *const allProfilers =
      new std::unordered_set<CodeCoverageProfiler *>();
  return *allProfilers;
}
             std::mutex &CodeCoverageProfiler::globalMutex() {
  static auto *const globalMutex = new std::mutex();
  return *globalMutex;
}

void CodeCoverageProfiler::markRoots(RootAcceptor &acceptor) {
  for (Domain *&domain : domains_) {
    acceptor.acceptPtr(domain);
  }
}

void CodeCoverageProfiler::markExecutedSlowPath(CodeBlock *codeBlock) {
  std::lock_guard<std::mutex> lk(localMutex_);
  std::vector<bool> &moduleFuncMap =
      getModuleFuncMapRef(codeBlock->getRuntimeModule());

  const auto funcId = codeBlock->getFunctionID();
  assert(
      funcId < moduleFuncMap.size() &&
      "funcId is out of bound for moduleFuncMap.");
  moduleFuncMap[funcId] = true;
}

             std::
    unordered_map<std::string, std::vector<CodeCoverageProfiler::FuncInfo>>
    CodeCoverageProfiler::getExecutedFunctions() {
  std::lock_guard<std::mutex> lk(globalMutex());
  auto &profilers = allProfilers();
  std::unordered_map<std::string, std::vector<CodeCoverageProfiler::FuncInfo>>
      result;
  for (const auto &profiler : profilers) {
    std::vector<CodeCoverageProfiler::FuncInfo> profilerOutput =
        profiler->getExecutedFunctionsLocal();
    result.emplace(profiler->runtime_.getHeap().getName(), profilerOutput);
  }
  return result;
}

std::vector<CodeCoverageProfiler::FuncInfo>
CodeCoverageProfiler::getExecutedFunctionsLocal() {
  std::vector<CodeCoverageProfiler::FuncInfo> funcInfos;
  std::lock_guard<std::mutex> lk(localMutex_);
  for (auto &entry : executedFuncBitsArrayMap_) {
    auto *bcProvider = entry.first->getBytecode();
    const uint32_t segmentID = bcProvider->getSegmentID();
                                                                   
                                                              
                                                                
                 
    llvh::StringRef sourceURL = entry.first->getSourceURL();
    const auto *debugInfo = bcProvider->getDebugInfo();
    const std::vector<bool> &moduleFuncBitsArray = entry.second;
    for (uint32_t i = 0; i < moduleFuncBitsArray.size(); ++i) {
      if (moduleFuncBitsArray[i]) {
        const auto *offsets = bcProvider->getDebugOffsets(i);
        if (debugInfo && offsets &&
            offsets->sourceLocations != hbc::DebugOffsets::NO_OFFSET) {
          if (auto pos = debugInfo->getLocationForAddress(
                  offsets->sourceLocations, 0                   )) {
            const std::string file =
                debugInfo->getFilenameByID(pos->filenameId);
            const uint32_t line = pos->line - 1;                             
            const uint32_t column =
                pos->column - 1;                             
            funcInfos.emplace_back(line, column, file);
          }
        } else {
          const uint32_t funcVirtualOffset =
              bcProvider->getVirtualOffsetForFunction(i);
          funcInfos.emplace_back(segmentID, funcVirtualOffset, sourceURL);
        }
      }
    }
  }
  return funcInfos;
}

std::vector<bool> &CodeCoverageProfiler::getModuleFuncMapRef(
    RuntimeModule *module) {
  auto funcMapIter = executedFuncBitsArrayMap_.find(module);
  if (LLVM_LIKELY(funcMapIter != executedFuncBitsArrayMap_.end())) {
    return funcMapIter->second;
  }

                                                    
  domains_.insert(module->getDomainUnsafe(runtime_));

  const uint32_t funcCount = module->getBytecode()->getFunctionCount();
  auto res = executedFuncBitsArrayMap_.insert(
      std::make_pair(module, std::vector<bool>(funcCount)));
  return res.first->second;
}

bool operator==(
    const CodeCoverageProfiler::FuncInfo &left,
    const CodeCoverageProfiler::FuncInfo &right) {
  return left.moduleId == right.moduleId &&
      left.funcVirtualOffset == right.funcVirtualOffset &&
      left.debugInfo == right.debugInfo;
}

}                
}                    

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_CODECOVERAGEPROFILER_H
#define HERMES_VM_CODECOVERAGEPROFILER_H

#include "hermes/VM/Domain.h"
#include "hermes/VM/Runtime.h"
#include "hermes/VM/RuntimeModule-inline.h"

#include "llvh/ADT/DenseMap.h"

#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace hermes {
namespace vm {

                                    
class CodeCoverageProfiler {
 public:
                             
  struct FuncInfo {
    FuncInfo(
        uint32_t moduleId,
        uint32_t funcVirtualOffset,
        std::string debugInfo)
        : moduleId(moduleId),
          funcVirtualOffset(funcVirtualOffset),
          debugInfo(debugInfo) {}

                                 
    uint32_t moduleId;
                                                  
    uint32_t funcVirtualOffset;

    std::string debugInfo;
  };

  explicit CodeCoverageProfiler(Runtime &runtime) : runtime_(runtime) {
    std::lock_guard<std::mutex> lk(globalMutex());
    allProfilers().insert(this);
  }

  ~CodeCoverageProfiler() {
    std::lock_guard<std::mutex> lk(globalMutex());
    allProfilers().erase(this);
  }

                                                                
  static std::
      unordered_map<std::string, std::vector<CodeCoverageProfiler::FuncInfo>>
      getExecutedFunctions();

                                                 
  static void enableGlobal() {
    globalEnabledFlag().store(true, std::memory_order_relaxed);
  }

                                                  
  static void disableGlobal() {
    globalEnabledFlag().store(false, std::memory_order_relaxed);
  }

                                                
  static bool globallyEnabled() {
    return globalEnabledFlag().load(std::memory_order_relaxed);
  }

                                         
  bool isEnabled() const {
    return !localDisabled_ && globallyEnabled();
  }

                                                                
  void restore() {
    localDisabled_ = false;
  }

                                                                                
              
  void disable() {
    localDisabled_ = true;
  }

                                                                                
  void markRoots(RootAcceptor &acceptor);

                                                                   
  inline void markExecuted(CodeBlock *codeBlock) {
    if (LLVM_LIKELY(!isEnabled())) {
      return;
    }
    markExecutedSlowPath(codeBlock);
  }

                                                              
  std::vector<CodeCoverageProfiler::FuncInfo> getExecutedFunctionsLocal();

 private:
  static std::unordered_set<CodeCoverageProfiler *> &allProfilers();
  static std::mutex &globalMutex();
  static std::atomic<bool> &globalEnabledFlag() {
    static std::atomic<bool> globalEnabledFlag;
    return globalEnabledFlag;
  }

  void markExecutedSlowPath(CodeBlock *codeBlock);

                                    
                                                                 
  std::vector<bool> &getModuleFuncMapRef(RuntimeModule *module);

  Runtime &runtime_;

                                                                        
                                                                           
                                
  std::mutex localMutex_;

                                                        
                                                             
                                                                   
                    
  llvh::DenseMap<RuntimeModule *, std::vector<bool>> executedFuncBitsArrayMap_;

                                                                              
                                                                                
                     
  llvh::DenseSet<Domain *> domains_;
                                                                           
                         
                                                                                
                     
  bool localDisabled_{false};
};

bool operator==(
    const CodeCoverageProfiler::FuncInfo &left,
    const CodeCoverageProfiler::FuncInfo &right);

}                
}                    

#endif                                    

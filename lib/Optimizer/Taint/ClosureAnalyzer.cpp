/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Optimizer/Taint/ClosureAnalyzer.h"
#include "hermes/IR/CFG.h"

namespace hermes {

//===----------------------------------------------------------------------===//
// Public API
//===----------------------------------------------------------------------===//

void ClosureAnalyzer::markVariableTainted(
    Variable *variable,
    ScopeCreationInst *scope) {
  VariableScopeKey key{variable, scope};
  taintedVariables_.insert(key);
}

bool ClosureAnalyzer::isVariableTainted(
    Variable *variable,
    ScopeCreationInst *scope) const {
  VariableScopeKey key{variable, scope};
  return taintedVariables_.find(key) != taintedVariables_.end();
}

void ClosureAnalyzer::recordTaintedStore(StoreFrameInst *store) {
  Variable *variable = store->getVariable();
  ScopeCreationInst *scope = store->getEnvironment();
  markVariableTainted(variable, scope);
}

std::unordered_set<LoadFrameInst *> ClosureAnalyzer::getTaintedLoads(
    Variable *variable,
    ScopeCreationInst *scope) const {
  VariableScopeKey key{variable, scope};
  auto it = variableLoads_.find(key);
  if (it != variableLoads_.end()) {
    return it->second;
  }
  return {};
}

void ClosureAnalyzer::clear() {
  taintedVariables_.clear();
  variableLoads_.clear();
  variableStores_.clear();
  closureEnvironments_.clear();
}

ClosureAnalyzer::Statistics ClosureAnalyzer::getStatistics() const {
  Statistics stats;
  stats.numTaintedVariables = taintedVariables_.size();
  stats.numTrackedScopes = closureEnvironments_.size();

  // Count total stores and loads
  stats.numStoreFrameInsts = 0;
  for (const auto &pair : variableStores_) {
    stats.numStoreFrameInsts += pair.second.size();
  }

  stats.numLoadFrameInsts = 0;
  for (const auto &pair : variableLoads_) {
    stats.numLoadFrameInsts += pair.second.size();
  }

  return stats;
}

//===----------------------------------------------------------------------===//
// Module and Function analysis
//===----------------------------------------------------------------------===//

void ClosureAnalyzer::analyzeModuleClosures(Module *module) {
  // Analyze all functions in the module
  for (auto &func : module->getFunctionList()) {
    analyzeFunctionClosures(&func);
  }
}

void ClosureAnalyzer::analyzeFunctionClosures(Function *func) {
  // Build mappings for this function
  buildVariableLoadMap(func);
  buildVariableStoreMap(func);

  // Process all CreateFunctionInst to track closures
  for (auto &basicBlock : func->getBasicBlockList()) {
    for (auto &inst : basicBlock) {
      if (auto *createFunc = llvh::dyn_cast<CreateFunctionInst>(&inst)) {
        processCreateFunction(createFunc);
      }
    }
  }
}

//===----------------------------------------------------------------------===//
// Helper methods
//===----------------------------------------------------------------------===//

void ClosureAnalyzer::buildVariableLoadMap(Function *func) {
  // Iterate through all instructions to find LoadFrameInsts
  for (auto &basicBlock : func->getBasicBlockList()) {
    for (auto &inst : basicBlock) {
      if (auto *loadFrame = llvh::dyn_cast<LoadFrameInst>(&inst)) {
        Variable *variable = loadFrame->getLoadVariable();
        ScopeCreationInst *scope = loadFrame->getEnvironment();
        VariableScopeKey key{variable, scope};

        // Add this load to the map
        variableLoads_[key].insert(loadFrame);
      }
    }
  }
}

void ClosureAnalyzer::buildVariableStoreMap(Function *func) {
  // Iterate through all instructions to find StoreFrameInsts
  for (auto &basicBlock : func->getBasicBlockList()) {
    for (auto &inst : basicBlock) {
      if (auto *storeFrame = llvh::dyn_cast<StoreFrameInst>(&inst)) {
        Variable *variable = storeFrame->getVariable();
        ScopeCreationInst *scope = storeFrame->getEnvironment();
        VariableScopeKey key{variable, scope};

        // Add this store to the map
        variableStores_[key].insert(storeFrame);
      }
    }
  }
}

void ClosureAnalyzer::processCreateFunction(CreateFunctionInst *createFunc) {
  // Get the environment captured by this closure
  Value *envValue = createFunc->getEnvironment();

  // The environment should be a ScopeCreationInst
  if (auto *scope = llvh::dyn_cast<ScopeCreationInst>(envValue)) {
    closureEnvironments_[createFunc] = scope;
  }
  // Note: In HBC (Hermes Bytecode Compiler) mode, the environment
  // might be other types like HBCSpillMov, but for now we only
  // handle ScopeCreationInst
}

} // namespace hermes

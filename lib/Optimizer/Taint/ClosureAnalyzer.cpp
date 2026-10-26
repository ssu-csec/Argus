/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Optimizer/Taint/ClosureAnalyzer.h"
#include "hermes/IR/CFG.h"

namespace hermes {

                                                                                
             
                                                                                

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

                                                                                
                               
                                                                                

void ClosureAnalyzer::analyzeModuleClosures(Module *module) {
                                        
  for (auto &func : module->getFunctionList()) {
    analyzeFunctionClosures(&func);
  }
}

void ClosureAnalyzer::analyzeFunctionClosures(Function *func) {
                                     
  buildVariableLoadMap(func);
  buildVariableStoreMap(func);

                                                     
  for (auto &basicBlock : func->getBasicBlockList()) {
    for (auto &inst : basicBlock) {
      if (auto *createFunc = llvh::dyn_cast<CreateFunctionInst>(&inst)) {
        processCreateFunction(createFunc);
      }
    }
  }
}

                                                                                
                 
                                                                                

void ClosureAnalyzer::buildVariableLoadMap(Function *func) {
                                                            
  for (auto &basicBlock : func->getBasicBlockList()) {
    for (auto &inst : basicBlock) {
      if (auto *loadFrame = llvh::dyn_cast<LoadFrameInst>(&inst)) {
        Variable *variable = loadFrame->getLoadVariable();
        ScopeCreationInst *scope = loadFrame->getEnvironment();
        VariableScopeKey key{variable, scope};

                                   
        variableLoads_[key].insert(loadFrame);
      }
    }
  }
}

void ClosureAnalyzer::buildVariableStoreMap(Function *func) {
                                                             
  for (auto &basicBlock : func->getBasicBlockList()) {
    for (auto &inst : basicBlock) {
      if (auto *storeFrame = llvh::dyn_cast<StoreFrameInst>(&inst)) {
        Variable *variable = storeFrame->getVariable();
        ScopeCreationInst *scope = storeFrame->getEnvironment();
        VariableScopeKey key{variable, scope};

                                    
        variableStores_[key].insert(storeFrame);
      }
    }
  }
}

void ClosureAnalyzer::processCreateFunction(CreateFunctionInst *createFunc) {
                                                 
  Value *envValue = createFunc->getEnvironment();

                                                  
  if (auto *scope = llvh::dyn_cast<ScopeCreationInst>(envValue)) {
    closureEnvironments_[createFunc] = scope;
  }
                                                                  
                                                               
                             
}

}                    

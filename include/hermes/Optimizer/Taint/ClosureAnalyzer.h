/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_OPTIMIZER_TAINT_CLOSUREANALYZER_H
#define HERMES_OPTIMIZER_TAINT_CLOSUREANALYZER_H

#include "hermes/IR/IR.h"
#include "hermes/IR/Instrs.h"

#include <unordered_map>
#include <unordered_set>

namespace hermes {

                       
class Variable;
class ScopeCreationInst;
class LoadFrameInst;
class StoreFrameInst;
class CreateFunctionInst;
class Function;

                                                                    
   
                                                                      
                                                                       
                                                                     
                                   
   
                 
                                                                
                                                              
                                                             
                                                             
                                                                        
   
                       
                 
                      
                                                             
                               
                                                              
        
     
       
   
                                                                      
                                                             
class ClosureAnalyzer {
 public:
  ClosureAnalyzer() = default;
  ~ClosureAnalyzer() = default;

                                                           
                                                         
     
                                                  
                                                                              
  void markVariableTainted(Variable *variable, ScopeCreationInst *scope);

                                                        
                                                       
     
                                                    
                                                                              
                                                           
  bool isVariableTainted(Variable *variable, ScopeCreationInst *scope) const;

                                                         
                                                                  
     
                                                              
  void recordTaintedStore(StoreFrameInst *store);

                                                       
                                                            
     
                                           
                                                                
                                                                        
  std::unordered_set<LoadFrameInst *> getTaintedLoads(
      Variable *variable,
      ScopeCreationInst *scope) const;

                                                               
                                                                  
     
                                         
  void analyzeFunctionClosures(Function *func);

                                      
                                                      
     
                                                       
  void analyzeModuleClosures(Module *module);

                                
  void clear();

                                           
  struct Statistics {
    size_t numTaintedVariables;
    size_t numTrackedScopes;
    size_t numStoreFrameInsts;
    size_t numLoadFrameInsts;
  };
  Statistics getStatistics() const;

 private:
                                                                 
  struct VariableScopeKey {
    Variable *variable;
    ScopeCreationInst *scope;

    bool operator==(const VariableScopeKey &other) const {
      return variable == other.variable && scope == other.scope;
    }
  };

                                        
  struct VariableScopeKeyHash {
    size_t operator()(const VariableScopeKey &key) const {
      return std::hash<void *>()(key.variable) ^
          (std::hash<void *>()(key.scope) << 1);
    }
  };

                                                                                
                   
                                                                                

                                                              
  void buildVariableLoadMap(Function *func);

                                                               
  void buildVariableStoreMap(Function *func);

                                                                 
  void processCreateFunction(CreateFunctionInst *createFunc);

                                                                                
                    
                                                                                

                                                     
  std::unordered_set<VariableScopeKey, VariableScopeKeyHash>
      taintedVariables_;

                                                                        
                                                                           
              
  std::unordered_map<
      VariableScopeKey,
      std::unordered_set<LoadFrameInst *>,
      VariableScopeKeyHash>
      variableLoads_;

                                                                        
                                                      
  std::unordered_map<
      VariableScopeKey,
      std::unordered_set<StoreFrameInst *>,
      VariableScopeKeyHash>
      variableStores_;

                                                                
                                  
  std::unordered_map<CreateFunctionInst *, ScopeCreationInst *>
      closureEnvironments_;
};

}                    

#endif                                            

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_OPTIMIZER_TAINT_DEFUSEANALYZER_H
#define HERMES_OPTIMIZER_TAINT_DEFUSEANALYZER_H

#include "hermes/IR/IR.h"
#include "hermes/IR/Instrs.h"

#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace hermes {

                       
class ClosureAnalyzer;
class Value;
class Instruction;
class MovInst;
class PhiInst;
class BinaryOperatorInst;
class CallInst;
class LoadPropertyInst;
class StorePropertyInst;
class LoadFrameInst;
class StoreFrameInst;
class ReturnInst;

                                                                   
                                                
   
                                                                         
                                                                                 
   
                 
                                                            
                                                                 
                                                                 
                                                                            
class DefUseAnalyzer {
 public:
                                                                    
  struct TaintPath {
    Instruction *source;                                                           
    std::vector<Instruction *> path;                                          
    Instruction *sink;                                                                 

    TaintPath(
        Instruction *src,
        std::vector<Instruction *> p,
        Instruction *snk = nullptr)
        : source(src), path(std::move(p)), sink(snk) {}
  };

                                                             
  struct FunctionCallMapping {
    CallInst *callSite;
    Function *targetFunction;
    std::vector<Value *> arguments;
  };

                                          
  struct TaintInfo {
    bool isTainted = false;
    std::vector<TaintPath> paths;                                       
  };

  DefUseAnalyzer() = default;
  ~DefUseAnalyzer() = default;

                                
                                                                     
     
                                                                                                 
                                                                         
                                                                                   
  void analyzeTaintFlow(
      const std::vector<Instruction *> &sources,
      const std::vector<Instruction *> &sinks,
      ClosureAnalyzer *closureAnalyzer = nullptr);

                                 
  bool isTainted(Value *v) const;

                                                
  const TaintInfo &getTaintInfo(Value *v) const;

                                       
  const std::vector<TaintPath> &getSinkReachingPaths() const {
    return sinkReachingPaths_;
  }

                                           
  void clear();

                                                              
  void setFunctionCalls(const std::vector<FunctionCallMapping> &calls) {
    functionCalls_ = calls;
  }

                              
  void setLogger(std::function<void(const std::string&)> logger) {
    logger_ = logger;
  }

                                                 
  void markTainted(
      Value *v,
      Instruction *source,
      const std::vector<Instruction *> &path);

 private:
  std::function<void(const std::string&)> logger_; 

                                                                                
                       
                                                                                

                                 
  void propagateTaint();
  
                                                                                  
                                                               
  void checkPropertyTaintConnections();
  
                                                                                  
                                                               
  void checkFrameTaintConnections();

                                                
  void addToWorklist(Value *v, const std::vector<Instruction *> &path);

                                                                                
                                         
                                                                                

                                                               
  void handleMovInst(MovInst *inst, const std::vector<Instruction *> &path);

                                                                                  
  void handlePhiInst(PhiInst *inst, const std::vector<Instruction *> &path);

                                                                                     
  void handleBinaryOp(
      BinaryOperatorInst *inst,
      const std::vector<Instruction *> &path);

                                                             
                                                             
                                                               
  void handleCallInst(CallInst *inst, const std::vector<Instruction *> &path);

                                                   
                                                           
  void handleLoadProperty(
      LoadPropertyInst *inst,
      const std::vector<Instruction *> &path);

                                                    
                                                         
  void handleStoreProperty(
      StorePropertyInst *inst,
      const std::vector<Instruction *> &path);

                                                         
                                                                
  void handleLoadFrame(
      LoadFrameInst *inst,
      const std::vector<Instruction *> &path);

                                                         
                                                                
  void handleStoreFrame(
      StoreFrameInst *inst,
      const std::vector<Instruction *> &path);

                                                      
  void handleReturn(ReturnInst *inst, const std::vector<Instruction *> &path);

                                          
  void handleUnaryOp(Instruction *inst, const std::vector<Instruction *> &path);

                                                                         
  void handleGenericInst(
      Instruction *inst,
      const std::vector<Instruction *> &path);

                                                                                
                    
                                                                                

                                                           
                                               
  bool shouldPropagateTo(Value *v) const;

                                       
  bool isSink(Instruction *inst) const;

                                         
  bool isSource(Instruction *inst) const;
  
                                       
  void markPropertyTainted(
      Value *object, 
      const std::string &propertyName,
      Instruction *source,
      const std::vector<Instruction *> &path);
  
  bool isPropertyTainted(Value *object, const std::string &propertyName) const;
  
  const TaintInfo &getPropertyTaintInfo(Value *object, const std::string &propertyName) const;

                                             
  void markFrameTainted(
      Value *environment,
      Variable *variable,
      Instruction *source,
      const std::vector<Instruction *> &path);
  
  bool isFrameTainted(Value *environment, Variable *variable) const;
  
  const TaintInfo &getFrameTaintInfo(Value *environment, Variable *variable) const;

                                                                                
                    
                                                                                

                                             
  std::unordered_map<Value *, TaintInfo> taintMap_;

                                                
  std::deque<std::pair<Value *, std::vector<Instruction *>>> worklist_;

                                                                     
  std::unordered_set<Value *> worklistSet_;

                                                
  std::vector<TaintPath> sinkReachingPaths_;

                                
  std::unordered_set<Instruction *> sources_;

                              
  std::unordered_set<Instruction *> sinks_;

                                                            
  ClosureAnalyzer *closureAnalyzer_ = nullptr;

                                                          
  std::vector<FunctionCallMapping> functionCalls_;
  
                                                                          
                                                                          
  std::unordered_map<std::string, TaintInfo> propertyTaintMap_;

                                                                                     
                                                                       
  std::unordered_map<std::string, TaintInfo> frameTaintMap_;

                                                       
  static const TaintInfo emptyTaintInfo_;
};

}                    

#endif                                           

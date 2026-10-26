/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_OPTIMIZER_TAINT_TAINTANALYSIS_H
#define HERMES_OPTIMIZER_TAINT_TAINTANALYSIS_H

#include <fstream>
#include <memory>
#include <string>
#include <vector>
#include <set>
#include <map>

#include "hermes/IR/IR.h"
#include "hermes/Optimizer/PassManager/Pass.h"
#include "hermes/Optimizer/Taint/CallGraphAnalyzer.h"
#include "hermes/Optimizer/Taint/ClosureAnalyzer.h"
#include "hermes/Optimizer/Taint/DefUseAnalyzer.h"
#include "hermes/Optimizer/Taint/SinkDefinitions.h"
#include "hermes/Optimizer/Taint/SourceDefinitions.h"
#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"

namespace hermes {

class TaintAnalysis : public ModulePass {
 private:
  DefUseAnalyzer defUseAnalyzer_;
  ClosureAnalyzer closureAnalyzer_;
  taint::SourceRegistry &sourceRegistry_;
  SinkRegistry &sinkRegistry_;

  std::ofstream reportFile_;
  std::string prefix_;                                                       

                                      
  std::set<Function *> eventDrivenFunctions_;
  enum FunctionContextBits : unsigned {
    NoKnownContext = 0,
    AutonomousContext = 1,
    EventDrivenContext = 2,
  };
  llvh::DenseMap<Function *, unsigned> functionContextBits_;
  llvh::DenseMap<Function *, std::set<std::string>> eventRootSources_;
  llvh::DenseMap<Function *, std::set<std::string>>
      autonomousResolutionSources_;
  llvh::DenseMap<Function *, std::set<std::string>>
      eventResolutionSources_;
  llvh::DenseMap<Function *, std::vector<std::string>>
      autonomousContextWitness_;
  llvh::DenseMap<Function *, std::vector<std::string>> eventContextWitness_;
  std::map<std::string, unsigned> functionContextDistribution_;
  void collectEventDrivenFunctions(Module *M);
  void markAsEventDriven(
      Value *V,
      int depth,
      const std::string &mechanism = "DOM_EVENT_REGISTRATION");
  void computeFunctionExecutionContexts(Module *M);

  std::string getTriggerContext(hermes::Instruction *sinkInst);
  std::string getTriggerContextReason(hermes::Instruction *sinkInst);
  std::set<std::string> getContextResolutionSources(
      hermes::Instruction *sinkInst);
  std::vector<std::string> getContextWitness(
      hermes::Instruction *sinkInst,
      unsigned contextBit);
  std::string getDestinationURL(hermes::Instruction *sinkInst);


  bool isTainted(Value *V); 

  bool isSourceInstruction(Instruction *I, std::string &sourceAPI);
  bool isSinkInstruction(Instruction *I, std::string &sinkAPI, SinkType &type);


  void log(const std::string &msg);

  struct Vulnerability {
    Instruction *source;
    Instruction *sink;
    std::string sourceAPI;
    std::string sinkAPI;
    SinkType sinkType;
    std::vector<Instruction *> path;

             
    Vulnerability() : source(nullptr), sink(nullptr), sinkType(SinkType::XSS) {}

              
    Vulnerability(
        Instruction *src,
        Instruction *snk,
        llvh::StringRef srcAPI,
        llvh::StringRef snkAPI,
        SinkType type,
        const std::vector<Instruction *> &p)
        : source(src),
          sink(snk),
          sourceAPI(srcAPI.str()),
          sinkAPI(snkAPI.str()),
          sinkType(type),
          path(p) {}
  };

                                                               
  std::vector<Vulnerability> vulnerabilities_;



              
  llvh::SmallVector<Instruction *, 32> identifySources(Module *M);
  llvh::SmallVector<Instruction *, 32> identifySinks(Module *M);

                                                                        
                                                                           
  std::string extractObjectName(Value *object);
  void analyzeTaintFlow(
      const llvh::SmallVectorImpl<Instruction *> &sources,
      const llvh::SmallVectorImpl<Instruction *> &sinks);

              
  void reportVulnerabilities();

  const char *getSinkTypeName(SinkType type);
  bool returnsTaintedValue(Function *F);

 public:
  explicit TaintAnalysis()
      : ModulePass("TaintAnalysis"),
        sourceRegistry_(taint::SourceRegistry::getInstance()),
        sinkRegistry_(SinkRegistry::getInstance()) {}

  ~TaintAnalysis() override = default;

  bool runOnModule(Module *M) override;

                      
  const std::vector<Vulnerability> &getReports() const {
    return vulnerabilities_;
  }
};

std::unique_ptr<Pass> createTaintAnalysis();

}

#endif

#ifndef HERMES_OPTIMIZER_TAINT_TAINTANALYSIS_H
#define HERMES_OPTIMIZER_TAINT_TAINTANALYSIS_H

#include "hermes/IR/IR.h"
#include "hermes/Optimizer/PassManager/Pass.h"
#include "hermes/Optimizer/Taint/DefUseAnalyzer.h"
#include "hermes/Optimizer/Taint/ClosureAnalyzer.h"
#include "hermes/Optimizer/Taint/SourceDefinitions.h"
#include "hermes/Optimizer/Taint/SinkDefinitions.h"
#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"
#include <vector>
#include <string>
#include <memory>  
#include <fstream>

namespace hermes {

class TaintAnalysis : public ModulePass {
private:
  DefUseAnalyzer defUseAnalyzer_;
  ClosureAnalyzer closureAnalyzer_;
  taint::SourceRegistry &sourceRegistry_;
  SinkRegistry &sinkRegistry_;

  std::ofstream reportFile_;
  
  void log(const std::string &msg);

  struct VulnerabilityReport {
    Instruction *source;
    Instruction *sink;
    std::string sourceAPI;
    std::string sinkAPI;
    SinkType sinkType;
    std::vector<Instruction *> path;

    VulnerabilityReport(
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

  std::vector<VulnerabilityReport> reports_;

  struct FunctionCallInfo {
    CallInst *callSite;
    Function *targetFunction;
    std::vector<Value *> arguments;
  };
  std::vector<FunctionCallInfo> functionCalls_;

  llvh::SmallVector<Instruction *, 32> identifySources(Module *M);
  llvh::SmallVector<Instruction *, 32> identifySinks(Module *M);
  void analyzeFunctionCalls(Module *M);
  bool shouldAnalyzeFunction(Function *F);
  bool isSourceInstruction(Instruction *I, std::string &sourceAPI);
  bool isSinkInstruction(Instruction *I, std::string &sinkAPI, SinkType &type);
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

  const std::vector<VulnerabilityReport> &getReports() const {
    return reports_;
  }
};

std::unique_ptr<Pass> createTaintAnalysis();

} // namespace hermes

#endif
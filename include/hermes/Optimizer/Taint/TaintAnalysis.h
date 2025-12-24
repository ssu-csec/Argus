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

namespace hermes {

/// Taint Analysis Pass for Hermes IR
///
/// This pass performs taint analysis on JavaScript code compiled to Hermes IR.
/// It identifies flows from sensitive sources (e.g., navigator.userAgent,
/// document.cookie) to dangerous sinks (e.g., eval, fetch, document.write).
///
/// Key Features:
/// - Def-Use Chain based taint propagation
/// - Closure-aware analysis
/// - Path recording (Source → Sink)
/// - Support for 100+ JavaScript source APIs
/// - Support for 20+ sink categories
///
/// The analysis is conservative: when uncertain, it assumes values are tainted
/// to minimize false negatives (missed vulnerabilities).
class TaintAnalysis : public ModulePass {
private:
  /// Def-Use analyzer for taint propagation
  DefUseAnalyzer defUseAnalyzer_;

  /// Closure analyzer for cross-function taint tracking
  ClosureAnalyzer closureAnalyzer_;

  /// Source/Sink registries (Singletons)
  taint::SourceRegistry &sourceRegistry_;
  SinkRegistry &sinkRegistry_;

  /// Vulnerability reports
  struct VulnerabilityReport {
    /// Source instruction
    Instruction *source;

    /// Sink instruction
    Instruction *sink;

    /// Source API name
    std::string sourceAPI;

    /// Sink API name
    std::string sinkAPI;

    /// Sink type
    SinkType sinkType;

    /// Full taint propagation path
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

  /// Function call tracking for inter-procedural analysis
  struct FunctionCallInfo {
    CallInst *callSite;
    Function *targetFunction;
    std::vector<Value *> arguments;
  };
  std::vector<FunctionCallInfo> functionCalls_;

  /// Identify all source instructions in the module
  llvh::SmallVector<Instruction *, 32> identifySources(Module *M);

  /// Identify all sink instructions in the module
  llvh::SmallVector<Instruction *, 32> identifySinks(Module *M);

  /// Analyze function calls for inter-procedural taint flow
  void analyzeFunctionCalls(Module *M);

  /// Check if a function call should be analyzed inter-procedurally
  bool shouldAnalyzeFunction(Function *F);

  /// Check if an instruction is a source
  bool isSourceInstruction(Instruction *I, std::string &sourceAPI);

  /// Check if an instruction is a sink
  bool isSinkInstruction(Instruction *I, std::string &sinkAPI, SinkType &type);

  /// Extract object name from a Value (e.g., "document" from document.write)
  std::string extractObjectName(Value *object);

  /// Analyze taint flow from sources to sinks
  void analyzeTaintFlow(
      const llvh::SmallVectorImpl<Instruction *> &sources,
      const llvh::SmallVectorImpl<Instruction *> &sinks);

  /// Report all found vulnerabilities
  void reportVulnerabilities(llvh::StringRef targetFilename);

  /// Get human-readable sink type name
  const char *getSinkTypeName(SinkType type);

  bool returnsTaintedValue(Function *F);

public:
  explicit TaintAnalysis()
      : ModulePass("TaintAnalysis"),
        sourceRegistry_(taint::SourceRegistry::getInstance()),
        sinkRegistry_(SinkRegistry::getInstance()) {}

  ~TaintAnalysis() override = default;

  /// Run taint analysis on the module
  bool runOnModule(Module *M) override;

  /// Get analysis results (for testing/debugging)
  const std::vector<VulnerabilityReport> &getReports() const {
    return reports_;
  }
};

std::unique_ptr<Pass> createTaintAnalysis();

} // namespace hermes

#endif
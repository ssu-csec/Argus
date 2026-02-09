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

    // 기본 생성자
    Vulnerability() : source(nullptr), sink(nullptr), sinkType(SinkType::XSS) {}

    // 편의용 생성자
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

  // ★ [핵심] .cpp 파일이 찾던 그 변수명 (reports_ 대신 vulnerabilities_ 사용)
  std::vector<Vulnerability> vulnerabilities_;



  // 내부 분석 함수들
  llvh::SmallVector<Instruction *, 32> identifySources(Module *M);
  llvh::SmallVector<Instruction *, 32> identifySinks(Module *M);

  // void analyzeFunctionCalls(Module *M); // Moved to CallGraphAnalyzer
  // bool shouldAnalyzeFunction(Function *F); // Moved to CallGraphAnalyzer
  std::string extractObjectName(Value *object);
  void analyzeTaintFlow(
      const llvh::SmallVectorImpl<Instruction *> &sources,
      const llvh::SmallVectorImpl<Instruction *> &sinks);

  // 보고서 출력 함수
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

  // 외부에서 결과를 가져갈 때 사용
  const std::vector<Vulnerability> &getReports() const {
    return vulnerabilities_;
  }
};

std::unique_ptr<Pass> createTaintAnalysis();

}

#endif
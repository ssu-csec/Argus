/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "taintanalysis"
#include "hermes/Optimizer/Taint/TaintAnalysis.h"
#include <fstream>
#include "hermes/IR/Analysis.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Optimizer/Taint/CallGraphAnalyzer.h"
#include "llvh/Support/Debug.h"
#include "llvh/Support/Path.h"
#include "llvh/Support/raw_ostream.h"

using namespace hermes;
using llvh::dbgs;
using llvh::outs;

//===----------------------------------------------------------------------===//
// TaintAnalysis Implementation
//===----------------------------------------------------------------------===//

// ★ [헬퍼 함수] 화면(outs)과 파일(reportFile_)에 동시에 로그를 남기는 함수
void TaintAnalysis::log(const std::string &msg) {
  outs() << msg; // 터미널 출력
  if (reportFile_.is_open()) {
    reportFile_ << msg; // 파일 출력
    reportFile_.flush(); // 즉시 저장
  }
}

bool TaintAnalysis::runOnModule(Module *M) {
  // 1. [파일 이름 추출]
  std::string sourceFileName = "unknown_script.js";
  for (auto &F : *M) {
    if (!F.empty() && !F.front().empty()) {
      auto &I = F.front().front();
      if (I.getLocation().isValid()) {
        auto *buf = M->getContext().getSourceErrorManager().findBufferForLoc(
            I.getLocation());
        if (buf) {
          sourceFileName = buf->getBufferIdentifier();
          break;
        }
      }
    }
  }

  // 2. [파일 열기] 멤버 변수 reportFile_을 여기서 엽니다.
  llvh::StringRef stem = llvh::sys::path::stem(sourceFileName);
  if (stem.empty())
    stem = "taint";
  std::string outFileName = (stem + "_report.txt").str();

  reportFile_.open(outFileName); // 파일 오픈

  // 3. [로그 기록] log() 함수 사용
  log("\n");
  log("========================================\n");
  log("=== Taint Analysis for Hermes IR\n");
  log("    Target: " + sourceFileName + "\n");
  log("    Output: " + outFileName + "\n");
  log("========================================\n\n");

  // Step 1
  log("[Phase 1] Analyzing closures...\n");
  closureAnalyzer_.analyzeModuleClosures(M);
  log("  Closure analysis complete.\n\n");

  // Step 2 (필터링 적용됨)
  log("[Phase 2] Identifying taint sources...\n");
  auto sources = identifySources(M);
  log("  Found " + std::to_string(sources.size()) + " source(s).\n\n");

  // Step 3
  log("[Phase 3] Identifying taint sinks...\n");
  auto sinks = identifySinks(M);
  log("  Found " + std::to_string(sinks.size()) + " sink(s).\n\n");

  // Step 4
  log("[Phase 4] Analyzing function calls...\n");
  CallGraphAnalyzer CGAnalyzer(M);
  CGAnalyzer.analyze();

  // Call Graph 덤프 캡처
  std::string graphDump;
  llvh::raw_string_ostream os(graphDump);
  CGAnalyzer.dump(os);
  log(os.str());

  analyzeFunctionCalls(M);
  log("  Call Graph extraction complete.\n\n");

  // Step 5
  log("[Phase 5] Creating inter-procedural taint links...\n");
  if (functionCalls_.empty()) {
    log("  (No inter-procedural calls found to link)\n");
  } else {
    std::vector<DefUseAnalyzer::FunctionCallMapping> mappings;
    for (auto &info : functionCalls_) {
      DefUseAnalyzer::FunctionCallMapping m;
      m.callSite = info.callSite;
      m.targetFunction = info.targetFunction;
      m.arguments = info.arguments;
      mappings.push_back(m);
    }
    defUseAnalyzer_.setFunctionCalls(mappings);
    log("  Inter-procedural links created (" + std::to_string(mappings.size()) +
        " links).\n");
  }
  log("\n");

  // Step 6
  log("[Phase 6] Analyzing taint propagation...\n");
  analyzeTaintFlow(sources, sinks);
  log("  Taint flow analysis complete.\n\n");

  // Step 7: 결과 리포트
  log("[Phase 7] Generating vulnerability report...\n");

  // ★ [수정됨] 인자 없이 호출 (멤버 변수 reportFile_ 사용)
  reportVulnerabilities();

  log("\n========================================\n");
  log("=== Taint Analysis Complete\n");
  log("========================================\n\n");

  // 4. [파일 닫기]
  if (reportFile_.is_open()) {
    outs() << "  [System] Report saved to '" << outFileName << "'\n";
    reportFile_.close();
  }

  return false;
}

llvh::SmallVector<Instruction *, 32> TaintAnalysis::identifySources(Module *M) {
  llvh::SmallVector<Instruction *, 32> sources;
  std::vector<std::string> taintedGlobals;

  // [Step 0] 전역 변수 오염 여부 미리 스캔
  for (auto &F : *M) {
    for (auto &BB : F) {
      for (auto &I : BB) {
        if (auto *SPI = llvh::dyn_cast<StorePropertyInst>(&I)) {
          Value *storedVal = SPI->getStoredValue();
          bool isTainted = false;
          if (auto *Instr = llvh::dyn_cast<Instruction>(storedVal)) {
            std::string dummy;
            if (isSourceInstruction(Instr, dummy)) {
              isTainted = true;
            } else if (auto *CI = llvh::dyn_cast<CallInst>(Instr)) {
              Value *callee = CI->getCallee();
              if (auto *func = llvh::dyn_cast<Function>(callee)) {
                if (returnsTaintedValue(func))
                  isTainted = true;
              }
            }
          }
          if (isTainted) {
            if (auto *Lit = llvh::dyn_cast<LiteralString>(SPI->getProperty())) {
              std::string varName = Lit->getValue().str().str();

              // =========================================================
              // ★ [수정됨] 강력한 노이즈 필터링 적용
              // 분석에 방해되는 흔한 단어들을 무시 목록(Blacklist)에
              // 등록합니다. static const를 사용하여 매번 생성하지 않도록
              // 최적화했습니다.
              // =========================================================
              static const std::set<std::string> ignoreList = {
                  // 1. 시스템 객체
                  "exports",
                  "module",
                  "window",
                  "self",
                  "global",
                  "document",
                  "console",
                  "process",

                  // 2. 시간/쿠키 관련 일반 명사 (오탐지 주범)
                  "now",
                  "date",
                  "time",
                  "expires",
                  "path",
                  "domain",
                  "secure",

                  // 3. Minified(압축된) 변수명 (한 글자 변수는 전역 추적에서
                  // 제외)
                  "a",
                  "b",
                  "c",
                  "d",
                  "e",
                  "f",
                  "g",
                  "h",
                  "i",
                  "j",
                  "k",
                  "l",
                  "m",
                  "n",
                  "o",
                  "p",
                  "q",
                  "r",
                  "s",
                  "t",
                  "u",
                  "v",
                  "w",
                  "x",
                  "y",
                  "z",
                  "_",
                  "$",

                  // 4. 기타 흔한 값 및 속성
                  "undefined",
                  "null",
                  "true",
                  "false",
                  "prototype",
                  "length",
                  "width",
                  "height"};

              if (ignoreList.count(varName)) {
                continue;
              }
              // =========================================================

              // (수정) 이미 출력한 변수면 로그는 생략 (분석은 계속 진행)
              taintedGlobals.push_back(varName);

              // 중복 로그 방지용 static set (함수 내부에 선언)
              static std::set<std::string> loggedVars;

              if (loggedVars.find(varName) == loggedVars.end()) {
                log("  [Global Taint] Found tainted global variable: " +
                    varName + "\n");
                loggedVars.insert(varName);
              }
            }
          }
        }
      }
    }
  }

  // [Step 1 & 2] 실제 오염원 등록
  for (auto &F : *M) {
    for (auto &BB : F) {
      for (auto &I : BB) {
        std::string sourceAPI;
        if (isSourceInstruction(&I, sourceAPI)) {
          sources.push_back(&I);
        }
        if (auto *CI = llvh::dyn_cast<CallInst>(&I)) {
          Value *callee = CI->getCallee();
          Function *targetFunc = nullptr;
          if (auto *func = llvh::dyn_cast<Function>(callee)) {
            targetFunc = func;
          } else if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(callee)) {
            if (auto *Lit = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
              std::string funcName = Lit->getValue().str().str();
              for (auto &candidateF : *M) {
                if (candidateF.getInternalNameStr() == funcName) {
                  targetFunc = &candidateF;
                  break;
                }
              }
            }
          }
          if (targetFunc && returnsTaintedValue(targetFunc)) {
            sources.push_back(&I);
          }
        }
        if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(&I)) {
          if (auto *Lit = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
            std::string varName = Lit->getValue().str().str();
            for (const auto &taintedName : taintedGlobals) {
              if (taintedName == varName) {
                sources.push_back(&I);

                // =================================================
                // ★ [수정] 중복 로그 방지 (한 번만 신고하기)
                // 분석은 계속 하되, 터미널 도배만 막습니다.
                // =================================================
                static std::set<std::string> loggedLoads;
                if (loggedLoads.find(varName) == loggedLoads.end()) {
                  log("  [Global Taint] Marking load of '" + varName +
                      "' as Source.\n");
                  loggedLoads.insert(varName);
                }
                // =================================================

                break;
              }
            }
          }
        }
      }
    }
  }
  return sources;
}
llvh::SmallVector<Instruction *, 32> TaintAnalysis::identifySinks(Module *M) {
  llvh::SmallVector<Instruction *, 32> sinks;
  for (auto &F : *M) {
    for (auto &BB : F) {
      for (auto &I : BB) {
        std::string sinkName;
        SinkType type;
        if (isSinkInstruction(&I, sinkName, type)) {
          sinks.push_back(&I);
        }
      }
    }
  }
  return sinks;
}

bool TaintAnalysis::isSourceInstruction(
    Instruction *I,
    std::string &sourceAPI) {
  if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(I)) {
    if (auto *litProp = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
      std::string propName = litProp->getValue().str().str();
      std::string objName = extractObjectName(LPI->getObject());
      std::string fullName = objName + "." + propName;
      const auto *sourceDef = sourceRegistry_.getSourceByFullName(fullName);
      if (sourceDef) {
        sourceAPI = fullName;
        return true;
      }
    }
  }
  if (auto *CI = llvh::dyn_cast<CallInst>(I)) {
    std::string funcName = extractObjectName(CI->getCallee());
    const auto *sourceDef = sourceRegistry_.getSourceByFullName(funcName);
    if (sourceDef) {
      sourceAPI = funcName;
      return true;
    }
  }
  if (auto *CNI = llvh::dyn_cast<ConstructInst>(I)) {
    std::string ctorName = extractObjectName(CNI->getCallee());
    const auto *sourceDef = sourceRegistry_.getSourceByFullName(ctorName);
    if (sourceDef) {
      sourceAPI = ctorName;
      return true;
    }
  }
  return false;
}

std::string TaintAnalysis::extractObjectName(Value *object) {
  if (!object)
    return "Unknown";
  if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(object)) {
    if (auto *Lit = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
      return Lit->getValue().str().str();
    }
  }
  if (auto *CI = llvh::dyn_cast<CallInst>(object)) {
    Value *callee = CI->getCallee();
    if (auto *func = llvh::dyn_cast<Function>(callee)) {
      return func->getInternalNameStr().str() + "()";
    }
    if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(callee)) {
      if (auto *Lit = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
        return Lit->getValue().str().str() + "()";
      }
    }
    return "AnonymousFunction()";
  }
  if (auto *I = llvh::dyn_cast<Instruction>(object)) {
    return std::string(I->getKindStr());
  }
  return "UnknownSource";
}

bool TaintAnalysis::isSinkInstruction(
    Instruction *I,
    std::string &sinkAPI,
    SinkType &type) {
  if (auto *SPI = llvh::dyn_cast<StorePropertyInst>(I)) {
    if (auto *litProp = llvh::dyn_cast<LiteralString>(SPI->getProperty())) {
      std::string propName = litProp->getValue().str().str();
      std::string objectName = extractObjectName(SPI->getObject());

      if (auto *sinkDef = sinkRegistry_.isPropertySink(objectName, propName)) {
        sinkAPI = sinkDef->name;
        type = sinkDef->type;
        return true;
      }
      if (auto *sinkDef = sinkRegistry_.isPropertySink("", propName)) {
        if (objectName != "Unknown" && objectName != "UnknownSource") {
          sinkAPI = objectName + "." + sinkDef->name;
        } else {
          sinkAPI = sinkDef->name;
        }
        type = sinkDef->type;
        return true;
      }
    }
  }

  if (auto *CI = llvh::dyn_cast<CallInst>(I)) {
    Value *callee = CI->getCallee();
    if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(callee)) {
      if (auto *litProp = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
        std::string methodName = litProp->getValue().str().str();
        std::string objectName = extractObjectName(LPI->getObject());

        if (auto *sinkDef =
                sinkRegistry_.isMethodSink(objectName, methodName)) {
          sinkAPI = sinkDef->name;
          type = sinkDef->type;
          return true;
        }
        if (auto *sinkDef = sinkRegistry_.isMethodSink("", methodName)) {
          if (objectName != "Unknown" && objectName != "UnknownSource") {
            sinkAPI = objectName + "." + sinkDef->name;
          } else {
            sinkAPI = sinkDef->name;
          }
          type = sinkDef->type;
          return true;
        }
      }
    }
    if (auto *GPI = llvh::dyn_cast<TryLoadGlobalPropertyInst>(callee)) {
      if (auto *litProp = llvh::dyn_cast<LiteralString>(GPI->getProperty())) {
        std::string functionName = litProp->getValue().str().str();
        if (auto *sinkDef = sinkRegistry_.isFunctionSink(functionName)) {
          sinkAPI = sinkDef->name;
          type = sinkDef->type;
          return true;
        }
      }
    }
  }

  if (llvh::isa<DirectEvalInst>(I)) {
    if (auto *sinkDef = sinkRegistry_.isFunctionSink("eval")) {
      sinkAPI = sinkDef->name;
      type = sinkDef->type;
      return true;
    }
  }

  return false;
}

void TaintAnalysis::analyzeTaintFlow(
    const llvh::SmallVectorImpl<Instruction *> &sources,
    const llvh::SmallVectorImpl<Instruction *> &sinks) {
  
  // 1. Source/Sink 벡터 변환
  std::vector<Instruction *> sourceVec(sources.begin(), sources.end());
  std::vector<Instruction *> sinkVec(sinks.begin(), sinks.end());

  // 2. 함수 호출 매핑 정보 설정
  std::vector<DefUseAnalyzer::FunctionCallMapping> callMappings;
  for (const auto &callInfo : functionCalls_) {
    DefUseAnalyzer::FunctionCallMapping mapping;
    mapping.callSite = callInfo.callSite;
    mapping.targetFunction = callInfo.targetFunction;
    mapping.arguments = callInfo.arguments;
    callMappings.push_back(mapping);
  }

  defUseAnalyzer_.setFunctionCalls(callMappings);

  // 3. 오염 흐름 분석 실행
  defUseAnalyzer_.analyzeTaintFlow(sourceVec, sinkVec, &closureAnalyzer_);
  
  // 4. 결과 경로 가져오기
  const auto &sinkPaths = defUseAnalyzer_.getSinkReachingPaths();

  // 5. 결과 처리 loop
  for (const auto &pathStruct : sinkPaths) { // 이름을 pathStruct로 명확하게 변경
    std::string sourceAPI;
    std::string sinkAPI;
    SinkType sinkType = SinkType::Network; // 기본값

    // 구조체 멤버인 source, sink에 접근
    isSourceInstruction(pathStruct.source, sourceAPI);
    isSinkInstruction(pathStruct.sink, sinkAPI, sinkType);

    // ★ [핵심 수정] 구조체(pathStruct) 안의 벡터(.path)를 꺼내서 반복
    std::vector<Instruction *> pathVec;
    for (auto *I : pathStruct.path) { 
      pathVec.push_back(I);
    }

    // pathVec이 비어있지 않으면 취약점으로 등록
    if (!pathVec.empty()) {
      Instruction *source = pathVec.front();
      Instruction *sink = pathVec.back();

      vulnerabilities_.emplace_back(
          source, sink, sourceAPI, sinkAPI, sinkType, pathVec);
    }
  }
}

void TaintAnalysis::reportVulnerabilities() {
  log("\n========================================\n");
  log("=== Vulnerability Report (Categorized)\n");
  log("========================================\n");

  if (vulnerabilities_.empty()) {
    log("  No vulnerabilities found.\n");
    return;
  }

  int index = 1;
  for (const auto &vuln : vulnerabilities_) {
    Instruction *sourceInst = vuln.path.front();
    Instruction *sinkInst = vuln.path.back();

    // 1. Sink 정보 가져오기
    std::string sinkName = "Unknown";
    SinkType sinkType = SinkType::XSS; // 기본값

    if (auto *Call = llvh::dyn_cast<CallInst>(sinkInst)) {
      if (auto *Func = llvh::dyn_cast<Function>(Call->getCallee())) {
        sinkName = Func->getInternalNameStr().str();
        auto *def = SinkRegistry::getInstance().isFunctionSink(sinkName);
        if (def)
          sinkType = def->type;
      }
      // (LoadPropertyInst 등으로 호출된 메서드 처리 로직은 생략되었으나 기존
      // 로직 활용 가능)
    } else if (auto *SPI = llvh::dyn_cast<StorePropertyInst>(sinkInst)) {
      if (auto *Lit = llvh::dyn_cast<LiteralString>(SPI->getProperty())) {
        sinkName = Lit->getValue().str().str();
        // 속성 Sink (예: innerHTML, src 등) 확인
        // 여기서는 간단히 이름으로 매칭하거나 레지스트리 조회
        if (sinkName == "src")
          sinkType = SinkType::Network;
        else if (sinkName == "innerHTML")
          sinkType = SinkType::XSS;
        else if (sinkName == "location.href")
          sinkType = SinkType::Navigation;
        // ... (SinkRegistry를 통해 정확히 가져오는 것이 베스트입니다)
        auto *def = SinkRegistry::getInstance().isPropertySink("", sinkName);
        if (def)
          sinkType = def->type;
      }
    }

    // 2. 위험도 및 태그 결정 (여기가 핵심!)
    std::string severityTag = "[INFO]";
    std::string category = "General Flow";

    switch (sinkType) {
      case SinkType::Network:
        severityTag = "[CRITICAL]"; // ★ 정보 유출 (가장 중요)
        category = "Data Exfiltration (Tracking)";
        break;
      case SinkType::Storage:
        severityTag = "[WARNING]"; // 식별자 저장
        category = "Fingerprinting / Storage";
        break;
      case SinkType::CodeInjection:
        severityTag = "[HIGH]"; // 코드 실행
        category = "Code Injection";
        break;
      case SinkType::XSS:
        severityTag = "[MEDIUM]";
        category = "DOM Manipulation (XSS)";
        break;
      case SinkType::Navigation:
        severityTag = "[LOW]"; // 단순 이동
        category = "Page Navigation";
        break;
    }

    // 3. 보고서 출력
    log("\n  " + severityTag + " [" + std::to_string(index++) + "] " +
        category + "\n");

    // Source 이름 가져오기
    std::string sourceName = "Unknown";
    std::string sourceAPI;
    if (isSourceInstruction(sourceInst, sourceAPI)) {
      sourceName = sourceAPI;
    } else if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(sourceInst)) {
      if (auto *Lit = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
        sourceName = Lit->getValue().str().str();
      }
    }

    log("      Source: " + sourceName + "\n");
    log("      Sink:   " + sinkName + "\n");
    log("      Path length: " + std::to_string(vuln.path.size()) +
        " instruction(s)\n");

    // Path 상세 출력 (옵션: CRITICAL인 경우만 출력해서 보고서를 줄일 수도 있음)
    /*
    log("      Path: ");
    for (auto *I : vuln.path) {
       log(I->getKindStr().str() + " -> ");
    }
    log("Sink\n");
    */
  }
}

const char *TaintAnalysis::getSinkTypeName(SinkType type) {
  switch (type) {
    case SinkType::Network:
      return "Network";
    case SinkType::Storage:
      return "Storage";
    case SinkType::XSS:
      return "XSS";
    case SinkType::CodeInjection:
      return "Code Injection";
    case SinkType::Navigation:
      return "Navigation";
    default:
      return "Unknown";
  }
}

void TaintAnalysis::analyzeFunctionCalls(Module *M) {
  functionCalls_.clear();
  for (auto &F : *M) {
    for (auto &BB : F) {
      for (auto &I : BB) {
        if (auto *CI = llvh::dyn_cast<CallInst>(&I)) {
          Value *callee = CI->getCallee();
          Function *targetFunc = nullptr;
          if (auto *func = llvh::dyn_cast<Function>(callee)) {
            targetFunc = func;
          } else if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(callee)) {
            if (auto *Lit = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
              std::string funcName = Lit->getValue().str().str();
              for (auto &candidateF : *M) {
                if (candidateF.getInternalNameStr() == funcName) {
                  targetFunc = &candidateF;
                  break;
                }
              }
            }
          }
          if (targetFunc && shouldAnalyzeFunction(targetFunc)) {
            // =======================================================
            // ★ [추가] Call Graph 노이즈 필터링
            // add, get, set 같은 너무 흔한 함수 이름은 연결하지 않음
            // =======================================================
            std::string funcName = targetFunc->getInternalNameStr();
            static const std::set<std::string> commonMethods = {
                "add",      "get",
                "set",      "push",
                "pop",      "call",
                "apply",    "bind",
                "toString", "hasOwnProperty",
                "slice",    "splice",
                "map",      "filter",
                "forEach",  "length",
                "qb",       "sb",
                "Fh",       "Wd" // 로그에 많이 뜨는 난독화 이름도 추가
            };

            // 흔한 함수거나, 이름이 너무 짧은(2글자 이하) 경우 무시
            if (commonMethods.count(funcName) || funcName.length() <= 2) {
              continue;
            }
            // =======================================================

            FunctionCallInfo callInfo;
            callInfo.callSite = CI;
            callInfo.targetFunction = targetFunc;
            for (unsigned i = 0; i < CI->getNumArguments(); ++i) {
              callInfo.arguments.push_back(CI->getArgument(i));
            }
            functionCalls_.push_back(callInfo);

            // 로그도 이제 중요한 것만 찍힙니다.
            log("  [Inter-procedural] Link created: " +
                F.getInternalNameStr().str() + " -> " + funcName + "\n");
          }
        }
      }
    }
  }
}

bool TaintAnalysis::shouldAnalyzeFunction(Function *F) {
  if (!F || F->empty())
    return false;
  std::string name = F->getInternalNameStr();
  if (name.empty() || name == "global" ||
      name.find("HermesInternal") != std::string::npos) {
    return false;
  }
  return true;
}

bool TaintAnalysis::returnsTaintedValue(Function *F) {
  for (auto &BB : *F) {
    for (auto &I : BB) {
      std::string sourceAPI;
      if (isSourceInstruction(&I, sourceAPI)) {
        for (auto *User : I.getUsers()) {
          if (llvh::isa<ReturnInst>(User))
            return true;
          if (llvh::isa<StoreFrameInst>(User)) {
            // Additional tracking logic could go here
          }
        }
      }
    }
  }
  return false;
}

std::unique_ptr<Pass> hermes::createTaintAnalysis() {
  return std::make_unique<TaintAnalysis>();
}

#undef DEBUG_TYPE
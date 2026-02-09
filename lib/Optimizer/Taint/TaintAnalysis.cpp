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
#include "llvh/Support/FileSystem.h"
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
  llvh::StringRef fullPath = sourceFileName;
  llvh::StringRef fileName =
      llvh::sys::path::filename(fullPath); // 전체 경로에서 파일명만 추출

  // 만약 분석 대상이 'wholepage.js'라면, 상위 디렉토리 이름(보통 도메인명으로
  // 설정됨)을 가져옵니다.
  std::string prefix = "";
  if (fileName.equals("wholepage.js")) {
    // 경로의 부모 디렉토리 이름을 도메인으로 간주 (예:
    // /crawler/output/naver.com/wholepage.js)
    llvh::StringRef parentDir = llvh::sys::path::parent_path(fullPath);
    prefix = llvh::sys::path::filename(parentDir).str();
    if (!prefix.empty())
      prefix += "_";
  }

  llvh::StringRef stem = llvh::sys::path::stem(fileName);
  if (stem.empty())
    stem = "taint";

  std::string fileNameStr = (prefix + stem + "_report.txt").str();

  llvh::SmallString<128> reportDir("report");
  llvh::sys::fs::create_directory(reportDir);
  
  llvh::sys::path::append(reportDir, fileNameStr);
  
  std::string outFileName = reportDir.str().str();

  reportFile_.open(outFileName);

  // 3. [로그 기록] log() 함수 사용
  log("\n");
  log("========================================\n");
  log("=== Taint Analysis for Hermes IR\n");
  log("    Target: " + sourceFileName + "\n");
  log("    Output: " + outFileName + "\n");
  log("========================================\n\n");

  // phase 1
  log("[Phase 1] Analyzing closures...\n");
  closureAnalyzer_.analyzeModuleClosures(M);
  log("  Closure analysis complete.\n\n");

  // phase 2 (필터링 적용됨)
  log("[Phase 2] Identifying taint sources...\n");
  auto sources = identifySources(M);
  log("  Found " + std::to_string(sources.size()) + " source(s).\n\n");

  // phase 3
  log("[Phase 3] Identifying taint sinks...\n");
  auto sinks = identifySinks(M);
  log("  Found " + std::to_string(sinks.size()) + " sink(s).\n\n");

  // Step 4
  log("[Phase 4] Analyzing function calls...\n");
  CallGraphAnalyzer CGAnalyzer(M);
  CGAnalyzer.analyze(&defUseAnalyzer_, [this](const std::string &msg) {
      log(msg);
  }); // Pass DefUseAnalyzer and logger

  // // Call Graph 덤프 캡처
  // std::string graphDump;
  // llvh::raw_string_ostream os(graphDump);
  // CGAnalyzer.dump(os);
  // log(os.str());

  // analyzeFunctionCalls(M); // Removed
  log("  Call Graph extraction complete.\n\n");

  // Step 5
  log("[Phase 5] Creating inter-procedural taint links...\n");
  const auto &functionCalls = CGAnalyzer.getFunctionCalls(); // Get results from CGAnalyzer
  if (functionCalls.empty()) {
    log("  (No inter-procedural calls found to link)\n");
  } else {
    std::vector<DefUseAnalyzer::FunctionCallMapping> mappings;
    for (auto &info : functionCalls) {
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

  // phase 6
  log("[Phase 6] Analyzing taint propagation...\n");
  analyzeTaintFlow(sources, sinks);
  log("  Taint flow analysis complete.\n\n");

  // phase 7: 결과 리포트
  log("[Phase 7] Generating vulnerability report...\n");

  reportVulnerabilities();

  log("\n========================================\n");
  log("=== Taint Analysis Complete\n");
  log("========================================\n\n");

  if (reportFile_.is_open()) {
    outs() << "  [System] Report saved to '" << outFileName << "'\n";
    reportFile_.close();
  }

  return false;
}

llvh::SmallVector<Instruction *, 32> TaintAnalysis::identifySources(Module *M) {
  llvh::SmallVector<Instruction *, 32> sources;
  std::vector<std::string> taintedGlobals;

  // [Step 0] 전역 변수 오염 여부 미리 스캔 (데이터 세탁 함수 포함)
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
                // 기존 규칙 + 데이터 세탁(Encoding/Decoding) 함수 감시 추가
                if (returnsTaintedValue(func))
                  isTainted = true;
              }
            }
          }

          if (isTainted) {
            if (auto *Lit = llvh::dyn_cast<LiteralString>(SPI->getProperty())) {
              std::string varName = Lit->getValue().str().str();

              // 기존 ignoreList 유지 (시스템 노이즈 제거)
              static const std::set<std::string> ignoreList = {
                  "exports",   "module",  "window",  "self",   "global",
                  "document",  "console", "process", "now",    "date",
                  "time",      "expires", "path",    "domain", "secure",
                  "undefined", "null",    "true",    "false",  "prototype",
                  "length",    "width",   "height"};

              // 한 글자 변수 필터링 유지
              if (varName.length() <= 1 || ignoreList.count(varName)) {
                continue;
              }

              taintedGlobals.push_back(varName);

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

  // [Step 1, 2, 3] 실제 오염원 및 핑거프린팅 요소 등록
  for (auto &F : *M) {
    for (auto &BB : F) {
      for (auto &I : BB) {
        // 1. 기존 명시적 Source API 탐지 (document.URL 등)
        std::string sourceAPI;
        if (isSourceInstruction(&I, sourceAPI)) {
          sources.push_back(&I);
        }

        // 2. 콜백 및 동적 함수 호출 분석 보강
        if (auto *CI = llvh::dyn_cast<CallInst>(&I)) {
          Value *callee = CI->getCallee();
          Function *targetFunc = nullptr;
          if (auto *func = llvh::dyn_cast<Function>(callee)) {
            targetFunc = func;
          } else if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(callee)) {
            if (auto *Lit = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
              std::string funcName = Lit->getValue().str().str();

              // ★ [추가] 데이터 세탁 함수 직접 감시 (atob, decodeURIComponent
              // 등)
              static const std::set<std::string> encodingAPIs = {
                  "atob",
                  "btoa",
                  "decodeURIComponent",
                  "unescape",
                  "decodeURI"};
              if (encodingAPIs.count(funcName)) {
                sources.push_back(&I); // 인코딩된 데이터 흐름 추적 시작
              }

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

        // 3. 속성 접근을 통한 핑거프린팅 요소 탐지 (navigator.*, screen.* 등)
        if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(&I)) {
          if (auto *Lit = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
            std::string varName = Lit->getValue().str().str();

            // ★ [추가] 고도화된 핑거프린팅 소스 목록
            static const std::set<std::string> fingerprintSources = {
                "userAgent",
                "platform",
                "deviceMemory",
                "hardwareConcurrency",
                "language",
                "languages",
                "connection",
                "plugins",
                "doNotTrack",
                "toDataURL",
                "AudioContext",
                "timeZone"};

            if (fingerprintSources.count(varName)) {
              sources.push_back(&I);
              static std::set<std::string> loggedFingerprints;
              if (loggedFingerprints.find(varName) ==
                  loggedFingerprints.end()) {
                log("  [Medium Source] Identified Fingerprinting factor: " +
                    varName + "\n");
                loggedFingerprints.insert(varName);
              }
            }

            // 오염된 전역 변수 로드 확인
            for (const auto &taintedName : taintedGlobals) {
              if (taintedName == varName) {
                sources.push_back(&I);
                static std::set<std::string> loggedLoads;
                if (loggedLoads.find(varName) == loggedLoads.end()) {
                  log("  [Global Taint] Marking load of '" + varName +
                      "' as Source.\n");
                  loggedLoads.insert(varName);
                }
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

bool TaintAnalysis::isSinkInstruction(Instruction *I, std::string &sinkAPI, SinkType &type) {
  // 1. 속성 저장 (예: .src, .innerHTML)
  if (auto *SPI = llvh::dyn_cast<StorePropertyInst>(I)) {
    // [Backtracking 적용] 리터럴이 아니면 역추적 시도
    std::string propName = "";
    if (auto *litProp = llvh::dyn_cast<LiteralString>(SPI->getProperty())) {
      propName = litProp->getValue().str().str();
    } else {
      // 속성 이름이 변수일 때도 한 번 더 뒤져봄 (필요 시)
    }

    std::string objectName = extractObjectName(SPI->getObject());
    if (auto *sinkDef = sinkRegistry_.isPropertySink(objectName, propName)) {
      sinkAPI = sinkDef->name;
      type = sinkDef->type;
      return true;
    }
  }

  // 2. 함수 호출 (예: .sendBeacon, .postMessage)
  if (auto *CI = llvh::dyn_cast<CallInst>(I)) {
    Value *callee = CI->getCallee();
    if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(callee)) {
      // ★ [고도화] 역추적 엔진을 사용하여 난독화된 메서드명 식별
      std::string methodName = CallGraphAnalyzer::tryBacktrackPropertyName(LPI); 
      std::string objectName = extractObjectName(LPI->getObject());

      if (auto *sinkDef = sinkRegistry_.isMethodSink(objectName, methodName)) {
        sinkAPI = sinkDef->name;
        type = sinkDef->type;
        return true;
      }
    }
  }
  return false;
}

// bool TaintAnalysis::isSinkInstruction(
//     Instruction *I,
//     std::string &sinkAPI,
//     SinkType &type) {

//   // 1. StorePropertyInst 처리 (중괄호가 여기서 닫히지 않도록 주의)
//   if (auto *SPI = llvh::dyn_cast<StorePropertyInst>(I)) {
//     std::string propName = "";
//     if (auto *litProp = llvh::dyn_cast<LiteralString>(SPI->getProperty())) {
//       propName = litProp->getValue().str().str();
//     }

//     std::string objectName = extractObjectName(SPI->getObject());

//     if (auto *sinkDef = sinkRegistry_.isPropertySink(objectName, propName)) {
//       sinkAPI = sinkDef->name;
//       type = sinkDef->type;
//       return true;
//     }
//   }

//   // 2. CallInst 처리
//   if (auto *CI = llvh::dyn_cast<CallInst>(I)) {
//     Value *callee = CI->getCallee();
    
//     // 메서드 호출 (obj.method())
//     if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(callee)) {
//       std::string methodName = tryBacktrackPropertyName(LPI); // 역추적 적용
//       std::string objectName = extractObjectName(LPI->getObject());

//       if (auto *sinkDef = sinkRegistry_.isMethodSink(objectName, methodName)) {
//         sinkAPI = sinkDef->name;
//         type = sinkDef->type;
//         return true;
//       }
//     }
    
//     // 전역 함수 호출 (eval, setTimeout 등)
//     if (auto *GPI = llvh::dyn_cast<TryLoadGlobalPropertyInst>(callee)) {
//       if (auto *litProp = llvh::dyn_cast<LiteralString>(GPI->getProperty())) {
//         std::string functionName = litProp->getValue().str().str();
//         if (auto *sinkDef = sinkRegistry_.isFunctionSink(functionName)) {
//           sinkAPI = sinkDef->name;
//           type = sinkDef->type;
//           return true;
//         }
//       }
//     }
//   }

//   // 3. DirectEvalInst 처리
//   if (llvh::isa<DirectEvalInst>(I)) {
//     if (auto *sinkDef = sinkRegistry_.isFunctionSink("eval")) {
//       sinkAPI = sinkDef->name;
//       type = sinkDef->type;
//       return true;
//     }
//   }

//   // 모든 조건에 맞지 않을 때만 마지막에 false 반환
//   return false;
// }

void TaintAnalysis::analyzeTaintFlow(
    const llvh::SmallVectorImpl<Instruction *> &sources,
    const llvh::SmallVectorImpl<Instruction *> &sinks) {
  // 1. Source/Sink 벡터 변환
  std::vector<Instruction *> sourceVec(sources.begin(), sources.end());
  std::vector<Instruction *> sinkVec(sinks.begin(), sinks.end());

  // 2. [변경됨] 함수 호출 매핑 정보는 runOnModule에서 이미 설정됨
  // (defUseAnalyzer_.setFunctionCalls 호출 완료)

  // 3. 오염 흐름 분석 실행
  defUseAnalyzer_.analyzeTaintFlow(sourceVec, sinkVec, &closureAnalyzer_);

  // 4. 결과 경로 가져오기
  const auto &sinkPaths = defUseAnalyzer_.getSinkReachingPaths();

  // 5. 결과 처리 loop
  for (const auto &pathStruct :
       sinkPaths) { // 이름을 pathStruct로 명확하게 변경
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
      default:
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

// analyzeFunctionCalls, shouldAnalyzeFunction, tryBacktrackPropertyName moved to CallGraphAnalyzer.cpp

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

// [구현] 실제 오염 데이터(Taint)가 흐르는지 엔진에 물어보는 함수
bool TaintAnalysis::isTainted(Value *V) {
  if (!V) return false;
  return defUseAnalyzer_.isTainted(V); // DefUseAnalyzer 엔진과 연결
}

#undef DEBUG_TYPE
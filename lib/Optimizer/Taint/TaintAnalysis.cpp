/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "taintanalysis"
#include "hermes/Optimizer/Taint/TaintAnalysis.h"
#include "hermes/IR/Analysis.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/Instrs.h"
#include "llvh/Support/Debug.h"
#include "llvh/Support/raw_ostream.h"
#include "hermes/Optimizer/Taint/CallGraphAnalyzer.h"
#include "llvh/Support/Path.h"
#include <fstream>

using namespace hermes;
using llvh::dbgs;
using llvh::outs;

//===----------------------------------------------------------------------===//
// TaintAnalysis Implementation
//===----------------------------------------------------------------------===//

bool TaintAnalysis::runOnModule(Module *M) {
  outs() << "\n";
  outs() << "========================================\n";
  outs() << "=== Taint Analysis for Hermes IR\n";
  outs() << "========================================\n\n";
  
  // Continue with normal processing

  // Step 1: 자바스크립트의 클로저(Scope) 관계 먼저 파악
  outs() << "[Phase 1] Analyzing closures...\n";
  closureAnalyzer_.analyzeModuleClosures(M);
  outs() << "  Closure analysis complete.\n\n";

  // Step 2: 오염원(Source) 찾기 e.g.) cookie, fetch 결과 등
  outs() << "[Phase 2] Identifying taint sources...\n";
  auto sources = identifySources(M);
  outs() << "  Found " << sources.size() << " source(s).\n\n";

  // Step 3: 도착지(sink) 찾기 e.g. innerHTML, send 등
  outs() << "[Phase 3] Identifying taint sinks...\n";
  
  // Continue with sink identification
  
  auto sinks = identifySinks(M);
  outs() << "  Found " << sinks.size() << " sink(s).\n\n";

  // Step 4: 함수 흐름 추출 (Call Graph)
  outs() << "[Phase 4] Analyzing function calls...\n";
  outs() << "  Function call analysis complete.\n\n";

  CallGraphAnalyzer CGAnalyzer(M);
  CGAnalyzer.analyze();
  CGAnalyzer.dump(outs());

  analyzeFunctionCalls(M);
  outs() << "  Call Graph extraction complete.\n\n";

  // Step 5: 함수간 오염 전파를 위한 연결(Inter-procedural Links)고리를 만드는 단계
  outs() << "[Phase 5] Creating inter-procedural taint links...\n";

  if (functionCalls_.empty()) {
      outs() << "  (No inter-procedural calls found to link)\n";
  } else {
      std::vector<DefUseAnalyzer::FunctionCallMapping> mappings;
      for(auto &info : functionCalls_) {
          DefUseAnalyzer::FunctionCallMapping m;
          m.callSite = info.callSite;
          m.targetFunction = info.targetFunction;
          m.arguments = info.arguments;
          mappings.push_back(m);
      }
      
      // 추적기에게 "이 지도대로 움직여!"라고 명령
      defUseAnalyzer_.setFunctionCalls(mappings);
      
      outs() << "  Inter-procedural links created (" << mappings.size() << " links).\n";
  }
  outs() << "\n";

  // Step 6: 오염 확산 분석(Propagation), DefUseAnalyzer를 시켜서 실제 변수 흐름 추적
  outs() << "[Phase 6] Analyzing taint propagation...\n";
  analyzeTaintFlow(sources, sinks);
  outs() << "  Taint flow analysis complete.\n\n";

  // Step 7: 결과출력(Reporting)
  outs() << "[Phase 7] Generating vulnerability report...\n";
  std::string sourceFileName = "unknown_script.js";
  for (auto &F : *M) {
      if (!F.empty() && !F.front().empty()) {
          auto &I = F.front().front();
          if (I.getLocation().isValid()) {
              auto *buf = M->getContext().getSourceErrorManager().findBufferForLoc(I.getLocation());
              if (buf) {
                  sourceFileName = buf->getBufferIdentifier();
                  break; 
              }
          }
      }
  }
  
  reportVulnerabilities(sourceFileName);

  outs() << "\n========================================\n";
  outs() << "=== Taint Analysis Complete\n";
  outs() << "========================================\n\n";

  // This pass does not modify IR
  return false;
}

llvh::SmallVector<Instruction *, 32> TaintAnalysis::identifySources(Module *M) {
  llvh::SmallVector<Instruction *, 32> sources;
  std::vector<std::string> taintedGlobals; // 오염된 전역 변수 이름 목록

  // ====================================================
  // [Step 0] 전역 변수 오염 여부 미리 스캔 (Pre-scan)
  // ====================================================
  for (auto &F : *M) {
    for (auto &BB : F) {
      for (auto &I : BB) {
        // 전역 변수에 뭔가 저장하는지(StorePropertyInst) 확인
        if (auto *SPI = llvh::dyn_cast<StorePropertyInst>(&I)) {
            Value *storedVal = SPI->getStoredValue();
            
            // 1. 저장하려는 값이 오염원(Source)에서 왔는지 확인
            bool isTainted = false;
            if (auto *Instr = llvh::dyn_cast<Instruction>(storedVal)) {
                std::string dummy;
                // 직접적인 오염원인가? (document.cookie)
                if (isSourceInstruction(Instr, dummy)) {
                    isTainted = true;
                }
                // 또는 오염된 값을 리턴하는 함수 호출인가? (Hybrid Logic 재사용)
                else if (auto *CI = llvh::dyn_cast<CallInst>(Instr)) {
                     // ... (간략화된 함수 확인 로직) ...
                     Value *callee = CI->getCallee();
                     if (auto *func = llvh::dyn_cast<Function>(callee)) {
                         if (returnsTaintedValue(func)) isTainted = true;
                     }
                     // LoadPropertyInst를 통한 호출 처리 등은 복잡하니 생략하거나 필요시 추가
                }
            }

            // 2. 오염된 값을 전역 객체에 저장한다면, 그 변수 이름을 기록
            if (isTainted) {
                if (auto *Lit = llvh::dyn_cast<LiteralString>(SPI->getProperty())) {
                    std::string varName = Lit->getValue().str().str();
                    taintedGlobals.push_back(varName);
                    llvh::outs() << "  [Global Taint] Found tainted global variable: " << varName << "\n";
                }
            }
        }
      }
    }
  }

  // ====================================================
  // [Step 1 & 2] 실제 오염원 등록 (기존 로직 + Global Load 추가)
  // ====================================================
  for (auto &F : *M) {
    for (auto &BB : F) {
      for (auto &I : BB) {
        
        // 1. 기존 API 오염원 (document.cookie 등)
        std::string sourceAPI;
        if (isSourceInstruction(&I, sourceAPI)) {
          sources.push_back(&I);
        }

        // 2. 함수 반환값 오염원 (CallInst)
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

        // 3. ★ [NEW] 전역 변수 읽기(Load) 오염원
        // 아까 [Step 0]에서 기록해둔 전역 변수를 읽는다면, 그것도 오염원이다!
        if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(&I)) {
            if (auto *Lit = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
                std::string varName = Lit->getValue().str().str();
                
                // 기록해둔 명단에 있는지 확인
                for (const auto &taintedName : taintedGlobals) {
                    if (taintedName == varName) {
                        sources.push_back(&I);
                        llvh::outs() << "  [Global Taint] Marking load of '" << varName << "' as Source.\n";
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
        
        // isSinkInstruction 헬퍼 함수를 사용하여 싱크인지 확인
        if (isSinkInstruction(&I, sinkName, type)) {
          sinks.push_back(&I);
          
          // 디버깅용 로그 출력
          LLVM_DEBUG(llvh::dbgs() << "  [Sink] Found " << sinkName 
                                  << " (Type: " << static_cast<int>(type) << ")\n");
        }
      }
    }
  }

  return sinks;
}

bool TaintAnalysis::isSourceInstruction(Instruction *I, std::string &sourceAPI) {
  
  // 1. 프로퍼티 접근 (Property Access) 확인
  // 예: navigator.userAgent, document.cookie 등
  if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(I)) {
    if (auto *litProp = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
      // (1) 프로퍼티 이름 추출 (예: "cookie")
      std::string propName = litProp->getValue().str().str();
      
      // (2) 객체 이름 추출 (예: "document") -> 우리가 만든 함수 활용!
      std::string objName = extractObjectName(LPI->getObject());
      
      // (3) 완전한 이름 생성 (예: "document.cookie")
      std::string fullName = objName + "." + propName;

      // (4) 레지스트리에 "정확한 이름"이 있는지 확인
      // SourceDefinitions.cpp에 정의된 데이터와 대조
      const auto *sourceDef = sourceRegistry_.getSourceByFullName(fullName);
      if (sourceDef) {
          sourceAPI = fullName;
          return true; // 진짜 오염원이다!
      }
      
      // 보완책: 만약 객체 이름 추적 실패("Unknown") 등으로 놓칠 수 있으니
      // 기존처럼 프로퍼티 이름만으로 체크하되, 로그를 남기거나 약한 오염원으로 처리할 수도 있음
    }
  }

  // 2. 함수 호출 (Function Call) 확인
  // 예: fetch(), localStorage.getItem() 등
  if (auto *CI = llvh::dyn_cast<CallInst>(I)) {
     // 함수 이름 추출 (예: "fetch" 또는 "localStorage.getItem")
     std::string funcName = extractObjectName(CI->getCallee());
     
     // 레지스트리 확인
     const auto *sourceDef = sourceRegistry_.getSourceByFullName(funcName);
     if (sourceDef) {
         sourceAPI = funcName;
         return true;
     }
  }

  // 3. 생성자 호출 (Constructor) 확인
  // 예: new WebSocket(...)
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
  if (!object) return "Unknown";

  // 1. [Global/Property Load] 전역 변수나 프로퍼티 읽기 (예: globalData)
  if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(object)) {
    if (auto *Lit = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
       return Lit->getValue().str().str(); 
    }
  }

  // 2. [Function Call] 함수 호출 결과 (예: checkCookie())
  if (auto *CI = llvh::dyn_cast<CallInst>(object)) {
    Value *callee = CI->getCallee();
    
    // 2-1. 직접 호출된 함수 이름
    if (auto *func = llvh::dyn_cast<Function>(callee)) {
        return func->getInternalNameStr().str() + "()";
    }
    // 2-2. 프로퍼티로 호출된 메서드 이름
    if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(callee)) {
        if (auto *Lit = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
            return Lit->getValue().str().str() + "()";
        }
    }
    return "AnonymousFunction()";
  }

  // 3. [Ordinary Instruction] 그 외 명령어 (예: document.cookie)
  if (auto *I = llvh::dyn_cast<Instruction>(object)) {
      // API 이름이 있다면 가져오기 (SourceDefinitions 확인)
      // 여기서는 단순히 명령어나 타입 이름을 반환하거나, "Detected Source"라고 표기
      return std::string(I->getKindStr());
  }

  return "UnknownSource";
}

bool TaintAnalysis::isSinkInstruction(
    Instruction *I,
    std::string &sinkAPI,
    SinkType &type) {
  
  // Add a counter to see if this function is called at all
  static int callCount = 0;
  callCount++;
  if (callCount <= 3) {  // Only print first few calls to avoid spam
    outs() << "  [DEBUG] isSinkInstruction called " << callCount << " times, instruction: " 
           << I->getKindStr() << "\n";
  }
  
  // Check StorePropertyInst (e.g., element.innerHTML = ...)
  if (auto *SPI = llvh::dyn_cast<StorePropertyInst>(I)) {
    outs() << "  [DEBUG] Found StorePropertyInst!\n";
    if (auto *litProp = llvh::dyn_cast<LiteralString>(SPI->getProperty())) {
      std::string propName = litProp->getValue().str().str();
      
      // Try to extract object name for better matching
      std::string objectName = extractObjectName(SPI->getObject());
      outs() << "  [DEBUG] Property assignment: " << objectName << "." << propName << "\n";
      
      // Try with specific object name first  
      if (auto *sinkDef = sinkRegistry_.isPropertySink(objectName, propName)) {
        outs() << "    [DEBUG] Found object-specific sink: " << sinkDef->name << "\n";
        sinkAPI = sinkDef->name;
        type = sinkDef->type;
        return true;
      }
      
      // Fall back to generic property name (works for innerHTML, outerHTML on any element)
      if (auto *sinkDef = sinkRegistry_.isPropertySink("", propName)) {
        outs() << "    [DEBUG] Found generic property sink: " << sinkDef->name << "\n";
        sinkAPI = sinkDef->name;
        type = sinkDef->type;
        return true;
      }
      
      outs() << "    [DEBUG] Property '" << objectName << "." << propName << "' is not a sink\n";
    } else {
      outs() << "  [DEBUG] StorePropertyInst property is not a literal string\n";
    }
  }

  // Check CallInst for method sinks (e.g., document.write, eval)
  if (auto *CI = llvh::dyn_cast<CallInst>(I)) {
    Value *callee = CI->getCallee();

    // Check if it's a LoadPropertyInst (method call)
    if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(callee)) {
      if (auto *litProp = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
        std::string methodName = litProp->getValue().str().str();
        
        // Try to extract object name for better matching
        std::string objectName = extractObjectName(LPI->getObject());
        outs() << "  [DEBUG] Method call: " << objectName << "." << methodName << "\n";
        
        // Try with specific object name first
        if (auto *sinkDef = sinkRegistry_.isMethodSink(objectName, methodName)) {
          outs() << "    [DEBUG] Found method sink: " << sinkDef->name << "\n";
          sinkAPI = sinkDef->name;
          type = sinkDef->type;
          return true;
        }
        
        // Fall back to generic method name
        if (auto *sinkDef = sinkRegistry_.isMethodSink("", methodName)) {
          outs() << "    [DEBUG] Found generic method sink: " << sinkDef->name << "\n";
          sinkAPI = sinkDef->name;
          type = sinkDef->type;
          return true;
        }
        
        outs() << "    [DEBUG] Method '" << objectName << "." << methodName << "' is not a sink\n";
      }
    }

    // Check if it's a direct function call (e.g., eval, fetch)
    if (auto *GPI = llvh::dyn_cast<TryLoadGlobalPropertyInst>(callee)) {
      if (auto *litProp = llvh::dyn_cast<LiteralString>(GPI->getProperty())) {
        std::string functionName = litProp->getValue().str().str();
        outs() << "  [DEBUG] Global function call: " << functionName << "\n";
        
        if (auto *sinkDef = sinkRegistry_.isFunctionSink(functionName)) {
          outs() << "    [DEBUG] Found function sink: " << sinkDef->name << "\n";
          sinkAPI = sinkDef->name;
          type = sinkDef->type;
          return true;
        }
        
        outs() << "    [DEBUG] Function '" << functionName << "' is not a sink\n";
      }
    }
  }

  // Check DirectEvalInst (eval() calls)
  if (auto *DEI = llvh::dyn_cast<DirectEvalInst>(I)) {
    outs() << "  [DEBUG] Found DirectEvalInst (eval call)\n";
    if (auto *sinkDef = sinkRegistry_.isFunctionSink("eval")) {
      outs() << "    [DEBUG] Found eval sink: " << sinkDef->name << "\n";
      sinkAPI = sinkDef->name;
      type = sinkDef->type;
      return true;
    }
    outs() << "    [DEBUG] eval not registered as sink\n";
  }

  return false;
}

void TaintAnalysis::analyzeTaintFlow(
    const llvh::SmallVectorImpl<Instruction *> &sources,
    const llvh::SmallVectorImpl<Instruction *> &sinks) {
  // Convert SmallVector to std::vector for DefUseAnalyzer API
  std::vector<Instruction *> sourceVec(sources.begin(), sources.end());
  std::vector<Instruction *> sinkVec(sinks.begin(), sinks.end());

  outs() << "[DEBUG TAINT] Passing " << sinkVec.size() << " sinks to DefUseAnalyzer:\n";
  for (size_t i = 0; i < sinkVec.size(); ++i) {
    outs() << "  [" << i << "] " << sinkVec[i]->getKindStr() << "\n";
  }

  // Convert function calls to DefUseAnalyzer format
  std::vector<DefUseAnalyzer::FunctionCallMapping> callMappings;
  for (const auto &callInfo : functionCalls_) {
    DefUseAnalyzer::FunctionCallMapping mapping;
    mapping.callSite = callInfo.callSite;
    mapping.targetFunction = callInfo.targetFunction;
    mapping.arguments = callInfo.arguments;
    callMappings.push_back(mapping);
  }
  
  // Set function calls in DefUseAnalyzer
  defUseAnalyzer_.setFunctionCalls(callMappings);

  // Perform taint analysis using DefUseAnalyzer
  defUseAnalyzer_.analyzeTaintFlow(sourceVec, sinkVec, &closureAnalyzer_);

  // Get all paths that reached sinks
  const auto &sinkPaths = defUseAnalyzer_.getSinkReachingPaths();
  
  outs() << "[DEBUG TAINT] DefUseAnalyzer found " << sinkPaths.size() << " sink-reaching paths\n";

  // Convert to vulnerability reports
  for (const auto &path : sinkPaths) {
    std::string sourceAPI;
    std::string sinkAPI;
    SinkType sinkType = SinkType::Network; // Default

    // Identify source API
    isSourceInstruction(path.source, sourceAPI);

    // Identify sink API
    isSinkInstruction(path.sink, sinkAPI, sinkType);

    // Create report
    reports_.emplace_back(
        path.source, path.sink, sourceAPI, sinkAPI, sinkType, path.path);
  }
}

void TaintAnalysis::reportVulnerabilities(llvh::StringRef targetFilename) {
  
  llvh::StringRef stem = llvh::sys::path::stem(targetFilename);
  if (stem.empty()) stem = "taint";
  std::string outFileName = (stem + "_report.txt").str();

  std::ofstream reportFile(outFileName);
  
  auto log = [&](const std::string &msg) {
      outs() << msg;
      if (reportFile.is_open()) {
          reportFile << msg;
      }
  };

  log("\n");
  log("========================================\n");
  log("=== [Final Vulnerability Report] ===\n");
  log("    Target File: " + targetFilename.str() + "\n");
  log("    Output File: " + outFileName + "\n");
  log("========================================\n\n");

  if (reports_.empty()) {
      log("  ✓ No taint flows detected.\n");
  } else {
      log("  ⚠️  Found " + std::to_string(reports_.size()) + " potential vulnerability(ies):\n\n");

      unsigned index = 1;
      for (const auto &report : reports_) {
          const auto &path = report.path; 
          Instruction *sourceInst = path.front();
          Instruction *sinkInst = path.back();    
          
          std::string sourceName = extractObjectName(sourceInst);
          std::string sinkName = extractObjectName(sinkInst);
          
          log("  [" + std::to_string(index++) + "] " + getSinkTypeName(report.sinkType) + " Vulnerability\n");
          log("      Source: " + sourceName + "\n");
          log("      Sink:   " + sinkName + "\n");
          log("      Path length: " + std::to_string(path.size()) + " instruction(s)\n");

          if (path.size() <= 20) {
              log("      Path: ");
              for (size_t i = 0; i < path.size(); ++i) {
                  if (i > 0) log(" → ");
                  log(path[i]->getKindStr().str());
              }
              log("\n");
          }
          log("\n");
      }
  }
  
  log("========================================\n");
  
  if (reportFile.is_open()) {
      outs() << "  [System] Report saved to '" << outFileName << "'\n";
      reportFile.close();
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
  functionCalls_.clear(); // 기존 목록 초기화

  for (auto &F : *M) {
    for (auto &BB : F) {
      for (auto &I : BB) {
        if (auto *CI = llvh::dyn_cast<CallInst>(&I)) {
          
          Value *callee = CI->getCallee();
          Function *targetFunc = nullptr;

          // 1. 직접 호출인 경우 (Direct Call)
          if (auto *func = llvh::dyn_cast<Function>(callee)) {
            targetFunc = func;
          }
          // 2. ★ [추가됨] 프로퍼티 로드 후 호출 (Smart Detection)
          // 예: global.sendData(...) 처럼 호출하는 경우를 찾습니다.
          else if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(callee)) {
             if (auto *Lit = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
                std::string funcName = Lit->getValue().str().str();
                
                // 모듈 전체를 뒤져서 이름이 같은 함수를 찾습니다.
                for (auto &candidateF : *M) {
                    if (candidateF.getInternalNameStr() == funcName) {
                        targetFunc = &candidateF;
                        break;
                    }
                }
             }
          }

          // 찾은 함수가 분석 대상이라면 연결 정보를 저장합니다.
          if (targetFunc && shouldAnalyzeFunction(targetFunc)) {
            FunctionCallInfo callInfo;
            callInfo.callSite = CI;           // 호출한 곳 (Caller)
            callInfo.targetFunction = targetFunc; // 호출당한 놈 (Callee)
            
            // 인자값들(Arguments) 수집
            for (unsigned i = 0; i < CI->getNumArguments(); ++i) {
              callInfo.arguments.push_back(CI->getArgument(i));
            }
            
            functionCalls_.push_back(callInfo); // 저장!
            
            outs() << "  [Inter-procedural] Link created: " 
                   << F.getInternalNameStr() << " -> " 
                   << targetFunc->getInternalNameStr() << "\n";
          }
        }
      }
    }
  }
}

bool TaintAnalysis::shouldAnalyzeFunction(Function *F) {
  // Skip built-in functions and empty functions
  if (!F || F->empty()) {
    return false;
  }
  
  // Skip functions that are likely built-ins based on naming patterns
  std::string name = F->getInternalNameStr();
  if (name.empty() || name == "global" || name.find("HermesInternal") != std::string::npos) {
    return false;
  }
  
  return true;
}

// 함수가 내부에서 Source를 반환하는지 검사하는 함수
bool TaintAnalysis::returnsTaintedValue(Function *F) {
  for (auto &BB : *F) {
    for (auto &I : BB) {
      // 1. 오염원(Source)이 있는지 확인 (예: document.cookie)
      std::string sourceAPI;
      if (isSourceInstruction(&I, sourceAPI)) {
        
        // 2. 이 오염원이 ReturnInst까지 흘러가는지 간단히 확인
        // (복잡한 DefUse 대신, 같은 블록 내에서 바로 리턴하는지 정도만 봐도 효과적)
        for (auto *User : I.getUsers()) {
            if (llvh::isa<ReturnInst>(User)) {
                return true; // "범인이다! 이 함수는 오염을 뱉는다!"
            }
            // 변수에 저장했다가 리턴하는 경우 (Load/Store)
            if (auto *SF = llvh::dyn_cast<StoreFrameInst>(User)) {
                // ... 조금 더 깊은 추적 로직이 필요할 수 있음 ...
                // 일단은 "직접 사용"만 체크해도 꽤 많이 잡힙니다.
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

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
#include <sstream>

using namespace hermes;
using llvh::dbgs;
using llvh::outs;

void TaintAnalysis::log(const std::string &msg) {
  outs() << msg;
  if (reportFile_.is_open()) {
      reportFile_ << msg;
      reportFile_.flush();
  }
}

bool TaintAnalysis::runOnModule(Module *M) {
  // 1. 파일 이름 찾기
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

  // 2. 파일 열기
  llvh::StringRef stem = llvh::sys::path::stem(sourceFileName);
  if (stem.empty()) stem = "taint";
  std::string outFileName = (stem + "_report.txt").str();
  
  reportFile_.open(outFileName);

  // 3. 로그 시작
  log("\n");
  log("========================================\n");
  log("=== Taint Analysis for Hermes IR\n");
  log("    Target: " + sourceFileName + "\n");
  log("    Output: " + outFileName + "\n");
  log("========================================\n\n");
  
  // Phase 1
  log("[Phase 1] Analyzing closures...\n");
  closureAnalyzer_.analyzeModuleClosures(M);
  log("  Closure analysis complete.\n\n");

  // Phase 2
  log("[Phase 2] Identifying taint sources...\n");
  auto sources = identifySources(M);
  log("  Found " + std::to_string(sources.size()) + " source(s).\n\n");

  // Phase 3
  log("[Phase 3] Identifying taint sinks...\n");
  auto sinks = identifySinks(M);
  log("  Found " + std::to_string(sinks.size()) + " sink(s).\n\n");

  // Phase 4
  log("[Phase 4] Analyzing function calls...\n");
  
  // CallGraphAnalyzer 실행
  CallGraphAnalyzer CGAnalyzer(M);
  CGAnalyzer.analyze();

  std::string graphDump;
  llvh::raw_string_ostream os(graphDump); // 문자열 스트림 생성
  CGAnalyzer.dump(os);                    // dump 결과를 스트림에 씀
  log(os.str());                          // 캡처된 문자열을 파일과 화면에 로그

  analyzeFunctionCalls(M);
  log("  Call Graph extraction complete.\n\n");

  // Phase 5
  log("[Phase 5] Creating inter-procedural taint links...\n");
  if (functionCalls_.empty()) {
      log("  (No inter-procedural calls found to link)\n");
  } else {
      std::vector<DefUseAnalyzer::FunctionCallMapping> mappings;
      for(auto &info : functionCalls_) {
          DefUseAnalyzer::FunctionCallMapping m;
          m.callSite = info.callSite;
          m.targetFunction = info.targetFunction;
          m.arguments = info.arguments;
          mappings.push_back(m);
      }
      defUseAnalyzer_.setFunctionCalls(mappings);
      log("  Inter-procedural links created (" + std::to_string(mappings.size()) + " links).\n");
  }
  log("\n");

  // Phase 6
  log("[Phase 6] Analyzing taint propagation...\n");
  analyzeTaintFlow(sources, sinks);
  log("  Taint flow analysis complete.\n\n");

  // Phase 7
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
                         if (returnsTaintedValue(func)) isTainted = true;
                     }
                }
            }
            if (isTainted) {
                if (auto *Lit = llvh::dyn_cast<LiteralString>(SPI->getProperty())) {
                    std::string varName = Lit->getValue().str().str();
                    taintedGlobals.push_back(varName);
                    log("  [Global Taint] Found tainted global variable: " + varName + "\n");
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
                        log("  [Global Taint] Marking load of '" + varName + "' as Source.\n");
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
          // 디버그 로그도 필요하면 log()로 변경 (현재는 유지)
        }
      }
    }
  }
  return sinks;
}

bool TaintAnalysis::isSourceInstruction(Instruction *I, std::string &sourceAPI) {
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
  if (!object) return "Unknown";
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
  
  // ★ [수정] 디버그 로그를 log()로 변경 (많이 출력될 수 있으니 주의)
  // static int callCount = 0;
  // callCount++;
  // if (callCount <= 3) {
  //   std::string msg = "  [DEBUG] isSinkInstruction called, instruction: " + std::string(I->getKindStr().str()) + "\n";
  //   log(msg); 
  // }
  
  // (나머지 isSinkInstruction 로직 그대로 유지)
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
        sinkAPI = sinkDef->name;
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
        
        if (auto *sinkDef = sinkRegistry_.isMethodSink(objectName, methodName)) {
          sinkAPI = sinkDef->name;
          type = sinkDef->type;
          return true;
        }
        if (auto *sinkDef = sinkRegistry_.isMethodSink("", methodName)) {
          sinkAPI = sinkDef->name;
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
  std::vector<Instruction *> sourceVec(sources.begin(), sources.end());
  std::vector<Instruction *> sinkVec(sinks.begin(), sinks.end());

  // 디버깅 로그 (필요시 log로 변경)
  // log("[DEBUG TAINT] Analyzing " + std::to_string(sinkVec.size()) + " sinks...\n");

  std::vector<DefUseAnalyzer::FunctionCallMapping> callMappings;
  for (const auto &callInfo : functionCalls_) {
    DefUseAnalyzer::FunctionCallMapping mapping;
    mapping.callSite = callInfo.callSite;
    mapping.targetFunction = callInfo.targetFunction;
    mapping.arguments = callInfo.arguments;
    callMappings.push_back(mapping);
  }
  
  defUseAnalyzer_.setFunctionCalls(callMappings);
  defUseAnalyzer_.analyzeTaintFlow(sourceVec, sinkVec, &closureAnalyzer_);
  const auto &sinkPaths = defUseAnalyzer_.getSinkReachingPaths();
  
  for (const auto &path : sinkPaths) {
    std::string sourceAPI;
    std::string sinkAPI;
    SinkType sinkType = SinkType::Network;

    isSourceInstruction(path.source, sourceAPI);
    isSinkInstruction(path.sink, sinkAPI, sinkType);

    reports_.emplace_back(
        path.source, path.sink, sourceAPI, sinkAPI, sinkType, path.path);
  }
}

void TaintAnalysis::reportVulnerabilities() {
  log("\n");
  log("========================================\n");
  log("=== [Final Vulnerability Report] ===\n");
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
}

const char *TaintAnalysis::getSinkTypeName(SinkType type) {
  switch (type) {
  case SinkType::Network: return "Network";
  case SinkType::Storage: return "Storage";
  case SinkType::XSS: return "XSS";
  case SinkType::CodeInjection: return "Code Injection";
  case SinkType::Navigation: return "Navigation";
  default: return "Unknown";
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
            FunctionCallInfo callInfo;
            callInfo.callSite = CI;
            callInfo.targetFunction = targetFunc;
            for (unsigned i = 0; i < CI->getNumArguments(); ++i) {
              callInfo.arguments.push_back(CI->getArgument(i));
            }
            functionCalls_.push_back(callInfo);
            
            log("  [Inter-procedural] Link created: " + F.getInternalNameStr().str() + " -> " + targetFunc->getInternalNameStr().str() + "\n");
          }
        }
      }
    }
  }
}

bool TaintAnalysis::shouldAnalyzeFunction(Function *F) {
  if (!F || F->empty()) return false;
  std::string name = F->getInternalNameStr();
  if (name.empty() || name == "global" || name.find("HermesInternal") != std::string::npos) {
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
            if (llvh::isa<ReturnInst>(User)) return true;
            if (llvh::isa<StoreFrameInst>(User)) {
                 // ...
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
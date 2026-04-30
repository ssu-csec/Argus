/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "taintanalysis"
#include <nlohmann/json.hpp>
#include <fstream>
#include <functional>
#include <unordered_set>
#include "hermes/IR/Analysis.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Optimizer/Taint/CallGraphAnalyzer.h"
#include "hermes/Optimizer/Taint/TaintAnalysis.h"
#include "llvh/Support/Debug.h"
#include "llvh/Support/FileSystem.h"
#include "llvh/Support/Path.h"
#include "llvh/Support/raw_ostream.h"


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

  llvh::StringRef fullPath = sourceFileName;
  llvh::StringRef fileName = llvh::sys::path::filename(fullPath);

  prefix_ = "";
  if (fileName.equals("wholepage.js")) {
    llvh::StringRef parentDir = llvh::sys::path::parent_path(fullPath);
    prefix_ = llvh::sys::path::filename(parentDir).str();
    if (!prefix_.empty())
      prefix_ += "_";
  }

  llvh::StringRef stem = llvh::sys::path::stem(fileName);
  if (stem.empty())
    stem = "taint";

  std::string fileNameStr = (prefix_ + stem + "_report.txt").str();

  llvh::SmallString<128> reportDir("report");
  llvh::sys::fs::create_directory(reportDir);

  llvh::sys::path::append(reportDir, fileNameStr);

  std::string outFileName = reportDir.str().str();

  reportFile_.open(outFileName);

  log("\n");
  log("========================================\n");
  log("=== Taint Analysis for Hermes IR\n");
  log("    Target: " + sourceFileName + "\n");
  log("    Output: " + outFileName + "\n");
  log("========================================\n\n");

  log("[Phase 1] Analyzing closures...\n");
  closureAnalyzer_.analyzeModuleClosures(M);
  log("  Closure analysis complete.\n");

  collectEventDrivenFunctions(M);
  log("\n");

  log("[Phase 2] Identifying taint sources...\n");
  auto sources = identifySources(M);
  log("  Found " + std::to_string(sources.size()) + " source(s).\n\n");

  log("[Phase 3] Identifying taint sinks...\n");
  auto sinks = identifySinks(M);
  log("  Found " + std::to_string(sinks.size()) + " sink(s).\n\n");

  log("[Phase 4] Analyzing function calls...\n");
  CallGraphAnalyzer CGAnalyzer(M);
  CGAnalyzer.analyze(
      &defUseAnalyzer_, [this](const std::string &msg) { log(msg); });

  log("  Call Graph extraction complete.\n\n");

  log("[Phase 5] Creating inter-procedural taint links...\n");
  const auto &functionCalls = CGAnalyzer.getFunctionCalls();
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

  log("[Phase 6] Analyzing taint propagation...\n");
  analyzeTaintFlow(sources, sinks);
  log("  Taint flow analysis complete.\n\n");

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

              static const std::set<std::string> ignoreList = {
                  "exports",   "module",  "window",  "self",   "global",
                  "document",  "console", "process", "now",    "date",
                  "time",      "expires", "path",    "domain", "secure",
                  "undefined", "null",    "true",    "false",  "prototype",
                  "length",    "width",   "height"};

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

              static const std::set<std::string> encodingAPIs = {
                  "atob",
                  "btoa",
                  "decodeURIComponent",
                  "unescape",
                  "decodeURI"};
              if (encodingAPIs.count(funcName)) {
                sources.push_back(&I);
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

        if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(&I)) {
          if (auto *Lit = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
            std::string varName = Lit->getValue().str().str();

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

void TaintAnalysis::markAsEventDriven(Value *V, int depth) {
  if (!V || depth > 8)
    return;

  if (auto *CCI = llvh::dyn_cast<CreateFunctionInst>(V)) {
    eventDrivenFunctions_.insert(CCI->getFunctionCode());
    return;
  }

  if (auto *Call = llvh::dyn_cast<CallInst>(V)) {
    Value *callee = Call->getCallee();
    if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(callee)) {
      if (auto *Lit = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
        std::string method = Lit->getValue().str().str();
        if (method == "bind" || method == "call" || method == "apply") {
          markAsEventDriven(LPI->getObject(), depth + 1);
          return;
        }
      }
    }
    if (auto *CCI = llvh::dyn_cast<CreateFunctionInst>(callee)) {
      eventDrivenFunctions_.insert(CCI->getFunctionCode());
    }
    return;
  }

  if (auto *LFI = llvh::dyn_cast<LoadFrameInst>(V)) {
    Variable *var = LFI->getLoadVariable();
    for (auto *U : var->getUsers()) {
      if (auto *SFI = llvh::dyn_cast<StoreFrameInst>(U)) {
        if (SFI->getVariable() == var) {
          markAsEventDriven(SFI->getValue(), depth + 1);
        }
      }
    }
    return;
  }

  if (auto *Phi = llvh::dyn_cast<PhiInst>(V)) {
    for (unsigned i = 0, e = Phi->getNumEntries(); i < e; ++i) {
      markAsEventDriven(Phi->getEntry(i).first, depth + 1);
    }
    return;
  }
}

void TaintAnalysis::collectEventDrivenFunctions(Module *M) {
  for (auto &F : *M) {
    for (auto &BB : F) {
      for (auto &I : BB) {
        if (auto *Call = llvh::dyn_cast<CallInst>(&I)) {
          Value *callee = Call->getCallee();
          if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(callee)) {
            if (auto *Lit = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
              std::string methodName = Lit->getValue().str().str();
              if (methodName == "addEventListener" ||
                  methodName == "attachEvent") {
                for (unsigned i = 1; i < Call->getNumArguments(); ++i) {
                  markAsEventDriven(Call->getArgument(i), 0);
                }
              }
            }
          }
        }

        if (auto *SPI = llvh::dyn_cast<StorePropertyInst>(&I)) {
          if (auto *Lit = llvh::dyn_cast<LiteralString>(SPI->getProperty())) {
            std::string propName = Lit->getValue().str().str();
            if (propName.size() > 2 && propName.rfind("on", 0) == 0) {
              markAsEventDriven(SPI->getStoredValue(), 0);
            }
          }
        }
      }
    }
  }

  bool changed = true;
  int iterations = 0;
  while (changed && iterations < 10) {
    changed = false;
    iterations++;
    for (auto &F : *M) {
      if (eventDrivenFunctions_.count(&F) == 0)
        continue;
      for (auto &BB : F) {
        for (auto &I : BB) {
          if (auto *Call = llvh::dyn_cast<CallInst>(&I)) {
            if (auto *CCI =
                    llvh::dyn_cast<CreateFunctionInst>(Call->getCallee())) {
              if (eventDrivenFunctions_.insert(CCI->getFunctionCode()).second) {
                changed = true;
              }
            }
            for (unsigned i = 1; i < Call->getNumArguments(); ++i) {
              if (auto *CCI = llvh::dyn_cast<CreateFunctionInst>(
                      Call->getArgument(i))) {
                if (eventDrivenFunctions_.insert(CCI->getFunctionCode())
                        .second) {
                  changed = true;
                }
              }
            }
          }
        }
      }
    }
  }

  log("  [Rule 3] Event-driven function scan: " +
      std::to_string(eventDrivenFunctions_.size()) +
      " handler(s) identified.\n");
}

std::string TaintAnalysis::getTriggerContext(Instruction *sourceInst) {
  if (!sourceInst)
    return "UNKNOWN";

  Function *F = sourceInst->getParent()->getParent();
  if (!F)
    return "UNKNOWN";

  std::string funcName = F->getInternalNameStr().str();
  if (funcName == "global" || funcName == "main" || funcName == "") {
    return "AUTONOMOUS";
  }

  if (eventDrivenFunctions_.count(F) > 0) {
    return "EVENT_DRIVEN";
  }

  return "AUTONOMOUS";
}

std::string TaintAnalysis::getDestinationURL(Instruction *sinkInst) {
  if (!sinkInst)
    return "UNKNOWN";

  std::unordered_set<Value *> visited;

  std::function<std::string(Value *, int)> extractStringFromValue =
      [&](Value *V, int depth) -> std::string {
    if (!V || depth > 8)
      return "";
    if (!visited.insert(V).second)
      return "";
    if (auto *Lit = llvh::dyn_cast<LiteralString>(V)) {
      return Lit->getValue().str().str();
    }

    if (auto *BinOp = llvh::dyn_cast<BinaryOperatorInst>(V)) {
      if (BinOp->getOperatorKind() == BinaryOperatorInst::OpKind::AddKind) {
        std::string lhs =
            extractStringFromValue(BinOp->getLeftHandSide(), depth + 1);
        std::string rhs =
            extractStringFromValue(BinOp->getRightHandSide(), depth + 1);
        if (lhs.empty())
          lhs = "{VAR}";
        if (rhs.empty())
          rhs = "{VAR}";
        return lhs + rhs;
      }
    }

    if (auto *LFI = llvh::dyn_cast<LoadFrameInst>(V)) {
      Variable *var = LFI->getLoadVariable();
      for (auto *U : var->getUsers()) {
        if (auto *SFI = llvh::dyn_cast<StoreFrameInst>(U)) {
          std::string val = extractStringFromValue(SFI->getValue(), depth + 1);
          if (!val.empty())
            return val;
        }
      }
    }

    if (auto *Phi = llvh::dyn_cast<PhiInst>(V)) {
      for (unsigned i = 0, e = Phi->getNumEntries(); i < e; ++i) {
        auto pair = Phi->getEntry(i);
        std::string val = extractStringFromValue(pair.first, depth + 1);
        if (!val.empty())
          return val;
      }
    }

    if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(V)) {
      if (auto *PropName = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
        std::string pname = PropName->getValue().str().str();
        Value *obj = LPI->getObject();
        for (auto *U : obj->getUsers()) {
          if (auto *SPI = llvh::dyn_cast<StorePropertyInst>(U)) {
            if (auto *SPropName =
                    llvh::dyn_cast<LiteralString>(SPI->getProperty())) {
              if (SPropName->getValue().str().str() == pname) {
                std::string val =
                    extractStringFromValue(SPI->getStoredValue(), depth + 1);
                if (!val.empty())
                  return val;
              }
            }
          }
        }
      }
    }

    if (auto *CI = llvh::dyn_cast<CallInst>(V)) {
      Value *callee = CI->getCallee();

      if (auto *CFI = llvh::dyn_cast<CreateFunctionInst>(callee)) {
        Function *F = CFI->getFunctionCode();
        for (auto &BB : *F) {
          for (auto &I : BB) {
            if (auto *RI = llvh::dyn_cast<ReturnInst>(&I)) {
              std::string val =
                  extractStringFromValue(RI->getValue(), depth + 1);
              if (!val.empty())
                return val;
            }
          }
        }
      }
      if (auto *LFI = llvh::dyn_cast<LoadFrameInst>(callee)) {
        Variable *var = LFI->getLoadVariable();
        for (auto *U : var->getUsers()) {
          if (auto *SFI = llvh::dyn_cast<StoreFrameInst>(U)) {
            if (auto *CFI2 =
                    llvh::dyn_cast<CreateFunctionInst>(SFI->getValue())) {
              Function *F = CFI2->getFunctionCode();
              for (auto &BB : *F) {
                for (auto &I : BB) {
                  if (auto *RI = llvh::dyn_cast<ReturnInst>(&I)) {
                    std::string val =
                        extractStringFromValue(RI->getValue(), depth + 1);
                    if (!val.empty())
                      return val;
                  }
                }
              }
            }
          }
        }
      }
    }

    return "";
  };

  if (auto *CI = llvh::dyn_cast<CallInst>(sinkInst)) {
    for (unsigned i = 1; i < CI->getNumArguments(); ++i) {
      std::string val = extractStringFromValue(CI->getArgument(i), 0);
      if (!val.empty() &&
          (val.find("http") == 0 || val.find("//") == 0 ||
           val.find("/") == 0)) {
        return val;
      }
    }
  }

  if (auto *SPI = llvh::dyn_cast<StorePropertyInst>(sinkInst)) {
    Value *storedVal = SPI->getStoredValue();
    std::string val = extractStringFromValue(storedVal, 0);
    if (!val.empty()) {
      return val;
    }
  }

  return "DYNAMIC_URL";
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
    std::string propName = "";
    if (auto *litProp = llvh::dyn_cast<LiteralString>(SPI->getProperty())) {
      propName = litProp->getValue().str().str();
    } else {
    }

    std::string objectName = extractObjectName(SPI->getObject());

    if (propName == "src" || propName == "href") {
      sinkAPI = objectName + "." + propName + " (Evasion Suspected)";
      type = SinkType::Network;

      static std::set<std::string> loggedEvasions;
      if (loggedEvasions.find(sinkAPI) == loggedEvasions.end()) {
        log("  [Rule 4 Alert] Forced mapping DOM Evasion to SINK_NETWORK: " +
            sinkAPI + "\n");
        loggedEvasions.insert(sinkAPI);
      }
      return true;
    }

    if (auto *sinkDef = sinkRegistry_.isPropertySink(objectName, propName)) {
      sinkAPI = sinkDef->name;
      type = sinkDef->type;
      return true;
    }
  }

  if (auto *CI = llvh::dyn_cast<CallInst>(I)) {
    Value *callee = CI->getCallee();
    if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(callee)) {
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

void TaintAnalysis::analyzeTaintFlow(
    const llvh::SmallVectorImpl<Instruction *> &sources,
    const llvh::SmallVectorImpl<Instruction *> &sinks) {
  std::vector<Instruction *> sourceVec(sources.begin(), sources.end());
  std::vector<Instruction *> sinkVec(sinks.begin(), sinks.end());

  defUseAnalyzer_.setLogger([this](const std::string &msg) { log(msg); });
  defUseAnalyzer_.analyzeTaintFlow(sourceVec, sinkVec, &closureAnalyzer_);

  const auto &sinkPaths = defUseAnalyzer_.getSinkReachingPaths();
  log("  [Phase 6] Found " + std::to_string(sinkPaths.size()) +
      " potential taint path(s).\n");

  int pathCount = 0;
  for (const auto &pathStruct : sinkPaths) {
    std::string sourceAPI;
    std::string sinkAPI;
    SinkType sinkType = SinkType::Network;

    isSourceInstruction(pathStruct.source, sourceAPI);

    if (sourceAPI.empty() && pathStruct.source != nullptr) {
      if (llvh::isa<LoadPropertyInst>(pathStruct.source)) {
        sourceAPI = "Obfuscated_Property (LoadPropertyInst)";
      } else if (llvh::isa<CallInst>(pathStruct.source)) {
        sourceAPI = "Obfuscated_Call (CallInst)";
      } else {
        sourceAPI =
            "Dynamic_Source (" + pathStruct.source->getKindStr().str() + ")";
      }
    }

    isSinkInstruction(pathStruct.sink, sinkAPI, sinkType);

    std::vector<Instruction *> pathVec;
    for (auto *I : pathStruct.path) {
      pathVec.push_back(I);
    }

    if (!pathVec.empty()) {
      Instruction *source = pathVec.front();
      Instruction *sink = pathVec.back();

      vulnerabilities_.emplace_back(
          source, sink, sourceAPI, sinkAPI, sinkType, pathVec);

      log("    Path #" + std::to_string(++pathCount) + ": " + sourceAPI +
          " -> " + sinkAPI + "\n");
      for (auto *I : pathVec) {
        log("      -> " + I->getKindStr().str() + "\n");
      }
    }
  }
}

void TaintAnalysis::reportVulnerabilities() {
  log("\n========================================\n");
  log("=== Vulnerability Report (Categorized)\n");
  log("========================================\n");

  if (vulnerabilities_.empty()) {
    log("  No vulnerabilities found.\n");

    nlohmann::json masterLog;

    std::string domain = prefix_;
    if (!domain.empty() && domain.back() == '_')
      domain.pop_back();
    masterLog["target_url"] = domain.empty() ? "unknown" : domain;
    masterLog["event_driven_functions"] = (int)eventDrivenFunctions_.size();
    masterLog["s2s_routes"] = nlohmann::json::array();

    std::string jsonFileName = "report/" + prefix_ + "report.json";
    std::ofstream jsonFile(jsonFileName);
    if (jsonFile.is_open()) {
      jsonFile << masterLog.dump(4);
      jsonFile.close();
    }
    return;
  }

  int index = 1;
  for (const auto &vuln : vulnerabilities_) {
    Instruction *sourceInst = vuln.path.front();
    Instruction *sinkInst = vuln.path.back();

    std::string sinkName = "Unknown";
    SinkType sinkType = SinkType::XSS;

    if (auto *Call = llvh::dyn_cast<CallInst>(sinkInst)) {
      if (auto *Func = llvh::dyn_cast<Function>(Call->getCallee())) {
        sinkName = Func->getInternalNameStr().str();
        auto *def = SinkRegistry::getInstance().isFunctionSink(sinkName);
        if (def)
          sinkType = def->type;
      }

    } else if (auto *SPI = llvh::dyn_cast<StorePropertyInst>(sinkInst)) {
      if (auto *Lit = llvh::dyn_cast<LiteralString>(SPI->getProperty())) {
        sinkName = Lit->getValue().str().str();

        if (sinkName == "src")
          sinkType = SinkType::Network;
        else if (sinkName == "innerHTML")
          sinkType = SinkType::XSS;
        else if (sinkName == "location.href")
          sinkType = SinkType::Navigation;

        auto *def = SinkRegistry::getInstance().isPropertySink("", sinkName);
        if (def)
          sinkType = def->type;
      }
    }

    std::string severityTag = "[INFO]";
    std::string category = "General Flow";

    switch (sinkType) {
      default:
      case SinkType::Network:
        severityTag = "[CRITICAL]";
        category = "Data Exfiltration (Tracking)";
        break;
      case SinkType::Storage:
        severityTag = "[WARNING]";
        category = "Fingerprinting / Storage";
        break;
      case SinkType::CodeInjection:
        severityTag = "[HIGH]";
        category = "Code Injection";
        break;
      case SinkType::XSS:
        severityTag = "[MEDIUM]";
        category = "DOM Manipulation (XSS)";
        break;
      case SinkType::Navigation:
        severityTag = "[LOW]";
        category = "Page Navigation";
        break;
    }

    log("\n  " + severityTag + " [" + std::to_string(index++) + "] " +
        category + "\n");

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
  }

  log("\n[Export] Generating Master JSON Log for Python Classifier...\n");

  nlohmann::json masterLog;

  std::string domain = prefix_;
  if (!domain.empty() && domain.back() == '_')
    domain.pop_back();
  masterLog["target_url"] = domain.empty() ? "unknown" : domain;
  masterLog["event_driven_functions"] = (int)eventDrivenFunctions_.size();

  nlohmann::json s2sRoutes = nlohmann::json::array();
  int routeId = 1;

  for (const auto &vuln : vulnerabilities_) {
    Instruction *sourceInst = vuln.path.front();
    Instruction *sinkInst = vuln.path.back();

    nlohmann::json routeObj;
    routeObj["route_id"] = routeId++;

    std::string resolvedSource = vuln.sourceAPI;
    if (resolvedSource.empty() && !vuln.path.empty()) {
      Instruction *srcInst = vuln.path.front();
      if (llvh::isa<LoadPropertyInst>(srcInst)) {
        auto *LPI = llvh::cast<LoadPropertyInst>(srcInst);
        if (auto *Lit = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
          resolvedSource =
              "Obfuscated_Property::" + Lit->getValue().str().str();
        } else {
          resolvedSource = "Obfuscated_Property (LoadPropertyInst)";
        }
      } else if (llvh::isa<CallInst>(srcInst)) {
        resolvedSource = "Obfuscated_Call (CallInst)";
      } else {
        resolvedSource = "Dynamic_Source (" + srcInst->getKindStr().str() + ")";
      }
    }
    routeObj["source_name"] = resolvedSource;
    routeObj["sink_name"] = vuln.sinkAPI;
    routeObj["sink_type"] = getSinkTypeName(vuln.sinkType);

    routeObj["path_length"] = vuln.path.size();
    nlohmann::json pathNodes = nlohmann::json::array();
    for (auto *I : vuln.path) {
      pathNodes.push_back(I->getKindStr().str());
    }
    routeObj["path_nodes"] = pathNodes;

    routeObj["trigger_context"] = getTriggerContext(sourceInst);

    routeObj["destination_url"] = getDestinationURL(sinkInst);

    s2sRoutes.push_back(routeObj);
  }

  masterLog["s2s_routes"] = s2sRoutes;

  std::string jsonFileName = "report/" + prefix_ + "report.json";
  std::ofstream jsonFile(jsonFileName);
  if (jsonFile.is_open()) {
    jsonFile << masterLog.dump(4);
    jsonFile.close();
    log("  [System] Master JSON Log saved to '" + jsonFileName + "'\n");
  } else {
    log("  [Error] Failed to open JSON output file.\n");
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

bool TaintAnalysis::returnsTaintedValue(Function *F) {
  for (auto &BB : *F) {
    for (auto &I : BB) {
      std::string sourceAPI;
      if (isSourceInstruction(&I, sourceAPI)) {
        for (auto *User : I.getUsers()) {
          if (llvh::isa<ReturnInst>(User))
            return true;
          if (llvh::isa<StoreFrameInst>(User)) {
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

bool TaintAnalysis::isTainted(Value *V) {
  if (!V)
    return false;
  return defUseAnalyzer_.isTainted(V);
}

#undef DEBUG_TYPE
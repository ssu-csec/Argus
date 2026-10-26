#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <unordered_map>
#include <cassert>
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
#include <map>
#include <set>
#include <unordered_set>
#include "hermes/IR/Analysis.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Optimizer/Taint/CallGraphAnalyzer.h"
#include "hermes/Optimizer/Taint/TaintAnalysis.h"
#include "hermes/Optimizer/Scalar/SimpleCallGraphProvider.h"
#include "llvh/ADT/ScopeExit.h"
#include "llvh/Support/Debug.h"
#include "llvh/Support/FileSystem.h"
#include "llvh/Support/Path.h"
#include "llvh/Support/raw_ostream.h"


using namespace hermes;
using llvh::dbgs;
using llvh::outs;

namespace {
                                                                     
                                                                           
                                                                                
bool utf8SourceSnippetRange(
    const char *text,
    size_t size,
    size_t columnOffset,
    size_t &start,
    size_t &end) {
  columnOffset = std::min(columnOffset, size);
  start = columnOffset > 120 ? columnOffset - 120 : 0;
  end = start + std::min<size_t>(240, size - start);
  const size_t originalStart = start;
  const size_t originalEnd = end;
  auto continuation = [](unsigned char c) { return (c & 0xC0) == 0x80; };
  while (start > 0 && continuation(static_cast<unsigned char>(text[start]))) {
    if (originalStart - start == 3)
      return false;
    --start;
  }
  while (end < size && continuation(static_cast<unsigned char>(text[end]))) {
    if (end - originalEnd == 3)
      return false;
    ++end;
  }
  for (size_t i = start; i < end;) {
    const unsigned char c = static_cast<unsigned char>(text[i]);
    size_t width;
    if (c < 0x80)
      width = 1;
    else if (c >= 0xC2 && c <= 0xDF)
      width = 2;
    else if (c >= 0xE0 && c <= 0xEF)
      width = 3;
    else if (c >= 0xF0 && c <= 0xF4)
      width = 4;
    else
      return false;
    if (width > end - i)
      return false;
    for (size_t j = 1; j < width; ++j)
      if (!continuation(static_cast<unsigned char>(text[i + j])))
        return false;
    if (width >= 3) {
      const unsigned char second = static_cast<unsigned char>(text[i + 1]);
      if ((c == 0xE0 && second < 0xA0) ||
          (c == 0xED && second >= 0xA0) ||
          (c == 0xF0 && second < 0x90) ||
          (c == 0xF4 && second >= 0x90))
        return false;
    }
    i += width;
  }
  return true;
}

nlohmann::json instructionLocation(Instruction *inst) {
  nlohmann::json result;
  if (!inst || !inst->getLocation().isValid())
    return nullptr;

  Function *function = inst->getParent()->getParent();
  if (!function || !function->getParent())
    return nullptr;

  auto &sourceManager =
      function->getParent()->getContext().getSourceErrorManager();
  SourceErrorManager::SourceCoords coords;
  if (!sourceManager.findBufferLineAndLoc(inst->getLocation(), coords))
    return nullptr;

  result["source_url"] = sourceManager.getSourceUrl(coords.bufId).str();
  result["line"] = coords.line;
  result["column"] = coords.col;
  llvh::StringRef line = sourceManager.getLineRef(coords.bufId, coords.line);
  const size_t columnOffset = std::min<size_t>(
      coords.col > 0 ? coords.col - 1 : 0, line.size());
  size_t snippetStart, snippetEnd;
  if (!utf8SourceSnippetRange(
          line.data(), line.size(), columnOffset, snippetStart, snippetEnd)) {
    std::fprintf(stderr,
                 "ARGUS_REPORT_INVALID_UTF8: source snippet at line %u column %u\n",
                 static_cast<unsigned>(coords.line),
                 static_cast<unsigned>(coords.col));
    std::abort();
  }
  result["snippet"] = line.substr(snippetStart, snippetEnd - snippetStart).str();
  result["snippet_start_column"] = snippetStart + 1;
  return result;
}

std::string instructionFunctionName(Instruction *inst) {
  if (!inst)
    return "UNKNOWN";
  Function *function = inst->getParent()->getParent();
  if (!function)
    return "UNKNOWN";
  std::string name = function->getInternalNameStr().str();
  return name.empty() ? "global" : name;
}

struct FunctionResolution {
  llvh::DenseSet<Function *> targets;
  std::set<std::string> mechanisms;
  bool complete{false};
};

class ConservativeFunctionResolver {
 public:
  explicit ConservativeFunctionResolver(Module *module) : module_(module) {
    for (auto &function : *module_) {
      for (auto &block : function) {
        for (auto &instruction : block) {
          auto *store = llvh::dyn_cast<StorePropertyInst>(&instruction);
          if (!store)
            continue;
          auto *name = llvh::dyn_cast<LiteralString>(store->getProperty());
          if (name) {
            propertyStores_[name->getValue().str().str()].push_back(store);
          } else {
            computedPropertyObjects_.insert(store->getObject());
            if (auto *load =
                    llvh::dyn_cast<LoadFrameInst>(store->getObject())) {
              computedPropertyFrameObjects_.insert(load->getLoadVariable());
            }
          }
        }
      }
    }
  }

  FunctionResolution resolve(Value *value) {
    if (!value)
      return {};
    auto cached = cache_.find(value);
    if (cached != cache_.end())
      return cached->second;
    std::unordered_set<Value *> visiting;
    return resolveImpl(value, visiting, 0);
  }

 private:
  static bool sameStaticObject(Value *lhs, Value *rhs) {
    if (lhs == rhs)
      return true;
    auto *lhsLoad = llvh::dyn_cast<LoadFrameInst>(lhs);
    auto *rhsLoad = llvh::dyn_cast<LoadFrameInst>(rhs);
    return lhsLoad && rhsLoad &&
        lhsLoad->getLoadVariable() == rhsLoad->getLoadVariable() &&
        !lhsLoad->getLoadVariable()->getParent()->isGlobalScope();
  }

  static void mergeInto(
      FunctionResolution &destination,
      const FunctionResolution &source) {
    destination.targets.insert(source.targets.begin(), source.targets.end());
    destination.mechanisms.insert(
        source.mechanisms.begin(), source.mechanisms.end());
  }

  FunctionResolution resolveImpl(
      Value *value,
      std::unordered_set<Value *> &visiting,
      unsigned depth) {
    FunctionResolution result;
    if (!value || depth > 12 || !visiting.insert(value).second)
      return result;

    auto cached = cache_.find(value);
    if (cached != cache_.end()) {
      visiting.erase(value);
      return cached->second;
    }

    auto finish = [&](FunctionResolution resolved) {
      visiting.erase(value);
      cache_[value] = resolved;
      return resolved;
    };

    if (auto *function = llvh::dyn_cast<Function>(value)) {
      result.targets.insert(function);
      result.complete = true;
      return finish(result);
    }

    if (auto *create = llvh::dyn_cast<CreateFunctionInst>(value)) {
      result.targets.insert(create->getFunctionCode());
      result.complete = true;
      return finish(result);
    }

    if (auto *call = llvh::dyn_cast<CallInst>(value)) {
      auto *property = llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
      auto *name = property
          ? llvh::dyn_cast<LiteralString>(property->getProperty())
          : nullptr;
      if (name && (name->getValue().str() == "bind" ||
                   name->getValue().str() == "call" ||
                   name->getValue().str() == "apply")) {
        result = resolveImpl(property->getObject(), visiting, depth + 1);
        if (result.complete)
          result.mechanisms.insert("BOUND_FUNCTION_RESOLUTION");
      }
      return finish(result);
    }

    if (auto *frameLoad = llvh::dyn_cast<LoadFrameInst>(value)) {
      Variable *variable = frameLoad->getLoadVariable();
      bool foundStore = false;
      result.complete = true;
      for (auto *user : variable->getUsers()) {
        if (llvh::isa<LoadFrameInst>(user))
          continue;
        auto *store = llvh::dyn_cast<StoreFrameInst>(user);
        if (!store || store->getVariable() != variable) {
          result.complete = false;
          break;
        }
        foundStore = true;
        FunctionResolution stored =
            resolveImpl(store->getValue(), visiting, depth + 1);
        if (!stored.complete || stored.targets.empty()) {
          result.complete = false;
          break;
        }
        mergeInto(result, stored);
      }
      result.complete = result.complete && foundStore && !result.targets.empty();
      if (result.complete) {
        result.mechanisms.insert(
            variable->getParent()->isGlobalScope()
                ? "GLOBAL_ALIAS_RESOLUTION"
                : "CLOSURE_FRAME_RESOLUTION");
      }
      return finish(result);
    }

    if (auto *phi = llvh::dyn_cast<PhiInst>(value)) {
      result.complete = phi->getNumEntries() > 0;
      for (unsigned index = 0; index < phi->getNumEntries(); ++index) {
        FunctionResolution entry =
            resolveImpl(phi->getEntry(index).first, visiting, depth + 1);
        if (!entry.complete || entry.targets.empty()) {
          result.complete = false;
          break;
        }
        mergeInto(result, entry);
      }
      result.complete = result.complete && !result.targets.empty();
      if (result.complete)
        result.mechanisms.insert("PHI_FUNCTION_RESOLUTION");
      return finish(result);
    }

    if (auto *propertyLoad = llvh::dyn_cast<LoadPropertyInst>(value)) {
      auto *propertyName =
          llvh::dyn_cast<LiteralString>(propertyLoad->getProperty());
      if (!propertyName)
        return finish(result);

      const std::string wanted = propertyName->getValue().str().str();
      bool foundStore = false;
      result.complete = true;
      const bool hasComputedWrite =
          computedPropertyObjects_.count(propertyLoad->getObject()) > 0 ||
          (llvh::isa<LoadFrameInst>(propertyLoad->getObject()) &&
           computedPropertyFrameObjects_.count(
               llvh::cast<LoadFrameInst>(propertyLoad->getObject())
                   ->getLoadVariable()) > 0);
      if (hasComputedWrite)
        result.complete = false;
      auto candidates = propertyStores_.find(wanted);
      if (result.complete && candidates != propertyStores_.end()) {
        for (StorePropertyInst *store : candidates->second) {
          if (!sameStaticObject(
                  store->getObject(), propertyLoad->getObject()))
            continue;
          foundStore = true;
          FunctionResolution stored =
              resolveImpl(store->getStoredValue(), visiting, depth + 1);
          if (!stored.complete || stored.targets.empty()) {
            result.complete = false;
            break;
          }
          mergeInto(result, stored);
        }
      }
      result.complete = result.complete && foundStore && !result.targets.empty();
      if (result.complete) {
        const bool globalProperty =
            llvh::isa<TryLoadGlobalPropertyInst>(propertyLoad) ||
            llvh::isa<GlobalObject>(propertyLoad->getObject()) ||
            llvh::isa<HBCGetGlobalObjectInst>(propertyLoad->getObject());
        result.mechanisms.insert(
            globalProperty ? "GLOBAL_ALIAS_RESOLUTION"
                           : "PROPERTY_CALL_RESOLUTION");
      }
      return finish(result);
    }

    if (auto *parameter = llvh::dyn_cast<Parameter>(value)) {
      if (parameter->isThisParameter())
        return finish(result);
      Function *parent = parameter->getParent();
                                                                           
                                                                               
                                                                              
                               
      for (auto &block : *parent) {
        for (auto &instruction : block) {
          if (llvh::isa<CreateArgumentsInst>(&instruction))
            return finish(result);
        }
      }

      llvh::DenseSet<CallInst *> callSites;
      bool allUsesAreDirectCalls = true;
      for (auto *functionUser : parent->getUsers()) {
        if (auto *site = llvh::dyn_cast<CallInst>(functionUser)) {
          if (site->getCallee() != parent) {
            allUsesAreDirectCalls = false;
            break;
          }
          callSites.insert(site);
          continue;
        }
        auto *create = llvh::dyn_cast<CreateFunctionInst>(functionUser);
        if (!create) {
          allUsesAreDirectCalls = false;
          break;
        }
        for (auto *createdUser : create->getUsers()) {
          auto *site = llvh::dyn_cast<CallInst>(createdUser);
          if (site && site->getCallee() == create) {
            callSites.insert(site);
            continue;
          }
                                                                              
                                                                       
          auto *store = llvh::dyn_cast<StoreFrameInst>(createdUser);
          if (store) {
            bool loaded = false;
            for (auto *variableUser : store->getVariable()->getUsers()) {
              if (llvh::isa<LoadFrameInst>(variableUser)) {
                loaded = true;
                break;
              }
            }
            if (!loaded)
              continue;
          }
          {
            allUsesAreDirectCalls = false;
            break;
          }
        }
        if (!allUsesAreDirectCalls)
          break;
      }
      if (!allUsesAreDirectCalls || callSites.empty())
        return finish(result);

      const int parameterIndex = parameter->getIndexInParamList();
      if (parameterIndex < 0)
        return finish(result);
      result.complete = true;
      for (CallInst *site : callSites) {
        const unsigned argumentIndex =
            static_cast<unsigned>(parameterIndex) + 1;
        if (argumentIndex >= site->getNumArguments()) {
          result.complete = false;
          break;
        }
        FunctionResolution argument =
            resolveImpl(site->getArgument(argumentIndex), visiting, depth + 1);
        if (!argument.complete || argument.targets.empty()) {
          result.complete = false;
          break;
        }
        mergeInto(result, argument);
      }
      result.complete = result.complete && !result.targets.empty();
      if (result.complete)
        result.mechanisms.insert("ARGUMENT_CALLBACK_RESOLUTION");
      return finish(result);
    }

    return finish(result);
  }

  Module *module_;
  llvh::DenseMap<Value *, FunctionResolution> cache_;
  std::map<std::string, std::vector<StorePropertyInst *>> propertyStores_;
  llvh::DenseSet<Value *> computedPropertyObjects_;
  llvh::DenseSet<Variable *> computedPropertyFrameObjects_;
};
}             

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
                                                                          
                                                                
  if(sources.empty()&&sinks.empty()) {
    for(auto &f:*M)for(auto &b:f)for(auto &i:b)if(auto *load=llvh::dyn_cast<LoadPropertyInst>(&i)) {
      auto *key=llvh::dyn_cast<LiteralString>(load->getProperty());
      if(key&&key->getValue().str()=="dynamicModuleGraph") {
        outs()<<"[DYNAMIC_MODULE_TRANSPORT] status=UNKNOWN reason=SOURCE_SINK_REGISTRY_EMPTY completion_eligible=0\n";
        M->getContext().getSourceErrorManager().error(i.getLocation(),"[NATIVE_DYNAMIC_MODULE_TAINT_UNPROVEN] No registry anchor for closed module proof");
        return false;
      }
    }
  }

  log("  Found " + std::to_string(sinks.size()) + " sink(s).\n\n");

  log("[Phase 4] Analyzing function calls...\n");
  CallGraphAnalyzer CGAnalyzer(M);
  CGAnalyzer.analyze(
      &defUseAnalyzer_, [this](const std::string &msg) { log(msg); });

  computeFunctionExecutionContexts(M);

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
                                                                         
                                                                              
  std::unordered_map<std::string, Function *> firstByName;
  uint64_t functions=0, duplicates=0, lookups=0, comparisons=0, shadowComparisons=0;
  uint64_t hits=0, misses=0;
  const auto began=std::chrono::steady_clock::now();
  const bool linear=std::getenv("ARGUS_SOURCE_LINEAR")!=nullptr;
  const bool shadow=std::getenv("ARGUS_SOURCE_VERIFY")!=nullptr;
  for (auto &candidate : *M) {
    ++functions;
    if (!firstByName.emplace(candidate.getInternalNameStr().str(),&candidate).second) ++duplicates;
  }
  auto metrics=[&](const char *phase) {
    const char *path=std::getenv("ARGUS_SOURCE_METRICS");
    if (!path || !*path) return;
    if (FILE *f=std::fopen(path,"w")) {
      std::fprintf(f,"{\"phase\":\"%s\",\"mode\":\"%s\",\"functions\":%llu,\"duplicates\":%llu,\"lookups\":%llu,\"comparisons\":%llu,\"shadow_comparisons\":%llu,\"hits\":%llu,\"misses\":%llu,\"elapsed_ns\":%lld}\n",phase,linear?"linear":"indexed",(unsigned long long)functions,(unsigned long long)duplicates,(unsigned long long)lookups,(unsigned long long)comparisons,(unsigned long long)shadowComparisons,(unsigned long long)hits,(unsigned long long)misses,(long long)std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-began).count());
      std::fclose(f);
    }
  };
  metrics("START");
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

              ++lookups;
              if (linear) {
                for (auto &candidateF : *M) {
                  ++comparisons;
                  if (candidateF.getInternalNameStr() == funcName) {
                    targetFunc=&candidateF; break;
                  }
                }
              } else {
                auto it=firstByName.find(funcName);
                if (it!=firstByName.end()) targetFunc=it->second;
                if (shadow) {
                  Function *expected=nullptr;
                  for (auto &candidateF : *M) {
                    ++shadowComparisons;
                    if (candidateF.getInternalNameStr() == funcName) {expected=&candidateF;break;}
                  }
                  assert(expected==targetFunc && "source index changed first match");
                }
              }
              if (targetFunc) ++hits; else ++misses;
              if ((lookups & 1023)==0) metrics("LOOKUP");
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
  metrics("COMPLETE");
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

void TaintAnalysis::markAsEventDriven(
    Value *V,
    int depth,
    const std::string &mechanism) {
  if (!V || depth > 8)
    return;

  if (auto *CCI = llvh::dyn_cast<CreateFunctionInst>(V)) {
    eventDrivenFunctions_.insert(CCI->getFunctionCode());
    eventRootSources_[CCI->getFunctionCode()].insert(mechanism);
    return;
  }

  if (auto *Call = llvh::dyn_cast<CallInst>(V)) {
    Value *callee = Call->getCallee();
    if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(callee)) {
      if (auto *Lit = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
        std::string method = Lit->getValue().str().str();
        if (method == "bind" || method == "call" || method == "apply") {
          markAsEventDriven(LPI->getObject(), depth + 1, mechanism);
          return;
        }
      }
    }
    if (auto *CCI = llvh::dyn_cast<CreateFunctionInst>(callee)) {
      eventDrivenFunctions_.insert(CCI->getFunctionCode());
      eventRootSources_[CCI->getFunctionCode()].insert(mechanism);
    }
    return;
  }

  if (auto *LFI = llvh::dyn_cast<LoadFrameInst>(V)) {
    Variable *var = LFI->getLoadVariable();
    for (auto *U : var->getUsers()) {
      if (auto *SFI = llvh::dyn_cast<StoreFrameInst>(U)) {
        if (SFI->getVariable() == var) {
          markAsEventDriven(SFI->getValue(), depth + 1, mechanism);
        }
      }
    }
    return;
  }

  if (auto *Phi = llvh::dyn_cast<PhiInst>(V)) {
    for (unsigned i = 0, e = Phi->getNumEntries(); i < e; ++i) {
      markAsEventDriven(Phi->getEntry(i).first, depth + 1, mechanism);
    }
    return;
  }
}

void TaintAnalysis::collectEventDrivenFunctions(Module *M) {
  eventDrivenFunctions_.clear();
  eventRootSources_.clear();
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
                  markAsEventDriven(
                      Call->getArgument(i), 0, "DOM_EVENT_REGISTRATION");
                }
              }
            }
          }
        }

        if (auto *SPI = llvh::dyn_cast<StorePropertyInst>(&I)) {
          if (auto *Lit = llvh::dyn_cast<LiteralString>(SPI->getProperty())) {
            std::string propName = Lit->getValue().str().str();
            if (propName.size() > 2 && propName.rfind("on", 0) == 0) {
              markAsEventDriven(
                  SPI->getStoredValue(), 0, "EVENT_PROPERTY_ASSIGNMENT");
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

void TaintAnalysis::computeFunctionExecutionContexts(Module *M) {
  functionContextBits_.clear();
  autonomousResolutionSources_.clear();
  eventResolutionSources_.clear();
  autonomousContextWitness_.clear();
  eventContextWitness_.clear();
  functionContextDistribution_.clear();

  struct ContextEdge {
    Function *caller;
    Function *callee;
    std::set<std::string> mechanisms;
  };
  std::vector<ContextEdge> callEdges;
  std::set<std::pair<Function *, Function *>> seenEdges;
  auto addEdge = [&](Function *caller,
                     Function *callee,
                     std::set<std::string> mechanisms) {
    if (!caller || !callee)
      return;
    if (mechanisms.empty())
      mechanisms.insert("DIRECT_CALL_RESOLUTION");
    auto key = std::make_pair(caller, callee);
    if (seenEdges.insert(key).second) {
      callEdges.push_back({caller, callee, std::move(mechanisms)});
      return;
    }
    for (auto &edge : callEdges) {
      if (edge.caller == caller && edge.callee == callee) {
        edge.mechanisms.insert(mechanisms.begin(), mechanisms.end());
        return;
      }
    }
  };
  auto functionName = [](Function *function) {
    std::string name = function->getInternalNameStr().str();
    return name.empty() ? std::string("global") : name;
  };
  auto mechanismLabel = [](const std::set<std::string> &mechanisms) {
    std::string result;
    for (const auto &mechanism : mechanisms) {
      if (!result.empty())
        result += "+";
      result += mechanism;
    }
    return result;
  };

  ConservativeFunctionResolver resolver(M);
  auto addResolvedEdge = [&](Function *caller,
                             Value *calleeValue,
                             const std::string &registrationMechanism) {
    FunctionResolution resolution = resolver.resolve(calleeValue);
    if (!resolution.complete)
      return;
    if (!registrationMechanism.empty())
      resolution.mechanisms.insert(registrationMechanism);
    for (Function *callee : resolution.targets)
      addEdge(caller, callee, resolution.mechanisms);
  };
  auto markResolvedEventRoot = [&](Value *callback,
                                   const std::string &mechanism) {
    FunctionResolution resolution = resolver.resolve(callback);
    if (!resolution.complete)
      return;
    for (Function *target : resolution.targets) {
      eventDrivenFunctions_.insert(target);
      eventRootSources_[target].insert(mechanism);
      eventRootSources_[target].insert(
          resolution.mechanisms.begin(), resolution.mechanisms.end());
    }
  };
  auto staticMethodName = [](Value *callee) -> std::string {
    if (auto *function = llvh::dyn_cast<Function>(callee))
      return function->getInternalNameStr().str();
    if (auto *load = llvh::dyn_cast<LoadFrameInst>(callee))
      return load->getLoadVariable()->getName().str().str();
    if (auto *property = llvh::dyn_cast<LoadPropertyInst>(callee)) {
      if (auto *literal =
              llvh::dyn_cast<LiteralString>(property->getProperty()))
        return literal->getValue().str().str();
    }
    return "";
  };
  auto isDirectJQueryReceiver = [&](Value *receiver) {
    auto *call = llvh::dyn_cast<CallInst>(receiver);
    if (!call)
      return false;
    const std::string calleeName = staticMethodName(call->getCallee());
    return calleeName == "$" || calleeName == "jQuery";
  };

  static const std::set<std::string> deferredMethods = {
      "setTimeout",
      "setInterval",
      "requestAnimationFrame",
      "queueMicrotask",
      "then",
      "catch",
      "finally"};
  static const std::set<std::string> observerConstructors = {
      "MutationObserver",
      "IntersectionObserver",
      "PerformanceObserver"};
  static const std::set<std::string> jqueryEventMethods = {
      "on", "click", "submit"};

  for (auto &F : *M) {
    unsigned bits = NoKnownContext;
    std::string name = F.getInternalNameStr().str();
    if (name == "global" || name == "main" || name.empty()) {
      bits |= AutonomousContext;
      autonomousResolutionSources_[&F].insert("AUTONOMOUS_ROOT");
      autonomousContextWitness_[&F] = {
          "AUTONOMOUS_ROOT:" + functionName(&F)};
    }
    if (eventDrivenFunctions_.count(&F) > 0) {
      bits |= EventDrivenContext;
      auto root = eventRootSources_.find(&F);
      if (root != eventRootSources_.end()) {
        eventResolutionSources_[&F].insert(
            root->second.begin(), root->second.end());
      } else {
        eventResolutionSources_[&F].insert("DOM_EVENT_REGISTRATION");
      }
      eventContextWitness_[&F] = {
          "EVENT_ROOT:" + functionName(&F) + "[" +
          mechanismLabel(eventResolutionSources_[&F]) + "]"};
    }
    functionContextBits_[&F] = bits;

    SimpleCallGraphProvider callGraph(&F);
    for (auto &entry : callGraph.callees_) {
      for (Function *callee : entry.second) {
        addEdge(&F, callee, {"DIRECT_CALL_RESOLUTION"});
      }
    }

    for (auto &BB : F) {
      for (auto &I : BB) {
        if (auto *call = llvh::dyn_cast<CallInst>(&I)) {
          FunctionResolution callee = resolver.resolve(call->getCallee());
          if (callee.complete) {
            for (Function *target : callee.targets)
              addEdge(&F, target, callee.mechanisms);
          }

          const std::string method = staticMethodName(call->getCallee());
          auto *property =
              llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
          if (method == "addEventListener" || method == "attachEvent") {
            for (unsigned index = 1; index < call->getNumArguments(); ++index)
              markResolvedEventRoot(
                  call->getArgument(index), "DOM_EVENT_REGISTRATION");
          } else if (
              property && jqueryEventMethods.count(method) &&
              isDirectJQueryReceiver(property->getObject())) {
            for (unsigned index = 1; index < call->getNumArguments(); ++index)
              markResolvedEventRoot(
                  call->getArgument(index), "JQUERY_EVENT_REGISTRATION");
          }

          if (deferredMethods.count(method)) {
            const std::string mechanism =
                method == "setTimeout" || method == "setInterval"
                ? "TIMER_REGISTRATION_PROPAGATION"
                : method == "requestAnimationFrame"
                ? "ANIMATION_FRAME_REGISTRATION_PROPAGATION"
                : method == "then" || method == "catch" ||
                        method == "finally"
                ? "PROMISE_REGISTRATION_PROPAGATION"
                : "MICROTASK_REGISTRATION_PROPAGATION";
            for (unsigned index = 1; index < call->getNumArguments(); ++index)
              addResolvedEdge(
                  &F, call->getArgument(index), mechanism);
          }
          if (property && method == "ready" &&
              isDirectJQueryReceiver(property->getObject())) {
            for (unsigned index = 1; index < call->getNumArguments(); ++index) {
              addResolvedEdge(
                  &F,
                  call->getArgument(index),
                  "DOCUMENT_READY_REGISTRATION_PROPAGATION");
            }
          }
        }

        if (auto *construct = llvh::dyn_cast<ConstructInst>(&I)) {
          const std::string constructor =
              staticMethodName(construct->getCallee());
          if (observerConstructors.count(constructor)) {
            for (unsigned index = 1;
                 index < construct->getNumArguments();
                 ++index) {
              addResolvedEdge(
                  &F,
                  construct->getArgument(index),
                  "OBSERVER_REGISTRATION_PROPAGATION");
            }
          }
        }

        if (auto *store = llvh::dyn_cast<StorePropertyInst>(&I)) {
          auto *literal =
              llvh::dyn_cast<LiteralString>(store->getProperty());
          if (!literal)
            continue;
          const std::string propertyName = literal->getValue().str().str();
          if (propertyName.size() > 2 &&
              propertyName.rfind("on", 0) == 0) {
            markResolvedEventRoot(
                store->getStoredValue(), "EVENT_PROPERTY_ASSIGNMENT");
          }
        }
      }
    }
  }

                                                                       
  for (Function *eventRoot : eventDrivenFunctions_) {
    unsigned oldBits = functionContextBits_.lookup(eventRoot);
    functionContextBits_[eventRoot] = oldBits | EventDrivenContext;
    auto sources = eventRootSources_.find(eventRoot);
    if (sources != eventRootSources_.end()) {
      eventResolutionSources_[eventRoot].insert(
          sources->second.begin(), sources->second.end());
    }
    if (eventContextWitness_.find(eventRoot) == eventContextWitness_.end()) {
      eventContextWitness_[eventRoot] = {
          "EVENT_ROOT:" + functionName(eventRoot) + "[" +
          mechanismLabel(eventResolutionSources_[eventRoot]) + "]"};
    }
  }

  bool changed = true;
  unsigned iterations = 0;
  const unsigned maxIterations =
      static_cast<unsigned>(std::distance(M->begin(), M->end())) * 2 + 1;

  while (changed && iterations++ < maxIterations) {
    changed = false;
    for (const auto &edge : callEdges) {
      Function *caller = edge.caller;
      Function *callee = edge.callee;
      unsigned callerBits = functionContextBits_.lookup(caller);
      if (callerBits == NoKnownContext)
        continue;
      unsigned oldBits = functionContextBits_.lookup(callee);
      unsigned newBits = oldBits | callerBits;
      if (newBits != oldBits) {
        functionContextBits_[callee] = newBits;
        changed = true;
      }
      if (callerBits & AutonomousContext) {
        auto &destination = autonomousResolutionSources_[callee];
        const size_t oldSize = destination.size();
        auto callerSources = autonomousResolutionSources_.find(caller);
        if (callerSources != autonomousResolutionSources_.end()) {
          destination.insert(
              callerSources->second.begin(), callerSources->second.end());
        }
        destination.insert(edge.mechanisms.begin(), edge.mechanisms.end());
        changed |= destination.size() != oldSize;
        auto callerWitness = autonomousContextWitness_.find(caller);
        if (callerWitness != autonomousContextWitness_.end() &&
            !callerWitness->second.empty() &&
            autonomousContextWitness_.find(callee) ==
                autonomousContextWitness_.end()) {
                                                                             
                                                                  
          std::vector<std::string> witness = callerWitness->second;
          witness.push_back(
              functionName(caller) + " --[" +
              mechanismLabel(edge.mechanisms) + "]--> " +
              functionName(callee));
          autonomousContextWitness_[callee] = std::move(witness);
        }
      }
      if (callerBits & EventDrivenContext) {
        auto &destination = eventResolutionSources_[callee];
        const size_t oldSize = destination.size();
        auto callerSources = eventResolutionSources_.find(caller);
        if (callerSources != eventResolutionSources_.end()) {
          destination.insert(
              callerSources->second.begin(), callerSources->second.end());
        }
        destination.insert(edge.mechanisms.begin(), edge.mechanisms.end());
        changed |= destination.size() != oldSize;
        auto callerWitness = eventContextWitness_.find(caller);
        if (callerWitness != eventContextWitness_.end() &&
            !callerWitness->second.empty() &&
            eventContextWitness_.find(callee) ==
                eventContextWitness_.end()) {
                                                                          
          std::vector<std::string> witness = callerWitness->second;
          witness.push_back(
              functionName(caller) + " --[" +
              mechanismLabel(edge.mechanisms) + "]--> " +
              functionName(callee));
          eventContextWitness_[callee] = std::move(witness);
        }
      }
    }
  }

  unsigned autonomous = 0;
  unsigned eventDriven = 0;
  unsigned ambiguous = 0;
  unsigned unknown = 0;
  for (auto &F : *M) {
    switch (functionContextBits_.lookup(&F)) {
      case AutonomousContext:
        ++autonomous;
        ++functionContextDistribution_["AUTONOMOUS"];
        break;
      case EventDrivenContext:
        ++eventDriven;
        ++functionContextDistribution_["EVENT_DRIVEN"];
        break;
      case AutonomousContext | EventDrivenContext:
        ++ambiguous;
        ++functionContextDistribution_["AMBIGUOUS_BOTH_CONTEXTS"];
        break;
      default:
        ++unknown;
        ++functionContextDistribution_["NO_KNOWN_CONTEXT"];
        break;
    }
  }
  log("  [Rule 3] Function execution contexts: AUTONOMOUS=" +
      std::to_string(autonomous) + " EVENT_DRIVEN=" +
      std::to_string(eventDriven) + " AMBIGUOUS=" +
      std::to_string(ambiguous) + " UNKNOWN=" + std::to_string(unknown) +
      "\n");
}

std::string TaintAnalysis::getTriggerContext(Instruction *sinkInst) {
  if (!sinkInst)
    return "UNKNOWN";

  Function *F = sinkInst->getParent()->getParent();
  if (!F)
    return "UNKNOWN";

  switch (functionContextBits_.lookup(F)) {
    case AutonomousContext:
      return "AUTONOMOUS";
    case EventDrivenContext:
      return "EVENT_DRIVEN";
    default:
      return "UNKNOWN";
  }
}

std::string TaintAnalysis::getTriggerContextReason(Instruction *sinkInst) {
  if (!sinkInst)
    return "NO_KNOWN_CONTEXT";
  Function *function = sinkInst->getParent()->getParent();
  if (!function)
    return "NO_KNOWN_CONTEXT";
  switch (functionContextBits_.lookup(function)) {
    case AutonomousContext:
      return "AUTONOMOUS_ROOT_REACHABLE";
    case EventDrivenContext:
      return "EVENT_ROOT_REACHABLE";
    case AutonomousContext | EventDrivenContext:
      return "AMBIGUOUS_BOTH_CONTEXTS";
    default:
      return "NO_KNOWN_CONTEXT";
  }
}

std::set<std::string> TaintAnalysis::getContextResolutionSources(
    Instruction *sinkInst) {
  std::set<std::string> result;
  if (!sinkInst)
    return result;
  Function *function = sinkInst->getParent()->getParent();
  if (!function)
    return result;
  auto autonomous = autonomousResolutionSources_.find(function);
  if (autonomous != autonomousResolutionSources_.end()) {
    result.insert(autonomous->second.begin(), autonomous->second.end());
  }
  auto event = eventResolutionSources_.find(function);
  if (event != eventResolutionSources_.end()) {
    result.insert(event->second.begin(), event->second.end());
  }
  return result;
}

std::vector<std::string> TaintAnalysis::getContextWitness(
    Instruction *sinkInst,
    unsigned contextBit) {
  if (!sinkInst)
    return {};
  Function *function = sinkInst->getParent()->getParent();
  if (!function)
    return {};
  auto &witnesses = contextBit == AutonomousContext
      ? autonomousContextWitness_
      : eventContextWitness_;
  auto witness = witnesses.find(function);
  return witness == witnesses.end() ? std::vector<std::string>{}
                                    : witness->second;
}

std::string TaintAnalysis::getDestinationURL(Instruction *sinkInst) {
  if (!sinkInst)
    return "UNKNOWN";

  std::unordered_set<Value *> visited;

                                                                          
                                                                          
                                                 
  unsigned proofSteps = 0;
  auto reachingStore = [&](LoadFrameInst *load) -> StoreFrameInst * {
    Variable *variable = load->getLoadVariable();
    Function *function = load->getParent()->getParent();
    for (auto *user : variable->getUsers()) {
      if (++proofSteps > 4096)
        return nullptr;
      if (auto *store = llvh::dyn_cast<StoreFrameInst>(user))
        if (store->getParent()->getParent() != function)
          return nullptr;                                                     
    }
    for (auto &block : *function)
      for (auto &instruction : block) {
        if (++proofSteps > 4096 || llvh::isa<DirectEvalInst>(&instruction))
          return nullptr;
      }
    std::unordered_set<BasicBlock *> active;
    std::function<StoreFrameInst *(BasicBlock *, Instruction *)> walk =
        [&](BasicBlock *block, Instruction *before) -> StoreFrameInst * {
      if (++proofSteps > 4096 || active.size() >= 64 ||
          !active.insert(block).second)
        return nullptr;
      auto pop = llvh::make_scope_exit([&] { active.erase(block); });
      bool scan = before == nullptr;
      for (auto it = block->rbegin(), end = block->rend(); it != end; ++it) {
        Instruction *instruction = &*it;
        if (++proofSteps > 4096)
          return nullptr;
        if (!scan) {
          scan = instruction == before;
          continue;
        }
        if (llvh::isa<CatchInst>(instruction))
          return nullptr;                                                    
        if (auto *store = llvh::dyn_cast<StoreFrameInst>(instruction))
          if (store->getVariable() == variable)
            return store;
      }
      StoreFrameInst *common = nullptr;
      bool found = false;
      for (auto *predecessor : predecessors(block)) {
        auto *candidate = walk(predecessor, nullptr);
        if (!candidate || (found && candidate != common))
          return nullptr;
        common = candidate;
        found = true;
      }
      return common;
    };
    return walk(load->getParent(), load);
  };


  std::function<std::string(Value *, int, bool)> extractStringFromValue =
      [&](Value *V, int depth, bool checkedPath) -> std::string {
    if (!V || depth > 8)
      return "";
    if (!visited.insert(V).second)
      return "";
    if (auto *Lit = llvh::dyn_cast<LiteralString>(V)) {
      return Lit->getValue().str().str();
    }

    if (auto *check = llvh::dyn_cast<ThrowIfEmptyInst>(V)) {
                                                                            
                                                                          
                                                                        
      return extractStringFromValue(check->getCheckedValue(), depth, true);
    }

    if (auto *BinOp = llvh::dyn_cast<BinaryOperatorInst>(V)) {
      if (BinOp->getOperatorKind() == BinaryOperatorInst::OpKind::AddKind) {
        std::string lhs =
            extractStringFromValue(BinOp->getLeftHandSide(), depth + 1, checkedPath);
        std::string rhs =
            extractStringFromValue(BinOp->getRightHandSide(), depth + 1, checkedPath);
        if (lhs.empty())
          lhs = "{VAR}";
        if (rhs.empty())
          rhs = "{VAR}";
        return lhs + rhs;
      }
    }

    if (auto *LFI = llvh::dyn_cast<LoadFrameInst>(V)) {
      if (checkedPath) {
        auto *store = reachingStore(LFI);
        return store ? extractStringFromValue(store->getValue(), depth + 1, true)
                     : "";
      }
      Variable *var = LFI->getLoadVariable();
      for (auto *U : var->getUsers()) {
        if (auto *SFI = llvh::dyn_cast<StoreFrameInst>(U)) {
          std::string val = extractStringFromValue(SFI->getValue(), depth + 1, checkedPath);
          if (!val.empty())
            return val;
        }
      }
    }

    if (auto *Phi = llvh::dyn_cast<PhiInst>(V)) {
      if (checkedPath)
        return "";                                                               

      for (unsigned i = 0, e = Phi->getNumEntries(); i < e; ++i) {
        auto pair = Phi->getEntry(i);
        std::string val = extractStringFromValue(pair.first, depth + 1, checkedPath);
        if (!val.empty())
          return val;
      }
    }

    if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(V)) {
      if (checkedPath)
        return "";                                                               

      if (auto *PropName = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
        std::string pname = PropName->getValue().str().str();
        Value *obj = LPI->getObject();
        for (auto *U : obj->getUsers()) {
          if (auto *SPI = llvh::dyn_cast<StorePropertyInst>(U)) {
            if (auto *SPropName =
                    llvh::dyn_cast<LiteralString>(SPI->getProperty())) {
              if (SPropName->getValue().str().str() == pname) {
                std::string val =
                    extractStringFromValue(SPI->getStoredValue(), depth + 1, checkedPath);
                if (!val.empty())
                  return val;
              }
            }
          }
        }
      }
    }

    if (auto *CI = llvh::dyn_cast<CallInst>(V)) {
      if (checkedPath)
        return "";                                                               

      Value *callee = CI->getCallee();

      if (auto *CFI = llvh::dyn_cast<CreateFunctionInst>(callee)) {
        Function *F = CFI->getFunctionCode();
        for (auto &BB : *F) {
          for (auto &I : BB) {
            if (auto *RI = llvh::dyn_cast<ReturnInst>(&I)) {
              std::string val =
                  extractStringFromValue(RI->getValue(), depth + 1, checkedPath);
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
                        extractStringFromValue(RI->getValue(), depth + 1, checkedPath);
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
      std::string val = extractStringFromValue(CI->getArgument(i), 0, false);
      if (!val.empty() &&
          (val.find("http") == 0 || val.find("//") == 0 ||
           val.find("/") == 0)) {
        return val;
      }
    }
  }

  if (auto *SPI = llvh::dyn_cast<StorePropertyInst>(sinkInst)) {
    Value *storedVal = SPI->getStoredValue();
    std::string val = extractStringFromValue(storedVal, 0, false);
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
    masterLog["function_context_distribution"] =
        functionContextDistribution_;
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
  masterLog["function_context_distribution"] = functionContextDistribution_;

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

    routeObj["trigger_context"] = getTriggerContext(sinkInst);
    routeObj["trigger_context_reason"] =
        getTriggerContextReason(sinkInst);
    routeObj["trigger_context_basis"] = "SINK_EXECUTION_CHAIN";
    routeObj["context_resolution_sources"] =
        getContextResolutionSources(sinkInst);
    routeObj["autonomous_context_witness"] =
        getContextWitness(sinkInst, AutonomousContext);
    routeObj["event_context_witness"] =
        getContextWitness(sinkInst, EventDrivenContext);
    routeObj["source_function"] = instructionFunctionName(sourceInst);
    routeObj["sink_function"] = instructionFunctionName(sinkInst);
    routeObj["source_location"] = instructionLocation(sourceInst);
    routeObj["sink_location"] = instructionLocation(sinkInst);

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

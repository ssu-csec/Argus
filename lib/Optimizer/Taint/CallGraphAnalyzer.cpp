#include "hermes/Optimizer/Taint/CallGraphAnalyzer.h"
#include "hermes/Optimizer/Taint/DefUseAnalyzer.h"
#include "llvh/Support/Debug.h"

#define DEBUG_TYPE "taintanalysis"

#include <set>

#include <functional>
#include <unordered_map>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cassert>
#ifndef ARGUS_CG_INDEXED
#define ARGUS_CG_INDEXED 1
#endif


namespace hermes {

void CallGraphAnalyzer::analyze(
    DefUseAnalyzer *defUseAnalyzer,
    std::function<void(const std::string &)> logger) {
  auto log = [&](const std::string &msg) {
    if (logger) {
      logger(msg);
    } else {
      llvh::dbgs() << msg;
    }
  };

  functionCalls_.clear();
                                                                          
                                                                           
  std::unordered_map<std::string, Function *> firstByName;
  std::unordered_map<Function *, uint64_t> functionOrdinal;
  uint64_t functionCount=0, duplicateNames=0;
  const auto passStart=std::chrono::steady_clock::now();
  for (auto &candidateF : *M_) {
    functionOrdinal.emplace(&candidateF, ++functionCount);
    if (!firstByName.emplace(candidateF.getInternalNameStr().str(), &candidateF).second)
      ++duplicateNames;
  }
  uint64_t calls=0, propertyLookups=0, comparisons=0, shadowComparisons=0;
  uint64_t hits=0, misses=0, edges=0, lookupNs=0;
  uint64_t digest=1469598103934665603ULL;
  const char *metricsPath=std::getenv("ARGUS_CALLGRAPH_METRICS");
  const bool verify=std::getenv("ARGUS_CALLGRAPH_VERIFY")!=nullptr;
  auto recordTarget=[&](Function *target) {
    digest ^= calls; digest *= 1099511628211ULL;
    digest ^= target ? functionOrdinal.at(target) : 0; digest *= 1099511628211ULL;
  };
  auto metrics=[&](const char *phase) {
    if (!metricsPath || !*metricsPath) return;
    const auto elapsed=std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now()-passStart).count();
    if (FILE *f=std::fopen(metricsPath,"w")) {
      std::fprintf(f,"{\"mode\":\"%s\",\"phase\":\"%s\",\"functions\":%llu,\"duplicate_names\":%llu,\"calls\":%llu,\"property_lookups\":%llu,\"linear_comparisons\":%llu,\"shadow_comparisons\":%llu,\"hits\":%llu,\"misses\":%llu,\"edges\":%llu,\"lookup_ns\":%llu,\"pass_ns\":%lld,\"target_digest\":\"%llu\"}\n",
        ARGUS_CG_INDEXED?"indexed":"linear",phase,
        (unsigned long long)functionCount,(unsigned long long)duplicateNames,
        (unsigned long long)calls,(unsigned long long)propertyLookups,
        (unsigned long long)comparisons,(unsigned long long)shadowComparisons,
        (unsigned long long)hits,(unsigned long long)misses,(unsigned long long)edges,
        (unsigned long long)lookupNs,(long long)elapsed,(unsigned long long)digest);
      std::fclose(f);
    }
  };
  metrics("START");
  for (auto &F : *M_) {
    for (auto &BB : F) {
      for (auto &I : BB) {
        if (auto *CI = llvh::dyn_cast<CallInst>(&I)) {
          ++calls; if ((calls & 255)==0) metrics("SCANNING");
          Value *callee = CI->getCallee();
          Function *targetFunc = nullptr;
          std::string funcName = "";

          if (auto *func = llvh::dyn_cast<Function>(callee)) {
            targetFunc = func;
            funcName = targetFunc->getInternalNameStr();
          } else if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(callee)) {
            funcName = tryBacktrackPropertyName(LPI);

            if (funcName != "DynamicProperty") {
              ++propertyLookups;
              const auto lookupStart=std::chrono::steady_clock::now();
#if ARGUS_CG_INDEXED
              auto found=firstByName.find(funcName);
              if (found!=firstByName.end()) targetFunc=found->second;
              if (verify) {
                Function *linearTarget=nullptr;
                for (auto &candidateF : *M_) {
                  ++shadowComparisons;
                  if (candidateF.getInternalNameStr()==funcName) {linearTarget=&candidateF;break;}
                }
                assert(linearTarget==targetFunc && "Call graph first-match changed");
              }
#else
              for (auto &candidateF : *M_) {
                ++comparisons;
                if (candidateF.getInternalNameStr() == funcName) {
                  targetFunc = &candidateF;
                  break;
                }
              }
#endif
              lookupNs+=std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now()-lookupStart).count();
              if (targetFunc) ++hits; else ++misses;
            }
          }

          recordTarget(targetFunc);
          if (!targetFunc) {
            bool hasTaintedArg = false;
            for (unsigned i = 0; i < CI->getNumArguments(); ++i) {
              if (defUseAnalyzer &&
                  defUseAnalyzer->isTainted(CI->getArgument(i))) {
                hasTaintedArg = true;
                break;
              }
            }

            if (hasTaintedArg) {
              log("  [!] Critical: Tainted data passed to Unknown/Indirect Call in " +
                  F.getInternalNameStr().str() + " (Evasion Suspected)\n");
            }
            continue;
          }

          if (shouldAnalyzeFunction(targetFunc)) {
            static const std::set<std::string> commonMethods = {
                "add",    "get",    "set",  "push",     "pop",
                "call",   "apply",  "bind", "toString", "hasOwnProperty",
                "slice",  "splice", "map",  "filter",   "forEach",
                "length", "qb",     "sb",   "Fh",       "Wd"};

            if (commonMethods.count(funcName) || funcName.length() <= 2) {
              continue;
            }

            FunctionCallInfo callInfo;
            callInfo.callSite = CI;
            callInfo.targetFunction = targetFunc;
            for (unsigned i = 0; i < CI->getNumArguments(); ++i) {
              Value *arg = CI->getArgument(i);
              callInfo.arguments.push_back(arg);

              callInfo.arguments.push_back(arg);
            }
            functionCalls_.push_back(callInfo);
            ++edges;

            log("  [Inter-procedural] Link created: " +
                F.getInternalNameStr().str() + " -> " + funcName + "\n");
          }
        }
      }
    }
  }
  metrics("COMPLETE");
}

bool CallGraphAnalyzer::shouldAnalyzeFunction(Function *F) {
  if (!F || F->empty())
    return false;
  std::string name = F->getInternalNameStr();
  if (name.empty() || name == "global" ||
      name.find("HermesInternal") != std::string::npos) {
    return false;
  }
  return true;
}

std::string CallGraphAnalyzer::tryBacktrackPropertyName(LoadPropertyInst *LPI) {
  Value *prop = LPI->getProperty();
  if (auto *Lit = llvh::dyn_cast<LiteralString>(prop))
    return Lit->getValue().str().str();

  BasicBlock *BB = LPI->getParent();
  for (auto it = BB->rbegin(); it != BB->rend(); ++it) {
    if (auto *SPI = llvh::dyn_cast<StorePropertyInst>(&*it)) {
      if (SPI->getObject() == prop || SPI->getProperty() == prop) {
        if (auto *valLit = llvh::dyn_cast<LiteralString>(SPI->getStoredValue()))
          return valLit->getValue().str().str();
      }
    }
  }
  return "DynamicProperty";
}

void CallGraphAnalyzer::dump(llvh::raw_ostream &OS) {
  OS << "\n=== [Feature Flow Extraction: Call Graph] ===\n";
  if (functionCalls_.empty()) {
    OS << "  (Graph is empty - no calls detected)\n";
  }
  for (const auto &info : functionCalls_) {
    OS << "Function ["
       << info.callSite->getParent()->getParent()->getInternalNameStr().str()
       << "] calls -> " << info.targetFunction->getInternalNameStr().str()
       << "\n";
  }
  OS << "=============================================\n";
}

}                    

#include "hermes/Optimizer/Taint/CallGraphAnalyzer.h"
#include "hermes/Optimizer/Taint/DefUseAnalyzer.h"
#include "llvh/Support/Debug.h"

#define DEBUG_TYPE "taintanalysis"

#include <set>

#include <functional>

namespace hermes {

void CallGraphAnalyzer::analyze(DefUseAnalyzer *defUseAnalyzer, std::function<void(const std::string&)> logger) {
  auto log = [&](const std::string &msg) {
      if (logger) {
          logger(msg);
      } else {
          llvh::dbgs() << msg;
      }
  };

  functionCalls_.clear();
  for (auto &F : *M_) {
    for (auto &BB : F) {
      for (auto &I : BB) {
        if (auto *CI = llvh::dyn_cast<CallInst>(&I)) {
          Value *callee = CI->getCallee();
          Function *targetFunc = nullptr;
          std::string funcName = "";

          // 1. [Backtracking 도입] 직접 Function이 아닌 경우 속성 추적 강화
          if (auto *func = llvh::dyn_cast<Function>(callee)) {
            targetFunc = func;
            funcName = targetFunc->getInternalNameStr();
          } else if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(callee)) {
            // ★ [개선] 리터럴이 아닐 경우 Backtracking 시도
            // (tryBacktrackPropertyName 호출)
            funcName = tryBacktrackPropertyName(LPI);

            if (funcName != "DynamicProperty") {
              for (auto &candidateF : *M_) {
                if (candidateF.getInternalNameStr() == funcName) {
                  targetFunc = &candidateF;
                  break;
                }
              }
            }
          }

          // 2. [익명/간접 호출 예외 처리] 타겟 함수를 못 찾았을 때 (TypeError
          // 지점)
          if (!targetFunc) {
            bool hasTaintedArg = false;
            for (unsigned i = 0; i < CI->getNumArguments(); ++i) {
              // ★ [핵심] 인자 중 오염된 데이터가 있는지 검사 (isTaintedValue는
              // 기존 로직 활용)
              if (defUseAnalyzer && defUseAnalyzer->isTainted(CI->getArgument(i))) {
                hasTaintedArg = true;
                break;
              }
            }

            if (hasTaintedArg) {
              log("  [!] Critical: Tainted data passed to Unknown/Indirect Call in " +
                  F.getInternalNameStr().str() + " (Evasion Suspected)\n");

              // 이름은 몰라도 오염된 데이터가 흐르므로 추적 리스트에 강제 삽입
              // 시도 가능 (필요 시 특수 플래그를 가진 FunctionCallInfo 생성)
            }
            continue;
          }

          // 3. 기존 필터링 로직 유지 및 강화
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

            log("  [Inter-procedural] Link created: " +
                F.getInternalNameStr().str() + " -> " + funcName + "\n");
          }
        }
      }
    }
  }
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
  if (auto *Lit = llvh::dyn_cast<LiteralString>(prop)) return Lit->getValue().str().str();

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
        OS << "Function [" << info.callSite->getParent()->getParent()->getInternalNameStr().str() 
           << "] calls -> " << info.targetFunction->getInternalNameStr().str() << "\n";
    }
    OS << "=============================================\n";
}

} // namespace hermes 
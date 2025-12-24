#include "hermes/Optimizer/Taint/CallGraphAnalyzer.h"

namespace hermes {

void CallGraphAnalyzer::analyze() {
    for (auto &F : *M_) {
        std::string callerName = F.getInternalName().str();

        for (auto &BB : F) {
            for (auto &I : BB) {
                if (auto *CI = llvh::dyn_cast<CallInst>(&I)) {
                    Value *callee = CI->getCallee();
                    std::string calleeName = "";

                    // Case 1: 직접 함수 호출 (이미 있던 코드)
                    if (auto *func = llvh::dyn_cast<Function>(callee)) {
                        calleeName = func->getInternalName().str();
                    }
                    // Case 2: 프로퍼티 로드 후 호출 (예: global.checkCookie()) ★ 추가됨
                    else if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(callee)) {
                        if (auto *Lit = llvh::dyn_cast<LiteralString>(LPI->getProperty())) {
                            calleeName = Lit->getValue().str().str();
                        }
                    }

                    // 이름 찾았으면 그래프에 추가
                    if (!calleeName.empty()) {
                        callGraph_[callerName].push_back(calleeName);
                    }
                }
            }
        }
    }
}

void CallGraphAnalyzer::dump(llvh::raw_ostream &OS) {
    OS << "\n=== [Feature Flow Extraction: Call Graph] ===\n";
    if (callGraph_.empty()) {
        OS << "  (Graph is empty - no calls detected)\n";
    }
    for (const auto &pair : callGraph_) {
        OS << "Function [" << pair.first << "] calls:\n";
        for (const auto &callee : pair.second) {
            OS << "  -> " << callee << "\n";
        }
    }
    OS << "=============================================\n";
}

} // namespace hermes
// include/hermes/Optimizer/Taint/CallGraphAnalyzer.h
#ifndef HERMES_OPTIMIZER_TAINT_CALLGRAPHANALYZER_H
#define HERMES_OPTIMIZER_TAINT_CALLGRAPHANALYZER_H

#include "hermes/IR/IR.h"
#include "hermes/IR/Instrs.h"
#include "llvh/Support/raw_ostream.h"
#include <map>
#include <vector>
#include <string>

namespace hermes {

class DefUseAnalyzer; // Forward declaration

class CallGraphAnalyzer {
public:
    struct FunctionCallInfo {
        CallInst *callSite;
        Function *targetFunction;
        std::vector<Value *> arguments;
    };

    explicit CallGraphAnalyzer(Module *M) : M_(M) {}

    /// Main analysis entry point.
    /// \param defUseAnalyzer Pointer to DefUseAnalyzer for taint queries
    /// \param logger Callback for logging messages
    void analyze(DefUseAnalyzer *defUseAnalyzer, std::function<void(const std::string&)> logger = nullptr);

    /// Get the results of the analysis
    const std::vector<FunctionCallInfo>& getFunctionCalls() const {
        return functionCalls_;
    }

    /// Try to backtrack property name from a LoadPropertyInst
    static std::string tryBacktrackPropertyName(LoadPropertyInst *LPI);

    void dump(llvh::raw_ostream &OS);

private:
    Module *M_;
    std::vector<FunctionCallInfo> functionCalls_;

    // Internal helpers
    bool shouldAnalyzeFunction(Function *F);
};

} // namespace hermes

#endif
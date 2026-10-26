                                                     
#ifndef HERMES_OPTIMIZER_TAINT_CALLGRAPHANALYZER_H
#define HERMES_OPTIMIZER_TAINT_CALLGRAPHANALYZER_H

#include "hermes/IR/IR.h"
#include "hermes/IR/Instrs.h"
#include "llvh/Support/raw_ostream.h"
#include <map>
#include <vector>
#include <string>

namespace hermes {

class DefUseAnalyzer;                       

class CallGraphAnalyzer {
public:
    struct FunctionCallInfo {
        CallInst *callSite;
        Function *targetFunction;
        std::vector<Value *> arguments;
    };

    explicit CallGraphAnalyzer(Module *M) : M_(M) {}

                                  
                                                                         
                                                   
    void analyze(DefUseAnalyzer *defUseAnalyzer, std::function<void(const std::string&)> logger = nullptr);

                                       
    const std::vector<FunctionCallInfo>& getFunctionCalls() const {
        return functionCalls_;
    }

                                                              
    static std::string tryBacktrackPropertyName(LoadPropertyInst *LPI);

    void dump(llvh::raw_ostream &OS);

private:
    Module *M_;
    std::vector<FunctionCallInfo> functionCalls_;

                       
    bool shouldAnalyzeFunction(Function *F);
};

}                    

#endif
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

class CallGraphAnalyzer {
public:
    explicit CallGraphAnalyzer(Module *M) : M_(M) {}

    void analyze();

    void dump(llvh::raw_ostream &OS);

private:
    Module *M_;
    std::map<std::string, std::vector<std::string>> callGraph_;
};

}

#endif
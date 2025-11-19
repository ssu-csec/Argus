#ifndef HERMES_OPTIMIZER_TAINT_TAINTANALYSIS_H
#define HERMES_OPTIMIZER_TAINT_TAINTANALYSIS_H

#include "hermes/IR/IR.h"
#include "hermes/Optimizer/PassManager/Pass.h"

namespace hermes {

/// Prints the Hermes IR to standard output for debugging and analysis purposes.
/// This pass does not modify the IR and returns false to indicate no changes.
class TaintAnalysis : public ModulePass {
    public:
        explicit TaintAnalysis() : hermes::ModulePass("TaintAnalysis") {}
        ~TaintAnalysis() override = default;

        bool runOnModule(Module *M) override;
};

} // namespace hermes 

#endif
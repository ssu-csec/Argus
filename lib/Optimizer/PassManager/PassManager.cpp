/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Optimizer/PassManager/PassManager.h"

#include "hermes/IR/IR.h"
#include "hermes/Support/Statistic.h"
#include "hermes/Support/Timer.h"
#include "llvh/Support/Debug.h"
#include "llvh/Support/raw_ostream.h"

#include <string>

#define DEBUG_TYPE "passmanager"

namespace hermes {
PassManager::PassManager(const CodeGenerationSettings &settings)
    : cgSettings_(settings) {}

PassManager::~PassManager() = default;

namespace {
                                                                           
bool shouldDump(
    const CodeGenerationSettings::DumpSettings &dumpSettings,
    const Pass &P) {
  return dumpSettings.all || dumpSettings.passes.count(P.getName()) != 0;
}

                                                                            
                             
bool dumpFullModule(const CodeGenerationSettings &cgSettings) {
  return cgSettings.functionsToDump.empty();
}

                                                               
bool shouldDumpFunction(const CodeGenerationSettings &cgSettings, Function *F) {
  return cgSettings.functionsToDump.empty() ||
      cgSettings.functionsToDump.count(F->getOriginalOrInferredName().str()) !=
      0;
}

                                                                              
                                                               
class DumpModule : public ModulePass {
 public:
  DumpModule(
      const CodeGenerationSettings &s,
      llvh::raw_ostream &o,
      std::unique_ptr<ModulePass> p)
      : ModulePass(p->getName()),
        cgSettings_(s),
        outs_(o),
        pass_(std::move(p)) {}

  bool runOnModule(Module *M) override {
    dumpIfEnabled(M, cgSettings_.dumpBefore, "*** BEFORE Module pass");
    bool result = pass_->runOnModule(M);
    dumpIfEnabled(M, cgSettings_.dumpAfter, "*** AFTER Module pass");

    return result;
  }

 private:
  const CodeGenerationSettings &cgSettings_;
  llvh::raw_ostream &outs_;
  std::unique_ptr<ModulePass> pass_;

  void dumpIfEnabled(
      Module *M,
      const CodeGenerationSettings::DumpSettings &settings,
      llvh::StringRef prefix) const {
    if (shouldDump(settings, *pass_)) {
                                                                       
                                                                            
                                                                         
                                                                         
      outs_ << "\n" << prefix << " " << pass_->getName() << "\n\n";
      if (dumpFullModule(cgSettings_)) {
        M->dump(outs_);
      } else {
        for (Function &F : *M) {
          if (shouldDumpFunction(cgSettings_, &F)) {
            F.dump(outs_);
          }
        }
      }
    }
  }
};

                                                                                
                                                               
class DumpFunction : public FunctionPass {
 public:
  DumpFunction(
      const CodeGenerationSettings &s,
      llvh::raw_ostream &o,
      std::unique_ptr<FunctionPass> p)
      : FunctionPass(p->getName()),
        cgSettings_(s),
        outs_(o),
        pass_(std::move(p)) {}

  bool runOnFunction(Function *F) override {
    dumpIfEnabled(F, cgSettings_.dumpBefore, "*** BEFORE Function pass");
    bool result = pass_->runOnFunction(F);
    dumpIfEnabled(F, cgSettings_.dumpAfter, "*** AFTER Function pass");

    return result;
  }

 private:
  const CodeGenerationSettings &cgSettings_;
  llvh::raw_ostream &outs_;
  std::unique_ptr<FunctionPass> pass_;

  void dumpIfEnabled(
      Function *F,
      const CodeGenerationSettings::DumpSettings &dumpSettings,
      llvh::StringRef prefix) const {
    if (shouldDump(dumpSettings, *pass_)) {
      if (shouldDumpFunction(cgSettings_, F)) {
        outs_ << "\n" << prefix << " " << pass_->getName() << "\n\n";
        F->dump(outs_);
      }
    }
  }
};
}             

std::unique_ptr<Pass> PassManager::makeDumpPass(std::unique_ptr<Pass> pass) {
  if (auto *MP = llvh::dyn_cast<ModulePass>(pass.get())) {
    pass.release();
    return std::make_unique<DumpModule>(
        cgSettings_, llvh::dbgs(), std::unique_ptr<ModulePass>{MP});
  } else if (auto *FP = llvh::dyn_cast<FunctionPass>(pass.get())) {
    pass.release();
    return std::make_unique<DumpFunction>(
        cgSettings_, llvh::dbgs(), std::unique_ptr<FunctionPass>{FP});
  } else {
    hermes_fatal("Unhandled pass type");
  }
}

void PassManager::addPass(std::unique_ptr<Pass> P) {
  if (shouldDump(cgSettings_.dumpBefore, *P) ||
      shouldDump(cgSettings_.dumpAfter, *P)) {
    std::unique_ptr<Pass> tmp = makeDumpPass(std::move(P));
    P = std::move(tmp);
  }

  pipeline_.emplace_back(std::move(P));
}

void PassManager::run(Function *F) {
  if (F->isLazy())
    return;

                   
  for (const std::unique_ptr<Pass> &P : pipeline_) {
    auto *FP = llvh::dyn_cast<FunctionPass>(P.get());
    assert(FP && "Invalid pass kind");
    LLVM_DEBUG(llvh::dbgs() << "Running the pass " << FP->getName() << "\n");
    LLVM_DEBUG(
        llvh::dbgs() << "Optimizing the function " << F->getInternalNameStr()
                     << "\n");
    FP->runOnFunction(F);
  }
}

void PassManager::run(Module *M) {
  llvh::SmallVector<Timer, 32> timers;
  std::unique_ptr<TimerGroup> timerGroup{nullptr};
  if (AreStatisticsEnabled()) {
    timerGroup.reset(new TimerGroup("", "PassManager Timers"));
  }

                   
  for (std::unique_ptr<Pass> &P : pipeline_) {
    TimeRegion timeRegion(
        timerGroup ? timers.emplace_back("", P->getName(), *timerGroup),
        &timers.back()
                   : nullptr);

                               
    if (auto *FP = llvh::dyn_cast<FunctionPass>(P.get())) {
      LLVM_DEBUG(
          llvh::dbgs() << "Running the function pass " << FP->getName()
                       << "\n");

      for (auto &I : *M) {
        Function *F = &I;
        if (F->isLazy())
          continue;
        LLVM_DEBUG(
            llvh::dbgs() << "Optimizing the function "
                         << F->getInternalNameStr() << "\n");
        FP->runOnFunction(F);
      }

                               
      continue;
    }

                             
    if (auto *MP = llvh::dyn_cast<ModulePass>(P.get())) {
      LLVM_DEBUG(
          llvh::dbgs() << "Running the module pass " << MP->getName() << "\n");
      MP->runOnModule(M);
                               
      continue;
    }

    llvm_unreachable("Unknown pass kind");
  }
}
}                    

#undef DEBUG_TYPE

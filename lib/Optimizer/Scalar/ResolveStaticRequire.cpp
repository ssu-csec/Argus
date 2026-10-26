/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "resolverequire"
#include "hermes/Optimizer/Scalar/ResolveStaticRequire.h"

#include "hermes/IR/IREval.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Optimizer/Scalar/Utils.h"
#include "hermes/Support/Conversions.h"
#include "hermes/Support/Statistic.h"

#include "llvh/ADT/SmallString.h"
#include "llvh/Support/Debug.h"
#include "llvh/Support/Path.h"

STATISTIC(NumRequireCalls, "Number of require() calls found");
STATISTIC(NumRequireCallsResolved, "Number of require() calls resolved");

namespace hermes {

namespace {

class ResolveStaticRequireImpl {
                                                                           
  Module *const M_;

                                                    
  SourceErrorManager &EM_;

                                        
  IRBuilder builder_;

                                                                         
                 
  bool canResolve_{true};

                                                                     
              
  struct Usage {
                                                       
                                             
                        
                       
                  
                           
    Value *V;

                                        
    Instruction *I;

    Usage(Value *V, Instruction *I) : V(V), I(I) {}
  };

                                
  struct ResolvedRequire {
                                                          
    CallInst *call;
                            
    Literal *resolvedTarget;

    ResolvedRequire(CallInst *call, Literal *resolvedTarget)
        : call(call), resolvedTarget(resolvedTarget) {}
  };

                                                                             
                                          
  std::vector<ResolvedRequire> resolvedRequireCalls_{};

 public:
  ResolveStaticRequireImpl(Module *M)
      : M_(M), EM_(M->getContext().getSourceErrorManager()), builder_{M} {}

  bool run();

 private:
  void resolveCJSModule(Function *moduleFunction);
  void resolveRequireCall(Function *moduleFunction, CallInst *call);

                                                                            
                                                           
                                                                          
                   
                                                                       
                  
                                                                              
                                                                             
  Literal *resolveModuleTarget(
      Function *moduleFunction,
      LiteralString *target,
      SMLoc errorLoc);
};

bool ResolveStaticRequireImpl::run() {
  for (const auto &module : M_->getCJSModules()) {
    resolveCJSModule(module.function);
  }

  if (!canResolve_)
    return false;

                                                                           
  for (const auto &RR : resolvedRequireCalls_) {
    builder_.setInsertionPointAfter(RR.call);

    builder_.setLocation(RR.call->getLocation());
    builder_.setCurrentSourceLevelScope(RR.call->getSourceLevelScope());

                                                   
    auto callHI = builder_.createCallBuiltinInst(
        BuiltinMethod::HermesBuiltin_requireFast, RR.resolvedTarget);

    RR.call->replaceAllUsesWith(callHI);
    RR.call->eraseFromParent();
  }

  M_->setCJSModulesResolved(true);
  return !resolvedRequireCalls_.empty();
}

void ResolveStaticRequireImpl::resolveCJSModule(Function *moduleFunction) {
  assert(
      moduleFunction->getParameters().size() == 3 &&
      "CJS module functions must have three parameters");

  Parameter *requireParam = moduleFunction->getParameters()[1];
  assert(
      requireParam->getName().str() == "require" &&
      "CJS module second parameter must be 'require'");

                          
  llvh::SmallDenseSet<Instruction *> visited{};

                       
  llvh::SmallVector<Usage, 8> workList{};

                                                         
  auto addUsers = [&visited, &workList](Value *value) {
    for (Instruction *I : value->getUsers())
      if (visited.insert(I).second)
        workList.emplace_back(value, I);
  };

                                                                              
                               
  addUsers(requireParam);

  while (!workList.empty()) {
    Usage U = workList.pop_back_val();

    if (auto *call = llvh::dyn_cast<CallInst>(U.I)) {
                                                           
      bool fail = false;
      for (unsigned numArgs = call->getNumArguments(), arg = 0; arg != numArgs;
           ++arg) {
        if (call->getArgument(arg) == U.V) {
                                                    
          EM_.warning(
              Warning::UnresolvedStaticRequire,
              call->getLocation(),
              "'require' used as function call argument");
                                                   
          fail = true;
          canResolve_ = false;
          break;
        }
      }

      if (fail)
        continue;

      if (llvh::isa<ConstructInst>(call) || llvh::isa<HBCConstructInst>(call)) {
        EM_.warning(
            Warning::UnresolvedStaticRequire,
            call->getLocation(),
            "'require' used as a constructor");
        canResolve_ = false;
        continue;
      }

      assert(
          call->getCallee() == U.V && "Value is not used at all in CallInst");

      resolveRequireCall(moduleFunction, call);
    } else if (auto *SS = llvh::dyn_cast<StoreStackInst>(U.I)) {
                                                 

      if (!isStoreOnceStackLocation(cast<AllocStackInst>(SS->getPtr()))) {
        EM_.warning(
            Warning::UnresolvedStaticRequire,
            SS->getLocation(),
            "'require' stored into local cannot be resolved");
        canResolve_ = false;
        continue;
      }

      addUsers(SS->getPtr());
    } else if (auto *LS = llvh::dyn_cast<LoadStackInst>(U.I)) {
                                                 

      addUsers(LS);
    } else if (auto *SF = llvh::dyn_cast<StoreFrameInst>(U.I)) {
                                                 

      if (!isStoreOnceVariable(SF->getVariable())) {
        EM_.warning(
            Warning::UnresolvedStaticRequire,
            SF->getLocation(),
            "'require' is copied to a variable which cannot be analyzed");
        canResolve_ = false;
        continue;
      }

      addUsers(SF->getVariable());
    } else if (auto *LF = llvh::dyn_cast<LoadFrameInst>(U.I)) {
                                                 

      addUsers(LF);
    } else if (auto *LPI = llvh::dyn_cast<LoadPropertyInst>(U.I)) {
      if (LPI->getProperty() == U.V) {
                                                                     
                                                           
        canResolve_ = false;
        EM_.warning(
            Warning::UnresolvedStaticRequire,
            U.I->getLocation(),
            "'require' is used as a property key and cannot be analyzed");
      }
                                                
                                                                     
    } else {
      canResolve_ = false;
      EM_.warning(
          Warning::UnresolvedStaticRequire,
          U.I->getLocation(),
          "'require' escapes or is modified");
    }
  }
}

void ResolveStaticRequireImpl::resolveRequireCall(
    Function *moduleFunction,
    CallInst *call) {
  ++NumRequireCalls;

  if (call->getNumArguments() < 2) {
    EM_.warning(
        Warning::UnresolvedStaticRequire,
        call->getLocation(),
        "require() invoked without arguments");
    canResolve_ = false;
    return;
  }

  if (call->getNumArguments() > 2) {
    EM_.warning(
        Warning::UnresolvedStaticRequire,
        call->getLocation(),
        "Additional require() arguments will be ignored");
  }

  LiteralString *stringTarget = nullptr;
  if (auto *lit = llvh::dyn_cast<Literal>(call->getArgument(1)))
    stringTarget = evalToString(builder_, lit);

  if (!stringTarget) {
    EM_.warning(
        Warning::UnresolvedStaticRequire,
        call->getLocation(),
        "require() argument cannot be coerced to constant string at compile time");
    if (auto *inst = llvh::dyn_cast<Instruction>(call->getArgument(1)))
      if (inst->hasLocation())
        EM_.note(inst->getLocation(), "First argument of require()");

    canResolve_ = false;
    return;
  }

  auto *resolved =
      resolveModuleTarget(moduleFunction, stringTarget, call->getLocation());
  if (!resolved) {
    canResolve_ = false;
    return;
  }

  resolvedRequireCalls_.emplace_back(call, resolved);
  ++NumRequireCallsResolved;
}

                                                                         
               
                                                                          
static void canonicalizePath(
    llvh::SmallVectorImpl<char> &dirname,
    llvh::StringRef target) {
  if (!target.empty() && target[0] == '/') {
                                                                             
                                    
    dirname.clear();
    llvh::sys::path::append(dirname, target.drop_front(1));
    return;
  }
  llvh::sys::path::append(dirname, llvh::sys::path::Style::posix, target);

                                                                           
  llvh::sys::path::remove_dots(dirname, true, llvh::sys::path::Style::posix);
}

Literal *ResolveStaticRequireImpl::resolveModuleTarget(
    Function *moduleFunction,
    LiteralString *target,
    SMLoc errorLoc) {
  IRBuilder builder{moduleFunction->getParent()};

  Module *module = moduleFunction->getParent();
  auto *cjsModule = module->findCJSModule(moduleFunction);
  assert(cjsModule && "Cannot run require() from a non-module function");

  Identifier targetIdentifier{};
  assert(
      !targetIdentifier.isValid() &&
      "Uninitialized identifier must be invalid");

                                                                        
  const auto *resolutionTable =
      moduleFunction->getContext().getResolutionTable();
  if (resolutionTable) {
    LLVM_DEBUG(
        llvh::errs() << "Resolving " << cjsModule->filename.str() << " @ "
                     << target->getValue().str() << '\n');
    auto fileEntry = resolutionTable->find(cjsModule->filename.str());
    if (fileEntry != resolutionTable->end()) {
      auto targetEntry = fileEntry->second.find(target->getValue().str());
      if (targetEntry != fileEntry->second.end()) {
        targetIdentifier = builder.createIdentifier(targetEntry->second);
      }
    }
  }

                                                                         
                                      
  if (!targetIdentifier.isValid()) {
                                                          
    llvh::SmallString<32> canonicalPath = cjsModule->filename.str();
    llvh::sys::path::remove_filename(
        canonicalPath, llvh::sys::path::Style::posix);

                                                                            
    canonicalizePath(canonicalPath, target->getValue().str());
    targetIdentifier = builder.createIdentifier(canonicalPath);
  }

  assert(
      targetIdentifier.isValid() && "Failed to construct valid target string");

  auto targetModuleID = module->findCJSModuleID(targetIdentifier);
  if (!targetModuleID) {
    EM_.warning(
        Warning::UnresolvedStaticRequire,
        errorLoc,
        "Cannot resolve target module of require");
    return nullptr;
  }
  return builder.getLiteralNumber(*targetModuleID);
}

}                       

bool ResolveStaticRequire::runOnModule(Module *M) {
  if (!M->getContext().getUseCJSModules() ||
      !M->getContext().getOptimizationSettings().staticRequire) {
    return false;
  }

  SourceErrorManager::SaveAndBufferMessages bm{
      &M->getContext().getSourceErrorManager()};
  ResolveStaticRequireImpl impl{M};
  return impl.run();
}

std::unique_ptr<Pass> createResolveStaticRequire() {
  return std::make_unique<ResolveStaticRequire>();
}

}                    

#undef DEBUG_TYPE

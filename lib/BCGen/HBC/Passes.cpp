/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/BCGen/HBC/Passes.h"

#include "hermes/BCGen/BCOpt.h"
#include "hermes/BCGen/HBC/BytecodeGenerator.h"
#include "hermes/BCGen/HBC/BytecodeStream.h"
#include "hermes/BCGen/HBC/HBC.h"
#include "hermes/BCGen/HBC/ISel.h"
#include "hermes/BCGen/Lowering.h"

#include "llvh/ADT/SetVector.h"

#define DEBUG_TYPE "hbc-backend"

namespace hermes {
namespace hbc {

namespace {
                                                                               
                       
void updateIncomingPhiValues(
    BasicBlock *blockToFix,
    BasicBlock *previousBlock,
    BasicBlock *newBlock) {
  for (auto &inst : *blockToFix) {
    auto *phi = llvh::dyn_cast<PhiInst>(&inst);
    if (!phi)
      return;

    for (int i = 0, e = phi->getNumEntries(); i < e; i++) {
      auto entry = phi->getEntry(i);
      if (entry.second == previousBlock) {
        phi->updateEntry(i, entry.first, newBlock);
      }
    }
  }
}
                                                                          
             
llvh::SmallVector<Instruction *, 4> getInsertionPointsAfter(
    IRBuilder &builder,
    Instruction *inst) {
  llvh::SmallVector<Instruction *, 4> points;

  if (!llvh::isa<TerminatorInst>(inst)) {
                                                                
    auto pos = inst->getIterator();
    pos++;
    points.push_back(&*pos);
    return points;
  }

  for (int i = 0, e = inst->getNumOperands(); i < e; i++) {
    BasicBlock *target = llvh::dyn_cast<BasicBlock>(inst->getOperand(i));
    if (!target)
      continue;

    auto *detour = builder.createBasicBlock(target->getParent());
    builder.setInsertionBlock(detour);
    auto *bounce = builder.createBranchInst(target);
    inst->setOperand(detour, i);
    updateIncomingPhiValues(target, inst->getParent(), detour);
    points.push_back(bounce);
  }
  return points;
}

                                                                            
                                                                                
                     
void updateToEntryInsertionPoint(IRBuilder &builder, Function *F) {
  auto &BB = F->front();
  auto it = BB.begin();
  auto end = BB.end();
                                       
  while (it != end && llvh::isa<HBCCreateEnvironmentInst>(*it))
    ++it;

  builder.setInsertionPoint(&*it);
}

}             

bool LoadConstants::operandMustBeLiteral(Instruction *Inst, unsigned opIndex) {
                                                 
  if (llvh::isa<HBCLoadConstInst>(Inst))
    return true;

                                                        
  if (llvh::isa<HBCLoadParamInst>(Inst))
    return true;

  if (llvh::isa<HBCAllocObjectFromBufferInst>(Inst))
    return true;

                                                 
  if (llvh::isa<AllocArrayInst>(Inst))
    return true;

  if (llvh::isa<AllocObjectInst>(Inst)) {
                                                 
    if (opIndex == AllocObjectInst::SizeIdx)
      return true;
                                                                                
    if (opIndex == AllocObjectInst::ParentObjectIdx &&
        llvh::isa<EmptySentinel>(Inst->getOperand(opIndex)))
      return true;

    return false;
  }

                                                       
                                      
  if (llvh::isa<SwitchInst>(Inst) && opIndex > 0)
    return true;

                                                      
  if (auto *SOP = llvh::dyn_cast<StoreOwnPropertyInst>(Inst)) {
    if (opIndex == StoreOwnPropertyInst::PropertyIdx) {
      if (llvh::isa<StoreNewOwnPropertyInst>(Inst)) {
                                                                          
        return true;
      }

                                                                              
                                                                              
                                       
      if (auto *LN = llvh::dyn_cast<LiteralNumber>(Inst->getOperand(opIndex))) {
        if (SOP->getIsEnumerable() && LN->convertToArrayIndex().hasValue())
          return true;
      }
    }

                                                                 
    if (opIndex == StoreOwnPropertyInst::IsEnumerableIdx)
      return true;

    return false;
  }

                                                                           
                                                 
  if (llvh::isa<StorePropertyInst>(Inst) &&
      opIndex == StorePropertyInst::PropertyIdx &&
      llvh::isa<LiteralString>(Inst->getOperand(opIndex)))
    return true;

                                                                          
                                                 
  if (llvh::isa<LoadPropertyInst>(Inst) &&
      opIndex == LoadPropertyInst::PropertyIdx &&
      llvh::isa<LiteralString>(Inst->getOperand(opIndex)))
    return true;

                                                                            
                                                 
  if (llvh::isa<DeletePropertyInst>(Inst) &&
      opIndex == DeletePropertyInst::PropertyIdx &&
      llvh::isa<LiteralString>(Inst->getOperand(opIndex)))
    return true;

                                                                
  if (llvh::isa<StoreGetterSetterInst>(Inst) &&
      opIndex == StoreGetterSetterInst::IsEnumerableIdx)
    return true;

                                                            
                         
  if (llvh::isa<CreateRegExpInst>(Inst))
    return true;

  if (llvh::isa<SwitchImmInst>(Inst) &&
      (opIndex == SwitchImmInst::MinValueIdx ||
       opIndex == SwitchImmInst::SizeIdx ||
       opIndex >= SwitchImmInst::FirstCaseIdx))
    return true;

                                                                
  if (llvh::isa<CallBuiltinInst>(Inst) &&
      (opIndex == CallBuiltinInst::CalleeIdx ||
       opIndex == CallBuiltinInst::ThisIdx))
    return true;

                                                                             
                                                                                
                         
  if (llvh::isa<CallInst>(Inst) && opIndex == CallInst::NewTargetIdx)
    return true;

                                                              
  if (llvh::isa<GetBuiltinClosureInst>(Inst) &&
      opIndex == GetBuiltinClosureInst::BuiltinIndexIdx)
    return true;

#ifdef HERMES_RUN_WASM
                                                                  
  if (llvh::isa<CallIntrinsicInst>(Inst) &&
      (opIndex == CallIntrinsicInst::IntrinsicIndexIdx))
    return true;
#endif

  if (llvh::isa<IteratorCloseInst>(Inst) &&
      opIndex == IteratorCloseInst::IgnoreInnerExceptionIdx) {
    return true;
  }

  if (llvh::isa<ThrowIfHasRestrictedGlobalPropertyInst>(Inst) &&
      opIndex == ThrowIfHasRestrictedGlobalPropertyInst::PropertyIdx) {
    return true;
  }
                                                     
  if (llvh::isa<DirectEvalInst>(Inst) &&
      opIndex == DirectEvalInst::IsStrictIdx) {
    return true;
  }

  return false;
}

bool LoadConstants::runOnFunction(Function *F) {
  IRBuilder builder(F);
  bool changed = false;

                                                                            
  auto createLoadLiteral = [&builder](Literal *literal, Instruction *where) {
    builder.setInsertionPoint(where);
    return llvh::isa<GlobalObject>(literal)
        ? cast<Instruction>(builder.createHBCGetGlobalObjectInst())
        : cast<Instruction>(builder.createHBCLoadConstInst(literal));
  };

  for (BasicBlock &BB : *F) {
    for (auto &I : BB) {
      if (auto *phi = llvh::dyn_cast<PhiInst>(&I)) {
                                                                               
                                                                              
                                                                             
                                                                          
        for (unsigned i = 0, e = phi->getNumEntries(); i < e; ++i) {
          auto [val, bb] = phi->getEntry(i);
          if (auto *literal = llvh::dyn_cast<Literal>(val)) {
            auto *load = createLoadLiteral(literal, bb->getTerminator());
            phi->updateEntry(i, load, bb);
            changed = true;
          }
        }
        continue;
      }
                                                                                
                                                                          
                                                                              
              
      for (unsigned i = 0, e = I.getNumOperands(); i < e; ++i) {
        if (auto *literal = llvh::dyn_cast<Literal>(I.getOperand(i))) {
          if (!operandMustBeLiteral(&I, i)) {
            auto *load = createLoadLiteral(literal, &I);
            I.setOperand(load, i);
            changed = true;
          }
        }
      }
    }
  }
  return changed;
}

bool LoadParameters::runOnFunction(Function *F) {
  IRBuilder builder(F);
  bool changed = false;

  updateToEntryInsertionPoint(builder, F);

                                        
  unsigned index = 1;
  for (Parameter *p : F->getParameters()) {
    auto *load =
        builder.createHBCLoadParamInst(builder.getLiteralNumber(index));
    p->replaceAllUsesWith(load);
    index++;
    changed = true;
  }

                              
  auto *thisParam = F->getThisParameter();
  if (thisParam && thisParam->hasUsers()) {
                                                                              
                       
    Value *getThisInst = F->isStrictMode()
        ? cast<Value>(
              builder.createHBCLoadParamInst(builder.getLiteralNumber(0)))
        : cast<Value>(builder.createHBCGetThisNSInst());
    thisParam->replaceAllUsesWith(getThisInst);
    changed = true;
  }
  return changed;
}

ScopeCreationInst *LowerLoadStoreFrameInst::getScope(
    IRBuilder &builder,
    Variable *var,
    ScopeCreationInst *environment) {
  if (var->getParent() == environment->getCreatedScopeDesc()) {
                                                   
    assert(
        var->getParent()->getFunction() == builder.getFunction() &&
        "Scope should only be found if var is not captured from another "
        "function");
    return environment;
  }

  auto *environmentWithParent =
      llvh::dyn_cast<NestedScopeCreationInst>(environment);
  if (!environmentWithParent) {
                                                                                
                                                           
    assert(
        var->getParent()->getFunction() != builder.getFunction() &&
        "Failed to find scope in current function for local variable.");
    return builder.createHBCResolveEnvironment(
        environment->getCreatedScopeDesc(), var->getParent());
  }

                  
  return getScope(builder, var, environmentWithParent->getParentScope());
}

bool LowerLoadStoreFrameInst::runOnFunction(Function *F) {
  IRBuilder builder(F);
  bool changed = false;

  bool fnScopeCreated = false;
  for (BasicBlock &BB : F->getBasicBlockList()) {
    for (auto I = BB.begin(), E = BB.end(); I != E;              ) {
      Instruction *Inst = &*I;
      ++I;
      if (auto *csi = llvh::dyn_cast<CreateScopeInst>(Inst)) {
        fnScopeCreated |=
            csi->getCreatedScopeDesc() == F->getFunctionScopeDesc();
        builder.setInsertionPoint(csi);
        Instruction *llInst =
            builder.createHBCCreateEnvironmentInst(csi->getCreatedScopeDesc());
        Inst->replaceAllUsesWith(llInst);
        Inst->eraseFromParent();
        changed = true;
      } else if (auto cisi = llvh::dyn_cast<CreateInnerScopeInst>(Inst)) {
        builder.setInsertionPoint(cisi);
        assert(
            llvh::isa<HBCCreateEnvironmentInst>(cisi->getParentScope()) ||
            llvh::isa<HBCCreateInnerEnvironmentInst>(cisi->getParentScope()));

        Instruction *llInst = builder.createHBCCreateInnerEnvironmentInst(
            cisi->getParentScope(), cisi->getCreatedScopeDesc());
        Inst->replaceAllUsesWith(llInst);
        Inst->eraseFromParent();
        changed = true;
      }
    }
  }

                                                                            
                                                                                
                                                                             
                                                                                
                                                                               
  assert(fnScopeCreated && "Function body scope not materialized.");
  (void)fnScopeCreated;

  for (BasicBlock &BB : F->getBasicBlockList()) {
    for (auto I = BB.begin(), E = BB.end(); I != E;              ) {
                                                         
      Instruction *Inst = &*I;
      ++I;

      builder.setLocation(Inst->getLocation());
      builder.setCurrentSourceLevelScope(Inst->getSourceLevelScope());

      switch (Inst->getKind()) {
        case ValueKind::LoadFrameInstKind: {
          auto *LFI = cast<LoadFrameInst>(Inst);
          auto *var = LFI->getLoadVariable();
          auto *environment = LFI->getEnvironment();

          builder.setInsertionPoint(Inst);
          ScopeCreationInst *scope = getScope(builder, var, environment);
          Instruction *newInst =
              builder.createHBCLoadFromEnvironmentInst(scope, var);

          Inst->replaceAllUsesWith(newInst);
          Inst->eraseFromParent();
          changed = true;
          break;
        }
        case ValueKind::StoreFrameInstKind: {
          auto *SFI = cast<StoreFrameInst>(Inst);
          auto *var = SFI->getVariable();
          auto *val = SFI->getValue();
          auto *environment = SFI->getEnvironment();

          builder.setInsertionPoint(Inst);
          ScopeCreationInst *scope = getScope(builder, var, environment);
          builder.createHBCStoreToEnvironmentInst(scope, val, var);

          Inst->eraseFromParent();
          changed = true;
          break;
        }
        case ValueKind::CreateFunctionInstKind: {
          auto *CFI = cast<CreateFunctionInst>(Inst);
          auto *environment = CFI->getEnvironment();

          builder.setInsertionPoint(Inst);
          auto *newInst = builder.createHBCCreateFunctionInst(
              CFI->getFunctionCode(), environment);

          Inst->replaceAllUsesWith(newInst);
          Inst->eraseFromParent();
          changed = true;
          break;
        }
        case ValueKind::CreateGeneratorInstKind: {
          auto *CFI = cast<CreateGeneratorInst>(Inst);
          auto *environment = CFI->getEnvironment();

          builder.setInsertionPoint(Inst);
          auto *newInst = builder.createHBCCreateGeneratorInst(
              CFI->getFunctionCode(), environment);

          Inst->replaceAllUsesWith(newInst);
          Inst->eraseFromParent();
          changed = true;
          break;
        }
        default:
          break;
      }
    }
  }
  return changed;
}

CreateArgumentsInst *LowerArgumentsArray::getCreateArgumentsInst(Function *F) {
                                                                          
                                                           
  if (llvh::isa<GeneratorInnerFunction>(F)) {
    for (BasicBlock *succ : F->front().getTerminator()->successors()) {
      for (auto &inst : *succ) {
        if (auto *target = llvh::dyn_cast<CreateArgumentsInst>(&inst)) {
          return target;
        }
      }
    }
  } else {
    for (auto &inst : F->front()) {
      if (auto *target = llvh::dyn_cast<CreateArgumentsInst>(&inst)) {
        return target;
      }
    }
  }
  return nullptr;
}

bool LowerArgumentsArray::runOnFunction(Function *F) {
  IRBuilder builder(F);
  updateToEntryInsertionPoint(builder, F);

  CreateArgumentsInst *createArguments = getCreateArgumentsInst(F);
  if (!createArguments) {
    return false;
  }

  builder.setInsertionPoint(createArguments);
  AllocStackInst *lazyReg = builder.createAllocStackInst("arguments");
  builder.createStoreStackInst(builder.getLiteralUndefined(), lazyReg);

                                                                           
                                             
                                                                   
                                                                             
                                                       
  llvh::SmallSetVector<Instruction *, 16> uniqueUsers;
  uniqueUsers.insert(
      createArguments->getUsers().begin(), createArguments->getUsers().end());
  for (Value *user : uniqueUsers) {
    auto *load = llvh::dyn_cast<LoadPropertyInst>(user);
    if (load && load->getObject() == createArguments) {
      builder.setInsertionPoint(load);
      builder.setLocation(load->getLocation());
      builder.setCurrentSourceLevelScope(load->getSourceLevelScope());
      auto *propertyString = llvh::dyn_cast<LiteralString>(load->getProperty());
      if (propertyString && propertyString->getValue().str() == "length") {
                                                  
        auto *length = builder.createHBCGetArgumentsLengthInst(lazyReg);
        load->replaceAllUsesWith(length);
        load->eraseFromParent();
      } else {
                                                      
        auto *get = builder.createHBCGetArgumentsPropByValInst(
            load->getProperty(), lazyReg);
        load->replaceAllUsesWith(get);
        load->eraseFromParent();
      }
    }
  }

  uniqueUsers.clear();
  uniqueUsers.insert(
      createArguments->getUsers().begin(), createArguments->getUsers().end());
  for (Value *user : uniqueUsers) {
    if (auto *phi = llvh::dyn_cast<PhiInst>(user)) {
                                                                       
      for (int i = 0, n = phi->getNumEntries(); i < n; i++) {
        auto entry = phi->getEntry(i);
        if (entry.first != createArguments)
          continue;

        auto *previousBlock = cast<BasicBlock>(entry.second);
        auto *thisBlock = phi->getParent();

        auto *newBlock = builder.createBasicBlock(F);
        builder.setInsertionBlock(newBlock);
        builder.createHBCReifyArgumentsInst(lazyReg);
        auto *reifiedValue = builder.createLoadStackInst(lazyReg);
        builder.createBranchInst(thisBlock);

        phi->updateEntry(i, reifiedValue, newBlock);
                                                                           
                                                            
        updateIncomingPhiValues(thisBlock, previousBlock, newBlock);

        auto *branch = previousBlock->getTerminator();
        for (int j = 0, m = branch->getNumOperands(); j < m; j++)
          if (branch->getOperand(j) == thisBlock)
            branch->setOperand(newBlock, j);
      }
    } else if (auto *inst = llvh::dyn_cast<Instruction>(user)) {
                                                                
                                   
      builder.setInsertionPoint(inst);
      builder.setLocation(inst->getLocation());
      builder.setCurrentSourceLevelScope(inst->getSourceLevelScope());
      builder.createHBCReifyArgumentsInst(lazyReg);
      auto *array = builder.createLoadStackInst(lazyReg);
      for (int i = 0, n = inst->getNumOperands(); i < n; i++) {
        if (inst->getOperand(i) == createArguments) {
          inst->setOperand(array, i);
        }
      }
    } else {
      hermes_fatal("CreateArguments used for a non-Instruction.");
    }
  }

  createArguments->eraseFromParent();
  return true;
}

bool DedupReifyArguments::runOnFunction(Function *F) {
  bool changed = false;

                                                                        
                                                                            
  bool hasRAI = false;
  for (auto &BB : *F) {
    for (auto &inst : BB.getInstList()) {
      if (llvh::isa<HBCReifyArgumentsInst>(&inst)) {
        hasRAI = true;
        break;
      }
    }
    if (hasRAI)
      break;
  }

  if (!hasRAI)
    return false;

  DominanceInfo domInfo{F};
  PostOrderAnalysis PO(F);
  IRBuilder::InstructionDestroyer destroyer;

  llvh::SmallVector<BasicBlock *, 16> reversePO(PO.rbegin(), PO.rend());
  llvh::SmallVector<HBCReifyArgumentsInst *, 4> reifications;

  for (auto *BB : reversePO) {
    for (auto &inst : BB->getInstList()) {
      if (auto *reify = llvh::dyn_cast<HBCReifyArgumentsInst>(&inst)) {
        HBCReifyArgumentsInst *dominator = nullptr;
        for (auto *possibleParent : reifications) {
          if (domInfo.properlyDominates(possibleParent, reify)) {
            dominator = possibleParent;
            break;
          }
        }

        if (dominator) {
          destroyer.add(reify);
          changed = true;
        } else {
          reifications.push_back(reify);
        }
      }
    }
  }
  return changed;
}

bool LowerConstruction::runOnFunction(Function *F) {
  IRBuilder builder(F);

  for (BasicBlock &BB : F->getBasicBlockList()) {
    IRBuilder::InstructionDestroyer destroyer;
    for (Instruction &I : BB) {
      if (auto *constructor = llvh::dyn_cast<ConstructInst>(&I)) {
        builder.setInsertionPoint(constructor);
        builder.setLocation(constructor->getLocation());
        builder.setCurrentSourceLevelScope(constructor->getSourceLevelScope());
        auto closure = constructor->getCallee();
                                                                              
        auto thisObject = builder.createHBCCreateThisInst(
            constructor->getNewTarget(), closure);

        llvh::SmallVector<Value *, 8> args;
        for (int i = 1, n = constructor->getNumArguments(); i < n; i++) {
          args.push_back(constructor->getArgument(i));
        }
        auto newConstructor = builder.createHBCConstructInst(
            closure, constructor->getNewTarget(), thisObject, args);
        auto finalValue = builder.createHBCGetConstructedObjectInst(
            thisObject, newConstructor);
        constructor->replaceAllUsesWith(finalValue);
        destroyer.add(constructor);
      }
    }
  }
  return true;
}

bool LowerCalls::runOnFunction(Function *F) {
  IRBuilder builder(F);
  bool changed = false;

  for (auto &BB : *F) {
    for (auto &I : BB) {
      auto *call = llvh::dyn_cast<CallInst>(&I);
                                        
      if (!call)
        continue;
      builder.setInsertionPoint(call);
      changed = true;

      auto reg = RA_.getLastRegister().getIndex() -
          HVMRegisterAllocator::CALL_EXTRA_REGISTERS;

      for (int i = 0, e = call->getNumArguments(); i < e; i++, --reg) {
                                                                            
                                                                       
                                                                                
                                                    
                                                                               
                                                                          
        Value *arg = call->getArgument(i);
        if (llvh::isa<HBCCallNInst>(call) ||
            (i == 0 && llvh::isa<CallBuiltinInst>(call))) {
          auto *imov = builder.createImplicitMovInst(arg);
          RA_.updateRegister(imov, Register(reg));
        } else {
          auto *mov = builder.createMovInst(arg);
          RA_.updateRegister(mov, Register(reg));
          call->setArgument(mov, i);
        }
      }
    }
  }
  return changed;
}

bool RecreateCheapValues::runOnFunction(Function *F) {
  IRBuilder builder(F);
  llvh::SmallPtrSet<Instruction *, 4> potentiallyUnused;
  bool changed = false;

  for (auto &BB : *F) {
    IRBuilder::InstructionDestroyer destroyer;
    for (auto &I : BB) {
      auto *mov = llvh::dyn_cast<MovInst>(&I);
      if (!mov)
        continue;
      auto *load = llvh::dyn_cast<HBCLoadConstInst>(mov->getSingleOperand());
      if (!load)
        continue;
      Literal *literal = load->getConst();

      switch (literal->getKind()) {
        case ValueKind::LiteralUndefinedKind:
        case ValueKind::LiteralNullKind:
        case ValueKind::LiteralBoolKind:
          break;
        case ValueKind::LiteralNumberKind:
          if (cast<LiteralNumber>(literal)->isPositiveZero()) {
            break;
          }
          continue;
        default:
          continue;
      }

      builder.setInsertionPoint(mov);
      auto *recreation = builder.createHBCLoadConstInst(literal);
      RA_.updateRegister(recreation, RA_.getRegister(mov));
      mov->replaceAllUsesWith(recreation);
      destroyer.add(mov);
      potentiallyUnused.insert(load);
      changed = true;
    }
  }

  {
    IRBuilder::InstructionDestroyer destroyer;
    for (auto *inst : potentiallyUnused) {
      if (!inst->hasUsers()) {
        destroyer.add(inst);
      }
    }
  }
  return changed;
}

bool LoadConstantValueNumbering::runOnFunction(Function *F) {
  IRBuilder builder(F);
  bool changed = false;

  for (auto &BB : *F) {
    IRBuilder::InstructionDestroyer destroyer;
                                                                       
                                                                     
                                    
    llvh::DenseMap<unsigned, Instruction *> regToInstMap{};
    for (auto &I : BB) {
      HBCLoadConstInst *loadI{nullptr};
                                                                           
                                                                            
      if (!(loadI = llvh::dyn_cast<HBCLoadConstInst>(&I))) {
        if (auto *movI = llvh::dyn_cast<MovInst>(&I)) {
          loadI = llvh::dyn_cast<HBCLoadConstInst>(movI->getSingleOperand());
        }
      }

      if (RA_.isAllocated(&I)) {
        unsigned reg = RA_.getRegister(&I).getIndex();
        if (loadI) {
          auto it = regToInstMap.find(reg);
          if (it != regToInstMap.end()) {
            auto prevI = it->second;
            HBCLoadConstInst *prevLoad{nullptr};
                                                                     
                                                                               
            if (!(prevLoad = llvh::dyn_cast<HBCLoadConstInst>(prevI))) {
              prevLoad = llvh::dyn_cast<HBCLoadConstInst>(prevI->getOperand(0));
            }
            if (prevLoad->isIdenticalTo(loadI)) {
              I.replaceAllUsesWith(prevI);
              destroyer.add(&I);
              changed = true;
              continue;
            }
          }
          regToInstMap[reg] = &I;
          continue;
        }
        regToInstMap.erase(reg);
      }

      for (auto index : I.getChangedOperands()) {
        auto *operand = I.getOperand(index);
        unsigned reg = RA_.getRegister(cast<Instruction>(operand)).getIndex();
        regToInstMap.erase(reg);
      }
    }
  }
  return changed;
}

bool SpillRegisters::requiresShortOutput(Instruction *I) {
  if (llvh::isa<TerminatorInst>(I)) {
                                                     
                                                   
    return false;
  }

                                                                           
               
  if (I->getType().isNoType())
    return false;

  switch (I->getKind()) {
                                                                         
    case ValueKind::HBCSpillMovInstKind:
    case ValueKind::LoadStackInstKind:
    case ValueKind::MovInstKind:
    case ValueKind::PhiInstKind:
                                                        
    case ValueKind::AllocStackInstKind:
    case ValueKind::TryEndInstKind:
    case ValueKind::TryStartInstKind:
      return false;
    default:
      return true;
  }
}

bool SpillRegisters::requiresShortOperand(Instruction *I, int op) {
  switch (I->getKind()) {
    case ValueKind::PhiInstKind:
    case ValueKind::MovInstKind:
    case ValueKind::HBCSpillMovInstKind:
    case ValueKind::LoadStackInstKind:
    case ValueKind::StoreStackInstKind:
      return false;
    case ValueKind::CallInstKind:
    case ValueKind::ConstructInstKind:
    case ValueKind::CallBuiltinInstKind:
    case ValueKind::HBCCallDirectInstKind:
      return op == CallInst::CalleeIdx;
    case ValueKind::HBCConstructInstKind:
                                                                               
      return op == CallInst::CalleeIdx || op == CallInst::NewTargetIdx;
    default:
      return true;
  }
}

bool SpillRegisters::modifiesOperandRegister(Instruction *I, int op) {
  return I->getChangedOperands().at((unsigned)op);
}

bool SpillRegisters::runOnFunction(Function *F) {
  if (RA_.getMaxRegisterUsage() < boundary_) {
    return false;
  }
  reserveLowRegisters(F);

  IRBuilder builder(F);
  llvh::SmallVector<std::pair<Instruction *, Register>, 2> toSpill;

  for (BasicBlock &BB : F->getBasicBlockList()) {
    for (Instruction &inst : BB) {
      if (!RA_.isAllocated(&inst)) {
                                                           
        continue;
      }

      int tempReg = 0;
      toSpill.clear();
      bool replaceWithFirstSpill = false;
      builder.setLocation(inst.getLocation());
      builder.setCurrentSourceLevelScope(inst.getSourceLevelScope());

      auto myRegister = RA_.getRegister(&inst);
      if (requiresShortOutput(&inst) && !isShort(myRegister)) {
        auto temp = getReserved(tempReg++);
        RA_.updateRegister(&inst, temp);
        toSpill.push_back(
            std::pair<Instruction *, Register>(&inst, myRegister));
        replaceWithFirstSpill = true;
      }

      for (int i = 0, e = inst.getNumOperands(); i < e; i++) {
        auto *op = llvh::dyn_cast<Instruction>(inst.getOperand(i));
        if (!op || !RA_.isAllocated(op)) {
                                                                      
                                                      
          continue;
        }
        auto opRegister = RA_.getRegister(op);

        if (requiresShortOperand(&inst, i) && !isShort(opRegister)) {
          auto temp = getReserved(tempReg++);

          builder.setInsertionPoint(&inst);
          auto *load = builder.createHBCSpillMovInst(op);
          RA_.updateRegister(load, temp);
          inst.setOperand(load, i);

          if (modifiesOperandRegister(&inst, i)) {
            toSpill.push_back(
                std::pair<Instruction *, Register>(load, opRegister));
          }
        }
      }

      if (toSpill.size()) {
        auto spillPoints = getInsertionPointsAfter(builder, &inst);

        assert(
            (!replaceWithFirstSpill || spillPoints.size() <= 1) &&
            "Asked to spill the value of a TerminatorInst. Our terminators "
            "shouldn't produce values. It wouldn't have mattered, but it "
            "also has multiple branches so users might need PhiInsts.");

        for (auto *point : spillPoints) {
          builder.setInsertionPoint(point);
          for (auto store : toSpill) {
            auto *storeInst = builder.createHBCSpillMovInst(store.first);
            RA_.updateRegister(storeInst, store.second);

            if (!replaceWithFirstSpill)
              continue;
                                                                  
            inst.replaceAllUsesWith(storeInst);
                                                    
            storeInst->setOperand(&inst, 0);
                                                
            replaceWithFirstSpill = false;
          }
        }
      }
    }
  }
  return true;
}

bool LowerSwitchIntoJumpTables::runOnFunction(Function *F) {
  bool changed = false;
  llvh::SmallVector<SwitchInst *, 4> switches;
                                     
  for (BasicBlock &BB : *F)
    for (auto &it : BB) {
      if (auto *S = llvh::dyn_cast<SwitchInst>(&it))
        switches.push_back(S);
    }

  for (auto *S : switches) {
    if (lowerIntoJumpTable(S))
      changed = true;
  }

  return changed;
}

bool LowerSwitchIntoJumpTables::lowerIntoJumpTable(SwitchInst *switchInst) {
                                          
  if (llvh::isa<Literal>(switchInst->getInputValue())) {
    return false;
  }
  IRBuilder builder(switchInst->getParent()->getParent());
  unsigned numCases = switchInst->getNumCasePair();
  uint32_t minValue = 0;
  uint32_t maxValue = 0;

  llvh::SmallVector<LiteralNumber *, 8> values;
  llvh::SmallVector<BasicBlock *, 8> blocks;

  for (unsigned i = 0; i != numCases; ++i) {
    auto casePair = switchInst->getCasePair(i);
    auto *lit = casePair.first;
    auto *num = llvh::dyn_cast<LiteralNumber>(lit);
    if (!num)
      return false;

                                                   
    if (auto ival = num->isIntTypeRepresentible<uint32_t>()) {
      values.push_back(num);
      blocks.push_back(casePair.second);

      if (i == 0) {
        minValue = maxValue = ival.getValue();
      } else {
        minValue = std::min(minValue, ival.getValue());
        maxValue = std::max(maxValue, ival.getValue());
      }
    } else {
      return false;
    }
  }

  assert(minValue <= maxValue && "Minimum cannot exceed maximum");
  uint32_t range = maxValue - minValue;
                                                      
  if (range == 0)
    return false;

                                                                  
  if (range == std::numeric_limits<uint32_t>::max())
    return false;

                                        
                                  
  if (range / numCases > 5 || numCases < 10)
    return false;

  builder.setInsertionPoint(switchInst);
  auto *switchImmInst = builder.createSwitchImmInst(
      switchInst->getInputValue(),
      switchInst->getDefaultDestination(),
      builder.getLiteralNumber(minValue),
      builder.getLiteralNumber(range + 1),
      values,
      blocks);

  switchInst->replaceAllUsesWith(switchImmInst);
  switchInst->eraseFromParent();
  return true;
}

}                 
}                    

#undef DEBUG_TYPE

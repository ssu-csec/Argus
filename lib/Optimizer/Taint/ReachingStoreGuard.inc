                                                                     
                                                                   
                                      
  
                                                      
                                                                             
                                                                             
                                                                             
                                                                          
                                                               
                                                                            
                                                                               
                                                                            
                                                                            
                                                                        
                                                                         

namespace {
thread_local std::unordered_map<Module *, std::array<int,2>> contractCache;
thread_local uint64_t contractQueries=0, contractScans=0, contractInstructions=0;

static std::string reachingStoreLiteralName(Value *value) {
  auto *literal = llvh::dyn_cast<LiteralString>(value);
  return literal ? literal->getValue().str().str() : std::string();
}

static Function *reachingStoreOwner(Instruction *instruction) {
  return instruction && instruction->getParent()
      ? instruction->getParent()->getParent() : nullptr;
}

                                                                             
                                                                             
                                                                        
static Value *reachingStoreBindingEnvironment(Value *environment, Variable *variable) {
  auto *scope = llvh::dyn_cast<ScopeCreationInst>(environment);
  auto *owner = scope ? reachingStoreOwner(scope) : nullptr;
  for (unsigned depth = 0; scope && owner && depth < 64; ++depth) {
    if (reachingStoreOwner(scope) != owner) break;
    if (scope->getCreatedScopeDesc() == variable->getParent()) return scope;
    auto *inner = llvh::dyn_cast<CreateInnerScopeInst>(scope);
    if (!inner) {
                                                                             
                                                                               
                                                                          
                                                                              
                                                                              
                                                                                
      if (llvh::isa<CreateScopeInst>(scope) &&
          scope->getCreatedScopeDesc() == owner->getFunctionScopeDesc()) {
        auto *parent = scope->getCreatedScopeDesc()->getParent();
        for (unsigned outer = 0; parent && outer < 64; ++outer) {
          if (parent == variable->getParent()) return scope;
          parent = parent->getParent();
        }
      }
      break;
    }
    scope = inner->getParentScope();
  }
  return environment;
}

static bool reachingStoreDeclaredGlobal(Module *module, Value *property) {
  auto *name = llvh::dyn_cast<LiteralString>(property);
  auto *binding = name ? module->findGlobalProperty(name->getValue()) : nullptr;
  return binding && binding->isDeclared();
}

                                                                              
                                                                         
                                                                    
                                        
                                                                             
static bool reachingStoreContractUncached(Module *module, bool isolatedFrame) {
  ++contractScans;
  for (auto *binding : module->getGlobalProperties()) {
    if (!binding->isDeclared()) continue;
    auto name = reachingStoreLiteralName(binding->getName());
    if (name == "Date" || (name == "document" && !isolatedFrame))
      return false;
  }
  for (Function &function : *module) {
    for (BasicBlock &block : function) {
      for (Instruction &instruction : block) {
        ++contractInstructions;
        if (llvh::isa<DirectEvalInst>(&instruction) ||
            llvh::isa<StoreGetterSetterInst>(&instruction)) return false;
        Value *writtenProperty = nullptr;
        if (auto *store = llvh::dyn_cast<StorePropertyInst>(&instruction))
          writtenProperty = store->getProperty();
        else if (auto *store = llvh::dyn_cast<StoreOwnPropertyInst>(&instruction))
          writtenProperty = store->getProperty();
        else if (auto *deletion = llvh::dyn_cast<DeletePropertyInst>(&instruction))
          writtenProperty = deletion->getProperty();
        if (writtenProperty) {
          auto *literal = llvh::dyn_cast<LiteralString>(writtenProperty);
                                                                               
          if (!literal) return false;
          auto name = literal->getValue().str();
          if (name == "Date" || name == "now") return false;
          if (name == "document") {
                                                                         
                                                                          
                                                                         
                                                                   
            auto *plainStore =
                llvh::dyn_cast<StorePropertyInst>(&instruction);
            if (!isolatedFrame || !plainStore ||
                plainStore->getObject() != module->getGlobalObject() ||
                !reachingStoreDeclaredGlobal(module, writtenProperty))
              return false;
          }
        }
        if (auto *propertyRead = llvh::dyn_cast<LoadPropertyInst>(&instruction)) {
          auto name = reachingStoreLiteralName(propertyRead->getProperty());
                                                                             
                                                                    
                                                                            
          if (name == "defineProperty" || name == "defineProperties" ||
              name == "__defineGetter__" || name == "__defineSetter__" ||
              name == "setPrototypeOf") return false;
        }
      }
    }
  }
  return true;
}

                                                                          
                                                                                 
static bool reachingStoreContract(Module *module, bool isolatedFrame) {
  ++contractQueries;
  auto result=contractCache.emplace(module,std::array<int,2>{{-1,-1}});
  int &cached=result.first->second[isolatedFrame?1:0];
  if (cached<0) cached=reachingStoreContractUncached(module,isolatedFrame)?1:0;
  if (std::getenv("ARGUS_VERIFY_FRAME_CACHE"))
    assert((cached!=0)==reachingStoreContractUncached(module,isolatedFrame));
  return cached!=0;
}

                                                                        
static bool reachingStoreGlobalContract(Module *module) {
  return reachingStoreContract(module, false);
}

                                                                         
                                                                         
                                                                               
static bool reachingStoreFrameContract(Module *module) {
  return reachingStoreContract(module, true);
}

static bool reachingStoreSafeGlobalRead(LoadPropertyInst *load, Module *module) {
  if (load->getObject() != module->getGlobalObject()) return false;
  if (!llvh::isa<LiteralString>(load->getProperty())) return false;
  auto name = reachingStoreLiteralName(load->getProperty());
  return name == "Date" || name == "document" ||
      reachingStoreDeclaredGlobal(module, load->getProperty());
}

static bool reachingStoreTrustedNowCall(CallInst *call, Module *module) {
  if (!call || call->getNumArguments() != 1 ||
      llvh::isa<ConstructInst>(call)) return false;
  auto *callee = llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
  if (!callee || reachingStoreLiteralName(callee->getProperty()) != "now")
    return false;
  auto *date = llvh::dyn_cast<TryLoadGlobalPropertyInst>(callee->getObject());
  return date && date->getObject() == module->getGlobalObject() &&
      reachingStoreLiteralName(date->getProperty()) == "Date" &&
      call->getArgument(0) == date;
}

static bool reachingStoreTrustedNowRead(LoadPropertyInst *load, Module *module) {
  if (load->getUsers().empty()) return false;
  for (auto *user : load->getUsers()) {
    auto *call = llvh::dyn_cast<CallInst>(user);
    if (!call || call->getCallee() != load ||
        !reachingStoreTrustedNowCall(call, module)) return false;
  }
  return true;
}

static bool reachingStoreUncapturedFrame(StoreFrameInst *store, LoadFrameInst *load) {
  if (store->getVariable() != load->getLoadVariable() ||
      reachingStoreBindingEnvironment(store->getEnvironment(), store->getVariable()) !=
          reachingStoreBindingEnvironment(load->getEnvironment(), load->getLoadVariable())) return false;
  auto *owner = reachingStoreOwner(store);
  auto *environment = llvh::dyn_cast<ScopeCreationInst>(
      reachingStoreBindingEnvironment(store->getEnvironment(), store->getVariable()));
  if (!environment) return false;
  if (!owner || reachingStoreOwner(load) != owner ||
      reachingStoreOwner(environment) != owner ||
      environment->getCreatedScopeDesc() != store->getVariable()->getParent())
    return false;
  for (auto *user : store->getVariable()->getUsers()) {
    if (reachingStoreOwner(user) != owner) return false;
    if (auto *write = llvh::dyn_cast<StoreFrameInst>(user)) {
      if (write->getVariable() != store->getVariable() ||
          reachingStoreBindingEnvironment(write->getEnvironment(), write->getVariable()) != environment) return false;
    } else if (auto *read = llvh::dyn_cast<LoadFrameInst>(user)) {
      if (read->getLoadVariable() != store->getVariable() ||
          reachingStoreBindingEnvironment(read->getEnvironment(), read->getLoadVariable()) != environment) return false;
    } else {
      return false;
    }
  }
  return true;
}

bool definitelyKilledStore(Instruction *store, Instruction *load) {
  if (!store || !load || store == load || !store->getParent() ||
      !load->getParent()) return false;
  auto *owner = reachingStoreOwner(store);
  if (!owner) return false;
  auto *module = owner->getParent();
  auto *propertyStore = llvh::dyn_cast<StorePropertyInst>(store);
  auto *propertyLoad = llvh::dyn_cast<LoadPropertyInst>(load);
  auto *frameStore = llvh::dyn_cast<StoreFrameInst>(store);
  auto *frameLoad = llvh::dyn_cast<LoadFrameInst>(load);

  bool global = false;
  if (propertyStore && propertyLoad) {
    if (store->getParent() != load->getParent() ||
        owner != module->getTopLevelFunction() ||
        propertyStore->getObject() != module->getGlobalObject() ||
        propertyLoad->getObject() != propertyStore->getObject() ||
        !llvh::isa<LiteralString>(propertyStore->getProperty()) ||
        !llvh::isa<LiteralString>(propertyLoad->getProperty()) ||
        reachingStoreLiteralName(propertyStore->getProperty()) !=
            reachingStoreLiteralName(propertyLoad->getProperty()) ||
        !reachingStoreDeclaredGlobal(module, propertyStore->getProperty()))
      return false;
    global = true;
  } else if (!(frameStore && frameLoad &&
               reachingStoreUncapturedFrame(frameStore, frameLoad))) {
    return false;
  }

                                                                           
                                                                       
                                                                            
  if (global ? !reachingStoreGlobalContract(module)
             : !reachingStoreFrameContract(module)) return false;

                                                                          
                                                                            
                                                                                
  bool afterStore = !global && store->getParent() != load->getParent();
  bool reachedLoad = false;
  Instruction *lastOverwrite = nullptr;
  for (Instruction &instruction : *load->getParent()) {
    if (&instruction == load) {
      reachedLoad = true;
      break;
    }
    if (&instruction == store) {
      afterStore = true;
      continue;
    }
    if (!afterStore) continue;

    if (global) {
      auto *write = llvh::dyn_cast<StorePropertyInst>(&instruction);
      if (write && write->getObject() == propertyStore->getObject() &&
          llvh::isa<LiteralString>(write->getProperty()) &&
          reachingStoreLiteralName(write->getProperty()) ==
              reachingStoreLiteralName(propertyStore->getProperty())) {
                                                                             
                                                                               
        lastOverwrite = &instruction;
      }
    } else if (auto *write = llvh::dyn_cast<StoreFrameInst>(&instruction)) {
      if (write->getVariable() == frameStore->getVariable() &&
          reachingStoreBindingEnvironment(write->getEnvironment(), write->getVariable()) ==
              reachingStoreBindingEnvironment(frameStore->getEnvironment(), frameStore->getVariable())) {
        lastOverwrite = &instruction;
      }
    }
  }
  if (!reachedLoad || !afterStore || !lastOverwrite) return false;

                                                                          
                                                                            
                                                                         
                                                                           
  bool afterOverwrite = false;
  for (Instruction &instruction : *load->getParent()) {
    if (&instruction == load) return afterOverwrite;
    if (&instruction == lastOverwrite) {
      afterOverwrite = true;
      continue;
    }
    if (!afterOverwrite) continue;
    if (auto *read = llvh::dyn_cast<LoadPropertyInst>(&instruction)) {
      if (reachingStoreSafeGlobalRead(read, module) ||
          reachingStoreTrustedNowRead(read, module)) continue;
                                                                               
      return false;
    }
    if (auto *call = llvh::dyn_cast<CallInst>(&instruction))
      if (reachingStoreTrustedNowCall(call, module)) continue;
                                                                            
                                                                           
                                                                        
    if (instruction.mayExecute()) return false;
  }
  return false;
}

}             

#include <array>
#include <cstdlib>

#include "hermes/Optimizer/Taint/DefUseAnalyzer.h"
#include "llvh/Support/Debug.h"
#include "StaticReturnTransport.inc"
#include "CtorInstanceTransport.inc"
#include "DerivedConstructorTransport.inc"
#include "PrivateMethodState.inc"
#include "AsyncArgumentTransport.inc"
#include "AsyncGeneratorTransport.inc"
#include "BoundedOrdinaryReturnTransport.inc"
#include "BoundedModuleClassReturnTransport.inc"
#include "NativeStaticReturnTransport.inc"
#include "DynamicModuleTransport.inc"
#include "BoundedOrdinaryAsyncReturnTransport.inc"
#include "GlobalAsyncOverwriteGuard.inc"
#include "BoundedToSetterTransport.inc"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <utility>

#define DEBUG_TYPE "taint-defuse"

using llvh::dbgs;
using llvh::outs;

namespace hermes {

#include "KnownCallSummary.inc"
#include "ReachingStoreGuard.inc"
#include "GlobalObjectStorage.inc"

namespace {

struct TaintMetrics {
  uint64_t pops=0, users=0, movedNodes=0, dumpBuilds=0, dumpReplays=0, rounds=0;
  std::chrono::steady_clock::time_point start=std::chrono::steady_clock::now();
  void write(const char *phase, size_t pending=0) const {
    const char *path=std::getenv("ARGUS_TAINT_METRICS");
    if (!path || !*path) return;
    if (FILE *f=std::fopen(path,"w")) {
      std::fprintf(f,"{\"phase\":\"%s\",\"popped_facts\":%llu,\"user_edges\":%llu,\"moved_path_nodes\":%llu,\"sink_dump_builds\":%llu,\"sink_dump_replays\":%llu,\"rounds\":%llu,\"pending\":%llu,\"elapsed_ns\":%lld}\n",
        phase,(unsigned long long)pops,(unsigned long long)users,
        (unsigned long long)movedNodes,(unsigned long long)dumpBuilds,
        (unsigned long long)dumpReplays,(unsigned long long)rounds,
        (unsigned long long)pending,(long long)std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-start).count());
      std::fclose(f);
    }
  }
};
thread_local TaintMetrics taintMetrics;
thread_local Module *indexedFrameModule=nullptr;
thread_local std::vector<LoadFrameInst *> indexedFrameLoads;
thread_local uint64_t frameRounds=0, frameLoadsVisited=0, frameFacts=0;
static void writeFrameMetrics(const char *phase) {
  const char *path=std::getenv("ARGUS_FRAME_METRICS");
  if (!path || !*path) return;
  if (FILE *f=std::fopen(path,"w")) {
    std::fprintf(f,"{\"phase\":\"%s\",\"rounds\":%llu,\"indexed_loads\":%llu,\"load_visits\":%llu,\"facts\":%llu,\"contract_queries\":%llu,\"contract_scans\":%llu,\"contract_instructions\":%llu}\n",
      phase,(unsigned long long)frameRounds,(unsigned long long)indexedFrameLoads.size(),
      (unsigned long long)frameLoadsVisited,(unsigned long long)frameFacts,
      (unsigned long long)contractQueries,(unsigned long long)contractScans,(unsigned long long)contractInstructions);
    std::fclose(f);
  }
}
                                                                                
                                                                                
                                                                                
thread_local std::unordered_map<Value *, std::unordered_set<Instruction *>> scheduledFacts;
thread_local Value *activeTaintValue = nullptr;
thread_local std::unordered_map<CallInst *, ExactCallSummary> exactCallCache;
thread_local std::unordered_map<Instruction *, std::string> identityNodeIds;
thread_local unsigned exactCallEdges = 0, killedStorageEdges = 0;
thread_local std::unordered_set<CallInst *> privateMethodExactReads;
thread_local std::unordered_set<LoadPropertyInst *> publicStaticExactReads;

bool sourceScheduled(Value *v, Instruction *s) {
  auto it = scheduledFacts.find(v);
  return it != scheduledFacts.end() && it->second.count(s);
}

                                                                              
                                                                                   
thread_local Module *receiverModule = nullptr;
thread_local std::unordered_map<Function *, Function *> receiverOwners;

Function *uniqueClosure(Value *value, unsigned depth = 0) {
  if (depth > 4) return nullptr;
  if (auto *create = llvh::dyn_cast<CreateFunctionInst>(value))
    return create->getFunctionCode();
  if (auto *function = llvh::dyn_cast<Function>(value)) return function;
  auto *load = llvh::dyn_cast<LoadFrameInst>(value);
  if (!load) return nullptr;
  Function *answer = nullptr;
  unsigned stores = 0;
  for (auto *user : load->getLoadVariable()->getUsers()) {
    auto *store = llvh::dyn_cast<StoreFrameInst>(user);
    if (!store || store->getVariable() != load->getLoadVariable()) continue;
    if (++stores > 1) return nullptr;
    answer = uniqueClosure(store->getValue(), depth + 1);
  }
  return answer;
}

std::string classHelper(CallInst *call) {
  auto *property = llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
  if (!property) return "";
  auto *name = llvh::dyn_cast<LiteralString>(property->getProperty());
  auto *global = llvh::dyn_cast<TryLoadGlobalPropertyInst>(property->getObject());
  if (!name || !global) return "";
  auto *objectName = llvh::dyn_cast<LiteralString>(global->getProperty());
  if (!objectName || objectName->getValue().str() != "HermesES6Internal") return "";
  return name->getValue().str().str();
}

Value *classReceiver(Value *object) {
  auto *parameter = llvh::dyn_cast<Parameter>(object);
  if (!parameter || parameter != parameter->getParent()->getThisParameter()) return object;
  auto *module = parameter->getParent()->getParent();
  if (receiverModule != module) {
    receiverModule = module;
    receiverOwners.clear();
    for (Function &function : *module)
      for (BasicBlock &block : function)
        for (Instruction &instruction : block)
          if (auto *call = llvh::dyn_cast<CallInst>(&instruction))
            if (classHelper(call) == "defineClass" && call->getNumArguments() == 3 &&
                llvh::isa<LiteralNull>(call->getArgument(2)))
              if (auto *ctor = uniqueClosure(call->getArgument(1))) receiverOwners[ctor] = ctor;
    for (Function &function : *module)
      for (BasicBlock &block : function)
        for (Instruction &instruction : block)
          if (auto *call = llvh::dyn_cast<CallInst>(&instruction))
            if (classHelper(call) == "defineClassMethod" && call->getNumArguments() == 4) {
              auto *ctor = uniqueClosure(call->getArgument(1));
              auto *method = uniqueClosure(call->getArgument(3));
              if (ctor && method && receiverOwners.count(ctor)) receiverOwners[method] = ctor;
            }
  }
  auto owner = receiverOwners.find(parameter->getParent());
  return owner == receiverOwners.end() ? object : owner->second->getThisParameter();
}
}             



const DefUseAnalyzer::TaintInfo DefUseAnalyzer::emptyTaintInfo_ = {};

void DefUseAnalyzer::analyzeTaintFlow(
    const std::vector<Instruction *> &sources,
    const std::vector<Instruction *> &sinks,
    ClosureAnalyzer *closureAnalyzer) {
  clear();
  closureAnalyzer_ = closureAnalyzer;
  if(!sources.empty()||!sinks.empty()) {
    auto *anchor=sources.empty()?sinks.front():sources.front();
    auto *module=anchor->getParent()->getParent()->getParent();
    if(DynamicModuleTransport::present(module)) {
      for(auto *i:sources)sources_.insert(i);
      for(auto *i:sinks)sinks_.insert(i);
      DynamicModuleTransport transport(module,sources,sinks);
      transport.analyze(sinkReachingPaths_);
      return;
    }
  }

  PrivateBindingMetadata privateMetadata;
  if (!sinks.empty() || !sources.empty()) {
    auto *anchor = sinks.empty() ? sources.front() : sinks.front();
    privateMetadata.module=anchor->getParent()->getParent()->getParent();
    unsigned fi = 0;
    for (Function &function : *anchor->getParent()->getParent()->getParent()) {
      ++privateMetadata.functions;
      unsigned ii = 0;
      for (BasicBlock &block : function)
        for (Instruction &instruction : block) {
          identityNodeIds[&instruction] = "F" + std::to_string(fi) + ":I" + std::to_string(ii++);
          privateMetadata.observe(&instruction);
        }
      ++fi;
    }
    privateMetadata.complete=true;
  }

  for (auto *source : sources) {
    sources_.insert(source);
  }

  for (auto *sink : sinks) {
    sinks_.insert(sink);
  }
  std::vector<Instruction *> reachableSinks = sinks;
  if(!sources.empty()&&!sinks.empty())
    globalObjectStorage.build(sources.front()->getParent()->getParent()->getParent());

                                                                              
                                                                                
                                                                       
  if (!sinks.empty() || !sources.empty()) {
    auto *anchor = sinks.empty() ? sources.front() : sinks.front();
    BoundedPrivateMethodState state(
        anchor->getParent()->getParent()->getParent(), sources, sinks, identityNodeIds,privateMetadata);
    state.build();
    if(!state.hasUnprovenEntryGuard() && state.completion()==BoundedPrivateMethodState::Completion::NORMAL) {
      const auto &dormant=state.dormantGetterSinks();
      for(auto *sink:dormant)sinks_.erase(sink);
      reachableSinks.erase(std::remove_if(reachableSinks.begin(),reachableSinks.end(),
          [&](Instruction *sink){return std::find(dormant.begin(),dormant.end(),sink)!=dormant.end();}),reachableSinks.end());
    }

                                                                            
                                                                              
                                                                         
    const bool abrupt = !state.hasUnprovenEntryGuard() && state.completion() ==
        BoundedPrivateMethodState::Completion::PROVED_ABRUPT;
    bool abruptValid = abrupt && state.reads().empty() &&
        !state.unreachableSinks().empty();
    std::unordered_set<Instruction *> unreachable;
    for (const auto &proof : state.unreachableSinks()) {
      auto *store = llvh::dyn_cast_or_null<StorePropertyInst>(proof.sink);
      auto *property = store ? llvh::dyn_cast<LiteralString>(store->getProperty()) : nullptr;
      bool ordered = false, seenCall = false;
      if (proof.outerCall && proof.sink &&
          proof.outerCall->getParent() == proof.sink->getParent())
        for (auto &i : *proof.outerCall->getParent()) {
          if (&i == proof.sink) { ordered = seenCall; break; }
          if (&i == proof.outerCall) seenCall = true;
        }
      abruptValid = abruptValid && store && property &&
          property->getValue().str() == "cookie" && ordered &&
          std::find(sinks.begin(), sinks.end(), proof.sink) != sinks.end() &&
          proof.sink->getParent()->getParent()->isGlobalScope() &&
          proof.sink->getParent() == &proof.sink->getParent()->getParent()->front() &&
          llvh::isa<ReturnInst>(proof.sink->getParent()->getTerminator()) &&
          proof.helperCall && proof.brandCall &&
          (proof.throwSite && llvh::isa<ThrowInst>(proof.throwSite)) &&
          (proof.receiverAllocation && llvh::isa<AllocObjectInst>(proof.receiverAllocation)) &&
          (proof.mapAllocation && llvh::isa<ConstructInst>(proof.mapAllocation)) &&
          proof.callableCreation && !proof.path.empty() &&
          proof.path.front() == proof.outerCall && proof.path.back() == proof.throwSite &&
          unreachable.insert(proof.sink).second;
      for (auto *node : proof.path)
        abruptValid = abruptValid && node && identityNodeIds.count(node);
    }
    if (abruptValid) {
      for (auto *sink : unreachable) sinks_.erase(sink);
      reachableSinks.erase(
          std::remove_if(reachableSinks.begin(), reachableSinks.end(),
              [&](Instruction *sink) { return unreachable.count(sink); }),
          reachableSinks.end());
    }
    outs() << "[PRIVATE_ABRUPT_INTEGRATION] proved=" << (abrupt ? 1 : 0)
           << " valid=" << (abruptValid ? 1 : 0)
           << " suppressed_sinks=" << (abruptValid ? unreachable.size() : 0) << "\n";
                                                                            
                                                                             
                                                                               
    bool valid = !state.hasUnprovenEntryGuard() && state.completion() ==
        BoundedPrivateMethodState::Completion::NORMAL;
    std::unordered_set<CallInst *> sites;
    for (const auto &read : state.reads()) {
      valid = valid && state.hasExactReadCertificate(read) && read.site &&
          !llvh::isa<ConstructInst>(read.site) && sites.insert(read.site).second;
      for (const auto &trace : read.traces)
        valid = valid && trace.source &&
            std::find(sources.begin(), sources.end(), trace.source) != sources.end() &&
            !trace.path.empty() && trace.path.front() == trace.source &&
            trace.path.back() == read.site;
    }
    unsigned seeded = 0, clean = 0;
    if (valid) for (const auto &read : state.reads()) {
      privateMethodExactReads.insert(read.site);
      if (read.traces.empty()) ++clean;
      for (const auto &trace : read.traces) {
        markTainted(read.site, trace.source, trace.path);
        addToWorklist(read.site, trace.path);
        ++seeded;
      }
    }
    bool publicValid = !state.hasUnprovenEntryGuard() && state.completion() ==
        BoundedPrivateMethodState::Completion::NORMAL;
    std::unordered_set<LoadPropertyInst *> publicSites;
    for(const auto &read:state.publicReads()) {
      publicValid=publicValid&&state.hasPublicReadCertificate(read)&&read.site&&
          publicSites.insert(read.site).second;
      for(const auto &trace:read.traces)
        publicValid=publicValid&&trace.source&&
            std::find(sources.begin(),sources.end(),trace.source)!=sources.end()&&
            !trace.path.empty()&&trace.path.front()==trace.source&&trace.path.back()==read.site;
    }
    unsigned publicSeeds=0,publicClean=0,publicStaticReads=0;
    unsigned instanceSeeds=0,instanceClean=0,instanceReads=0;
    if(publicValid) for(const auto &read:state.publicReads()) {
                                                                          
                                                                             
      publicStaticExactReads.insert(read.site);
      if(read.instance)++instanceReads;else ++publicStaticReads;
      if(read.traces.empty()) {if(read.instance)++instanceClean;else ++publicClean;}
      for(const auto &trace:read.traces) {
        markTainted(read.site,trace.source,trace.path);
        addToWorklist(read.site,trace.path);
        if(read.instance)++instanceSeeds;else ++publicSeeds;
      }
    }
    outs()<<"[PUBLIC_STATIC_READ_EXPORT] certified="<<(publicValid?1:0)
        <<" reads="<<publicStaticReads<<" clean="<<publicClean
        <<" seeds="<<publicSeeds<<" policy=EXACT_NORMAL_OR_PRESERVE_GENERIC\n";
    outs()<<"[PUBLIC_INSTANCE_READ_EXPORT] certified="<<(publicValid?1:0)
        <<" reads="<<instanceReads<<" clean="<<instanceClean
        <<" seeds="<<instanceSeeds<<" policy=EXACT_NORMAL_OR_PRESERVE_GENERIC\n";
    outs() << "[PRIVATE_METHOD_INTEGRATION] valid=" << (valid ? 1 : 0)
           << " exact_reads=" << privateMethodExactReads.size()
           << " clean_reads=" << clean << " source_seeds=" << seeded << "\n";
    outs() << "[PRIVATE_READ_EXPORT_GATE] certified=" << (valid ? 1 : 0)
           << " unresolved_entry_guard=" << (state.hasUnprovenEntryGuard() ? 1 : 0)
           << " registry_inserted=" << (valid ? sites.size() : 0)
           << " policy=EXACT_NORMAL_READ_CERTIFICATE_OR_PRESERVE_GENERIC\n";
  }

                                                                           
                                                                       
                                                                          
                                                                            
  if(!sources.empty()&&!sinks.empty()) {
    const char *profile=std::getenv("ARGUS_PRIVATE_ENTRY_PROFILE");
    const bool ordinary=profile&&
        std::string(profile)=="ordinary-pristine-global-v1";
    auto *m=sources.front()->getParent()->getParent()->getParent();
    BoundedPrivateMethodState additive(m,sources,sinks,identityNodeIds,privateMetadata,true,ordinary);
    additive.build();
    if(additive.hasUnprovenEntryGuard()) {
                                                                               
                                                                     
      BoundedPrivateMethodState partition(m,sources,sinks,identityNodeIds,
                                         privateMetadata,true,false,true);
      partition.build();
    }
    unsigned seeds=0;
    for(const auto &flow:additive.sinkFlows()) {
      bool valid=flow.site&&std::find(sinks.begin(),sinks.end(),flow.site)!=sinks.end();
      for(const auto &trace:flow.traces) {
        valid=valid&&trace.source&&
            std::find(sources.begin(),sources.end(),trace.source)!=sources.end()&&
            !trace.path.empty()&&trace.path.front()==trace.source&&
            trace.path.back()==flow.site;
        for(auto *node:trace.path)valid=valid&&node&&identityNodeIds.count(node);
      }
      if(valid)for(const auto &trace:flow.traces) {
                                                                          
                                                                    
        markTainted(flow.site,trace.source,trace.path);
        addToWorklist(flow.site,trace.path);++seeds;
      }
    }
    outs()<<"[PRIVATE_ADDITIVE_EXPORT] seeds="<<seeds
        <<" environment_evidence="<<(ordinary?"EXPLICIT_CALLER_PROFILE":"UNASSERTED")
        <<" exact_registry_insertions=0 suppressed_sinks=0\n";
  }

  for (auto *source : sources) {
    std::vector<Instruction *> initialPath = {source};
    markTainted(source, source, initialPath);
    addToWorklist(source, initialPath);
  }

                                                                             
                                                                               
  do {
    ++taintMetrics.rounds;
    taintMetrics.write("PROPAGATING",worklist_.size());
    propagateTaint();
    taintMetrics.write("PROPERTY_CONNECTIONS",worklist_.size());
    checkPropertyTaintConnections();
    taintMetrics.write("FRAME_CONNECTIONS",worklist_.size());
    checkFrameTaintConnections();
  } while (!worklist_.empty());
  taintMetrics.write("POST_TRANSPORTS",worklist_.size());
  outs()<<"[GLOBAL_OBJECT_STORAGE] admitted="<<globalObjectStorage.admitted
        <<" limited="<<globalObjectStorage.limited<<" scanned="<<globalObjectStorage.scanned
        <<" indexed_reads="<<globalObjectStorage.edges.size()<<" seeds="<<globalObjectStorageSeeds
        <<" barriers="<<globalObjectStorage.barriers
        <<" contract=SAME_BLOCK_LITERAL_LATEST_STORE_STABLE_GLOBAL_SLOT_MAY"
        <<" assumptions=ORDINARY_HOST_DATA_PROPERTIES_NO_EXTERNAL_REENTRY"
        <<" runtime_identity_proven=0 existing_gates_changed=0\n";
  unsigned knownCalls = 0;
  for (const auto &entry : exactCallCache) if (entry.second.known) ++knownCalls;
  size_t scheduledCount = 0, witnessNodes = 0;
  for (const auto &entry : scheduledFacts) scheduledCount += entry.second.size();
  for (const auto &entry : taintMap_)
    for (const auto &path : entry.second.paths) witnessNodes += path.path.size();
  outs() << "[TAINT_FACT_SIZE] values=" << scheduledFacts.size()
         << " source_value_facts=" << scheduledCount
         << " witness_nodes=" << witnessNodes << "\n";
  outs() << "[SOURCE_IDENTITY] known_calls=" << knownCalls
         << " legacy_calls=" << exactCallCache.size() - knownCalls
         << " exact_call_edges=" << exactCallEdges
         << " killed_storage_edges=" << killedStorageEdges << "\n";
  if (!reachableSinks.empty()) {
    BoundedStaticReturnTransport transport(
        reachableSinks.front()->getParent()->getParent()->getParent(), sources, reachableSinks);
    transport.append(sinkReachingPaths_);
    BoundedCtorInstanceTransport instances(
        reachableSinks.front()->getParent()->getParent()->getParent(), sources, reachableSinks);
    instances.append(sinkReachingPaths_);
    BoundedDerivedConstructorTransport derivedInstances(
        reachableSinks.front()->getParent()->getParent()->getParent(), sources, reachableSinks);
    derivedInstances.append(sinkReachingPaths_);
    BoundedAsyncArgumentTransport asyncArguments(
        reachableSinks.front()->getParent()->getParent()->getParent(), sources, reachableSinks);
    asyncArguments.append(sinkReachingPaths_);
    BoundedAsyncGeneratorTransport asyncGenerators(
        reachableSinks.front()->getParent()->getParent()->getParent(), sources, reachableSinks);
    asyncGenerators.append(sinkReachingPaths_);
    BoundedOrdinaryReturnTransport ordinaryReturns(
        reachableSinks.front()->getParent()->getParent()->getParent(), sources, reachableSinks, functionCalls_);
    ordinaryReturns.append(sinkReachingPaths_);
    BoundedModuleClassReturnTransport moduleClassReturns(
        reachableSinks.front()->getParent()->getParent()->getParent(), sources, reachableSinks);
    moduleClassReturns.append(sinkReachingPaths_);
    BoundedNativeStaticReturnTransport nativeStaticReturns(
        reachableSinks.front()->getParent()->getParent()->getParent(), sources, reachableSinks);
    nativeStaticReturns.append(sinkReachingPaths_);
    BoundedOrdinaryAsyncReturnTransport ordinaryAsyncReturns(
        reachableSinks.front()->getParent()->getParent()->getParent(), sources, reachableSinks);
    ordinaryAsyncReturns.append(sinkReachingPaths_);
    BoundedToSetterTransport toSetter(
        reachableSinks.front()->getParent()->getParent()->getParent(), sources, reachableSinks);
    toSetter.append(sinkReachingPaths_);
    BoundedGlobalAsyncOverwriteGuard globalAsyncOverwrite(
        reachableSinks.front()->getParent()->getParent()->getParent(), sources, reachableSinks);
    globalAsyncOverwrite.refine(sinkReachingPaths_);
    derivedInstances.refine(sinkReachingPaths_);
  }
}

void DefUseAnalyzer::clear() {
  globalObjectStorage=GlobalObjectStorageIndex{};globalObjectStorageSeeds=0;
  contractCache.clear(); contractQueries=contractScans=contractInstructions=0;
  indexedFrameModule=nullptr; indexedFrameLoads.clear();
  frameRounds=frameLoadsVisited=frameFacts=0;
  taintMetrics=TaintMetrics{};
  taintMetrics.write("INITIALIZING");
  privateMethodExactReads.clear();
  publicStaticExactReads.clear();
  scheduledFacts.clear();
  exactCallCache.clear();
  identityNodeIds.clear();
  activeTaintValue = nullptr;
  exactCallEdges = killedStorageEdges = 0;
  receiverModule = nullptr;
  receiverOwners.clear();
  taintMap_.clear();
  propertyTaintMap_.clear();
  frameTaintMap_.clear();
  worklist_.clear();
  worklistSet_.clear();
  sinkReachingPaths_.clear();
  sources_.clear();
  sinks_.clear();
  closureAnalyzer_ = nullptr;
}

bool DefUseAnalyzer::isTainted(Value *v) const {
  auto it = taintMap_.find(v);
  return it != taintMap_.end() && it->second.isTainted;
}

const DefUseAnalyzer::TaintInfo &DefUseAnalyzer::getTaintInfo(Value *v) const {
  auto it = taintMap_.find(v);
  if (it != taintMap_.end()) {
    return it->second;
  }
  return emptyTaintInfo_;
}

void DefUseAnalyzer::propagateTaint() {
                                                                             
                                                                                
  std::string sinkDump;
  bool dumpReady=false;
  const char *compactSetting=std::getenv("ARGUS_TAINT_COMPACT_SINK_DEBUG");
  const bool compactSinkDebug=compactSetting && std::string(compactSetting)=="1";
  bool dumpEmitted=false;
  auto cachedIsSink=[&](Instruction *inst) {
    bool found=sinks_.find(inst)!=sinks_.end();
    if (!found && llvh::isa<StorePropertyInst>(inst)) {
      outs() << "[DEBUG SINK] StorePropertyInst not found in sinks set. Comparing pointers:\n";
      outs() << "  Current inst: " << inst << "\n";
      if (!dumpReady) {
        llvh::raw_string_ostream rendered(sinkDump);
        for (auto *sink : sinks_)
          rendered << "  Sink in set: " << sink << " (" << sink->getKindStr() << ")\n";
        rendered.flush(); dumpReady=true; ++taintMetrics.dumpBuilds;
      }
                                                                            
                                                                                    
                                                                                   
      if (!compactSinkDebug) {
        outs() << sinkDump;
      } else if (!dumpEmitted) {
        outs() << "[ARGUS_SINK_DUMP_V1 BEGIN bytes=" << sinkDump.size() << "]\n";
        outs() << sinkDump << "[ARGUS_SINK_DUMP_V1 END]\n";
        dumpEmitted=true;
      } else {
        outs() << "[ARGUS_SINK_DUMP_V1 REF]\n";
      }
      ++taintMetrics.dumpReplays;
    }
    return found;
  };
  while (!worklist_.empty()) {
    auto [currentValue, currentPath] = std::move(worklist_.front());
    ++taintMetrics.pops; taintMetrics.movedNodes+=currentPath.size();
    if ((taintMetrics.pops & 4095)==0) taintMetrics.write("PROPAGATING",worklist_.size());
    worklist_.pop_front();
    activeTaintValue = currentValue;

    if (auto *inst = llvh::dyn_cast<Instruction>(currentValue)) {
      outs() << "[DEBUG PROPAGATE] Checking instruction: " << inst->getKindStr()
             << ", is sink: " << (cachedIsSink(inst) ? "YES" : "NO") << "\n";

      if (cachedIsSink(inst)) {
        Instruction *source = currentPath.empty() ? nullptr : currentPath.front();
        sinkReachingPaths_.emplace_back(source, currentPath, inst);
        outs() << "[DEBUG PROPAGATE] SINK REACHED! Added to sinkReachingPaths. Total paths: "
               << sinkReachingPaths_.size() << "\n";
      }
    }

    for (Instruction *user : currentValue->getUsers()) {
      ++taintMetrics.users;
      outs() << "[DEBUG USERS] Found user: " << user->getKindStr() << "\n";

      if (auto *movInst = llvh::dyn_cast<MovInst>(user)) {
        handleMovInst(movInst, currentPath);
      } else if (auto *phiInst = llvh::dyn_cast<PhiInst>(user)) {
        handlePhiInst(phiInst, currentPath);
      } else if (auto *binOp = llvh::dyn_cast<BinaryOperatorInst>(user)) {
        handleBinaryOp(binOp, currentPath);
      } else if (auto *callInst = llvh::dyn_cast<CallInst>(user)) {
        handleCallInst(callInst, currentPath);
      } else if (auto *loadProp = llvh::dyn_cast<LoadPropertyInst>(user)) {
        handleLoadProperty(loadProp, currentPath);
      } else if (auto *storeProp = llvh::dyn_cast<StorePropertyInst>(user)) {
        handleStoreProperty(storeProp, currentPath);
      } else if (auto *loadFrame = llvh::dyn_cast<LoadFrameInst>(user)) {
        handleLoadFrame(loadFrame, currentPath);
      } else if (auto *storeFrame = llvh::dyn_cast<StoreFrameInst>(user)) {
        handleStoreFrame(storeFrame, currentPath);
      } else if (auto *retInst = llvh::dyn_cast<ReturnInst>(user)) {
        handleReturn(retInst, currentPath);
      } else if (auto *unaryOp = llvh::dyn_cast<UnaryOperatorInst>(user)) {
        handleUnaryOp(unaryOp, currentPath);
      } else {
        handleGenericInst(user, currentPath);
      }
    }
  }
}

void DefUseAnalyzer::addToWorklist(
    Value *v,
    const std::vector<Instruction *> &path) {
  if (!path.empty() && scheduledFacts[v].insert(path.front()).second) {
    worklist_.emplace_back(v, path);
  }
}

void DefUseAnalyzer::handleMovInst(
    MovInst *inst,
    const std::vector<Instruction *> &path) {
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  if (!isTainted(inst) || shouldPropagateTo(inst)) {
    markTainted(inst, path.front(), newPath);
    addToWorklist(inst, newPath);
  }
}

void DefUseAnalyzer::handlePhiInst(
    PhiInst *inst,
    const std::vector<Instruction *> &path) {
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  if (!isTainted(inst) || shouldPropagateTo(inst)) {
    markTainted(inst, path.front(), newPath);
    addToWorklist(inst, newPath);
  }
}

void DefUseAnalyzer::handleBinaryOp(
    BinaryOperatorInst *inst,
    const std::vector<Instruction *> &path) {
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  if (!isTainted(inst) || shouldPropagateTo(inst)) {
    markTainted(inst, path.front(), newPath);
    addToWorklist(inst, newPath);
  }
}

void DefUseAnalyzer::handleCallInst(
    CallInst *inst,
    const std::vector<Instruction *> &path) {
                                                                           
                                                                            
  if (privateMethodExactReads.count(inst)) return;
  auto found = exactCallCache.find(inst);
  if (found == exactCallCache.end()) {
    found = exactCallCache.emplace(inst, summarizeExactCall(inst)).first;
    const auto &result = found->second;
    outs() << "[CALL_SUMMARY] call=" << identityNodeIds[inst]
           << " known=" << (result.known ? 1 : 0)
           << " returns_primitive=" << (result.returnsPrimitive ? 1 : 0)
           << " reason=" << result.reason << " barrier="
           << (result.barrier ? identityNodeIds[result.barrier] : "NONE") << "\n";
  }
  const auto &summary = found->second;
  if (summary.known) {
    // Only returned dependencies are transported, separately for this callsite.
    // A valid constant return has no dependencies; an unknown body falls through.
    for (size_t i = 0; i < summary.parameterPaths.size(); ++i) {
      if (i + 1 >= inst->getNumArguments() || inst->getArgument(i + 1) != activeTaintValue ||
          summary.parameterPaths[i].empty()) continue;
      auto precisePath = path;
      precisePath.insert(precisePath.end(), summary.parameterPaths[i].begin(), summary.parameterPaths[i].end());
      precisePath.push_back(inst);
      if (!sourceScheduled(inst, path.front())) {
        ++exactCallEdges;
        outs() << "[EXACT_CALL_RETURN] source=" << identityNodeIds[path.front()]
               << " call=" << identityNodeIds[inst] << " parameter=" << i << " path=";
        for (auto *node : precisePath)
          outs() << identityNodeIds[node] << "/" << node->getKindStr() << " ";
        outs() << "\n";
      }
      markTainted(inst, path.front(), precisePath);
      addToWorklist(inst, precisePath);
    }
    return;
  }
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  if (!isTainted(inst) || shouldPropagateTo(inst)) {
    markTainted(inst, path.front(), newPath);
    addToWorklist(inst, newPath);
  }

  for (const auto &funcCall : functionCalls_) {
    if (funcCall.callSite == inst) {
      outs() << "[DEBUG INTERPROCEDURAL] Found mapped function call to: "
             << funcCall.targetFunction->getInternalNameStr() << "\n";

      auto &params = funcCall.targetFunction->getParameters();

       outs() << "  Arguments: " << funcCall.arguments.size()
              << ", Parameters: " << params.size() << "\n";
       outs() << "  CallInst has " << inst->getNumArguments() << " arguments:\n";
       for (unsigned i = 0; i < inst->getNumArguments(); ++i) {
         outs() << "    Arg[" << i << "]: " << inst->getArgument(i)->getKindStr() << "\n";
       }

       for (size_t i = 1; i < inst->getNumArguments() && (i-1) < params.size(); ++i) {
         Value *arg = inst->getArgument(i);
         Parameter *param = params[i-1];

         outs() << "  [DEBUG] Checking actual CallInst argument " << i << " (type: " << arg->getKindStr() << ") for taint...\n";

         if (isTainted(arg)) {
          std::string msg = "    [Taint Propagation] Tainted value passed to '" +
                            funcCall.targetFunction->getInternalNameStr().str() +
                            "' at argument #" + std::to_string(i-1) + "\n";
          if (logger_) logger_(msg);
          else outs() << msg;

                                                                             
          auto argumentPaths = getTaintInfo(arg).paths;
          for (const auto &argumentPath : argumentPaths) {
            auto paramPath = argumentPath.path;
            paramPath.push_back(inst);
            markTainted(param, argumentPath.source, paramPath);
            addToWorklist(param, paramPath);
          }
        } else {
        }
      }

      break;
    }
  }
}

void DefUseAnalyzer::handleLoadProperty(
    LoadPropertyInst *inst, const std::vector<Instruction *> &path) {
                                                                        
                                                                        
  if(publicStaticExactReads.count(inst))return;
                                                                                 
                                                                               
  auto next = path;
  next.push_back(inst);
  markTainted(inst, path.front(), next);
  addToWorklist(inst, next);
}

void DefUseAnalyzer::handleStoreProperty(
    StorePropertyInst *inst, const std::vector<Instruction *> &path) {
  auto next = path;
  next.push_back(inst);
                                                                        
  if (inst->getStoredValue() == activeTaintValue) {
    if (auto *name = llvh::dyn_cast<LiteralString>(inst->getProperty()))
      markPropertyTainted(inst->getObject(), name->getValue().str().str(), path.front(), next);
  }
  markTainted(inst, path.front(), next);
  addToWorklist(inst, next);
}

void DefUseAnalyzer::handleLoadFrame(
    LoadFrameInst *inst,
    const std::vector<Instruction *> &path) {
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  if (closureAnalyzer_) {
    if (!isTainted(inst) || shouldPropagateTo(inst)) {
      markTainted(inst, path.front(), newPath);
      addToWorklist(inst, newPath);
    }
  } else {
    if (!isTainted(inst) || shouldPropagateTo(inst)) {
      markTainted(inst, path.front(), newPath);
      addToWorklist(inst, newPath);
    }
  }
}

void DefUseAnalyzer::handleStoreFrame(
    StoreFrameInst *inst, const std::vector<Instruction *> &path) {
  if (inst->getValue() != activeTaintValue) return;
  auto next = path;
  next.push_back(inst);
  markFrameTainted(inst->getEnvironment(), inst->getVariable(), path.front(), next);
  markTainted(inst, path.front(), next);
  addToWorklist(inst, next);
}

void DefUseAnalyzer::handleReturn(
    ReturnInst *inst,
    const std::vector<Instruction *> &path) {
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  if (!isTainted(inst)) {
    markTainted(inst, path.front(), newPath);
  }

}

void DefUseAnalyzer::handleUnaryOp(
    Instruction *inst,
    const std::vector<Instruction *> &path) {
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  if (!isTainted(inst) || shouldPropagateTo(inst)) {
    markTainted(inst, path.front(), newPath);
    addToWorklist(inst, newPath);
  }
}

void DefUseAnalyzer::handleGenericInst(
    Instruction *inst,
    const std::vector<Instruction *> &path) {
  std::vector<Instruction *> newPath = path;
  newPath.push_back(inst);

  if (!isTainted(inst) || shouldPropagateTo(inst)) {
    markTainted(inst, path.front(), newPath);
    addToWorklist(inst, newPath);
  }
}

void DefUseAnalyzer::markTainted(
    Value *v, Instruction *source, const std::vector<Instruction *> &path) {
  assert(!path.empty() && source == path.front() && "source/path identity mismatch");
  auto &info = taintMap_[v];
  for (const auto &existing : info.paths)
    if (existing.source == source) return;
  info.isTainted = true;
  info.paths.emplace_back(source, path, nullptr);
}

bool DefUseAnalyzer::shouldPropagateTo(Value *v) const {
  return true;
}

bool DefUseAnalyzer::isSink(Instruction *inst) const {
  bool found = sinks_.find(inst) != sinks_.end();
  if (!found && llvh::isa<StorePropertyInst>(inst)) {
    outs() << "[DEBUG SINK] StorePropertyInst not found in sinks set. Comparing pointers:\n";
    outs() << "  Current inst: " << inst << "\n";
    for (auto *sink : sinks_) {
      outs() << "  Sink in set: " << sink << " (" << sink->getKindStr() << ")\n";
    }
  }
  return found;
}

bool DefUseAnalyzer::isSource(Instruction *inst) const {
  return sources_.find(inst) != sources_.end();
}

void DefUseAnalyzer::markPropertyTainted(
    Value *object, const std::string &propertyName,
    Instruction *source, const std::vector<Instruction *> &path) {
  assert(!path.empty() && source == path.front());
  std::string key = std::to_string(reinterpret_cast<uintptr_t>(classReceiver(object))) + ":" + propertyName;
  auto &info = propertyTaintMap_[key];
                                                                              
                                                                               
  for (const auto &existing : info.paths)
    if (existing.source == source && existing.path.back() == path.back()) return;
  info.isTainted = true;
  info.paths.emplace_back(source, path);
}

bool DefUseAnalyzer::isPropertyTainted(Value *object, const std::string &propertyName) const {
  std::string key = std::to_string(reinterpret_cast<uintptr_t>(classReceiver(object))) + ":" + propertyName;
  auto it = propertyTaintMap_.find(key);
  return it != propertyTaintMap_.end() && it->second.isTainted;
}

const DefUseAnalyzer::TaintInfo &DefUseAnalyzer::getPropertyTaintInfo(
    Value *object, const std::string &propertyName) const {
  std::string key = std::to_string(reinterpret_cast<uintptr_t>(classReceiver(object))) + ":" + propertyName;
  auto it = propertyTaintMap_.find(key);
  return it != propertyTaintMap_.end() ? it->second : emptyTaintInfo_;
}

void DefUseAnalyzer::checkPropertyTaintConnections() {
  std::unordered_set<Function *> functions;
  for (auto *s : sources_) functions.insert(s->getParent()->getParent());
  for (auto *s : sinks_) functions.insert(s->getParent()->getParent());
  for (auto *function : functions)
    for (BasicBlock &block : *function)
      for (Instruction &instruction : block) {
        auto *load = llvh::dyn_cast<LoadPropertyInst>(&instruction);
        if (!load || publicStaticExactReads.count(load)) continue;
        auto *name = llvh::dyn_cast<LiteralString>(load->getProperty());
        if (!name) continue;
        auto paths = getPropertyTaintInfo(load->getObject(), name->getValue().str().str()).paths;
        auto globalEdge=globalObjectStorage.edges.find(load);
        if(globalEdge!=globalObjectStorage.edges.end()) {
          auto *store=globalEdge->second;
          for(const auto &fact:getPropertyTaintInfo(store->getObject(), name->getValue().str().str()).paths)
            if(!fact.path.empty()&&fact.path.back()==store) {
              bool duplicate=false;
              for(const auto &old:paths)if(old.source==fact.source&&old.path.back()==store)duplicate=true;
              if(!duplicate){paths.push_back(fact);if(!sourceScheduled(load,fact.source))++globalObjectStorageSeeds;}
            }
        }
        for (const auto &fact : paths) {
          if (fact.path.empty()) continue;
          if (definitelyKilledStore(fact.path.back(), load)) {
            ++killedStorageEdges;
            continue;
          }
          if (sourceScheduled(load, fact.source)) continue;
          auto next = fact.path;
          next.push_back(load);
          markTainted(load, fact.source, next);
          addToWorklist(load, next);
        }
      }
}

void DefUseAnalyzer::markFrameTainted(
    Value *environment, Variable *variable,
    Instruction *source, const std::vector<Instruction *> &path) {
  assert(!path.empty() && source == path.front());
  environment = reachingStoreBindingEnvironment(environment, variable);
  std::string key = std::to_string(reinterpret_cast<uintptr_t>(environment)) + ":" +
      std::to_string(reinterpret_cast<uintptr_t>(variable));
  auto &info = frameTaintMap_[key];
  for (const auto &existing : info.paths)
    if (existing.source == source && existing.path.back() == path.back()) return;
  info.isTainted = true;
  info.paths.emplace_back(source, path);
}

bool DefUseAnalyzer::isFrameTainted(Value *environment, Variable *variable) const {
  std::string varName = variable->getName().str().str();
  environment = reachingStoreBindingEnvironment(environment, variable);
  std::string key = std::to_string(reinterpret_cast<uintptr_t>(environment)) + ":" +
      std::to_string(reinterpret_cast<uintptr_t>(variable));
  auto it = frameTaintMap_.find(key);
  return it != frameTaintMap_.end() && it->second.isTainted;
}

const DefUseAnalyzer::TaintInfo &DefUseAnalyzer::getFrameTaintInfo(
    Value *environment, Variable *variable) const {
  std::string varName = variable->getName().str().str();
  environment = reachingStoreBindingEnvironment(environment, variable);
  std::string key = std::to_string(reinterpret_cast<uintptr_t>(environment)) + ":" +
      std::to_string(reinterpret_cast<uintptr_t>(variable));
  auto it = frameTaintMap_.find(key);
  return it != frameTaintMap_.end() ? it->second : emptyTaintInfo_;
}

void DefUseAnalyzer::checkFrameTaintConnections() {
  if (sinks_.empty()) return;
  auto *module = (*sinks_.begin())->getParent()->getParent()->getParent();
  if (indexedFrameModule!=module) {
    indexedFrameLoads.clear(); indexedFrameModule=module;
    for (Function &function : *module)
      for (BasicBlock &block : function)
        for (Instruction &instruction : block)
          if (auto *load=llvh::dyn_cast<LoadFrameInst>(&instruction))
            indexedFrameLoads.push_back(load);
  }
  ++frameRounds; writeFrameMetrics("START");
  for (auto *load : indexedFrameLoads) {
    ++frameLoadsVisited;
    if ((frameLoadsVisited & 511)==0) writeFrameMetrics("SCANNING");
                                                                             
                                                                              
    const auto &paths = getFrameTaintInfo(load->getEnvironment(), load->getLoadVariable()).paths;
    for (const auto &fact : paths) {
      ++frameFacts;
      if (fact.path.empty()) continue;
      if (definitelyKilledStore(fact.path.back(), load)) {
        ++killedStorageEdges;
        continue;
      }
      if (sourceScheduled(load, fact.source)) continue;
      auto next = fact.path;
      next.push_back(load);
      markTainted(load, fact.source, next);
      addToWorklist(load, next);
    }
  }
  writeFrameMetrics("COMPLETE");
}

}

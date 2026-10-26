                                                                          
                                                                              
                                                                            
                                                                          
                                                                       
                                                                            
                                                             
                                                                              
                                                                              
                                                                            
                                                                             
                                                                             
                                                                               
#include "hermes/Support/Conversions.h"
#include <algorithm>
#include <cmath>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace hermes {
namespace {
                                                                        
                                                                             
                                                                 
struct PrivateBindingMetadata {
  Module *module{nullptr};
  size_t instructions{0}, functions{0}, facts{0}, globalWrites{0};
  bool complete{false}, overflow{false};
  std::map<Function *,unsigned> creations;
  std::map<std::string,std::vector<StorePropertyInst *>> bindings;
  void observe(Instruction *i) {
    ++instructions;
    auto *c=llvh::dyn_cast<CreateFunctionInst>(i);
    auto *s=llvh::dyn_cast<StorePropertyInst>(i);
    std::string name;
    if(s&&llvh::isa<GlobalObject>(s->getObject())) {
      if(auto *str=llvh::dyn_cast<LiteralString>(s->getProperty()))
        name=str->getValue().str().str();
      else if(auto *num=llvh::dyn_cast<LiteralNumber>(s->getProperty())) {
        char buffer[NUMBER_TO_STRING_BUF_SIZE];
        auto length=numberToString(num->getValue(),buffer,sizeof(buffer));
        name=std::string(buffer,length);
      }
    }
    const bool write=!name.empty();
    if(!c&&!write)return;
    if(facts>=250000){overflow=true;return;}
    ++facts;
    if(c)++creations[c->getFunctionCode()];
    if(write){bindings[name].push_back(s);++globalWrites;}
  }
};
class BoundedPrivateMethodState {
 public:
  struct Trace { Instruction *source; std::vector<Instruction *> path; };
  struct Read { CallInst *site; std::vector<Trace> traces; };
                                                                                  
  struct SinkFlow { Instruction *site; std::vector<Trace> traces; };
  struct PublicRead {
    LoadPropertyInst *site;
    std::vector<Trace> traces;
                                                                            
                                                                         
    unsigned instance{0};
    std::string property;
    unsigned getter{0};
    bool record{false};
  };
                                                                          
                                                                          
  struct EntryGuardObservation {
    ThrowIfHasRestrictedGlobalPropertyInst *site;
    bool bookkeepingPrefix;
  };
  enum class Completion { NORMAL, PROVED_ABRUPT, UNKNOWN };
  struct UnreachableSink {
    Instruction *sink{nullptr};
    CallInst *outerCall{nullptr};
    CallInst *helperCall{nullptr};
    CallInst *brandCall{nullptr};
    Instruction *throwSite{nullptr};
    Instruction *receiverAllocation{nullptr};
    Instruction *mapAllocation{nullptr};
    CreateFunctionInst *callableCreation{nullptr};
    std::vector<Instruction *> path;
  };

 private:
  using Path = std::vector<Instruction *>;
  enum class Role { None, Redeclare, Brand, FieldInit, MethodInit, Get, Set };
  enum class Classification { UNCLASSIFIED, VISITING, VERIFIED_ROLE, VERIFIED_NON_HELPER, UNKNOWN };
  enum Kind { Invalid, UninitializedBinding, Scalar, Undefined, Null, Global, Scope, Closure,
              Instance, Record, Array, BoundArray, BoundArrayIterator, ConditionalArrayMethod, ConditionalRecordFunction, ArgumentsObject, DateObject, DateNow, Helpers,
              DefineClass, DefineMethod, ReflectObject, ReflectApply,
              WeakMapCtor, WeakSetCtor, WeakMapObject, WeakSetObject, NativePrivateToken, PublicFieldFunction,
              AmbientDocument, AmbientWindow, OpaqueInitializerWindow, ModuleEntry, InheritedCall, NativeStaticMethod, NativePrivateCallable, AsyncPromise, AsyncGeneratorObject, AsyncGeneratorNext, AsyncGeneratorBuiltin, AsyncAwaitMarker, AsyncIteratorResult };
  struct Datum {
    Kind kind{Invalid};
    unsigned ref{0};
    bool knownString{false};
    std::string stringValue;
    bool knownBool{false}, boolValue{false};
    bool knownNumber{false};
    bool numericPrimitive{false};                                                           
    double number{0};
    unsigned receiver{0}, brand{0};
    Instruction *entryRead{nullptr};
    std::vector<Trace> traces;
  };
  struct Slot { Datum value; Instruction *write; };
  struct Environment {
    unsigned parent{0};
                                                                      
                                                                              
    unsigned invocation{0};
    ScopeDesc *description{nullptr};
    Function *function{nullptr};
    ScopeCreationInst *creation{nullptr};
    std::map<Variable *, Datum> variables;
                                                                               
                                                                            
    std::map<Variable *, std::pair<Kind,unsigned>> literalFrameStates;

  };
  struct ClosureInfo {
    Function *body;
    unsigned environment;
    CreateFunctionInst *creation;
    bool isClass{false};
    bool publicFieldFunction{false};
                                                                             
                                                                          
    unsigned nativeDefinitionEnvironment{0};
    std::map<std::string, unsigned> methods;
                                                                              
    std::map<std::string, unsigned> staticMethods;
    struct Accessor { unsigned get{0}, set{0}; };
    std::map<std::string, Accessor> instanceAccessors, staticAccessors;
    std::map<std::string, Datum> ownProperties;
                                                                          
                                                                            
    std::map<std::string, Datum> publicStaticFields;
  };
  struct Object {
    Instruction *allocation{nullptr};
    unsigned allocationEnvironment{0};
    unsigned ctor{0};
    std::map<std::string, Slot> properties;
    std::map<unsigned, Slot> privateSlots;
    std::map<std::string,unsigned> ownGetters;
                                                                          
                                                                            
    std::map<std::string, Slot> publicInstanceFields;
    std::set<unsigned> members;
    std::vector<Datum> elements;
    unsigned iteratorArray{0}, iteratorIndex{0};
                                                                             
    bool moduleTable{false}, modulePublished{false};
    std::map<std::string, Slot> moduleEntries;
    Instruction *modulePublication{nullptr};
  };
  enum Mode { GlobalMode, WrapperMode, ConstructorMode, MethodMode, ModuleMode, NativeInitializerMode, DirectMode, ReduceCallbackMode };
  struct Frame {
    Function *function;
    Mode mode;
    unsigned environment;
    Datum receiver;
    std::vector<Datum> arguments;
    std::set<unsigned> initializerCallbacks;
    bool substitutedGlobalThis{false};
    std::map<Value *, Datum> values;
    std::map<AllocStackInst *, Datum> stack;
    Path calls;
    unsigned definitions{0};
    unsigned privateCallable{0};
    unsigned asyncPromise{0};
    unsigned asyncGenerator{0};
    std::set<BasicBlock *> visited;
  };
  struct Binding {
    AsyncFunction *wrapper{nullptr};
    CreateArgumentsInst *arguments{nullptr};
    CreateFunctionInst *generatorClosure{nullptr};
    GeneratorFunction *generator{nullptr};
    CallInst *spawn{nullptr};
    CreateGeneratorInst *createGenerator{nullptr};
    GeneratorInnerFunction *inner{nullptr};
    CreateScopeInst *innerScope{nullptr};
    BasicBlock *prefix{nullptr};
    std::vector<StoreFrameInst *> formalStores;
    bool parameterActivation{false};
    LoadPropertyInst *activationNext{nullptr};
    CallInst *activationCall{nullptr};
    bool valid{false};
    const char *reason{"WRAPPER_NOT_CERTIFIED"};
  };
  struct AsyncJob { Frame frame; SaveAndYieldInst *suspension{nullptr}; Datum value; };
  struct GeneratorState {
    Frame frame;
    BasicBlock *entry{nullptr};
    SaveAndYieldInst *suspension{nullptr};
    unsigned request{0};
    bool started{false}, done{false}, wrapped{false};
  };
  std::map<unsigned,GeneratorState> generators_;
  std::map<unsigned,Datum> awaitMarkers_;
  unsigned nextGenerator_{1}, nextAwaitMarker_{1};
  struct AsyncFulfillment {
    bool fulfilled{false}; Datum value; Instruction *call{nullptr};
    std::vector<AsyncJob> waiters;
  };
  const PrivateBindingMetadata &metadata_;
  unsigned creationCount(Function *fn) const {
    auto it=metadata_.creations.find(fn);
    return it==metadata_.creations.end()?0:it->second;
  }
  std::map<AsyncFunction *,Binding> asyncBindings_;
  std::map<unsigned,AsyncFulfillment> asyncPromises_;
  std::vector<AsyncJob> asyncQueue_;
  unsigned nextAsyncPromise_{1},asyncResumed_{0};
  Module *module_;
  Function *top_{nullptr};
  const std::vector<Instruction *> &sources_, &sinks_;
  const std::unordered_map<Instruction *, std::string> &ids_;
  const std::map<std::string, std::vector<StorePropertyInst *>> &bindings_;
  std::map<Function *, Role> roles_;
  std::map<Function *, std::set<Function *>> dependencies_;
  std::map<Function *, Classification> classifications_;
  std::map<std::string, Datum> globals_;
  std::map<unsigned, Environment> environments_;
  std::map<unsigned, ClosureInfo> closures_;
  std::map<unsigned, Object> objects_;
  std::map<unsigned, unsigned> nativeTokenEnvironments_;
  unsigned nativeCreates_{0}, nativeInits_{0}, nativeGets_{0}, nativeSets_{0};
  std::set<Function *> active_;
  std::vector<Read> reads_;
  std::vector<PublicRead> publicReads_;
  std::vector<EntryGuardObservation> entryGuards_;
  std::vector<UnreachableSink> unreachableSinks_;
  UnreachableSink abruptWitness_;
  Completion completion_{Completion::UNKNOWN};
  unsigned nextEnvironment_{1}, nextClosure_{1}, nextObject_{1};
  unsigned steps_{0}, depth_{0}, fieldReads_{0}, fieldWrites_{0}, counters_{0};
  unsigned graphCalls_{0},graphVisits_{0},graphPrimitiveVisits_{0},graphObjectVisits_{0};
  Instruction *graphSite_{nullptr};
                                                                           
                                                                               
  std::set<unsigned> primitiveArrayCertificates_;
  unsigned graphCacheHits_{0},graphPrimitiveSkips_{0},graphCacheInvalidations_{0};
  void invalidatePrimitiveArray(unsigned ref) {
    graphCacheInvalidations_+=primitiveArrayCertificates_.erase(ref);
  }
  std::map<unsigned,unsigned> graphRootVisits_,graphRootCalls_;
  struct GraphCertificate {
    Kind kind; unsigned visits,height; std::set<unsigned> children;
  };
  std::map<unsigned,GraphCertificate> graphCertificates_;
  std::map<unsigned,std::set<unsigned>> graphParents_;
  unsigned graphDependencyEdges_{0},nestedCacheHits_{0},nestedVisitsSkipped_{0};
  unsigned nestedInvalidated_{0},nestedAncestorsInvalidated_{0},nestedClears_{0},nestedMaintenance_{0};
  bool graphMaintenance() { ++nestedMaintenance_;return spend(graphSite_); }
  void clearGraphCertificates() {
    if(graphCertificates_.empty()&&graphParents_.empty())return;
    ++nestedClears_;
    const unsigned work=unsigned(graphCertificates_.size())+graphDependencyEdges_;
    for(unsigned n=0;n<work&&!failed_;++n)if(!graphMaintenance())break;
    graphCertificates_.clear();graphParents_.clear();graphDependencyEdges_=0;
  }
  void invalidateGraphCertificate(unsigned ref) {
    if(graphCertificates_.empty()&&graphParents_.empty())return;
    std::vector<unsigned> todo{ref};std::set<unsigned> seen;
    while(!todo.empty()&&!failed_) {
      unsigned n=todo.back();todo.pop_back();if(!seen.insert(n).second)continue;
      auto parents=graphParents_.find(n);
      if(parents!=graphParents_.end())for(unsigned p:parents->second)todo.push_back(p);
      auto cert=graphCertificates_.find(n);if(cert==graphCertificates_.end())continue;
      if(!graphMaintenance())break;
      for(unsigned child:cert->second.children) {
        if(!graphMaintenance())break;
        auto ps=graphParents_.find(child);
        if(ps!=graphParents_.end()) {
          graphDependencyEdges_-=unsigned(ps->second.erase(n));
          if(ps->second.empty())graphParents_.erase(ps);
        }
      }
      graphCertificates_.erase(cert);++nestedInvalidated_;
      if(n!=ref)++nestedAncestorsInvalidated_;
    }
                                                                           
    if(failed_){graphCertificates_.clear();graphParents_.clear();graphDependencyEdges_=0;}
  }
  void certifyGraph(unsigned ref,Kind kind,unsigned visits,unsigned height,const std::set<unsigned>&children) {
    if(failed_||visits>4096||height>64||graphCertificates_.count(ref)||
       graphCertificates_.size()>=8192||children.size()>32768-graphDependencyEdges_)return;
    if(!graphMaintenance())return;
    for(unsigned child:children) {
      if(!graphMaintenance()){graphCertificates_.clear();graphParents_.clear();graphDependencyEdges_=0;return;}
      graphParents_[child].insert(ref);++graphDependencyEdges_;
    }
    graphCertificates_.emplace(ref,GraphCertificate{kind,visits,height,children});
  }

  unsigned metadataInstructions_{0}, metadataFunctions_{0}, metadataGlobalWrites_{0};
  unsigned fingerprintSteps_{0}, executionSteps_{0}, fingerprintCalls_{0};
  unsigned demandedFunctions_{0}, classificationCacheHits_{0}, classificationDepth_{0};
  bool failed_{false}, cutoff_{false}, used_{false}, abrupt_{false};
  const bool additive_, ordinaryEntry_, guardPartition_;
  CallInst *exactDirectEntry_{nullptr};
  Function *exactDirectBody_{nullptr};
  bool exactReadFrame(const Frame &f, Instruction *site) const {
    if(f.mode==GlobalMode && f.calls.empty())return true;
    return !additive_ && exactDirectEntry_ && exactDirectBody_ &&
        f.mode==DirectMode && f.function==exactDirectBody_ && f.calls.size()==1 &&
        f.calls.front()==exactDirectEntry_ && owner(site)==exactDirectBody_ &&
        site->getParent()==&exactDirectBody_->front();
  }
  std::vector<SinkFlow> sinkFlows_;
  std::set<Function *> registeredRecordGetters_, invokedBodies_;
  std::vector<Instruction *> dormantGetterSinks_;
  void collectDormantGetterSinks() {
                                                                                
                                                                               
                                                                           
    if(additive_||failed_||abrupt_||!cutoff_||!entryGuards_.empty()||
       !exactDirectEntry_||!exactDirectBody_||owner(barrier_)!=exactDirectBody_||
       !asyncPromises_.empty()||!generators_.empty())return;
    for(const auto &g:globals_)if(!primitive(g.second))return;
    auto emptyTail=[](Instruction *site) {
      bool after=false;unsigned returns=0;
      std::set<Value *> carried{site};std::set<AllocStackInst *> slots;
      for(auto &i:*site->getParent()) {
        if(&i==site){after=true;continue;}
        if(!after)continue;
                                                                          
                                                                            
        if(auto *store=llvh::dyn_cast<StoreStackInst>(&i)) {
          if(!carried.count(store->getValue()))return false;
          slots.insert(store->getPtr());continue;
        }
        if(auto *load=llvh::dyn_cast<LoadStackInst>(&i)) {
          if(!slots.count(load->getPtr()))return false;
          carried.insert(load);continue;
        }
        auto *r=llvh::dyn_cast<ReturnInst>(&i);
        if(!r||(!llvh::isa<LiteralUndefined>(r->getValue())&&!carried.count(r->getValue())))return false;
        ++returns;
      }
      return after&&returns==1;
    };
    if(!emptyTail(barrier_)||!emptyTail(exactDirectEntry_))return;
    for(auto *sink:sinks_) {
      auto *body=owner(sink);
      if(registeredRecordGetters_.count(body)&&!invokedBodies_.count(body)&&
         creationCount(body)==1)dormantGetterSinks_.push_back(sink);
    }
  }
  const char *reason_{"NO_PROVED_READ"};
  Instruction *barrier_{nullptr};

  static Function *owner(Instruction *i) { return i->getParent()->getParent(); }
  static std::string key(Value *v) {
    if (auto *s = llvh::dyn_cast<LiteralString>(v))
      return s->getValue().str().str();
    if (auto *n = llvh::dyn_cast<LiteralNumber>(v)) {
                                                                         
                                                                         
      char buffer[NUMBER_TO_STRING_BUF_SIZE];
      auto length=numberToString(n->getValue(),buffer,sizeof(buffer));
      return std::string(buffer,length);
    }
    return "";
  }
  static bool before(Instruction *a, Instruction *b) {
    if (!a || !b || a->getParent() != b->getParent()) return false;
    for (auto &i : *a->getParent()) {
      if (&i == b) return false;
      if (&i == a) return true;
    }
    return false;
  }
  std::string id(Instruction *i) const {
    auto it = ids_.find(i); return it == ids_.end() ? "NONE" : it->second;
  }
  static Datum make(Kind k, unsigned ref = 0) { Datum d; d.kind=k; d.ref=ref; return d; }
  static Datum number(double n) { Datum d=make(Scalar); d.knownNumber=true; d.number=n; return d; }
  static bool primitive(const Datum &d) { return d.kind==Scalar || d.kind==Undefined || d.kind==Null; }
  static bool hostName(const std::string &s) {
    return s=="Date" || s=="Reflect" || s=="WeakMap" || s=="WeakSet" ||
        s=="TypeError" || s=="HermesES6Internal" || s=="Function" || s=="document" ||
        s=="window" || s=="self" || s=="globalThis";
  }
  static bool dangerousKey(const std::string &s) {
    return s.empty() || s=="__proto__" || s=="prototype";
  }
  Datum reject(const char *reason, Instruction *at=nullptr) {
    if (!failed_) { reason_=reason; barrier_=at; }
    failed_=true; return {};
  }
  bool spend(Instruction *at=nullptr,bool fingerprint=false) {
    if(fingerprint)++fingerprintSteps_;else ++executionSteps_;
    if (++steps_<=100000) return true;
    reject("PROOF_BUDGET_EXHAUSTED",at); return false;
  }
  bool edge(Datum &d, Instruction *i) {
    if (!i) return false;
    if (d.traces.size()>16) { reject("TRACE_COUNT_LIMIT",i); return false; }
    for (auto &t:d.traces) {
      if (t.path.size()>=512) { reject("TRACE_LENGTH_LIMIT",i); return false; }
      if (t.path.empty() || t.path.back()!=i) t.path.push_back(i);
    }
    return true;
  }
  static const char *roleName(Role r) {
    switch (r) {
      case Role::Redeclare:return "redeclare";
      case Role::Brand:return "brand";
      case Role::FieldInit:return "field-init";
      case Role::MethodInit:return "method-init";
      case Role::Get:return "get";
      case Role::Set:return "set";
      default:return "none";
    }
  }
  StorePropertyInst *binding(const std::string &name) const {
    auto it=bindings_.find(name);
    if (it==bindings_.end() || it->second.size()!=1) return nullptr;
    auto *s=it->second.front();
    return owner(s)==top_ && s->getParent()==&top_->front() ? s : nullptr;
  }
  Function *globalClosure(const std::string &name) const {
    auto *s=binding(name);
    auto *c=s ? llvh::dyn_cast<CreateFunctionInst>(s->getStoredValue()) : nullptr;
    return c && before(c,s) ? c->getFunctionCode() : nullptr;
  }
                                                                             
                                                                                  
  std::string fingerprint(Function *f, std::set<Function *> &references,bool shapeOnly=false) {
    ++fingerprintCalls_;
    if (!f || f->empty()) return "";
    std::map<Instruction *,unsigned> instructions;
    std::map<BasicBlock *,unsigned> blocks;
    std::map<Variable *,unsigned> variables;
    unsigned ni=0,nb=0;
    for (auto &b:*f) {
      blocks[&b]=nb++;
      for (auto &i:b) { if (!spend(&i,true) || ni>=128) return ""; instructions[&i]=ni++; }
    }
    auto operand=[&](Value *v, Instruction *context, unsigned index)->std::string {
      if (auto *i=llvh::dyn_cast<Instruction>(v)) {
        auto it=instructions.find(i); return it==instructions.end()?"?foreign":"i"+std::to_string(it->second);
      }
      if (auto *b=llvh::dyn_cast<BasicBlock>(v)) {
        auto it=blocks.find(b); return it==blocks.end()?"?block":"b"+std::to_string(it->second);
      }
      if (auto *p=llvh::dyn_cast<Parameter>(v)) {
        if (p->getParent()!=f) return "?parameter";
        return p->isThisParameter()?"this":"p"+std::to_string(p->getIndexInParamList());
      }
      if (auto *var=llvh::dyn_cast<Variable>(v)) {
        auto it=variables.find(var);
        if (it==variables.end()) it=variables.emplace(var,variables.size()).first;
        return "v"+std::to_string(it->second);
      }
      if (auto *s=llvh::dyn_cast<ScopeDesc>(v)) return s==f->getFunctionScopeDesc()?"scope":"?scope";
      if (llvh::isa<GlobalObject>(v)) return "global";
      if (llvh::isa<LiteralUndefined>(v)) return "u";
      if (llvh::isa<LiteralNull>(v)) return "null";
      if (auto *b=llvh::dyn_cast<LiteralBool>(v)) return b->getValue()?"true":"false";
      if (auto *n=llvh::dyn_cast<LiteralNumber>(v)) {
        if (n->getValue()==0) return "n0";
        if (n->getValue()==3) return "n3";
        return "?number";
      }
      if (auto *s=llvh::dyn_cast<LiteralString>(v)) {
        auto *p=llvh::dyn_cast<LoadPropertyInst>(context);
        if (p && index==LoadPropertyInst::PropertyIdx && llvh::isa<GlobalObject>(p->getObject())) {
          auto *fn=globalClosure(key(s));
                                                                              
                                                                            
          if(shapeOnly&&fn) { references.insert(fn);return "R:*"; }
          auto it=roles_.find(fn);
          if (it!=roles_.end()) { references.insert(fn); return std::string("R:")+roleName(it->second); }
        }
        return "s["+s->getValue().str().str()+"]";
      }
      return "?operand";
    };
    std::string out="P"+std::to_string(f->getParameters().size())+"\n";
    for (auto &b:*f) {
      out+="B"+std::to_string(blocks[&b])+"\n";
      for (auto &i:b) {
        out+=std::to_string(instructions[&i])+"="+i.getKindStr().str();
        if (auto *u=llvh::dyn_cast<UnaryOperatorInst>(&i)) out+="["+u->getOperatorStr().str()+"]";
        if (auto *v=llvh::dyn_cast<BinaryOperatorInst>(&i)) out+="["+v->getOperatorStr().str()+"]";
        out+="(";
        for (unsigned k=0;k<i.getNumOperands();++k) { if(k)out+=","; out+=operand(i.getOperand(k),&i,k); }
        out+=")\n";
      }
    }
    return out;
  }
                                                                             
                                                                             
  static const char *expected(Role role) {
    switch(role) {
      case Role::Redeclare: return R"IR(P2
B0
0=CreateScopeInst(scope)
1=StoreFrameInst(p0,v0,i0)
2=StoreFrameInst(p1,v1,i0)
3=LoadFrameInst(v1,i0)
4=LoadPropertyInst(i3,s[has])
5=LoadFrameInst(v0,i0)
6=CallInst(i4,u,i3,i5)
7=CondBranchInst(i6,b1,b2)
B1
8=TryLoadGlobalPropertyInst(global,s[TypeError])
9=ConstructInst(i8,i8,u,s[Cannot initialize the same private elements twice on an object])
10=ThrowInst(i9)
B2
11=BranchInst(b3)
B3
12=ReturnInst(u)
B4
13=BranchInst(b3)
)IR";
case Role::Brand: return R"IR(P3
B0
0=CreateScopeInst(scope)
1=CreateArgumentsInst()
2=StoreFrameInst(p0,v0,i0)
3=StoreFrameInst(p1,v1,i0)
4=StoreFrameInst(p2,v2,i0)
5=LoadFrameInst(v0,i0)
6=UnaryOperatorInst[typeof](i5)
7=BinaryOperatorInst[==](s[function],i6)
8=CondBranchInst(i7,b5,b4)
B1
9=LoadPropertyInst(i1,s[length])
10=BinaryOperatorInst[<](i9,n3)
11=CondBranchInst(i10,b8,b7)
B2
12=BranchInst(b3)
B3
13=TryLoadGlobalPropertyInst(global,s[TypeError])
14=ConstructInst(i13,i13,u,s[Private element is not present on this object])
15=ThrowInst(i14)
B4
16=LoadFrameInst(v0,i0)
17=LoadPropertyInst(i16,s[has])
18=LoadFrameInst(v1,i0)
19=CallInst(i17,u,i16,i18)
20=BranchInst(b6)
B5
21=LoadFrameInst(v0,i0)
22=LoadFrameInst(v1,i0)
23=BinaryOperatorInst[===](i21,i22)
24=BranchInst(b6)
B6
25=PhiInst(i23,b5,i19,b4)
26=CondBranchInst(i25,b1,b2)
B7
27=LoadFrameInst(v2,i0)
28=BranchInst(b9)
B8
29=LoadFrameInst(v1,i0)
30=BranchInst(b9)
B9
31=PhiInst(i29,b8,i27,b7)
32=ReturnInst(i31)
B10
33=BranchInst(b3)
B11
34=ReturnInst(u)
)IR";
case Role::FieldInit: return R"IR(P3
B0
0=CreateScopeInst(scope)
1=StoreFrameInst(p0,v0,i0)
2=StoreFrameInst(p1,v1,i0)
3=StoreFrameInst(p2,v2,i0)
4=LoadPropertyInst(global,R:redeclare)
5=LoadFrameInst(v0,i0)
6=LoadFrameInst(v1,i0)
7=CallInst(i4,u,u,i5,i6)
8=LoadFrameInst(v1,i0)
9=LoadPropertyInst(i8,s[set])
10=LoadFrameInst(v0,i0)
11=LoadFrameInst(v2,i0)
12=CallInst(i9,u,i8,i10,i11)
13=ReturnInst(u)
)IR";
case Role::Get: return R"IR(P2
B0
0=CreateScopeInst(scope)
1=StoreFrameInst(p0,v0,i0)
2=StoreFrameInst(p1,v1,i0)
3=LoadFrameInst(v0,i0)
4=LoadPropertyInst(i3,s[get])
5=LoadPropertyInst(global,R:brand)
6=LoadFrameInst(v0,i0)
7=LoadFrameInst(v1,i0)
8=CallInst(i5,u,u,i6,i7)
9=CallInst(i4,u,i3,i8)
10=ReturnInst(i9)
B1
11=ReturnInst(u)
)IR";
case Role::Set: return R"IR(P3
B0
0=CreateScopeInst(scope)
1=StoreFrameInst(p0,v0,i0)
2=StoreFrameInst(p1,v1,i0)
3=StoreFrameInst(p2,v2,i0)
4=LoadFrameInst(v0,i0)
5=LoadPropertyInst(i4,s[set])
6=LoadPropertyInst(global,R:brand)
7=LoadFrameInst(v0,i0)
8=LoadFrameInst(v1,i0)
9=CallInst(i6,u,u,i7,i8)
10=LoadFrameInst(v2,i0)
11=CallInst(i5,u,i4,i9,i10)
12=LoadFrameInst(v2,i0)
13=ReturnInst(i12)
B1
14=ReturnInst(u)
)IR";
case Role::MethodInit: return R"IR(P2
B0
0=CreateScopeInst(scope)
1=StoreFrameInst(p0,v0,i0)
2=StoreFrameInst(p1,v1,i0)
3=LoadPropertyInst(global,R:redeclare)
4=LoadFrameInst(v0,i0)
5=LoadFrameInst(v1,i0)
6=CallInst(i3,u,u,i4,i5)
7=LoadFrameInst(v1,i0)
8=LoadPropertyInst(i7,s[add])
9=LoadFrameInst(v0,i0)
10=CallInst(i8,u,i7,i9)
11=ReturnInst(u)
)IR";
      default:return "";
    }
  }
  static std::string roleShape(Role role) {
    std::string shape=expected(role);
    for(const auto *name:{"redeclare","brand","field-init","method-init","get","set"}) {
      const std::string token=std::string("R:")+name;
      for(size_t pos=0;(pos=shape.find(token,pos))!=std::string::npos;pos+=3)
        shape.replace(pos,token.size(),"R:*");
    }
    return shape;
  }
  bool classify(Function *fn) {
    if(failed_||!fn)return false;
    const auto status=classifications_[fn];
    if(status==Classification::VERIFIED_ROLE||status==Classification::VERIFIED_NON_HELPER) {
      ++classificationCacheHits_;return true;
    }
    if(status==Classification::VISITING) {
      classifications_[fn]=Classification::UNKNOWN;reject("HELPER_DEPENDENCY_CYCLE");return false;
    }
    if(status==Classification::UNKNOWN) { reject("HELPER_CLASSIFICATION_UNKNOWN");return false; }
    if(classificationDepth_>=32) {
      classifications_[fn]=Classification::UNKNOWN;reject("HELPER_CLASSIFICATION_DEPTH_LIMIT");return false;
    }
    classifications_[fn]=Classification::VISITING;++demandedFunctions_;++classificationDepth_;
    std::set<Function *> possibleDependencies;
    const std::string shape=fingerprint(fn,possibleDependencies,true);
    const Role order[]={Role::Redeclare,Role::Brand,Role::FieldInit,Role::MethodInit,Role::Get,Role::Set};
    bool possible=false;
    for(Role role:order)if(shape==roleShape(role)){possible=true;break;}
    if(!failed_&&possible) {
      for(auto *dependency:possibleDependencies)
        if(!classify(dependency))break;
      if(!failed_) {
        std::set<Function *> verifiedDependencies;
        const std::string graph=fingerprint(fn,verifiedDependencies);
        if(!failed_)for(Role role:order)if(graph==expected(role)) {
          roles_[fn]=role;dependencies_[fn]=verifiedDependencies;
          classifications_[fn]=Classification::VERIFIED_ROLE;break;
        }
      }
    }
    --classificationDepth_;
    if(failed_) { classifications_[fn]=Classification::UNKNOWN;return false; }
    if(classifications_[fn]!=Classification::VERIFIED_ROLE)
      classifications_[fn]=Classification::VERIFIED_NON_HELPER;
    return true;
  }
  bool nonHelper(Function *fn) {
    return classify(fn)&&classifications_[fn]==Classification::VERIFIED_NON_HELPER;
  }
  bool index() {
    if (!module_ || !(top_=module_->getTopLevelFunction()) || top_->empty()) {
      reject("MISSING_GLOBAL"); return false;
    }
    if(metadata_.module!=module_ || !metadata_.complete ||
       metadata_.instructions!=ids_.size()) {
      reject("SHARED_METADATA_INCOMPLETE");return false;
    }
    metadataInstructions_=metadata_.instructions;
    metadataFunctions_=metadata_.functions;
    metadataGlobalWrites_=metadata_.globalWrites;
    if(metadata_.overflow){reject("METADATA_FACT_LIMIT");return false;}
    for(auto *g:module_->getGlobalProperties())
      if(g->isDeclared() && hostName(key(g->getName()))) { reject("HOST_INTRINSIC_SHADOWED"); return false; }
                                                                               
                                                                              
    return true;
  }
  Datum value(Value *v,Frame &f,Instruction *use) {
    if(auto *n=llvh::dyn_cast<LiteralNumber>(v))return number(n->getValue());
    if(auto *str=llvh::dyn_cast<LiteralString>(v)){Datum d=make(Scalar);d.knownString=true;d.stringValue=str->getValue().str().str();return d;}
    if(auto *b=llvh::dyn_cast<LiteralBool>(v)){Datum d=make(Scalar);d.knownBool=true;d.boolValue=b->getValue();return d;}
    if(llvh::isa<LiteralEmpty>(v))return make(UninitializedBinding);
    if(llvh::isa<LiteralUndefined>(v))return make(Undefined);
    if(llvh::isa<LiteralNull>(v))return make(Null);
    if(llvh::isa<GlobalObject>(v))return make(Global);
    if(auto *p=llvh::dyn_cast<Parameter>(v)) {
      if(p->getParent()!=f.function)return reject("FOREIGN_PARAMETER",use);
      if(p==f.function->getThisParameter())return f.receiver;
      auto &params=f.function->getParameters();
      for(unsigned n=0;n<params.size();++n)
        if(params[n]==p)return n<f.arguments.size()?f.arguments[n]:make(Undefined);
      return reject("UNRESOLVED_PARAMETER",use);
    }
    auto it=f.values.find(v);return it==f.values.end()?reject("UNRESOLVED_VALUE",use):it->second;
  }
  unsigned environment(unsigned parent,ScopeDesc *description,Function *function,
                       unsigned invocation,Instruction *at) {
    if(nextEnvironment_>128){reject("ENVIRONMENT_LIMIT",at);return 0;}
                                                                           
                                                                          
    if(description&&description->getDynamic()) {
      reject("DYNAMIC_LEXICAL_SCOPE_UNPROVEN",at);return 0;
    }
    if(!description||!description->hasFunction()||description->getFunction()!=function) {
      reject("ENVIRONMENT_DESCRIPTION_OWNER_UNPROVEN",at);return 0;
    }
    if(parent) {
      auto p=environments_.find(parent);
      if(p==environments_.end()||!p->second.creation||
         description->getParent()!=p->second.description) {
        reject("ENVIRONMENT_LEXICAL_PARENT_UNPROVEN",at);return 0;
      }
    } else if(function!=top_||description!=top_->getFunctionScopeDesc()||invocation) {
      reject("ENVIRONMENT_ROOT_UNPROVEN",at);return 0;
    }
    unsigned n=nextEnvironment_++;
    Environment e;e.parent=parent;e.invocation=invocation?invocation:n;
    e.description=description;e.function=function;
    environments_.emplace(n,std::move(e));return n;
  }
  bool currentEnvironment(unsigned n,const Frame &f) const {
    auto it=environments_.find(n);
    return it!=environments_.end()&&it->second.creation&&
      it->second.invocation==f.environment&&it->second.function==f.function;
  }
                                                                            
                                                                             
                                                                  
  unsigned scopeOperand(Value *operand,Frame &f,Instruction *at) {
    auto *creation=llvh::dyn_cast<ScopeCreationInst>(operand);
    Datum d=value(operand,f,at);
    if(failed_)return 0;
    auto it=environments_.find(d.ref);
    if(!creation||owner(creation)!=f.function||d.kind!=Scope||
       !currentEnvironment(d.ref,f)||it->second.creation!=creation||
       it->second.description!=creation->getCreatedScopeDesc()) {
      reject("FRAME_ENVIRONMENT_UNPROVEN",at);return 0;
    }
    return d.ref;
  }
                                                                           
                                                                             
  bool sameInvocationDescendant(unsigned child,unsigned ancestor) const {
    auto base=environments_.find(ancestor);
    if(base==environments_.end()||!base->second.creation)return false;
    for(unsigned hops=0;child&&hops<128;++hops) {
      auto e=environments_.find(child);
      if(e==environments_.end()||!e->second.creation||
         e->second.invocation!=base->second.invocation||
         e->second.function!=base->second.function)return false;
      if(child==ancestor)return true;
      auto p=environments_.find(e->second.parent);
      if(p==environments_.end()||e->second.description->getParent()!=p->second.description)
        return false;
      child=e->second.parent;
    }
    return false;
  }
  unsigned variableEnvironment(unsigned start,Variable *variable,Instruction *at) {
    if(!variable){reject("FRAME_VARIABLE_UNPROVEN",at);return 0;}
    auto *target=variable->getParent();
    if(!target||std::find(target->getVariables().begin(),target->getVariables().end(),variable)==
       target->getVariables().end()) {
      reject("FRAME_VARIABLE_MEMBERSHIP_UNPROVEN",at);return 0;
    }
    // Reading a captured value follows only the environment chain captured at
    // this exact closure's creation and installed at its exact invocation.
    // A missing slot at the correct ScopeDesc does NOT fall through to a
    // different invocation or a same-spelled variable in an outer scope.
    for(unsigned n=start,hops=0;n&&hops<128;++hops) {
      auto e=environments_.find(n);
      if(e==environments_.end()||!e->second.creation)break;
      if(e->second.description==target)return n;
      auto p=environments_.find(e->second.parent);
      if(p==environments_.end()||e->second.description->getParent()!=p->second.description)break;
      n=e->second.parent;
    }
    reject("FRAME_LEXICAL_OWNER_UNRESOLVED",at);return 0;
  }
  unsigned object(Instruction *at) {
                                                                             
                                                                            
    const bool dataPartition=guardPartition_&&at&&
        (llvh::isa<AllocObjectInst>(at)||llvh::isa<AllocArrayInst>(at));
    const unsigned limit=dataPartition?8192:128;
    if(dataPartition&&(nextObject_==129||nextObject_>limit))
      llvh::outs()<<"[PRIVATE_GUARD_OBJECT_BUDGET] at="<<id(at)
        <<" allocated="<<(nextObject_-1)<<" limit="<<limit
        <<" object_struct_bytes="<<sizeof(Object)
        <<" status="<<(nextObject_>limit?"LIMIT":"EXPANDED")
        <<" environment=UNPROVEN export=0 suppression=0\n";
    if(nextObject_>limit){reject(dataPartition?"CONDITIONAL_DATA_OBJECT_LIMIT":"OBJECT_LIMIT",at);return 0;}
                                                                            
    unsigned n=nextObject_++;objects_[n].allocation=at;return n;
  }
  Datum frameLoad(LoadFrameInst *load,Frame &f) {
    unsigned env=scopeOperand(load->getEnvironment(),f,load);
    if(failed_)return {};
    unsigned target=variableEnvironment(env,load->getLoadVariable(),load);
    if(failed_)return {};
    auto &vars=environments_.at(target).variables;
    auto it=vars.find(load->getLoadVariable());
    if(it==vars.end()) {
      if(guardPartition_) {
        const auto &states=environments_.at(target).literalFrameStates;
        auto state=states.find(load->getLoadVariable());
        if(state!=states.end())return make(state->second.first,state->second.second);
      }
      return reject("FRAME_VALUE_UNRESOLVED",load);
    }
    Datum d=it->second;edge(d,load);return d;
  }
  Datum globalRead(const std::string &name,Instruction *at) {
    auto it=globals_.find(name);if(it!=globals_.end()){Datum d=it->second;edge(d,at);return d;}
    if(name=="Date")return make(DateObject);
    if(name=="Reflect")return make(ReflectObject);
    if(name=="WeakMap")return make(WeakMapCtor);
    if(name=="WeakSet")return make(WeakSetCtor);
    if(name=="HermesES6Internal")return make(Helpers);
    if(name=="document")return make(AmbientDocument);
                                                                             
                                                                          
                                                                           
    if(guardPartition_&&name=="self")return reject("GLOBAL_SELF_IDENTITY_UNPROVEN",at);

    if(name=="window"||name=="self"||name=="globalThis")return make(AmbientWindow);
                                                                           
                                                                              
    if(guardPartition_&&name=="Math")return reject("GLOBAL_MATH_IDENTITY_UNPROVEN",at);
    return reject("GLOBAL_VALUE_UNRESOLVED",at);
  }
  unsigned dataArrayLimit() const { return guardPartition_?256:64; }
  bool conditionalArrayElementImpl(
      const Datum &d,unsigned depth,unsigned &work,
      std::set<unsigned>&active,bool partitionRoot=false) {
    if(guardPartition_){++graphCalls_;if(objects_.count(d.ref))++graphRootCalls_[d.ref];}
                                                                             
                                                                            
    struct Frame {
      Datum value;
      unsigned depth,index;
      const Object *object;
      bool primitiveOnly{true};
      unsigned logicalVisits{1},height{1};
      std::set<unsigned> children;
      std::map<std::string,Slot>::const_iterator next,end;
      Frame(const Datum &v,unsigned n):value(v),depth(n),index(0),object(nullptr){}
    };
    std::vector<Frame> stack;
    stack.reserve(65);                                                   
    stack.emplace_back(d,depth);
    auto finish=[&](unsigned visits,unsigned height) {
      stack.pop_back();
      if(!stack.empty()) {
        stack.back().logicalVisits+=visits;
        stack.back().height=std::max(stack.back().height,1+height);
      }
    };
    while(!stack.empty()) {
      Frame &f=stack.back();
      if(!f.object) {
                                                                           
                                                                              
        if(++work>4096) {
          auto root=objects_.find(d.ref);
          reject("DATA_GRAPH_WORK_LIMIT",root==objects_.end()?nullptr:root->second.allocation);
          return false;
        }
        if(guardPartition_){++graphVisits_;if(primitive(f.value))++graphPrimitiveVisits_;else ++graphObjectVisits_;if(objects_.count(d.ref))++graphRootVisits_[d.ref];}
        if(!spend(graphSite_))return false;
        if(primitive(f.value)){finish(1,0);continue;}
        if(!guardPartition_||(f.value.kind!=Record&&f.value.kind!=BoundArray))return false;
        auto found=objects_.find(f.value.ref);if(found==objects_.end())return false;
        const Object &r=found->second;
        if(f.depth>=64){reject("DATA_GRAPH_DEPTH_LIMIT",r.allocation);return false;}
        if(!r.allocation||!r.allocationEnvironment||r.moduleTable||r.modulePublished||
           !r.moduleEntries.empty()||!r.ownGetters.empty()||r.properties.size()>64)return false;
        if(!active.insert(f.value.ref).second){
          reject("ARRAY_RECORD_CYCLE_UNPROVEN",r.allocation);return false;
        }
        f.object=&r;
        if(f.value.kind==Record){f.next=r.properties.begin();f.end=r.properties.end();}
        else if(r.elements.size()>dataArrayLimit()||!r.properties.empty())return false;
        auto cert=graphCertificates_.find(f.value.ref);
                                                                          
                                                                  
        if(!(partitionRoot&&f.depth==0)&&cert!=graphCertificates_.end()&&cert->second.kind==f.value.kind) {
          const auto &c=cert->second;
          if(c.height>64-f.depth){reject("DATA_GRAPH_DEPTH_LIMIT",r.allocation);return false;}
          if(c.visits-1>4096-work){auto root=objects_.find(d.ref);reject("DATA_GRAPH_WORK_LIMIT",root==objects_.end()?nullptr:root->second.allocation);return false;}
          work+=c.visits-1;++nestedCacheHits_;nestedVisitsSkipped_+=c.visits-1;
          const unsigned visits=c.visits,height=c.height;
          active.erase(f.value.ref);finish(visits,height);continue;
        }
        if(f.value.kind==BoundArray&&primitiveArrayCertificates_.count(f.value.ref)) {
                                                                            
                                                                             
          if(r.elements.size()>4096-work) {
            auto root=objects_.find(d.ref);
            reject("DATA_GRAPH_WORK_LIMIT",root==objects_.end()?nullptr:root->second.allocation);
            return false;
          }
          work+=unsigned(r.elements.size());
          ++graphCacheHits_;graphPrimitiveSkips_+=unsigned(r.elements.size());
          const unsigned ref=f.value.ref,visits=unsigned(r.elements.size())+1;
          certifyGraph(ref,BoundArray,visits,1,{});if(failed_)return false;
          active.erase(ref);finish(visits,1);continue;
        }
      }
      const Object &r=*f.object;
      if(f.value.kind==Record) {
        if(f.next==f.end){
          if(!(partitionRoot&&f.depth==0))certifyGraph(f.value.ref,Record,f.logicalVisits,f.height,f.children);
          if(failed_)return false;
          const unsigned visits=f.logicalVisits,height=f.height,ref=f.value.ref;
          active.erase(ref);finish(visits,height);continue;
        }
                                                                          
                                                                            
        if(partitionRoot&&f.depth==0)work=1;
        Datum child=(f.next++)->second.value;
        if(!primitive(child)) {
          f.children.insert(child.ref);
          auto target=objects_.find(child.ref);
          if((child.kind!=BoundArray&&child.kind!=Record)||target==objects_.end()||
             target->second.allocationEnvironment!=r.allocationEnvironment||
             !target->second.allocation||owner(target->second.allocation)!=owner(r.allocation))return false;
        }
        const unsigned childDepth=f.depth+1;
        stack.emplace_back(child,childDepth);
      } else {
        if(f.index==r.elements.size()){
          if(f.primitiveOnly)primitiveArrayCertificates_.insert(f.value.ref);
          certifyGraph(f.value.ref,BoundArray,f.logicalVisits,f.height,f.children);if(failed_)return false;
          const unsigned visits=f.logicalVisits,height=f.height,ref=f.value.ref;
          active.erase(ref);finish(visits,height);continue;
        }
        Datum child=r.elements[f.index++];
        if(!primitive(child)){f.primitiveOnly=false;f.children.insert(child.ref);}
        const unsigned childDepth=f.depth+1;
        stack.emplace_back(child,childDepth);
      }
    }
    return true;
  }
  bool conditionalArrayElement(const Datum &d) {
    unsigned work=0;std::set<unsigned> active;
    return conditionalArrayElementImpl(d,0,work,active);
  }
  bool conditionalRecordReference(const Datum &d) {
    if(!guardPartition_||d.kind!=Record)return false;
    unsigned work=0;std::set<unsigned> active;
    return conditionalArrayElementImpl(d,0,work,active,true);
  }
  Datum propertyRead(LoadPropertyInst *load,Frame &f) {
    const auto name=key(load->getProperty());if(dangerousKey(name))return reject("DYNAMIC_OR_PROTOTYPE_READ",load);
    Datum o=value(load->getObject(),f,load);
    if(guardPartition_&&o.kind==BoundArray) {
      const auto &arr=objects_.at(o.ref);
      for(const auto &element:arr.elements)if(!conditionalArrayElement(element))return reject("ARRAY_HOLE_OR_EFFECT_UNPROVEN",load);
      if(name=="length")return number(arr.elements.size());
      if(name=="reduce"||name=="concat") {
        if(arr.elements.size()>64)return reject("ARRAY_METHOD_SIZE_LIMIT",load);
                                                                          
        for(const auto &element:arr.elements)if(!primitive(element))return reject("ARRAY_METHOD_OBJECT_ELEMENT_UNPROVEN",load);
                                                                                
                                                                               
        llvh::outs()<<"[PRIVATE_GUARD_ARRAY_HYPOTHESIS] at="<<id(load)<<" method="<<name
          <<" identity=UNPROVEN assumption=STANDARD_ARRAY_INTRINSICS_NO_CUSTOM_HOOKS environment=UNPROVEN export=0\n";
        Datum d=make(ConditionalArrayMethod,o.ref);d.stringValue=name;d.entryRead=load;return d;
      }
      unsigned index=0;
      if(name.empty()||name.size()>3||(name.size()>1&&name.front()=='0'))return reject("ARRAY_OWN_KEY_UNPROVEN",load);
      for(char ch:name){if(ch<'0'||ch>'9')return reject("ARRAY_OWN_KEY_UNPROVEN",load);index=index*10+unsigned(ch-'0');}
      if(index>=arr.elements.size())return reject("ARRAY_OWN_INDEX_ABSENT",load);
      Datum d=arr.elements[index];edge(d,load);return d;
    }
    if(o.kind==AsyncGeneratorObject) {
      auto found=generators_.find(o.ref);
      if(!additive_ || found==generators_.end() || !found->second.wrapped || name!="next")
        return reject("ASYNC_GENERATOR_PROPERTY_OUTSIDE_PROFILE",load);
      Datum d=make(AsyncGeneratorNext,o.ref);d.entryRead=load;return d;
    }
    if(o.kind==AsyncIteratorResult) {
      auto found=objects_.find(o.ref);
      if(found==objects_.end() || (name!="value"&&name!="done") ||
         !found->second.properties.count(name))return reject("ASYNC_ITERATOR_RESULT_IDENTITY",load);
      Datum d=found->second.properties.at(name).value;edge(d,load);return d;
    }
    if(o.kind==ArgumentsObject) {
      auto found=objects_.find(o.ref);
      if(found==objects_.end())return reject("ARGUMENTS_IDENTITY_UNPROVEN",load);
      if(name=="length")return number(found->second.elements.size());
      unsigned index=0;
      if(name.empty() || name.size()>2 || (name.size()>1&&name.front()=='0'))
        return reject("ARGUMENTS_KEY_UNPROVEN",load);
      for(char ch:name) {
        if(ch<'0'||ch>'9')return reject("ARGUMENTS_KEY_UNPROVEN",load);
        index=index*10+unsigned(ch-'0');
      }
                                                                            
      if(index>=found->second.elements.size())return reject("ARGUMENTS_INDEX_ABSENT",load);
      Datum d=found->second.elements[index];edge(d,load);return d;
    }
    if(o.kind==OpaqueInitializerWindow)
      return reject("INITIALIZER_WINDOW_PROPERTY_UNPROVEN",load);
    if(o.kind==Global)return globalRead(name,load);
    if(o.kind==AmbientWindow) {
      if(name=="window"||name=="self"||name=="globalThis")return make(AmbientWindow);
      if(name=="Date")return make(DateObject);
      if(name=="document")return make(AmbientDocument);
      return reject("AMBIENT_PROPERTY_UNRESOLVED",load);
    }
    if(o.kind==DateObject&&name=="now")return make(DateNow);
    if(o.kind==ReflectObject&&name=="apply")return make(ReflectApply);
    if(o.kind==Helpers&&name=="defineClass")return make(DefineClass);
    if(o.kind==Helpers&&name=="defineClassMethod")return make(DefineMethod);
    if(o.kind==Closure && closures_[o.ref].isClass) {
      auto &accessors=closures_[o.ref].staticAccessors;
      auto accessor=accessors.find(name);
      if(accessor!=accessors.end()) {
        const unsigned getter=accessor->second.get;
        Datum d=getter ? invoke(getter,{},o,f,load,MethodMode) : make(Undefined);
        if(failed_)return {};
        if(!primitive(d))return reject("CLASS_GETTER_NONSCALAR_RESULT",load);
        edge(d,load);
        if(f.mode==GlobalMode&&f.calls.empty()) {
          if(publicReads_.size()>=64)return reject("PUBLIC_STATIC_READ_LIMIT",load);
          publicReads_.push_back({load,d.traces,0,name,getter});
        }
        return d;
      }
      auto &fields=closures_[o.ref].publicStaticFields;
      auto found=fields.find(name);
      if(found==fields.end()) {
        auto method=closures_[o.ref].staticMethods.find(name);
        if(method==closures_[o.ref].staticMethods.end())
          return reject("PUBLIC_STATIC_OWN_READ_UNPROVEN",load);
        Datum d=make(NativeStaticMethod,method->second);
        d.receiver=o.ref;d.entryRead=load;return d;
      }
      if(fieldValue(found->second)&&!primitive(found->second)) {
        Datum d=found->second;d.kind=PublicFieldFunction;d.entryRead=load;return d;
      }
      if(!primitive(found->second))
        return reject("PUBLIC_STATIC_OWN_READ_UNPROVEN",load);
      Datum d=found->second;edge(d,load);
      if(f.mode==GlobalMode && f.calls.empty()) {
        if(publicReads_.size()>=64)return reject("PUBLIC_STATIC_READ_LIMIT",load);
        publicReads_.push_back({load,d.traces});
      }
      return d;
    }
    if(o.kind==Instance) {
      auto &instance=objects_.at(o.ref);
      auto own=instance.publicInstanceFields.find(name);
      if(own!=instance.publicInstanceFields.end()) {
        if(fieldValue(own->second.value)&&!primitive(own->second.value)) {
          Datum d=own->second.value;d.kind=PublicFieldFunction;d.entryRead=load;return d;
        }
        if(!primitive(own->second.value))return reject("PUBLIC_INSTANCE_NONSCALAR_READ",load);
        Datum d=own->second.value;edge(d,instance.allocation);edge(d,load);++fieldReads_;
        if(f.mode==GlobalMode&&f.calls.empty()) {
          if(publicReads_.size()>=64)return reject("PUBLIC_INSTANCE_READ_LIMIT",load);
          publicReads_.push_back({load,d.traces,o.ref,name});
        }
        return d;
      }
      auto &c=closures_[instance.ctor];
      auto accessor=c.instanceAccessors.find(name);
      if(accessor!=c.instanceAccessors.end()) {
        const unsigned getter=accessor->second.get;
        Datum d=getter ? invoke(getter,{},o,f,load,MethodMode) : make(Undefined);
        if(failed_)return {};
        if(!primitive(d))return reject("CLASS_GETTER_NONSCALAR_RESULT",load);
        edge(d,instance.allocation);edge(d,load);
        if(f.mode==GlobalMode&&f.calls.empty()) {
          if(publicReads_.size()>=64)return reject("PUBLIC_INSTANCE_READ_LIMIT",load);
                                                                        
          publicReads_.push_back({load,d.traces,o.ref,name,getter?getter:~0u});
        }
        return d;
      }
      auto it=c.methods.find(name);
      if(it==c.methods.end())return reject("INSTANCE_METHOD_UNPROVEN",load);
      Datum d=make(Closure,it->second);d.receiver=o.ref;d.entryRead=load;return d;
    }
    if(o.kind==Record) {
      auto &table=objects_[o.ref];
      if(table.moduleTable) {
        auto it=table.moduleEntries.find(name);
        if(!table.modulePublished||it==table.moduleEntries.end())return reject("MODULE_ENTRY_UNPROVEN",load);
        Datum d=it->second.value;d.kind=ModuleEntry;d.receiver=o.ref;d.entryRead=load;return d;
      }
      auto getter=table.ownGetters.find(name);
      if(getter!=table.ownGetters.end()) {
        Datum d=invoke(getter->second,{},o,f,load,MethodMode);
        if(failed_||abrupt_)return {};
        if(!primitive(d))return reject("RECORD_GETTER_NONSCALAR_RETURN",load);
        edge(d,load);
        if(exactReadFrame(f,load)) {
          if(publicReads_.size()>=64)return reject("RECORD_GETTER_READ_LIMIT",load);
          publicReads_.push_back({load,d.traces,o.ref,name,getter->second,true});
        }
        return d;
      }
      auto &props=objects_[o.ref].properties;auto it=props.find(name);
      if(it==props.end())return reject("OWN_RECORD_PROPERTY_UNPROVEN",load);
      Datum d=it->second.value;
      const bool exactLocalRecord=f.mode==MethodMode && f.function->isStrictMode() &&
          table.allocation && owner(table.allocation)==f.function &&
          table.allocationEnvironment==f.environment && !table.moduleTable;
      if((guardPartition_||exactLocalRecord)&&d.kind==Closure) {
                                                                                 
                                                                    
        if(!closures_.count(d.ref)||d.receiver||d.brand||d.entryRead)
          return reject("RECORD_FUNCTION_VALUE_UNPROVEN",load);
        d.kind=ConditionalRecordFunction;d.receiver=o.ref;d.entryRead=load;return d;
      }
      if(guardPartition_&&d.kind==Record) {
        if(!conditionalRecordReference(d))return reject("RECORD_OBJECT_CONTENT_UNPROVEN",load);
        edge(d,load);return d;
      }
      if(guardPartition_&&d.kind==BoundArray) {
        for(const auto &element:objects_.at(d.ref).elements)if(!conditionalArrayElement(element))
          return reject("RECORD_ARRAY_CONTENT_UNPROVEN",load);
        edge(d,load);return d;
      }
      if(!primitive(d))return reject("OWN_RECORD_PROPERTY_UNPROVEN",load);
      edge(d,load);return d;
    }
                                                                             
                                                                                
                                                                               
                                                                               
    if(o.kind==Closure&&o.brand&&name=="call"&&
        !closures_[o.ref].isClass&&nonHelper(closures_[o.ref].body)) {
      if(closures_[o.ref].ownProperties.count("call"))return reject("OWN_CALL_OVERRIDE",load);
      Datum d=o;d.kind=InheritedCall;return d;
    }
                                                                               
                                                                           
    return reject("PROPERTY_RECEIVER_UNPROVEN",load);
  }
  Datum propertyStore(Value *ov,Value *pv,Value *sv,Instruction *at,Frame &f,bool own) {
    Datum o=value(ov,f,at),d=value(sv,f,at);const auto name=key(pv);
    if(failed_)return {};
    if(o.kind==Record||o.kind==BoundArray)invalidateGraphCertificate(o.ref);
    else clearGraphCertificates();
    if(failed_)return {};
    if(o.kind==OpaqueInitializerWindow)
      return reject("INITIALIZER_WINDOW_WRITE_UNPROVEN",at);
    if(f.mode==ModuleMode)return reject("MODULE_WRITE_OR_ESCAPE",at);
    if(dangerousKey(name))return reject("DYNAMIC_OR_PROTOTYPE_WRITE",at);
    if(o.kind==Global) {
      if(f.mode!=GlobalMode||hostName(name))return reject("GLOBAL_OR_HOST_MUTATION",at);
      if(globals_.size()>=128&&!globals_.count(name))return reject("GLOBAL_LIMIT",at);
      auto old=globals_.find(name);
      if(old!=globals_.end()&&!primitive(old->second))return reject("IDENTITY_REBINDING",at);
      if(!(primitive(d)||d.kind==Closure||d.kind==Instance||d.kind==Record||d.kind==WeakMapObject||d.kind==WeakSetObject))
        return reject("GLOBAL_VALUE_UNPROVEN",at);
      if(d.kind==Record&&objects_[d.ref].moduleTable) {
        objects_[d.ref].modulePublished=true;
        if(!objects_[d.ref].modulePublication)objects_[d.ref].modulePublication=at;
      }
      edge(d,at);globals_[name]=d;return make(Undefined);
    }
    if(o.kind==Closure && closures_[o.ref].isClass) {
      auto accessor=closures_[o.ref].staticAccessors.find(name);
      if(accessor!=closures_[o.ref].staticAccessors.end()) {
        if(!accessor->second.set||!primitive(d)||own)
          return reject("CLASS_SETTER_OR_DESCRIPTOR_UNPROVEN",at);
        invoke(accessor->second.set,{d},o,f,at,MethodMode);
        return failed_?Datum{}:make(Undefined);
      }
      auto &fields=closures_[o.ref].publicStaticFields;
                                                                            
                                                                          
      auto &methods=closures_[o.ref].staticMethods;
      if(!primitive(d)||(!fields.count(name)&&!methods.count(name))||
         (f.mode!=GlobalMode&&f.mode!=NativeInitializerMode&&f.mode!=MethodMode))
        return reject("PUBLIC_STATIC_OVERWRITE_UNPROVEN",at);
      if(fields.size()>=64&&!fields.count(name))
        return reject("PUBLIC_STATIC_PROPERTY_LIMIT",at);
                                                                            
                                                                             
      methods.erase(name);edge(d,at);fields[name]=d;return make(Undefined);
    }
    if(o.kind==Instance) {
      auto &fields=objects_.at(o.ref).publicInstanceFields;
      auto found=fields.find(name);
      auto &accessors=closures_[objects_.at(o.ref).ctor].instanceAccessors;
      auto accessor=accessors.find(name);
      if(found==fields.end()&&accessor!=accessors.end()) {
        if(!accessor->second.set||!primitive(d)||own)
          return reject("CLASS_SETTER_OR_DESCRIPTOR_UNPROVEN",at);
        invoke(accessor->second.set,{d},o,f,at,MethodMode);
        return failed_?Datum{}:make(Undefined);
      }
                                                                         
                                                                           
      if(found==fields.end()||!primitive(d)||
         !(f.mode==GlobalMode||f.mode==ConstructorMode||f.mode==MethodMode||f.mode==NativeInitializerMode))
        return reject("PUBLIC_INSTANCE_OVERWRITE_UNPROVEN",at);
      edge(d,at);found->second={d,at};++fieldWrites_;return make(Undefined);
    }
    if(o.kind==BoundArray) {
      invalidatePrimitiveArray(o.ref);
                                                                                
      const bool localRecord=guardPartition_&&(d.kind==Record||d.kind==BoundArray)&&conditionalArrayElement(d)&&
          objects_.at(o.ref).allocationEnvironment==f.environment &&
          owner(objects_.at(o.ref).allocation)==f.function &&
          objects_.at(d.ref).allocationEnvironment==f.environment &&
          owner(objects_.at(d.ref).allocation)==f.function;
      if(!additive_||!own||(!primitive(d)&&!localRecord))return reject("ARRAY_ELEMENT_WRITE_UNPROVEN",at);
      auto &a=objects_.at(o.ref);unsigned index=0;
      if(name.empty()||name.size()>(guardPartition_?3:2)||(name.size()>1&&name.front()=='0'))return reject("ARRAY_KEY_UNPROVEN",at);
      for(char c:name){if(c<'0'||c>'9')return reject("ARRAY_KEY_UNPROVEN",at);index=index*10+unsigned(c-'0');}
      if(index>=a.elements.size())return reject("ARRAY_INDEX_UNPROVEN",at);
                                                                            
                                                                                 
      invalidatePrimitiveArray(o.ref);
      invalidateGraphCertificate(o.ref);if(failed_)return {};
      edge(d,at);a.elements[index]=d;return make(Undefined);
    }
    if(o.kind==Record) {
      auto &table=objects_[o.ref];
      const bool exactLocalClosure=f.mode==MethodMode && f.function->isStrictMode() &&
          d.kind==Closure;
      if((guardPartition_||exactLocalClosure)&&f.mode!=GlobalMode&&!table.moduleTable &&
         (d.kind==Closure||d.kind==BoundArray||d.kind==Record)) {
                                                                                   
        if(!table.allocation||table.allocationEnvironment!=f.environment||
           owner(table.allocation)!=f.function||!table.ownGetters.empty()||
           (!own&&!table.properties.count(name)))return reject("RECORD_REFERENCE_TARGET_UNPROVEN",at);
        if(d.kind==Closure) {
          auto found=closures_.find(d.ref);
          if(found==closures_.end()||found->second.isClass||d.receiver||d.brand||d.entryRead||
             !d.traces.empty()||!found->second.creation||owner(found->second.creation)!=f.function||
             !sameInvocationDescendant(found->second.environment,f.environment))
            return reject("RECORD_FUNCTION_CAPTURE_UNPROVEN",at);
        } else if(d.kind==Record) {
          auto found=objects_.find(d.ref);
          if(found==objects_.end()||found->second.allocationEnvironment!=f.environment||
             !found->second.allocation||owner(found->second.allocation)!=f.function)
            return reject("RECORD_OBJECT_OWNER_UNPROVEN",at);
          if(!conditionalRecordReference(d))return reject("RECORD_OBJECT_CONTENT_UNPROVEN",at);
        } else {
          const auto &array=objects_.at(d.ref);
          if(array.allocationEnvironment!=f.environment||!array.allocation||
             owner(array.allocation)!=f.function)return reject("RECORD_ARRAY_OWNER_UNPROVEN",at);
          for(const auto &element:array.elements)if(!conditionalArrayElement(element))
            return reject("RECORD_ARRAY_CONTENT_UNPROVEN",at);
        }
        if(table.properties.size()>=64&&!table.properties.count(name))return reject("RECORD_PROPERTY_LIMIT",at);
                                                                                 
        invalidateGraphCertificate(o.ref);if(failed_)return {};
        edge(d,at);table.properties[name]={d,at};return make(Undefined);
      }
      if(table.moduleTable||d.kind==Closure) {
        if(f.mode!=GlobalMode||!own||table.modulePublished||!table.properties.empty()||
            owner(table.allocation)!=top_||d.kind!=Closure||d.brand||d.receiver||
            closures_[d.ref].isClass||owner(closures_[d.ref].creation)!=top_||
            closures_[d.ref].environment!=f.environment||table.moduleEntries.size()>=16||
            !table.moduleEntries.emplace(name,Slot{d,at}).second)
          return reject("MODULE_TABLE_DEFINITION_OR_MUTATION_UNPROVEN",at);
        table.moduleTable=true;return make(Undefined);
      }
      if(table.ownGetters.count(name)) {
        if(!own)return reject("RECORD_GETTER_ASSIGNMENT_UNPROVEN",at);
        table.ownGetters.erase(name);
      }
      auto &props=objects_[o.ref].properties;
                                                                             
                                                                             
      if(!primitive(d)||(!own&&!props.count(name)))return reject("RECORD_WRITE_UNPROVEN",at);
      if(props.size()>=64&&!props.count(name))return reject("RECORD_PROPERTY_LIMIT",at);
                                                                         
                                                                         
      const bool localRecord=((f.mode==MethodMode && f.function->isStrictMode()) ||
          (own && (f.mode==MethodMode || f.mode==DirectMode))) &&
          table.allocationEnvironment==f.environment && table.allocation &&
          owner(table.allocation)==f.function;
      if(f.mode!=GlobalMode && !localRecord && (!d.knownNumber||!d.traces.empty()))
        return reject("NONNUMERIC_COUNTER_EFFECT",at);
      invalidateGraphCertificate(o.ref);if(failed_)return {};
      edge(d,at);props[name]={d,at};if(f.mode!=GlobalMode)++counters_;return make(Undefined);
    }
    if(o.kind==Closure && f.mode==GlobalMode && o.brand &&
        (name=="call"||name=="apply") && d.kind==Closure &&
        !closures_[o.ref].isClass && nonHelper(closures_[o.ref].body)) {
      closures_[o.ref].ownProperties[name]=d;return make(Undefined);
    }
    return reject("UNKNOWN_WRITE_OR_ESCAPE",at);
  }
  bool dependenciesReady(Function *fn,Instruction *at,std::set<Function *> &seen) {
    if(!seen.insert(fn).second)return true;
    if(seen.size()>32||!roles_.count(fn))return false;
    for(auto *dep:dependencies_[fn]) {
      bool found=false;
      for(const auto &g:globals_)if(g.second.kind==Closure&&closures_[g.second.ref].body==dep) {
        auto *s=binding(g.first);if(s&&before(s,at)){found=true;break;}
      }
      if(!found||!dependenciesReady(dep,at,seen))return false;
    }
    return true;
  }
  static Instruction *nth(Function *fn,unsigned n) {
    for(auto &b:*fn)for(auto &i:b)if(n--==0)return &i;return nullptr;
  }
  bool helperEdges(Datum &d,Function *fn,const std::vector<unsigned> &indices,Instruction *call) {
    for(unsigned n:indices)if(!edge(d,nth(fn,n)))return false;
    return edge(d,call);
  }
  Datum proveBrandAbrupt(Function *get,const Datum &map,const Datum &receiver,
                         Frame &f,CallInst *site) {
                                                                           
                                                                              
                                                                
    if(f.mode!=MethodMode||!f.privateCallable||receiver.kind!=Record||
        map.kind!=WeakMapObject||objects_[map.ref].privateSlots.count(receiver.ref)||
        f.calls.empty()||cutoff_||abrupt_||
        !llvh::isa<ReturnInst>(top_->front().getTerminator()))
      return reject("ABRUPT_CONTEXT_UNPROVEN",site);
    auto *allocation=llvh::dyn_cast<AllocObjectInst>(objects_[receiver.ref].allocation);
    auto *outer=llvh::dyn_cast<CallInst>(f.calls.front());
    auto *brandCall=llvh::dyn_cast_or_null<CallInst>(nth(get,8));
    if(!allocation||!llvh::isa<EmptySentinel>(allocation->getParentObject())||
        !outer||owner(outer)!=top_||outer->getParent()!=&top_->front()||!brandCall)
      return reject("ABRUPT_IDENTITY_UNPROVEN",site);
    Function *brand=nullptr;
    for(auto *dependency:dependencies_[get]) {
      if(roles_[dependency]!=Role::Brand||brand)return reject("ABRUPT_BRAND_GRAPH_UNPROVEN",site);
      brand=dependency;
    }
    auto *throwSite=brand?llvh::dyn_cast_or_null<ThrowInst>(nth(brand,15)):nullptr;
    if(!brand||!throwSite||roles_[get]!=Role::Get)
      return reject("ABRUPT_THROW_GRAPH_UNPROVEN",site);
                                                                              
                                                                          
                                                                            
                                                                            
    abruptWitness_.outerCall=outer;abruptWitness_.helperCall=site;
    abruptWitness_.brandCall=brandCall;abruptWitness_.throwSite=throwSite;
    abruptWitness_.receiverAllocation=allocation;
    abruptWitness_.mapAllocation=objects_[map.ref].allocation;
    abruptWitness_.callableCreation=closures_[f.privateCallable].creation;
    abruptWitness_.path=f.calls;abruptWitness_.path.push_back(site);
    for(unsigned n:{0u,1u,2u,3u,4u,5u,6u,7u,8u})abruptWitness_.path.push_back(nth(get,n));
    for(unsigned n:{0u,1u,2u,3u,4u,5u,6u,7u,8u,16u,17u,18u,19u,20u,25u,26u,12u,13u,14u,15u})
      abruptWitness_.path.push_back(nth(brand,n));
    abrupt_=true;reason_="VERIFIED_PRIVATE_BRAND_TYPEERROR";barrier_=throwSite;
    return {};
  }
  Datum helper(unsigned closure,const std::vector<Datum> &args,Frame &f,CallInst *site) {
    auto *fn=closures_[closure].body;Role role=roles_[fn];
    Instruction *outer=f.calls.empty()?static_cast<Instruction *>(site):f.calls.front();
    std::set<Function *> seen;
    if(!dependenciesReady(fn,outer,seen))return reject("HELPER_DEPENDENCY_NOT_INITIALIZED",site);
    if(role==Role::MethodInit || role==Role::FieldInit) {
      unsigned count=role==Role::MethodInit?2:3;
      if(args.size()!=count||args[0].kind!=Instance||f.mode!=ConstructorMode||args[0].ref!=f.receiver.ref)
        return reject("PRIVATE_INITIALIZATION_RECEIVER_UNPROVEN",site);
      Datum map=args[1];unsigned receiver=args[0].ref;
      if(role==Role::MethodInit) {
        if(map.kind!=WeakSetObject||objects_[map.ref].members.count(receiver))return reject("PRIVATE_BRAND_REDECLARATION",site);
        objects_[map.ref].members.insert(receiver);return make(Undefined);
      }
      if(map.kind!=WeakMapObject||objects_[map.ref].privateSlots.count(receiver)||!primitive(args[2]))
        return reject("PRIVATE_FIELD_INITIALIZATION_UNPROVEN",site);
      Datum d=args[2];helperEdges(d,fn,{3,11,12},site);
      objects_[map.ref].privateSlots[receiver]={d,site};++fieldWrites_;return make(Undefined);
    }
    if(role==Role::Brand) {
      if(args.size()!=3||args[0].kind!=WeakSetObject||args[1].kind!=Instance||args[2].kind!=Closure||
          !objects_[args[0].ref].members.count(args[1].ref)||!nonHelper(closures_[args[2].ref].body))
        return reject("PRIVATE_METHOD_BRAND_UNPROVEN",site);
      Datum d=args[2];d.receiver=args[1].ref;d.brand=args[0].ref;return d;
    }
    if(role==Role::Get||role==Role::Set) {
      if(role==Role::Get&&args.size()==2&&args[0].kind==WeakMapObject&&args[1].kind==Record)
        return proveBrandAbrupt(fn,args[0],args[1],f,site);
      if(args.size()!=(role==Role::Get?2u:3u)||args[0].kind!=WeakMapObject||args[1].kind!=Instance)
        return reject("PRIVATE_FIELD_RECEIVER_UNPROVEN",site);
      auto &slots=objects_[args[0].ref].privateSlots;auto it=slots.find(args[1].ref);
      if(it==slots.end())return reject("PRIVATE_FIELD_BRAND_OR_INIT_UNPROVEN",site);
      if(role==Role::Set) {
        if(!primitive(args[2]))return reject("NONSCALAR_PRIVATE_WRITE",site);
        Datum d=args[2];helperEdges(d,fn,{3,10,11,12,13},site);
        for(auto i=f.calls.rbegin();i!=f.calls.rend();++i)edge(d,*i);
        it->second={d,site};++fieldWrites_;return d;
      }
      Datum d=it->second.value;edge(d,objects_[args[1].ref].allocation);
      helperEdges(d,fn,{3,9,10},site);++fieldReads_;return d;
    }
    return reject("UNSUPPORTED_HELPER_INVOCATION",site);
  }
  Instruction *sourceCall(CallInst *call) const {
    if(std::find(sources_.begin(),sources_.end(),call)!=sources_.end())return call;
    auto *p=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
    if(p&&std::find(sources_.begin(),sources_.end(),p)!=sources_.end())return p;
    return nullptr;
  }
  Binding recognizePrivateAsync(AsyncFunction *function) {
    Binding b; b.wrapper = function;
    auto bad = [&](const char *reason) { b.reason = reason; return b; };
    if (function->isLazy() || function->empty() ||
        function->getBasicBlockList().size() != 1 ||
        !function->getParameters().empty() || creationCount(function) != 1)
      return bad("ASYNC_FUNCTION_KIND_OR_SHAPE");
    CreateScopeInst *scope = nullptr;
    GetBuiltinClosureInst *builtin = nullptr;
    ReturnInst *ret = nullptr;
    std::set<CreateFunctionInst *> hoists;
    for (auto &i : function->front()) {
      if (auto *s = llvh::dyn_cast<CreateScopeInst>(&i)) {
        if (scope || s->getCreatedScopeDesc() != function->getFunctionScopeDesc()) return bad("WRAPPER_SCOPE");
        scope = s;
      } else if (auto *a = llvh::dyn_cast<CreateArgumentsInst>(&i)) {
        if (!scope || b.arguments) return bad("WRAPPER_ARGUMENTS");
        b.arguments = a;
      } else if (auto *s = llvh::dyn_cast<StoreFrameInst>(&i)) {
        auto *closure = llvh::dyn_cast<CreateFunctionInst>(s->getValue());
        if (!scope || b.spawn || s->getEnvironment() != scope ||
            s->getVariable()->getParent() != function->getFunctionScopeDesc() ||
            (!(llvh::isa<LiteralUndefined>(s->getValue()) || llvh::isa<LiteralEmpty>(s->getValue())) && (!closure || !hoists.count(closure))))
          return bad("WRAPPER_FRAME_EFFECT");
      } else if (auto *c = llvh::dyn_cast<CreateFunctionInst>(&i)) {
        if (!scope || b.spawn || llvh::isa<CreateGeneratorInst>(c) ||
            c->getEnvironment() != scope) return bad("WRAPPER_GENERATOR_CLOSURE");
        if (auto *generator = llvh::dyn_cast<GeneratorFunction>(c->getFunctionCode())) {
          if (b.generatorClosure) return bad("WRAPPER_MULTIPLE_GENERATORS");
          b.generatorClosure = c; b.generator = generator;
        } else {
          if (llvh::isa<GeneratorInnerFunction>(c->getFunctionCode())) return bad("WRAPPER_HOIST_KIND");
          hoists.insert(c);
        }
      } else if (auto *g = llvh::dyn_cast<GetBuiltinClosureInst>(&i)) {
        if (builtin || g->getBuiltinIndex() != BuiltinMethod::HermesBuiltin_spawnAsync)
          return bad("SPAWN_BUILTIN_IDENTITY");
        builtin = g;
      } else if (auto *c = llvh::dyn_cast<CallInst>(&i)) {
        if (b.spawn || llvh::isa<ConstructInst>(c) || llvh::isa<CallBuiltinInst>(c) ||
            !builtin || !b.generatorClosure || !b.arguments || c->getCallee() != builtin ||
            c->getNumArguments() != 4 || !llvh::isa<LiteralUndefined>(c->getNewTarget()) ||
            !llvh::isa<LiteralUndefined>(c->getArgument(0)) ||
            c->getArgument(1) != b.generatorClosure ||
            c->getArgument(2) != function->getThisParameter() ||
            c->getArgument(3) != b.arguments) return bad("SPAWN_OPERAND_IDENTITY");
        b.spawn = c;
      } else if (auto *r = llvh::dyn_cast<ReturnInst>(&i)) {
        if (!b.spawn || r->getValue() != b.spawn) return bad("WRAPPER_RETURN");
        ret = r;
      } else return bad("WRAPPER_UNKNOWN_INSTRUCTION");
    }
    if (!scope || !ret || !b.generator || creationCount(b.generator) != 1 ||
        b.generator->isLazy() || b.generator->getBasicBlockList().size() != 1 ||
        !b.generator->getParameters().empty()) return bad("GENERATOR_WRAPPER_KIND");
    for (auto *u : b.arguments->getUsers()) if (u != b.spawn) return bad("ARGUMENTS_ESCAPE");
    for (auto *u : b.generatorClosure->getUsers()) if (u != b.spawn) return bad("GENERATOR_CLOSURE_ESCAPE");
    for (auto *u : builtin->getUsers()) if (u != b.spawn) return bad("BUILTIN_CLOSURE_ESCAPE");
    for (auto *c : hoists) for (auto *u : c->getUsers()) {
      auto *s = llvh::dyn_cast<StoreFrameInst>(u);
      if (!s || s->getValue() != c || s->getEnvironment() != scope ||
          s->getVariable()->getParent() != function->getFunctionScopeDesc()) return bad("WRAPPER_HOIST_ESCAPE");
    }
    hoists.clear();
    scope = nullptr; ret = nullptr;
    for (auto &i : b.generator->front()) {
      if (auto *s = llvh::dyn_cast<CreateScopeInst>(&i)) {
        if (scope || s->getCreatedScopeDesc() != b.generator->getFunctionScopeDesc()) return bad("GENERATOR_SCOPE");
        scope = s;
      } else if (auto *s = llvh::dyn_cast<StoreFrameInst>(&i)) {
        auto *closure = llvh::dyn_cast<CreateFunctionInst>(s->getValue());
        if (!scope || b.createGenerator || s->getEnvironment() != scope ||
            s->getVariable()->getParent() != b.generator->getFunctionScopeDesc() ||
            (!(llvh::isa<LiteralUndefined>(s->getValue()) || llvh::isa<LiteralEmpty>(s->getValue())) && (!closure || !hoists.count(closure))))
          return bad("GENERATOR_FRAME_EFFECT");
      } else if (auto *c = llvh::dyn_cast<CreateGeneratorInst>(&i)) {
        if (!scope || b.createGenerator || c->getEnvironment() != scope) return bad("CREATE_GENERATOR_IDENTITY");
        b.createGenerator = c;
        b.inner = llvh::dyn_cast<GeneratorInnerFunction>(c->getFunctionCode());
      } else if (auto *c = llvh::dyn_cast<CreateFunctionInst>(&i)) {
        if (!scope || b.createGenerator || c->getEnvironment() != scope ||
            llvh::isa<GeneratorFunction>(c->getFunctionCode()) ||
            llvh::isa<GeneratorInnerFunction>(c->getFunctionCode())) return bad("GENERATOR_HOIST_KIND");
        hoists.insert(c);
      } else if (auto *r = llvh::dyn_cast<ReturnInst>(&i)) {
        if (!b.createGenerator || r->getValue() != b.createGenerator) return bad("GENERATOR_RETURN");
        if(b.activationNext && !b.activationCall)return bad("PARAMETER_ACTIVATION_INCOMPLETE");
        ret = r;
      } else if(auto *l=llvh::dyn_cast<LoadPropertyInst>(&i)) {
        if(!b.createGenerator || b.activationNext || l->getObject()!=b.createGenerator ||
           key(l->getProperty())!="next")return bad("PARAMETER_ACTIVATION_LOOKUP");
        b.activationNext=l;
      } else if(auto *c=llvh::dyn_cast<CallInst>(&i)) {
        if(!b.activationNext || b.activationCall || llvh::isa<CallBuiltinInst>(c) ||
           llvh::isa<ConstructInst>(c) || c->getCallee()!=b.activationNext ||
           c->getNumArguments()!=1 || c->getArgument(0)!=b.createGenerator ||
           !llvh::isa<LiteralUndefined>(c->getNewTarget()) || !c->getUsers().empty())
          return bad("PARAMETER_ACTIVATION_CALL");
        b.activationCall=c;b.parameterActivation=true;
      } else return bad("GENERATOR_NON_SIMPLE_PARAMETERS_OR_EFFECT");
    }
    if (!ret || !b.inner || b.inner->isLazy() || b.inner->empty() ||
        creationCount(b.inner) != 1 || b.inner->getParameters().size() > 16)
      return bad("INNER_KIND_OR_LIMIT");
    for (auto *u : b.createGenerator->getUsers())
      if (u != ret && u!=b.activationNext && u!=b.activationCall) return bad("GENERATOR_OBJECT_ESCAPE");
    if(b.activationNext)for(auto *u:b.activationNext->getUsers())
      if(u!=b.activationCall)return bad("PARAMETER_NEXT_ESCAPE");
    for (auto *c : hoists) for (auto *u : c->getUsers()) {
      auto *s = llvh::dyn_cast<StoreFrameInst>(u);
      if (!s || s->getValue() != c || s->getEnvironment() != scope ||
          s->getVariable()->getParent() != b.generator->getFunctionScopeDesc()) return bad("GENERATOR_HOIST_ESCAPE");
    }
    for (auto &block : *b.inner) for (auto &i : block)
      if (llvh::isa<CreateArgumentsInst>(&i)) return bad("INNER_ARGUMENTS_OUTSIDE_PROFILE");
    std::vector<Instruction *> entry;
    for (auto &i : b.inner->front()) entry.push_back(&i);
    if (entry.size() != 6) return bad("INNER_START_PROLOGUE_SIZE");
    b.innerScope = llvh::dyn_cast<CreateScopeInst>(entry[0]);
    auto *slot = llvh::dyn_cast<AllocStackInst>(entry[2]);
    auto *resume = llvh::dyn_cast<ResumeGeneratorInst>(entry[3]);
    auto *load = llvh::dyn_cast<LoadStackInst>(entry[4]);
    auto *branch = llvh::dyn_cast<CondBranchInst>(entry[5]);
    if (!b.innerScope || b.innerScope->getCreatedScopeDesc() != b.inner->getFunctionScopeDesc() ||
        !llvh::isa<StartGeneratorInst>(entry[1]) || !slot || !resume || !load || !branch ||
        resume->getIsReturn() != slot || load->getPtr() != slot || branch->getCondition() != load ||
        branch->getTrueDest() == branch->getFalseDest() ||
        branch->getFalseDest() == &b.inner->front()) return bad("INNER_START_PROLOGUE_IDENTITY");
    auto *returnBlock = branch->getTrueDest();
    if (returnBlock->size() != 1) return bad("INNER_RETURN_RESUME_BLOCK");
    auto *initialReturn = llvh::dyn_cast<ReturnInst>(&returnBlock->front());
    if (!initialReturn || initialReturn->getValue() != resume) return bad("INNER_RETURN_RESUME_VALUE");
    b.prefix = branch->getFalseDest();
    auto it = b.prefix->begin();
    if(b.parameterActivation) {
      if(it==b.prefix->end() || !llvh::isa<AllocStackInst>(&*it))
        return bad("PARAMETER_ACTIVATION_RESUME_SLOT");
      ++it;
    }
    for (auto *formal : b.inner->getParameters()) {
      if (it == b.prefix->end()) return bad("FORMAL_STORE_MISSING");
      auto *store = llvh::dyn_cast<StoreFrameInst>(&*it++);
      if (!store || store->getValue() != formal || store->getEnvironment() != b.innerScope ||
          store->getVariable()->getParent() != b.inner->getFunctionScopeDesc()) return bad("FORMAL_STORE_IDENTITY");
      b.formalStores.push_back(store);
    }
    b.valid = true; b.reason = "EXACT_COMPILER_ASYNC_WRAPPER"; return b;
  }

  unsigned asyncScope(Function *fn,unsigned parent,Instruction *at) {
    if(!fn || fn->empty() || !parent || !environments_.count(parent) ||
       fn->getFunctionScopeDesc()->getParent()!=environments_.at(parent).description)
      return reject("ASYNC_SCOPE_PARENT_UNPROVEN",at),0;
    unsigned env=environment(parent,fn->getFunctionScopeDesc(),fn,0,at);
    if(failed_)return 0;
    for(auto &i:fn->front()) {
      if(auto *scope=llvh::dyn_cast<CreateScopeInst>(&i))
        environments_.at(env).creation=scope;
      if(auto *store=llvh::dyn_cast<StoreFrameInst>(&i)) {
        if(!llvh::isa<LiteralUndefined>(store->getValue()) && !llvh::isa<LiteralEmpty>(store->getValue()))
          return reject("ASYNC_WRAPPER_HOIST_UNSUPPORTED",store),0;
        environments_.at(env).variables[store->getVariable()]=make(llvh::isa<LiteralEmpty>(store->getValue())?UninitializedBinding:Undefined);
      }
    }
    return env;
  }
  void fulfillPrivateAsync(unsigned token,Datum d,Instruction *site) {
    auto found=asyncPromises_.find(token);
    if(found==asyncPromises_.end() || found->second.fulfilled || !(primitive(d)||d.kind==AsyncIteratorResult)) {
      reject("ASYNC_FULFILLMENT_OR_ASSIMILATION_UNPROVEN",site);return;
    }
    edge(d,site);edge(d,found->second.call);
    found->second.fulfilled=true;found->second.value=d;
    for(auto &job:found->second.waiters) {
      if(asyncQueue_.size()>=128){reject("ASYNC_JOB_LIMIT",site);return;}
      job.value=d;edge(job.value,job.suspension);asyncQueue_.push_back(std::move(job));
    }
    found->second.waiters.clear();
  }
  BasicBlock *resumePrivateAsync(AsyncJob &job) {
    auto *y=job.suspension;auto &f=job.frame;
    if(!y || !y->getNextBlock() || y->getNextBlock()->getParent()!=f.function ||
       !(primitive(job.value)||job.value.kind==AsyncIteratorResult))return reject("ASYNC_RESUME_IDENTITY",y),nullptr;
    std::vector<Instruction *> ins;for(auto &i:*y->getNextBlock())ins.push_back(&i);
    if(ins.size()!=3)return reject("ASYNC_RESUME_SHAPE",y),nullptr;
    auto *r=llvh::dyn_cast<ResumeGeneratorInst>(ins[0]);
    auto *l=llvh::dyn_cast<LoadStackInst>(ins[1]);
    auto *b=llvh::dyn_cast<CondBranchInst>(ins[2]);
    auto *slot=r?llvh::dyn_cast<AllocStackInst>(r->getIsReturn()):nullptr;
    if(!r||!l||!b||!slot||!f.values.count(slot)||owner(slot)!=f.function||l->getPtr()!=slot||
       b->getCondition()!=l||b->getTrueDest()==b->getFalseDest()||
       b->getTrueDest()->size()!=1)return reject("ASYNC_RESUME_OPERANDS",y),nullptr;
    auto *ret=llvh::dyn_cast<ReturnInst>(&b->getTrueDest()->front());
    if(!ret||ret->getValue()!=r)return reject("ASYNC_RESUME_RETURN_ARM",y),nullptr;
    Datum d=job.value;edge(d,r);f.values[r]=d;
    ++asyncResumed_;
    return b->getFalseDest();
  }
  bool boundedArgument(const Datum &a) {
    if(additive_&&a.kind==BoundArray){
      auto array=objects_.find(a.ref);if(array==objects_.end())return false;
      for(const auto &element:array->second.elements)if(!primitive(element))return false;
      return true;
    }

    if(primitive(a))return true;
    if(a.kind!=Record)return false;
    auto it=objects_.find(a.ref);
    if(it==objects_.end()||!it->second.allocation||it->second.moduleTable)return false;
    for(const auto &entry:it->second.properties)if(!primitive(entry.second.value))return false;
    return true;
  }
                                                                           
                                                                          
                                                                              
  bool initializerArgument(const Datum &a) {
    if(boundedArgument(a))return true;
    if(!guardPartition_)return false;
    if(a.kind==OpaqueInitializerWindow)return true;
    if(a.kind!=Closure||a.receiver||a.brand||a.entryRead)return false;
    auto it=closures_.find(a.ref);if(it==closures_.end())return false;
    const auto &c=it->second;auto env=environments_.find(c.environment);
    return !c.isClass&&c.creation&&c.body&&!llvh::isa<AsyncFunction>(c.body)&&
        (c.body->getDefinitionKind()==Function::DefinitionKind::ES5Function||
         c.body->getDefinitionKind()==Function::DefinitionKind::ES6Method)&&
        env!=environments_.end()&&env->second.creation&&
        c.body->getFunctionScopeDesc()->getParent()==env->second.description;
  }
  Datum invokePrivateAsync(unsigned closure,const std::vector<Datum> &args,
                           Datum receiver,Frame &caller,Instruction *site) {
    const auto info=closures_.at(closure);
    auto *fn=llvh::dyn_cast<AsyncFunction>(info.body);
                                                                        
                                                                  
    if(!additive_ || !fn || info.isClass || depth_>=8 || active_.count(fn) ||
       caller.calls.size()>=8 || nextAsyncPromise_>64 || args.size()>16)
      return reject("ASYNC_ENTRY_OUTSIDE_BOUNDED_PROFILE",site);
    for(const auto &a:args)if(!boundedArgument(a))return reject("ASYNC_ARGUMENT_THENABLE_UNPROVEN",site);
    auto found=asyncBindings_.find(fn);
    if(found==asyncBindings_.end())found=asyncBindings_.emplace(fn,recognizePrivateAsync(fn)).first;
    const auto &b=found->second;
    if(!b.valid || b.parameterActivation)return reject(b.valid?"ASYNC_PARAMETER_ACTIVATION_UNSUPPORTED":b.reason,site);
    unsigned wrapper=asyncScope(b.wrapper,info.environment,site);
    unsigned generator=failed_?0:asyncScope(b.generator,wrapper,site);
    if(failed_)return {};
    if(b.inner->getFunctionScopeDesc()->getParent()!=environments_.at(generator).description)
      return reject("ASYNC_INNER_SCOPE_PARENT_UNPROVEN",site);
    unsigned env=environment(generator,b.inner->getFunctionScopeDesc(),b.inner,0,site);
    if(failed_)return {};
    Frame frame{b.inner,MethodMode,env};frame.receiver=receiver;frame.arguments=args;
    frame.calls=caller.calls;frame.calls.push_back(site);
    for(auto &a:frame.arguments)edge(a,site);
    environments_.at(env).creation=b.innerScope;
    frame.values[b.innerScope]=make(Scope,env);
    frame.asyncPromise=nextAsyncPromise_++;
    auto &promise=asyncPromises_[frame.asyncPromise];promise.call=site;
    ++depth_;active_.insert(fn);execute(frame,b.prefix);active_.erase(fn);--depth_;
    return failed_?Datum{}:make(AsyncPromise,frame.asyncPromise);
  }

  Datum invoke(unsigned closure,const std::vector<Datum> &args,Datum receiver,Frame &caller,Instruction *site,Mode mode,
               bool privateCallable=false,bool initializerTransport=false) {
    const ClosureInfo info=closures_.at(closure);
    invokedBodies_.insert(info.body);
    if(llvh::isa<AsyncFunction>(info.body))
      return invokePrivateAsync(closure,args,receiver,caller,site);
    if(depth_>=8||active_.count(info.body)||args.size()>16||info.body->getParameters().size()>16||
        info.body->empty()||
        (!llvh::isa<ReturnInst>(info.body->front().getTerminator()) &&
         !((mode==MethodMode || (mode==ConstructorMode && info.isClass)) && info.body->isStrictMode()) &&
         !(guardPartition_&&mode==DirectMode)))
      return reject("NONLINEAR_OR_RECURSIVE_BODY",site);
    for(const auto &a:args) {
                                                                             
                                                                               
                                                                          
      const auto object=objects_.find(a.ref);
      const bool exactInstance=!initializerTransport && mode==MethodMode &&
          info.body->isStrictMode() && a.kind==Instance &&
          object!=objects_.end() && object->second.allocation &&
          object->second.ctor && closures_.count(object->second.ctor) &&
          closures_.at(object->second.ctor).isClass;
      if(!(initializerTransport?initializerArgument(a):boundedArgument(a)) && !exactInstance)
        return reject("NONSCALAR_ARGUMENT",site);
    }
    if(mode==ConstructorMode && !info.isClass)return reject("CONSTRUCTOR_IDENTITY_UNPROVEN",site);
                                                                          
                                                         
    auto capture=environments_.find(info.environment);
    if(capture==environments_.end()||!capture->second.creation||
       info.body->getFunctionScopeDesc()->getParent()!=capture->second.description)
      return reject("CALL_CAPTURE_ENVIRONMENT_UNPROVEN",site);
    unsigned env=environment(info.environment,info.body->getFunctionScopeDesc(),info.body,0,site);
    if(failed_)return {};
    Frame frame{info.body,mode,env};
    frame.receiver=receiver;frame.arguments=args;frame.calls=caller.calls;frame.calls.push_back(site);
    if(initializerTransport) {
      if(!guardPartition_||mode!=DirectMode)return reject("INITIALIZER_PROFILE_UNPROVEN",site);
      unsigned windows=0;
      for(const auto &a:args) {
        if(a.kind==Closure)frame.initializerCallbacks.insert(a.ref);
        if(a.kind==OpaqueInitializerWindow)++windows;
      }
      llvh::outs()<<"[PRIVATE_GUARD_INITIALIZER_CALL] at="<<id(site)
          <<" opaque_windows="<<windows<<" callbacks="<<frame.initializerCallbacks.size()
          <<" environment=UNPROVEN export=0\n";
    }
    if(additive_ || exactDirectEntry_) {
                                                                          
                                                                        
      if((mode==DirectMode||mode==ReduceCallbackMode)&&receiver.kind==Undefined&&!info.body->isStrictMode()) {
        frame.receiver=make(Global);
        frame.substitutedGlobalThis=true;
      }
                                                                             
      for(auto &argument:frame.arguments)edge(argument,site);
      if(failed_)return {};
    }
    if(privateCallable)frame.privateCallable=closure;
    ++depth_;active_.insert(info.body);Datum d=execute(frame);active_.erase(info.body);--depth_;
    if(failed_||abrupt_)return {};
                                                                          
                                                                          
    if((additive_||exactDirectEntry_)&&cutoff_)return make(Undefined);
    if(mode==DirectMode&&!primitive(d)&&!(additive_&&(d.kind==AsyncPromise||d.kind==AsyncGeneratorObject)))
      return reject("DIRECT_RETURN_OR_ESCAPE_UNPROVEN",site);
    if(mode==ReduceCallbackMode && !primitive(d) &&
       !(d.kind==BoundArray&&boundedArgument(d)))return reject("REDUCE_CALLBACK_RESULT_UNPROVEN",site);
    if(mode==WrapperMode) {
      if(frame.definitions!=1||d.kind!=Closure||!closures_[d.ref].isClass||!sameInvocationDescendant(closures_[d.ref].environment,frame.environment) ||
         !closures_[d.ref].creation || owner(closures_[d.ref].creation)!=frame.function)
        return reject("CLASS_WRAPPER_RETURN_UNPROVEN",site);
    } else if(mode==ConstructorMode&&d.kind!=Undefined)return reject("CONSTRUCTOR_RETURN_UNPROVEN",site);
    else if(mode==ModuleMode&&!primitive(d))return reject("MODULE_RETURN_OR_ESCAPE_UNPROVEN",site);
                                                                              
                                                                              
                                                                              
    if(mode==NativeInitializerMode && d.kind==Closure) {
      auto &returned=closures_.at(d.ref);
      if(returned.isClass || !returned.creation || !returned.body->isStrictMode() ||
         owner(returned.creation)!=info.body ||
         !sameInvocationDescendant(returned.environment,frame.environment))
        return reject("FIELD_FUNCTION_CREATION_OWNER_UNPROVEN",site);
      returned.publicFieldFunction=true;
    }
    edge(d,site);return d;
  }
  bool fieldValue(const Datum &d) const {
    if(primitive(d))return true;
    auto c=closures_.find(d.ref);
    return (d.kind==Closure||d.kind==PublicFieldFunction)&&c!=closures_.end()&&
        c->second.publicFieldFunction&&!c->second.isClass;
  }
  Datum nativeClassDefinition(CallBuiltinInst *site,Frame &f) {
    const auto op=site->getBuiltinIndex();
    const bool init=op==BuiltinMethod::HermesBuiltin_initBaseClass;
    const bool getter=op==BuiltinMethod::HermesBuiltin_defineStaticClassGetter||
        op==BuiltinMethod::HermesBuiltin_defineInstanceClassGetter;
    const bool setter=op==BuiltinMethod::HermesBuiltin_defineStaticClassSetter||
        op==BuiltinMethod::HermesBuiltin_defineInstanceClassSetter;
    const bool staticMethod=op==BuiltinMethod::HermesBuiltin_defineStaticClassMethod||
        op==BuiltinMethod::HermesBuiltin_defineStaticClassGetter||
        op==BuiltinMethod::HermesBuiltin_defineStaticClassSetter;
    const bool method=staticMethod||op==BuiltinMethod::HermesBuiltin_defineInstanceClassMethod||getter||setter;
    if(!(init||method)||!llvh::isa<LiteralUndefined>(site->getNewTarget())||
       site->getNumArguments()!=(init?2u:4u)||
       !llvh::isa<LiteralUndefined>(site->getArgument(0)))
      return reject("NATIVE_CLASS_ABI_UNPROVEN",site);
    if(f.mode!=WrapperMode)return reject("NATIVE_CLASS_WRAPPER_UNPROVEN",site);
    Datum ctor=value(site->getArgument(1),f,site);
    if(failed_)return {};
    if(ctor.kind!=Closure)return reject("NATIVE_CLASS_CONSTRUCTOR_UNPROVEN",site);
    auto &c=closures_[ctor.ref];
    if(!sameInvocationDescendant(c.environment,f.environment)||!c.creation||
       c.creation->getParent()->getParent()!=f.function||
       c.body->getDefinitionKind()!=Function::DefinitionKind::ES6Constructor||
       !c.body->isStrictMode())
      return reject("NATIVE_CLASS_CONSTRUCTOR_OWNER_UNPROVEN",site);
    if(init) {
      if(c.isClass||!c.ownProperties.empty()||f.definitions)
        return reject("NATIVE_CLASS_FRESHNESS_UNPROVEN",site);
      ++f.definitions;c.isClass=true;
      c.nativeDefinitionEnvironment=f.environment;
      return make(Undefined);
    }
    Datum fn=value(site->getArgument(3),f,site);
    if(failed_)return {};
    const auto name=evaluatedPublicKey(site->getArgument(2),f,site);
    auto &methods=staticMethod?c.staticMethods:c.methods;
    if(fn.kind!=Closure||!c.isClass||dangerousKey(name)||name=="constructor"||
       (methods.size()>=16&&!methods.count(name)))
      return reject("NATIVE_CLASS_METHOD_UNPROVEN",site);
    auto &m=closures_[fn.ref];
    if(!sameInvocationDescendant(m.environment,f.environment)||!m.creation||
       m.creation->getParent()->getParent()!=f.function||m.isClass||
       !m.ownProperties.empty()||
       m.body->getDefinitionKind()!=Function::DefinitionKind::ES6Method||
       !m.body->isStrictMode())
      return reject("NATIVE_CLASS_METHOD_OWNER_OR_KEY_UNPROVEN",site);
    auto &accessors=staticMethod?c.staticAccessors:c.instanceAccessors;
    if(getter||setter) {
      if(accessors.size()>=16&&!accessors.count(name))return reject("CLASS_ACCESSOR_LIMIT",site);
      methods.erase(name);
      if(staticMethod)c.publicStaticFields.erase(name);
      auto &descriptor=accessors[name];
      if(getter)descriptor.get=fn.ref;else descriptor.set=fn.ref;
      return make(Undefined);
    }
    accessors.erase(name);
    if(staticMethod) {
                                                                             
                                                                              
      methods[name]=fn.ref;c.publicStaticFields.erase(name);
    } else if(!methods.emplace(name,fn.ref).second) {
      return reject("NATIVE_CLASS_METHOD_OWNER_OR_KEY_UNPROVEN",site);
    }
                                                                           
                                                       
    return make(Undefined);
  }

  std::string evaluatedPublicKey(Value *v,Frame &f,Instruction *site) {
    if(llvh::isa<LiteralString>(v)||llvh::isa<LiteralNumber>(v))return key(v);
    Datum d=value(v,f,site);
    if(d.kind==Scalar&&d.knownString&&d.traces.empty())return d.stringValue;
    reject("PUBLIC_KEY_IDENTITY_UNPROVEN",site);return "";
  }
  Datum nativePublicKey(CallBuiltinInst *site,Frame &f) {
    const bool naming=site->getBuiltinIndex()==BuiltinMethod::HermesBuiltin_namePublicFieldFunction;
    if(site->getNumArguments()!=(naming?3u:2u)||!llvh::isa<LiteralUndefined>(site->getArgument(0)))
      return reject("PUBLIC_KEY_ABI_UNPROVEN",site);
    Datum d=value(site->getArgument(1),f,site);
    if(naming) {
      Datum fn=value(site->getArgument(2),f,site);
      if(f.mode==WrapperMode && d.kind==Scalar && d.knownString && d.traces.empty() &&
         fn.kind==Closure && closures_.count(fn.ref) && closures_[fn.ref].isClass &&
         closures_[fn.ref].nativeDefinitionEnvironment==f.environment &&
         sameInvocationDescendant(closures_[fn.ref].environment,f.environment) &&
         closures_[fn.ref].creation && owner(closures_[fn.ref].creation)==f.function) return fn;
      if(f.mode!=NativeInitializerMode||d.kind!=Scalar||!d.knownString||!d.traces.empty()||
         fn.kind!=Closure||!closures_.count(fn.ref)||closures_[fn.ref].isClass||
         !closures_[fn.ref].creation||owner(closures_[fn.ref].creation)!=f.function||
         !sameInvocationDescendant(closures_[fn.ref].environment,f.environment))
        return reject("PUBLIC_FUNCTION_NAME_IDENTITY_UNPROVEN",site);
      return fn;
    }
    if(f.mode!=WrapperMode||!d.traces.empty())return reject("PUBLIC_KEY_EFFECT_OR_CONTEXT_UNPROVEN",site);
    if(d.kind==Scalar&&d.knownString)return d;
    std::string text;
    if(d.kind==Undefined)text="undefined";
    else if(d.kind==Null)text="null";
    else if(d.kind==Scalar&&d.knownNumber) {
      char b[NUMBER_TO_STRING_BUF_SIZE];auto n=numberToString(d.number,b,sizeof(b));text.assign(b,n);
    } else return reject("PUBLIC_KEY_COERCION_UNPROVEN",site);
    Datum out=make(Scalar);out.knownString=true;out.stringValue=text;return out;
  }
  Datum nativePublicStatic(CallBuiltinInst *site,Frame &f) {
    if(site->getBuiltinIndex()!=BuiltinMethod::HermesBuiltin_definePublicClassField ||
       !llvh::isa<LiteralUndefined>(site->getNewTarget()) ||
       site->getNumArguments()!=4 ||
       !llvh::isa<LiteralUndefined>(site->getArgument(0)) || f.mode!=WrapperMode)
      return reject("PUBLIC_STATIC_ABI_OR_CONTEXT_UNPROVEN",site);
    Datum target=value(site->getArgument(1),f,site);
    Datum d=value(site->getArgument(3),f,site);
    const auto name=evaluatedPublicKey(site->getArgument(2),f,site);
    if(failed_)return {};
    if(target.kind!=Closure || !closures_[target.ref].isClass ||
       !fieldValue(d) || dangerousKey(name))
      return reject("PUBLIC_STATIC_TARGET_KEY_OR_VALUE_UNPROVEN",site);
    auto &c=closures_[target.ref];
    if(!c.creation || owner(c.creation)!=f.function ||
       !sameInvocationDescendant(c.environment,f.environment) ||
       c.body->getDefinitionKind()!=Function::DefinitionKind::ES6Constructor ||
       !c.body->isStrictMode() ||
       (c.publicStaticFields.size()>=64 && !c.publicStaticFields.count(name)))
      return reject("PUBLIC_STATIC_OWNER_OR_LIMIT_UNPROVEN",site);
                                                                  
    c.staticMethods.erase(name);c.staticAccessors.erase(name);edge(d,site);c.publicStaticFields[name]=d;return make(Undefined);
  }

  Datum nativePublicInstance(CallBuiltinInst *site,Frame &f) {
    if(site->getBuiltinIndex()!=BuiltinMethod::HermesBuiltin_definePublicInstanceClassField||
       !llvh::isa<LiteralUndefined>(site->getNewTarget())||site->getNumArguments()!=4||
       !llvh::isa<LiteralUndefined>(site->getArgument(0))||f.mode!=ConstructorMode)
      return reject("PUBLIC_INSTANCE_ABI_OR_CONTEXT_UNPROVEN",site);
    Datum receiver=value(site->getArgument(1),f,site);
    Datum d=value(site->getArgument(3),f,site);
    const auto name=evaluatedPublicKey(site->getArgument(2),f,site);
    if(failed_)return {};
    if(receiver.kind!=Instance||f.receiver.kind!=Instance||receiver.ref!=f.receiver.ref||
       dangerousKey(name)||!fieldValue(d))
      return reject("PUBLIC_INSTANCE_TARGET_KEY_OR_VALUE_UNPROVEN",site);
    auto &object=objects_.at(receiver.ref);
    auto ctor=closures_.find(object.ctor);
    if(!object.allocation||ctor==closures_.end()||!ctor->second.isClass||
       ctor->second.body!=f.function||
       (object.publicInstanceFields.size()>=64&&!object.publicInstanceFields.count(name)))
      return reject("PUBLIC_INSTANCE_OWNER_OR_LIMIT_UNPROVEN",site);
                                                                             
                                                                         
    edge(d,site);object.publicInstanceFields[name]={d,site};++fieldWrites_;
    return make(Undefined);
  }

  Datum nativePrivate(CallBuiltinInst *site,Frame &f) {
    const auto op=site->getBuiltinIndex();
    const bool create=op==BuiltinMethod::HermesBuiltin_privateNameCreate;
    const bool init=op==BuiltinMethod::HermesBuiltin_privateFieldInit;
    const bool get=op==BuiltinMethod::HermesBuiltin_privateFieldGet;
    const bool set=op==BuiltinMethod::HermesBuiltin_privateFieldSet;
    if(!(create||init||get||set))
      return reject("BUILTIN_OR_SPREAD_OUTSIDE_PROFILE",site);
                                                                               
    if(!llvh::isa<LiteralUndefined>(site->getNewTarget())||
       !llvh::isa<LiteralUndefined>(site->getArgument(0))||
       site->getNumArguments()!=(create?1u:(get?3u:4u)))
      return reject("NATIVE_PRIVATE_ABI_UNPROVEN",site);
    if(create) {
      if(f.mode!=WrapperMode)return reject("NATIVE_PRIVATE_TOKEN_CONTEXT",site);
      unsigned token=object(site);if(failed_)return {};
      nativeTokenEnvironments_[token]=f.environment;++nativeCreates_;
      return make(NativePrivateToken,token);
    }
    Datum receiver=value(site->getArgument(1),f,site);
    Datum token=value(site->getArgument(2),f,site);
    if(failed_)return {};
    if(receiver.kind!=Instance||token.kind!=NativePrivateToken||
       !nativeTokenEnvironments_.count(token.ref))
      return reject("NATIVE_PRIVATE_IDENTITY_UNPROVEN",site);
    auto &slots=objects_[token.ref].privateSlots;
    auto found=slots.find(receiver.ref);
    if(init) {
      if(f.mode!=ConstructorMode||f.receiver.kind!=Instance||
         receiver.ref!=f.receiver.ref||found!=slots.end()||
         (!closures_[objects_[receiver.ref].ctor].nativeDefinitionEnvironment ||
           nativeTokenEnvironments_[token.ref]!=
               closures_[objects_[receiver.ref].ctor].nativeDefinitionEnvironment))
        return reject("NATIVE_PRIVATE_INITIALIZATION_UNPROVEN",site);
      Datum d=value(site->getArgument(3),f,site);
      bool privateMethod=false;
      if(d.kind==Closure && closures_.count(d.ref)) {
        const auto &fn=closures_.at(d.ref);
        privateMethod=!fn.publicFieldFunction && nativeInitializerOwner(
            fn,closures_.at(objects_.at(receiver.ref).ctor));
      }
      if(!primitive(d) && !fieldValue(d) && !privateMethod)
        return reject("NATIVE_PRIVATE_NONSCALAR_VALUE",site);
      edge(d,site);slots.emplace(receiver.ref,Slot{d,site});
      ++fieldWrites_;++nativeInits_;return make(Undefined);
    }
                                                                             
                                                                            
    if(found==slots.end())return reject("NATIVE_PRIVATE_BRAND_OR_TDZ",site);
    if(get) {
      Datum d=found->second.value;
      if(d.kind==Closure) {
        auto fn=closures_.find(d.ref);
        if(fn==closures_.end())return reject("PRIVATE_CALLABLE_MISSING",site);
        d.kind=fn->second.publicFieldFunction?PublicFieldFunction:NativePrivateCallable;
        d.receiver=receiver.ref;d.brand=token.ref;d.entryRead=site;
      }
      edge(d,site);++fieldReads_;++nativeGets_;return d;
    }
    Datum d=value(site->getArgument(3),f,site);
    if(!primitive(d)&&!fieldValue(d))return reject("NATIVE_PRIVATE_NONSCALAR_VALUE",site);
    edge(d,site);found->second=Slot{d,site};++fieldWrites_;++nativeSets_;
    return d;                                                                 
  }
  bool nativeInitializerOwner(const ClosureInfo &initializer,
                              const ClosureInfo &constructor) const {
    return constructor.isClass && constructor.nativeDefinitionEnvironment &&
        initializer.creation && constructor.creation && !initializer.isClass &&
        initializer.body->getDefinitionKind()==Function::DefinitionKind::ES6Method &&
        initializer.body->isStrictMode() &&
        owner(initializer.creation)==owner(constructor.creation) &&
        sameInvocationDescendant(initializer.environment,
                                 constructor.nativeDefinitionEnvironment) &&
        sameInvocationDescendant(constructor.environment,
                                 constructor.nativeDefinitionEnvironment);
  }
  Datum copyOwnRecord(CallBuiltinInst *site,Frame &f) {
    if(site->getNumArguments()!=4 || !llvh::isa<LiteralUndefined>(site->getArgument(0)) ||
       !llvh::isa<LiteralUndefined>(site->getArgument(3)) ||
       !llvh::isa<LiteralUndefined>(site->getNewTarget()))
      return reject("OBJECT_REST_ABI_OR_EXCLUSIONS_UNPROVEN",site);
    Datum target=value(site->getArgument(1),f,site),source=value(site->getArgument(2),f,site);
    if(failed_ || target.kind!=Record || source.kind!=Record || target.ref==source.ref ||
       !boundedArgument(source))return reject("OBJECT_REST_SOURCE_UNPROVEN",site);
    auto &to=objects_.at(target.ref);const auto &from=objects_.at(source.ref);
    if(!from.ownGetters.empty() || !to.ownGetters.empty() || to.moduleTable || !to.properties.empty() || !to.allocation ||
       to.allocationEnvironment!=f.environment || owner(to.allocation)!=f.function ||
       from.properties.size()>64)return reject("OBJECT_REST_TARGET_UNPROVEN",site);
                                                                                
                                                                             
    for(const auto &entry:from.properties) {
      auto *definition=llvh::dyn_cast_or_null<StoreOwnPropertyInst>(entry.second.write);
      if(!definition || !definition->getIsEnumerable() ||
         dangerousKey(entry.first)||!primitive(entry.second.value))
        return reject("OBJECT_REST_PROPERTY_UNPROVEN",site);
      Datum d=entry.second.value;edge(d,site);to.properties[entry.first]={d,site};
    }
    return target;
  }
                                                                         
                                                                            
                                                                         
  Datum createAsyncGenerator(CreateGeneratorInst *site,Frame &f) {
    auto *inner=llvh::dyn_cast<GeneratorInnerFunction>(site->getFunctionCode());
    Datum parent=value(site->getEnvironment(),f,site);
    if(!additive_||f.function->getDefinitionKind()!=Function::DefinitionKind::ES6AsyncGenerator||
       !inner||inner->isLazy()||inner->empty()||parent.kind!=Scope||parent.ref!=f.environment||
       nextGenerator_>32||inner->getParameters().size()>16||f.arguments.size()>16||
       inner->getFunctionScopeDesc()->getParent()!=environments_.at(parent.ref).description)
      return reject("ASYNC_GENERATOR_CREATION_IDENTITY",site);
    std::vector<Instruction *> entry;for(auto &i:inner->front())entry.push_back(&i);
    if(entry.size()!=6)return reject("ASYNC_GENERATOR_START_SHAPE",site);
    auto *scope=llvh::dyn_cast<CreateScopeInst>(entry[0]);
    auto *slot=llvh::dyn_cast<AllocStackInst>(entry[2]);
    auto *resume=llvh::dyn_cast<ResumeGeneratorInst>(entry[3]);
    auto *load=llvh::dyn_cast<LoadStackInst>(entry[4]);
    auto *branch=llvh::dyn_cast<CondBranchInst>(entry[5]);
    if(!scope||scope->getCreatedScopeDesc()!=inner->getFunctionScopeDesc()||
       !llvh::isa<StartGeneratorInst>(entry[1])||!slot||!resume||!load||!branch||
       resume->getIsReturn()!=slot||load->getPtr()!=slot||branch->getCondition()!=load||
       branch->getTrueDest()==branch->getFalseDest()||branch->getTrueDest()->size()!=1)
      return reject("ASYNC_GENERATOR_START_OPERANDS",site);
    auto *ret=llvh::dyn_cast<ReturnInst>(&branch->getTrueDest()->front());
    if(!ret||ret->getValue()!=resume)return reject("ASYNC_GENERATOR_START_RETURN",site);
    unsigned env=environment(parent.ref,inner->getFunctionScopeDesc(),inner,0,site);
    if(failed_)return {};
    Frame frame{inner,MethodMode,env};frame.receiver=f.receiver;frame.arguments=f.arguments;
    frame.calls=f.calls;frame.values[scope]=make(Scope,env);
    environments_.at(env).creation=scope;
    unsigned ref=nextGenerator_++;frame.asyncGenerator=ref;
    generators_.emplace(ref,GeneratorState{frame,branch->getFalseDest()});
    return make(AsyncGeneratorObject,ref);
  }
  void finishAsyncGenerator(Frame &f,Datum value,bool done,Instruction *site) {
    auto found=generators_.find(f.asyncGenerator);
    if(found==generators_.end()||!found->second.request||!primitive(value)) {
      reject("ASYNC_GENERATOR_RESULT_UNPROVEN",site);return;
    }
    unsigned ref=object(site);if(failed_)return;
    edge(value,site);objects_[ref].properties["value"]={value,site};
    Datum flag=make(Scalar);flag.knownBool=true;flag.boolValue=done;
    objects_[ref].properties["done"]={flag,site};
    unsigned request=found->second.request;found->second.request=0;found->second.done=done;
    fulfillPrivateAsync(request,make(AsyncIteratorResult,ref),site);
  }
  Datum nextAsyncGenerator(unsigned ref,const std::vector<Datum> &args,Frame &caller,CallInst *site) {
    auto found=generators_.find(ref);
    if(!additive_||found==generators_.end()||!found->second.wrapped||found->second.request||
       args.size()>1||nextAsyncPromise_>64||depth_>=8||caller.calls.size()>=8)
      return reject("ASYNC_GENERATOR_REQUEST_OUTSIDE_SERIAL_PROFILE",site);
    Datum sent=args.empty()?make(Undefined):args[0];
    if(!primitive(sent))return reject("ASYNC_GENERATOR_RESUME_VALUE_UNPROVEN",site);
    auto &state=found->second;
    unsigned token=nextAsyncPromise_++;asyncPromises_[token].call=site;state.request=token;
    if(state.done) {finishAsyncGenerator(state.frame,make(Undefined),true,site);return make(AsyncPromise,token);}
    Frame frame=state.frame;BasicBlock *entry=state.entry;
    if(state.started) {
      AsyncJob job{frame,state.suspension,sent};entry=resumePrivateAsync(job);frame=job.frame;
    } else state.started=true;
    if(!entry||failed_)return {};
    ++depth_;execute(frame,entry);--depth_;
    return failed_?Datum{}:make(AsyncPromise,token);
  }
  Datum generatorBuiltin(unsigned op,const std::vector<Datum> &args,CallInst *site) {
    if(!additive_||args.size()!=1)return reject("ASYNC_GENERATOR_BUILTIN_ABI",site);
    Datum d=args[0];
    if(op==BuiltinMethod::HermesBuiltin_asyncGeneratorWrap) {
      auto found=generators_.find(d.ref);
      if(d.kind!=AsyncGeneratorObject||found==generators_.end()||found->second.wrapped)
        return reject("ASYNC_GENERATOR_WRAP_IDENTITY",site);
      found->second.wrapped=true;return d;
    }
    if(op==BuiltinMethod::HermesBuiltin_asyncGeneratorAwait) {
      if(!(primitive(d)||d.kind==AsyncPromise||d.kind==AsyncIteratorResult)||nextAwaitMarker_>128)
        return reject("ASYNC_GENERATOR_AWAIT_VALUE_UNPROVEN",site);
      unsigned id=nextAwaitMarker_++;awaitMarkers_[id]=d;return make(AsyncAwaitMarker,id);
    }
    return reject("ASYNC_GENERATOR_DELEGATION_OR_PARAMETER_ACTIVATION_UNPROVEN",site);
  }
  Datum call(CallInst *site,Frame &f) {
    if(auto *builtin=llvh::dyn_cast<CallBuiltinInst>(site)) {
      const auto op=builtin->getBuiltinIndex();
      if(op==BuiltinMethod::HermesBuiltin_copyDataProperties)return copyOwnRecord(builtin,f);
      if(op==BuiltinMethod::HermesBuiltin_classElementKey||op==BuiltinMethod::HermesBuiltin_namePublicFieldFunction)
        return nativePublicKey(builtin,f);
      if(op==BuiltinMethod::HermesBuiltin_definePublicClassField)
        return nativePublicStatic(builtin,f);
      if(op==BuiltinMethod::HermesBuiltin_definePublicInstanceClassField)
        return nativePublicInstance(builtin,f);
      if(op==BuiltinMethod::HermesBuiltin_initBaseClass ||
         op==BuiltinMethod::HermesBuiltin_defineInstanceClassMethod ||
         op==BuiltinMethod::HermesBuiltin_defineStaticClassMethod ||
         op==BuiltinMethod::HermesBuiltin_defineStaticClassGetter ||
         op==BuiltinMethod::HermesBuiltin_defineStaticClassSetter ||
         op==BuiltinMethod::HermesBuiltin_defineInstanceClassGetter ||
         op==BuiltinMethod::HermesBuiltin_defineInstanceClassSetter)
        return nativeClassDefinition(builtin,f);
      return nativePrivate(builtin,f);
    }
    Datum callee=value(site->getCallee(),f,site),self=value(site->getArgument(0),f,site);
    std::vector<Datum> args;for(unsigned n=1;n<site->getNumArguments();++n)args.push_back(value(site->getArgument(n),f,site));
    if(failed_)return {};
    if(callee.kind==ConditionalRecordFunction) {
      const auto record=objects_.find(callee.receiver);
      const auto closure=closures_.find(callee.ref);
      const bool exactLocalCall=f.mode==MethodMode && f.function->isStrictMode() &&
          record!=objects_.end() && record->second.allocation &&
          owner(record->second.allocation)==f.function &&
          record->second.allocationEnvironment==f.environment && !record->second.moduleTable &&
          closure!=closures_.end() && closure->second.creation &&
          owner(closure->second.creation)==f.function && closure->second.body->isStrictMode() &&
          sameInvocationDescendant(closure->second.environment,f.environment);
      if((!guardPartition_&&!exactLocalCall)||llvh::isa<ConstructInst>(site)||
         !llvh::isa<LiteralUndefined>(site->getNewTarget())||!closures_.count(callee.ref))
        return reject("RECORD_METHOD_RECEIVER_UNPROVEN",site);
      const auto &fn=closures_.at(callee.ref);
      if(fn.isClass||llvh::isa<AsyncFunction>(fn.body))return reject("RECORD_METHOD_KIND_UNPROVEN",site);
      const bool directMethod=self.kind==Record&&self.ref==callee.receiver&&
          site->getCallee()==callee.entryRead;
                                                                             
                                                                            
                                                                          
                                                                            
                                                                             
      const bool detachedStrict=self.kind==Undefined&&
          llvh::isa<LiteralUndefined>(site->getArgument(0))&&
          callee.entryRead&&llvh::isa<LoadPropertyInst>(callee.entryRead)&&
          fn.body->isStrictMode()&&
          (fn.body->getDefinitionKind()==Function::DefinitionKind::ES5Function||
           fn.body->getDefinitionKind()==Function::DefinitionKind::ES6Method);
      if(!directMethod&&!detachedStrict)
        return reject("RECORD_METHOD_RECEIVER_UNPROVEN",site);
      Datum result=invoke(callee.ref,args,self,f,site,
          guardPartition_?DirectMode:MethodMode);
      if(!failed_&&!primitive(result))return reject("LOCAL_RECORD_METHOD_ESCAPE",site);
      return result;
    }
    if(callee.kind==ConditionalArrayMethod) {
      if(!guardPartition_||self.kind!=BoundArray||self.ref!=callee.ref||
         site->getCallee()!=callee.entryRead||llvh::isa<ConstructInst>(site)||
         !llvh::isa<LiteralUndefined>(site->getNewTarget()))return reject("ARRAY_METHOD_RECEIVER_UNPROVEN",site);
                                                                              
                                                                        
      auto elements=objects_.at(self.ref).elements;
      for(const auto &e:elements)if(!primitive(e))return reject("ARRAY_HOLE_OR_EFFECT_UNPROVEN",site);
      if(callee.stringValue=="concat") {
        for(const auto &a:args) {
          if(a.kind==BoundArray) {
            for(const auto &e:objects_.at(a.ref).elements) {
              if(!primitive(e))return reject("CONCAT_HOLE_OR_EFFECT_UNPROVEN",site);
              if(elements.size()>=64)return reject("ARRAY_SIZE_LIMIT",site);
              elements.push_back(e);
            }
          } else {
            if(!primitive(a))return reject("CONCAT_SPREADABILITY_UNPROVEN",site);
            if(elements.size()>=64)return reject("ARRAY_SIZE_LIMIT",site);
            elements.push_back(a);
          }
        }
        unsigned n=object(site);if(failed_)return {};
        for(auto &e:elements)edge(e,site);
        objects_.at(n).elements=std::move(elements);return make(BoundArray,n);
      }
      if(args.size()!=2||args[0].kind!=Closure||args[0].receiver||args[0].brand||
         closures_.at(args[0].ref).isClass || llvh::isa<AsyncFunction>(closures_.at(args[0].ref).body) ||
         !(primitive(args[1])||(args[1].kind==BoundArray&&boundedArgument(args[1]))))
        return reject("REDUCE_ARGUMENT_PROFILE_UNPROVEN",site);
      Datum acc=args[1];
      for(unsigned n=0;n<elements.size();++n) {
        if(!spend(site))return {};
        acc=invoke(args[0].ref,{acc,elements[n],number(n),self},make(Undefined),f,site,ReduceCallbackMode);
        if(failed_||abrupt_)return {};
        if(cutoff_)return make(Undefined);
      }
      edge(acc,site);return acc;
    }
    if(callee.kind==AsyncGeneratorBuiltin) {
      if(self.kind!=Undefined||llvh::isa<ConstructInst>(site)||
         !llvh::isa<LiteralUndefined>(site->getNewTarget()))return reject("ASYNC_GENERATOR_BUILTIN_CALL",site);
      return generatorBuiltin(callee.ref,args,site);
    }
    if(callee.kind==AsyncGeneratorNext) {
      if(self.kind!=AsyncGeneratorObject||self.ref!=callee.ref||
         site->getCallee()!=callee.entryRead||llvh::isa<ConstructInst>(site)||
         !llvh::isa<LiteralUndefined>(site->getNewTarget()))return reject("ASYNC_GENERATOR_NEXT_RECEIVER",site);
      return nextAsyncGenerator(callee.ref,args,f,site);
    }
    if(callee.kind==Closure&&additive_&&self.kind==Undefined&&
       closures_.at(callee.ref).body->getDefinitionKind()==Function::DefinitionKind::ES6AsyncGenerator&&
       !llvh::isa<ConstructInst>(site)&&llvh::isa<LiteralUndefined>(site->getNewTarget()))
      return invoke(callee.ref,args,self,f,site,DirectMode);
    if(auto *c=llvh::dyn_cast<ConstructInst>(site)) {
      if((f.mode!=GlobalMode&&!(f.mode==DirectMode&&(additive_||exactDirectEntry_))&&!(additive_&&f.mode==MethodMode&&f.asyncPromise))||
         self.kind!=Undefined||c->getNewTarget()!=c->getCallee())return reject("CONSTRUCT_IDENTITY_UNPROVEN",c);
      if((callee.kind==WeakMapCtor||callee.kind==WeakSetCtor)&&args.empty())
        return make(callee.kind==WeakMapCtor?WeakMapObject:WeakSetObject,object(c));
      if(callee.kind!=Closure||!closures_[callee.ref].isClass)return reject("CONSTRUCTOR_NOT_VERIFIED",c);
      unsigned n=object(c);objects_[n].ctor=callee.ref;Datum instance=make(Instance,n);
      invoke(callee.ref,args,instance,f,site,ConstructorMode);return failed_?Datum{}:instance;
    }
    if(!llvh::isa<LiteralUndefined>(site->getNewTarget()))return reject("CALL_NEW_TARGET_UNPROVEN",site);
    if(callee.kind==ModuleEntry) {
      if(f.mode!=GlobalMode||!args.empty()||self.kind!=Record||self.ref!=callee.receiver||
          !objects_[self.ref].moduleTable||!objects_[self.ref].modulePublished||
          closures_[callee.ref].isClass||!nonHelper(closures_[callee.ref].body)||
          !callee.entryRead||!f.calls.empty())return reject("MODULE_CALL_IDENTITY_OR_CONTEXT_UNPROVEN",site);
      unsigned readBefore=fieldReads_,writeBefore=fieldWrites_,counterBefore=counters_;
      Datum d=invoke(callee.ref,{},self,f,site,ModuleMode);
      if(failed_||abrupt_)return {};
      if(fieldWrites_!=writeBefore||counters_!=counterBefore)return reject("MODULE_TRANSITIVE_MUTATION_UNPROVEN",site);
      if(primitive(d)&&fieldReads_>readBefore) {
        if(reads_.size()>=64)return reject("READ_SITE_LIMIT",site);
                                                                               
                                                                           
                                                                              
                                                                               
        reads_.push_back({site,d.traces});
      }
      return d;
    }
    if(callee.kind==NativePrivateCallable) {
      auto fn=closures_.find(callee.ref);
      auto token=objects_.find(callee.brand);
      if(self.kind!=Instance || self.ref!=callee.receiver || fn==closures_.end() ||
          token==objects_.end() || !nativeTokenEnvironments_.count(callee.brand) ||
          !callee.entryRead || site->getCallee()!=callee.entryRead ||
          fn->second.isClass || fn->second.publicFieldFunction ||
          !fn->second.body->isStrictMode() ||
          fn->second.body->getDefinitionKind()!=Function::DefinitionKind::ES6Method)
        return reject("PRIVATE_CALLABLE_IDENTITY_UNPROVEN",site);
      auto slot=token->second.privateSlots.find(self.ref);
      if(slot==token->second.privateSlots.end() || slot->second.value.kind!=Closure ||
          slot->second.value.ref!=callee.ref)
        return reject("PRIVATE_CALLABLE_SLOT_CHANGED",site);
      Datum d=invoke(callee.ref,args,self,f,site,MethodMode);
      if(!failed_&&!primitive(d)&&!(additive_&&d.kind==AsyncPromise))return reject("PRIVATE_CALLABLE_RETURN_UNPROVEN",site);
      return d;
    }
    if(callee.kind==PublicFieldFunction) {
      auto closure=closures_.find(callee.ref);
      if(closure==closures_.end()||!closure->second.publicFieldFunction||
         closure->second.isClass||!closure->second.body->isStrictMode()||
         !(self.kind==Undefined||self.kind==Instance||
           (self.kind==Closure&&closures_[self.ref].isClass)))
        return reject("PUBLIC_FIELD_CALL_IDENTITY_UNPROVEN",site);
      Datum d=invoke(callee.ref,args,self,f,site,MethodMode);
      if(failed_||abrupt_)return {};
      if(!primitive(d)&&!(additive_&&d.kind==AsyncPromise))return reject("PUBLIC_FIELD_CALL_NONSCALAR_RETURN",site);
      if(exactReadFrame(f,site)) {
        if(reads_.size()>=64)return reject("READ_SITE_LIMIT",site);
        reads_.push_back({site,d.traces});
      }
      return d;
    }
    if(callee.kind==NativeStaticMethod) {
                                                                           
                                                                             
                                                                              
      auto *read=llvh::dyn_cast_or_null<LoadPropertyInst>(callee.entryRead);
      if(f.mode!=GlobalMode||!f.calls.empty()||self.kind!=Closure||
         self.ref!=callee.receiver||!closures_[self.ref].isClass||
         !read||site->getCallee()!=read||owner(read)!=top_||
         read->getParent()!=&top_->front()||!before(read,site)||
         closures_[callee.ref].isClass||!nonHelper(closures_[callee.ref].body))
        return reject("STATIC_METHOD_CALL_IDENTITY_UNPROVEN",site);
      auto found=closures_[self.ref].staticMethods.find(key(read->getProperty()));
      if(found==closures_[self.ref].staticMethods.end()||found->second!=callee.ref)
        return reject("STATIC_METHOD_REPLACED_OR_ESCAPED",site);
      Datum d=invoke(callee.ref,args,self,f,site,MethodMode);
      if(failed_||abrupt_)return {};
      if(!primitive(d))return reject("STATIC_METHOD_NONSCALAR_RETURN",site);
      if(reads_.size()>=64)return reject("READ_SITE_LIMIT",site);
                                                                            
                                                                              
                                                                              
      reads_.push_back({site,d.traces});return d;
    }
    if(callee.kind==DateNow&&self.kind==DateObject&&args.empty()) {
      auto *source=sourceCall(site);if(!source)return reject("SOURCE_NOT_REGISTERED",site);
      Datum d=make(Scalar);d.numericPrimitive=true;d.traces.push_back({source,{source}});edge(d,site);return d;
    }
    if(callee.kind==DefineClass&&self.kind==Helpers&&f.mode==WrapperMode&&args.size()==2&&args[0].kind==Closure) {
      if(!llvh::isa<LiteralNull>(site->getArgument(2)))return reject("INHERITANCE_OUTSIDE_PROFILE",site);
      auto &c=closures_[args[0].ref];
      if(c.isClass||c.environment!=f.environment||f.definitions++)return reject("CLASS_DEFINITION_UNPROVEN",site);
      c.isClass=true;return make(Undefined);
    }
    if(callee.kind==DefineMethod&&self.kind==Helpers&&f.mode==WrapperMode&&args.size()==3&&args[0].kind==Closure&&args[2].kind==Closure) {
      const auto name=key(site->getArgument(2));auto &c=closures_[args[0].ref];
      if(!c.isClass||c.environment!=f.environment||dangerousKey(name)||name=="constructor"||
          !sameInvocationDescendant(closures_[args[2].ref].environment,f.environment)||
          c.methods.size()>=16||!c.methods.emplace(name,args[2].ref).second)
        return reject("METHOD_DEFINITION_UNPROVEN",site);
      return make(Undefined);
    }
    if(callee.kind==ReflectApply&&self.kind==Undefined&&args.size()==3&&args[0].kind==Closure&&
        args[1].kind==Instance&&args[2].kind==Array) {
      const auto &fn=args[0];
      if(!fn.brand||fn.receiver!=args[1].ref||!objects_[fn.brand].members.count(args[1].ref))
        return reject("CAPTURED_APPLY_BRAND_OR_RECEIVER_UNPROVEN",site);
      return invoke(fn.ref,objects_[args[2].ref].elements,args[1],f,site,MethodMode,true);
    }
    if(callee.kind==InheritedCall) {
      if(f.mode!=GlobalMode||self.kind!=Closure||self.ref!=callee.ref||
          !self.brand||self.brand!=callee.brand||args.size()!=1||
          (args[0].kind!=Record&&args[0].kind!=Instance)||
          closures_[callee.ref].ownProperties.count("call")||
          closures_[callee.ref].isClass||!nonHelper(closures_[callee.ref].body))
        return reject("INHERITED_CALL_IDENTITY_OR_ARGUMENTS_UNPROVEN",site);
                                                                             
                                                                              
                                                                             
                                                                         
      unsigned readBefore=fieldReads_,writeBefore=fieldWrites_;
      Datum d=invoke(callee.ref,{},args[0],f,site,MethodMode,true);
      if(!failed_&&!abrupt_&&primitive(d)&&fieldReads_>readBefore&&fieldWrites_==writeBefore) {
        if(reads_.size()>=64)return reject("READ_SITE_LIMIT",site);
        reads_.push_back({site,d.traces});
      }
      return d;
    }
    if(callee.kind==Closure) {
      if(!classify(closures_[callee.ref].body))return {};
      if(roles_.count(closures_[callee.ref].body)) {
        if(self.kind!=Undefined)return reject("HELPER_THIS_UNPROVEN",site);
        return helper(callee.ref,args,f,site);
      }
      if(f.mode==WrapperMode && self.kind==Closure && closures_[self.ref].isClass &&
          args.empty() && !callee.receiver && !callee.brand &&
          !closures_[callee.ref].isClass &&
          closures_[callee.ref].body->getDefinitionKind()==Function::DefinitionKind::ES6Method &&
          closures_[callee.ref].body->isStrictMode() &&
          owner(closures_[callee.ref].creation)==f.function &&
          sameInvocationDescendant(closures_[callee.ref].environment,f.environment) &&
          sameInvocationDescendant(closures_[self.ref].environment,f.environment)) {
        Datum d=invoke(callee.ref,args,self,f,site,NativeInitializerMode);
        if(!failed_&&!fieldValue(d))return reject("PUBLIC_STATIC_INITIALIZER_RETURN_UNPROVEN",site);
        return d;
      }
      if(f.mode==ConstructorMode&&self.kind==Instance&&self.ref==f.receiver.ref&&
          !callee.receiver&&!callee.brand&&args.empty()&&
          !closures_[callee.ref].isClass&&closures_[callee.ref].body->isStrictMode()&&
          (sameInvocationDescendant(closures_[callee.ref].environment,
                                    closures_[objects_[self.ref].ctor].environment) ||
           nativeInitializerOwner(closures_[callee.ref],
                                  closures_[objects_[self.ref].ctor]))) {
                                                                            
                                                                            
        Datum d=invoke(callee.ref,args,self,f,site,NativeInitializerMode);
        if(!failed_&&!fieldValue(d))return reject("NATIVE_INITIALIZER_NONSCALAR_RETURN",site);
        return d;
      }
      if(self.kind==Instance&&callee.receiver==self.ref&&!callee.brand) {
                                                                             
                                                                              
                                                                              
                                                                             
        auto *read=llvh::dyn_cast_or_null<LoadPropertyInst>(callee.entryRead);
        const auto &object=objects_.at(self.ref);
        const auto &ctor=closures_.at(object.ctor);
        const auto name=read?key(read->getProperty()):std::string{};
        auto method=ctor.methods.find(name);
        const bool directNative=exactReadFrame(f,site)&&
            ctor.nativeDefinitionEnvironment&&ctor.isClass&&object.allocation&&
            read&&site->getCallee()==read&&owner(read)==f.function&&
            read->getParent()==&f.function->front()&&before(read,site)&&
            !object.publicInstanceFields.count(name)&&
            !ctor.instanceAccessors.count(name)&&method!=ctor.methods.end()&&
            method->second==callee.ref&&!closures_[callee.ref].isClass&&
            nonHelper(closures_[callee.ref].body);
        unsigned readBefore=fieldReads_,writeBefore=fieldWrites_;
        Datum d=invoke(callee.ref,args,self,f,site,MethodMode);
                                                                             
                                                                                 
        if(!failed_&&!abrupt_&&exactReadFrame(f,site)&&primitive(d)&&
           (fieldReads_>readBefore||directNative)&&
           (fieldWrites_==writeBefore||directNative)) {
          if(reads_.size()>=64)return reject("READ_SITE_LIMIT",site);
          reads_.push_back({site,d.traces});
        }
        return d;
      }
                                                                        
                                                                              
                                                                            
      const auto &init=closures_.at(callee.ref);
      const bool specialArgs=std::any_of(args.begin(),args.end(),[](const Datum &a){
        return a.kind==AmbientWindow||a.kind==OpaqueInitializerWindow||a.kind==Closure;
      });
      const bool immediateInit=init.creation==site->getCallee()&&
          init.creation&&owner(init.creation)==f.function&&
          sameInvocationDescendant(init.environment,f.environment)&&specialArgs;
      if(guardPartition_&&(f.mode==GlobalMode||f.mode==DirectMode)&&
         self.kind==Undefined&&llvh::isa<LiteralUndefined>(site->getArgument(0))&&
         !llvh::isa<ConstructInst>(site)&&llvh::isa<LiteralUndefined>(site->getNewTarget())&&
         !callee.receiver&&!callee.brand&&!callee.entryRead&&
         !init.isClass&&!llvh::isa<AsyncFunction>(init.body)&&
         (init.body->getDefinitionKind()==Function::DefinitionKind::ES5Function||
          init.body->getDefinitionKind()==Function::DefinitionKind::ES6Method)&&
         (immediateInit||f.initializerCallbacks.count(callee.ref))) {
        for(auto &a:args)if(a.kind==AmbientWindow)a.kind=OpaqueInitializerWindow;
        if(!std::all_of(args.begin(),args.end(),[this](const Datum &a){return initializerArgument(a);}))
          return reject("INITIALIZER_ARGUMENT_UNPROVEN",site);
        return invoke(callee.ref,args,self,f,site,DirectMode,false,true);
      }
                                                                             
                                                                            
                                                                               
      const auto &local=closures_.at(callee.ref);
      if(guardPartition_&&(f.mode==GlobalMode||f.mode==DirectMode)&&
         self.kind==Undefined&&llvh::isa<LiteralUndefined>(site->getArgument(0))&&
         !llvh::isa<ConstructInst>(site)&&llvh::isa<LiteralUndefined>(site->getNewTarget())&&
         !callee.receiver&&!callee.brand&&!callee.entryRead&&
         !local.isClass&&!llvh::isa<AsyncFunction>(local.body)&&local.body->isStrictMode()&&
         (local.body->getDefinitionKind()==Function::DefinitionKind::ES5Function||
          local.body->getDefinitionKind()==Function::DefinitionKind::ES6Method)&&
         local.creation&&site->getCallee()!=local.creation&&owner(local.creation)==f.function&&
         sameInvocationDescendant(local.environment,f.environment))
        return invoke(callee.ref,args,self,f,site,DirectMode);
                                                                                
                                                                               
                                                                             
       if((f.mode==NativeInitializerMode||f.mode==MethodMode)&&self.kind==Undefined&&
         !closures_[callee.ref].isClass&&closures_[callee.ref].body->isStrictMode()&&
         owner(closures_[callee.ref].creation)==f.function&&
         sameInvocationDescendant(closures_[callee.ref].environment,f.environment))
        return invoke(callee.ref,args,self,f,site,MethodMode);
      if(self.kind==Undefined&&
         (args.empty()||(args.size()==1&&args[0].kind==Scalar&&args[0].knownString&&args[0].traces.empty())||
          (additive_&&args.size()<=16&&std::all_of(args.begin(),args.end(),
              [this](const Datum &a){return boundedArgument(a);})))&&
         (f.mode==GlobalMode||f.mode==DirectMode)&&
         !closures_[callee.ref].isClass&&!callee.receiver&&!callee.brand&&
         closures_[callee.ref].creation==site->getCallee()&&
         owner(closures_[callee.ref].creation)==f.function&&
         sameInvocationDescendant(closures_[callee.ref].environment,f.environment)) {
                                                                            
                                                                                 
        bool definesClass=false;
        for(auto &i:closures_[callee.ref].body->front())
          if(auto *b=llvh::dyn_cast<CallBuiltinInst>(&i))
            if(b->getBuiltinIndex()==BuiltinMethod::HermesBuiltin_initBaseClass)
              definesClass=true;
                                                                            
                                                                                  
                                                                                
        if(!additive_ && !args.empty() && !definesClass)return reject("CLASS_NAME_WRAPPER_UNPROVEN",site);
        if(!additive_ && !definesClass) {
                                                                               
                                                                                 
          auto *creation=closures_[callee.ref].creation;
          if(exactDirectEntry_ || f.mode!=GlobalMode || !f.calls.empty() ||
              f.function!=top_ || site->getParent()!=&top_->front() ||
              !creation->hasOneUser() || !closures_[callee.ref].body->hasOneUser())
            return reject("EXACT_DIRECT_ENTRY_NOT_UNIQUE",site);
          exactDirectEntry_=site;exactDirectBody_=closures_[callee.ref].body;
        }
        return invoke(callee.ref,args,self,f,site,
                      definesClass?WrapperMode:DirectMode);
      }
      if(!additive_&&self.kind==Undefined&&f.mode==GlobalMode&&args.empty())
        return invoke(callee.ref,args,self,f,site,WrapperMode);
    }
    return reject("UNPROVED_CALL_OR_ESCAPE",site);
  }
                                                                     
                                                                          
  bool conditionalGuardPrefix(ThrowIfHasRestrictedGlobalPropertyInst *check,
                              const Frame &f) const {
    if(!top_||!top_->isGlobalScope()||f.mode!=GlobalMode||f.function!=top_||
       owner(check)!=top_||check->getParent()!=&top_->front()||!ids_.count(check))
      return false;
    CreateScopeInst *root=nullptr;GetNewTargetInst *target=nullptr;
    unsigned count=0;
    for(auto &i:top_->front()) {
      if(++count>256)return false;
      if(&i==check)return root!=nullptr;
      if(auto *scope=llvh::dyn_cast<CreateScopeInst>(&i)) {
        if(root||scope->getCreatedScopeDesc()!=top_->getFunctionScopeDesc())return false;
        root=scope;continue;
      }
      if(auto *n=llvh::dyn_cast<GetNewTargetInst>(&i)) {
        if(!root||target)return false;target=n;continue;
      }
      if(auto *store=llvh::dyn_cast<StoreFrameInst>(&i)) {
        if(!root||store->getEnvironment()!=root||
           store->getVariable()->getParent()!=top_->getFunctionScopeDesc())return false;
        auto *v=store->getValue();
        if(!llvh::isa<LiteralEmpty>(v)&&v!=top_->getThisParameter()&&v!=target)return false;
        continue;
      }
      if(auto *prior=llvh::dyn_cast<ThrowIfHasRestrictedGlobalPropertyInst>(&i)) {
        bool visited=false;for(const auto &g:entryGuards_)if(g.site==prior)visited=true;
        if(!visited)return false;continue;
      }
      return false;
    }
    return false;
  }
  bool entryBookkeepingPrefix(
      ThrowIfHasRestrictedGlobalPropertyInst *check,const Frame &f) const {
    if(!top_||!top_->isGlobalScope()||f.mode!=GlobalMode||f.function!=top_||
       owner(check)!=top_||check->getParent()!=&top_->front()||
       !llvh::isa<ReturnInst>(top_->front().getTerminator())||
       !ids_.count(check)||check->getProperty()->getValue().str().empty())
      return false;
    CreateScopeInst *rootScope=nullptr;
    unsigned inspected=0;
                                                                        
                                                                          
                                                         
    for(auto &item:top_->front()) {
      if(++inspected>256)return false;
      if(&item==check)return rootScope!=nullptr;
      if(auto *scope=llvh::dyn_cast<CreateScopeInst>(&item)) {
        if(rootScope||scope->getCreatedScopeDesc()!=top_->getFunctionScopeDesc())
          return false;
        rootScope=scope;continue;
      }
      if(auto *store=llvh::dyn_cast<StoreFrameInst>(&item)) {
        if(!rootScope||store->getEnvironment()!=rootScope||
           store->getVariable()->getParent()!=top_->getFunctionScopeDesc()||
           !llvh::isa<LiteralEmpty>(store->getValue()))return false;
        continue;
      }
      if(auto *prior=llvh::dyn_cast<ThrowIfHasRestrictedGlobalPropertyInst>(&item)) {
                                                                         
                                                                  
        bool recorded=false;
        for(const auto &guard:entryGuards_)
          if(guard.site==prior&&guard.bookkeepingPrefix)recorded=true;
        if(!recorded)return false;
        continue;
      }
      return false;
    }
    return false;
  }
  Datum instruction(Instruction *i,Frame &f) {
    if(guardPartition_) {
      graphSite_=i;
                                                                          
                                                                          
                                                                    
      const bool supported=llvh::isa<AllocObjectInst>(i)||llvh::isa<AllocArrayInst>(i)||
          llvh::isa<StoreOwnPropertyInst>(i)||llvh::isa<StorePropertyInst>(i)||
          llvh::isa<LoadPropertyInst>(i)||llvh::isa<LoadFrameInst>(i)||llvh::isa<StoreFrameInst>(i)||
          llvh::isa<LoadStackInst>(i)||llvh::isa<StoreStackInst>(i);
      if(!supported)clearGraphCertificates();
      if(failed_)return {};
    }
    if(auto *g=llvh::dyn_cast<CreateGeneratorInst>(i))return createAsyncGenerator(g,f);
    if(auto *g=llvh::dyn_cast<GetBuiltinClosureInst>(i)) {
      unsigned op=g->getBuiltinIndex();
      if(op==BuiltinMethod::HermesBuiltin_asyncGeneratorWrap||
         op==BuiltinMethod::HermesBuiltin_asyncGeneratorStart||
         op==BuiltinMethod::HermesBuiltin_asyncGeneratorAwait||
         op==BuiltinMethod::HermesBuiltin_asyncGeneratorDelegate)
        return make(AsyncGeneratorBuiltin,op);
      return reject("ASYNC_GENERATOR_UNKNOWN_BUILTIN",g);
    }
    if(llvh::isa<GetNewTargetInst>(i)) {
      if(f.mode==GlobalMode&&f.function==top_)return make(Undefined);
                                                                         
                                                                     
      if(((f.mode==MethodMode && f.function->isStrictMode()) || (additive_&&f.mode==DirectMode)) && !f.calls.empty()) {
        auto *call=llvh::dyn_cast<CallInst>(f.calls.back());
        if(call && !llvh::isa<ConstructInst>(call) &&
            llvh::isa<LiteralUndefined>(call->getNewTarget()))
          return make(Undefined);
      }
      return reject("NEW_TARGET_CONTEXT_UNPROVEN",i);
    }
    if(!spend(i))return {};
    if(auto *check=llvh::dyn_cast<ThrowIfHasRestrictedGlobalPropertyInst>(i)) {
      const bool prefix=entryBookkeepingPrefix(check,f);
      if(entryGuards_.size()>=64)return reject("ENTRY_GUARD_OBSERVATION_LIMIT",check);
      if(guardPartition_) {
        const bool structural=conditionalGuardPrefix(check,f);
        const unsigned prior=entryGuards_.size();entryGuards_.push_back({check,prefix});
        llvh::outs()<<"[PRIVATE_GUARD_BRANCH] guard="<<id(check)
          <<" prior_pass_guards="<<prior<<" structural_prefix="<<(structural?1:0)
          <<" outcome=THREW continuation=NOT_TAKEN_IF_UNCAUGHT"
          <<" environment=UNPROVEN descriptor_effects=UNMODELED export=0 suppression=0\n";
        llvh::outs()<<"[PRIVATE_GUARD_BRANCH] guard="<<id(check)
          <<" prior_pass_guards="<<prior<<" structural_prefix="<<(structural?1:0)
          <<" outcome=RETURNED hypothesis=ALL_PRIOR_CHECKS_RETURNED_WITHOUT_STATE_CHANGE"
          <<" current_check_effects=ASSUMED_NONE_FOR_EXPLORATION environment=UNPROVEN export=0\n";
        if(!structural||hostName(check->getProperty()->getValue().str().str()))
          return reject("GUARD_PARTITION_PREFIX_OR_HOST_BINDING_UNPROVEN",check);
                                                                        
                                                                      
        return make(Undefined);
      }
      entryGuards_.push_back({check,prefix});
                                                                         
                                                                           
                                                                          
                                                                            
      if(additive_&&ordinaryEntry_&&prefix&&
         !hostName(check->getProperty()->getValue().str().str()))
        return make(Undefined);
                                                                           
                                                                           
                                                                             
                                                                      
                                                                            
      return reject(prefix?"ENTRY_GLOBAL_ENVIRONMENT_UNPROVEN":
                           "ENTRY_GUARD_NOT_BOOKKEEPING_PREFIX",check);
    }
    if(auto *check=llvh::dyn_cast<ThrowIfEmptyInst>(i)) {
      Datum d=value(check->getCheckedValue(),f,check);
      if(failed_)return {};
                                                                            
                                                                              
      if(d.kind==UninitializedBinding)return reject("LEXICAL_TDZ_ABRUPT_UNMODELED",check);
      if(d.kind==Invalid)return reject("LEXICAL_TDZ_VALUE_UNPROVEN",check);
      edge(d,check);return d;
    }
    if(auto *scope=llvh::dyn_cast<CreateScopeInst>(i)) {
      auto e=environments_.find(f.environment);
      if(e==environments_.end()||e->second.creation||
         e->second.invocation!=f.environment||e->second.function!=f.function||
         owner(scope)!=f.function||scope->getCreatedScopeDesc()!=f.function->getFunctionScopeDesc()||
         scope->getCreatedScopeDesc()!=e->second.description)
        return reject("FUNCTION_SCOPE_CREATION_UNPROVEN",scope);
      e->second.creation=scope;return make(Scope,f.environment);
    }
    if(auto *scope=llvh::dyn_cast<CreateInnerScopeInst>(i)) {
      unsigned parent=scopeOperand(scope->getParentScope(),f,scope);
      if(failed_)return {};
      auto *description=scope->getCreatedScopeDesc();
      if(owner(scope)!=f.function||description==f.function->getFunctionScopeDesc()||
         description->getParent()!=environments_.at(parent).description)
        return reject("INNER_SCOPE_PARENT_UNPROVEN",scope);
      unsigned n=environment(parent,description,f.function,f.environment,scope);
      if(failed_)return {};
      environments_.at(n).creation=scope;return make(Scope,n);
    }
    if(llvh::isa<AllocStackInst>(i))return make(Undefined);
    if(auto *s=llvh::dyn_cast<StoreStackInst>(i)) {
      if(f.stack.size()>=128&&!f.stack.count(s->getPtr()))return reject("STACK_LIMIT",s);
      Datum d=value(s->getValue(),f,s);edge(d,s);f.stack[s->getPtr()]=d;return make(Undefined);
    }
    if(auto *l=llvh::dyn_cast<LoadStackInst>(i)) {
      auto it=f.stack.find(l->getPtr());if(it==f.stack.end())return reject("UNRESOLVED_STACK",l);
      Datum d=it->second;edge(d,l);return d;
    }
    if(auto *s=llvh::dyn_cast<StoreFrameInst>(i)) {
      unsigned env=scopeOperand(s->getEnvironment(),f,s);
      if(failed_)return {};
      unsigned target=variableEnvironment(env,s->getVariable(),s);
      if(failed_)return {};
                                                                             
                                                                             
      if(!currentEnvironment(target,f))return reject("CAPTURED_FRAME_WRITE",s);
      Datum d=value(s->getValue(),f,s);if(failed_)return {};
      auto &vars=environments_.at(target).variables;
      auto &states=environments_.at(target).literalFrameStates;
      const bool plainClosure=llvh::isa<CreateFunctionInst>(s->getValue()) && d.kind==Closure &&
          !d.receiver&&!d.brand&&!d.entryRead&&!d.knownString&&!d.knownBool&&!d.knownNumber &&
          closures_.count(d.ref) && closures_.at(d.ref).creation==s->getValue();
      if(guardPartition_ && d.traces.empty() &&
         (llvh::isa<LiteralUndefined>(s->getValue()) || llvh::isa<LiteralEmpty>(s->getValue()) || plainClosure)) {
        if(states.size()>=4096&&!states.count(s->getVariable()))return reject("FRAME_LITERAL_STATE_LIMIT",s);
        states[s->getVariable()]={d.kind,d.ref};
        vars.erase(s->getVariable());
        return make(Undefined);
      }
                                                                                
      if(vars.size()>=128&&!vars.count(s->getVariable()))return reject("FRAME_SLOT_LIMIT",s);
      edge(d,s);vars[s->getVariable()]=d;states.erase(s->getVariable());return make(Undefined);
    }
    if(auto *l=llvh::dyn_cast<LoadFrameInst>(i))return frameLoad(l,f);
    if(auto *c=llvh::dyn_cast<CreateFunctionInst>(i)) {
      unsigned env=scopeOperand(c->getEnvironment(),f,c);
      if(failed_)return {};
      auto *body=c->getFunctionCode();
      if(guardPartition_) {
        if(!body)return reject("CLOSURE_BODY_UNPROVEN",c);
        if(body->getFunctionScopeDesc()->getParent()!=environments_.at(env).description)
          return reject("CLOSURE_LEXICAL_PARENT_UNPROVEN",c);
        if(nextClosure_>2048)return reject("CLOSURE_COUNT_LIMIT",c);
        if(nextClosure_==129)
          llvh::outs()<<"[PRIVATE_GUARD_CLOSURE_CAPACITY] at="<<id(c)<<" next=129 old_limit=128 limit=2048 parent_identity=EXACT environment=UNPROVEN export=0\n";
      } else if(!body||nextClosure_>128||body->getFunctionScopeDesc()->getParent()!=environments_.at(env).description)
        return reject("CLOSURE_IDENTITY_UNPROVEN",c);
      unsigned n=nextClosure_++;closures_.emplace(n,ClosureInfo{body,env,c});return make(Closure,n);
    }
    if(auto *definition=llvh::dyn_cast<StoreGetterSetterInst>(i)) {
      const auto name=key(definition->getProperty());
      Datum o=value(definition->getObject(),f,definition);
      Datum getter=value(definition->getStoredGetter(),f,definition);
      if(failed_ || o.kind!=Record || getter.kind!=Closure || dangerousKey(name) ||
         !llvh::isa<LiteralUndefined>(definition->getStoredSetter()))
        return reject("RECORD_GETTER_DESCRIPTOR_UNPROVEN",definition);
      auto &record=objects_.at(o.ref);const auto &closure=closures_.at(getter.ref);
      if(record.moduleTable || record.allocationEnvironment!=f.environment ||
         owner(record.allocation)!=f.function || closure.isClass ||
         !sameInvocationDescendant(closure.environment,f.environment) || !closure.body->isStrictMode() ||
         !closure.body->getParameters().empty() ||
         llvh::isa<AsyncFunction>(closure.body) || record.ownGetters.size()>=64)
        return reject("RECORD_GETTER_IDENTITY_UNPROVEN",definition);
      record.properties.erase(name);record.ownGetters[name]=getter.ref;
      registeredRecordGetters_.insert(closure.body);
      return make(Undefined);
    }
    if(auto *l=llvh::dyn_cast<LoadPropertyInst>(i))return propertyRead(l,f);
    if(auto *s=llvh::dyn_cast<StorePropertyInst>(i))return propertyStore(s->getObject(),s->getProperty(),s->getStoredValue(),s,f,false);
    if(auto *s=llvh::dyn_cast<StoreOwnPropertyInst>(i))return propertyStore(s->getObject(),s->getProperty(),s->getStoredValue(),s,f,true);
    if(auto *a=llvh::dyn_cast<AllocObjectInst>(i)) {
      if((f.mode!=GlobalMode&&f.mode!=MethodMode&&f.mode!=DirectMode&&f.mode!=ConstructorMode)||
          !llvh::isa<EmptySentinel>(a->getParentObject()))return reject("RECORD_ALLOCATION_UNPROVEN",a);
      unsigned ref=object(a);if(failed_)return {};
      objects_[ref].allocationEnvironment=f.environment;
      return make(Record,ref);
    }
    if(auto *a=llvh::dyn_cast<CreateArgumentsInst>(i)) {
                                                                         
                                                                                 
      if(f.mode==GlobalMode || !f.function->isStrictMode() ||
          f.function->getDefinitionKind()==Function::DefinitionKind::ES6Arrow ||
          f.arguments.size()>64)
        return reject("ARGUMENTS_OWNER_OR_MAPPING_UNPROVEN",a);
      unsigned ref=object(a);if(failed_)return {};
      objects_[ref].elements=f.arguments;
      return make(ArgumentsObject,ref);
    }
    if(auto *a=llvh::dyn_cast<AllocArrayInst>(i)) {
      if(additive_) {
        double count=a->getSizeHint()->getValue();
        if(count<0||count>dataArrayLimit()||count!=unsigned(count))return reject("ARRAY_SIZE_LIMIT",a);
        unsigned ref=object(a);if(failed_)return {};
        auto &arr=objects_.at(ref);arr.allocationEnvironment=f.environment;arr.elements.resize(unsigned(count));
        for(unsigned j=0;j<a->getElementCount();++j){
          if(j>=arr.elements.size())return reject("ARRAY_SIZE_UNPROVEN",a);
          invalidatePrimitiveArray(ref);invalidateGraphCertificate(ref);if(failed_)return {};
          arr.elements[j]=value(a->getArrayElement(j),f,a);
          const auto &element=arr.elements[j];
          if(!primitive(element)&&!(guardPartition_&&(element.kind==Record||element.kind==BoundArray)&&conditionalArrayElement(element)&&
             objects_.at(element.ref).allocationEnvironment==f.environment &&
             owner(objects_.at(element.ref).allocation)==f.function))return reject("ARRAY_ELEMENT_UNPROVEN",a);
        }
        return make(BoundArray,ref);
      }
      if(f.mode!=MethodMode||a->getElementCount())return reject("ARGUMENT_ARRAY_OUTSIDE_PROFILE",a);
      return make(Array,object(a));
    }
    if(auto *begin=llvh::dyn_cast<IteratorBeginInst>(i)) {
      auto found=f.stack.find(llvh::cast<AllocStackInst>(begin->getSourceOrNext()));
      if(!additive_||found==f.stack.end()||found->second.kind!=BoundArray)
        return reject("ARRAY_ITERATOR_SOURCE_UNPROVEN",begin);
      unsigned array=found->second.ref;
      if(objects_.at(array).elements.size()>64)return reject("ARRAY_ITERATOR_SIZE_LIMIT",begin);
      for(const auto &element:objects_.at(array).elements)
        if(!primitive(element))return reject("ARRAY_ITERATOR_HOLE_OR_EFFECT",begin);
      unsigned ref=object(begin);if(failed_)return {};
      objects_.at(ref).iteratorArray=array;return make(BoundArrayIterator,ref);
    }
    if(auto *next=llvh::dyn_cast<IteratorNextInst>(i)) {
      auto it=f.stack.find(llvh::cast<AllocStackInst>(next->getIterator())),src=f.stack.find(llvh::cast<AllocStackInst>(next->getSourceOrNext()));
      if(!additive_||it==f.stack.end()||it->second.kind!=BoundArrayIterator||src==f.stack.end())
        return reject("ARRAY_ITERATOR_IDENTITY_UNPROVEN",next);
      auto &state=objects_.at(it->second.ref);
      if(src->second.kind!=BoundArray||src->second.ref!=state.iteratorArray)
        return reject("ARRAY_ITERATOR_SOURCE_CHANGED",next);
      auto &elements=objects_.at(state.iteratorArray).elements;
      if(state.iteratorIndex>=elements.size()){it->second=make(Undefined);return make(Undefined);}
      Datum d=elements[state.iteratorIndex++];edge(d,next);return d;
    }
    if(auto *close=llvh::dyn_cast<IteratorCloseInst>(i)) {
      auto it=f.stack.find(llvh::cast<AllocStackInst>(close->getIterator()));
      if(!additive_||it==f.stack.end()||it->second.kind!=BoundArrayIterator)
        return reject("ARRAY_ITERATOR_CLOSE_UNPROVEN",close);
                                                                                     
      return make(Undefined);
    }
    if(auto *c=llvh::dyn_cast<CallInst>(i))return call(c,f);
    if(auto *a=llvh::dyn_cast<AsNumericInst>(i)) {
      Datum d=value(a->getSingleOperand(),f,a);
      if(!d.knownNumber&&!d.numericPrimitive)return reject("NUMERIC_COUNTER_COERCION_UNPROVEN",a);
      edge(d,a);
      return d;
    }
    if(auto *u=llvh::dyn_cast<UnaryOperatorInst>(i)) {
      Datum d=value(u->getSingleOperand(),f,u);
      if(guardPartition_&&u->getOperatorStr().str()=="!") {
        if(failed_)return {};
        if(!d.traces.empty())return reject("NOT_TRUTHINESS_UNPROVEN",u);
        bool truth=false;
        if(d.kind==Undefined||d.kind==Null)truth=false;
        else if(d.kind==Scalar&&d.knownBool)truth=d.boolValue;
        else if(d.kind==Scalar&&d.knownString)truth=!d.stringValue.empty();
        else if(d.kind==Scalar&&d.knownNumber)truth=d.number!=0&&d.number==d.number;
        else return reject("NOT_TRUTHINESS_UNPROVEN",u);
        Datum out=make(Scalar);out.knownBool=true;out.boolValue=!truth;return out;
      }
      if(guardPartition_&&u->getOperatorKind()==UnaryOperatorInst::OpKind::TypeofKind) {
        if(failed_)return {};
        std::string type;
        if(d.kind==Undefined)type="undefined";
        else if(d.kind==Null||d.kind==Record||d.kind==Instance||d.kind==Array||
                d.kind==BoundArray||d.kind==Global||d.kind==AmbientWindow||
                d.kind==AmbientDocument)type="object";
        else if(d.kind==Closure)type="function";
        else if(d.kind==Scalar) {
          if(d.knownString)type="string";
          else if(d.knownBool)type="boolean";
          else if(d.knownNumber||d.numericPrimitive)type="number";
        }
        if(type.empty())return reject("TYPEOF_VALUE_KIND_UNPROVEN",u);
                                                                            
                                                                          
        Datum out=make(Scalar);out.knownString=true;out.stringValue=type;return out;
      }
      if(u->getOperatorKind()==UnaryOperatorInst::OpKind::VoidKind)return make(Undefined);
      if((u->getOperatorKind()==UnaryOperatorInst::OpKind::IncKind ||
          u->getOperatorKind()==UnaryOperatorInst::OpKind::DecKind)&&
         (d.knownNumber||d.numericPrimitive)) {
        if(d.knownNumber)d.number+=u->getOperatorKind()==UnaryOperatorInst::OpKind::IncKind?1:-1;
        d.numericPrimitive=true;edge(d,u);return d;
      }
      return reject("UNSUPPORTED_UNARY_OPERATOR",u);
    }
    if(auto *b=llvh::dyn_cast<BinaryOperatorInst>(i)) {
      Datum a=value(b->getLeftHandSide(),f,b),d=value(b->getRightHandSide(),f,b);
      const auto op=b->getOperatorKind();
      if(guardPartition_&&!failed_&&a.kind==Scalar&&d.kind==Scalar&&
         a.knownString&&d.knownString&&a.traces.empty()&&d.traces.empty()&&
         (op==BinaryOperatorInst::OpKind::EqualKind||op==BinaryOperatorInst::OpKind::NotEqualKind||
          op==BinaryOperatorInst::OpKind::StrictlyEqualKind||op==BinaryOperatorInst::OpKind::StrictlyNotEqualKind)) {
                                                                             
        Datum out=make(Scalar);out.knownBool=true;out.boolValue=a.stringValue==d.stringValue;
        if(op==BinaryOperatorInst::OpKind::NotEqualKind||op==BinaryOperatorInst::OpKind::StrictlyNotEqualKind)out.boolValue=!out.boolValue;
        return out;
      }
      if(op==BinaryOperatorInst::OpKind::EqualKind &&
         (llvh::isa<LiteralNull>(b->getLeftHandSide()) || llvh::isa<LiteralNull>(b->getRightHandSide()))) {
        const Datum &tested=llvh::isa<LiteralNull>(b->getLeftHandSide())?d:a;
        const bool proven=tested.kind==Null || tested.kind==Undefined ||
          tested.kind==Closure || tested.kind==NativePrivateCallable ||
          tested.kind==PublicFieldFunction || tested.kind==Instance ||
          tested.kind==Record || tested.kind==Array || tested.kind==AsyncPromise ||
          (tested.kind==Scalar && (tested.knownString||tested.knownNumber||tested.knownBool));
        if(failed_ || !proven)return reject("OPTIONAL_NULL_TEST_UNPROVEN",b);
                                                                                
        Datum out=make(Scalar);out.knownBool=true;
        out.boolValue=tested.kind==Null || tested.kind==Undefined;
        return out;
      }
      if((op==BinaryOperatorInst::OpKind::StrictlyEqualKind ||
          op==BinaryOperatorInst::OpKind::StrictlyNotEqualKind) &&
          (llvh::isa<LiteralUndefined>(b->getLeftHandSide()) ||
           llvh::isa<LiteralUndefined>(b->getRightHandSide()))) {
        if(failed_ || a.kind==Invalid || d.kind==Invalid ||
            a.kind==UninitializedBinding || d.kind==UninitializedBinding)
          return reject("DEFAULT_UNDEFINED_TEST_UNPROVEN",b);
                                                                          
                                                                         
        Datum out=make(Scalar);out.knownBool=true;
        out.boolValue=(a.kind==Undefined)==(d.kind==Undefined);
        if(op==BinaryOperatorInst::OpKind::StrictlyNotEqualKind)out.boolValue=!out.boolValue;
        return out;
      }
      if(op==BinaryOperatorInst::OpKind::MultiplyKind) {
                                                                              
                                                                         
        if(failed_ || a.kind!=Scalar || d.kind!=Scalar ||
           !(a.knownNumber||a.numericPrimitive) || !(d.knownNumber||d.numericPrimitive))
          return reject("NUMERIC_MULTIPLY_COERCION_UNPROVEN",b);
        Datum out=make(Scalar);out.numericPrimitive=true;
        if(a.knownNumber&&d.knownNumber){out.knownNumber=true;out.number=a.number*d.number;}
        out.traces=a.traces;out.traces.insert(out.traces.end(),d.traces.begin(),d.traces.end());edge(out,b);return out;
      }
      if(b->getOperatorKind()!=BinaryOperatorInst::OpKind::AddKind||!primitive(a)||!primitive(d))return reject("COERCION_OR_OPERATOR_UNPROVEN",b);
      Datum out=make(Scalar);if(a.knownNumber&&d.knownNumber){out.knownNumber=true;out.number=a.number+d.number;}
      out.numericPrimitive=(a.knownNumber||a.numericPrimitive)&&(d.knownNumber||d.numericPrimitive);
      out.traces=a.traces;out.traces.insert(out.traces.end(),d.traces.begin(),d.traces.end());edge(out,b);return out;
    }
    if(auto *m=llvh::dyn_cast<MovInst>(i)){Datum d=value(m->getSingleOperand(),f,m);edge(d,m);return d;}
    return reject("UNSUPPORTED_INSTRUCTION_OR_BRANCH",i);
  }
  Datum execute(Frame &f,BasicBlock *start=nullptr) {
    BasicBlock *block=start?start:&f.function->front(), *previous=nullptr;
    auto &visited=f.visited;
    while(block) {
      if(block->getParent()!=f.function || visited.size()>=64 || !visited.insert(block).second)
        return reject("DEFAULT_CFG_CYCLE_OR_LIMIT",block->getTerminator());
      BasicBlock *next=nullptr;
      for(auto &i:*block) {
        if(auto *phi=llvh::dyn_cast<PhiInst>(&i)) {
          if(!previous || !spend(phi))return reject("DEFAULT_PHI_PREDECESSOR_UNPROVEN",phi);
          Value *chosen=nullptr;unsigned matches=0;
          for(unsigned n=0;n<phi->getNumEntries();++n) {
            const auto entry=phi->getEntry(n);
            if(entry.second==previous){chosen=entry.first;++matches;}
          }
          if(matches!=1)return reject("DEFAULT_PHI_PREDECESSOR_UNPROVEN",phi);
          Datum d=value(chosen,f,phi);if(failed_)return {};
          edge(d,phi);f.values[phi]=std::move(d);continue;
        }
        if(auto *branch=llvh::dyn_cast<CondBranchInst>(&i)) {
          if((!((f.mode==MethodMode||f.mode==ConstructorMode)&&f.function->isStrictMode()) &&
              !(guardPartition_&&(f.mode==GlobalMode||f.mode==DirectMode))) || !spend(branch))
            return reject("DEFAULT_BRANCH_CONTEXT_UNPROVEN",branch);
          Datum condition=value(branch->getCondition(),f,branch);
                                                                              
                                                                             
                                                                               
          if(!failed_ && guardPartition_ && f.mode==DirectMode &&
             branch->getCondition()==f.function->getThisParameter() &&
             condition.traces.empty() &&
             ((!f.function->isStrictMode() && f.substitutedGlobalThis && condition.kind==Global) ||
              (f.function->isStrictMode() && condition.kind==Undefined))) {
            bool truth=condition.kind==Global;
            llvh::outs()<<"[PRIVATE_GUARD_THIS_BRANCH] at="<<id(branch)
                <<" strict="<<(f.function->isStrictMode()?1:0)
                <<" receiver="<<(truth?"SUBSTITUTED_GLOBAL_OBJECT":"UNDEFINED")
                <<" truth="<<(truth?1:0)
                <<" context=COMPILED_IR_ONLY environment=UNPROVEN export=0\n";
            next=truth?branch->getTrueDest():branch->getFalseDest();break;
          }
          if(failed_ || !condition.knownBool || !condition.traces.empty())
            return reject("DEFAULT_BRANCH_CONDITION_UNPROVEN",branch);
          next=condition.boolValue?branch->getTrueDest():branch->getFalseDest();break;
        }
        if(auto *branch=llvh::dyn_cast<BranchInst>(&i)) {
          if((!((f.mode==MethodMode||f.mode==ConstructorMode)&&f.function->isStrictMode()) &&
              !(guardPartition_&&(f.mode==GlobalMode||f.mode==DirectMode))) || !spend(branch))
            return reject("DEFAULT_BRANCH_CONTEXT_UNPROVEN",branch);
          next=branch->getBranchDest();break;
        }
      if((f.mode==GlobalMode||additive_||(exactDirectEntry_&&f.mode==DirectMode))&&
         std::find(sinks_.begin(),sinks_.end(),&i)!=sinks_.end()) {
        auto *s=llvh::dyn_cast<StorePropertyInst>(&i);
        if(!s||key(s->getProperty())!="cookie")return reject("UNSUPPORTED_HOST_SINK",&i);
        Datum o=value(s->getObject(),f,s),d=value(s->getStoredValue(),f,s);
        if(o.kind!=AmbientDocument||!primitive(d))return reject("SINK_IDENTITY_UNPROVEN",s);
        if(additive_) {
                                                                      
                                                                          
          edge(d,s);sinkFlows_.push_back({s,d.traces});
          llvh::outs()<<(guardPartition_?"[PRIVATE_GUARD_CONDITIONAL_SINK] sink=":"[PRIVATE_ADDITIVE_SINK] sink=")<<id(s)<<" sources=";
          for(const auto &trace:d.traces)llvh::outs()<<id(trace.source)<<"/";
          llvh::outs()<<" calls=";
          for(auto *call:f.calls)llvh::outs()<<id(call)<<"/";
          llvh::outs()<<" conditional_global="<<(entryGuards_.empty()?0:1);
          if(guardPartition_)llvh::outs()<<" export=0";
          llvh::outs()<<"\n";
        }
        cutoff_=true;reason_="FIRST_HOST_WRITE_CUTOFF";barrier_=s;return make(Undefined);
      }
      if(auto *ret=llvh::dyn_cast<ReturnInst>(&i)){
        Datum d=value(ret->getValue(),f,ret);edge(d,ret);
        if(f.asyncGenerator)finishAsyncGenerator(f,d,true,ret);
        else if(f.asyncPromise)fulfillPrivateAsync(f.asyncPromise,d,ret);
        return d;
      }
      if(auto *y=llvh::dyn_cast<SaveAndYieldInst>(&i)) {
        if(!additive_||(!f.asyncPromise&&!f.asyncGenerator)||!spend(y))return reject("ASYNC_YIELD_UNCERTIFIED",y);
        Datum d=value(y->getResult(),f,y);if(failed_)return {};
        if(f.asyncGenerator) {
          if(d.kind==AsyncAwaitMarker) {
            auto marker=awaitMarkers_.find(d.ref);
            if(marker==awaitMarkers_.end())return reject("ASYNC_GENERATOR_AWAIT_IDENTITY",y);
            d=marker->second;
          } else {
            auto &state=generators_.at(f.asyncGenerator);state.frame=f;state.suspension=y;
            finishAsyncGenerator(f,d,false,y);return make(Undefined);
          }
        }
        AsyncJob job;job.frame=f;job.suspension=y;
        if(d.kind==AsyncPromise) {
          auto token=asyncPromises_.find(d.ref);
          if(token==asyncPromises_.end() || d.ref==f.asyncPromise)
            return reject("ASYNC_AWAIT_TOKEN_IDENTITY",y);
          if(!token->second.fulfilled) {
            if(token->second.waiters.size()>=64)return reject("ASYNC_WAITER_LIMIT",y);
            token->second.waiters.push_back(std::move(job));return make(Undefined);
          }
          d=token->second.value;
        }
        if(!(primitive(d)||d.kind==AsyncIteratorResult))return reject("ASYNC_AWAIT_THENABLE_UNPROVEN",y);
        if(asyncQueue_.size()>=128)return reject("ASYNC_JOB_LIMIT",y);
        edge(d,y);job.value=d;asyncQueue_.push_back(std::move(job));return make(Undefined);
      }
      Datum d=instruction(&i,f);if(failed_||abrupt_)return {};
      if((additive_||exactDirectEntry_)&&cutoff_)return make(Undefined);
      f.values[&i]=std::move(d);
      }
      if(!next)return reject("MISSING_NORMAL_RETURN",block->getTerminator());
      previous=block;block=next;
    }
    return reject("MISSING_NORMAL_RETURN",f.function->front().getTerminator());
  }
  void collectUnreachableSinks() {
                                                                         
                                                                              
                                                                     
    auto *outer=abruptWitness_.outerCall;
    if(!abrupt_||failed_||!outer||cutoff_||owner(outer)!=top_||
        outer->getParent()!=&top_->front()||
        !llvh::isa<ReturnInst>(top_->front().getTerminator())) {
      reject("UNREACHABLE_SINK_SCOPE_UNPROVEN",outer);return;
    }
    for(auto *i:sinks_) {
      auto *sink=llvh::dyn_cast<StorePropertyInst>(i);
      if(!sink||owner(sink)!=top_||sink->getParent()!=outer->getParent()||
          !before(outer,sink)||key(sink->getProperty())!="cookie")continue;
      auto *document=llvh::dyn_cast<LoadPropertyInst>(sink->getObject());
      if(!document||!llvh::isa<GlobalObject>(document->getObject())||
          key(document->getProperty())!="document"||document->getParent()!=sink->getParent()||
          !before(document,sink))continue;
      if(unreachableSinks_.size()>=64){reject("UNREACHABLE_SINK_LIMIT",sink);return;}
      UnreachableSink witness=abruptWitness_;witness.sink=sink;
      unreachableSinks_.push_back(std::move(witness));
    }
  }
 public:
  BoundedPrivateMethodState(Module *m,const std::vector<Instruction *> &sources,const std::vector<Instruction *> &sinks,
      const std::unordered_map<Instruction *, std::string> &ids,
      const PrivateBindingMetadata &metadata,
      bool additive=false,bool ordinaryEntry=false,bool guardPartition=false)
      :metadata_(metadata),module_(m),sources_(sources),sinks_(sinks),ids_(ids),bindings_(metadata.bindings),
       additive_(additive),ordinaryEntry_(ordinaryEntry),guardPartition_(guardPartition){}
  void build() {
    if(used_){reads_.clear();unreachableSinks_.clear();completion_=Completion::UNKNOWN;reject("BUILD_ALREADY_USED");return;}used_=true;
    if(index()&&!failed_) {
      unsigned env=environment(0,top_->getFunctionScopeDesc(),top_,0,nullptr);
      if(!failed_) {
        Frame frame{top_,GlobalMode,env};frame.receiver=make(Global);execute(frame);
      }
    }
    if(additive_ && !failed_ && !cutoff_) {
      for(unsigned n=0;n<asyncQueue_.size()&&!failed_&&!cutoff_;++n) {
        AsyncJob job=asyncQueue_[n];auto *next=resumePrivateAsync(job);
        if(next&&!failed_)execute(job.frame,next);
      }
      if(!failed_&&!cutoff_)for(const auto &p:asyncPromises_)
        if(!p.second.fulfilled || !p.second.waiters.empty())
          reject("ASYNC_PENDING_WORK_UNPROVEN",p.second.call);
    }
    if(additive_&&guardPartition_) {
      llvh::outs()<<"[PRIVATE_GUARD_WORK_PROFILE] steps="<<steps_<<" limit=100000 graph_calls="<<graphCalls_<<" graph_visits="<<graphVisits_
        <<" graph_primitives="<<graphPrimitiveVisits_<<" graph_objects="<<graphObjectVisits_
        <<" cache_hits="<<graphCacheHits_<<" primitive_visits_avoided="<<graphPrimitiveSkips_
        <<" cache_invalidations="<<graphCacheInvalidations_<<" cache_entries="<<primitiveArrayCertificates_.size()
        <<" nested_hits="<<nestedCacheHits_<<" nested_visits_avoided="<<nestedVisitsSkipped_
        <<" nested_invalidated="<<nestedInvalidated_<<" nested_ancestors_invalidated="<<nestedAncestorsInvalidated_
        <<" nested_full_clears="<<nestedClears_<<" nested_maintenance="<<nestedMaintenance_
        <<" nested_entries="<<graphCertificates_.size()<<" nested_edges="<<graphDependencyEdges_
        <<" fingerprint_steps="<<fingerprintSteps_<<" non_graph_steps="<<(steps_-graphVisits_)<<" last_site="<<id(graphSite_)<<" environment=UNPROVEN export=0\n";
      std::vector<std::pair<unsigned,unsigned>> top;
      for(const auto &p:graphRootVisits_)top.emplace_back(p.second,p.first);
      std::sort(top.rbegin(),top.rend());
      for(unsigned n=0;n<top.size()&&n<8;++n){auto r=top[n].second;
        llvh::outs()<<"[PRIVATE_GUARD_WORK_ROOT] ref="<<r<<" allocation="<<id(objects_.at(r).allocation)<<" calls="<<graphRootCalls_[r]<<" visits="<<top[n].first<<" export=0\n";}
      llvh::outs()<<"[PRIVATE_GUARD_PARTITION] status="
        <<(failed_?"UNKNOWN":cutoff_?"CONDITIONAL_SINK":"CONDITIONAL_NO_SINK")
        <<" guards="<<entryGuards_.size()<<" conditional_sinks="<<(failed_?0:sinkFlows_.size())
        <<" reason="<<reason_<<" barrier="<<id(barrier_)
        <<" environment=UNPROVEN coverage=NOT_PROVED export=0 replacement=0 suppression=0\n";
                                                                          
      reads_.clear();publicReads_.clear();unreachableSinks_.clear();sinkFlows_.clear();
      completion_=Completion::UNKNOWN;return;
    }
    if(additive_) {
      llvh::outs()<<"[ASYNC_GENERATOR_STATE] instances="<<generators_.size()<<" status="<<(failed_?"UNKNOWN":"BOUNDED")<<" serial_next_only=1 replacement=0 suppression=0\n";
      llvh::outs()<<"[PRIVATE_ASYNC_STATE] promises="<<asyncPromises_.size()
        <<" resumed="<<asyncResumed_<<" jobs="<<asyncQueue_.size()
        <<" status="<<(failed_?"UNKNOWN":"BOUNDED")<<" replacement=0 suppression=0\n";
                                                                           
      reads_.clear();publicReads_.clear();unreachableSinks_.clear();
      if(failed_||abrupt_)sinkFlows_.clear();
      completion_=Completion::UNKNOWN;
      llvh::outs()<<"[PRIVATE_ADDITIVE_PREFIX] status="
          <<(failed_?"UNKNOWN":cutoff_?"FIRST_SINK_REACHED":"NO_SINK")
          <<" profile="<<(ordinaryEntry_?"EXPLICIT_ORDINARY_PRISTINE_GLOBAL":"NO_ENTRY_ASSUMPTION")
          <<" guards="<<entryGuards_.size()<<" sinks="<<sinkFlows_.size()
          <<" gets="<<nativeGets_<<" sets="<<nativeSets_
          <<" reason="<<reason_<<" barrier="<<id(barrier_)
          <<" replacement=0 suppression=0\n";
      return;
    }
    if(abrupt_&&!failed_)collectUnreachableSinks();
    if(failed_||abrupt_)reads_.clear();
    if(failed_){unreachableSinks_.clear();completion_=Completion::UNKNOWN;}
    else completion_=abrupt_?Completion::PROVED_ABRUPT:Completion::NORMAL;
    collectDormantGetterSinks();
    llvh::outs()<<"[CLOSED_IIFE_DORMANT_GETTER] certified_sinks="<<dormantGetterSinks_.size()<<"\n";
    llvh::outs()<<"[PRIVATE_SCOPE_METADATA] id_mode=SHARED_FULL_MODULE metadata_functions="<<metadataFunctions_
        <<" metadata_instructions="<<metadataInstructions_<<" metadata_global_writes="<<metadataGlobalWrites_
        <<" metadata_scan=SHARED_COMPLETE metadata_facts="<<metadata_.facts
        <<" metadata_fact_limit=250000 helper_mode=DEMAND_FULL_GRAPH demanded_functions="<<demandedFunctions_
        <<" fingerprint_calls="<<fingerprintCalls_<<" classification_cache_hits="<<classificationCacheHits_
        <<" fingerprint_steps="<<fingerprintSteps_<<" execution_steps="<<executionSteps_
        <<" proof_steps="<<steps_<<" proof_limit=100000\n";
    llvh::outs()<<"[NATIVE_PRIVATE_SCALAR_STATE] status="
      <<(failed_?"UNKNOWN":(cutoff_?"PREFIX_TO_FIRST_HOST_WRITE":"BOUNDED_NORMAL_RETURN"))
      <<" tokens="<<nativeCreates_<<" inits="<<nativeInits_
      <<" gets="<<nativeGets_<<" sets="<<nativeSets_
      <<" reason="<<reason_<<" barrier="<<id(barrier_)<<"\n";
    unsigned clean=0;for(const auto &r:reads_)if(r.traces.empty())++clean;
    llvh::outs()<<"[PRIVATE_METHOD_STATE] status="<<(reads_.empty()?"UNKNOWN":"PROVED")
      <<" reads="<<reads_.size()<<" clean_reads="<<clean<<" tainted_reads="<<reads_.size()-clean
      <<" helpers="<<roles_.size()<<" field_reads="<<fieldReads_<<" field_writes="<<fieldWrites_
      <<" counters="<<counters_<<" reason="<<reason_<<" barrier="<<id(barrier_)<<"\n";
    const char *completion=completion_==Completion::NORMAL?"NORMAL":
        completion_==Completion::PROVED_ABRUPT?"PROVED_ABRUPT":"UNKNOWN";
    llvh::outs()<<"[PRIVATE_METHOD_COMPLETION] status="<<completion
        <<" unreachable_sinks="<<unreachableSinks_.size()<<" reads="<<reads_.size()
        <<" reason="<<reason_<<" barrier="<<id(barrier_)<<"\n";
    for(const auto &guard:entryGuards_) {
      llvh::outs()<<"[PRIVATE_ENTRY_GUARD] check="<<id(guard.site)
        <<" bookkeeping_prefix="<<(guard.bookkeepingPrefix?1:0)
        <<" descriptor_effect_proof=UNAVAILABLE pass_path=UNPROVED"
        <<" throw_before_read=UNPROVED read_export=BLOCKED refinement=BLOCKED\n";
    }
    for(const auto &w:unreachableSinks_) {
      llvh::outs()<<"[PRIVATE_METHOD_UNREACHABLE] sink="<<id(w.sink)
          <<" outer_call="<<id(w.outerCall)<<" helper_call="<<id(w.helperCall)
          <<" brand_call="<<id(w.brandCall)<<" throw="<<id(w.throwSite)
          <<" receiver_allocation="<<id(w.receiverAllocation)<<" map_allocation="<<id(w.mapAllocation)
          <<" callable_creation="<<id(w.callableCreation)<<" path=";
      for(auto *i:w.path)llvh::outs()<<id(i)<<"/"<<i->getKindStr()<<" ";
      llvh::outs()<<"\n";
    }
    for(const auto &r:publicReads_) if(r.instance&&hasPublicReadCertificate(r)) {
      std::string encoded;const char *hex="0123456789abcdef";
      for(unsigned char c:r.property){encoded.push_back(hex[c>>4]);encoded.push_back(hex[c&15]);}
      llvh::outs()<<"[PUBLIC_INSTANCE_READ] read="<<id(r.site)
          <<" allocation="<<id(objects_.at(r.instance).allocation)
          <<" key_hex="<<encoded<<" sources="<<r.traces.size()<<"\n";
      for(const auto &t:r.traces)
        llvh::outs()<<"[PUBLIC_INSTANCE_EXACT] source="<<id(t.source)<<" read="<<id(r.site)<<"\n";
    }
    for(const auto &r:reads_) {
      llvh::outs()<<"[PRIVATE_METHOD_READ] read="<<id(r.site)<<" sources="<<r.traces.size()<<"\n";
      for(const auto &t:r.traces) {
        llvh::outs()<<"[PRIVATE_METHOD_EXACT] source="<<id(t.source)<<" read="<<id(r.site)<<" path=";
        for(auto *i:t.path)llvh::outs()<<id(i)<<"/"<<i->getKindStr()<<" ";
        llvh::outs()<<"\n";
      }
    }
  }
                                                                         
                                                                            
                                                                 
  bool hasExactReadCertificate(const Read &read) const {
    if(failed_||abrupt_||completion_!=Completion::NORMAL||!entryGuards_.empty()||
       !top_||!top_->isGlobalScope()||!read.site||
       llvh::isa<ConstructInst>(read.site)||
        !(owner(read.site)==top_ ||
          (exactDirectEntry_ && owner(read.site)==exactDirectBody_)) ||
        read.site->getParent()!=&owner(read.site)->front()||!ids_.count(read.site)||
       !llvh::isa<ReturnInst>(top_->front().getTerminator()))return false;
    bool issuedHere=false;
    unsigned sameSite=0;
    for(const auto &issued:reads_) {
      if(&issued==&read)issuedHere=true;
      if(issued.site==read.site)++sameSite;
    }
    if(!issuedHere||sameSite!=1)return false;
                                                                        
                                                                         
    auto *boundary=cutoff_?barrier_:top_->front().getTerminator();
    if(!boundary||boundary->getParent()!=read.site->getParent()||
       !before(read.site,boundary))return false;
    return true;
  }
  bool hasPublicReadCertificate(const PublicRead &read) const {
    if(read.record) {
      if(failed_||abrupt_||completion_!=Completion::NORMAL||!entryGuards_.empty()||
         !top_||!top_->isGlobalScope()||!read.site||!ids_.count(read.site)||
         !(owner(read.site)==top_ || (exactDirectEntry_&&owner(read.site)==exactDirectBody_))||
         read.site->getParent()!=&owner(read.site)->front()||
         !llvh::isa<ReturnInst>(top_->front().getTerminator()))return false;
      auto object=objects_.find(read.instance);
      if(object==objects_.end()||!object->second.allocation||object->second.moduleTable||
         object->second.properties.count(read.property))return false;
      auto getter=object->second.ownGetters.find(read.property);
      if(getter==object->second.ownGetters.end()||getter->second!=read.getter)return false;
      unsigned matches=0;bool issued=false;
      for(const auto &r:publicReads_){if(&r==&read)issued=true;if(r.site==read.site)++matches;}
      auto *boundary=cutoff_?barrier_:top_->front().getTerminator();
      return issued&&matches==1&&boundary&&boundary->getParent()==read.site->getParent()&&before(read.site,boundary);
    }
    if(failed_||abrupt_||completion_!=Completion::NORMAL||!entryGuards_.empty()||
       !top_||!top_->isGlobalScope()||!read.site||owner(read.site)!=top_||
       read.site->getParent()!=&top_->front()||!ids_.count(read.site)||
       !llvh::isa<ReturnInst>(top_->front().getTerminator()))return false;
    if(read.instance) {
      auto object=objects_.find(read.instance);
      if(object==objects_.end()||!object->second.allocation||!object->second.ctor||
         dangerousKey(read.property))return false;
      if(read.getter) {
        auto ctor=closures_.find(object->second.ctor);
        if(ctor==closures_.end()||object->second.publicInstanceFields.count(read.property))return false;
        auto descriptor=ctor->second.instanceAccessors.find(read.property);
        if(descriptor==ctor->second.instanceAccessors.end()||
           descriptor->second.get!=(read.getter==~0u?0:read.getter))return false;
      } else if(!object->second.publicInstanceFields.count(read.property))return false;
    }
    bool issued=false;unsigned same=0;
    for(const auto &r:publicReads_) {
      if(&r==&read)issued=true;
      if(r.site==read.site)++same;
    }
    auto *boundary=cutoff_?barrier_:top_->front().getTerminator();
    return issued&&same==1&&boundary&&boundary->getParent()==read.site->getParent()&&
        before(read.site,boundary);
  }
  const std::vector<SinkFlow> &sinkFlows()const{return sinkFlows_;}
  const std::vector<Instruction *> &dormantGetterSinks()const{return dormantGetterSinks_;}
  const std::vector<PublicRead> &publicReads()const{return publicReads_;}
  bool hasUnprovenEntryGuard()const{return !entryGuards_.empty();}
  const std::vector<Read> &reads()const{return reads_;}
  Completion completion()const{return completion_;}
  const std::vector<UnreachableSink> &unreachableSinks()const{return unreachableSinks_;}
};
}             
}                    

                                                                        
                                                                         
                                                                              
                                                                               
                                                            
                                                                               
                                                                              
                                                                            
                                                                             
                                                                            
                                                                        
                                                                              
#include <algorithm>
#include <map>
#include <set>

namespace hermes { namespace {
class BoundedGlobalAsyncOverwriteGuard {
  using Path = std::vector<Instruction *>;
  struct Trace {
    Instruction *source;
    Path path;
    unsigned origin;
    bool awaited{false};
  };
  enum Kind { Invalid, Primitive, Undefined, Null, Global, OpaqueGlobalThis,
              Scope, Closure, Instance, DateObject, DateNow, AmbientDocument,
              Helpers, DefineClass, DefineMethod, PromiseToken };
  struct Datum {
    Kind kind{Invalid}; unsigned ref{0};
    std::vector<Trace> traces;
  };
  struct Environment {
    ScopeDesc *descriptor{nullptr}; unsigned parent{0};
    std::map<Variable *, Datum> vars;
  };
  struct ClosureInfo {
    Function *function{nullptr}; CreateFunctionInst *creation{nullptr};
    unsigned environment{0}; bool isClass{false}; unsigned methodOwner{0};
    std::map<std::string,unsigned> methods;
  };
  struct ObjectInfo {
    unsigned constructor{0}; ConstructInst *allocation{nullptr};
    std::map<std::string, Datum> fields;
  };
  struct Frame {
    Function *function{nullptr}; CreateScopeInst *scope{nullptr};
    CallInst *entry{nullptr}; unsigned invocation{0}, environment{0}, parent{0};
    unsigned promise{0}, constructor{0}, definitions{0}, resumes{0};
    Datum receiver; std::vector<Datum> arguments;
    std::map<Value *,Datum> values;
    std::map<AllocStackInst *,Datum> stack;
    std::set<BasicBlock *> visited;
  };
  struct Fulfillment {
    bool fulfilled{false}; Datum value; CallInst *call{nullptr};
    unsigned invocation{0}, receiver{0}; ReturnInst *returned{nullptr};
  };
  struct Continuation {
    Frame frame; SaveAndYieldInst *suspension{nullptr}; Datum value;
    unsigned awaitedPromise{0};
  };
  struct GlobalWriteObservation {
    StorePropertyInst *site{nullptr}; std::string name; Datum value;
    unsigned sequence{0};
  };
  struct GlobalReadObservation {
    LoadPropertyInst *site{nullptr}; std::string name; Datum value;
    StorePropertyInst *latestWrite{nullptr};
    unsigned sequence{0}, invocation{0}; bool afterCertifiedAwait{false};
  };
  struct SinkObservation {
    Instruction *site{nullptr}; Datum value;
    unsigned sequence{0},invocation{0};
  };
  struct FrameWriteObservation {
    StoreFrameInst *site{nullptr}; Variable *variable{nullptr}; Datum value;
    unsigned sequence{0}, environment{0}, invocation{0};
  };
  struct FrameReadObservation {
    LoadFrameInst *site{nullptr}; Variable *variable{nullptr}; Datum value;
    unsigned sequence{0}, environment{0}, invocation{0}, latestWrite{0};
    bool afterCertifiedAwait{false};
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
    bool valid{false};
    const char *reason{"WRAPPER_NOT_CERTIFIED"};
  };
  Module *module_;
  const std::vector<Instruction *> &sources_, &sinks_;
  std::map<Instruction *,std::string> ids_;
  std::map<Function *,unsigned> creationCounts_;
  std::map<AsyncFunction *,Binding> bindings_;
  std::map<unsigned,Environment> environments_;
  std::map<unsigned,ClosureInfo> closures_;
  std::map<unsigned,ObjectInfo> objects_;
  std::map<unsigned,Fulfillment> promises_;
  std::map<std::string,Datum> globals_;
  std::set<std::string> declaredGlobals_;
  std::set<Function *> active_;
  std::vector<Continuation> queue_;
  std::map<StorePropertyInst *,GlobalWriteObservation> globalWrites_;
  std::map<std::string,StorePropertyInst *> latestGlobalWrite_;
  std::map<LoadPropertyInst *,std::vector<GlobalReadObservation>> globalReads_;
  std::map<Instruction *,std::vector<SinkObservation>> observedSinks_;
  std::map<unsigned,FrameWriteObservation> frameWrites_;
  std::map<StoreFrameInst *,std::vector<unsigned>> frameWritesBySite_;
  std::map<unsigned,std::map<Variable *,unsigned>> latestFrameWrite_;
  std::map<LoadFrameInst *,std::vector<FrameReadObservation>> frameReads_;
  std::map<Variable *,bool> uncapturedFrames_;
  unsigned observationSequence_{0},readObservations_{0},sinkObservations_{0};
  unsigned frameReadObservations_{0};
  Function *global_{nullptr};
  unsigned nextEnv_{1},nextClosure_{1},nextObject_{1},nextPromise_{1};
  unsigned steps_{0},invocations_{0},fulfilled_{0},awaits_{0},resumed_{0};
  bool failed_{false},suspended_{false};
  const char *reason_{"NORMAL_CLOSED_ASYNC_ENTRY"}; Instruction *barrier_{nullptr};
  static std::string key(Value *v) {
    auto *s=llvh::dyn_cast<LiteralString>(v); return s?s->getValue().str().str():"";
  }
  static Datum make(Kind k,unsigned n=0) { Datum d;d.kind=k;d.ref=n;return d; }
  static bool primitive(const Datum &d) {return d.kind==Primitive||d.kind==Undefined||d.kind==Null;}
  static bool hostName(const std::string &n) {
    return n=="Date"||n=="document"||n=="Promise"||n=="Function"||n=="Object"||n=="Reflect"||n=="Symbol"||n=="HermesES6Internal";
  }
  bool source(Instruction *i) const {return std::find(sources_.begin(),sources_.end(),i)!=sources_.end();}
  bool sink(Instruction *i) const {return std::find(sinks_.begin(),sinks_.end(),i)!=sinks_.end();}
  std::string id(Instruction *i) const {auto p=ids_.find(i);return p==ids_.end()?"NONE":p->second;}
  Datum reject(const char *why,Instruction *i=nullptr) {
    if(!failed_){reason_=why;barrier_=i;}failed_=true;return {};
  }
  bool tick(Instruction *i) {if(++steps_>30000){reject("PROOF_STEP_LIMIT",i);return false;}return !failed_;}
  bool uncapturedFrame(Variable *variable,Function *owner,CreateScopeInst *scope) {
    if(!variable||!owner||!scope||!llvh::isa<GeneratorInnerFunction>(owner)||
        variable->getParent()!=owner->getFunctionScopeDesc()||
        scope->getParent()->getParent()!=owner||scope->getCreatedScopeDesc()!=variable->getParent())return false;
    auto cached=uncapturedFrames_.find(variable);if(cached!=uncapturedFrames_.end())return cached->second;
    bool valid=!variable->getUsers().empty();
    for(auto *user:variable->getUsers()){
      if(!user->getParent()||user->getParent()->getParent()!=owner){valid=false;break;}
      if(auto *write=llvh::dyn_cast<StoreFrameInst>(user)){
        if(write->getVariable()!=variable||write->getEnvironment()!=scope){valid=false;break;}
      }else if(auto *read=llvh::dyn_cast<LoadFrameInst>(user)){
        if(read->getLoadVariable()!=variable||read->getEnvironment()!=scope){valid=false;break;}
      }else{valid=false;break;}
    }
    uncapturedFrames_[variable]=valid;return valid;
  }
  void observeFrameWrite(StoreFrameInst *site,const Datum &d,Frame &f) {
    if(!f.promise||site->getEnvironment()!=f.scope||!uncapturedFrame(site->getVariable(),f.function,f.scope))return;
    if(frameWrites_.size()>=512){reject("FRAME_WRITE_OBSERVATION_LIMIT",site);return;}
    FrameWriteObservation write;write.site=site;write.variable=site->getVariable();write.value=d;
    write.sequence=++observationSequence_;write.environment=f.environment;write.invocation=f.invocation;
    frameWrites_[write.sequence]=write;frameWritesBySite_[site].push_back(write.sequence);
    latestFrameWrite_[f.environment][write.variable]=write.sequence;
  }
  void observeFrameRead(LoadFrameInst *site,const Datum &d,Frame &f,unsigned resolvedEnvironment) {
                                                                              
                                                                              
    if(!f.promise||resolvedEnvironment!=f.environment||site->getEnvironment()!=f.scope||
        !uncapturedFrame(site->getLoadVariable(),f.function,f.scope))return;
    if(++frameReadObservations_>512){reject("FRAME_READ_OBSERVATION_LIMIT",site);return;}
    FrameReadObservation read;read.site=site;read.variable=site->getLoadVariable();read.value=d;
    read.sequence=++observationSequence_;read.environment=f.environment;read.invocation=f.invocation;
    read.latestWrite=latestFrameWrite_[f.environment][read.variable];read.afterCertifiedAwait=f.resumes>0;
    frameReads_[site].push_back(std::move(read));
  }
  void edge(Datum &d,Instruction *i) {
    std::vector<Trace> out;
    for(auto t:d.traces){
      if(std::any_of(out.begin(),out.end(),[&](const Trace &o){return t.source==o.source&&t.origin==o.origin&&t.awaited==o.awaited;}))continue;
      if(t.path.size()>=256){reject("PATH_LIMIT",i);return;}
      if(t.path.empty()||t.path.back()!=i)t.path.push_back(i);out.push_back(std::move(t));
    }
    if(out.size()>16){reject("TRACE_LIMIT",i);return;}d.traces=std::move(out);
  }
  unsigned environment(Function *f,unsigned parent) {
    if(nextEnv_>256){reject("ENVIRONMENT_LIMIT");return 0;}
    unsigned n=nextEnv_++;environments_[n].descriptor=f->getFunctionScopeDesc();environments_[n].parent=parent;return n;
  }
  Datum value(Value *v,Frame &f,Instruction *at) {
    if(llvh::isa<LiteralNumber>(v)||llvh::isa<LiteralString>(v)||llvh::isa<LiteralBool>(v))return make(Primitive);
    if(llvh::isa<LiteralUndefined>(v))return make(Undefined);
    if(llvh::isa<LiteralNull>(v))return make(Null);
    if(llvh::isa<GlobalObject>(v))return make(Global);
    if(auto *p=llvh::dyn_cast<Parameter>(v)){
      if(p->getParent()!=f.function)return reject("FOREIGN_PARAMETER",at);
      if(p==f.function->getThisParameter())return f.receiver;
      auto &params=f.function->getParameters();
      for(unsigned n=0;n<params.size();++n)if(params[n]==p)return n<f.arguments.size()?f.arguments[n]:make(Undefined);
      return reject("PARAMETER_IDENTITY",at);
    }
    auto q=f.values.find(v);return q==f.values.end()?reject("VALUE_NOT_IN_INVOCATION",at):q->second;
  }
  Binding recognize(AsyncFunction *function) {
    Binding b; b.wrapper = function;
    auto bad = [&](const char *reason) { b.reason = reason; return b; };
    if (function->isLazy() || function->empty() ||
        function->getBasicBlockList().size() != 1 ||
        !function->getParameters().empty() || creationCounts_[function] != 1)
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
            (!llvh::isa<LiteralUndefined>(s->getValue()) && (!closure || !hoists.count(closure))))
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
    if (!scope || !ret || !b.generator || creationCounts_[b.generator] != 1 ||
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
            (!llvh::isa<LiteralUndefined>(s->getValue()) && (!closure || !hoists.count(closure))))
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
        ret = r;
      } else return bad("GENERATOR_NON_SIMPLE_PARAMETERS_OR_EFFECT");
    }
    if (!ret || !b.inner || b.inner->isLazy() || b.inner->empty() ||
        creationCounts_[b.inner] != 1 || b.inner->getParameters().size() > 16)
      return bad("INNER_KIND_OR_LIMIT");
    for (auto *u : b.createGenerator->getUsers()) if (u != ret) return bad("GENERATOR_OBJECT_ESCAPE");
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
    for (auto *formal : b.inner->getParameters()) {
      if (it == b.prefix->end()) return bad("FORMAL_STORE_MISSING");
      auto *store = llvh::dyn_cast<StoreFrameInst>(&*it++);
      if (!store || store->getValue() != formal || store->getEnvironment() != b.innerScope ||
          store->getVariable()->getParent() != b.inner->getFunctionScopeDesc()) return bad("FORMAL_STORE_IDENTITY");
      b.formalStores.push_back(store);
    }
    b.valid = true; b.reason = "EXACT_COMPILER_ASYNC_WRAPPER"; return b;
  }

  Datum globalRead(const std::string &name,Frame &f,LoadPropertyInst *at) {
    auto p=globals_.find(name);if(p!=globals_.end()){
      Datum d=p->second;edge(d,at);
      if(primitive(d)&&declaredGlobals_.count(name)){
        if(at->getObject()!=module_->getGlobalObject()||!latestGlobalWrite_.count(name))
          return reject("GLOBAL_READ_BINDING_IDENTITY",at);
        if(++readObservations_>512)return reject("GLOBAL_READ_OBSERVATION_LIMIT",at);
        GlobalReadObservation read;read.site=at;read.name=name;read.value=d;
        read.latestWrite=latestGlobalWrite_[name];read.sequence=++observationSequence_;
        read.invocation=f.invocation;read.afterCertifiedAwait=f.promise&&f.resumes>0;
        globalReads_[at].push_back(std::move(read));
      }
      return d;
    }
    if(declaredGlobals_.count(name))return reject("GLOBAL_BEFORE_INITIALIZATION",at);
    if(name=="Date")return make(DateObject);
    if(name=="document")return make(AmbientDocument);
    if(name=="HermesES6Internal")return make(Helpers);
    return reject("AMBIENT_GLOBAL_UNRESOLVED",at);
  }
  Datum propertyRead(LoadPropertyInst *l,Frame &f) {
    const auto name=key(l->getProperty());if(name.empty())return reject("DYNAMIC_PROPERTY_READ",l);
    Datum o=value(l->getObject(),f,l);if(failed_)return {};
    if(o.kind==Global)return globalRead(name,f,l);
    if(o.kind==DateObject&&name=="now")return make(DateNow);
    if(o.kind==Helpers){
      if(name=="defineClass")return make(DefineClass);
      if(name=="defineClassMethod")return make(DefineMethod);
    }
    if(o.kind==Instance){
      auto &object=objects_[o.ref];auto p=object.fields.find(name);
      if(p!=object.fields.end()){Datum d=p->second;edge(d,l);return d;}
      auto &ctor=closures_[object.constructor];auto m=ctor.methods.find(name);
      if(m!=ctor.methods.end())return make(Closure,m->second);
      return reject("INSTANCE_PROPERTY_NOT_OWN_OR_CERTIFIED_METHOD",l);
    }
    return reject("PROPERTY_GETTER_OR_ALIAS_OUTSIDE_PROFILE",l);
  }
  Datum storeProperty(StorePropertyInst *s,Frame &f) {
    const auto name=key(s->getProperty());Datum o=value(s->getObject(),f,s),d=value(s->getStoredValue(),f,s);
    if(failed_)return {};
    if(o.kind==Global){
      if(f.function!=global_||name.empty()||!declaredGlobals_.count(name)||hostName(name)||
          s->getObject()!=module_->getGlobalObject()||(!primitive(d)&&d.kind!=Closure))
        return reject("GLOBAL_WRITE_OUTSIDE_PROFILE",s);
      auto old=globals_.find(name);
                                                                           
                                                                               
                                                                             
      if(suspended_){
        const bool scalarOverwrite=old!=globals_.end()&&primitive(old->second)&&primitive(d);
        const bool freshClosure=old==globals_.end()&&d.kind==Closure;
        if(!scalarOverwrite&&!freshClosure)return reject("GLOBAL_MUTATION_AFTER_SUSPENSION",s);
      }
      if(globalWrites_.count(s)||globalWrites_.size()>=256)return reject("GLOBAL_STORE_OBSERVATION_LIMIT",s);
      edge(d,s);globals_[name]=d;
      GlobalWriteObservation write;write.site=s;write.name=name;write.value=d;write.sequence=++observationSequence_;
      globalWrites_[s]=std::move(write);latestGlobalWrite_[name]=s;return make(Undefined);
    }
    if(o.kind==Instance){
      if(!f.constructor||f.receiver.kind!=Instance||f.receiver.ref!=o.ref||
          objects_[o.ref].constructor!=f.constructor||!primitive(d)||name.empty()||name=="__proto__"||
          name=="constructor"||closures_[f.constructor].methods.count(name))
        return reject("INSTANCE_WRITE_OUTSIDE_FRESH_CONSTRUCTOR",s);
      edge(d,s);objects_[o.ref].fields[name]=d;return make(Undefined);
    }
    if(o.kind!=AmbientDocument||name!="cookie"||!sink(s)||!primitive(d))return reject("UNKNOWN_PROPERTY_EFFECT",s);
    edge(d,s);
    if(++sinkObservations_>256)return reject("SINK_OBSERVATION_LIMIT",s);
    SinkObservation observation;observation.site=s;observation.value=d;
    observation.sequence=++observationSequence_;observation.invocation=f.invocation;
                                                                             
                                                                        
    observedSinks_[s].push_back(std::move(observation));
    return make(Undefined);
  }
  void initializeCertifiedScope(Function *function,unsigned env) {
                                                                            
                                                                              
                                                                       
    std::map<CreateFunctionInst *,Datum> hoists;
    for(auto &i:function->front()){
      if(auto *c=llvh::dyn_cast<CreateFunctionInst>(&i)){
        if(llvh::isa<CreateGeneratorInst>(c)||llvh::isa<GeneratorFunction>(c->getFunctionCode()))continue;
        if(nextClosure_>128){reject("HOIST_CLOSURE_LIMIT",c);return;}
        unsigned n=nextClosure_++;auto &info=closures_[n];info.function=c->getFunctionCode();
        info.creation=c;info.environment=env;hoists[c]=make(Closure,n);
      }else if(auto *s=llvh::dyn_cast<StoreFrameInst>(&i)){
        if(llvh::isa<LiteralUndefined>(s->getValue()))environments_[env].vars[s->getVariable()]=make(Undefined);
        else {
          auto *c=llvh::dyn_cast<CreateFunctionInst>(s->getValue());auto p=hoists.find(c);
          if(!c||p==hoists.end()){reject("CERTIFIED_HOIST_INITIALIZATION_MISSING",s);return;}
          environments_[env].vars[s->getVariable()]=p->second;
        }
      }
    }
  }
  Datum callClosure(unsigned closure,const std::vector<Datum> &args,Datum receiver,CallInst *call,bool constructing=false) {
    auto &c=closures_[closure];Function *target=c.function;
    if(!target||target->isLazy()||target->empty()||active_.count(target)||active_.size()>=8||++invocations_>64)
      return reject("CALL_RECURSION_OR_LIMIT",call);
    if(target->getParameters().size()>16||args.size()>16)return reject("ARGUMENT_LIMIT",call);
    if(c.isClass!=constructing)return reject("CONSTRUCTOR_CALL_KIND",call);
    if(c.methodOwner){
      auto *load=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
      if(!load||call->getArgument(0)!=load->getObject()||receiver.kind!=Instance||
          objects_[receiver.ref].constructor!=c.methodOwner)return reject("METHOD_RECEIVER_IDENTITY",call);
    }else if(!constructing&&receiver.kind!=Undefined)return reject("ORDINARY_RECEIVER_OUTSIDE_PROFILE",call);
    Frame f;f.function=target;f.entry=call;f.invocation=invocations_;f.receiver=receiver;f.arguments=args;
                                                                             
                                                                              
                                                         
    if(receiver.kind==Undefined&&!target->isStrictMode())f.receiver=make(OpaqueGlobalThis);
    f.parent=c.environment;f.constructor=constructing?closure:0;
    for(auto &a:f.arguments){if(!primitive(a))return reject("NON_PRIMITIVE_ARGUMENT",call);edge(a,call);}
    if(auto *async=llvh::dyn_cast<AsyncFunction>(target)){
      auto found=bindings_.find(async);if(found==bindings_.end())found=bindings_.emplace(async,recognize(async)).first;
      Binding &b=found->second;if(!b.valid)return reject(b.reason,call);
      if(constructing||c.isClass)return reject("ASYNC_CONSTRUCTOR",call);
                                                                             
                                                                               
                                                                 
      unsigned wrapperEnv=environment(b.wrapper,c.environment);
      unsigned generatorEnv=environment(b.generator,wrapperEnv);
      initializeCertifiedScope(b.wrapper,wrapperEnv);initializeCertifiedScope(b.generator,generatorEnv);
      if(failed_)return {};
      f.function=b.inner;f.parent=generatorEnv;f.environment=environment(b.inner,generatorEnv);
      f.scope=b.innerScope;f.values[f.scope]=make(Scope,f.environment);
      if(nextPromise_>128)return reject("PROMISE_TOKEN_LIMIT",call);
      f.promise=nextPromise_++;
      auto &p=promises_[f.promise];p.call=call;p.invocation=f.invocation;p.receiver=receiver.kind==Instance?receiver.ref:0;
      active_.insert(target);execute(f,b.prefix);active_.erase(target);
      return failed_?Datum{}:make(PromiseToken,f.promise);
    }
    if(llvh::isa<GeneratorFunction>(target)||llvh::isa<GeneratorInnerFunction>(target))return reject("GENERIC_GENERATOR_NOT_ASYNC",call);
    if(target->getDefinitionKind()==Function::DefinitionKind::ES6Constructor&&!constructing)
      return reject("CLASS_CONSTRUCTOR_REQUIRES_NEW",call);
    active_.insert(target);Datum d=execute(f,&target->front());active_.erase(target);
    if(failed_)return {};
    if(constructing){if(d.kind!=Undefined)return reject("CONSTRUCTOR_NON_UNDEFINED_RETURN",call);return receiver;}
    if(!primitive(d)&&d.kind!=Closure)return reject("ORDINARY_RETURN_OBJECT_OR_PROMISE",call);
    edge(d,call);return d;
  }
  Datum invoke(CallInst *call,Frame &f) {
    if(llvh::isa<CallBuiltinInst>(call)||call->getNumArguments()<1||call->getNumArguments()>17)
      return reject("CALL_KIND_OR_ARITY",call);
    Datum callee=value(call->getCallee(),f,call),receiver=value(call->getArgument(0),f,call);
    std::vector<Datum> args;for(unsigned n=1;n<call->getNumArguments();++n)args.push_back(value(call->getArgument(n),f,call));
    if(failed_)return {};
    if(auto *construct=llvh::dyn_cast<ConstructInst>(call)){
      if(callee.kind!=Closure||!closures_[callee.ref].isClass||call->getNewTarget()!=call->getCallee()||
          receiver.kind!=Undefined||nextObject_>64||(f.function==global_&&suspended_))
        return reject("CONSTRUCT_IDENTITY_OR_TIMING",call);
      unsigned object=nextObject_++;objects_[object].constructor=callee.ref;objects_[object].allocation=construct;
      return callClosure(callee.ref,args,make(Instance,object),call,true);
    }
    if(!llvh::isa<LiteralUndefined>(call->getNewTarget()))return reject("CALL_NEWTARGET",call);
    if(callee.kind==DateNow){
      auto *load=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
      if(!load||!args.empty()||receiver.kind!=DateObject||call->getArgument(0)!=load->getObject())
        return reject("DATE_NOW_IDENTITY",call);
      Instruction *src=source(call)?static_cast<Instruction *>(call):source(load)?load:nullptr;
      if(!src)return reject("DATE_SOURCE_NOT_REGISTERED",call);
      Datum d=make(Primitive);d.traces.push_back({src,{src},f.invocation,false});edge(d,call);return d;
    }
    if(callee.kind==DefineClass&&receiver.kind==Helpers&&args.size()==2&&args[0].kind==Closure){
      auto &ctor=closures_[args[0].ref];
      if(f.promise||f.constructor||f.receiver.kind!=Undefined||f.definitions||ctor.isClass||
          ctor.environment!=f.environment||!llvh::isa<LiteralNull>(call->getArgument(2))||
          !ctor.creation||ctor.creation->getParent()->getParent()!=f.function||ctor.function->getParent()!=module_||
          (ctor.function->getDefinitionKind()!=Function::DefinitionKind::ES6Constructor&&
           ctor.function->getDefinitionKind()!=Function::DefinitionKind::ES5Function)||
          llvh::isa<AsyncFunction>(ctor.function)||llvh::isa<GeneratorFunction>(ctor.function)||
          llvh::isa<GeneratorInnerFunction>(ctor.function)||suspended_)
        return reject("NONLOCAL_OR_DERIVED_CLASS_DEFINITION",call);
      ctor.isClass=true;++f.definitions;return make(Undefined);
    }
    if(callee.kind==DefineMethod&&receiver.kind==Helpers&&args.size()==3&&args[0].kind==Closure&&args[2].kind==Closure){
      auto &ctor=closures_[args[0].ref];auto &method=closures_[args[2].ref];const auto name=key(call->getArgument(2));
      if(f.promise||f.constructor||f.definitions!=1||!ctor.isClass||ctor.environment!=f.environment||
          method.environment!=f.environment||method.isClass||method.methodOwner||name.empty()||
          name=="constructor"||name=="__proto__"||name=="then"||ctor.methods.count(name)||suspended_)
        return reject("CLASS_METHOD_DEFINITION_IDENTITY",call);
      method.methodOwner=args[0].ref;ctor.methods[name]=args[2].ref;return make(Undefined);
    }
    if(callee.kind!=Closure)return reject("UNKNOWN_CALLEE_OR_PROMISE_API",call);
    return callClosure(callee.ref,args,receiver,call);
  }
  Datum instruction(Instruction *i,Frame &f) {
    if(!tick(i))return {};
    if(auto *s=llvh::dyn_cast<CreateScopeInst>(i)){
      if(f.scope||s->getCreatedScopeDesc()!=f.function->getFunctionScopeDesc())return reject("SCOPE_IDENTITY",s);
      f.scope=s;f.environment=environment(f.function,f.parent);return make(Scope,f.environment);
    }
    if(auto *a=llvh::dyn_cast<AllocStackInst>(i)){f.stack[a]={};return {};}
    if(auto *s=llvh::dyn_cast<StoreStackInst>(i)){
      if(!f.stack.count(s->getPtr()))return reject("STACK_IDENTITY",s);
      Datum d=value(s->getValue(),f,s);edge(d,s);f.stack[s->getPtr()]=d;return make(Undefined);
    }
    if(auto *l=llvh::dyn_cast<LoadStackInst>(i)){
      auto p=f.stack.find(l->getPtr());if(p==f.stack.end()||p->second.kind==Invalid)return reject("STACK_UNINITIALIZED",l);
      Datum d=p->second;edge(d,l);return d;
    }
    if(auto *s=llvh::dyn_cast<StoreFrameInst>(i)){
      Datum env=value(s->getEnvironment(),f,s),d=value(s->getValue(),f,s);
      if(env.kind!=Scope||env.ref!=f.environment||s->getVariable()->getParent()!=f.function->getFunctionScopeDesc())
        return reject("CAPTURED_FRAME_MUTATION",s);
      if(d.kind==Invalid)return reject("INVALID_FRAME_VALUE",s);
      auto &vars=environments_[f.environment].vars;
      if(f.function==global_&&suspended_){
        auto old=vars.find(s->getVariable());
        if(d.kind!=Closure||old==vars.end()||old->second.kind!=Undefined)
          return reject("GLOBAL_CAPTURE_MUTATION_AFTER_SUSPENSION",s);
      }
      edge(d,s);vars[s->getVariable()]=d;observeFrameWrite(s,d,f);return make(Undefined);
    }
    if(auto *l=llvh::dyn_cast<LoadFrameInst>(i)){
      Datum env=value(l->getEnvironment(),f,l);if(env.kind!=Scope||env.ref!=f.environment)return reject("FRAME_ENVIRONMENT_IDENTITY",l);
      for(unsigned n=f.environment;n;n=environments_[n].parent){
        auto &e=environments_[n];if(e.descriptor!=l->getLoadVariable()->getParent())continue;
        auto p=e.vars.find(l->getLoadVariable());if(p==e.vars.end())return reject("LEXICAL_READ_BEFORE_INITIALIZATION",l);
        Datum d=p->second;edge(d,l);observeFrameRead(l,d,f,n);return d;
      }
      return reject("LEXICAL_ENVIRONMENT_NOT_FOUND",l);
    }
    if(auto *c=llvh::dyn_cast<CreateFunctionInst>(i)){
      Datum env=value(c->getEnvironment(),f,c);
      if(llvh::isa<CreateGeneratorInst>(c)||env.kind!=Scope||env.ref!=f.environment||nextClosure_>128)
        return reject("CLOSURE_ENVIRONMENT_OR_KIND",c);
      unsigned n=nextClosure_++;auto &closure=closures_[n];closure.function=c->getFunctionCode();closure.creation=c;closure.environment=env.ref;
      return make(Closure,n);
    }
    if(llvh::isa<GetNewTargetInst>(i)){
      if(f.function==global_)return make(Undefined);
      return reject("OBSERVABLE_NEWTARGET_OUTSIDE_PROFILE",i);
    }
    if(auto *l=llvh::dyn_cast<LoadPropertyInst>(i))return propertyRead(l,f);
    if(auto *s=llvh::dyn_cast<StorePropertyInst>(i))return storeProperty(s,f);
    if(auto *c=llvh::dyn_cast<CallInst>(i))return invoke(c,f);
    if(auto *b=llvh::dyn_cast<BinaryOperatorInst>(i)){
      Datum a=value(b->getLeftHandSide(),f,b),d=value(b->getRightHandSide(),f,b);
      if(b->getOperatorKind()!=BinaryOperatorInst::OpKind::AddKind||!primitive(a)||!primitive(d))
        return reject("OPERATOR_OR_COERCION_OUTSIDE_PROFILE",b);
      Datum out=make(Primitive);out.traces=a.traces;out.traces.insert(out.traces.end(),d.traces.begin(),d.traces.end());edge(out,b);return out;
    }
    return reject("INSTRUCTION_OUTSIDE_ASYNC_PROFILE",i);
  }
  BasicBlock *resume(Continuation &job) {
    auto *y=job.suspension;auto &f=job.frame;std::vector<Instruction *> ins;
    for(auto &i:*y->getNextBlock())ins.push_back(&i);
    if(ins.size()!=3)return reject("AWAIT_RESUME_BLOCK_SHAPE",y),nullptr;
    auto *r=llvh::dyn_cast<ResumeGeneratorInst>(ins[0]);auto *l=llvh::dyn_cast<LoadStackInst>(ins[1]);
    auto *b=llvh::dyn_cast<CondBranchInst>(ins[2]);auto *slot=r?llvh::dyn_cast<AllocStackInst>(r->getIsReturn()):nullptr;
    if(!r||!l||!b||!slot||!f.stack.count(slot)||l->getPtr()!=slot||b->getCondition()!=l||
        b->getTrueDest()==b->getFalseDest()||b->getTrueDest()->size()!=1)
      return reject("AWAIT_RESUME_OPERAND_IDENTITY",y),nullptr;
    auto *ret=llvh::dyn_cast<ReturnInst>(&b->getTrueDest()->front());
    if(!ret||ret->getValue()!=r)return reject("AWAIT_RETURN_ACTION_BLOCK",y),nullptr;
                                                                                
                                                                               
    Datum d=job.value;if(!primitive(d))return reject("RESUME_VALUE_NOT_PRIMITIVE",r),nullptr;
    for(auto &t:d.traces)t.awaited=true;edge(d,r);f.values[r]=d;
    ++resumed_;++f.resumes;
    llvh::outs()<<"[GLOBAL_ASYNC_OVERWRITE_RESUME] consumer_invocation="<<f.invocation<<" consumer_promise="<<f.promise
      <<" awaited_promise="<<job.awaitedPromise<<" yield="<<id(y)<<" resume="<<id(r);
    if(job.awaitedPromise){auto &p=promises_[job.awaitedPromise];llvh::outs()<<" producer_invocation="<<p.invocation
      <<" receiver_instance="<<p.receiver<<" call="<<id(p.call)<<" return="<<id(p.returned);}
    llvh::outs()<<"\n";
    return b->getFalseDest();
  }
  Datum execute(Frame &f,BasicBlock *block) {
    if(!block||block->getParent()!=f.function||!f.visited.insert(block).second)return reject("CONTROL_OR_LOOP_OUTSIDE_PROFILE",f.entry);
    for(auto &i:*block){
      if(failed_)return {};
      if(auto *ret=llvh::dyn_cast<ReturnInst>(&i)){
        if(!tick(ret))return {};Datum d=value(ret->getValue(),f,ret);edge(d,ret);
        if(f.promise){
          if(!primitive(d))return reject("ASYNC_RETURN_ASSIMILATION_OR_THENABLE",ret);
          auto &p=promises_[f.promise];if(p.fulfilled)return reject("PROMISE_DOUBLE_COMPLETION",ret);
          edge(d,p.call);p.fulfilled=true;p.value=d;p.returned=ret;++fulfilled_;
        }
        return d;
      }
      if(auto *y=llvh::dyn_cast<SaveAndYieldInst>(&i)){
        if(!tick(y)||!f.promise)return reject("YIELD_WITHOUT_CERTIFIED_ASYNC",y);
        Datum d=value(y->getResult(),f,y);unsigned token=0;
        if(d.kind==PromiseToken){
          token=d.ref;auto p=promises_.find(token);
          if(p==promises_.end()||!p->second.fulfilled)return reject("PENDING_PRODUCER_OUTSIDE_PROFILE",y);
          d=p->second.value;
        }
        if(!primitive(d))return reject("AWAIT_THENABLE_OR_UNKNOWN_VALUE",y);
        if(queue_.size()>=64)return reject("CONTINUATION_LIMIT",y);
        edge(d,y);Continuation job;job.frame=f;job.suspension=y;job.value=d;job.awaitedPromise=token;
        queue_.push_back(std::move(job));suspended_=true;++awaits_;return make(Undefined);
      }
      f.values[&i]=instruction(&i,f);
    }
    return reject("ENTRY_WITHOUT_NORMAL_RETURN",f.entry);
  }
  void index() {
    unsigned fi=0,count=0;
    for(auto *g:module_->getGlobalProperties())if(g->isDeclared()){
      auto name=key(g->getName());declaredGlobals_.insert(name);if(hostName(name))reject("HOST_GLOBAL_SHADOWED");
    }
    for(auto &f:*module_){
      if(f.isGlobalScope()){if(global_)reject("MULTIPLE_GLOBAL_ENTRIES");global_=&f;}
      unsigned ii=0;
      for(auto &b:f)for(auto &i:b){
        if(++count>50000){reject("MODULE_METADATA_LIMIT",&i);return;}
        ids_[&i]="F"+std::to_string(fi)+":I"+std::to_string(ii++);
        if(auto *c=llvh::dyn_cast<CreateFunctionInst>(&i))++creationCounts_[c->getFunctionCode()];
        if(llvh::isa<DirectEvalInst>(&i)||llvh::isa<DeletePropertyInst>(&i)||llvh::isa<StoreGetterSetterInst>(&i))
          reject("DYNAMIC_OR_DESCRIPTOR_MUTATION",&i);
        if(auto *s=llvh::dyn_cast<StorePropertyInst>(&i)){
          auto n=key(s->getProperty());
          if(n.empty()||hostName(n)||n=="__proto__"||n=="prototype"||n=="constructor"||n=="now"||
              n=="then"||n=="resolve"||n=="apply"||n=="next"||n=="throw"||n=="return")
            reject("HOST_OR_DYNAMIC_PROPERTY_MUTATION",s);
        }
        if(auto *l=llvh::dyn_cast<LoadPropertyInst>(&i)){
          auto n=key(l->getProperty());
          if(n=="defineProperty"||n=="defineProperties"||n=="__defineGetter__"||n=="__defineSetter__"||n=="setPrototypeOf")
            reject("DESCRIPTOR_API_OUTSIDE_PROFILE",l);
        }
      }++fi;
    }
    if(!global_)reject("GLOBAL_ENTRY_MISSING");
  }
  static bool carriesSource(const Datum &d,Instruction *source) {
    return std::any_of(d.traces.begin(),d.traces.end(),[&](const Trace &t){return t.source==source;});
  }
  bool certifyStalePath(const DefUseAnalyzer::TaintPath &path) {
                                                                            
                                                                              
                                                                            
                                                                   
    auto sinks=observedSinks_.find(path.sink);
    if(!source(path.source)||sinks==observedSinks_.end()||sinks->second.empty()||
        path.path.empty()||path.path.front()!=path.source)return false;
    for(const auto &observation:sinks->second)
      if(carriesSource(observation.value,path.source))return false;
    for(unsigned n=1;n<path.path.size();++n){
      auto *old=llvh::dyn_cast<StorePropertyInst>(path.path[n-1]);
      auto *load=llvh::dyn_cast<LoadPropertyInst>(path.path[n]);
      if(!old||!load||old->getObject()!=module_->getGlobalObject()||
          load->getObject()!=module_->getGlobalObject())continue;
      const auto name=key(old->getProperty());
      if(name.empty()||key(load->getProperty())!=name||!declaredGlobals_.count(name))continue;
      auto original=globalWrites_.find(old);auto reads=globalReads_.find(load);
                                                                         
                                                                         
                                                                               
      if(original==globalWrites_.end()||!primitive(original->second.value)||
          !carriesSource(original->second.value,path.source)||reads==globalReads_.end()||reads->second.empty())continue;
      bool all=true;
      for(const auto &read:reads->second){
        auto later=globalWrites_.find(read.latestWrite);
        if(!read.afterCertifiedAwait||read.name!=name||read.latestWrite==old||
            carriesSource(read.value,path.source)||later==globalWrites_.end()||later->second.name!=name||
            !primitive(later->second.value)||carriesSource(later->second.value,path.source)||
            later->second.sequence<=original->second.sequence||later->second.sequence>=read.sequence){all=false;break;}
      }
      if(!all)continue;
      llvh::outs()<<"[GLOBAL_ASYNC_OVERWRITE_CERT] source="<<id(path.source)<<" sink="<<id(path.sink)
        <<" old_store="<<id(old)<<" load="<<id(load)<<" old_store_sequence="<<original->second.sequence
        <<" read_contexts="<<reads->second.size()<<" sink_contexts="<<sinks->second.size()
        <<" source_absent_all_sink_contexts=1\n";
      for(const auto &read:reads->second){auto &later=globalWrites_.find(read.latestWrite)->second;
        llvh::outs()<<"[GLOBAL_ASYNC_OVERWRITE_READ] load="<<id(load)<<" invocation="<<read.invocation
          <<" read_sequence="<<read.sequence<<" latest_store="<<id(read.latestWrite)
          <<" latest_store_sequence="<<later.sequence<<" after_certified_await=1 source_absent=1\n";}
      return true;
    }
    return false;
  }
  bool certifyStaleFramePath(const DefUseAnalyzer::TaintPath &path) {
    auto sinks=observedSinks_.find(path.sink);
    if(!source(path.source)||sinks==observedSinks_.end()||sinks->second.empty()||
        path.path.empty()||path.path.front()!=path.source)return false;
                                                                              
                                                                  
    for(const auto &observation:sinks->second)
      if(carriesSource(observation.value,path.source))return false;
    for(unsigned n=1;n<path.path.size();++n){
      auto *old=llvh::dyn_cast<StoreFrameInst>(path.path[n-1]);
      auto *load=llvh::dyn_cast<LoadFrameInst>(path.path[n]);
      if(!old||!load||old->getVariable()!=load->getLoadVariable()||
          old->getEnvironment()!=load->getEnvironment()||old->getParent()->getParent()!=load->getParent()->getParent())continue;
      auto *owner=old->getParent()->getParent();auto *scope=llvh::dyn_cast<CreateScopeInst>(old->getEnvironment());
      if(!uncapturedFrame(old->getVariable(),owner,scope))continue;
      auto oldSites=frameWritesBySite_.find(old);auto reads=frameReads_.find(load);
      if(oldSites==frameWritesBySite_.end()||oldSites->second.empty()||reads==frameReads_.end()||reads->second.empty())continue;
      bool all=true;std::vector<unsigned> matchedOlds;
      for(const auto &read:reads->second){
        if(!read.afterCertifiedAwait||read.variable!=old->getVariable()||!primitive(read.value)||
            carriesSource(read.value,path.source)){all=false;break;}
        auto later=frameWrites_.find(read.latestWrite);
        if(later==frameWrites_.end()||later->second.site==old||later->second.variable!=read.variable||
            later->second.environment!=read.environment||later->second.invocation!=read.invocation||
            !primitive(later->second.value)||carriesSource(later->second.value,path.source)||
            later->second.sequence>=read.sequence){all=false;break;}
        unsigned matching=0;
        for(auto seq:oldSites->second){
          const auto &write=frameWrites_.find(seq)->second;
          if(write.environment!=read.environment||write.invocation!=read.invocation)continue;
                                                                           
                                                                            
          if(matching||write.variable!=read.variable||!primitive(write.value)||
              !carriesSource(write.value,path.source)||write.sequence>=later->second.sequence){all=false;break;}
          matching=seq;
        }
        if(!all||!matching){all=false;break;}matchedOlds.push_back(matching);
      }
      if(!all)continue;
      llvh::outs()<<"[ASYNC_FRAME_OVERWRITE_CERT] source="<<id(path.source)<<" sink="<<id(path.sink)
        <<" old_store="<<id(old)<<" load="<<id(load)<<" scope="<<id(scope)
        <<" read_contexts="<<reads->second.size()<<" sink_contexts="<<sinks->second.size()
        <<" uncaptured_same_owner=1 source_absent_all_sink_contexts=1\n";
      for(unsigned j=0;j<reads->second.size();++j){const auto &read=reads->second[j];
        const auto &later=frameWrites_.find(read.latestWrite)->second;
        llvh::outs()<<"[ASYNC_FRAME_OVERWRITE_READ] load="<<id(load)<<" invocation="<<read.invocation
          <<" environment="<<read.environment<<" old_store_sequence="<<matchedOlds[j]
          <<" latest_store="<<id(later.site)<<" latest_store_sequence="<<later.sequence
          <<" read_sequence="<<read.sequence<<" after_certified_await=1 source_absent=1\n";
      }
      return true;
    }
    return false;
  }
 public:
  BoundedGlobalAsyncOverwriteGuard(Module *m,const std::vector<Instruction *> &sources,const std::vector<Instruction *> &sinks)
    :module_(m),sources_(sources),sinks_(sinks){index();}
  void refine(std::vector<DefUseAnalyzer::TaintPath> &paths) {
    const unsigned candidatePaths=paths.size();
    if(candidatePaths>1024)reject("CERTIFICATE_CANDIDATE_LIMIT");
    if(!failed_){Frame f;f.function=global_;f.receiver=make(OpaqueGlobalThis);Datum result=execute(f,&global_->front());
      if(!failed_&&!primitive(result)&&result.kind!=PromiseToken)reject("CLOSED_GLOBAL_COMPLETION_ESCAPE");}
    for(unsigned n=0;n<queue_.size()&&!failed_;++n){Continuation job=queue_[n];auto *next=resume(job);if(next&&!failed_)execute(job.frame,next);}
    if(!failed_)for(const auto &promise:promises_)if(!promise.second.fulfilled){reject("INCOMPLETE_KNOWN_PROMISE");break;}
    unsigned suppressed=0,frameSuppressed=0;
                                                                             
                                                                           
                                                            
    if(!failed_){
      auto end=std::remove_if(paths.begin(),paths.end(),[&](const DefUseAnalyzer::TaintPath &p){
        if(!certifyStalePath(p))return false;++suppressed;return true;
      });paths.erase(end,paths.end());
      auto frameEnd=std::remove_if(paths.begin(),paths.end(),[&](const DefUseAnalyzer::TaintPath &p){
        if(!certifyStaleFramePath(p))return false;++frameSuppressed;return true;
      });paths.erase(frameEnd,paths.end());
    }
    llvh::outs()<<"[GLOBAL_ASYNC_OVERWRITE_GUARD] status="<<(failed_?"UNKNOWN":"PROVED")
      <<" invocations="<<invocations_<<" fulfillments="<<fulfilled_<<" awaits="<<awaits_<<" resumed="<<resumed_
      <<" candidate_paths="<<candidatePaths<<" suppressed="<<suppressed<<" added=0"
      <<" read_observations="<<readObservations_<<" sink_observations="<<sinkObservations_
      <<" steps="<<steps_<<" reason="<<reason_<<" barrier="<<id(barrier_)
      <<" contract=CLOSED_COMPLETE_FIFO_EXACT_GLOBAL_OVERWRITE_ALL_CONTEXT_SOURCE_ABSENCE\n";
    llvh::outs()<<"[ASYNC_FRAME_OVERWRITE_GUARD] status="<<(failed_?"UNKNOWN":"PROVED")
      <<" suppressed="<<frameSuppressed<<" added=0 global_suppressed="<<suppressed
      <<" removed_total="<<(suppressed+frameSuppressed)<<" read_observations="<<frameReadObservations_
      <<" write_observations="<<frameWrites_.size()<<" sink_observations="<<sinkObservations_
      <<" reason="<<reason_<<" barrier="<<id(barrier_)
      <<" contract=CLOSED_COMPLETE_FIFO_UNCAPTURED_CURRENT_ENV_FRAME_OVERWRITE_ALL_CONTEXT_SOURCE_ABSENCE\n";
  }
};
} }                    

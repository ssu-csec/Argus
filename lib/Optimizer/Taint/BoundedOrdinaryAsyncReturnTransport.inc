                                                                                
                                                                              
                                                                           
                                                                       
                                                                            
                                                                                 
                                                                                         
                                                                             
                                                                                
#include <algorithm>
#include <map>
#include <set>

namespace hermes { namespace {
class BoundedOrdinaryAsyncReturnTransport {
  using Path = std::vector<Instruction *>;
  struct Trace {
    Instruction *source;
    Path path;
    unsigned origin;
    bool awaited{false};
    bool restBound{false};
  };
  enum Kind { Invalid, Empty, RestArray, RestIterator, Primitive, Undefined, Null, Global, OpaqueGlobalThis,
              Scope, Closure, Instance, DateObject, DateNow, AmbientDocument,
              Helpers, DefineClass, DefineMethod, PromiseToken, KnownBoolean,
              WeakMapConstructor, FreshWeakMap, WeakMapHas, WeakMapSet, WeakMapGet,
              FreshDate, DateUTCString, PrivateToken };
  struct Datum {
    Kind kind{Invalid}; unsigned ref{0};
    bool knownString{false}; std::string stringValue;
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
    unsigned promise{0}, constructor{0}, definitions{0};
    bool parameterActivation{false};
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
  Module *module_;
  const std::vector<Instruction *> &sources_, &sinks_;
  std::map<Instruction *,std::string> ids_;
  std::map<Function *,unsigned> creationCounts_;
  std::map<AsyncFunction *,Binding> bindings_;
  std::map<unsigned,Environment> environments_;
  std::map<unsigned,ClosureInfo> closures_;
  std::map<unsigned,ObjectInfo> objects_;
  std::map<unsigned,Fulfillment> promises_;
  unsigned nextPrivateToken_{1};
  std::set<unsigned> privateTokens_;
  std::map<std::pair<unsigned,unsigned>,Datum> privateSlots_;
  struct RestCursor { unsigned array,cursor; AllocStackInst *source; };
  std::map<unsigned,std::vector<Datum>> restArrays_;
  std::map<unsigned,RestCursor> restCursors_;
  unsigned nextRestArray_{1},nextRestCursor_{1};
                                                                              
                                                                           
  std::map<unsigned,std::map<unsigned,Datum>> weakMaps_;
  unsigned nextWeakMap_{1}, nextDate_{1}, weakChecks_{0}, weakWrites_{0}, weakReads_{0}, brandChecks_{0};
  std::map<Function *,bool> privateBrandCertificates_;
  std::map<std::string,Datum> globals_;
  std::set<std::string> declaredGlobals_;
  std::set<Function *> active_;
  std::vector<Continuation> queue_;
  std::map<unsigned,std::vector<Continuation>> waiters_;
  unsigned waitingCount_{0};
  std::vector<DefUseAnalyzer::TaintPath> pending_;
  Function *global_{nullptr};
  unsigned nextEnv_{1},nextClosure_{1},nextObject_{1},nextPromise_{1};
  unsigned steps_{0},invocations_{0},fulfilled_{0},awaits_{0},resumed_{0};
  bool failed_{false},suspended_{false};
  const char *reason_{"NORMAL_CLOSED_ASYNC_ENTRY"}; Instruction *barrier_{nullptr};
  static std::string key(Value *v) {
    auto *s=llvh::dyn_cast<LiteralString>(v); return s?s->getValue().str().str():"";
  }
  static Datum make(Kind k,unsigned n=0) { Datum d;d.kind=k;d.ref=n;return d; }
  static bool primitive(const Datum &d) {return d.kind==Primitive||d.kind==Undefined||d.kind==Null||d.kind==KnownBoolean;}
  static bool hostName(const std::string &n) {
    return n=="Date"||n=="document"||n=="Promise"||n=="Function"||n=="Object"||n=="Reflect"||n=="Symbol"||n=="HermesES6Internal"||n=="WeakMap";
  }
  bool source(Instruction *i) const {return std::find(sources_.begin(),sources_.end(),i)!=sources_.end();}
  bool sink(Instruction *i) const {return std::find(sinks_.begin(),sinks_.end(),i)!=sinks_.end();}
  std::string id(Instruction *i) const {auto p=ids_.find(i);return p==ids_.end()?"NONE":p->second;}
  Datum reject(const char *why,Instruction *i=nullptr) {
    if(!failed_){reason_=why;barrier_=i;}failed_=true;return {};
  }
  bool tick(Instruction *i) {if(++steps_>30000){reject("PROOF_STEP_LIMIT",i);return false;}return !failed_;}
  void edge(Datum &d,Instruction *i) {
    std::vector<Trace> out;
    for(auto t:d.traces){
      if(std::any_of(out.begin(),out.end(),[&](const Trace &o){return t.source==o.source&&t.origin==o.origin&&t.awaited==o.awaited&&t.restBound==o.restBound;}))continue;
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
    if(auto *s=llvh::dyn_cast<LiteralString>(v)){Datum d=make(Primitive);d.knownString=true;d.stringValue=s->getValue().str().str();return d;}
    if(llvh::isa<LiteralNumber>(v)||llvh::isa<LiteralBool>(v))return make(Primitive);
    if(llvh::isa<LiteralEmpty>(v))return make(Empty);
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
            (!llvh::isa<LiteralUndefined>(s->getValue()) && !llvh::isa<LiteralEmpty>(s->getValue()) && (!closure || !hoists.count(closure))))
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
            (!llvh::isa<LiteralUndefined>(s->getValue()) && !llvh::isa<LiteralEmpty>(s->getValue()) && (!closure || !hoists.count(closure))))
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
        creationCounts_[b.inner] != 1 || b.inner->getParameters().size() > 16)
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

  Datum globalRead(const std::string &name,Instruction *at) {
    auto p=globals_.find(name);if(p!=globals_.end()){Datum d=p->second;edge(d,at);return d;}
    if(declaredGlobals_.count(name))return reject("GLOBAL_BEFORE_INITIALIZATION",at);
    if(name=="Date")return make(DateObject);
    if(name=="WeakMap")return make(WeakMapConstructor);
    if(name=="document")return make(AmbientDocument);
    if(name=="HermesES6Internal")return make(Helpers);
    return reject("AMBIENT_GLOBAL_UNRESOLVED",at);
  }
  Datum propertyRead(LoadPropertyInst *l,Frame &f) {
    const auto name=key(l->getProperty());if(name.empty())return reject("DYNAMIC_PROPERTY_READ",l);
    Datum o=value(l->getObject(),f,l);if(failed_)return {};
    if(o.kind==Global)return globalRead(name,l);
    if(o.kind==DateObject&&name=="now")return make(DateNow);
    if(o.kind==FreshWeakMap){
      if(name=="has")return make(WeakMapHas,o.ref);
      if(name=="set")return make(WeakMapSet,o.ref);
      if(name=="get")return make(WeakMapGet,o.ref);
    }
    if(o.kind==FreshDate&&name=="toUTCString"){
      Datum d=o;d.kind=DateUTCString;edge(d,l);return d;
    }
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
          (!primitive(d)&&d.kind!=Closure&&d.kind!=FreshWeakMap))return reject("GLOBAL_WRITE_OUTSIDE_PROFILE",s);
      if(suspended_&&(globals_.count(name)||d.kind!=Closure))return reject("GLOBAL_MUTATION_AFTER_SUSPENSION",s);
      edge(d,s);globals_[name]=d;return make(Undefined);
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
    for(auto &t:d.traces)if((t.awaited||t.restBound)&&source(t.source)&&!t.path.empty()&&t.path.front()==t.source){
      if(pending_.size()>=256)return reject("PENDING_PATH_LIMIT",s);
      pending_.emplace_back(t.source,t.path,s);
    }
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
        else if(llvh::isa<LiteralEmpty>(s->getValue()))environments_[env].vars[s->getVariable()]=make(Empty);
        else {
          auto *c=llvh::dyn_cast<CreateFunctionInst>(s->getValue());auto p=hoists.find(c);
          if(!c||p==hoists.end()){reject("CERTIFIED_HOIST_INITIALIZATION_MISSING",s);return;}
          environments_[env].vars[s->getVariable()]=p->second;
        }
      }
    }
  }
                                                                         
                                                                             
                                                                              
                                                                                
  bool exactPrivateBrand(Function *f) {
    auto known=privateBrandCertificates_.find(f);
    if(known!=privateBrandCertificates_.end())return known->second;
    privateBrandCertificates_[f]=false;
    if(!f||f->isLazy()||f->empty()||f->getParameters().size()!=3||
        f->getDefinitionKind()!=Function::DefinitionKind::ES5Function||
        llvh::isa<AsyncFunction>(f)||llvh::isa<GeneratorFunction>(f)||
        llvh::isa<GeneratorInnerFunction>(f)||creationCounts_[f]!=1||
        !f->getThisParameter()->getUsers().empty())return false;
    std::map<Instruction *,unsigned> instructions;
    std::map<BasicBlock *,unsigned> blocks;
    std::map<Variable *,unsigned> variables;
    unsigned ni=0,nb=0;
    for(auto &b:*f){
      blocks[&b]=nb++;
      for(auto &i:b){if(ni>=128||!tick(&i))return false;instructions[&i]=ni++;}
    }
    auto operand=[&](Value *v)->std::string {
      if(auto *i=llvh::dyn_cast<Instruction>(v)){auto p=instructions.find(i);return p==instructions.end()?"?foreign":"i"+std::to_string(p->second);}
      if(auto *b=llvh::dyn_cast<BasicBlock>(v)){auto p=blocks.find(b);return p==blocks.end()?"?block":"b"+std::to_string(p->second);}
      if(auto *p=llvh::dyn_cast<Parameter>(v)){
        if(p->getParent()!=f)return "?parameter";
        return p->isThisParameter()?"this":"p"+std::to_string(p->getIndexInParamList());
      }
      if(auto *var=llvh::dyn_cast<Variable>(v)){
        if(var->getParent()!=f->getFunctionScopeDesc())return "?captured-variable";
        auto p=variables.find(var);if(p==variables.end())p=variables.emplace(var,variables.size()).first;
        return "v"+std::to_string(p->second);
      }
      if(auto *s=llvh::dyn_cast<ScopeDesc>(v))return s==f->getFunctionScopeDesc()?"scope":"?scope";
      if(llvh::isa<GlobalObject>(v))return "global";
      if(llvh::isa<LiteralUndefined>(v))return "u";
      if(llvh::isa<LiteralNull>(v))return "null";
      if(auto *b=llvh::dyn_cast<LiteralBool>(v))return b->getValue()?"true":"false";
      if(auto *n=llvh::dyn_cast<LiteralNumber>(v)){
        if(n->getValue()==0)return "n0";if(n->getValue()==3)return "n3";return "?number";
      }
      if(auto *s=llvh::dyn_cast<LiteralString>(v))return "s["+s->getValue().str().str()+"]";
      return "?operand";
    };
    std::string graph="P"+std::to_string(f->getParameters().size())+"\n";
    for(auto &b:*f){
      graph+="B"+std::to_string(blocks[&b])+"\n";
      for(auto &i:b){
        graph+=std::to_string(instructions[&i])+"="+i.getKindStr().str();
        if(auto *u=llvh::dyn_cast<UnaryOperatorInst>(&i))graph+="["+u->getOperatorStr().str()+"]";
        if(auto *v=llvh::dyn_cast<BinaryOperatorInst>(&i))graph+="["+v->getOperatorStr().str()+"]";
        graph+="(";
        for(unsigned k=0;k<i.getNumOperands();++k){if(k)graph+=",";graph+=operand(i.getOperand(k));}
        graph+=")\n";
      }
    }
    static const char *expected=R"IR(P3
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
    const bool matches=graph==expected;privateBrandCertificates_[f]=matches;return matches;
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
    }else if(!constructing&&receiver.kind!=Undefined&&
        !(receiver.kind==Instance&&objects_.count(receiver.ref)&&target->isStrictMode()))return reject("ORDINARY_RECEIVER_OUTSIDE_PROFILE",call);
    if(!constructing&&!c.methodOwner&&receiver.kind==Undefined&&args.size()==2&&
        args[0].kind==FreshWeakMap&&args[1].kind==Instance&&exactPrivateBrand(target)){
      auto map=weakMaps_.find(args[0].ref);
      if(map==weakMaps_.end()||!objects_.count(args[1].ref)||!map->second.count(args[1].ref))
        return reject("PRIVATE_BRAND_KEY_NOT_PROVEN",call);
      ++brandChecks_;++weakChecks_;
      Datum d=args[1];edge(d,call);return d;
    }
    if(failed_)return {};
    Frame f;f.function=target;f.entry=call;f.invocation=invocations_;f.receiver=receiver;f.arguments=args;
                                                                             
                                                                              
                                                         
    if(receiver.kind==Undefined&&!target->isStrictMode())f.receiver=make(OpaqueGlobalThis);
    f.parent=c.environment;f.constructor=constructing?closure:0;
    for(auto &a:f.arguments){
                                                                             
                                                                            
      if(!primitive(a)&&a.kind!=Instance&&
          (llvh::isa<AsyncFunction>(target)||a.kind!=FreshWeakMap))return reject("NON_PRIMITIVE_ARGUMENT",call);
      edge(a,call);
    }
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
      f.parameterActivation=b.parameterActivation;
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
                                                                        
                                                                             
                                                                             
                                                                       
  bool classDefinitionReceiverAllowed(const Frame &f) const {
    if (f.receiver.kind == Undefined) return true;
    if (f.receiver.kind != OpaqueGlobalThis || !f.function || !f.entry ||
        f.function->isStrictMode() || !f.arguments.empty() ||
        !f.function->getParameters().empty() ||
        f.function->getDefinitionKind() != Function::DefinitionKind::ES5Function ||
        llvh::isa<AsyncFunction>(f.function) ||
        llvh::isa<GeneratorFunction>(f.function) ||
        llvh::isa<GeneratorInnerFunction>(f.function) ||
        !f.function->getThisParameter()->getUsers().empty() ||
        llvh::isa<ConstructInst>(f.entry) || f.entry->getNumArguments() != 1 ||
        !llvh::isa<LiteralUndefined>(f.entry->getNewTarget()) ||
        !llvh::isa<LiteralUndefined>(f.entry->getArgument(0)))
      return false;
    auto *creation = llvh::dyn_cast<CreateFunctionInst>(f.entry->getCallee());
    auto count = creationCounts_.find(f.function);
    if (!creation || llvh::isa<CreateGeneratorInst>(creation) ||
        creation->getFunctionCode() != f.function ||
        creation->getParent()->getParent() != f.entry->getParent()->getParent() ||
        count == creationCounts_.end() || count->second != 1)
      return false;
    for (auto &block : *f.function)
      for (auto &instruction : block)
        if (llvh::isa<CreateArgumentsInst>(&instruction)) return false;
    return true;
  }
  Datum invoke(CallInst *call,Frame &f) {
    if(auto *b=llvh::dyn_cast<CallBuiltinInst>(call)) {
      const auto op=b->getBuiltinIndex();
      if(!llvh::isa<LiteralUndefined>(call->getNewTarget())||!call->getNumArguments()||!llvh::isa<LiteralUndefined>(call->getArgument(0)))return reject("NATIVE_CLASS_ABI_UNPROVEN",call);
      if(op==BuiltinMethod::HermesBuiltin_privateNameCreate&&call->getNumArguments()==1) {
        if(nextPrivateToken_>128||suspended_)return reject("PRIVATE_TOKEN_BOUND_OR_TIMING",call);
        unsigned n=nextPrivateToken_++;privateTokens_.insert(n);return make(PrivateToken,n);
      }
      if(op==BuiltinMethod::HermesBuiltin_privateFieldInit||op==BuiltinMethod::HermesBuiltin_privateFieldGet||op==BuiltinMethod::HermesBuiltin_privateFieldSet) {
        const bool get=op==BuiltinMethod::HermesBuiltin_privateFieldGet,init=op==BuiltinMethod::HermesBuiltin_privateFieldInit;
        if(call->getNumArguments()!=(get?3u:4u))return reject("PRIVATE_SLOT_ARITY",call);
        Datum o=value(call->getArgument(1),f,call),t=value(call->getArgument(2),f,call);
        if(failed_||o.kind!=Instance||!objects_.count(o.ref)||t.kind!=PrivateToken||!privateTokens_.count(t.ref))return reject("PRIVATE_SLOT_IDENTITY",call);
        auto k=std::make_pair(t.ref,o.ref);auto found=privateSlots_.find(k);
        if(init?(found!=privateSlots_.end()):(found==privateSlots_.end()))return reject("PRIVATE_BRAND_OR_REINITIALIZATION",call);
        if(get){Datum d=found->second;edge(d,call);return d;}
        if(suspended_)return reject("PRIVATE_WRITE_AFTER_SUSPENSION",call);
        Datum d=value(call->getArgument(3),f,call);
        if(failed_||(!primitive(d)&&(d.kind!=Closure||!closures_.count(d.ref))))return reject("PRIVATE_SLOT_VALUE_UNPROVEN",call);
        if(init&&privateSlots_.size()>=512)return reject("PRIVATE_SLOT_BOUND",call);
        edge(d,call);privateSlots_[k]=d;return init?make(Undefined):d;
      }
      if(op==BuiltinMethod::HermesBuiltin_defineInstanceClassMethod&&call->getNumArguments()==4) {
        Datum c=value(call->getArgument(1),f,call),k=value(call->getArgument(2),f,call),m=value(call->getArgument(3),f,call);
        if(failed_||c.kind!=Closure||!closures_.count(c.ref)||!closures_.at(c.ref).isClass||m.kind!=Closure||!closures_.count(m.ref)||!k.knownString||!k.traces.empty()||k.stringValue.empty()||k.stringValue=="then"||k.stringValue=="constructor"||k.stringValue=="__proto__"||suspended_)return reject("NATIVE_METHOD_IDENTITIES",call);
        auto &ctor=closures_.at(c.ref);auto &method=closures_.at(m.ref);
        if(ctor.methods.count(k.stringValue)||method.methodOwner||method.isClass)return reject("NATIVE_METHOD_OVERWRITE",call);
        method.methodOwner=c.ref;ctor.methods[k.stringValue]=m.ref;return make(Undefined);
      }
      if(op==BuiltinMethod::HermesBuiltin_initBaseClass&&call->getNumArguments()==2){
        Datum d=value(call->getArgument(1),f,call);
        if(failed_||d.kind!=Closure||!closures_.count(d.ref))return reject("NATIVE_CLASS_IDENTITY",call);
        auto &c=closures_.at(d.ref);
        if(c.isClass||!c.creation||c.creation->getParent()->getParent()!=f.function||c.function->getDefinitionKind()!=Function::DefinitionKind::ES6Constructor||suspended_)return reject("NATIVE_CLASS_DEFINITION_CONTEXT",call);
        c.isClass=true;++f.definitions;return make(Undefined);
      }
      if(op==BuiltinMethod::HermesBuiltin_classElementKey&&call->getNumArguments()==2){
        Datum d=value(call->getArgument(1),f,call);
        if(failed_||!d.knownString||!d.traces.empty())return reject("NATIVE_KEY_COERCION_UNPROVEN",call);
        return d;
      }
      if(op==BuiltinMethod::HermesBuiltin_namePublicFieldFunction&&call->getNumArguments()==3){
        Datum k=value(call->getArgument(1),f,call),d=value(call->getArgument(2),f,call);
        if(failed_||!k.knownString||!k.traces.empty()||d.kind!=Closure||!closures_.count(d.ref))return reject("NATIVE_FUNCTION_NAME_UNPROVEN",call);
        return d;                                           
      }
      if(op==BuiltinMethod::HermesBuiltin_definePublicInstanceClassField&&call->getNumArguments()==4){
        Datum o=value(call->getArgument(1),f,call),k=value(call->getArgument(2),f,call),d=value(call->getArgument(3),f,call);
        if(failed_||o.kind!=Instance||!objects_.count(o.ref)||!k.knownString||!k.traces.empty()||k.stringValue.empty()||k.stringValue=="then"||k.stringValue=="__proto__"||k.stringValue=="constructor"||(!primitive(d)&&(d.kind!=Closure||!closures_.count(d.ref))))return reject("NATIVE_FIELD_IDENTITY_OR_VALUE",call);
        auto &fields=objects_.at(o.ref).fields;
        if(fields.size()>=64&&!fields.count(k.stringValue))return reject("NATIVE_FIELD_BOUND",call);
        edge(d,call);fields[k.stringValue]=d;return make(Undefined);
      }
      if(op!=BuiltinMethod::HermesBuiltin_copyRestArgs)return reject("NATIVE_BUILTIN_OUTSIDE_ASYNC_PROFILE",call);
      auto *n=call->getNumArguments()==2?llvh::dyn_cast<LiteralNumber>(call->getArgument(1)):nullptr;
      if(b->getBuiltinIndex()!=BuiltinMethod::HermesBuiltin_copyRestArgs ||
         !f.promise || !f.parameterActivation || !n || n->getValue()<0 ||
         n->getValue()>16 || n->getValue()!=unsigned(n->getValue()) ||
         !llvh::isa<LiteralUndefined>(call->getNewTarget()) ||
         !llvh::isa<LiteralUndefined>(call->getArgument(0)) || nextRestArray_>64)
        return reject("REST_CALL_FRAME_OR_ABI_UNPROVEN",call);
      unsigned id=nextRestArray_++;auto &a=restArrays_[id];
      for(unsigned k=unsigned(n->getValue());k<f.arguments.size();++k) {
        Datum d=f.arguments[k];if(!primitive(d))return reject("REST_NON_PRIMITIVE",call);
        for(auto &t:d.traces)t.restBound=true;
        edge(d,call);a.push_back(d);
      }
      return make(RestArray,id);
    }
    if(llvh::isa<CallBuiltinInst>(call)||call->getNumArguments()<1||call->getNumArguments()>17)
      return reject("CALL_KIND_OR_ARITY",call);
    Datum callee=value(call->getCallee(),f,call),receiver=value(call->getArgument(0),f,call);
    std::vector<Datum> args;for(unsigned n=1;n<call->getNumArguments();++n)args.push_back(value(call->getArgument(n),f,call));
    if(failed_)return {};
    if(auto *construct=llvh::dyn_cast<ConstructInst>(call)){
      if(callee.kind==WeakMapConstructor){
        if(call->getNewTarget()!=call->getCallee()||receiver.kind!=Undefined||
            !args.empty()||nextWeakMap_>64||suspended_)
          return reject("WEAKMAP_CONSTRUCTION_OUTSIDE_PROFILE",call);
        unsigned n=nextWeakMap_++;weakMaps_[n];return make(FreshWeakMap,n);
      }
      if(callee.kind==DateObject){
        if(call->getNewTarget()!=call->getCallee()||receiver.kind!=Undefined||
            !args.empty()||nextDate_>64||!source(call))
          return reject("DATE_CONSTRUCTION_OUTSIDE_PROFILE",call);
        Datum d=make(FreshDate,nextDate_++);
        d.traces.push_back({call,{call},f.invocation,false});return d;
      }
      if(callee.kind!=Closure||!closures_[callee.ref].isClass||call->getNewTarget()!=call->getCallee()||
          receiver.kind!=Undefined||nextObject_>64||(f.function==global_&&suspended_))
        return reject("CONSTRUCT_IDENTITY_OR_TIMING",call);
      unsigned object=nextObject_++;objects_[object].constructor=callee.ref;objects_[object].allocation=construct;
      return callClosure(callee.ref,args,make(Instance,object),call,true);
    }
    if(!llvh::isa<LiteralUndefined>(call->getNewTarget()))return reject("CALL_NEWTARGET",call);
    if(callee.kind==WeakMapHas||callee.kind==WeakMapSet||callee.kind==WeakMapGet){
      auto *load=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
      if(!load||call->getArgument(0)!=load->getObject()||receiver.kind!=FreshWeakMap||
          receiver.ref!=callee.ref||!weakMaps_.count(receiver.ref)||
          args.size()!=(callee.kind==WeakMapSet?2u:1u)||args[0].kind!=Instance)
        return reject("WEAKMAP_METHOD_RECEIVER_OR_KEY",call);
      auto &entries=weakMaps_[receiver.ref];
      if(callee.kind==WeakMapHas){++weakChecks_;return make(KnownBoolean,entries.count(args[0].ref)?1:0);}
      if(callee.kind==WeakMapGet){
        auto entry=entries.find(args[0].ref);
        Datum d=entry==entries.end()?make(Undefined):entry->second;
                                                                              
                                                                             
        if(!primitive(d))return reject("WEAKMAP_GET_NON_PRIMITIVE",call);
        edge(d,load);edge(d,call);++weakReads_;return d;
      }
      if(suspended_||!primitive(args[1]))return reject("WEAKMAP_WRITE_OUTSIDE_PROFILE",call);
      Datum d=args[1];edge(d,call);entries[args[0].ref]=d;++weakWrites_;return receiver;
    }
    if(callee.kind==DateUTCString){
      auto *load=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
      if(!load||call->getArgument(0)!=load->getObject()||!args.empty()||
          receiver.kind!=FreshDate||receiver.ref!=callee.ref)
        return reject("DATE_FORMAT_RECEIVER_IDENTITY",call);
      Datum d=callee;d.kind=Primitive;d.ref=0;edge(d,call);return d;
    }
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
      if(f.promise||f.constructor||!classDefinitionReceiverAllowed(f)||f.definitions||ctor.isClass||
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
    if(auto *s=llvh::dyn_cast<CreateInnerScopeInst>(i)) {
      Datum parent=value(s->getParentScope(),f,s);
      if(parent.kind!=Scope || s->getCreatedScopeDesc()->getParent()!=environments_[parent.ref].descriptor ||
         nextEnv_>256)return reject("INNER_SCOPE_IDENTITY",s);
      unsigned n=nextEnv_++;environments_[n].descriptor=s->getCreatedScopeDesc();
      environments_[n].parent=parent.ref;return make(Scope,n);
    }
    if(auto *check=llvh::dyn_cast<ThrowIfEmptyInst>(i)) {
      Datum d=value(check->getCheckedValue(),f,check);
      if(d.kind==Empty || d.kind==Invalid)return reject("TDZ_NOT_INITIALIZED",check);
      edge(d,check);return d;
    }
    if(llvh::isa<ThrowIfHasRestrictedGlobalPropertyInst>(i)) {
      if(f.function!=global_)return reject("GLOBAL_GUARD_CONTEXT",i);
      return make(Undefined);                                                 
    }
    if(auto *s=llvh::dyn_cast<StoreOwnPropertyInst>(i)) {
      Datum o=value(s->getObject(),f,s),d=value(s->getStoredValue(),f,s);
      auto *k=llvh::dyn_cast<LiteralNumber>(s->getProperty());
      if(failed_||o.kind!=RestArray||!restArrays_.count(o.ref)||!k||
          !(k->getValue()>=0&&k->getValue()<restArrays_.at(o.ref).size())||
          k->getValue()!=unsigned(k->getValue())||
          (!primitive(d)&&(d.kind!=Closure||!closures_.count(d.ref))))return reject("ARRAY_OWN_WRITE_IDENTITY",s);
      edge(d,s);restArrays_.at(o.ref)[unsigned(k->getValue())]=d;return make(Undefined);
    }
    if(auto *a=llvh::dyn_cast<AllocArrayInst>(i)) {
                                                                         
      const double hint=a->getSizeHint()->getValue();
      if(nextRestArray_>64||!(hint>=0&&hint<=64)||hint!=unsigned(hint)||a->getElementCount()>hint)return reject("ARRAY_SHAPE_OR_BOUND",a);
      unsigned n=nextRestArray_++;auto &items=restArrays_[n];items.resize(unsigned(hint),make(Empty));
      for(unsigned j=0;j<a->getElementCount();++j) {
        Datum d=value(a->getArrayElement(j),f,a);
        if(failed_||(!primitive(d)&&(d.kind!=Closure||!closures_.count(d.ref))))return reject("ARRAY_ELEMENT_UNPROVEN",a);
        edge(d,a);items[j]=d;
      }
      return make(RestArray,n);
    }
    if(auto *begin=llvh::dyn_cast<IteratorBeginInst>(i)) {
      auto *slot=llvh::dyn_cast<AllocStackInst>(begin->getSourceOrNext());auto p=f.stack.find(slot);
      if(!slot || p==f.stack.end() || p->second.kind!=RestArray || nextRestCursor_>64)
        return reject("REST_ITERATOR_SOURCE",begin);
      unsigned n=nextRestCursor_++;restCursors_[n]={p->second.ref,0,slot};return make(RestIterator,n);
    }
    if(auto *next=llvh::dyn_cast<IteratorNextInst>(i)) {
      auto *slot=llvh::dyn_cast<AllocStackInst>(next->getIterator());
      auto *src=llvh::dyn_cast<AllocStackInst>(next->getSourceOrNext());auto p=f.stack.find(slot);
      if(!slot || !src || p==f.stack.end())return reject("REST_ITERATOR_SLOT",next);
      if(p->second.kind==Undefined)return make(Undefined);
      if(p->second.kind!=RestIterator || !restCursors_.count(p->second.ref))
        return reject("REST_ITERATOR_IDENTITY",next);
      auto &c=restCursors_[p->second.ref];auto &a=restArrays_[c.array];auto q=f.stack.find(src);
      if(c.source!=src || q==f.stack.end() || q->second.kind!=RestArray || q->second.ref!=c.array)
        return reject("REST_ARRAY_CHANGED",next);
      if(c.cursor>=a.size()){f.stack[slot]=make(Undefined);return make(Undefined);}
      Datum d=a[c.cursor++];
      if(d.kind==Empty)return reject("ARRAY_HOLE_PROTOTYPE_UNPROVEN",next);
      edge(d,next);return d;
    }
    if(auto *close=llvh::dyn_cast<IteratorCloseInst>(i)) {
      auto *slot=llvh::dyn_cast<AllocStackInst>(close->getIterator());auto p=f.stack.find(slot);
      if(!slot || p==f.stack.end() || (p->second.kind!=Undefined && p->second.kind!=RestIterator))
        return reject("REST_ITERATOR_CLOSE",close);
      return make(Undefined);
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
      if(env.kind!=Scope)return reject("CAPTURED_FRAME_MUTATION",s);
      unsigned target=env.ref;
      while(target && environments_[target].descriptor!=s->getVariable()->getParent())target=environments_[target].parent;
      unsigned local=target;
      while(local && local!=f.environment)local=environments_[local].parent;
      if(!target || !local)return reject("CAPTURED_FRAME_MUTATION",s);
      if(d.kind==Invalid)return reject("INVALID_FRAME_VALUE",s);
      auto &vars=environments_[target].vars;
      if(f.function==global_&&suspended_){
        auto old=vars.find(s->getVariable());
        if(d.kind!=Closure||old==vars.end()||old->second.kind!=Undefined)
          return reject("GLOBAL_CAPTURE_MUTATION_AFTER_SUSPENSION",s);
      }
      edge(d,s);vars[s->getVariable()]=d;return make(Undefined);
    }
    if(auto *l=llvh::dyn_cast<LoadFrameInst>(i)){
      Datum env=value(l->getEnvironment(),f,l);if(env.kind!=Scope)return reject("FRAME_ENVIRONMENT_IDENTITY",l);
      for(unsigned n=env.ref;n;n=environments_[n].parent){
        auto &e=environments_[n];if(e.descriptor!=l->getLoadVariable()->getParent())continue;
        auto p=e.vars.find(l->getLoadVariable());if(p==e.vars.end())return reject("LEXICAL_READ_BEFORE_INITIALIZATION",l);
        Datum d=p->second;edge(d,l);return d;
      }
      return reject("LEXICAL_ENVIRONMENT_NOT_FOUND",l);
    }
    if(auto *c=llvh::dyn_cast<CreateFunctionInst>(i)){
      Datum env=value(c->getEnvironment(),f,c);
      unsigned local=env.kind==Scope?env.ref:0;
      while(local && local!=f.environment)local=environments_[local].parent;
      if(llvh::isa<CreateGeneratorInst>(c)||env.kind!=Scope||!local||nextClosure_>128)
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
    if(auto *u=llvh::dyn_cast<UnaryOperatorInst>(i)) {
      Datum d=value(u->getSingleOperand(),f,u);
      if(!failed_&&u->getOperatorKind()==UnaryOperatorInst::OpKind::VoidKind&&d.kind!=Invalid)return make(Undefined);
      return reject("UNARY_OUTSIDE_ASYNC_PROFILE",u);
    }
    if(auto *b=llvh::dyn_cast<BinaryOperatorInst>(i)){
      Datum a=value(b->getLeftHandSide(),f,b),d=value(b->getRightHandSide(),f,b);
      if(b->getOperatorKind()==BinaryOperatorInst::OpKind::StrictlyEqualKind &&
         ((a.kind==Undefined && (d.kind==Undefined || d.kind==RestIterator)) ||
          (d.kind==Undefined && a.kind==RestIterator)))
        return make(KnownBoolean,a.kind==d.kind);
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
    ++resumed_;
    llvh::outs()<<"[ORDINARY_ASYNC_RESUME] consumer_invocation="<<f.invocation<<" consumer_promise="<<f.promise
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
      if(auto *start=llvh::dyn_cast<TryStartInst>(&i)) {
        if(!tick(start))return {};return execute(f,start->getTryBody());
      }
      if(auto *end=llvh::dyn_cast<TryEndInst>(&i)) {
        if(!tick(end))return {};continue;
      }
      if(auto *branch=llvh::dyn_cast<CondBranchInst>(&i)){
        if(!tick(branch))return {};
        Datum d=value(branch->getCondition(),f,branch);
        if(d.kind!=KnownBoolean)return reject("BRANCH_CONDITION_NOT_EXACT",branch);
        return execute(f,d.ref?branch->getTrueDest():branch->getFalseDest());
      }
      if(auto *branch=llvh::dyn_cast<BranchInst>(&i)){
        if(!tick(branch))return {};return execute(f,branch->getBranchDest());
      }
      if(auto *ret=llvh::dyn_cast<ReturnInst>(&i)){
        if(!tick(ret))return {};Datum d=value(ret->getValue(),f,ret);edge(d,ret);
        if(f.promise){
          if(!primitive(d))return reject("ASYNC_RETURN_ASSIMILATION_OR_THENABLE",ret);
          auto &p=promises_[f.promise];if(p.fulfilled)return reject("PROMISE_DOUBLE_COMPLETION",ret);
          edge(d,p.call);p.fulfilled=true;p.value=d;p.returned=ret;++fulfilled_;
                                                                                 
                                                                           
          auto waiting=waiters_.find(f.promise);
          if(waiting!=waiters_.end()) {
            for(auto &job:waiting->second) {
              if(!waitingCount_||queue_.size()>=64)return reject("CONTINUATION_LIMIT",ret);
              --waitingCount_;job.value=d;edge(job.value,job.suspension);
              queue_.push_back(std::move(job));
            }
            waiters_.erase(waiting);
          }
        }
        return d;
      }
      if(auto *y=llvh::dyn_cast<SaveAndYieldInst>(&i)){
        if(!tick(y)||!f.promise)return reject("YIELD_WITHOUT_CERTIFIED_ASYNC",y);
        Datum d=value(y->getResult(),f,y);unsigned token=0;
        if(f.parameterActivation) {
          if(d.kind!=Undefined || !llvh::isa<LiteralUndefined>(y->getResult()))
            return reject("PARAMETER_ACTIVATION_YIELD",y);
          f.parameterActivation=false;
          Continuation job;job.frame=f;job.suspension=y;job.value=d;
          auto *next=resume(job);f=std::move(job.frame);
          return next&&!failed_?execute(f,next):Datum{};
        }
        if(d.kind==PromiseToken){
          token=d.ref;auto p=promises_.find(token);
          if(p==promises_.end()||token==f.promise)return reject("UNKNOWN_OR_CYCLIC_PRODUCER",y);
          if(!p->second.fulfilled) {
            if(queue_.size()+waitingCount_>=64)return reject("CONTINUATION_LIMIT",y);
            Continuation job;job.frame=f;job.suspension=y;job.awaitedPromise=token;
            waiters_[token].push_back(std::move(job));++waitingCount_;
            suspended_=true;++awaits_;return make(Undefined);
          }
          d=p->second.value;
        }
        if(!primitive(d))return reject("AWAIT_THENABLE_OR_UNKNOWN_VALUE",y);
        if(queue_.size()+waitingCount_>=64)return reject("CONTINUATION_LIMIT",y);
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
              n=="then"||n=="resolve"||n=="apply"||n=="next"||n=="throw"||n=="return"||
              n=="has"||n=="set"||n=="get"||n=="toUTCString")
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
 public:
  BoundedOrdinaryAsyncReturnTransport(Module *m,const std::vector<Instruction *> &sources,const std::vector<Instruction *> &sinks)
    :module_(m),sources_(sources),sinks_(sinks){index();}
  void append(std::vector<DefUseAnalyzer::TaintPath> &paths) {
    if(!failed_){Frame f;f.function=global_;f.receiver=make(OpaqueGlobalThis);execute(f,&global_->front());}
    for(unsigned n=0;n<queue_.size()&&!failed_;++n){Continuation job=queue_[n];auto *next=resume(job);if(next&&!failed_)execute(job.frame,next);}
    if(!failed_&&waitingCount_)reject("UNRESOLVED_PENDING_PRODUCER");
    unsigned added=0;
    if(!failed_)for(auto &p:pending_){
      if(std::any_of(paths.begin(),paths.end(),[&](const DefUseAnalyzer::TaintPath &q){return p.source==q.source&&p.sink==q.sink;}))continue;
      paths.push_back(p);++added;llvh::outs()<<"[ORDINARY_ASYNC_RETURN_TRACE] source="<<id(p.source)<<" sink="<<id(p.sink)<<"\n";
    }
    llvh::outs()<<"[ORDINARY_ASYNC_RETURN_TRANSPORT] status="<<(failed_?"UNKNOWN":"PROVED")
      <<" invocations="<<invocations_<<" fulfillments="<<fulfilled_<<" awaits="<<awaits_<<" resumed="<<resumed_
      <<" weakmaps="<<weakMaps_.size()<<" weak_checks="<<weakChecks_<<" weak_writes="<<weakWrites_
      <<" weak_reads="<<weakReads_<<" brand_checks="<<brandChecks_
      <<" tentative="<<pending_.size()<<" added="<<added<<" steps="<<steps_<<" reason="<<reason_<<" barrier="<<id(barrier_)
      <<" environment=UNPROVEN assumptions=PRISTINE_OBJECT_DATE_PROMISE_ARRAY_ITERATOR_AND_NORMAL_GLOBAL_GUARDS negative_certificate=0"
      <<" contract=EXACT_SPAWN_ASYNC_PRIMITIVE_FULFILLMENT_FIFO_AFTER_GLOBAL_ADDITIVE\n";
  }
};
} }                    

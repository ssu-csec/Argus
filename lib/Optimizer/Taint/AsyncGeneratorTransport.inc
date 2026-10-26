                                                                                
                                                                           
                                                                            
                                                                               
                                                                              
                                                                                 
#include <algorithm>
#include <map>
#include <set>

namespace hermes { namespace {
class BoundedAsyncGeneratorTransport {
  using Path=std::vector<Instruction *>;
  enum Role { Await,Overload,Wrap,WrapBody,Ctor,Resume,Fulfill,Reject,Settle,
    Invoke,Executor,Iterator,Next,Throw,Return,Forward,Factory,Generator,Inner,
    Consumer,ConsumerGenerator,ConsumerInner,RoleCount };
  enum Kind { Bad,Scalar,Undefined,Null,Global,Scope,Closure,Prototype,
    SymbolHost,SymbolIterator,DateHost,DateNow,PromiseHost,PromiseResolve,
    PromiseValue,AwaitValue,Instance,NextMethod,NextPromise,NextResult,Record,Array };
  struct Datum { Kind kind{Bad}; Instruction *identity{nullptr};
    Function *function{nullptr}; std::string text; int truth{-1}; Path path;
    Instruction *source{nullptr}; };
  struct Frame { Function *fn; CreateScopeInst *scope{nullptr};
    std::map<Value *,Datum> values; std::map<Variable *,Datum> vars;
    std::map<AllocStackInst *,Datum> stack; };
  Module *module_; const std::vector<Instruction *> &sources_,&sinks_;
  Function *top_{nullptr}; Function *role_[RoleCount]{};
  std::map<Function *,unsigned> roleIds_;
  std::map<std::string,std::vector<StorePropertyInst *>> bindings_;
  std::map<std::string,unsigned> globalRoles_;
  std::map<Function *,std::vector<CreateFunctionInst *>> creations_;
  std::map<Variable *,std::string> variableIds_;
  std::map<Instruction *,std::string> ids_;
  std::set<std::string> declared_;
  std::map<std::string,Datum> globals_;
  std::map<Instruction *,std::map<std::string,Datum>> records_;
  std::map<std::string,Function *> prototype_;
  CallInst *entry_{nullptr}, *instanceCall_{nullptr}, *nextCall_{nullptr};
  StorePropertyInst *target_{nullptr};
  std::vector<DefUseAnalyzer::TaintPath> pending_;
  unsigned steps_{0}; bool failed_{false},metadataBad_{false},visitedNext_{false};
  const char *reason_{"NO_MATCH"}; Instruction *barrier_{nullptr};
  static Function *owner(Instruction *i){return i->getParent()->getParent();}
  static std::string key(Value *v){auto *s=llvh::dyn_cast<LiteralString>(v);return s?s->getValue().str().str():"";}
  static Datum make(Kind k,Instruction *i=nullptr){Datum d;d.kind=k;d.identity=i;return d;}
  static bool primitive(const Datum &d){return d.kind==Scalar||d.kind==Undefined||d.kind==Null;}
  bool reject(const char *why,Instruction *i=nullptr){if(!failed_){reason_=why;barrier_=i;}failed_=true;return false;}
  Datum bad(const char *why,Instruction *i){reject(why,i);return {};}
  bool spend(Instruction *i){return ++steps_<=30000||reject("PROOF_STEP_LIMIT",i);}
  std::string id(Instruction *i) const {auto f=ids_.find(i);return f==ids_.end()?"NONE":f->second;}
  bool edge(Datum &d,Instruction *i){if(!d.source)return true;if(d.path.size()>=256)return reject("WITNESS_LIMIT",i);if(d.path.empty()||d.path.back()!=i)d.path.push_back(i);return true;}
  static std::vector<Instruction *> instructions(Function *f){std::vector<Instruction *>v;for(auto &b:*f)for(auto &i:b)v.push_back(&i);return v;}
  static std::vector<CreateFunctionInst *> children(Function *f){std::vector<CreateFunctionInst *>v;for(auto *i:instructions(f))if(auto *c=llvh::dyn_cast<CreateFunctionInst>(i))v.push_back(c);return v;}
  bool assign(unsigned r,Function *f){if(!f||f->isLazy()||f->empty())return reject("FUNCTION_MISSING_OR_LAZY");if(role_[r]&&role_[r]!=f)return reject("ROLE_CONFLICT");auto q=roleIds_.find(f);if(q!=roleIds_.end()&&q->second!=r)return reject("ROLE_ALIAS");role_[r]=f;roleIds_[f]=r;return true;}
  Function *globalFunction(Value *v,unsigned r){
    auto *l=llvh::dyn_cast<LoadPropertyInst>(v);
    if(!l||!llvh::isa<GlobalObject>(l->getObject())){reject("CALLEE_NOT_GLOBAL_CLOSURE",llvh::dyn_cast<Instruction>(v));return nullptr;}
    const auto n=key(l->getProperty());auto it=bindings_.find(n);
    if(n.empty()||it==bindings_.end()||it->second.empty()){reject("GLOBAL_CLOSURE_MISSING",l);return nullptr;}
    CreateFunctionInst *creation=nullptr;
    for(auto *s:it->second)if(owner(s)==top_){
      auto *c=llvh::dyn_cast<CreateFunctionInst>(s->getStoredValue());
      if(!c||creation){reject("GLOBAL_CLOSURE_REDEFINED",s);return nullptr;}creation=c;
    }
    if(!creation||!assign(r,creation->getFunctionCode()))return nullptr;
    globalRoles_[n]=r;return creation->getFunctionCode();
  }
  static CallInst *singleCall(Function *f,bool construct=false){CallInst *ans=nullptr;for(auto *i:instructions(f))if(auto *c=llvh::dyn_cast<CallInst>(i))if(llvh::isa<ConstructInst>(c)==construct){if(ans)return nullptr;ans=c;}return ans;}
  Function *parentClosure(Function *f,unsigned r){auto it=creations_.find(f);if(it==creations_.end()||it->second.size()!=1){reject("CLOSURE_CREATION_NOT_UNIQUE");return nullptr;}auto *c=it->second.front();auto *p=owner(c);return assign(r,p)?p:nullptr;}
  bool discover(StorePropertyInst *sink){
    target_=sink;auto *ci=llvh::dyn_cast<GeneratorInnerFunction>(owner(sink));
    if(!ci||!assign(ConsumerInner,ci)||!parentClosure(ci,ConsumerGenerator)||
       !parentClosure(role_[ConsumerGenerator],Consumer))return false;
    if(!llvh::isa<AsyncFunction>(role_[Consumer])||!llvh::isa<GeneratorFunction>(role_[ConsumerGenerator]))return reject("CONSUMER_COMPILER_KIND");
                                                                                
    CallInst *factoryCall=nullptr;
    for(auto *i:instructions(ci))if(auto *c=llvh::dyn_cast<CallInst>(i)){
      auto *l=llvh::dyn_cast<LoadPropertyInst>(c->getCallee());
      if(l&&llvh::isa<GlobalObject>(l->getObject())){factoryCall=c;break;}
    }
    if(!factoryCall||!globalFunction(factoryCall->getCallee(),Forward))return reject("FIRST_FACTORY_CALL_MISSING",factoryCall);
    auto *forwardCall=singleCall(role_[Forward]);
    auto *apply=forwardCall?llvh::dyn_cast<LoadPropertyInst>(forwardCall->getCallee()):nullptr;
    if(!apply||key(apply->getProperty())!="apply"||!globalFunction(apply->getObject(),Factory))return reject("FORWARD_APPLY_SHAPE",forwardCall);
    auto factoryChildren=children(role_[Factory]);
    if(factoryChildren.size()!=1||!assign(Generator,factoryChildren[0]->getFunctionCode())||!llvh::isa<GeneratorFunction>(role_[Generator]))return reject("GENERATOR_CREATION_SHAPE");
    auto genChildren=children(role_[Generator]);
    if(genChildren.size()!=1||!llvh::isa<CreateGeneratorInst>(genChildren[0])||!assign(Inner,genChildren[0]->getFunctionCode())||!llvh::isa<GeneratorInnerFunction>(role_[Inner]))return reject("GENERATOR_INNER_SHAPE");
    CallInst *wrapCall=nullptr;
    for(auto *i:instructions(role_[Factory]))if(auto *c=llvh::dyn_cast<CallInst>(i))if(c->getNumArguments()==2&&c->getArgument(1)==factoryChildren[0])wrapCall=c;
    if(!wrapCall||!globalFunction(wrapCall->getCallee(),Wrap))return reject("WRAP_CALL_MISSING",wrapCall);
    auto wc=children(role_[Wrap]);
    if(wc.size()!=1||!assign(WrapBody,wc[0]->getFunctionCode()))return reject("WRAP_RETURN_CLOSURE");
    auto *ctorCall=singleCall(role_[WrapBody],true);
    if(!ctorCall||!globalFunction(ctorCall->getCallee(),Ctor))return reject("ASYNC_GENERATOR_CTOR",ctorCall);
    auto cc=children(role_[Ctor]);
    if(cc.size()!=3||!assign(Resume,cc[0]->getFunctionCode())||!assign(Settle,cc[1]->getFunctionCode())||!assign(Invoke,cc[2]->getFunctionCode()))return reject("CTOR_CHILDREN");
    auto rc=children(role_[Resume]);auto ic=children(role_[Invoke]);
    if(rc.size()!=2||ic.size()!=1||!assign(Fulfill,rc[0]->getFunctionCode())||!assign(Reject,rc[1]->getFunctionCode())||!assign(Executor,ic[0]->getFunctionCode()))return reject("HELPER_CHILDREN");
    SaveAndYieldInst *yield=nullptr;
    for(auto *i:instructions(role_[Inner]))if(auto *y=llvh::dyn_cast<SaveAndYieldInst>(i)){yield=y;break;}
    auto *awaitCall=yield?llvh::dyn_cast<CallInst>(yield->getResult()):nullptr;
    if(!awaitCall||!globalFunction(awaitCall->getCallee(),Await))return reject("FIRST_YIELD_NOT_AWAIT_MARKER",yield);
    auto *over=singleCall(role_[Await],true);
    if(!over||!globalFunction(over->getCallee(),Overload))return reject("OVERLOAD_CTOR",over);
                                                                                  
    for(auto *i:instructions(top_))if(auto *s=llvh::dyn_cast<StorePropertyInst>(i)){
      auto *p=llvh::dyn_cast<LoadPropertyInst>(s->getObject());auto *l=p?llvh::dyn_cast<LoadPropertyInst>(p->getObject()):nullptr;
      auto *c=llvh::dyn_cast<CreateFunctionInst>(s->getStoredValue());
      auto gr=l?globalRoles_.find(key(l->getProperty())):globalRoles_.end();
      if(!p||!l||!c||key(p->getProperty())!="prototype"||!llvh::isa<GlobalObject>(l->getObject())||gr==globalRoles_.end()||gr->second!=Ctor)continue;
      const auto k=key(s->getProperty());unsigned r=k=="next"?Next:k=="throw"?Throw:k=="return"?Return:Iterator;
      if(!assign(r,c->getFunctionCode()))return false;
    }
                                                                         
    auto cr=creations_.find(role_[Consumer]);
    if(cr==creations_.end()||cr->second.size()!=1)return reject("CONSUMER_CREATION_COUNT");
    for(auto &kv:bindings_)for(auto *s:kv.second)if(s->getStoredValue()==cr->second[0])globalRoles_[kv.first]=Consumer;
    for(unsigned r=0;r<RoleCount;++r)if(!role_[r])return reject("ROLE_NOT_DISCOVERED");
    return true;
  }

#include "AsyncGeneratorGraphs.inc"

  std::string fingerprint(unsigned role){
    Function *f=role_[role];std::map<Instruction *,unsigned> ii;std::map<BasicBlock *,unsigned>bb;
    unsigned n=0;for(auto &b:*f){bb[&b]=bb.size();for(auto &i:b){if(!spend(&i)||n>512)return "";ii[&i]=n++;}}
    auto operand=[&](Value *v)->std::string{
      if(auto *i=llvh::dyn_cast<Instruction>(v)){auto q=ii.find(i);return q==ii.end()?"?foreign":"i"+std::to_string(q->second);}
      if(auto *b=llvh::dyn_cast<BasicBlock>(v)){auto q=bb.find(b);return q==bb.end()?"?block":"b"+std::to_string(q->second);}
      if(auto *fn=llvh::dyn_cast<Function>(v)){auto q=roleIds_.find(fn);return q==roleIds_.end()?"?function":"f"+std::to_string(q->second);}
      if(auto *p=llvh::dyn_cast<Parameter>(v))return p->getParent()!=f?"?param":p->isThisParameter()?"this":"p"+std::to_string(p->getIndexInParamList());
      if(auto *s=llvh::dyn_cast<ScopeDesc>(v)){auto q=roleIds_.find(s->hasFunction()?s->getFunction():nullptr);return q==roleIds_.end()?"?scope":"scope"+std::to_string(q->second);}
      if(auto *v0=llvh::dyn_cast<Variable>(v)){auto q=variableIds_.find(v0);return q==variableIds_.end()?"?variable":q->second;}
      if(llvh::isa<GlobalObject>(v))return "global";
      if(llvh::isa<LiteralUndefined>(v))return "u";
      if(llvh::isa<LiteralNull>(v))return "null";
      if(llvh::isa<EmptySentinel>(v))return "empty";
      if(llvh::isa<Label>(v))return "L";
      if(auto *b=llvh::dyn_cast<LiteralBool>(v))return b->getValue()?"true":"false";
      if(auto *n0=llvh::dyn_cast<LiteralNumber>(v)){const double n=n0->getValue();return n>=-10&&n<=10&&n==static_cast<int>(n)?"n"+std::to_string(static_cast<int>(n)):"?number";}
      if(auto *s=llvh::dyn_cast<LiteralString>(v)){const auto k=key(s);auto q=globalRoles_.find(k);return q==globalRoles_.end()?"s["+k+"]":"R"+std::to_string(q->second);}
      return "?operand";
    };
    std::string out="P"+std::to_string(f->getParameters().size())+"\n";
    for(auto &b:*f){out+="B"+std::to_string(bb[&b])+"\n";for(auto &i:b){
      out+=std::to_string(ii[&i])+"="+i.getKindStr().str();
      if(auto *u=llvh::dyn_cast<UnaryOperatorInst>(&i))out+="["+u->getOperatorStr().str()+"]";
      if(auto *v=llvh::dyn_cast<BinaryOperatorInst>(&i))out+="["+v->getOperatorStr().str()+"]";
      out+="(";
      if(auto *g=llvh::dyn_cast<GetBuiltinClosureInst>(&i))out+=g->getBuiltinIndex()==BuiltinMethod::HermesBuiltin_spawnAsync?"BuiltinSpawn":"?builtin";
      else for(unsigned k=0;k<i.getNumOperands();++k){if(k)out+=",";out+=operand(i.getOperand(k));}
      out+=")\n";
    }}return out;
  }
  bool certify(){
                                                                            
                                                                            
    std::map<Function *,unsigned> nextVariable;
    for(unsigned r=0;r<RoleCount;++r)for(auto *i:instructions(role_[r]))for(unsigned k=0;k<i->getNumOperands();++k)
      if(auto *v=llvh::dyn_cast<Variable>(i->getOperand(k))){auto *s=v->getParent();auto q=roleIds_.find(s->hasFunction()?s->getFunction():nullptr);if(q==roleIds_.end())return reject("FOREIGN_CAPTURE",i);if(!variableIds_.count(v))variableIds_[v]="v"+std::to_string(q->second)+"."+std::to_string(nextVariable[q->first]++);}
    for(unsigned r=0;r<RoleCount;++r){
      if(creations_[role_[r]].size()!=1)return reject("SHARED_CLOSURE_CREATION");
      if(r==Inner||r==ConsumerInner)continue;
      if(r<Generator&&(llvh::isa<GeneratorFunction>(role_[r])||llvh::isa<AsyncFunction>(role_[r])))return reject("HELPER_KIND_MISMATCH");
      if(fingerprint(r)!=expectedGraph(r)){llvh::outs()<<"[ASYNC_GENERATOR_GRAPH] role="<<r<<" matched=0\n";return reject("FULL_HELPER_GRAPH_MISMATCH");}
    }
    for(auto &kv:globalRoles_){auto &stores=bindings_[kv.first];const auto r=kv.second;
      if(stores.size()!=(r==Factory?2u:1u))return reject("HELPER_GLOBAL_REBIND");
      for(auto *s:stores)if(owner(s)!=top_&&!(r==Factory&&owner(s)==role_[Factory]))return reject("HELPER_GLOBAL_WRITE",s);
    }
    for(const auto &n:{"Date","Promise","Function","Symbol","Object","Reflect","globalThis"})
      if(declared_.count(n)||bindings_.count(n))return reject("HOST_INTRINSIC_SHADOWED");
    return !failed_;
  }
  Datum value(Value *v,Frame &f,Instruction *at){
    if(auto *s=llvh::dyn_cast<LiteralString>(v)){Datum d=make(Scalar);d.text=key(s);d.truth=!d.text.empty();return d;}
    if(auto *n=llvh::dyn_cast<LiteralNumber>(v)){Datum d=make(Scalar);d.truth=n->getValue()!=0;return d;}
    if(auto *b=llvh::dyn_cast<LiteralBool>(v)){Datum d=make(Scalar);d.truth=b->getValue();return d;}
    if(llvh::isa<LiteralUndefined>(v)){Datum d=make(Undefined);d.truth=0;return d;}
    if(llvh::isa<LiteralNull>(v)){Datum d=make(Null);d.truth=0;return d;}
    if(llvh::isa<GlobalObject>(v))return make(Global);
    auto q=f.values.find(v);return q==f.values.end()?bad("VALUE_OUTSIDE_PROVED_PREFIX",at):q->second;
  }
  Datum globalRead(const std::string &k,Instruction *at){
    auto q=globals_.find(k);if(q!=globals_.end())return q->second;
    if(k=="Date")return make(DateHost);if(k=="Promise")return make(PromiseHost);
    if(k=="Symbol")return make(SymbolHost);if(k=="globalThis")return make(Global);
    return bad("UNRESOLVED_GLOBAL",at);
  }
  Datum property(LoadPropertyInst *l,Frame &f){
    Datum o=value(l->getObject(),f,l);const auto k=key(l->getProperty());
    if(k.empty())return bad("COMPUTED_READ",l);
    if(o.kind==Global)return globalRead(k,l);
    if(o.kind==Closure&&o.function==role_[Ctor]&&k=="prototype")return make(Prototype,l);
    if(o.kind==SymbolHost&&k=="asyncIterator"){Datum d=make(SymbolIterator);d.truth=1;return d;}
    if(o.kind==DateHost&&k=="now")return make(DateNow,l);
    if(o.kind==PromiseHost&&k=="resolve")return make(PromiseResolve,l);
    if(o.kind==Instance&&k=="next"){Datum d=make(NextMethod,o.identity);return d;}
    if(o.kind==NextResult&&k=="value"){o.kind=Scalar;edge(o,l);return o;}
    if(o.kind==Record){auto q=records_[o.identity].find(k);if(q!=records_[o.identity].end()){Datum d=q->second;edge(d,l);return d;}}
    return bad("PROPERTY_IDENTITY_NOT_PROVED",l);
  }
                                                                               
                                                                           
  BasicBlock *start(Frame &f){
    std::vector<Instruction *>e;for(auto &i:f.fn->front())e.push_back(&i);
    if(e.size()!=6)return reject("GENERATOR_PROLOGUE_SIZE"),nullptr;
    f.scope=llvh::dyn_cast<CreateScopeInst>(e[0]);auto *a=llvh::dyn_cast<AllocStackInst>(e[2]);auto *r=llvh::dyn_cast<ResumeGeneratorInst>(e[3]);auto *l=llvh::dyn_cast<LoadStackInst>(e[4]);auto *c=llvh::dyn_cast<CondBranchInst>(e[5]);
    if(!f.scope||!llvh::isa<StartGeneratorInst>(e[1])||!a||!r||!l||!c||r->getIsReturn()!=a||l->getPtr()!=a||c->getCondition()!=l||c->getTrueDest()->size()!=1)return reject("GENERATOR_PROLOGUE_IDENTITY"),nullptr;
    auto *ret=llvh::dyn_cast<ReturnInst>(&c->getTrueDest()->front());if(!ret||ret->getValue()!=r)return reject("GENERATOR_START_RETURN"),nullptr;
    f.values[f.scope]=make(Scope,f.scope);return c->getFalseDest();
  }
  BasicBlock *resume(SaveAndYieldInst *y,Frame &f,Datum d){
    BasicBlock *b=y->getNextBlock();std::vector<Instruction *>v;for(auto &i:*b)v.push_back(&i);
    if(v.size()!=3)return reject("RESUME_BLOCK_SIZE",y),nullptr;
    auto *r=llvh::dyn_cast<ResumeGeneratorInst>(v[0]);auto *l=llvh::dyn_cast<LoadStackInst>(v[1]);auto *c=llvh::dyn_cast<CondBranchInst>(v[2]);
    auto *flag=r?llvh::dyn_cast<AllocStackInst>(r->getIsReturn()):nullptr;
    if(!r||!l||!c||!flag||!f.stack.count(flag)||flag!=l->getPtr()||c->getCondition()!=l||c->getTrueDest()->size()!=1)return reject("RESUME_DISPATCH_IDENTITY",y),nullptr;
    auto *ret=llvh::dyn_cast<ReturnInst>(&c->getTrueDest()->front());if(!ret||ret->getValue()!=r)return reject("RESUME_RETURN_VALUE",y),nullptr;
    edge(d,y);edge(d,r);f.values[r]=d;return c->getFalseDest();
  }
  Datum generatorValue(CallInst *call){
    Frame f{role_[Inner]};BasicBlock *b=start(f);unsigned suspensions=0;
    std::set<BasicBlock *>visited;
    while(b&&!failed_){if(!visited.insert(b).second)return bad("GENERATOR_LOOP",call);
      BasicBlock *next=nullptr;
      for(auto &i:*b){
        if(auto *y=llvh::dyn_cast<SaveAndYieldInst>(&i)){
          Datum d=value(y->getResult(),f,y);
          if(suspensions++==0){if(d.kind!=AwaitValue)return bad("FIRST_SUSPENSION_NOT_PRIMITIVE_AWAIT",y);d.kind=Scalar;next=resume(y,f,d);break;}
          if(suspensions!=2||!primitive(d))return bad("FIRST_NORMAL_YIELD_NOT_PRIMITIVE",y);
          edge(d,y);return d;
        }
        if(llvh::isa<ReturnInst>(&i))return bad("RETURN_BEFORE_FIRST_NORMAL_YIELD",&i);
        f.values[&i]=instruction(&i,f,false);if(failed_)return {};
      }
      b=next;
    }return bad("GENERATOR_FIRST_YIELD_MISSING",call);
  }
  Datum instruction(Instruction *i,Frame &f,bool global){
    if(!spend(i))return {};
                                                                            
                                                                               
                                                                             
                                                      
    if(global&&entry_&&!llvh::isa<StoreStackInst>(i)&&!llvh::isa<LoadStackInst>(i)){
      auto *s=llvh::dyn_cast<StorePropertyInst>(i);
      if(!s||key(s->getProperty())!="__done"||s->getStoredValue()!=entry_)
        return bad("GLOBAL_EFFECT_AFTER_ASYNC_ENTRY",i);
    }
    if(auto *s=llvh::dyn_cast<CreateScopeInst>(i)){if(f.scope||s->getCreatedScopeDesc()!=f.fn->getFunctionScopeDesc())return bad("SCOPE_IDENTITY",i);f.scope=s;return make(Scope,s);}
    if(auto *a=llvh::dyn_cast<AllocStackInst>(i)){f.stack[a]={};return make(Bad,a);}
    if(auto *s=llvh::dyn_cast<StoreStackInst>(i)){if(!f.stack.count(s->getPtr()))return bad("FOREIGN_STACK",i);Datum d=value(s->getValue(),f,i);f.stack[s->getPtr()]=d;return make(Undefined);}
    if(auto *l=llvh::dyn_cast<LoadStackInst>(i)){auto q=f.stack.find(l->getPtr());return q==f.stack.end()?bad("STACK_MISSING",i):q->second;}
    if(auto *s=llvh::dyn_cast<StoreFrameInst>(i)){if(s->getEnvironment()!=f.scope||s->getVariable()->getParent()!=f.fn->getFunctionScopeDesc())return bad("CAPTURED_FRAME_WRITE",i);Datum d=value(s->getValue(),f,i);edge(d,i);f.vars[s->getVariable()]=d;return make(Undefined);}
    if(auto *l=llvh::dyn_cast<LoadFrameInst>(i)){if(l->getEnvironment()!=f.scope||!f.vars.count(l->getLoadVariable()))return bad("CAPTURED_OR_MISSING_FRAME",i);Datum d=f.vars[l->getLoadVariable()];edge(d,i);return d;}
    if(auto *c=llvh::dyn_cast<CreateFunctionInst>(i)){if(!global||llvh::isa<CreateGeneratorInst>(c)||c->getEnvironment()!=f.scope||!roleIds_.count(c->getFunctionCode()))return bad("UNKNOWN_CLOSURE_CREATION",i);Datum d=make(Closure,c);d.function=c->getFunctionCode();return d;}
    if(auto *l=llvh::dyn_cast<LoadPropertyInst>(i))return property(l,f);
    if(auto *a=llvh::dyn_cast<AllocObjectInst>(i)){if(!global||!llvh::isa<EmptySentinel>(a->getParentObject()))return bad("NON_ORDINARY_ALLOCATION",i);records_[a]={};return make(Record,a);}
    if(auto *a=llvh::dyn_cast<AllocArrayInst>(i)){if(!global||a->getNumOperands()!=1)return bad("ARRAY_OUTSIDE_PROFILE",i);return make(Array,a);}
    if(auto *s=llvh::dyn_cast<StoreOwnPropertyInst>(i)){
      Datum o=value(s->getObject(),f,i),d=value(s->getStoredValue(),f,i);const auto k=key(s->getProperty());
      if(!global||o.kind!=Record||!primitive(d)||k.empty()||k=="__proto__")return bad("OWN_WRITE_OUTSIDE_PROFILE",i);records_[o.identity][k]=d;return make(Undefined);
    }
    if(auto *s=llvh::dyn_cast<StorePropertyInst>(i)){
      Datum o=value(s->getObject(),f,i),d=value(s->getStoredValue(),f,i);std::string k=key(s->getProperty());
      if(global&&o.kind==Prototype){if(k.empty()){Datum p=value(s->getProperty(),f,i);if(p.kind!=SymbolIterator)return bad("PROTOTYPE_DYNAMIC_KEY",i);k="@@iterator-symbol";}if(k!="next"&&k!="throw"&&k!="return"&&k!="@@iterator-symbol")return bad("PROTOTYPE_SLOT_OUTSIDE_PROFILE",i);unsigned r=k=="next"?Next:k=="throw"?Throw:k=="return"?Return:Iterator;if(d.kind!=Closure||d.function!=role_[r]||prototype_.count(k))return bad("PROTOTYPE_SLOT_REDEFINE",i);prototype_[k]=d.function;return make(Undefined);}
      if(global&&o.kind==Global){
        if(k=="__done"&&d.kind==NextPromise&&d.identity==entry_)return make(Undefined);
        if(!declared_.count(k)||globals_.count(k)||(!primitive(d)&&d.kind!=Record&&d.kind!=Array&&d.kind!=Closure))return bad("GLOBAL_WRITE_OR_ESCAPE",i);
        globals_[k]=d;return make(Undefined);
      }
      if(!global&&s==target_&&o.kind==Record&&k=="cookie"&&records_[o.identity].count(k)&&primitive(d)){
        edge(d,i);if(d.source)pending_.emplace_back(d.source,d.path,s);return make(Undefined);
      }
      return bad("UNKNOWN_PROPERTY_WRITE",i);
    }
    if(auto *c=llvh::dyn_cast<CallInst>(i)){
      if(llvh::isa<ConstructInst>(c)||llvh::isa<CallBuiltinInst>(c)||!llvh::isa<LiteralUndefined>(c->getNewTarget()))return bad("UNSUPPORTED_CALL_FORM",i);
      Datum d=value(c->getCallee(),f,i);
      auto *load=llvh::dyn_cast<LoadPropertyInst>(c->getCallee());
      if(d.kind==DateNow&&!global&&f.fn==role_[Inner]&&load&&c->getNumArguments()==1&&c->getArgument(0)==load->getObject()){
        Instruction *source=nullptr;if(std::find(sources_.begin(),sources_.end(),c)!=sources_.end())source=c;else if(std::find(sources_.begin(),sources_.end(),load)!=sources_.end())source=load;
        if(!source)return bad("DATE_SOURCE_NOT_REGISTERED",i);Datum out=make(Scalar);out.source=source;out.path={source};edge(out,c);return out;
      }
      if(d.kind==PromiseResolve&&!global&&f.fn==role_[Inner]&&load&&c->getNumArguments()==2&&c->getArgument(0)==load->getObject()){
        Datum out=value(c->getArgument(1),f,i);if(!primitive(out))return bad("THENABLE_OR_UNKNOWN_PROMISE_INPUT",i);out.kind=PromiseValue;edge(out,c);return out;
      }
      if(d.kind==Closure&&d.function==role_[Await]&&!global&&f.fn==role_[Inner]&&c->getNumArguments()==2&&llvh::isa<LiteralUndefined>(c->getArgument(0))){Datum out=value(c->getArgument(1),f,i);if(out.kind!=PromiseValue)return bad("AWAIT_MARKER_INPUT",i);out.kind=AwaitValue;edge(out,c);return out;}
      if(d.kind==Closure&&d.function==role_[Forward]&&!global&&f.fn==role_[ConsumerInner]&&c->getNumArguments()==1&&llvh::isa<LiteralUndefined>(c->getArgument(0))){if(instanceCall_)return bad("MULTIPLE_GENERATOR_INSTANCES",i);instanceCall_=c;return make(Instance,c);}
      if(d.kind==NextMethod&&!global&&f.fn==role_[ConsumerInner]&&c->getNumArguments()==1&&load&&c->getArgument(0)==load->getObject()&&d.identity==instanceCall_){
        if(visitedNext_)return bad("REPEATED_NEXT",i);visitedNext_=true;nextCall_=c;
        Datum out=generatorValue(c);if(failed_)return {};out.kind=NextPromise;out.identity=instanceCall_;
                                                                              
                                                                                 
        edge(out,c);return out;
      }
      if(d.kind==Closure&&d.function==role_[Consumer]&&global&&c->getNumArguments()==1&&llvh::isa<LiteralUndefined>(c->getArgument(0))){if(entry_||prototype_.size()!=4)return bad("CONSUMER_ENTRY_OR_PROTO_NOT_READY",i);entry_=c;Datum out=make(NextPromise,c);return out;}
      return bad("UNSUPPORTED_CALL_OR_REQUEST_ORDER",i);
    }
    if(auto *b=llvh::dyn_cast<BinaryOperatorInst>(i)){
      Datum a=value(b->getLeftHandSide(),f,i),d=value(b->getRightHandSide(),f,i);if(!primitive(a)||!primitive(d))return bad("UNKNOWN_BINARY_EFFECT",i);
      if(b->getOperatorKind()==BinaryOperatorInst::OpKind::AddKind){if(a.source&&d.source&&a.source!=d.source)return bad("MULTISOURCE_OUTSIDE_PROFILE",i);Datum o=a.source?a:d;o.kind=Scalar;o.truth=-1;o.text.clear();edge(o,i);return o;}
      if(global&&b->getOperatorKind()==BinaryOperatorInst::OpKind::EqualKind&&!a.text.empty()&&!d.text.empty()){Datum o=make(Scalar);o.truth=a.text==d.text;return o;}
      return bad("BINARY_OUTSIDE_PROFILE",i);
    }
    if(auto *u=llvh::dyn_cast<UnaryOperatorInst>(i)){
      Datum d=value(u->getSingleOperand(),f,i);if(global&&d.kind==SymbolHost&&u->getOperatorKind()==UnaryOperatorInst::OpKind::TypeofKind){Datum o=make(Scalar);o.text="function";o.truth=1;return o;}
      return bad("UNARY_OUTSIDE_PROFILE",i);
    }
    return bad("UNKNOWN_INSTRUCTION_OR_CONTROL",i);
  }
  bool globalPrefix(){
    Frame f{top_};BasicBlock *b=&top_->front();std::set<BasicBlock *>visited;
    while(b&&!failed_){if(!visited.insert(b).second)return reject("GLOBAL_LOOP");BasicBlock *next=nullptr;
      for(auto &i:*b){
        if(auto *c=llvh::dyn_cast<CondBranchInst>(&i)){if(entry_)return reject("GLOBAL_BRANCH_AFTER_ASYNC_ENTRY",c);Datum d=value(c->getCondition(),f,c);if(d.truth<0)return reject("UNKNOWN_GLOBAL_BRANCH",c);next=d.truth?c->getTrueDest():c->getFalseDest();break;}
        if(auto *j=llvh::dyn_cast<BranchInst>(&i)){if(entry_)return reject("GLOBAL_BRANCH_AFTER_ASYNC_ENTRY",j);next=j->getBranchDest();break;}
        if(llvh::isa<ReturnInst>(&i))return entry_&&!failed_;
        f.values[&i]=instruction(&i,f,true);if(failed_)return false;
      }b=next;
    }return reject("GLOBAL_ENTRY_NOT_COMPLETE");
  }
  bool consumer(){
    Frame f{role_[ConsumerInner]};BasicBlock *b=start(f);bool awaited=false;std::set<BasicBlock *>visited;
    while(b&&!failed_){if(!visited.insert(b).second)return reject("CONSUMER_LOOP");BasicBlock *next=nullptr;
      for(auto &i:*b){
        if(auto *y=llvh::dyn_cast<SaveAndYieldInst>(&i)){
          Datum d=value(y->getResult(),f,y);if(awaited||d.kind!=NextPromise||d.identity!=instanceCall_||!nextCall_)return reject("CONSUMER_AWAIT_CONTEXT",y);
          awaited=true;d.kind=NextResult;next=resume(y,f,d);break;
        }
        if(llvh::isa<ReturnInst>(&i))return reject("RETURN_BEFORE_COOKIE",&i);
        f.values[&i]=instruction(&i,f,false);if(failed_)return false;
        if(&i==target_)return awaited;
      }b=next;
    }return reject("CONSUMER_COOKIE_NOT_REACHED");
  }
 public:
  BoundedAsyncGeneratorTransport(Module *m,const std::vector<Instruction *> &sources,const std::vector<Instruction *> &sinks):module_(m),sources_(sources),sinks_(sinks){
    for(auto *g:m->getGlobalProperties())if(g->isDeclared())declared_.insert(key(g->getName()));
    unsigned fn=0;
    for(auto &f:*m){if(f.isGlobalScope()){if(top_)metadataBad_=true;top_=&f;}unsigned in=0;
      for(auto &b:f)for(auto &i:b){if(ids_.size()>=250000){metadataBad_=true;return;}ids_[&i]="F"+std::to_string(fn)+":I"+std::to_string(in++);
        if(auto *c=llvh::dyn_cast<CreateFunctionInst>(&i))creations_[c->getFunctionCode()].push_back(c);
        if(auto *s=llvh::dyn_cast<StorePropertyInst>(&i))if(llvh::isa<GlobalObject>(s->getObject()))bindings_[key(s->getProperty())].push_back(s);
      }++fn;
    }
  }
  void append(std::vector<DefUseAnalyzer::TaintPath> &paths){
    unsigned added=0;StorePropertyInst *candidate=nullptr;
    for(auto *s:sinks_)if(auto *p=llvh::dyn_cast<StorePropertyInst>(s))if(key(p->getProperty())=="cookie"&&llvh::isa<GeneratorInnerFunction>(owner(p))){if(candidate){reject("MULTIPLE_COOKIE_CANDIDATES",s);break;}candidate=p;}
    bool ok=!failed_&&!metadataBad_&&top_&&candidate&&discover(candidate)&&certify()&&globalPrefix()&&consumer();
    if(ok){for(auto &p:pending_){bool duplicate=std::any_of(paths.begin(),paths.end(),[&](const DefUseAnalyzer::TaintPath &q){return q.source==p.source&&q.sink==p.sink;});if(!duplicate){paths.push_back(p);++added;}llvh::outs()<<"[ASYNC_GENERATOR_TRACE] source="<<id(p.source)<<" instance="<<id(instanceCall_)<<" next="<<id(nextCall_)<<" sink="<<id(p.sink)<<" path=";for(auto *i:p.path)llvh::outs()<<id(i)<<"/"<<i->getKindStr()<<" ";llvh::outs()<<"\n";}}
    llvh::outs()<<"[ASYNC_GENERATOR_TRANSPORT] status="<<(ok?"PROVED_FIRST_NEXT_CONTRACT":"UNKNOWN")<<" added="<<added<<" steps="<<steps_<<" reason="<<(ok?"FIRST_PRIMITIVE_AWAIT_NORMAL_YIELD":reason_)<<" barrier="<<id(barrier_)<<" contract=PINNED_HELPER_GRAPH_FRESH_INSTANCE_FIRST_NEXT_PRIMITIVE_FULFILLMENT assumptions=CLOSED_INPUT_PRISTINE_INTRINSICS_ORDINARY_GLOBALS\n";
  }
};
} }                              

                                                                           
                                                                                             
                                                                                                         
                                                                                                     
                                                                               
                                                                              
                                                                                
                                                                                
                                                           
                                                                                
                                                                               
                                                                         
#include <algorithm>
#include <cmath>
#include <map>
#include <set>

namespace hermes {
namespace {
class BoundedOrdinaryReturnTransport {
  using Path = std::vector<Instruction *>;
  struct Trace {
    Instruction *source;
    Path path;
    unsigned originInvocation;
    bool crossedReturn{false};
    bool crossedArgument{false};
  };
  enum Kind { Invalid, Empty, Primitive, Undefined, Null, Global, Scope, Closure,
              DateObject, DateNow, AmbientDocument, LocalObject, BoundClosure, BindMethod, PromiseConstructor, PromiseResolve, PromiseReject, PromiseThen, PromiseValue };
  struct Datum {
    Kind kind{Invalid};
    int truth{-1};                                                               
    Instruction *identity{nullptr};
    unsigned environment{0};
    unsigned object{0};
    std::vector<Instruction *> argumentCalls;
    std::vector<Trace> traces;
  };
  struct Frame {
    Function *function;
    Datum receiver;
    CreateScopeInst *scope{nullptr};
    CallInst *entry{nullptr};
    unsigned invocation{0};
    unsigned capturedEnvironment{0};
    std::vector<Datum> arguments;
    std::map<Value *, Datum> values;
    std::map<Variable *, Datum> variables;
    std::map<AllocStackInst *, Datum> stack;
  };
  struct Environment {
    ScopeDesc *descriptor;
    unsigned parent;
    unsigned ownerInvocation;
    std::map<Variable *, Datum> variables;
  };
  std::map<unsigned, Environment> environments_;
  std::map<unsigned, std::map<std::string, Datum>> objects_;
  unsigned nextObject_{1}, propertyCount_{0};
  struct Bound { Datum target, receiver; std::vector<Datum> prefix; };
  struct Reaction { Datum yes, no; unsigned output; CallInst *call; };
  struct Promise { unsigned state{0}; Datum result; std::vector<Reaction> reactions; };
  struct Job { Reaction reaction; unsigned state; Datum input; };
  std::map<unsigned, Bound> bound_;
  std::map<unsigned, Datum> bindBases_;
  std::map<unsigned, Promise> promises_;
  std::vector<Job> jobs_;
  unsigned nextBound_{1}, nextAdapter_{1}, nextPromise_{1}, jobsRun_{0};
  static bool callable(const Datum &d) { return d.kind == Closure || d.kind == BoundClosure; }
  static bool storable(const Datum &d) { return primitive(d) || callable(d) || d.kind == LocalObject || d.kind == PromiseValue; }
  bool same(const Datum &a, const Datum &b) {
    return a.kind == b.kind && a.identity == b.identity && a.environment == b.environment && a.object == b.object;
  }
  Datum newPromise(CallInst *at) {
    if (nextPromise_ > 128) return reject("PROMISE_COUNT_LIMIT", at);
    Datum d=make(PromiseValue, at); d.object=nextPromise_++; promises_.emplace(d.object, Promise{}); return d;
  }
  bool fulfillable(const Datum &d, Instruction *at) {
    if (primitive(d)) return true;
    if (d.kind != LocalObject || !objects_.count(d.object)) { reject("PROMISE_VALUE_OR_THENABLE_UNPROVEN",at);return false; }
    auto &props=objects_.at(d.object);auto t=props.find("then");
                                                                                          
    if (t==props.end() || !primitive(t->second)) { reject("PROMISE_THENABLE_UNPROVEN",at);return false; }
    return true;
  }
  void enqueue(const Reaction &r, unsigned state, const Datum &input) {
    if(jobs_.size()>=128){reject("PROMISE_JOB_LIMIT",r.call);return;}
    jobs_.push_back({r,state,input});
  }
  void settle(unsigned id, unsigned state, Datum d, CallInst *at) {
    auto p=promises_.find(id);
    if(p==promises_.end()||p->second.state){reject("PROMISE_SETTLEMENT_IDENTITY",at);return;}
    if(state==1&&!fulfillable(d,at))return;
    edge(d,at);p->second.state=state;p->second.result=d;
    for(const auto &r:p->second.reactions)enqueue(r,state,d);
    p->second.reactions.clear();
  }
  void drainJobs() {
                                                                                
    for(unsigned cursor=0;!failed_&&cursor<jobs_.size();++cursor){
      if(++jobsRun_>128){reject("PROMISE_JOB_LIMIT",jobs_[cursor].reaction.call);break;}
      Job job=jobs_[cursor];Datum handler=job.state==1?job.reaction.yes:job.reaction.no;
      if(!callable(handler)){settle(job.reaction.output,job.state,job.input,job.reaction.call);continue;}
      Datum result=applyClosure(handler,make(Undefined),{job.input},job.reaction.call,true);
      if(failed_)break;
                                                                                 
      if(result.kind==PromiseValue){reject("PROMISE_RETURN_ADOPTION_UNPROVEN",job.reaction.call);break;}
      settle(job.reaction.output,1,result,job.reaction.call);
    }
  }
  struct ContextCallEdge {
    CallInst *call; Function *target; unsigned invocation, environment, receiver;
    bool bound, reaction; unsigned legacyCandidates; bool legacyMatch;
  };
  std::map<CallInst *, std::set<Function *>> legacyCalls_;
  std::vector<ContextCallEdge> contextCalls_;
  unsigned cfgBlocks_{0}, cfgBranches_{0}, cfgPhis_{0};
  int truthiness(const Datum &d) const {
    if (d.kind==Undefined || d.kind==Null) return 0;
    if (d.kind==LocalObject || callable(d) || d.kind==PromiseValue) return 1;
    return d.truth;
  }
  unsigned nextEnvironment_{1};
  Datum newEnvironment(ScopeDesc *descriptor, unsigned parent,
                       unsigned invocation, Instruction *at) {
    if (!descriptor || descriptor->getDynamic() || nextEnvironment_ > 512)
      return reject("LEXICAL_ENVIRONMENT_LIMIT_OR_DYNAMIC", at);
    if (parent && (!environments_.count(parent) ||
        descriptor->getParent() != environments_.at(parent).descriptor))
      return reject("LEXICAL_PARENT_IDENTITY", at);
    const unsigned id = nextEnvironment_++;
    environments_.emplace(id, Environment{descriptor, parent, invocation, {}});
    Datum d = make(Scope, at); d.environment = id; return d;
  }
  Environment *bindingEnvironment(Datum scope, Variable *variable,
                                  Instruction *at) {
    if (scope.kind != Scope || !scope.environment || !variable) {
      reject("LEXICAL_SCOPE_VALUE", at); return nullptr;
    }
    unsigned current = scope.environment;
    for (unsigned n = 0; current && n < 64; ++n) {
      auto found = environments_.find(current);
      if (found == environments_.end()) break;
      if (found->second.descriptor == variable->getParent())
        return &found->second;
      current = found->second.parent;
    }
    reject("LEXICAL_BINDING_NOT_ANCESTOR", at); return nullptr;
  }
  Module *module_;
  const std::vector<Instruction *> &sources_, &sinks_;
  std::map<Instruction *, std::string> ids_;
  std::map<std::string, Datum> globals_;
  std::set<std::string> declaredGlobals_;
  std::set<Function *> active_;
  std::vector<DefUseAnalyzer::TaintPath> pending_;
  Function *global_{nullptr};
  unsigned steps_{0}, invocations_{0}, returns_{0}, argumentEdges_{0};
  bool failed_{false};
  const char *reason_{"NORMAL_EXACT_ENTRY"};
  Instruction *barrier_{nullptr};

  static std::string key(Value *v) {
    if(auto *s=llvh::dyn_cast<LiteralString>(v))return s->getValue().str().str();
    if(auto *n=llvh::dyn_cast<LiteralNumber>(v)) {
      double x=n->getValue();
      if(std::isfinite(x)&&x>=0&&x<=4294967294.0&&std::floor(x)==x)
        return std::to_string(static_cast<unsigned long long>(x));
    }
    return "";
  }
  static Datum make(Kind kind, Instruction *identity = nullptr) {
    Datum d; d.kind = kind; d.identity = identity; return d;
  }
  static bool primitive(const Datum &d) {
    return d.kind == Primitive || d.kind == Undefined || d.kind == Null;
  }
  bool source(Instruction *i) const {
    return std::find(sources_.begin(), sources_.end(), i) != sources_.end();
  }
  bool sink(Instruction *i) const {
    return std::find(sinks_.begin(), sinks_.end(), i) != sinks_.end();
  }
  std::string id(Instruction *i) const {
    auto found = ids_.find(i); return found == ids_.end() ? "NONE" : found->second;
  }
                                                                           
                                                                           
  std::map<Variable *,std::vector<StoreFrameInst *>> metadataStores_;
  std::map<Variable *,std::vector<LoadFrameInst *>> metadataLoads_;
  std::map<Instruction *,unsigned> metadataOrder_;
  std::map<Instruction *,std::string> metadataKeys_;
  std::map<BasicBlock *,std::vector<BasicBlock *>> metadataPreds_;
  std::map<std::pair<Instruction *,Instruction *>,bool> metadataDominance_;
  unsigned metadataCrossBlockLoads_{0};
  std::map<std::pair<Function *,LoadFrameInst *>,bool> metadataLateClosures_;
  std::map<Function *,bool> metadataOrdinaryOwners_;
  unsigned metadataLateWriterExclusions_{0},metadataClosureOrderHeld_{0};
                                                                                       
  std::map<std::pair<Value *,Variable *>,Value *> metadataBindings_;
  std::map<std::pair<std::pair<Value *,Instruction *>,unsigned>,Value *> metadataValues_;
  std::map<Instruction *,bool> metadataEscapes_;
  std::map<LoadFrameInst *,std::vector<StoreFrameInst *>> metadataDefs_;
  std::set<LoadFrameInst *> metadataBadDefs_;
  unsigned metadataCacheHits_{0},metadataCacheMisses_{0},metadataRangeProved_{0},metadataRangeSymbolic_{0};
  struct IndexRange { bool proved{false}; bool symbolic{false}; unsigned upper{0}; Value *arguments{nullptr}; };
  std::set<unsigned> arrayObjects_;
  unsigned metadataProofSteps_{0},metadataLocal_{0},metadataHeld_{0};
  bool metadataProofLimited_{false};
  bool metadataTick() { if(metadataProofSteps_>=4096){metadataProofLimited_=true;return false;}++metadataProofSteps_;return true; }
  bool before(Instruction *a,Instruction *b) const {
    auto x=metadataOrder_.find(a),y=metadataOrder_.find(b);
    return a&&b&&a->getParent()==b->getParent()&&x!=metadataOrder_.end()&&y!=metadataOrder_.end()&&x->second<y->second;
  }
  Value *metadataBinding(Value *environment,Variable *variable) {
    if(!metadataTick())return nullptr;
    auto k=std::make_pair(environment,variable);auto found=metadataBindings_.find(k);
    if(found!=metadataBindings_.end()){++metadataCacheHits_;return found->second;}
    ++metadataCacheMisses_;Value *r=metadataBindingRaw(environment,variable);
    if(!metadataProofLimited_)metadataBindings_[k]=r;
    return r;
  }
  Value *metadataBindingRaw(Value *environment,Variable *variable) {
    for(unsigned n=0;n<16&&environment;++n) {
      if(!metadataTick())return nullptr;
      if(auto *scope=llvh::dyn_cast<CreateScopeInst>(environment))
        return scope->getCreatedScopeDesc()==variable->getParent()?environment:nullptr;
      if(auto *inner=llvh::dyn_cast<CreateInnerScopeInst>(environment)) {
        if(inner->getCreatedScopeDesc()==variable->getParent())return environment;
        environment=inner->getParentScope();continue;
      }
                                                                             
      return nullptr;
    }
    return nullptr;
  }
                                                                         
                                                                               
  bool metadataDominates(Instruction *def,Instruction *use) {
    if(!def||!use||def==use||def->getParent()->getParent()!=use->getParent()->getParent())return false;
    if(def->getParent()==use->getParent())return before(def,use);
    auto pair=std::make_pair(def,use);auto cached=metadataDominance_.find(pair);
    if(cached!=metadataDominance_.end())return cached->second;
    std::vector<BasicBlock *> todo{use->getParent()};std::set<BasicBlock *> seen;
    bool boundary=false;
    for(unsigned n=0;n<todo.size();++n) {
      if(!metadataTick()||todo.size()>256)return false;
      auto *block=todo[n];if(!seen.insert(block).second)continue;
      if(block==def->getParent()){boundary=true;continue;}
      if(block==&block->getParent()->front()||metadataPreds_[block].empty())return metadataDominance_[pair]=false;
      for(auto *pred:metadataPreds_[block]) {
        if(!metadataTick()||pred->getParent()!=block->getParent())return false;
        todo.push_back(pred);
      }
    }
    return metadataDominance_[pair]=boundary;
  }
                                                                       
                                                                              
                                                                         
                                                                             
                                                                   
  bool ordinaryClosureOwner(Function *owner) {
    if(!metadataTick())return false;
    auto found=metadataOrdinaryOwners_.find(owner);
    if(found!=metadataOrdinaryOwners_.end())return found->second;
    for(auto &block:*owner) {
      if(!metadataTick())return false;
      auto *term=block.getTerminator();
      if(!metadataOrder_.count(term)||
         (!llvh::isa<ReturnInst>(term)&&!llvh::isa<BranchInst>(term)&&!llvh::isa<CondBranchInst>(term)))
        return metadataOrdinaryOwners_[owner]=false;
    }
    return metadataOrdinaryOwners_[owner]=true;
  }
  bool creationCannotReach(CreateFunctionInst *creation,LoadFrameInst *load) {
    Function *owner=load->getParent()->getParent();
    if(!ordinaryClosureOwner(owner))return false;
    if(creation->getParent()->getParent()!=owner||!metadataOrder_.count(creation)||!metadataOrder_.count(load))return false;
    using Cursor=std::pair<BasicBlock *,Instruction *>;
    std::vector<Cursor> todo{{creation->getParent(),creation}};std::set<Cursor> seen;
    for(unsigned n=0;n<todo.size();++n) {
      if(!metadataTick()||todo.size()>256)return false;
      auto cursor=todo[n];if(!seen.insert(cursor).second)continue;
      auto *block=cursor.first;
      if(block->getParent()!=owner||!metadataOrder_.count(block->getTerminator()))return false;
                                                                             
      if(block==load->getParent()&&(!cursor.second||before(cursor.second,load)))return false;
      auto *term=block->getTerminator();
      if(llvh::isa<ReturnInst>(term))continue;
      if(!llvh::isa<BranchInst>(term)&&!llvh::isa<CondBranchInst>(term))return false;
      for(unsigned k=0;k<term->getNumSuccessors();++k) {
        if(!metadataTick())return false;
        todo.emplace_back(term->getSuccessor(k),nullptr);
      }
    }
    return true;
  }
  bool foreignWriterUnavailable(Function *writer,LoadFrameInst *load) {
    if(!metadataTick())return false;
    auto k=std::make_pair(writer,load);auto cached=metadataLateClosures_.find(k);
    if(cached!=metadataLateClosures_.end()){++metadataCacheHits_;return cached->second;}
    ++metadataCacheMisses_;bool proved=true;unsigned creations=0;
    Value *binding=metadataBinding(load->getEnvironment(),load->getLoadVariable());
    if(!binding)proved=false;
                                                                            
                                                                       
    for(auto *u:writer->getUsers()) {
      if(!proved)break;
      if(!metadataTick()||++creations>256){proved=false;break;}
      auto *creation=llvh::dyn_cast<CreateFunctionInst>(u);
      if(!creation||creation->getFunctionCode()!=writer||
         creation->getParent()->getParent()!=load->getParent()->getParent()||
         metadataBinding(creation->getEnvironment(),load->getLoadVariable())!=binding||
         !creationCannotReach(creation,load)){proved=false;break;}
    }
    proved=proved&&creations>0&&!metadataProofLimited_;
    if(!metadataProofLimited_)metadataLateClosures_[k]=proved;
    if(proved)++metadataLateWriterExclusions_;else ++metadataClosureOrderHeld_;
    if(metadataLateWriterExclusions_+metadataClosureOrderHeld_<=24)
      llvh::outs()<<"[METADATA_CLOSURE_ORDER] load="<<id(load)
                  <<" result="<<(proved?"NOT_CREATED_BEFORE_LOAD":"UNKNOWN")
                  <<" creation_uses="<<creations<<" writer_entry="
                  <<(writer->empty()?"NONE":id(&writer->front().front()))<<"\n";
    return proved;
  }
  bool metadataDefinitions(LoadFrameInst *l,std::vector<StoreFrameInst *> &out) {
    if(!metadataTick())return false;
    auto cached=metadataDefs_.find(l);
    if(cached!=metadataDefs_.end()){++metadataCacheHits_;out=cached->second;return true;}
    if(metadataBadDefs_.count(l)){++metadataCacheHits_;return false;}
    ++metadataCacheMisses_;
    auto bad=[&](){if(!metadataProofLimited_)metadataBadDefs_.insert(l);return false;};
    Value *binding=metadataBinding(l->getEnvironment(),l->getLoadVariable());
    if(!binding)return bad();
    auto &stores=metadataStores_[l->getLoadVariable()];
    for(auto *st:stores) {
      if(!metadataTick())return false;
      if(st->getParent()->getParent()!=l->getParent()->getParent()) {
        if(!foreignWriterUnavailable(st->getParent()->getParent(),l))return bad();
        continue;
      }
      if(metadataBinding(st->getEnvironment(),st->getVariable())!=binding)return bad();
    }
    using Cursor=std::pair<BasicBlock *,Instruction *>;
    std::vector<Cursor> todo{{l->getParent(),l}};std::set<Cursor> seen;std::set<StoreFrameInst *> definitions;bool crossed=false;
    for(unsigned n=0;n<todo.size();++n) {
      if(!metadataTick())return false;
      if(todo.size()>256)return bad();
      auto cursor=todo[n];if(!seen.insert(cursor).second)continue;
      auto *block=cursor.first;StoreFrameInst *latest=nullptr;
      for(auto *st:stores) {
        if(!metadataTick())return false;
        if(st->getParent()==block&&(!cursor.second||before(st,cursor.second))&&(!latest||before(latest,st)))latest=st;
      }
      if(latest){definitions.insert(latest);continue;}
      if(block==&block->getParent()->front()||metadataPreds_[block].empty())return bad();
      crossed=true;
      for(auto *pred:metadataPreds_[block]) {
        if(!metadataTick())return false;
        if(pred->getParent()!=block->getParent())return bad();
        todo.emplace_back(pred,nullptr);
      }
    }
    if(definitions.empty())return bad();
    out.assign(definitions.begin(),definitions.end());metadataDefs_[l]=out;
    if(crossed)++metadataCrossBlockLoads_;
    return true;
  }
  Value *metadataValue(Value *v,Instruction *at,unsigned depth=0) {
    if(depth>16||!metadataTick())return nullptr;
    auto k=std::make_pair(std::make_pair(v,at),depth);auto found=metadataValues_.find(k);
    if(found!=metadataValues_.end()){++metadataCacheHits_;return found->second;}
    ++metadataCacheMisses_;Value *r=metadataValueRaw(v,at,depth);
                                                                            
                                                                                 
                                                                       
    if(!metadataProofLimited_&&(r||depth==0))metadataValues_[k]=r;
    return r;
  }
  Value *metadataValueRaw(Value *v,Instruction *at,unsigned depth) {
    if(auto *m=llvh::dyn_cast<MovInst>(v))return metadataDominates(m,at)?metadataValue(m->getSingleOperand(),m,depth+1):nullptr;
    if(auto *e=llvh::dyn_cast<ThrowIfEmptyInst>(v))return metadataDominates(e,at)?metadataValue(e->getCheckedValue(),e,depth+1):nullptr;
    if(auto *l=llvh::dyn_cast<LoadFrameInst>(v)) {
      if(l!=at&&!metadataDominates(l,at))return nullptr;
      std::vector<StoreFrameInst *> definitions;if(!metadataDefinitions(l,definitions))return nullptr;
      Value *result=nullptr;
      for(auto *st:definitions) {
        Value *r=metadataValue(st->getValue(),st,depth+1);
        if(!r||(result&&result!=r))return nullptr;
        result=r;
      }
      return result;
    }
    return v;
  }
  Instruction *freshRoot(Value *v,Instruction *at) {
    Value *r=metadataValue(v,at);auto *i=llvh::dyn_cast_or_null<Instruction>(r);
    if(!i||!metadataDominates(i,at))return nullptr;
    if(auto *o=llvh::dyn_cast<AllocObjectInst>(i))
      return llvh::isa<EmptySentinel>(o->getParentObject())||llvh::isa<LiteralNull>(o->getParentObject())?i:nullptr;
    return llvh::isa<AllocArrayInst>(i)?i:nullptr;
  }
  bool nonescaping(Instruction *root) {
    if(!metadataTick())return false;
    auto found=metadataEscapes_.find(root);
    if(found!=metadataEscapes_.end()){++metadataCacheHits_;return found->second;}
    ++metadataCacheMisses_;bool r=nonescapingRaw(root);
    if(!metadataProofLimited_)metadataEscapes_[root]=r;
    return r;
  }
  bool nonescapingRaw(Instruction *root) {
    std::vector<Value *> todo{root};std::set<Value *> seen;
    Function *owner=root->getParent()->getParent();
    for(unsigned n=0;n<todo.size();++n) {
      if(!metadataTick()||todo.size()>256)return false;
      Value *v=todo[n];if(!seen.insert(v).second)continue;
      for(auto *u:v->getUsers()) {
        if(!metadataTick()||u->getParent()->getParent()!=owner)return false;
        if(auto *st=llvh::dyn_cast<StoreFrameInst>(u)) {
          if(st->getValue()!=v)return false;
          for(auto *l:metadataLoads_[st->getVariable()]) {
            if(l->getParent()->getParent()!=owner||!metadataBinding(st->getEnvironment(),st->getVariable())||metadataBinding(l->getEnvironment(),l->getLoadVariable())!=metadataBinding(st->getEnvironment(),st->getVariable()))return false;
            if(metadataValue(l,l)!=root)return false;
            todo.push_back(l);
          }
          continue;
        }
        if(llvh::isa<MovInst>(u)||llvh::isa<ThrowIfEmptyInst>(u)){todo.push_back(u);continue;}
        if(auto *l=llvh::dyn_cast<LoadPropertyInst>(u)) {if(l->getObject()==v&&l->getProperty()!=v)continue;return false;}
        if(auto *st=llvh::dyn_cast<StoreOwnPropertyInst>(u)) {if(st->getObject()==v&&st->getStoredValue()!=v&&st->getProperty()!=v)continue;return false;}
        if(auto *st=llvh::dyn_cast<StorePropertyInst>(u)) {if(st->getObject()==v&&st->getStoredValue()!=v&&st->getProperty()!=v)continue;return false;}
                                                                                   
        return false;
      }
    }
    return true;
  }
  bool initializedOwnSlot(Instruction *root,const std::string &name,StorePropertyInst *at) {
    if(!metadataDominates(root,at))return false;
    if(auto *a=llvh::dyn_cast<AllocArrayInst>(root)) {
      for(unsigned n=0;n<a->getElementCount();++n) {
        if(!metadataTick())return false;
        if(std::to_string(n)==name&&!llvh::isa<LiteralEmpty>(a->getArrayElement(n)))return true;
      }
    }
    for(auto &i:*root->getParent()) {
      if(&i==at)break;
      if(!metadataTick())return false;
      if(auto *st=llvh::dyn_cast<StoreOwnPropertyInst>(&i))
        if(st->getObject()==root&&key(st->getProperty())==name&&before(root,st)&&metadataDominates(st,at))return true;
    }
    return false;
  }
  bool sameIndexBinding(LoadFrameInst *a,LoadFrameInst *b) {
    return a&&b&&a->getLoadVariable()==b->getLoadVariable()&&
      a->getParent()->getParent()==b->getParent()->getParent()&&
      metadataBinding(a->getEnvironment(),a->getLoadVariable())&&
      metadataBinding(a->getEnvironment(),a->getLoadVariable())==metadataBinding(b->getEnvironment(),b->getLoadVariable());
  }
  bool zeroUnitInduction(LoadFrameInst *index) {
    std::vector<LoadFrameInst *> todo{index};std::set<LoadFrameInst *> seen;bool initialized=false;
    for(unsigned n=0;n<todo.size();++n) {
      if(!metadataTick()||todo.size()>256)return false;
      auto *l=todo[n];if(!seen.insert(l).second)continue;
      if(!sameIndexBinding(index,l))return false;
      std::vector<StoreFrameInst *> defs;if(!metadataDefinitions(l,defs))return false;
      for(auto *st:defs) {
        if(!metadataTick())return false;
        if(auto *number=llvh::dyn_cast<LiteralNumber>(st->getValue())) {
          if(number->getValue()!=0)return false;
          initialized=true;continue;
        }
        auto *inc=llvh::dyn_cast<UnaryOperatorInst>(st->getValue());
        if(!inc||inc->getOperatorKind()!=UnaryOperatorInst::OpKind::IncKind||!before(inc,st))return false;
        auto *numeric=llvh::dyn_cast<AsNumericInst>(inc->getSingleOperand());
        if(!numeric||!before(numeric,inc))return false;
        auto *previous=llvh::dyn_cast<LoadFrameInst>(numeric->getSingleOperand());
        if(!previous||!before(previous,numeric)||!sameIndexBinding(index,previous))return false;
        todo.push_back(previous);
      }
    }
    return initialized;
  }
  bool untouchedArguments(CreateArgumentsInst *args) {
    if(!args)return false;
    for(auto *u:args->getUsers()) {
      if(!metadataTick()||u->getParent()->getParent()!=args->getParent()->getParent())return false;
      auto *l=llvh::dyn_cast<LoadPropertyInst>(u);
                                                                                      
      if(!l||l->getObject()!=args||l->getProperty()==args)return false;
    }
    return true;
  }
  IndexRange indexRange(StorePropertyInst *store) {
    IndexRange none;auto *index=llvh::dyn_cast<LoadFrameInst>(store->getProperty());
    if(!index||index->getParent()!=store->getParent()||!before(index,store))return none;
                                                                        
    for(auto &i:*index->getParent()) {
      if(&i==index)break;
      if(!metadataTick())return none;
      if(!llvh::isa<LoadFrameInst>(&i)&&!llvh::isa<MovInst>(&i))return none;
    }
    if(metadataPreds_[index->getParent()].empty()||!zeroUnitInduction(index))return none;
    IndexRange result;bool first=true;
    for(auto *pred:metadataPreds_[index->getParent()]) {
      if(!metadataTick())return none;
      auto *branch=llvh::dyn_cast<CondBranchInst>(pred->getTerminator());
      if(!branch||branch->getTrueDest()!=index->getParent()||branch->getFalseDest()==index->getParent())return none;
      auto *cmp=llvh::dyn_cast<BinaryOperatorInst>(branch->getCondition());
      if(!cmp||!before(cmp,branch))return none;
      LoadFrameInst *counter=nullptr;Value *upper=nullptr;
      if(cmp->getOperatorKind()==BinaryOperatorInst::OpKind::LessThanKind) {
        counter=llvh::dyn_cast<LoadFrameInst>(cmp->getLeftHandSide());upper=cmp->getRightHandSide();
      } else if(cmp->getOperatorKind()==BinaryOperatorInst::OpKind::GreaterThanKind) {
        counter=llvh::dyn_cast<LoadFrameInst>(cmp->getRightHandSide());upper=cmp->getLeftHandSide();
      } else return none;
      if(!counter||!sameIndexBinding(index,counter)||!before(counter,cmp)||!zeroUnitInduction(counter))return none;
      IndexRange one;one.proved=true;
      if(auto *number=llvh::dyn_cast<LiteralNumber>(upper)) {
        double n=number->getValue();if(!std::isfinite(n)||n<=0||n>4294967295.0||std::floor(n)!=n)return none;
        one.upper=static_cast<unsigned>(n);
      } else {
        auto *length=llvh::dyn_cast<LoadPropertyInst>(upper);
        if(!length||key(length->getProperty())!="length"||!before(length,cmp))return none;
        auto *args=llvh::dyn_cast<CreateArgumentsInst>(length->getObject());
        if(!untouchedArguments(args))return none;
        one.symbolic=true;one.arguments=args;
      }
      bool after=false;
      for(auto &i:*pred) {
        if(&i==counter){after=true;continue;}
        if(!after||&i==branch)continue;
        if(!metadataTick())return none;
        if(&i!=cmp&&&i!=upper&&!llvh::isa<LoadFrameInst>(&i)&&!llvh::isa<MovInst>(&i))return none;
      }
      if(!first&&(one.symbolic!=result.symbolic||one.upper!=result.upper||one.arguments!=result.arguments))return none;
      result=one;first=false;
    }
    return first?none:result;
  }
  bool initializedOwnRange(Instruction *root,const IndexRange &range,StorePropertyInst *at) {
    if(!range.proved||range.symbolic||range.upper>256)return false;
    for(unsigned n=0;n<range.upper;++n) {
      if(!metadataTick()||!initializedOwnSlot(root,std::to_string(n),at))return false;
    }
    return true;
  }

  void classifyRestrictedWrite(StorePropertyInst *st) {
    std::string name=key(st->getProperty());
    Value *resolved=metadataValue(st->getProperty(),st);
    if(name.empty()&&resolved)name=key(resolved);
    Instruction *root=freshRoot(st->getObject(),st);
    IndexRange range;
    if(root&&name.empty()&&llvh::isa<AllocArrayInst>(root))range=indexRange(st);
    if(range.proved) {
      if(range.symbolic)++metadataRangeSymbolic_;else ++metadataRangeProved_;
      llvh::outs()<<"[METADATA_INDEX_RANGE] site="<<id(st)<<" lower=0 upper_exclusive=";
      if(range.symbolic)llvh::outs()<<"arguments.length";else llvh::outs()<<range.upper;
      llvh::outs()<<" kind="<<(range.symbolic?"SYMBOLIC_ARGUMENT_COUNT":"FINITE_LITERAL")<<" implies_write_safe=0\n";
    }
    const char *why=nullptr;
    if(!root)why="METADATA_TARGET_IDENTITY_UNPROVEN";
    else if(name.empty()&&!range.proved)why="LOCAL_PROPERTY_KEY_UNPROVEN";
    else if(name.empty()&&range.symbolic)why="LOCAL_SYMBOLIC_RANGE_OWN_SLOTS_UNPROVEN";
    else if(name=="__proto__"||name=="length")why="LOCAL_SPECIAL_PROPERTY_UNPROVEN";
    else if(!nonescaping(root))why="LOCAL_OBJECT_ESCAPE_OR_ALIAS_UNPROVEN";
    else if(name.empty()?!initializedOwnRange(root,range,st):!initializedOwnSlot(root,name,st))why="LOCAL_OWN_SLOT_OR_INHERITED_SETTER_UNPROVEN";
    if(metadataProofLimited_)why="METADATA_OWNERSHIP_WORK_LIMIT";
    if(why){++metadataHeld_;reject(why,st);}else{++metadataLocal_;if(!name.empty())metadataKeys_[st]=name;}
    if(metadataLocal_+metadataHeld_<=24)
      llvh::outs()<<"[METADATA_WRITE_CLASS] site="<<id(st)
                  <<" target="<<(root?(llvh::isa<AllocArrayInst>(root)?"FRESH_ARRAY":"FRESH_OBJECT"):"UNKNOWN_OR_EXTERNAL")
                  <<" result="<<(why?"UNKNOWN":"LOCAL_OWN_DATA_ONLY")
                  <<" reason="<<(why?why:"NONESCAPING_INITIALIZED_OWN_SLOT")<<"\n";
  }
  Datum reject(const char *why, Instruction *at) {
    if (!failed_) { reason_ = why; barrier_ = at; }
    failed_ = true; return {};
  }
  void edge(Datum &d, Instruction *i) {
    std::vector<Trace> unique;
    for (auto t : d.traces) {
      if (std::any_of(unique.begin(), unique.end(), [&](const Trace &other) {
        return t.source == other.source && t.originInvocation == other.originInvocation &&
               t.crossedReturn == other.crossedReturn && t.crossedArgument == other.crossedArgument;
      })) continue;
      if (t.path.size() >= 256) { reject("PATH_LIMIT", i); return; }
      if (t.path.empty() || t.path.back() != i) t.path.push_back(i);
      unique.push_back(std::move(t));
    }
    if (unique.size() > 16) { reject("TRACE_LIMIT", i); return; }
    d.traces = std::move(unique);
  }
  Datum value(Value *v, Frame &frame, Instruction *use) {
    if (auto *n=llvh::dyn_cast<LiteralNumber>(v)) { Datum d=make(Primitive); double x=n->getValue(); d.truth=x!=0&&!std::isnan(x); return d; }
    if (auto *s=llvh::dyn_cast<LiteralString>(v)) { Datum d=make(Primitive); d.truth=!s->getValue().str().empty(); return d; }
    if (auto *b=llvh::dyn_cast<LiteralBool>(v)) { Datum d=make(Primitive); d.truth=b->getValue(); return d; }
    if (llvh::isa<LiteralEmpty>(v)) return make(Empty);
    if (llvh::isa<LiteralUndefined>(v)) return make(Undefined);
    if (llvh::isa<LiteralNull>(v)) return make(Null);
    if (llvh::isa<GlobalObject>(v)) return make(Global);
    if (auto *p = llvh::dyn_cast<Parameter>(v)) {
      if (p->getParent() != frame.function) return reject("FOREIGN_PARAMETER", use);
      if (p == frame.function->getThisParameter()) return frame.receiver;
      const auto &parameters = frame.function->getParameters();
      for (unsigned n = 0; n < parameters.size(); ++n)
        if (parameters[n] == p) return n < frame.arguments.size() ? frame.arguments[n] : make(Undefined);
      return reject("PARAMETER_NOT_BOUND", use);
    }
    auto found = frame.values.find(v);
    return found == frame.values.end() ? reject("VALUE_OUTSIDE_INVOCATION", use) : found->second;
  }
  Datum globalRead(const std::string &name, Instruction *at) {
    auto found = globals_.find(name);
    if (found != globals_.end()) { Datum d = found->second; edge(d, at); return d; }
    if (name == "Promise" && !declaredGlobals_.count(name)) return make(PromiseConstructor);
    if (name == "Date" && !declaredGlobals_.count(name)) return make(DateObject);
    if (name == "document" && !declaredGlobals_.count(name)) return make(AmbientDocument);
    return reject("GLOBAL_READ_UNRESOLVED", at);
  }
  Datum propertyRead(LoadPropertyInst *load, Frame &frame) {
    const auto name = key(load->getProperty());
    if (name.empty()) return reject("DYNAMIC_PROPERTY_KEY", load);
    Datum object = value(load->getObject(), frame, load);
    if (object.kind == Global) return globalRead(name, load);
    if (object.kind == DateObject && name == "now") return make(DateNow, load);
    if (callable(object) && name == "bind") {
      if(nextAdapter_>128)return reject("BIND_ADAPTER_LIMIT",load);
      Datum d=make(BindMethod,load);d.object=nextAdapter_++;bindBases_[d.object]=object;return d;
    }
    if(object.kind==PromiseConstructor && (name=="resolve"||name=="reject"))return make(name=="resolve"?PromiseResolve:PromiseReject,load);
    if(object.kind==PromiseValue&&name=="then") { Datum d=make(PromiseThen,load);d.object=object.object;return d; }
    if (object.kind == LocalObject && objects_.count(object.object)) {
      const auto &properties = objects_.at(object.object);
      auto found = properties.find(name);
                                                                                        
      if (found == properties.end()) return reject("OWN_PROPERTY_NOT_PROVEN", load);
      Datum d = found->second;
      for (auto *call : object.argumentCalls) {
        if (d.argumentCalls.size() >= 64) return reject("OBJECT_ARGUMENT_PATH_LIMIT", load);
        d.argumentCalls.push_back(call);
        for (auto &trace : d.traces) trace.crossedArgument = true;
        edge(d, call);
      }
      edge(d, load); return d;
    }
    return reject("PROPERTY_OR_GETTER_UNPROVEN", load);
  }
  Datum propertyStore(StorePropertyInst *store, Frame &frame) {
    auto name = key(store->getProperty());
    if(name.empty()&&metadataKeys_.count(store))name=metadataKeys_.at(store);
    Datum object = value(store->getObject(), frame, store);
    Datum d = value(store->getStoredValue(), frame, store);
    if (failed_) return {};
    if (object.kind == Global) {
                                                                               
                                                                               
                                                                         
      if (frame.function != global_ || !declaredGlobals_.count(name) || name.empty() ||
          name == "Date" || name == "document" || name == "__proto__" ||
          (!storable(d))) return reject("GLOBAL_WRITE_OUTSIDE_PROFILE", store);
      edge(d, store); globals_[name] = d; return make(Undefined);
    }
    if (object.kind == LocalObject) {
                                                                                          
      if (!objects_.count(object.object) || !objects_.at(object.object).count(name) ||
          (!storable(d)))
        return reject("OWN_DATA_WRITE_UNPROVEN", store);
      edge(d, store); objects_.at(object.object)[name] = d; return make(Undefined);
    }
    if (object.kind != AmbientDocument || name != "cookie" || !sink(store) || !primitive(d))
      return reject("PROPERTY_EFFECT_OUTSIDE_PROFILE", store);
    edge(d, store);
    for (auto &trace : d.traces) {
      if ((!trace.crossedReturn && !trace.crossedArgument) || !source(trace.source) || trace.path.empty() || trace.path.front() != trace.source) continue;
      if (pending_.size() >= 256) return reject("PENDING_PATH_LIMIT", store);
      pending_.emplace_back(trace.source, trace.path, store);
    }
    return make(Undefined);
  }
  Datum invoke(CallInst *call, Frame &caller) {
    if (llvh::isa<ConstructInst>(call) || llvh::isa<CallBuiltinInst>(call) || call->getNumArguments() < 1)
      return reject("NON_ORDINARY_CALL", call);
    Datum callee = value(call->getCallee(), caller, call);
    if (callee.kind == DateNow) {
      auto *load = llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
      if (!load || call->getNumArguments() != 1 || call->getArgument(0) != load->getObject() ||
          value(call->getArgument(0), caller, call).kind != DateObject)
        return reject("DATE_CALL_SHAPE", call);
      Instruction *registered = source(call) ? static_cast<Instruction *>(call) : source(load) ? load : nullptr;
      if (!registered) return reject("DATE_SOURCE_NOT_REGISTERED", call);
      Datum d = make(Primitive); d.traces.push_back({registered, {registered}, caller.invocation, false});
      edge(d, call); return d;
    }
    Datum receiver=value(call->getArgument(0),caller,call);
    std::vector<Datum> arguments;
    if(call->getNumArguments()>17)return reject("CALL_ARGUMENT_LIMIT",call);
    for(unsigned n=1;n<call->getNumArguments();++n)arguments.push_back(value(call->getArgument(n),caller,call));
    if(failed_)return {};
    if(callee.kind==BindMethod){
      if(!bindBases_.count(callee.object)||!same(receiver,bindBases_.at(callee.object))||arguments.empty()||nextBound_>128)
        return reject("BIND_RECEIVER_OR_TARGET_UNPROVEN",call);
      Datum result=make(BoundClosure,call);result.object=nextBound_++;
      bound_[result.object]={bindBases_.at(callee.object),arguments.front(),std::vector<Datum>(arguments.begin()+1,arguments.end())};return result;
    }
    if(callee.kind==PromiseResolve||callee.kind==PromiseReject){
      if(receiver.kind!=PromiseConstructor||arguments.size()>1)return reject("PROMISE_CONSTRUCTOR_RECEIVER",call);
      Datum input=arguments.empty()?make(Undefined):arguments[0];
      if(callee.kind==PromiseResolve&&input.kind==PromiseValue)return input;
      Datum result=newPromise(call);if(failed_)return {};
      settle(result.object,callee.kind==PromiseResolve?1:2,input,call);return result;
    }
    if(callee.kind==PromiseThen){
      if(receiver.kind!=PromiseValue||receiver.object!=callee.object||!promises_.count(callee.object)||arguments.size()>2)
        return reject("PROMISE_THEN_RECEIVER",call);
      Datum result=newPromise(call);if(failed_)return {};
      Reaction r{arguments.empty()?make(Undefined):arguments[0],arguments.size()<2?make(Undefined):arguments[1],result.object,call};
      auto &p=promises_.at(callee.object);
      if(p.state)enqueue(r,p.state,p.result);else {if(p.reactions.size()>=128)return reject("PROMISE_REACTION_LIMIT",call);p.reactions.push_back(r);}
      return result;
    }
    return applyClosure(callee,receiver,arguments,call);
  }
  Datum applyClosure(Datum callee, Datum receiver, std::vector<Datum> arguments, CallInst *call, bool reaction=false) {
    const bool wasBound=callee.kind==BoundClosure;
    for(unsigned n=0;callee.kind==BoundClosure;++n){
      if(n>=8||!bound_.count(callee.object))return reject("BOUND_TARGET_LIMIT_OR_IDENTITY",call);
      const auto &b=bound_.at(callee.object);receiver=b.receiver;
      std::vector<Datum> merged=b.prefix;merged.insert(merged.end(),arguments.begin(),arguments.end());arguments=std::move(merged);callee=b.target;
    }
    if (callee.kind != Closure) return reject("CALL_TARGET_NOT_EXACT_CLOSURE", call);
    auto *creation = llvh::dyn_cast<CreateFunctionInst>(callee.identity);
    if (!creation) return reject("CLOSURE_IDENTITY_MISSING", call);
    Function *target = creation->getFunctionCode();
    if (target->getDefinitionKind() == Function::DefinitionKind::ES6Constructor)
      return reject("CLASS_CONSTRUCTOR_REQUIRES_NEW", call);
    if (active_.count(target)) return reject("RECURSIVE_CALL", call);
    if (active_.size() >= 8 || ++invocations_ > 64) return reject("CALL_BOUND", call);
    if (llvh::isa<AsyncFunction>(target) || llvh::isa<GeneratorFunction>(target) ||
        llvh::isa<GeneratorInnerFunction>(target)) return reject("ASYNC_OR_GENERATOR_CALL", call);
    if ((receiver.kind != Undefined && receiver.kind != LocalObject) || target->getParameters().size() > 16 || arguments.size() > 16)
      return reject("RECEIVER_OR_ARITY_OUTSIDE_PROFILE", call);
    if (!callee.environment || !environments_.count(callee.environment) ||
        target->getFunctionScopeDesc()->getParent() != environments_.at(callee.environment).descriptor)
      return reject("CLOSURE_LEXICAL_PARENT_IDENTITY", call);
                                                                               
                                                                             
                                                                                  
    auto previous=legacyCalls_.find(call);
    unsigned candidates=previous==legacyCalls_.end()?0:previous->second.size();
    bool matched=previous!=legacyCalls_.end()&&previous->second.count(target);
    contextCalls_.push_back({call,target,invocations_,callee.environment,receiver.object,wasBound,reaction,candidates,matched});
    Frame child; child.function = target; child.entry = call; child.invocation = invocations_;
    child.capturedEnvironment = callee.environment;
    if (receiver.kind == LocalObject) {
      if (receiver.argumentCalls.size() >= 64) return reject("OBJECT_ARGUMENT_PATH_LIMIT", call);
      receiver.argumentCalls.push_back(call);
    }
    child.receiver = receiver;
    for (Datum actual : arguments) {
      if (!storable(actual)) return reject("ARGUMENT_VALUE_UNPROVEN",call);
      for (auto &trace : actual.traces) trace.crossedArgument = true;
      if (actual.kind == LocalObject) {
        if (actual.argumentCalls.size() >= 64) return reject("OBJECT_ARGUMENT_PATH_LIMIT", call);
        actual.argumentCalls.push_back(call);
      }
      edge(actual, call); argumentEdges_ += actual.traces.size(); child.arguments.push_back(std::move(actual));
    }
    Datum returned = execute(child);
    if (failed_ || !storable(returned)) return reject("NON_PRIMITIVE_RETURN", call);
    for (auto &trace : returned.traces) trace.crossedReturn = true;
    edge(returned, call); ++returns_;
    return returned;
  }
  Datum instruction(Instruction *i, Frame &frame) {
    if (++steps_ > 20000) return reject("PROOF_STEP_LIMIT", i);
    if (auto *coerce = llvh::dyn_cast<CoerceThisNSInst>(i)) {
      Datum d=value(coerce->getOperand(0),frame,coerce);
      if(d.kind!=LocalObject)return reject("THIS_COERCION_UNPROVEN",coerce);
      edge(d,coerce);return d;
    }
    if (auto *scope = llvh::dyn_cast<CreateScopeInst>(i)) {
      if (frame.scope || scope->getCreatedScopeDesc() != frame.function->getFunctionScopeDesc()) return reject("SCOPE_NOT_LOCAL", i);
      if (frame.function != global_ && !frame.capturedEnvironment)
        return reject("MISSING_CAPTURED_ENVIRONMENT", scope);
      frame.scope = scope;
      return newEnvironment(scope->getCreatedScopeDesc(), frame.capturedEnvironment, frame.invocation, scope);
    }
    if (auto *inner = llvh::dyn_cast<CreateInnerScopeInst>(i)) {
      Datum parent = value(inner->getParentScope(), frame, inner);
      if (parent.kind != Scope || !parent.environment) return reject("INNER_SCOPE_PARENT", inner);
      return newEnvironment(inner->getCreatedScopeDesc(), parent.environment, frame.invocation, inner);
    }
    if (auto *check = llvh::dyn_cast<ThrowIfEmptyInst>(i)) {
      Datum d = value(check->getCheckedValue(), frame, check);
      if (d.kind == Empty || d.kind == Invalid) return reject("LEXICAL_TDZ_OR_UNKNOWN", check);
      edge(d, check); return d;
    }
    if (auto *a = llvh::dyn_cast<AllocStackInst>(i)) { frame.stack[a] = {}; return make(Invalid, a); }
    if (auto *s = llvh::dyn_cast<StoreStackInst>(i)) {
      if (!frame.stack.count(s->getPtr())) return reject("STACK_NOT_LOCAL", s);
      Datum d = value(s->getValue(), frame, s); edge(d, s); frame.stack[s->getPtr()] = d; return make(Undefined);
    }
    if (auto *l = llvh::dyn_cast<LoadStackInst>(i)) {
      auto found = frame.stack.find(l->getPtr());
      if (found == frame.stack.end() || found->second.kind == Invalid) return reject("STACK_UNINITIALIZED", l);
      Datum d = found->second; edge(d, l); return d;
    }
    if (auto *s = llvh::dyn_cast<StoreFrameInst>(i)) {
      Datum scope = value(s->getEnvironment(), frame, s);
      Environment *environment = bindingEnvironment(scope, s->getVariable(), s);
      if (!environment || failed_) return {};
      Datum d = value(s->getValue(), frame, s);
      if (!storable(d) && d.kind != Empty)
        return reject("FRAME_VALUE_OUTSIDE_PROFILE", s);
      if (environment->ownerInvocation != frame.invocation) {
        if (frame.entry) edge(d, frame.entry);
        for (auto &trace : d.traces) trace.crossedReturn = true;
      }
      edge(d, s); environment->variables[s->getVariable()] = d; return make(Undefined);
    }
    if (auto *l = llvh::dyn_cast<LoadFrameInst>(i)) {
      Datum scope = value(l->getEnvironment(), frame, l);
      Environment *environment = bindingEnvironment(scope, l->getLoadVariable(), l);
      if (!environment || failed_) return {};
      auto found = environment->variables.find(l->getLoadVariable());
      if (found == environment->variables.end()) return reject("LEXICAL_UNINITIALIZED_FRAME", l);
      Datum d = found->second;
      if (environment->ownerInvocation != frame.invocation) {
        for (auto &trace : d.traces) trace.crossedReturn = true;
        if (d.kind == LocalObject && frame.entry) {
          if (d.argumentCalls.size() >= 64) return reject("OBJECT_ARGUMENT_PATH_LIMIT", l);
          d.argumentCalls.push_back(frame.entry);
        }
      }
      edge(d, l); return d;
    }
    if (auto *c = llvh::dyn_cast<CreateFunctionInst>(i)) {
      Datum scope = value(c->getEnvironment(), frame, c);
      if (scope.kind != Scope || !environments_.count(scope.environment) ||
          c->getFunctionCode()->getFunctionScopeDesc()->getParent() != environments_.at(scope.environment).descriptor)
        return reject("CLOSURE_ENVIRONMENT_UNPROVEN", c);
      Datum d = make(Closure, c); d.environment = scope.environment; return d;
    }
    if (auto *a=llvh::dyn_cast<AllocArrayInst>(i)) {
      if(nextObject_>512||a->getElementCount()>256)return reject("LOCAL_ARRAY_ALLOCATION_LIMIT",a);
      Datum d=make(LocalObject,a);d.object=nextObject_++;arrayObjects_.insert(d.object);
      auto &slots=objects_[d.object];
      for(unsigned n=0;n<a->getElementCount();++n) {
        Datum element=value(a->getArrayElement(n),frame,a);
        if(element.kind==Empty)continue;                                        
        if(!storable(element)||++propertyCount_>4096)return reject("LOCAL_ARRAY_ELEMENT_UNPROVEN",a);
        edge(element,a);slots[std::to_string(n)]=element;
      }
      return d;
    }
    if (auto *a = llvh::dyn_cast<AllocObjectInst>(i)) {
      if (!llvh::isa<EmptySentinel>(a->getParentObject()) && !llvh::isa<LiteralNull>(a->getParentObject()))
        return reject("OBJECT_PROTOTYPE_OUTSIDE_PROFILE", a);
      if (nextObject_ > 512) return reject("LOCAL_OBJECT_LIMIT", a);
      Datum d = make(LocalObject, a); d.object = nextObject_++;
      objects_.emplace(d.object, std::map<std::string, Datum>{}); return d;
    }
    if (auto *s = llvh::dyn_cast<StoreOwnPropertyInst>(i)) {
      Datum object = value(s->getObject(), frame, s), d = value(s->getStoredValue(), frame, s);
      const auto name = key(s->getProperty());
      if (failed_ || object.kind != LocalObject || !objects_.count(object.object) || name.empty() ||
          name == "__proto__" || (!storable(d)))
        return reject("OWN_PROPERTY_DEFINITION_OUTSIDE_PROFILE", s);
      auto &properties = objects_.at(object.object);
      if (!properties.count(name) && ++propertyCount_ > 4096) return reject("OWN_PROPERTY_LIMIT", s);
      edge(d, s); properties[name] = d; return make(Undefined);
    }
    if (auto *l = llvh::dyn_cast<LoadPropertyInst>(i)) return propertyRead(l, frame);
    if (auto *s = llvh::dyn_cast<StorePropertyInst>(i)) return propertyStore(s, frame);
    if (auto *c = llvh::dyn_cast<CallInst>(i)) return invoke(c, frame);
    if (auto *b = llvh::dyn_cast<BinaryOperatorInst>(i)) {
      Datum left = value(b->getLeftHandSide(), frame, b), right = value(b->getRightHandSide(), frame, b);
      if (!primitive(left) || !primitive(right) || b->getOperatorKind() != BinaryOperatorInst::OpKind::AddKind)
        return reject("PRIMITIVE_ADD_UNPROVEN", b);
      Datum d = make(Primitive); d.traces = left.traces;
      d.traces.insert(d.traces.end(), right.traces.begin(), right.traces.end()); edge(d, b); return d;
    }
    if (auto *m = llvh::dyn_cast<MovInst>(i)) { Datum d = value(m->getSingleOperand(), frame, m); edge(d, m); return d; }
    if (auto *u = llvh::dyn_cast<UnaryOperatorInst>(i)) {
      if (u->getOperatorKind() == UnaryOperatorInst::OpKind::VoidKind) { value(u->getSingleOperand(), frame, u); return make(Undefined); }
      if (u->getOperatorKind() == UnaryOperatorInst::OpKind::BangKind) {
        Datum x=value(u->getSingleOperand(),frame,u);int t=truthiness(x);
        if(t<0)return reject("BOOLEAN_VALUE_UNPROVEN",u);
        Datum d=make(Primitive);d.truth=!t;d.traces=x.traces;edge(d,u);return d;
      }
    }
    return reject("CONTROL_OR_EFFECT_OUTSIDE_PROFILE", i);
  }
  Datum execute(Frame &frame) {
    Function *f=frame.function;
    if(!f||f->empty())return reject("EMPTY_CALLEE",frame.entry);
    active_.insert(f); BasicBlock *block=&f->front(), *predecessor=nullptr;
    std::set<BasicBlock *> visited;
    auto stop=[&](const char *why,Instruction *at)->Datum { active_.erase(f);return reject(why,at); };
    while(!failed_) {
      if(!block||block->getParent()!=f)return stop("CFG_FOREIGN_BLOCK",frame.entry);
                                                                             
      if(!visited.insert(block).second)return stop("CFG_BACKEDGE_UNPROVEN",block->getTerminator());
      if(++cfgBlocks_>512)return stop("CFG_BLOCK_LIMIT",block->getTerminator());
                                                                          
      std::vector<std::pair<PhiInst *,Datum>> phis;
      for(auto &i:*block)if(auto *phi=llvh::dyn_cast<PhiInst>(&i)) {
        if(++steps_>20000)return stop("PROOF_STEP_LIMIT",phi);
        Value *selected=nullptr;unsigned matches=0;
        for(unsigned n=0;n<phi->getNumEntries();++n){auto e=phi->getEntry(n);if(e.second==predecessor){selected=e.first;++matches;}}
        if(matches!=1)return stop("CFG_PHI_PREDECESSOR_UNPROVEN",phi);
        Datum d=value(selected,frame,phi);edge(d,phi);phis.emplace_back(phi,std::move(d));++cfgPhis_;
      }
      for(auto &p:phis)frame.values[p.first]=std::move(p.second);
      BasicBlock *next=nullptr;
      for(auto &i:*block) {
        if(failed_)break;
        if(llvh::isa<PhiInst>(&i))continue;
        if(auto *ret=llvh::dyn_cast<ReturnInst>(&i)) {
          if(++steps_>20000)return stop("PROOF_STEP_LIMIT",ret);
          Datum d=value(ret->getValue(),frame,ret);edge(d,ret);active_.erase(f);return d;
        }
        if(auto *jump=llvh::dyn_cast<BranchInst>(&i)) {
          if(++steps_>20000)return stop("PROOF_STEP_LIMIT",jump);
          next=jump->getBranchDest();break;
        }
        if(auto *branch=llvh::dyn_cast<CondBranchInst>(&i)) {
          if(++steps_>20000)return stop("PROOF_STEP_LIMIT",branch);
          Datum d=value(branch->getCondition(),frame,branch);int t=truthiness(d);
          if(failed_)break;
          if(t<0)return stop("CFG_BRANCH_CONDITION_UNPROVEN",branch);
          next=t?branch->getTrueDest():branch->getFalseDest();++cfgBranches_;break;
        }
        Datum d=instruction(&i,frame);frame.values[&i]=std::move(d);
      }
      if(failed_)break;
      if(!next)return stop("CFG_TERMINATOR_UNSUPPORTED",block->getTerminator());
      predecessor=block;block=next;
    }
    active_.erase(f);return {};
  }
  void index() {
    unsigned fi=0,count=0;std::vector<Instruction *> nodes;bool limited=false;
    for(auto *g:module_->getGlobalProperties())if(g->isDeclared()) {
      auto name=key(g->getName());declaredGlobals_.insert(name);
      if(name=="Date"||name=="document"||name=="Promise"||name=="Function")reject("HOST_GLOBAL_SHADOWED",nullptr);
    }
    for(auto &f:*module_) {
      if(f.isGlobalScope()){if(global_)reject("MULTIPLE_GLOBAL_ENTRIES",nullptr);global_=&f;}
      unsigned ii=0;
      for(auto &b:f) {
       if(limited)break;
       for(auto &i:b) {
        if(++count>50000){limited=true;break;}
        ids_[&i]="F"+std::to_string(fi)+":I"+std::to_string(ii++);
        metadataOrder_[&i]=count;nodes.push_back(&i);
        if(auto *term=llvh::dyn_cast<TerminatorInst>(&i)) {
          for(unsigned n=0;n<term->getNumSuccessors();++n)metadataPreds_[term->getSuccessor(n)].push_back(&b);
        }
        if(auto *st=llvh::dyn_cast<StoreFrameInst>(&i))metadataStores_[st->getVariable()].push_back(st);
        if(auto *l=llvh::dyn_cast<LoadFrameInst>(&i))metadataLoads_[l->getLoadVariable()].push_back(l);
      }
      }
      if(limited)break;
      ++fi;
    }
    for(auto *i:nodes) {
      if(llvh::isa<DirectEvalInst>(i)||llvh::isa<DeletePropertyInst>(i)||llvh::isa<StoreGetterSetterInst>(i))reject("DYNAMIC_OR_DESCRIPTOR_MUTATION",i);
      if(auto *st=llvh::dyn_cast<StorePropertyInst>(i)) {
        auto name=key(st->getProperty());
        if(!llvh::isa<LiteralString>(st->getProperty())||name.empty()||name=="Date"||name=="document"||name=="now"||name=="__proto__"||name=="Promise"||name=="bind"||name=="then"||name=="resolve"||name=="reject")classifyRestrictedWrite(st);
      }
      if(auto *l=llvh::dyn_cast<LoadPropertyInst>(i)) {
        auto name=key(l->getProperty());
        if(name=="defineProperty"||name=="defineProperties"||name=="__defineGetter__"||name=="__defineSetter__"||name=="setPrototypeOf")reject("DESCRIPTOR_API_OUTSIDE_PROFILE",l);
      }
    }
    if(limited)reject("MODULE_METADATA_LIMIT",nodes.empty()?nullptr:nodes.back());
    if(!global_)reject("GLOBAL_ENTRY_MISSING",nullptr);
  }
 public:
  BoundedOrdinaryReturnTransport(Module *m, const std::vector<Instruction *> &sources,
      const std::vector<Instruction *> &sinks,
      const std::vector<DefUseAnalyzer::FunctionCallMapping> &calls)
      : module_(m), sources_(sources), sinks_(sinks) {
    unsigned count=0;
    for(const auto &c:calls) {
      if(++count>50000){reject("CALL_GRAPH_METADATA_LIMIT",c.callSite);break;}
      if(c.callSite&&c.targetFunction)legacyCalls_[c.callSite].insert(c.targetFunction);
    }
    index();
  }
  void append(std::vector<DefUseAnalyzer::TaintPath> &paths) {
    if (!failed_) { Frame entry; entry.function = global_; entry.receiver=make(Undefined); execute(entry); if(!failed_)drainJobs(); }
    unsigned added = 0;
    if (!failed_) for (const auto &p : pending_) {
      if (std::any_of(paths.begin(), paths.end(), [&](const DefUseAnalyzer::TaintPath &existing) {
        return existing.source == p.source && existing.sink == p.sink;
      })) continue;
      paths.push_back(p); ++added;
      llvh::outs() << "[ORDINARY_RETURN_TRACE] source=" << id(p.source) << " sink=" << id(p.sink) << "\n";
    }
    if(!failed_)for(const auto &c:contextCalls_) {
      llvh::outs()<<"[CONTEXT_CALL_EDGE] call="<<id(c.call)
                  <<" target="<<id(&c.target->front().front())
                  <<" invocation="<<c.invocation<<" captured_environment="<<c.environment
                  <<" receiver="<<c.receiver<<" bound="<<c.bound<<" promise_reaction="<<c.reaction
                  <<" legacy_candidates="<<c.legacyCandidates<<" legacy_match="<<c.legacyMatch
                  <<" export=CONTEXT_VALIDATED_SINK_PATH_ONLY\n";
    }
    llvh::outs()<<"[METADATA_OWNERSHIP] local_own_writes="<<metadataLocal_<<" held_writes="<<metadataHeld_
                <<" late_writer_exclusions="<<metadataLateWriterExclusions_<<" closure_order_held="<<metadataClosureOrderHeld_<<" cross_block_loads="<<metadataCrossBlockLoads_<<" cache_hits="<<metadataCacheHits_<<" cache_misses="<<metadataCacheMisses_<<" finite_ranges="<<metadataRangeProved_<<" symbolic_ranges="<<metadataRangeSymbolic_<<" proof_steps="<<metadataProofSteps_<<" proof_limit=4096 metadata_limit=50000\n";
    llvh::outs()<<"[CFG_CALL_BRIDGE] status="<<(failed_?"UNKNOWN":"PROVED")
                <<" blocks="<<cfgBlocks_<<" known_branches="<<cfgBranches_<<" selected_phis="<<cfgPhis_
                <<" certified_calls="<<(failed_?0:contextCalls_.size())
                <<" shared_formal_seeds=0 legacy_graph_unchanged=1\n";
    llvh::outs() << "[ORDINARY_RETURN_TRANSPORT] status=" << (failed_ ? "UNKNOWN" : "PROVED")
                 << " invocations=" << invocations_ << " returns=" << returns_ << " argument_edges=" << argumentEdges_
                 << " tentative=" << pending_.size() << " added=" << added << " steps=" << steps_
                 << " reason=" << reason_ << " barrier=" << id(barrier_)
                 << " promise_jobs=" << jobsRun_ << " bound_functions=" << bound_.size()
                 << " contract=EXACT_CFG_BIND_PROMISE_CONTEXTUAL_ADDITIVE\n";
  }
};
}             
}                    

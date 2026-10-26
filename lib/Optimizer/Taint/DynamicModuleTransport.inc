                                                                             
                                                                                
                                                                            
                                                                             
                                                                            
#include <deque>
#include <map>
#include <set>
#include <algorithm>
#include <cmath>
namespace hermes { namespace {
class DynamicModuleTransport {
 using Path=std::vector<Instruction *>;
 struct Trace {Instruction *source;Path path;};
 enum Kind {Bad,Undef,Null,Empty,Scalar,String,Number,Boolean,Global,Scope,Closure,
  Object,Array,Arguments,Generator,Internal,CreateGraph,Graph,Start,Context,Bind,Read,
  GetNamespace,Import,Namespace,PromiseCtor,Resolve,Promise,Then,Spawn,DateObj,Now,Document,Push};
 struct D {Kind k{Bad};unsigned id{0};std::string text;double number{0};std::vector<Trace> traces;Path carrier;};
 struct Env {ScopeDesc *desc;unsigned parent;std::map<Variable *,D> vars;};
 struct C {Function *fn;unsigned env;CreateFunctionInst *site;};
 struct Obj {bool array{false},sealed{false};unsigned length{0};std::map<std::string,D> fields;};
 struct Frame {Function *fn{nullptr};unsigned parent{0},env{0};D receiver;std::vector<D>args;
  std::map<Value *,D> values;std::map<AllocStackInst *,D>stack;std::set<BasicBlock *>visited;
  BasicBlock *block{nullptr};BasicBlock *previous{nullptr};D resume;unsigned generator{0};};
 struct Gen {Frame frame;bool done{false},yielded{false},running{false};D result;unsigned asyncPromise{0};};
 struct Job {enum Type{ImportJob,ThenJob,ResumeJob}type;unsigned promise{0},target{0},result{0};D handler,value;CallInst *call{nullptr};};
 struct Prom {bool settled{false};D value;std::vector<Job> waiters;};
 struct Mod {unsigned graph{0},factory{0},gen{0},state{0},index{0},low{0};std::string url;
  std::vector<std::string>deps;std::set<std::string>exports;std::map<std::string,D> getters;CallInst *entry{nullptr};};
 Module *module_;const std::vector<Instruction *>&sources_,&sinks_;
 std::map<unsigned,Env>envs_;std::map<unsigned,C>closures_;std::map<unsigned,Obj>objects_;
 std::map<unsigned,Gen>gens_;std::map<unsigned,Prom>promises_;std::map<unsigned,Mod>modules_;
 std::map<unsigned,std::map<std::string,unsigned>>graphs_;
 std::map<std::string,D>globals_;std::set<std::string>declared_;
 std::map<Instruction *,std::string>ids_;std::deque<Job>jobs_;std::vector<unsigned>scc_;
 std::vector<DefUseAnalyzer::TaintPath>paths_;Function *global_{nullptr};
 unsigned serial_{1},steps_{0},depth_{0},jobsRun_{0},evals_{0},namespaceReads_{0},bindings_{0},sccIndex_{0};
 bool failed_{false};const char *reason_{"CLOSED_NATIVE_MODULE_GRAPH"};Instruction *barrier_{nullptr};
 static D make(Kind k,unsigned id=0){D d;d.k=k;d.id=id;return d;}
 static bool primitive(D d){return d.k==Undef||d.k==Null||d.k==Scalar||d.k==String||d.k==Number||d.k==Boolean;}
 static std::string literalKey(Value *v){if(auto *s=llvh::dyn_cast<LiteralString>(v))return s->getValue().str().str();return "";}
 bool source(Instruction *i){return std::find(sources_.begin(),sources_.end(),i)!=sources_.end();}
 bool sink(Instruction *i){return std::find(sinks_.begin(),sinks_.end(),i)!=sinks_.end();}
 std::string id(Instruction *i){auto p=ids_.find(i);return p==ids_.end()?"NONE":p->second;}
 D fail(const char *why,Instruction *at=nullptr){if(!failed_){reason_=why;barrier_=at;}failed_=true;return {};}
 unsigned fresh(){if(serial_>4096){fail("IDENTITY_LIMIT");return 0;}return serial_++;}
 void edge(D &d,Instruction *i){
  if(!i)return;
  for(auto &t:d.traces){if(t.path.size()>=512){fail("PATH_LIMIT",i);return;}if(t.path.empty()||t.path.back()!=i)t.path.push_back(i);}
  if(d.k==Namespace){if(d.carrier.size()>=128){fail("NAMESPACE_TRANSPORT_LIMIT",i);return;}d.carrier.push_back(i);}
 }
 bool tick(Instruction *at){if(++steps_>50000)fail("STEP_LIMIT",at);return !failed_;}
 D val(Value *v,Frame &f,Instruction *at){
  if(auto *s=llvh::dyn_cast<LiteralString>(v)){D d=make(String);d.text=s->getValue().str().str();return d;}
  if(auto *n=llvh::dyn_cast<LiteralNumber>(v)){D d=make(Number);d.number=n->getValue();return d;}
  if(auto *b=llvh::dyn_cast<LiteralBool>(v))return make(Boolean,b->getValue());
  if(llvh::isa<LiteralUndefined>(v))return make(Undef);
  if(llvh::isa<LiteralNull>(v))return make(Null);
  if(llvh::isa<LiteralEmpty>(v))return make(Empty);
  if(llvh::isa<GlobalObject>(v))return make(Global);
  if(auto *p=llvh::dyn_cast<Parameter>(v)){
   if(p->getParent()!=f.fn)return fail("FOREIGN_PARAMETER",at);
   if(p==f.fn->getThisParameter())return f.receiver;
   auto &params=f.fn->getParameters();for(unsigned n=0;n<params.size();++n)if(params[n]==p)return n<f.args.size()?f.args[n]:make(Undef);
   return fail("PARAMETER_IDENTITY",at);
  }
  auto p=f.values.find(v);return p==f.values.end()?fail("VALUE_NOT_IN_INVOCATION",at):p->second;
 }
 std::string propKey(D d,Instruction *at){
  if(d.k==String)return d.text;
  if(d.k==Number&&d.number>=0&&d.number<100000&&d.number==unsigned(d.number))return std::to_string(unsigned(d.number));
  fail("PROPERTY_KEY_NOT_LITERAL",at);return "";
 }
 unsigned environment(ScopeDesc *desc,unsigned parent,Instruction *at){
  if(!desc||desc->getDynamic()||(parent&&(!envs_.count(parent)||desc->getParent()!=envs_[parent].desc))){fail("LEXICAL_PARENT_IDENTITY",at);return 0;}
  unsigned n=fresh();envs_.emplace(n,Env{desc,parent,{}});return n;
 }
 Env *binding(D env,Variable *v,Instruction *at){
  if(env.k!=Scope){fail("LEXICAL_SCOPE_VALUE",at);return nullptr;}
  for(unsigned n=env.id,b=0;n&&b<64;++b){auto p=envs_.find(n);if(p==envs_.end())break;if(p->second.desc==v->getParent())return &p->second;n=p->second.parent;}
  fail("LEXICAL_BINDING_NOT_ANCESTOR",at);return nullptr;
 }
 D globalRead(std::string name,Instruction *at){
  auto p=globals_.find(name);if(p!=globals_.end()){D d=p->second;edge(d,at);return d;}
  if(declared_.count(name))return fail("GLOBAL_BEFORE_INITIALIZATION",at);
  if(name=="HermesInternal")return make(Internal);
  if(name=="Promise")return make(PromiseCtor);
  if(name=="Date")return make(DateObj);
  if(name=="document")return make(Document);
  return fail("AMBIENT_GLOBAL_UNRESOLVED",at);
 }
 D invokeClosure(D c,std::vector<D>args,D receiver,CallInst *at){
  if(c.k!=Closure||!closures_.count(c.id))return fail("CALL_TARGET_IDENTITY",at);
  if(++depth_>32){--depth_;return fail("CALL_DEPTH_LIMIT",at);}
  auto info=closures_.at(c.id);if(info.fn->isLazy()||info.fn->empty()){--depth_;return fail("LAZY_OR_EMPTY_FUNCTION",at);}
  if(args.size()>32||info.fn->getParameters().size()>32){--depth_;return fail("ARGUMENT_LIMIT",at);}
  Frame f;f.fn=info.fn;f.parent=info.env;f.receiver=receiver;f.args=args;f.block=&info.fn->front();
  if(!info.fn->isStrictMode()&&(receiver.k==Undef||receiver.k==Null))f.receiver=make(Global);
  for(auto &a:f.args)edge(a,at);
  D out=execute(f);edge(out,at);--depth_;return out;
 }
 D own(D obj,const std::string &key,Instruction *at){
  if((obj.k!=Object&&obj.k!=Array&&obj.k!=Arguments)||!objects_.count(obj.id))return fail("OWN_DATA_OBJECT_REQUIRED",at);
  auto &o=objects_[obj.id];auto p=o.fields.find(key);return p==o.fields.end()?make(Undef):p->second;
 }
 D get(D obj,const std::string &key,Instruction *at){
  if(obj.k==Global)return globalRead(key,at);
  if(obj.k==Internal&&key=="dynamicModuleGraph")return make(CreateGraph);
  if(obj.k==Graph&&key=="start")return make(Start,obj.id);
  if(obj.k==Graph&&key=="import")return make(Import,obj.id);
  if(obj.k==Context){
   if(key=="bind")return make(Bind,obj.id);if(key=="read")return make(Read,obj.id);
   if(key=="import")return make(Import,modules_[obj.id].graph);
   if(key=="namespace")return make(GetNamespace,obj.id);
  }
  if(obj.k==Promise&&key=="then")return make(Then,obj.id);
  if(obj.k==PromiseCtor&&key=="resolve")return make(Resolve);
  if(obj.k==DateObj&&key=="now")return make(Now);
  if(obj.k==Namespace){
   auto &m=modules_[obj.id];if(!m.exports.count(key))return make(Undef);
   auto p=m.getters.find(key);if(p==m.getters.end())return fail("EXPORT_NOT_INSTANTIATED",at);
   ++namespaceReads_;D d=invokeClosure(p->second,{},make(Undef),nullptr);
   for(auto *via:obj.carrier)edge(d,via);edge(d,at);return d;
  }
  if(obj.k==Array&&key=="push")return make(Push,obj.id);
  if((obj.k==Array||obj.k==Arguments)&&key=="length"){D d=make(Number);d.number=objects_[obj.id].length;return d;}
  if(obj.k==Object||obj.k==Array||obj.k==Arguments){D d=own(obj,key,at);edge(d,at);return d;}
  return fail("PROPERTY_GETTER_OUTSIDE_PROFILE",at);
 }
 D put(D obj,std::string key,D value,Instruction *at,bool ownStore){
  if(obj.k==Global){
   if(!declared_.count(key)||key=="Date"||key=="document"||key=="Promise"||key=="HermesInternal")return fail("HOST_OR_IMPLICIT_GLOBAL_WRITE",at);
   edge(value,at);globals_[key]=value;return make(Undef);
  }
  if(obj.k==Document&&key=="cookie"&&!ownStore){
   if(!primitive(value)||!sink(at))return fail("COOKIE_VALUE_OR_SINK_UNRESOLVED",at);
   edge(value,at);for(auto &trace:value.traces){if(paths_.size()>=256)return fail("SINK_PATH_LIMIT",at);paths_.emplace_back(trace.source,trace.path,at);}return make(Undef);
  }
  if(obj.k==Object||obj.k==Array){
   if(!ownStore||objects_[obj.id].sealed||key=="__proto__")return fail("MUTABLE_OR_INHERITED_OBJECT_WRITE",at);
   if(obj.k==Array){if(key.empty()||key.find_first_not_of("0123456789")!=std::string::npos||key.size()>3)return fail("ARRAY_INDEX_OUTSIDE_PROFILE",at);unsigned index=std::stoul(key);if(index>=128)return fail("ARRAY_LIMIT",at);objects_[obj.id].length=std::max(objects_[obj.id].length,index+1);}
   objects_[obj.id].fields[key]=value;return make(Undef);
  }
  return fail("PROPERTY_WRITE_OUTSIDE_PROFILE",at);
 }
 std::vector<D> elements(D d,Instruction *at){
  if(d.k!=Array&&d.k!=Arguments){fail("ARRAY_IDENTITY",at);return {};}
  auto &o=objects_[d.id];if(o.length>128){fail("ARRAY_LENGTH_LIMIT",at);return {};}
  std::vector<D> out;for(unsigned i=0;i<o.length;++i){auto p=o.fields.find(std::to_string(i));if(p==o.fields.end()){fail("ARRAY_HOLE",at);return {};}out.push_back(p->second);}return out;
 }
 unsigned resolveModule(unsigned graph,D url,Instruction *at){
  if(url.k!=String||!graphs_.count(graph)){fail("MODULE_ID_NOT_EXACT",at);return 0;}
  auto p=graphs_[graph].find(url.text);if(p==graphs_[graph].end()){fail("MISSING_MODULE_REJECTION_OUTSIDE_PROFILE",at);return 0;}return p->second;
 }
 D createGraph(D array,Instruction *at){
  unsigned graph=fresh();graphs_[graph]={};auto list=elements(array,at);if(failed_)return {};
  if(list.empty()||list.size()>64)return fail("MODULE_COUNT",at);
  objects_[array.id].sealed=true;
  for(auto d:list){
   D url=own(d,"id",at),exports=own(d,"exports",at),deps=own(d,"deps",at),factory=own(d,"factory",at);
   if(failed_||url.k!=String||factory.k!=Closure||!llvh::isa<GeneratorFunction>(closures_[factory.id].fn)||graphs_[graph].count(url.text))return fail("MODULE_DESCRIPTOR",at);
   if(objects_[d.id].fields.size()!=4)return fail("EXTRA_DESCRIPTOR_PROPERTY",at);
   unsigned id=fresh();Mod m;m.url=url.text;m.graph=graph;m.factory=factory.id;
   for(auto e:elements(exports,at)){if(e.k!=String||!m.exports.insert(e.text).second)return fail("EXPORT_NAME",at);}
   for(auto e:elements(deps,at)){if(e.k!=String)return fail("DEPENDENCY_ID",at);m.deps.push_back(e.text);}
   objects_[d.id].sealed=objects_[exports.id].sealed=objects_[deps.id].sealed=true;
   modules_[id]=m;graphs_[graph][url.text]=id;
  }
  return make(Graph,graph);
 }
 D resumeGenerator(unsigned gen,D value){
  auto &g=gens_[gen];if(g.done||g.running)return fail("GENERATOR_STATE");
  g.running=true;g.yielded=false;g.frame.resume=value;
  D result=execute(g.frame);g.result=result;g.running=false;
  if(!g.yielded)g.done=true;
  return result;
 }
 void instantiate(unsigned id,CallInst *at){
  if(failed_)return;auto &m=modules_[id];if(m.state)return;m.state=1;m.entry=at;
  D gen=invokeClosure(make(Closure,m.factory),{make(Context,id)},make(Undef),at);
  if(gen.k!=Generator||failed_){fail("MODULE_FACTORY_GENERATOR",at);return;}
  m.gen=gen.id;D first=resumeGenerator(gen.id,make(Undef));
  if(failed_||gens_[gen.id].done||!gens_[gen.id].yielded||first.k!=Undef||m.getters.size()!=m.exports.size()){fail("MODULE_INSTANTIATION_CONTRACT",at);return;}
  for(auto &url:m.deps){D s=make(String);s.text=url;unsigned dep=resolveModule(m.graph,s,at);if(failed_)return;instantiate(dep,at);}
  m.state=2;
 }
 void evaluateVisit(unsigned id,CallInst *at){
  if(failed_)return;auto &m=modules_[id];if(m.state==4||m.state==3)return;
  if(m.state!=2){fail("MODULE_EVALUATION_STATE",at);return;}
  m.state=3;m.index=m.low=sccIndex_++;scc_.push_back(id);
  for(auto &url:m.deps){D s=make(String);s.text=url;unsigned dep=resolveModule(m.graph,s,at);if(failed_)return;evaluateVisit(dep,at);if(modules_[dep].state==3)m.low=std::min(m.low,modules_[dep].low);}
  resumeGenerator(m.gen,make(Undef));if(failed_)return;
  if(!gens_[m.gen].done){fail("MODULE_BODY_EXTRA_YIELD",at);return;}++evals_;
  if(m.low==m.index){unsigned n;do{n=scc_.back();scc_.pop_back();modules_[n].state=4;}while(n!=id);}
 }
 D evaluate(unsigned id,CallInst *at){instantiate(id,at);if(!failed_)evaluateVisit(id,at);D d=make(Namespace,id);edge(d,at);return d;}
 unsigned newPromise(){unsigned p=fresh();promises_[p]={};return p;}
 void enqueue(Job job){if(jobs_.size()+jobsRun_>=256){fail("JOB_LIMIT",job.call);return;}jobs_.push_back(job);}
 void settle(unsigned promise,D value,CallInst *at){
  if(failed_)return;if(promises_[promise].settled){fail("PROMISE_DOUBLE_RESOLUTION",at);return;}
  if(value.k==Namespace){if(modules_[value.id].exports.count("then")){fail("NAMESPACE_THENABLE_ASSIMILATION",at);return;}}
  else if(!primitive(value)){fail("PROMISE_ASSIMILATION_OUTSIDE_PROFILE",at);return;}
  edge(value,at);auto &p=promises_[promise];p.value=value;p.settled=true;
  for(auto job:p.waiters){job.value=value;enqueue(job);}p.waiters.clear();
 }
 void awaitPromise(unsigned promise,Job job){
  if(!promises_.count(promise)){fail("PROMISE_IDENTITY",job.call);return;}
  auto &p=promises_[promise];if(p.settled){job.value=p.value;enqueue(job);}else p.waiters.push_back(job);
 }
 void advanceAsync(unsigned generator,D value){
  auto &g=gens_[generator];D out=resumeGenerator(generator,value);if(failed_)return;
  if(g.done){settle(g.asyncPromise,out,nullptr);return;}
  Job job;job.type=Job::ResumeJob;job.target=generator;
  if(out.k==Promise)awaitPromise(out.id,job);
  else {if(!primitive(out)&&out.k!=Namespace){fail("AWAIT_THENABLE_OUTSIDE_PROFILE");return;}
   if(out.k==Namespace&&modules_[out.id].exports.count("then")){fail("AWAIT_NAMESPACE_THENABLE");return;}
   job.value=out;enqueue(job);}
 }
 D invoke(CallInst *call,Frame &f){
  if(llvh::isa<ConstructInst>(call)||llvh::isa<CallBuiltinInst>(call)||call->getNumArguments()<1)return fail("CALL_KIND_OUTSIDE_PROFILE",call);
  D callee=val(call->getCallee(),f,call),receiver=val(call->getArgument(0),f,call);std::vector<D>args;
  for(unsigned n=1;n<call->getNumArguments();++n)args.push_back(val(call->getArgument(n),f,call));if(failed_)return {};
  auto arity=[&](unsigned n){if(args.size()!=n){fail("ABI_ARITY",call);return false;}return true;};
  if(callee.k==Closure){if(receiver.k!=Undef&&receiver.k!=Namespace)return fail("ORDINARY_CALL_RECEIVER",call);return invokeClosure(callee,args,receiver,call);}
  if(callee.k==CreateGraph){if(!arity(1)||receiver.k!=Internal)return fail("GRAPH_ABI_RECEIVER",call);return createGraph(args[0],call);}
  if(callee.k==Start){if(!arity(1)||receiver.k!=Graph||receiver.id!=callee.id)return fail("START_ABI_RECEIVER",call);unsigned m=resolveModule(callee.id,args[0],call);return failed_?D{}:evaluate(m,call);}
  if(callee.k==Bind){
   if(!arity(2)||receiver.k!=Context||receiver.id!=callee.id||args[0].k!=String||args[1].k!=Closure)return fail("BIND_ABI",call);
   auto &m=modules_[callee.id];if(m.state!=1||!m.exports.count(args[0].text)||m.getters.count(args[0].text))return fail("EXPORT_BINDING_STATE",call);
   m.getters[args[0].text]=args[1];++bindings_;return make(Undef);
  }
  if(callee.k==Read||callee.k==GetNamespace){
   if(!arity(callee.k==Read?2:1)||receiver.k!=Context||receiver.id!=callee.id)return fail("READ_ABI",call);
   unsigned m=resolveModule(modules_[callee.id].graph,args[0],call);if(failed_)return {};D ns=make(Namespace,m);edge(ns,call);
   if(callee.k==GetNamespace)return ns;
   if(args[1].k!=String)return fail("EXPORT_KEY",call);return get(ns,args[1].text,call);
  }
  if(callee.k==Import){
   if(!arity(1)||!((receiver.k==Context&&modules_[receiver.id].graph==callee.id)||(receiver.k==Graph&&receiver.id==callee.id)))return fail("IMPORT_ABI",call);
   unsigned target=resolveModule(callee.id,args[0],call);if(failed_)return {};unsigned p=newPromise();Job job;job.type=Job::ImportJob;job.target=target;job.promise=p;job.call=call;enqueue(job);return make(Promise,p);
  }
  if(callee.k==Then){
   if(receiver.k!=Promise||receiver.id!=callee.id||args.size()>2||args.empty()||args[0].k!=Closure)return fail("THEN_EXACT_HANDLER",call);
   unsigned p=newPromise();Job job;job.type=Job::ThenJob;job.handler=args[0];job.result=p;job.promise=callee.id;job.call=call;awaitPromise(callee.id,job);return make(Promise,p);
  }
  if(callee.k==Resolve){
   if(receiver.k!=PromiseCtor||args.size()>1)return fail("PROMISE_RESOLVE_ABI",call);D d=args.empty()?make(Undef):args[0];
   if(d.k==Promise)return d;unsigned p=newPromise();settle(p,d,call);return make(Promise,p);
  }
  if(callee.k==Spawn){
   if(!arity(3)||args[0].k!=Closure||args[2].k!=Arguments||receiver.k!=Undef)return fail("SPAWN_ASYNC_ABI",call);
   D gen=invokeClosure(args[0],elements(args[2],call),args[1],call);if(gen.k!=Generator||failed_)return fail("SPAWN_GENERATOR",call);
   unsigned p=newPromise();gens_[gen.id].asyncPromise=p;advanceAsync(gen.id,make(Undef));return make(Promise,p);
  }
  if(callee.k==Now){
   if(!arity(0)||receiver.k!=DateObj)return fail("DATE_RECEIVER",call);
   auto *load=llvh::dyn_cast<Instruction>(call->getCallee());Instruction *s=source(call)?call:(load&&source(load)?load:nullptr);
   if(!s)return fail("DATE_SOURCE_NOT_REGISTERED",call);D d=make(Scalar);d.traces.push_back({s,{s}});edge(d,call);return d;
  }
  if(callee.k==Push){
   if(receiver.k!=Array||receiver.id!=callee.id||objects_[callee.id].sealed)return fail("ARRAY_PUSH_RECEIVER",call);
   for(auto d:args){if(!primitive(d))return fail("ARRAY_PUSH_OBJECT_ESCAPE",call);auto &o=objects_[callee.id];if(o.length>=128)return fail("ARRAY_LIMIT",call);o.fields[std::to_string(o.length++)]=d;}
   D d=make(Number);d.number=objects_[callee.id].length;return d;
  }
  return fail("CALL_TARGET_UNMODELLED",call);
 }
 D instruction(Instruction *i,Frame &f){
  if(auto *s=llvh::dyn_cast<CreateScopeInst>(i)){
   if(f.env)return fail("DUPLICATE_SCOPE",i);f.env=environment(s->getCreatedScopeDesc(),f.parent,i);return make(Scope,f.env);
  }
  if(auto *s=llvh::dyn_cast<CreateInnerScopeInst>(i)){D p=val(s->getParentScope(),f,i);if(p.k!=Scope)return fail("INNER_SCOPE",i);return make(Scope,environment(s->getCreatedScopeDesc(),p.id,i));}
  if(auto *s=llvh::dyn_cast<StoreFrameInst>(i)){Env *e=binding(val(s->getEnvironment(),f,i),s->getVariable(),i);if(!e)return {};D d=val(s->getValue(),f,i);edge(d,i);e->vars[s->getVariable()]=d;return make(Undef);}
  if(auto *l=llvh::dyn_cast<LoadFrameInst>(i)){Env *e=binding(val(l->getEnvironment(),f,i),l->getLoadVariable(),i);if(!e)return {};auto p=e->vars.find(l->getLoadVariable());if(p==e->vars.end())return fail("UNINITIALIZED_BINDING",i);D d=p->second;edge(d,i);return d;}
  if(auto *c=llvh::dyn_cast<CreateFunctionInst>(i)){
   D scope=val(c->getEnvironment(),f,i);if(scope.k!=Scope||!envs_.count(scope.id)||c->getFunctionCode()->getFunctionScopeDesc()->getParent()!=envs_[scope.id].desc)return fail("CLOSURE_PARENT",i);
   unsigned n=fresh();
   if(llvh::isa<CreateGeneratorInst>(c)){
    Gen g;g.frame.fn=c->getFunctionCode();g.frame.parent=scope.id;g.frame.args=f.args;g.frame.receiver=f.receiver;g.frame.block=&g.frame.fn->front();g.frame.generator=n;gens_[n]=g;return make(Generator,n);
   }
   closures_[n]={c->getFunctionCode(),scope.id,c};return make(Closure,n);
  }
  if(auto *b=llvh::dyn_cast<GetBuiltinClosureInst>(i)){
   if(b->getBuiltinIndex()!=BuiltinMethod::HermesBuiltin_spawnAsync)return fail("BUILTIN_OUTSIDE_PROFILE",i);return make(Spawn);
  }
  if(auto *a=llvh::dyn_cast<AllocObjectInst>(i)){if(!llvh::isa<EmptySentinel>(a->getParentObject()))return fail("CUSTOM_OBJECT_PROTOTYPE",i);unsigned n=fresh();objects_[n]={};return make(Object,n);}
  if(auto *a=llvh::dyn_cast<AllocArrayInst>(i)){
   unsigned n=fresh();auto &o=objects_[n];o.array=true;o.length=a->getElementCount();if(o.length>128)return fail("ARRAY_SIZE_LIMIT",i);
   for(unsigned k=0;k<a->getElementCount();++k)o.fields[std::to_string(k)]=val(a->getArrayElement(k),f,i);return make(Array,n);
  }
  if(llvh::isa<CreateArgumentsInst>(i)){unsigned n=fresh();auto &o=objects_[n];o.array=true;o.length=f.args.size();for(unsigned k=0;k<f.args.size();++k)o.fields[std::to_string(k)]=f.args[k];return make(Arguments,n);}
  if(auto *s=llvh::dyn_cast<StoreOwnPropertyInst>(i))return put(val(s->getObject(),f,i),propKey(val(s->getProperty(),f,i),i),val(s->getStoredValue(),f,i),i,true);
  if(auto *l=llvh::dyn_cast<LoadPropertyInst>(i))return get(val(l->getObject(),f,i),propKey(val(l->getProperty(),f,i),i),i);
  if(auto *s=llvh::dyn_cast<StorePropertyInst>(i))return put(val(s->getObject(),f,i),propKey(val(s->getProperty(),f,i),i),val(s->getStoredValue(),f,i),i,false);
  if(auto *a=llvh::dyn_cast<AllocStackInst>(i)){f.stack[a]=make(Bad);return make(Bad);}
  if(auto *s=llvh::dyn_cast<StoreStackInst>(i)){D d=val(s->getValue(),f,i);edge(d,i);f.stack[s->getPtr()]=d;return make(Undef);}
  if(auto *l=llvh::dyn_cast<LoadStackInst>(i)){auto p=f.stack.find(l->getPtr());if(p==f.stack.end()||p->second.k==Bad)return fail("STACK_NOT_INITIALIZED",i);D d=p->second;edge(d,i);return d;}
  if(llvh::isa<StartGeneratorInst>(i)){if(!f.generator)return fail("GENERATOR_START_IDENTITY",i);return make(Undef);}
  if(auto *r=llvh::dyn_cast<ResumeGeneratorInst>(i)){
   auto *slot=llvh::dyn_cast<AllocStackInst>(r->getIsReturn());if(!f.generator||!slot||!f.stack.count(slot))return fail("GENERATOR_RESUME_IDENTITY",i);
   f.stack[slot]=make(Boolean,0);D d=f.resume;edge(d,i);return d;
  }
  if(auto *c=llvh::dyn_cast<ThrowIfEmptyInst>(i)){D d=val(c->getCheckedValue(),f,i);if(d.k==Empty||d.k==Bad)return fail("TDZ_EXCEPTION_OUTSIDE_PROFILE",i);edge(d,i);return d;}
  if(llvh::isa<GetNewTargetInst>(i))return make(Undef);
  if(auto *c=llvh::dyn_cast<CallInst>(i))return invoke(c,f);
  if(auto *m=llvh::dyn_cast<MovInst>(i)){D d=val(m->getSingleOperand(),f,i);edge(d,i);return d;}
  if(auto *u=llvh::dyn_cast<UnaryOperatorInst>(i)){
   D d=val(u->getSingleOperand(),f,i);if(u->getOperatorKind()==UnaryOperatorInst::OpKind::VoidKind)return make(Undef);
   if(u->getOperatorKind()==UnaryOperatorInst::OpKind::BangKind){int b=truth(d);if(b<0)return fail("UNKNOWN_TRUTHINESS",i);return make(Boolean,!b);}return fail("UNARY_OPERATOR",i);
  }
  if(auto *b=llvh::dyn_cast<BinaryOperatorInst>(i)){
   D a=val(b->getLeftHandSide(),f,i),c=val(b->getRightHandSide(),f,i);
   if(b->getOperatorKind()!=BinaryOperatorInst::OpKind::AddKind||!primitive(a)||!primitive(c))return fail("OPERATOR_OR_COERCION",i);
   D d=make(Scalar);d.traces=a.traces;d.traces.insert(d.traces.end(),c.traces.begin(),c.traces.end());if(d.traces.size()>16)return fail("TRACE_LIMIT",i);edge(d,i);return d;
  }
  if(auto *p=llvh::dyn_cast<PhiInst>(i)){
   for(unsigned n=0;n<p->getNumEntries();++n){auto e=p->getEntry(n);if(e.second==f.previous){D d=val(e.first,f,i);edge(d,i);return d;}}return fail("PHI_PREDECESSOR",i);
  }
  return fail("INSTRUCTION_OUTSIDE_MODULE_PROFILE",i);
 }
 int truth(D d){if(d.k==Boolean)return d.id?1:0;if(d.k==Undef||d.k==Null)return 0;if(d.k==String)return !d.text.empty();if(d.k==Number)return d.number!=0&&!std::isnan(d.number);if(d.k==Scalar||d.k==Bad||d.k==Empty)return -1;return 1;}
 D execute(Frame &f){
  while(f.block&&!failed_){
   BasicBlock *block=f.block;if(!f.visited.insert(block).second)return fail("LOOP_OUTSIDE_PROFILE");
   f.block=nullptr;
   for(auto &i:*block){if(!tick(&i))return {};
    if(auto *ret=llvh::dyn_cast<ReturnInst>(&i)){D d=val(ret->getValue(),f,ret);edge(d,ret);return d;}
    if(auto *b=llvh::dyn_cast<BranchInst>(&i)){f.previous=block;f.block=b->getBranchDest();break;}
    if(auto *b=llvh::dyn_cast<CondBranchInst>(&i)){int cond=truth(val(b->getCondition(),f,b));if(cond<0)return fail("BRANCH_NOT_EXACT",b);f.previous=block;f.block=cond?b->getTrueDest():b->getFalseDest();break;}
    if(auto *y=llvh::dyn_cast<SaveAndYieldInst>(&i)){
     if(!f.generator)return fail("YIELD_OUTSIDE_GENERATOR",y);D d=val(y->getResult(),f,y);edge(d,y);f.previous=block;f.block=y->getNextBlock();gens_[f.generator].yielded=true;return d;
    }
    f.values[&i]=instruction(&i,f);
   }
   if(!f.block&&!failed_)return fail("MISSING_NORMAL_RETURN");
  }
  return {};
 }
 void runJobs(){
  while(!jobs_.empty()&&!failed_){Job j=jobs_.front();jobs_.pop_front();++jobsRun_;
   if(j.type==Job::ImportJob){D ns=evaluate(j.target,j.call);if(!failed_)settle(j.promise,ns,j.call);}
   else if(j.type==Job::ThenJob){D d=j.value;edge(d,j.call);D result=invokeClosure(j.handler,{d},make(Undef),j.call);if(!failed_)settle(j.result,result,j.call);}
   else advanceAsync(j.target,j.value);
  }
  for(auto &p:promises_)if(!p.second.settled||!p.second.waiters.empty())fail("UNSETTLED_PROMISE_OR_WAITERS");
 }
 void index(){
  unsigned fn=0,count=0;
  for(auto *g:module_->getGlobalProperties())if(g->isDeclared())declared_.insert(literalKey(g->getName()));
  for(auto &f:*module_){if(f.isGlobalScope()){if(global_)fail("MULTIPLE_GLOBAL_ENTRIES");global_=&f;}unsigned in=0;
   for(auto &b:f)for(auto &i:b){ids_[&i]="F"+std::to_string(fn)+":I"+std::to_string(in++);if(++count>100000){fail("IR_LIMIT",&i);return;}}
   ++fn;
  }
  if(!global_)fail("MISSING_GLOBAL_ENTRY");
 }
public:
 static bool present(Module *m){
  for(auto &f:*m)for(auto &b:f)for(auto &i:b)if(auto *l=llvh::dyn_cast<LoadPropertyInst>(&i))
   if(literalKey(l->getProperty())=="dynamicModuleGraph")return true;
  return false;
 }
 DynamicModuleTransport(Module *m,const std::vector<Instruction *>&sources,const std::vector<Instruction *>&sinks):module_(m),sources_(sources),sinks_(sinks){index();}
 bool analyze(std::vector<DefUseAnalyzer::TaintPath>&out){
  if(!failed_){Frame f;f.fn=global_;f.receiver=make(Global);f.block=&global_->front();execute(f);runJobs();}
  if(graphs_.empty()&&!failed_)fail("NO_NATIVE_GRAPH_CREATED");
  if(!failed_){out.clear();for(auto &p:paths_){if(std::none_of(out.begin(),out.end(),[&](const DefUseAnalyzer::TaintPath&q){return p.source==q.source&&p.sink==q.sink;}))out.push_back(p);}}
  llvh::outs()<<"[DYNAMIC_MODULE_TRANSPORT] status="<<(failed_?"UNKNOWN":"PROVED")<<" modules="<<modules_.size()<<" evaluated="<<evals_<<" exports="<<bindings_<<" namespace_reads="<<namespaceReads_<<" jobs="<<jobsRun_<<" paths="<<(failed_?0:out.size())<<" reason="<<reason_<<" barrier="<<id(barrier_)<<" contract=CLOSED_EXACT_NATIVE_MODULE_STATE_FIFO_PROMISE_NAMESPACE_LEXICAL_ENV_PRISTINE_INTRINSICS\n";
  if(!failed_)for(auto &p:out)llvh::outs()<<"[DYNAMIC_MODULE_TRACE] source="<<id(p.source)<<" sink="<<id(p.sink)<<"\n";
  if(failed_){out.clear();module_->getContext().getSourceErrorManager().error(barrier_?barrier_->getLocation():SMLoc(),"[NATIVE_DYNAMIC_MODULE_TAINT_UNPROVEN] Unsupported effect, value, or module state");}
  return !failed_;
 }
};
} }

                                                                            
                                                                                            
                                                                              
                                                                           
                                                                       
                                                                            
                                                                                 
                                                                                       
                                                                             
                                                                                
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <map>
#include <set>

namespace hermes { namespace {
class BoundedToSetterTransport {
  using Path = std::vector<Instruction *>;
  struct Trace {
    Instruction *source;
    Path path;
    unsigned origin;
    bool awaited{false};
    bool setter{false};
    bool property{false};
    bool module{false};
    bool dynamic{false};
    bool proxy{false};
    bool functionProperty{false};
    bool descriptor{false};
    bool registry{false};
    bool ownState{false};
    bool dispatch{false};
    bool enumeration{false};
    bool iteration{false};
                                                                                 
    std::set<unsigned> deferredOwnReads;
  };
  enum Kind { Invalid, Primitive, Undefined, Null, Global, OpaqueGlobalThis,
              Scope, Closure, Instance, DateObject, DateNow, AmbientDocument,
              Helpers, DefineClass, DefineMethod, PromiseToken, Array, Record, SetterObject,
              ProxyConstructor, ProxyCallable, TargetApply, ObjectIntrinsic, DescriptorDefine, HasOwnIntrinsic, RecordHasOwnIntrinsic, ObjectKeysIntrinsic, KeysForEachIntrinsic, FreshGetterSlot, Empty, SymbolIntrinsic, IteratorSymbol, AsyncIterationIntrinsic, AsyncIterationRecord, AsyncIterationResult };
  struct Datum {
    Kind kind{Invalid}; unsigned ref{0};
    bool knownString{false}; std::string string;
    bool knownInteger{false}; int64_t integer{0};
    bool dynamicClosure{false};
    bool knownBoolean{false}; bool boolean{false};
    bool functionProperty{false}; bool callbackClosure{false};
    bool ownStateBoolean{false};
    bool dispatchBoolean{false};
    unsigned moduleDataRoot{0},moduleDataDepth{0},moduleKeyEvent{0},dispatchRegistration{0},dispatchSelection{0};
    unsigned enumerationSnapshot{0}; bool enumerationClosure{false};
    bool truthKnown{false},truthValue{false};
    std::vector<Trace> traces;
  };
  struct Environment {
    ScopeDesc *descriptor{nullptr}; unsigned parent{0};
    std::map<Variable *, Datum> vars;
  };
  struct ClosureInfo {
    Function *function{nullptr}; CreateFunctionInst *creation{nullptr};
    unsigned environment{0}; bool isClass{false}; unsigned methodOwner{0};
                                                                            
    bool exactBaseClassOwnState{false};
    std::map<std::string,unsigned> methods;
    std::map<std::string,Datum> ownFields;
  };
  struct ObjectInfo {
    unsigned constructor{0}; ConstructInst *allocation{nullptr};
    std::map<std::string, Datum> fields;
    std::vector<std::string> keyOrder;
    AllocObjectInst *recordAllocation{nullptr};
  };
  struct ArrayInfo { std::vector<Datum> values; };
  struct SetterCertificate {
    Function *helper{nullptr}, *setter{nullptr};
    StorePropertyInst *slotWrite{nullptr}; CallInst *apply{nullptr};
  };
  struct SetterInfo {
    unsigned closure{0}, array{0}, slot{0}; Datum receiver;
    SetterCertificate certificate; CallInst *creation{nullptr};
  };
  struct PropertyCertificate {
    Function *helper{nullptr}; Instruction *keyBinding{nullptr};
    CallInst *keyCall{nullptr}, *defineCall{nullptr}; StorePropertyInst *store{nullptr};
    ReturnInst *returned{nullptr};
  };
  struct KeyCertificate {
    Function *helper{nullptr}; Instruction *primitiveBinding{nullptr}; CallInst *call{nullptr};
  };
  struct ModuleCertificate {
    Function *function{nullptr}; Instruction *cacheBinding{nullptr}, *registryBinding{nullptr}, *selfBinding{nullptr};
    AllocObjectInst *cacheAllocation{nullptr}, *registryAllocation{nullptr};
    StorePropertyInst *cacheWrite{nullptr}; CallInst *dispatch{nullptr}; ReturnInst *returned{nullptr};
    bool viaCall{false};
  };
  struct ModuleEntry { unsigned record{0}; bool complete{false}; };
  struct LoaderState { unsigned registry{0},cache{0}; std::map<std::string,ModuleEntry> entries; };
  struct ProxyInfo { unsigned target{0},handler{0}; ConstructInst *creation{nullptr}; };
  struct ProxyInvocation { unsigned proxy{0},target{0},handler{0},array{0}; Datum receiver; CallInst *call{nullptr}; };
  struct ResultObservation { bool allPrimitive{true}; unsigned count{0}; std::set<Instruction *> sources; };
  struct DeferredOwnRead { unsigned object; std::string key; LoadPropertyInst *read; unsigned invocation,step; };
  struct DeferredOwnSink { Trace trace; Instruction *sink; unsigned step; };
  struct OwnStateProof { Instruction *operation; std::string key; unsigned step; };
  struct ModuleKeyRead { unsigned root,object; std::string key,value; LoadPropertyInst *read; };
  struct DispatchRegistration { unsigned table,closure,keyEvent; std::string key; StorePropertyInst *write; };
  struct DispatchSelection { unsigned table,closure,keyEvent,registration; std::string key; LoadPropertyInst *read; };
  struct DispatchSlot { unsigned table,closure; std::string key; Instruction *write; };
  struct InactiveDispatch { unsigned event,slot,keyEvent; std::string testedKey; Instruction *effect; bool replaced; };
  struct EnumerationSnapshot { unsigned object; std::vector<std::string> keys; };
  struct Frame {
    Function *function{nullptr}; CreateScopeInst *scope{nullptr};
    Instruction *entry{nullptr}; unsigned invocation{0}, environment{0}, parent{0};
    unsigned promise{0}, constructor{0}, definitions{0};
    Datum receiver; std::vector<Datum> arguments; bool setterReceiver{false};
    bool moduleFactory{false};
    bool iteratorMode{false};
    bool dynamicContext{false};
    unsigned proxyInvocation{0}; bool proxyTrap{false}; BasicBlock *predecessor{nullptr};
    bool functionContext{false};
    bool registryContext{false};
    bool ownControl{false};
    bool dispatchContext{false},dispatchControl{false};
    bool enumerationMode{false},enumerationCallback{false};unsigned enumerationSnapshot{0};
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
    unsigned delay{0};
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
                                                                        
                                                                           
  struct IterationState {
    Datum iterable, receiver, next;
    bool syncArray{false}, syncRecord{false};
    unsigned cursor{0};
  };
  struct IterationResult {
    bool done{false}; Datum value;
    Instruction *next{nullptr}, *yield{nullptr}, *resume{nullptr};
    unsigned delay{0};bool closeOnly{false};
  };
  bool nativeIterationPresent_{false};
  std::set<Function *> iteratorFunctions_;
  std::set<StorePropertyInst *> iteratorWriteCandidates_;
  std::map<std::pair<unsigned,unsigned>,Datum> iteratorSymbols_;
  std::map<unsigned,IterationState> iterators_;
  std::map<unsigned,IterationResult> iterationResults_;
  unsigned iteratorCreates_{0},iteratorNexts_{0},iteratorCloses_{0};

  Module *module_;
  const std::vector<Instruction *> &sources_, &sinks_;
  std::map<Instruction *,std::string> ids_;
  std::map<Function *,unsigned> creationCounts_;
  std::map<AsyncFunction *,Binding> bindings_;
  std::map<unsigned,Environment> environments_;
  std::map<unsigned,ClosureInfo> closures_;
  std::map<unsigned,ObjectInfo> objects_;
  std::map<unsigned,Fulfillment> promises_;
  std::map<unsigned,ArrayInfo> arrays_;
  std::map<unsigned,SetterInfo> setters_;
  std::map<Function *,SetterCertificate> helperCertificates_;
  std::set<Instruction *> helperInstructions_;
  std::map<Function *,PropertyCertificate> propertyCertificates_;
  std::map<Function *,KeyCertificate> keyCertificates_;
  std::set<Function *> primitiveStringCertificates_;
  std::map<Function *,ModuleCertificate> moduleCertificates_;
  std::set<Instruction *> moduleCacheInstructions_;
  std::set<AllocObjectInst *> registryAllocations_,cacheAllocations_;
  std::map<unsigned,LoaderState> loaderStates_;
  std::set<unsigned> registryObjects_,cacheObjects_,moduleRecords_,exportObjects_;
  unsigned moduleRequires_{0},factoryCalls_{0},cacheHits_{0},moduleTentative_{0};
  struct FreshGetter { unsigned closure,event; StoreGetterSetterInst *definition; };
  std::set<StoreGetterSetterInst *> freshGetterCandidates_;
  std::map<std::pair<unsigned,std::string>,FreshGetter> freshGetters_;
  unsigned freshGetterDefinitions_{0},freshGetterCalls_{0},freshGetterReturns_{0};
  std::set<Function *> nestedAliasFunctions_;
  unsigned nestedAliasBranches_{0};
  std::set<StorePropertyInst *> nestedAliasCandidates_;
  std::set<LoadPropertyInst *> nestedAliasOperands_;
  std::map<std::pair<unsigned,std::string>,unsigned> nestedAliasSlots_;
  unsigned nestedAliasWrites_{0},nestedAliasReads_{0},nestedAliasOperandReads_{0};
  std::set<StorePropertyInst *> dynamicWriteCandidates_;
  std::set<unsigned> dynamicObjects_;
  unsigned dynamicWrites_{0},dynamicCalls_{0},dynamicTentative_{0};
  std::set<ConstructInst *> proxyCandidates_;
  std::set<AllocObjectInst *> handlerAllocations_;
  std::set<StorePropertyInst *> handlerWriteCandidates_;
  std::set<Function *> proxyFunctions_;
  std::set<unsigned> handlerObjects_,proxyArgumentArrays_;
  std::map<unsigned,ProxyInfo> proxies_;
  std::map<unsigned,ProxyInvocation> proxyInvocations_;
  std::map<CallInst *,ResultObservation> proxyResultObservations_;
  std::map<Instruction *,ResultObservation> cookieObservations_;
  std::set<Instruction *> observedDateSources_;
  std::set<DeletePropertyInst *> functionDeleteCandidates_;
  std::set<unsigned> functionObjects_;
  std::map<Instruction *,ResultObservation> functionReadObservations_,callbackResultObservations_;
  std::map<Instruction *,unsigned> callExecutions_,readExecutions_;
  std::set<Instruction *> functionResultSites_;
  std::map<LoadPropertyInst *,CallInst *> descriptorCandidates_;
  std::map<unsigned,std::set<std::string>> descriptorKeys_;
  std::map<Instruction *,ResultObservation> descriptorReadObservations_;
  unsigned descriptorCalls_{0},descriptorWrites_{0},descriptorReads_{0},descriptorTentative_{0};
  std::set<StorePropertyInst *> registryWriteCandidates_;
  std::map<unsigned,unsigned> registryOwners_;
  std::map<unsigned,std::set<std::string>> registeredKeys_;
  std::set<unsigned> registeredExportObjects_;
  unsigned registryWrites_{0},registryReads_{0},registryAliases_{0},registryTentative_{0};
  std::set<DeletePropertyInst *> ownDeleteCandidates_;
  std::map<LoadPropertyInst *,CallInst *> ownCheckCandidates_;
  std::set<unsigned> ownStateObjects_;
  std::map<unsigned,OwnStateProof> ownStateProofs_;
  std::map<unsigned,DeferredOwnRead> deferredOwnReads_;
  std::vector<DeferredOwnSink> deferredOwnSinks_;
  unsigned ownPromoted_{0};
  std::set<StorePropertyInst *> moduleKeyWriteCandidates_;
  std::map<LoadPropertyInst *,CallInst *> recordHasCandidates_;
  std::map<unsigned,ModuleKeyRead> moduleKeyReads_;
  std::map<unsigned,DispatchRegistration> dispatchRegistrations_;
  std::map<unsigned,DispatchSelection> dispatchSelections_;
  std::map<unsigned,DispatchSlot> dispatchSlots_;
  std::map<unsigned,InactiveDispatch> inactiveDispatch_;
  std::map<unsigned,unsigned> exactClosureCalls_;
  std::map<Function *,unsigned> exactFunctionCalls_;
  unsigned inactiveDispatchEvents_{0};
  std::map<LoadPropertyInst *,CallInst *> objectKeysCandidates_;
  std::set<StorePropertyInst *> enumerationWriteCandidates_;
  std::set<Function *> enumerationFunctions_;
  std::set<Function *> nestedCacheFunctions_;
  std::set<CallInst *> nestedCacheChecks_;
  std::set<StorePropertyInst *> nestedCacheWrites_;
  std::map<unsigned,std::map<std::pair<unsigned,std::string>,bool>> nestedCachePresence_;
  unsigned nestedCacheChecksCount_{0},nestedCacheWritesCount_{0},nestedCacheReadsCount_{0};
                                                                              
                                                                           
  std::map<Value *,Value *> enumerationBindings_;
  std::set<Value *> enumerationAmbiguousBindings_;
  std::map<std::string,Value *> enumerationGlobals_;
  std::set<std::string> enumerationAmbiguousGlobals_;
  std::map<CallInst *,std::vector<std::pair<CallInst *,Function *>>> enumerationLinks_;
  std::map<unsigned,EnumerationSnapshot> enumerationSnapshots_;
  unsigned enumerationForeach_{0},enumerationCallbacks_{0},enumerationReads_{0},enumerationWrites_{0},enumerationCalls_{0},enumerationBranches_{0},enumerationTentative_{0};
  unsigned dispatchReads_{0},dispatchCalls_{0},dispatchChecks_{0},dispatchBranches_{0},dispatchTentative_{0};
  std::map<Instruction *,ResultObservation> ownReadObservations_;
  std::map<Instruction *,ResultObservation> ownCheckObservations_,ownDeleteObservations_;
  std::map<Instruction *,unsigned> deleteExecutions_;
  unsigned ownDeletes_{0},ownChecks_{0},ownReads_{0},ownBranches_{0},ownTentative_{0};
  unsigned functionWrites_{0},functionReads_{0},functionDeletes_{0},functionCalls_{0},callbackCalls_{0},functionTentative_{0};
  unsigned proxyCalls_{0},proxyTrapCalls_{0},proxyForwards_{0},proxyFallbacks_{0},proxyTentative_{0},proxyApplyWrites_{0},proxyBranches_{0};
  unsigned defineCalls_{0},definedWrites_{0},propertyTentative_{0};
  unsigned classOwnDefinitions_{0},classOwnWrites_{0},classOwnReads_{0},classOwnOverwrites_{0};
  unsigned setterWrites_{0},setterCalls_{0},metadataInstructions_{0};
  std::map<std::string,Datum> globals_;
  std::set<std::string> declaredGlobals_;
  std::set<Function *> active_;
  std::vector<Continuation> queue_;
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
  void putOwn(unsigned object,const std::string &name,const Datum &value) {
    nestedAliasSlots_.erase({object,name});freshGetters_.erase({object,name});
    auto &info=objects_[object];if(!info.fields.count(name))info.keyOrder.push_back(name);info.fields[name]=value;
  }
  void eraseOwn(unsigned object,const std::string &name) {
    nestedAliasSlots_.erase({object,name});freshGetters_.erase({object,name});
    auto &info=objects_[object];info.fields.erase(name);info.keyOrder.erase(std::remove(info.keyOrder.begin(),info.keyOrder.end(),name),info.keyOrder.end());
  }
  static bool primitive(const Datum &d) {return d.kind==Primitive||d.kind==Undefined||d.kind==Null;}
  static bool hostName(const std::string &n) {
    return n=="Date"||n=="document"||n=="Promise"||n=="Function"||n=="Object"||n=="Reflect"||n=="Symbol"||n=="String"||n=="Number"||n=="HermesES6Internal"||n=="Proxy";
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
      if(std::any_of(out.begin(),out.end(),[&](const Trace &o){return t.source==o.source&&t.origin==o.origin&&t.awaited==o.awaited&&t.setter==o.setter&&t.property==o.property&&t.module==o.module&&t.dynamic==o.dynamic&&t.proxy==o.proxy&&t.functionProperty==o.functionProperty&&t.descriptor==o.descriptor&&t.registry==o.registry&&t.ownState==o.ownState&&t.dispatch==o.dispatch&&t.enumeration==o.enumeration&&t.iteration==o.iteration&&t.deferredOwnReads==o.deferredOwnReads;}))continue;
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
    if(auto *str=llvh::dyn_cast<LiteralString>(v)){Datum d=make(Primitive);d.knownString=true;d.string=str->getValue().str().str();return d;}
    if(auto *n=llvh::dyn_cast<LiteralNumber>(v)){Datum d=make(Primitive);double x=n->getValue();
      d.truthKnown=true;d.truthValue=x!=0&&!std::isnan(x);
      if(std::isfinite(x)&&x>=-2147483647.0&&x<=2147483647.0&&std::floor(x)==x){d.knownInteger=true;d.integer=int64_t(x);}return d;}
    if(auto *b=llvh::dyn_cast<LiteralBool>(v)){Datum d=make(Primitive);d.knownBoolean=true;d.boolean=b->getValue();return d;}
    if(llvh::isa<LiteralEmpty>(v)&&nativeIterationPresent_)return make(Empty);
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
                                                                             
                                                                              
                                                                              
  bool recognizeSetter(Function *fn,SetterCertificate &cert) {
    if(fn->isLazy()||fn->empty()||fn->getParameters().size()!=3||
        fn->getBasicBlockList().size()!=4||llvh::isa<AsyncFunction>(fn)||
        llvh::isa<GeneratorFunction>(fn)||llvh::isa<GeneratorInnerFunction>(fn))return false;
    std::vector<Instruction *> x;for(auto &b:*fn)for(auto &i:b)x.push_back(&i);
    if(x.size()!=29)return false;
    auto *scope=llvh::dyn_cast<CreateScopeInst>(x[0]);
    if(!scope||scope->getCreatedScopeDesc()!=fn->getFunctionScopeDesc())return false;
    auto sf=[&](unsigned n,Value *v,Variable *var)->bool{
      auto *s=llvh::dyn_cast<StoreFrameInst>(x[n]);return s&&s->getValue()==v&&
        s->getVariable()==var&&s->getEnvironment()==scope&&var->getParent()==fn->getFunctionScopeDesc();};
    auto lf=[&](unsigned n,Variable *var)->bool{
      auto *l=llvh::dyn_cast<LoadFrameInst>(x[n]);return l&&l->getLoadVariable()==var&&l->getEnvironment()==scope;};
    std::vector<Variable *> vars;
    for(unsigned n=1;n<=4;++n){auto *s=llvh::dyn_cast<StoreFrameInst>(x[n]);if(!s)return false;vars.push_back(s->getVariable());}
    if(std::set<Variable *>(vars.begin(),vars.end()).size()!=4)return false;
    for(unsigned n=0;n<3;++n)if(!sf(n+1,fn->getParameters()[n],vars[n]))return false;
    auto *init=llvh::dyn_cast<StoreFrameInst>(x[4]);
    if(!llvh::isa<LiteralUndefined>(init->getValue())||!sf(4,init->getValue(),vars[3]))return false;
    auto *stack=llvh::dyn_cast<AllocStackInst>(x[5]);
    auto *save=llvh::dyn_cast<StoreStackInst>(x[7]);
    auto *cond=llvh::dyn_cast<CondBranchInst>(x[8]);
    auto *array=llvh::dyn_cast<AllocArrayInst>(x[9]);
    auto *saveArray=llvh::dyn_cast<StoreStackInst>(x[11]);
    auto *jump=llvh::dyn_cast<BranchInst>(x[12]);
    auto *reload=llvh::dyn_cast<LoadStackInst>(x[13]);
    if(!stack||!lf(6,vars[1])||!save||save->getValue()!=x[6]||save->getPtr()!=stack||
        !cond||cond->getCondition()!=x[6]||cond->getTrueDest()!=x[13]->getParent()||
        cond->getFalseDest()!=x[9]->getParent()||!array||array->getElementCount()!=0||
        array->getSizeHint()->getValue()!=0||!sf(10,array,vars[1])||!saveArray||
        saveArray->getValue()!=array||saveArray->getPtr()!=stack||!jump||
        jump->getBranchDest()!=x[13]->getParent()||!reload||reload->getPtr()!=stack||!lf(14,vars[1]))return false;
    auto *length=llvh::dyn_cast<LoadPropertyInst>(x[15]);
    auto *numeric=llvh::dyn_cast<AsNumericInst>(x[16]);
    auto *increment=llvh::dyn_cast<UnaryOperatorInst>(x[17]);
    auto *lengthWrite=llvh::dyn_cast<StorePropertyInst>(x[18]);
    if(!length||length->getObject()!=x[14]||key(length->getProperty())!="length"||!numeric||
        numeric->getSingleOperand()!=length||!increment||increment->getSingleOperand()!=numeric||
        increment->getOperatorKind()!=UnaryOperatorInst::OpKind::IncKind||!lengthWrite||
        lengthWrite->getObject()!=x[14]||key(lengthWrite->getProperty())!="length"||
        lengthWrite->getStoredValue()!=increment||!sf(19,numeric,vars[3]))return false;
    auto *object=llvh::dyn_cast<TryLoadGlobalPropertyInst>(x[20]);
    auto *define=llvh::dyn_cast<LoadPropertyInst>(x[21]);
    auto *fresh=llvh::dyn_cast<AllocObjectInst>(x[22]);
    auto *descriptor=llvh::dyn_cast<AllocObjectInst>(x[23]);
    auto *closure=llvh::dyn_cast<CreateFunctionInst>(x[24]);
    auto *set=llvh::dyn_cast<StoreNewOwnPropertyInst>(x[25]);
    auto *call=llvh::dyn_cast<CallInst>(x[26]);
    auto *ret=llvh::dyn_cast<ReturnInst>(x[27]);
    auto *dead=llvh::dyn_cast<ReturnInst>(x[28]);
    if(!object||!llvh::isa<GlobalObject>(object->getObject())||key(object->getProperty())!="Object"||
        !define||define->getObject()!=object||key(define->getProperty())!="defineProperty"||
        !fresh||!descriptor||!llvh::isa<EmptySentinel>(fresh->getParentObject())||
        !llvh::isa<EmptySentinel>(descriptor->getParentObject())||!closure||
        llvh::isa<CreateGeneratorInst>(closure)||closure->getEnvironment()!=scope||!set||
        set->getObject()!=descriptor||set->getStoredValue()!=closure||key(set->getProperty())!="set"||
        !set->getIsEnumerable()||!call||llvh::isa<ConstructInst>(call)||llvh::isa<CallBuiltinInst>(call)||
        call->getCallee()!=define||call->getNumArguments()!=4||
        !llvh::isa<LiteralUndefined>(call->getNewTarget())||call->getArgument(0)!=object||
        call->getArgument(1)!=fresh||key(call->getArgument(2))!="_"||call->getArgument(3)!=descriptor||
        !ret||ret->getValue()!=call||!dead||!llvh::isa<LiteralUndefined>(dead->getValue()))return false;
                                                                              
    for(unsigned n=0;n<29;++n){BasicBlock *expected=n<9?x[0]->getParent():n<13?x[9]->getParent():n<28?x[13]->getParent():x[28]->getParent();
      if(x[n]->getParent()!=expected)return false;}
    if(&fn->front()!=x[0]->getParent()||x[0]->getParent()->size()!=9||x[9]->getParent()->size()!=4||
        x[13]->getParent()->size()!=15||x[28]->getParent()->size()!=1)return false;
    Function *setter=closure->getFunctionCode();
    if(!setter||setter->isLazy()||setter->empty()||setter->getParameters().size()!=1||
        setter->getBasicBlockList().size()!=1||llvh::isa<AsyncFunction>(setter)||
        llvh::isa<GeneratorFunction>(setter)||llvh::isa<GeneratorInnerFunction>(setter))return false;
    std::vector<Instruction *> y;for(auto &i:setter->front())y.push_back(&i);
    if(y.size()!=12)return false;
    auto *innerScope=llvh::dyn_cast<CreateScopeInst>(y[0]);
    auto *formal=llvh::dyn_cast<StoreFrameInst>(y[1]);
    if(!innerScope||innerScope->getCreatedScopeDesc()!=setter->getFunctionScopeDesc()||!formal||
        formal->getEnvironment()!=innerScope||formal->getValue()!=setter->getParameters()[0]||
        formal->getVariable()->getParent()!=setter->getFunctionScopeDesc())return false;
    auto innerLoad=[&](unsigned n,Variable *var)->bool{auto *l=llvh::dyn_cast<LoadFrameInst>(y[n]);
      return l&&l->getLoadVariable()==var&&l->getEnvironment()==innerScope;};
    auto *write=llvh::dyn_cast<StorePropertyInst>(y[5]);
    auto *apply=llvh::dyn_cast<LoadPropertyInst>(y[7]);
    auto *invoke=llvh::dyn_cast<CallInst>(y[10]);
    auto *finish=llvh::dyn_cast<ReturnInst>(y[11]);
    if(!innerLoad(2,vars[1])||!innerLoad(3,vars[3])||!innerLoad(4,formal->getVariable())||
        !write||write->getStoredValue()!=y[4]||write->getObject()!=y[2]||write->getProperty()!=y[3]||
        !innerLoad(6,vars[0])||!apply||apply->getObject()!=y[6]||key(apply->getProperty())!="apply"||
        !innerLoad(8,vars[2])||!innerLoad(9,vars[1])||!invoke||llvh::isa<ConstructInst>(invoke)||
        llvh::isa<CallBuiltinInst>(invoke)||invoke->getCallee()!=apply||invoke->getNumArguments()!=3||
        !llvh::isa<LiteralUndefined>(invoke->getNewTarget())||invoke->getArgument(0)!=y[6]||
        invoke->getArgument(1)!=y[8]||invoke->getArgument(2)!=y[9]||!finish||
        !llvh::isa<LiteralUndefined>(finish->getValue()))return false;
                                                                           
    for(auto *u:closure->getUsers())if(u!=set)return false;
    cert.helper=fn;cert.setter=setter;cert.slotWrite=write;cert.apply=invoke;return true;
  }

  static bool plainFunction(Function *f,unsigned arity) {
    return f&&!f->isLazy()&&!f->empty()&&f->getParameters().size()==arity&&
      !llvh::isa<AsyncFunction>(f)&&!llvh::isa<GeneratorFunction>(f)&&!llvh::isa<GeneratorInnerFunction>(f);
  }
  static bool loadFrameIs(Instruction *i,Variable *v,Value *env) {
    auto *l=llvh::dyn_cast<LoadFrameInst>(i);return l&&l->getLoadVariable()==v&&l->getEnvironment()==env;
  }
  static bool storeFrameIs(Instruction *i,Value *v,Variable *var,Value *env) {
    auto *s=llvh::dyn_cast<StoreFrameInst>(i);return s&&s->getValue()==v&&s->getVariable()==var&&s->getEnvironment()==env;
  }
  bool closedBindingShape(Instruction *i,Function *f,CreateScopeInst *scope) {
    if(auto *l=llvh::dyn_cast<LoadPropertyInst>(i))return llvh::isa<GlobalObject>(l->getObject())&&!key(l->getProperty()).empty();
    if(auto *l=llvh::dyn_cast<LoadFrameInst>(i))return l->getEnvironment()==scope&&l->getLoadVariable()->getParent()!=f->getFunctionScopeDesc();
    return false;
  }
  static bool phiIs(PhiInst *p,Value *a,BasicBlock *ab,Value *b,BasicBlock *bb) {
    if(!p||p->getNumEntries()!=2)return false;
    auto x=p->getEntry(0),y=p->getEntry(1);
    return (x.first==a&&x.second==ab&&y.first==b&&y.second==bb)||
      (y.first==a&&y.second==ab&&x.first==b&&x.second==bb);
  }
  bool recognizeProperty(Function *fn,PropertyCertificate &cert) {
    if(!plainFunction(fn,3)||fn->getBasicBlockList().size()!=5)return false;
    std::vector<Instruction *> x;for(auto &b:*fn)for(auto &i:b){x.push_back(&i);if(x.size()>35)return false;}
    if(x.size()!=35)return false;
    auto *scope=llvh::dyn_cast<CreateScopeInst>(x[0]);
    if(!scope||scope->getCreatedScopeDesc()!=fn->getFunctionScopeDesc())return false;
    Variable *vars[3];
    for(unsigned n=0;n<3;++n){auto *s=llvh::dyn_cast<StoreFrameInst>(x[n+1]);
      if(!s||s->getVariable()->getParent()!=fn->getFunctionScopeDesc()||
          !storeFrameIs(s,fn->getParameters()[n],s->getVariable(),scope))return false;vars[n]=s->getVariable();}
    if(std::set<Variable *>(vars,vars+3).size()!=3||!closedBindingShape(x[4],fn,scope)||!loadFrameIs(x[5],vars[1],scope))return false;
    auto *convert=llvh::dyn_cast<CallInst>(x[6]);
    if(!convert||llvh::isa<ConstructInst>(convert)||llvh::isa<CallBuiltinInst>(convert)||convert->getCallee()!=x[4]||
        convert->getNumArguments()!=2||!llvh::isa<LiteralUndefined>(convert->getNewTarget())||
        !llvh::isa<LiteralUndefined>(convert->getArgument(0))||convert->getArgument(1)!=x[5]||
        !storeFrameIs(x[7],convert,vars[1],scope)||!loadFrameIs(x[8],vars[0],scope))return false;
    auto *in=llvh::dyn_cast<BinaryOperatorInst>(x[9]);auto *cond=llvh::dyn_cast<CondBranchInst>(x[10]);
    if(!in||in->getOperatorKind()!=BinaryOperatorInst::OpKind::InKind||in->getLeftHandSide()!=convert||
        in->getRightHandSide()!=x[8]||!cond||cond->getCondition()!=in||cond->getTrueDest()!=x[16]->getParent()||
        cond->getFalseDest()!=x[11]->getParent()||!loadFrameIs(x[11],vars[0],scope)||!loadFrameIs(x[12],vars[1],scope)||
        !loadFrameIs(x[13],vars[2],scope))return false;
    auto *write=llvh::dyn_cast<StorePropertyInst>(x[14]);auto *jump=llvh::dyn_cast<BranchInst>(x[15]);
    if(!write||write->getObject()!=x[11]||write->getProperty()!=x[12]||write->getStoredValue()!=x[13]||
        !jump||jump->getBranchDest()!=x[31]->getParent())return false;
    auto *object=llvh::dyn_cast<TryLoadGlobalPropertyInst>(x[16]);auto *define=llvh::dyn_cast<LoadPropertyInst>(x[17]);
    auto *descriptor=llvh::dyn_cast<AllocObjectInst>(x[20]);auto *field=llvh::dyn_cast<StoreNewOwnPropertyInst>(x[22]);
    if(!object||!llvh::isa<GlobalObject>(object->getObject())||key(object->getProperty())!="Object"||
        !define||define->getObject()!=object||key(define->getProperty())!="defineProperty"||
        !loadFrameIs(x[18],vars[0],scope)||!loadFrameIs(x[19],vars[1],scope)||!descriptor||
        !llvh::isa<EmptySentinel>(descriptor->getParentObject())||!loadFrameIs(x[21],vars[2],scope)||
        !field||field->getObject()!=descriptor||field->getStoredValue()!=x[21]||
        key(field->getProperty())!="value"||!field->getIsEnumerable())return false;
    const char *names[]={"enumerable","configurable","writable"};
    for(unsigned n=0;n<3;++n){auto *u=llvh::dyn_cast<UnaryOperatorInst>(x[23+n*2]);
      auto *s=llvh::dyn_cast<StoreNewOwnPropertyInst>(x[24+n*2]);
      auto *zero=u?llvh::dyn_cast<LiteralNumber>(u->getSingleOperand()):nullptr;
      if(!u||!zero||zero->getValue()!=0||u->getOperatorKind()!=UnaryOperatorInst::OpKind::BangKind||
          !s||s->getObject()!=descriptor||s->getStoredValue()!=u||key(s->getProperty())!=names[n]||!s->getIsEnumerable())return false;}
    auto *call=llvh::dyn_cast<CallInst>(x[29]);auto *join=llvh::dyn_cast<BranchInst>(x[30]);
    auto *phi=llvh::dyn_cast<PhiInst>(x[31]);auto *ret=llvh::dyn_cast<ReturnInst>(x[33]);auto *dead=llvh::dyn_cast<ReturnInst>(x[34]);
    if(!call||llvh::isa<ConstructInst>(call)||llvh::isa<CallBuiltinInst>(call)||call->getCallee()!=define||
        call->getNumArguments()!=4||!llvh::isa<LiteralUndefined>(call->getNewTarget())||call->getArgument(0)!=object||
        call->getArgument(1)!=x[18]||call->getArgument(2)!=x[19]||call->getArgument(3)!=descriptor||
        !join||join->getBranchDest()!=x[31]->getParent()||!phiIs(phi,call,x[16]->getParent(),x[13],x[11]->getParent())||
        !loadFrameIs(x[32],vars[0],scope)||!ret||ret->getValue()!=x[32]||!dead||!llvh::isa<LiteralUndefined>(dead->getValue()))return false;
    unsigned starts[]={0,11,16,31,34},sizes[]={11,5,15,3,1};
    for(unsigned b=0;b<5;++b){if(x[starts[b]]->getParent()->size()!=sizes[b])return false;
      for(unsigned n=starts[b];n<starts[b]+sizes[b];++n)if(x[n]->getParent()!=x[starts[b]]->getParent())return false;}
    if(&fn->front()!=x[0]->getParent())return false;
    cert.helper=fn;cert.keyBinding=x[4];cert.keyCall=convert;cert.defineCall=call;cert.store=write;cert.returned=ret;return true;
  }
  bool recognizeKey(Function *fn,KeyCertificate &cert) {
    if(!plainFunction(fn,1)||fn->getBasicBlockList().size()!=5)return false;
    std::vector<Instruction *> x;for(auto &b:*fn)for(auto &i:b){x.push_back(&i);if(x.size()>19)return false;}
    if(x.size()!=19)return false;
    auto *scope=llvh::dyn_cast<CreateScopeInst>(x[0]);auto *formal=llvh::dyn_cast<StoreFrameInst>(x[1]);
    auto *init=llvh::dyn_cast<StoreFrameInst>(x[2]);
    if(!scope||scope->getCreatedScopeDesc()!=fn->getFunctionScopeDesc()||!formal||!init||
        formal->getVariable()->getParent()!=fn->getFunctionScopeDesc()||init->getVariable()->getParent()!=fn->getFunctionScopeDesc()||
        formal->getVariable()==init->getVariable()||!storeFrameIs(formal,fn->getParameters()[0],formal->getVariable(),scope)||
        !llvh::isa<LiteralUndefined>(init->getValue())||!storeFrameIs(init,init->getValue(),init->getVariable(),scope)||
        !closedBindingShape(x[3],fn,scope)||!loadFrameIs(x[4],formal->getVariable(),scope))return false;
    auto *call=llvh::dyn_cast<CallInst>(x[5]);
    if(!call||llvh::isa<ConstructInst>(call)||llvh::isa<CallBuiltinInst>(call)||call->getCallee()!=x[3]||call->getNumArguments()!=3||
        !llvh::isa<LiteralUndefined>(call->getNewTarget())||!llvh::isa<LiteralUndefined>(call->getArgument(0))||
        call->getArgument(1)!=x[4]||key(call->getArgument(2))!="string"||!storeFrameIs(x[6],call,init->getVariable(),scope)||
        !loadFrameIs(x[7],init->getVariable(),scope))return false;
    auto *type=llvh::dyn_cast<UnaryOperatorInst>(x[8]);auto *compare=llvh::dyn_cast<BinaryOperatorInst>(x[9]);
    auto *branch=llvh::dyn_cast<CondBranchInst>(x[10]);auto *add=llvh::dyn_cast<BinaryOperatorInst>(x[12]);
    auto *left=llvh::dyn_cast<BranchInst>(x[13]);auto *right=llvh::dyn_cast<BranchInst>(x[15]);
    auto *phi=llvh::dyn_cast<PhiInst>(x[16]);auto *ret=llvh::dyn_cast<ReturnInst>(x[17]);auto *dead=llvh::dyn_cast<ReturnInst>(x[18]);
    auto *empty=add?llvh::dyn_cast<LiteralString>(add->getRightHandSide()):nullptr;
    if(!type||type->getOperatorKind()!=UnaryOperatorInst::OpKind::TypeofKind||type->getSingleOperand()!=x[7]||
        !compare||compare->getOperatorKind()!=BinaryOperatorInst::OpKind::EqualKind||key(compare->getLeftHandSide())!="symbol"||
        compare->getRightHandSide()!=type||!branch||branch->getCondition()!=compare||
        branch->getTrueDest()!=x[14]->getParent()||branch->getFalseDest()!=x[11]->getParent()||
        !loadFrameIs(x[11],init->getVariable(),scope)||!add||add->getOperatorKind()!=BinaryOperatorInst::OpKind::AddKind||
        add->getLeftHandSide()!=x[11]||!empty||!empty->getValue().str().empty()||!left||left->getBranchDest()!=x[16]->getParent()||
        !loadFrameIs(x[14],init->getVariable(),scope)||!right||right->getBranchDest()!=x[16]->getParent()||
        !phiIs(phi,x[14],x[14]->getParent(),add,x[11]->getParent())||!ret||ret->getValue()!=phi||!dead||!llvh::isa<LiteralUndefined>(dead->getValue()))return false;
    unsigned starts[]={0,11,14,16,18},sizes[]={11,3,2,2,1};
    for(unsigned b=0;b<5;++b){if(x[starts[b]]->getParent()->size()!=sizes[b])return false;
      for(unsigned n=starts[b];n<starts[b]+sizes[b];++n)if(x[n]->getParent()!=x[starts[b]]->getParent())return false;}
    if(&fn->front()!=x[0]->getParent())return false;
    cert.helper=fn;cert.primitiveBinding=x[3];cert.call=call;return true;
  }
  bool recognizePrimitiveString(Function *fn) {
                                                                           
                                                                   
    if(!plainFunction(fn,2)||fn->front().size()!=9)return false;
    std::vector<Instruction *> x;for(auto &i:fn->front())x.push_back(&i);
    auto *scope=llvh::dyn_cast<CreateScopeInst>(x[0]);if(!scope||scope->getCreatedScopeDesc()!=fn->getFunctionScopeDesc())return false;
    Variable *vars[4];for(unsigned n=0;n<4;++n){auto *s=llvh::dyn_cast<StoreFrameInst>(x[n+1]);
      if(!s||s->getVariable()->getParent()!=fn->getFunctionScopeDesc()||s->getEnvironment()!=scope)return false;vars[n]=s->getVariable();
      if(n<2){if(s->getValue()!=fn->getParameters()[n])return false;}else if(!llvh::isa<LiteralUndefined>(s->getValue()))return false;}
    if(std::set<Variable *>(vars,vars+4).size()!=4||!loadFrameIs(x[5],vars[0],scope))return false;
    auto *type=llvh::dyn_cast<UnaryOperatorInst>(x[6]);auto *compare=llvh::dyn_cast<BinaryOperatorInst>(x[7]);auto *branch=llvh::dyn_cast<CondBranchInst>(x[8]);
    if(!type||type->getOperatorKind()!=UnaryOperatorInst::OpKind::TypeofKind||type->getSingleOperand()!=x[5]||
        !compare||compare->getOperatorKind()!=BinaryOperatorInst::OpKind::NotEqualKind||key(compare->getLeftHandSide())!="object"||
        compare->getRightHandSide()!=type||!branch||branch->getCondition()!=compare||branch->getTrueDest()==branch->getFalseDest()||
        branch->getTrueDest()->getParent()!=fn||branch->getTrueDest()->size()!=2)return false;
    auto it=branch->getTrueDest()->begin();Instruction *loaded=&*it++;auto *ret=llvh::dyn_cast<ReturnInst>(&*it);
    return loadFrameIs(loaded,vars[0],scope)&&ret&&ret->getValue()==loaded;
  }
  Datum resolveHelperBinding(Instruction *load,unsigned environment,Instruction *at) {
    if(auto *l=llvh::dyn_cast<LoadPropertyInst>(load)){
      if(!llvh::isa<GlobalObject>(l->getObject()))return reject("HELPER_BINDING_NOT_GLOBAL",at);
      return globalRead(key(l->getProperty()),load);
    }
    auto *l=llvh::dyn_cast<LoadFrameInst>(load);if(!l)return reject("HELPER_BINDING_KIND",at);
    for(unsigned n=environment;n;n=environments_[n].parent){auto &e=environments_[n];
      if(e.descriptor!=l->getLoadVariable()->getParent())continue;
      auto found=e.vars.find(l->getLoadVariable());if(found==e.vars.end())return reject("HELPER_BINDING_UNINITIALIZED",at);
      return found->second;}
    return reject("HELPER_BINDING_ENVIRONMENT",at);
  }
  static bool safeDataKey(const std::string &name) {
    return !name.empty()&&name.size()<=256&&name!="__proto__"&&name!="prototype"&&name!="constructor"&&
      name!="__defineGetter__"&&name!="__defineSetter__"&&name!="__lookupGetter__"&&name!="__lookupSetter__"&&
      name!="hasOwnProperty"&&name!="isPrototypeOf"&&name!="propertyIsEnumerable"&&name!="toLocaleString"&&
      name!="toString"&&name!="valueOf"&&name!="then";
  }
  static std::string keyHex(const std::string &name) {
    static const char *digits="0123456789abcdef";std::string out;
    for(unsigned char c:name){out.push_back(digits[c>>4]);out.push_back(digits[c&15]);}return out;
  }
  static bool sameClosedBinding(Instruction *a,Instruction *b) {
    auto *x=llvh::dyn_cast<LoadFrameInst>(a),*y=llvh::dyn_cast<LoadFrameInst>(b);
    if(x&&y)return x->getLoadVariable()==y->getLoadVariable();
    auto *p=llvh::dyn_cast<LoadPropertyInst>(a),*q=llvh::dyn_cast<LoadPropertyInst>(b);
    return p&&q&&llvh::isa<GlobalObject>(p->getObject())&&llvh::isa<GlobalObject>(q->getObject())&&
      !key(p->getProperty()).empty()&&key(p->getProperty())==key(q->getProperty());
  }
  AllocObjectInst *bindingAllocation(Instruction *load) {
    auto *frame=llvh::dyn_cast<LoadFrameInst>(load);auto *global=llvh::dyn_cast<LoadPropertyInst>(load);
    if(!frame&&(!global||!llvh::isa<GlobalObject>(global->getObject())))return nullptr;
    AllocObjectInst *allocation=nullptr;unsigned writes=0;
    for(auto &fn:*module_)for(auto &bb:fn)for(auto &i:bb){Value *stored=nullptr;
      if(frame){auto *s=llvh::dyn_cast<StoreFrameInst>(&i);if(s&&s->getVariable()==frame->getLoadVariable())stored=s->getValue();}
      else {auto *s=llvh::dyn_cast<StorePropertyInst>(&i);if(s&&llvh::isa<GlobalObject>(s->getObject())&&key(s->getProperty())==key(global->getProperty()))stored=s->getStoredValue();}
      if(!stored||llvh::isa<LiteralUndefined>(stored))continue;
      if(++writes!=1)return nullptr;allocation=llvh::dyn_cast<AllocObjectInst>(stored);if(!allocation)return nullptr;
    }
    return writes==1?allocation:nullptr;
  }
  bool recognizeModule(Function *fn,ModuleCertificate &cert) {
    if(!plainFunction(fn,1)||fn->getDefinitionKind()!=Function::DefinitionKind::ES5Function||
        fn->getBasicBlockList().size()!=6)return false;
    std::vector<Instruction *> x;for(auto &b:*fn)for(auto &i:b){x.push_back(&i);if(x.size()>39)return false;}
    if(x.size()!=36&&x.size()!=39)return false;bool viaCall=x.size()==39;
    auto *scope=llvh::dyn_cast<CreateScopeInst>(x[0]);
    auto *arg=llvh::dyn_cast<StoreFrameInst>(x[1]),*cached=llvh::dyn_cast<StoreFrameInst>(x[2]),*record=llvh::dyn_cast<StoreFrameInst>(x[3]);
    if(!scope||scope->getCreatedScopeDesc()!=fn->getFunctionScopeDesc()||!arg||!cached||!record)return false;
    Variable *av=arg->getVariable(),*cv=cached->getVariable(),*mv=record->getVariable();
    if(av==cv||av==mv||cv==mv||av->getParent()!=fn->getFunctionScopeDesc()||cv->getParent()!=fn->getFunctionScopeDesc()||mv->getParent()!=fn->getFunctionScopeDesc()||
        !storeFrameIs(x[1],fn->getParameters()[0],av,scope)||!llvh::isa<LiteralUndefined>(cached->getValue())||
        !storeFrameIs(x[2],cached->getValue(),cv,scope)||!llvh::isa<LiteralUndefined>(record->getValue())||!storeFrameIs(x[3],record->getValue(),mv,scope))return false;
    auto lp=[&](unsigned n,Value *o,Value *p)->bool{auto *l=llvh::dyn_cast<LoadPropertyInst>(x[n]);return l&&l->getObject()==o&&l->getProperty()==p;};
    auto named=[&](unsigned n,Value *o,const char *p)->bool{auto *l=llvh::dyn_cast<LoadPropertyInst>(x[n]);return l&&l->getObject()==o&&key(l->getProperty())==p;};
    auto *voided=llvh::dyn_cast<UnaryOperatorInst>(x[8]);auto *zero=voided?llvh::dyn_cast<LiteralNumber>(voided->getSingleOperand()):nullptr;
    auto *compare=llvh::dyn_cast<BinaryOperatorInst>(x[10]);auto *condition=llvh::dyn_cast<CondBranchInst>(x[11]);
    auto *hit=llvh::dyn_cast<ReturnInst>(x[14]);auto *jump=llvh::dyn_cast<BranchInst>(x[15]);
    if(!closedBindingShape(x[4],fn,scope)||!loadFrameIs(x[5],av,scope)||!lp(6,x[4],x[5])||!storeFrameIs(x[7],x[6],cv,scope)||
        !voided||voided->getOperatorKind()!=UnaryOperatorInst::OpKind::VoidKind||!zero||zero->getValue()!=0||!loadFrameIs(x[9],cv,scope)||
        !compare||compare->getOperatorKind()!=BinaryOperatorInst::OpKind::StrictlyNotEqualKind||compare->getLeftHandSide()!=x[8]||compare->getRightHandSide()!=x[9]||
        !condition||condition->getCondition()!=x[10]||condition->getTrueDest()!=x[12]->getParent()||condition->getFalseDest()!=x[15]->getParent()||
        !loadFrameIs(x[12],cv,scope)||!named(13,x[12],"exports")||!hit||hit->getValue()!=x[13]||!jump||jump->getBranchDest()!=x[16]->getParent())return false;
    auto *module=llvh::dyn_cast<AllocObjectInst>(x[18]),*exports=llvh::dyn_cast<AllocObjectInst>(x[19]);
    auto *own=llvh::dyn_cast<StoreNewOwnPropertyInst>(x[20]);auto *write=llvh::dyn_cast<StorePropertyInst>(x[21]);
    if(!closedBindingShape(x[16],fn,scope)||!sameClosedBinding(x[4],x[16])||!loadFrameIs(x[17],av,scope)||!module||!exports||
        !llvh::isa<EmptySentinel>(module->getParentObject())||!llvh::isa<EmptySentinel>(exports->getParentObject())||!own||own->getObject()!=module||
        own->getStoredValue()!=exports||key(own->getProperty())!="exports"||!own->getIsEnumerable()||!write||write->getObject()!=x[16]||
        write->getProperty()!=x[17]||write->getStoredValue()!=module||!storeFrameIs(x[22],module,mv,scope)||
        !closedBindingShape(x[23],fn,scope)||sameClosedBinding(x[4],x[23])||!loadFrameIs(x[24],av,scope)||!lp(25,x[23],x[24]))return false;
    unsigned dispatch=viaCall?33:30,self=viaCall?32:29,tail=dispatch+1;
    auto *call=llvh::dyn_cast<CallInst>(x[dispatch]);auto *returned=llvh::dyn_cast<ReturnInst>(x[tail+2]);
    if(!call||llvh::isa<ConstructInst>(call)||llvh::isa<CallBuiltinInst>(call)||!llvh::isa<LiteralUndefined>(call->getNewTarget())||
        !closedBindingShape(x[self],fn,scope)||!loadFrameIs(x[tail],mv,scope)||!named(tail+1,x[tail],"exports")||!returned||returned->getValue()!=x[tail+1])return false;
    if(!viaCall){if(!loadFrameIs(x[26],mv,scope)||!loadFrameIs(x[27],mv,scope)||!named(28,x[27],"exports")||
        call->getCallee()!=x[25]||call->getNumArguments()!=4||call->getArgument(0)!=x[23]||call->getArgument(1)!=x[26]||call->getArgument(2)!=x[28]||call->getArgument(3)!=x[self])return false;}
    else {if(!named(26,x[25],"call")||!loadFrameIs(x[27],mv,scope)||!named(28,x[27],"exports")||!loadFrameIs(x[29],mv,scope)||
        !loadFrameIs(x[30],mv,scope)||!named(31,x[30],"exports")||call->getCallee()!=x[26]||call->getNumArguments()!=5||
        call->getArgument(0)!=x[25]||call->getArgument(1)!=x[28]||call->getArgument(2)!=x[29]||call->getArgument(3)!=x[31]||call->getArgument(4)!=x[self])return false;}
    auto *deadJump=llvh::dyn_cast<BranchInst>(x[tail+3]);auto *dead=llvh::dyn_cast<ReturnInst>(x[tail+4]);
    if(!deadJump||deadJump->getBranchDest()!=x[16]->getParent()||!dead||!llvh::isa<LiteralUndefined>(dead->getValue()))return false;
    for(unsigned n=0;n<x.size();++n){BasicBlock *expected=n<12?x[0]->getParent():n<15?x[12]->getParent():n<16?x[15]->getParent():n<tail+3?x[16]->getParent():n<tail+4?x[tail+3]->getParent():x[tail+4]->getParent();
      if(x[n]->getParent()!=expected)return false;}
    if(&fn->front()!=x[0]->getParent()||x[0]->getParent()->size()!=12||x[12]->getParent()->size()!=3||x[15]->getParent()->size()!=1||
        x[16]->getParent()->size()!=(viaCall?21:18)||x[tail+3]->getParent()->size()!=1||x[tail+4]->getParent()->size()!=1)return false;
    auto *cache= bindingAllocation(x[4]),*registry=bindingAllocation(x[23]);if(!cache||!registry||cache==registry)return false;
    cert.function=fn;cert.cacheBinding=x[4];cert.registryBinding=x[23];cert.selfBinding=x[self];cert.cacheAllocation=cache;
    cert.registryAllocation=registry;cert.cacheWrite=write;cert.dispatch=call;cert.returned=returned;cert.viaCall=viaCall;return true;
  }
  static bool moduleKey(const Datum &d,std::string &out) {
    if(!d.traces.empty())return false;
    if(d.knownString)out=d.string;else if(d.knownInteger)out=std::to_string(d.integer);else return false;
    return out.size()<=64&&safeDataKey(out);
  }
  void moduleEdge(Datum &d,Instruction *at) {for(auto &t:d.traces)t.module=true;edge(d,at);}
  void registryEdge(Datum &d,Instruction *at) {for(auto &t:d.traces)t.registry=true;edge(d,at);}
  void ownStateEdge(Datum &d,Instruction *at) {for(auto &t:d.traces)t.ownState=true;edge(d,at);}
  void dispatchEdge(Datum &d,Instruction *at) {for(auto &t:d.traces)t.dispatch=true;edge(d,at);}
  void enumerationEdge(Datum &d,Instruction *at) {for(auto &t:d.traces)t.enumeration=true;edge(d,at);}
  void dynamicEdge(Datum &d,Instruction *at) {for(auto &t:d.traces)t.dynamic=true;edge(d,at);}
  void proxyEdge(Datum &d,Instruction *at) {for(auto &t:d.traces)t.proxy=true;edge(d,at);}
  void functionEdge(Datum &d,Instruction *at) {for(auto &t:d.traces)t.functionProperty=true;edge(d,at);}
  static bool functionDataKey(const Datum &value,std::string &name) {
    return dataKey(value,name)&&name!="name"&&name!="length"&&name!="arguments"&&name!="caller"&&name!="bind";
  }
  bool formalFeedsCallback(Function *fn,unsigned index) {
    if(index>=fn->getParameters().size())return false;
    for(auto &bb:*fn)for(auto &i:bb){auto *call=llvh::dyn_cast<CallInst>(&i);
      if(!call||llvh::isa<ConstructInst>(call)||llvh::isa<CallBuiltinInst>(call))continue;
      auto *load=llvh::dyn_cast<LoadFrameInst>(call->getCallee());if(!load)continue;
      for(auto &block:*fn)for(auto &inst:block){auto *store=llvh::dyn_cast<StoreFrameInst>(&inst);
        if(store&&store->getVariable()==load->getLoadVariable()&&store->getValue()==fn->getParameters()[index])return true;}
    }
    return false;
  }
  bool formalFeedsFunctionReceiver(Function *fn,unsigned index) {
    if(index>=fn->getParameters().size())return false;
    for(auto &bb:*fn)for(auto &i:bb){Value *object=nullptr;
      if(auto *s=llvh::dyn_cast<StorePropertyInst>(&i))object=s->getObject();
      if(auto *l=llvh::dyn_cast<LoadPropertyInst>(&i))object=l->getObject();
      if(auto *d=llvh::dyn_cast<DeletePropertyInst>(&i))object=d->getObject();
      auto *load=llvh::dyn_cast_or_null<LoadFrameInst>(object);if(!load)continue;
      for(auto &block:*fn)for(auto &inst:block){auto *store=llvh::dyn_cast<StoreFrameInst>(&inst);
        if(store&&store->getVariable()==load->getLoadVariable()&&store->getValue()==fn->getParameters()[index])return true;}
    }
    return false;
  }

                                                                             
                                                                                 
  bool exactClassOwnReceiver(const Datum &d) {
    if(d.kind!=Closure)return false;
    auto found=closures_.find(d.ref);if(found==closures_.end())return false;
    const auto &c=found->second;
    return c.isClass&&c.exactBaseClassOwnState&&!c.methodOwner&&c.creation&&c.function&&
      !c.function->isLazy()&&!c.function->empty()&&c.environment&&
      !llvh::isa<AsyncFunction>(c.function)&&!llvh::isa<GeneratorFunction>(c.function)&&
      !llvh::isa<GeneratorInnerFunction>(c.function);
  }
  static bool classOwnKey(const Datum &property,std::string &name) {
    if(!property.knownString||!property.traces.empty())return false;
    name=property.string;
    return safeDataKey(name)&&name!="name"&&name!="length"&&name!="arguments"&&
      name!="caller"&&name!="call"&&name!="apply"&&name!="bind";
  }
  Datum classOwnWrite(Datum object,Datum property,Datum stored,Instruction *at,bool definition) {
    std::string name;
    if(!exactClassOwnReceiver(object)||!classOwnKey(property,name)||!primitive(stored)||
        suspended_||classOwnWrites_>=64)return reject("CLASS_OWN_WRITE_OUTSIDE_PROFILE",at);
    auto &ctor=closures_[object.ref];auto found=ctor.ownFields.find(name);
                                                                             
                                                                               
    if((!definition&&found==ctor.ownFields.end())||ctor.methods.count(name))
      return reject("CLASS_OWN_WRITE_NOT_EXISTING_DATA_OR_METHOD_COLLISION",at);
    if(found!=ctor.ownFields.end()&&!primitive(found->second))
      return reject("CLASS_OWN_PRIOR_DESCRIPTOR_OR_VALUE_UNKNOWN",at);
    bool replacing=found!=ctor.ownFields.end();
    edge(stored,at);for(auto &trace:stored.traces)trace.property=true;
                                                                       
    ctor.ownFields[name]=stored;++classOwnWrites_;if(replacing)++classOwnOverwrites_;
    llvh::outs()<<"[CLASS_OWN_WRITE] closure="<<object.ref<<" environment="<<ctor.environment
      <<" key_hex="<<keyHex(name)<<" definition="<<(definition?1:0)<<" replacing="<<(replacing?1:0)
      <<" source_traces="<<stored.traces.size()<<" write="<<id(at)<<"\n";
    return make(Undefined);
  }
  Datum classOwnRead(Datum object,Datum property,LoadPropertyInst *at) {
    std::string name;
    if(!exactClassOwnReceiver(object)||!classOwnKey(property,name)||suspended_||classOwnReads_>=128)
      return reject("CLASS_OWN_READ_OUTSIDE_PROFILE",at);
    auto &ctor=closures_[object.ref];auto found=ctor.ownFields.find(name);
                                                                                    
    if(found==ctor.ownFields.end()||!primitive(found->second)||ctor.methods.count(name))
      return reject("CLASS_OWN_READ_NOT_PROVED_DATA",at);
    Datum d=found->second;edge(d,at);++classOwnReads_;
    llvh::outs()<<"[CLASS_OWN_READ] closure="<<object.ref<<" environment="<<ctor.environment
      <<" key_hex="<<keyHex(name)<<" source_traces="<<d.traces.size()<<" read="<<id(at)<<"\n";
    return d;
  }

  Datum functionStore(Datum object,Datum property,Datum stored,Instruction *at) {
    std::string name;
    if(stored.kind==Record&&registryObjects_.count(stored.ref)){
      if(registryAliases_>=64||!functionDataKey(property,name)||registryOwner(stored.ref,at)!=object.ref||object.kind!=Closure||
          !moduleCertificates_.count(closures_[object.ref].function))return reject("REGISTRY_ALIAS_NOT_OWN_LOADER_TABLE",at);
      closures_[object.ref].ownFields[name]=stored;++registryAliases_;
      llvh::outs()<<"[MODULE_REGISTRY_ALIAS] event="<<registryAliases_<<" loader="<<object.ref<<" environment="<<closures_[object.ref].environment
        <<" registry="<<stored.ref<<" key_hex="<<keyHex(name)<<" write="<<id(at)<<"\n";return make(Undefined);
    }
    if(!ordinaryDataClosure(object)||!functionDataKey(property,name)||(!primitive(stored)&&!ordinaryDataClosure(stored))||functionWrites_>=128)
      return reject("FUNCTION_OWN_WRITE_OUTSIDE_PROFILE",at);
    auto &fields=closures_[object.ref].ownFields;auto prior=fields.find(name);
    unsigned oldKind=prior==fields.end()?unsigned(Invalid):unsigned(prior->second.kind),oldRef=prior==fields.end()?0:prior->second.ref;
    if(stored.kind==Closure)stored.functionProperty=true;
    functionEdge(stored,at);fields[name]=stored;functionObjects_.insert(object.ref);++functionWrites_;
    llvh::outs()<<"[FUNCTION_PROPERTY_WRITE] event="<<functionWrites_<<" function="<<object.ref<<" environment="<<closures_[object.ref].environment
      <<" key_hex="<<keyHex(name)<<" old_kind="<<oldKind<<" old_ref="<<oldRef<<" new_kind="<<unsigned(stored.kind)<<" new_ref="<<stored.ref
      <<" source_traces="<<stored.traces.size()<<" write="<<id(at)<<"\n";
    return make(Undefined);
  }
  Datum functionRead(Datum object,Datum property,LoadPropertyInst *at) {
    std::string name;if(!ordinaryDataClosure(object)||!functionDataKey(property,name)||functionReads_>=256)
      return reject("FUNCTION_OWN_READ_OUTSIDE_PROFILE",at);
    auto &fields=closures_[object.ref].ownFields;auto found=fields.find(name);bool present=found!=fields.end();
    Datum d=present?found->second:make(Undefined);if(d.kind==Closure)d.functionProperty=true;
    if(d.kind==Record){
      if(!registryObjects_.count(d.ref)||registryOwner(d.ref,at)!=object.ref)return reject("REGISTRY_ALIAS_READ_IDENTITY",at);
      edge(d,at);return d;
    }
    functionEdge(d,at);observeResult(functionReadObservations_[at],d);functionObjects_.insert(object.ref);++functionReads_;
    llvh::outs()<<"[FUNCTION_PROPERTY_READ] event="<<functionReads_<<" function="<<object.ref<<" environment="<<closures_[object.ref].environment
      <<" key_hex="<<keyHex(name)<<" present="<<(present?1:0)<<" value_kind="<<unsigned(d.kind)<<" value_ref="<<d.ref
      <<" source_traces="<<d.traces.size()<<" read="<<id(at)<<"\n";
    return d;
  }
  Datum functionDelete(DeletePropertyInst *at,Frame &f) {
    Datum object=value(at->getObject(),f,at),property=value(at->getProperty(),f,at);std::string name;
    if(!functionDeleteCandidates_.count(at)||!ordinaryDataClosure(object)||!functionDataKey(property,name)||functionDeletes_>=128)
      return reject("FUNCTION_OWN_DELETE_OUTSIDE_PROFILE",at);
    auto &fields=closures_[object.ref].ownFields;bool existed=fields.erase(name)!=0;functionObjects_.insert(object.ref);++functionDeletes_;
    llvh::outs()<<"[FUNCTION_PROPERTY_DELETE] event="<<functionDeletes_<<" function="<<object.ref<<" environment="<<closures_[object.ref].environment
      <<" key_hex="<<keyHex(name)<<" existed="<<(existed?1:0)<<" result=true delete="<<id(at)<<"\n";
    Datum out=make(Primitive);out.knownBoolean=true;out.boolean=true;return out;
  }
  void observeResult(ResultObservation &observation,const Datum &value) {
    ++observation.count;observation.allPrimitive=observation.allPrimitive&&primitive(value);
    for(auto &trace:value.traces)observation.sources.insert(trace.source);
  }
                                                                          
                                                                               
                                                                              
                                                                              
  bool directResultUse(Instruction *call,Instruction *consumer) {
    if(!consumer||consumer->getParent()->getParent()!=call->getParent()->getParent())return false;
    if(auto *b=llvh::dyn_cast<BinaryOperatorInst>(consumer))return b->getOperatorKind()==BinaryOperatorInst::OpKind::AddKind&&
      (b->getLeftHandSide()==call||b->getRightHandSide()==call);
    if(auto *s=llvh::dyn_cast<StoreFrameInst>(consumer))return s->getValue()==call;
    if(auto *s=llvh::dyn_cast<StoreStackInst>(consumer))return s->getValue()==call;
    if(auto *s=llvh::dyn_cast<StorePropertyInst>(consumer))return s->getStoredValue()==call;
    return false;
  }
  unsigned guardProxyResults(std::vector<DefUseAnalyzer::TaintPath> &paths,bool completed) {
    unsigned removed=0;if(failed_||!completed||paths.size()>1024)return removed;
    paths.erase(std::remove_if(paths.begin(),paths.end(),[&](const DefUseAnalyzer::TaintPath &path){
      if(!observedDateSources_.count(path.source)||!sink(path.sink)||path.path.empty()||path.path.front()!=path.source)return false;
      auto sinkObservation=cookieObservations_.find(path.sink);
      if(sinkObservation==cookieObservations_.end()||!sinkObservation->second.count||!sinkObservation->second.allPrimitive||
          sinkObservation->second.sources.count(path.source))return false;
      for(unsigned n=0;n+1<path.path.size();++n){auto *call=llvh::dyn_cast<CallInst>(path.path[n]);if(!call)continue;
        auto observed=proxyResultObservations_.find(call);
        if(observed==proxyResultObservations_.end()||!observed->second.count||!observed->second.allPrimitive||
            observed->second.sources.count(path.source)||call->getParent()->getParent()!=path.sink->getParent()->getParent()||
            !directResultUse(call,path.path[n+1]))continue;
        ++removed;llvh::outs()<<"[PROXY_RESULT_SUPPRESS] source="<<id(path.source)<<" sink="<<id(path.sink)<<" call="<<id(call)
          <<" consumer="<<id(path.path[n+1])<<" call_observations="<<observed->second.count<<" sink_observations="<<sinkObservation->second.count
          <<" reason=COMPLETE_CALL_RESULT_AND_SINK_SOURCE_ABSENCE\n";return true;
      }
      return false;
    }),paths.end());return removed;
  }
  unsigned guardFunctionResults(std::vector<DefUseAnalyzer::TaintPath> &paths,bool completed) {
    unsigned removed=0;if(failed_||!completed||paths.size()>1024)return removed;
    paths.erase(std::remove_if(paths.begin(),paths.end(),[&](const DefUseAnalyzer::TaintPath &path){
      if(!observedDateSources_.count(path.source)||!sink(path.sink)||path.path.empty()||path.path.front()!=path.source)return false;
      auto s=cookieObservations_.find(path.sink);
      if(s==cookieObservations_.end()||!s->second.count||!s->second.allPrimitive||s->second.sources.count(path.source))return false;
      for(unsigned n=0;n+1<path.path.size();++n){Instruction *producer=path.path[n];
        bool read=llvh::isa<LoadPropertyInst>(producer);
        if(!read&&!functionResultSites_.count(producer))continue;
        auto &observations=read?functionReadObservations_:callbackResultObservations_;
        auto &executions=read?readExecutions_:callExecutions_;auto o=observations.find(producer),end=observations.end();
        auto count=executions.find(producer);
        if(o==end||!o->second.count||!o->second.allPrimitive||o->second.sources.count(path.source)||
            count==executions.end()||count->second!=o->second.count||
            producer->getParent()->getParent()!=path.sink->getParent()->getParent()||!directResultUse(producer,path.path[n+1]))continue;
        ++removed;llvh::outs()<<"[FUNCTION_PROPERTY_SUPPRESS] source="<<id(path.source)<<" sink="<<id(path.sink)
          <<" producer="<<id(producer)<<" consumer="<<id(path.path[n+1])<<" kind="<<(read?"READ":"CALL")
          <<" observations="<<o->second.count<<" executions="<<count->second<<" sink_observations="<<s->second.count
          <<" reason=COMPLETE_FUNCTION_VALUE_USE_AND_SINK_SOURCE_ABSENCE\n";return true;
      }
      return false;
    }),paths.end());return removed;
  }
  unsigned guardDescriptorResults(std::vector<DefUseAnalyzer::TaintPath> &paths,bool completed) {
    unsigned removed=0;if(failed_||!completed||paths.size()>1024)return removed;
    paths.erase(std::remove_if(paths.begin(),paths.end(),[&](const DefUseAnalyzer::TaintPath &path){
      if(!observedDateSources_.count(path.source)||!sink(path.sink)||path.path.empty()||path.path.front()!=path.source)return false;
      auto s=cookieObservations_.find(path.sink);
      if(s==cookieObservations_.end()||!s->second.count||!s->second.allPrimitive||s->second.sources.count(path.source))return false;
      for(unsigned n=0;n+1<path.path.size();++n){Instruction *producer=path.path[n];
        auto o=descriptorReadObservations_.find(producer);auto count=readExecutions_.find(producer);
        if(o==descriptorReadObservations_.end()||!o->second.count||!o->second.allPrimitive||o->second.sources.count(path.source)||
            count==readExecutions_.end()||count->second!=o->second.count||
            producer->getParent()->getParent()!=path.sink->getParent()->getParent()||!directResultUse(producer,path.path[n+1]))continue;
        ++removed;llvh::outs()<<"[DESCRIPTOR_DATA_SUPPRESS] source="<<id(path.source)<<" sink="<<id(path.sink)
          <<" producer="<<id(producer)<<" consumer="<<id(path.path[n+1])<<" observations="<<o->second.count
          <<" executions="<<count->second<<" sink_observations="<<s->second.count
          <<" reason=COMPLETE_DESCRIPTOR_READ_AND_SINK_SOURCE_ABSENCE\n";return true;
      }
      return false;
    }),paths.end());return removed;
  }
  unsigned guardOwnDataResults(std::vector<DefUseAnalyzer::TaintPath> &paths,bool completed) {
    unsigned removed=0;if(failed_||!completed||paths.size()>1024)return removed;
    paths.erase(std::remove_if(paths.begin(),paths.end(),[&](const DefUseAnalyzer::TaintPath &path){
      if(!observedDateSources_.count(path.source)||!sink(path.sink)||path.path.empty()||path.path.front()!=path.source)return false;
      auto s=cookieObservations_.find(path.sink);
      if(s==cookieObservations_.end()||!s->second.count||!s->second.allPrimitive||s->second.sources.count(path.source))return false;
      for(unsigned n=0;n+1<path.path.size();++n){Instruction *producer=path.path[n];
        bool read=llvh::isa<LoadPropertyInst>(producer),deletion=llvh::isa<DeletePropertyInst>(producer);
        if(!read&&!deletion&&!llvh::isa<CallInst>(producer))continue;
        auto &observations=read?ownReadObservations_:deletion?ownDeleteObservations_:ownCheckObservations_;
        auto &executions=read?readExecutions_:deletion?deleteExecutions_:callExecutions_;
        auto o=observations.find(producer);auto count=executions.find(producer);
        if(o==observations.end()||!o->second.count||!o->second.allPrimitive||o->second.sources.count(path.source)||
            count==executions.end()||count->second!=o->second.count||
            producer->getParent()->getParent()!=path.sink->getParent()->getParent()||!directResultUse(producer,path.path[n+1]))continue;
        ++removed;llvh::outs()<<"[OWN_DATA_SUPPRESS] source="<<id(path.source)<<" sink="<<id(path.sink)
          <<" producer="<<id(producer)<<" consumer="<<id(path.path[n+1])<<" kind="<<(read?"READ":deletion?"DELETE":"HAS_OWN")
          <<" observations="<<o->second.count<<" executions="<<count->second<<" sink_observations="<<s->second.count
          <<" reason=COMPLETE_OWN_STATE_VALUE_AND_SINK_SOURCE_ABSENCE\n";return true;
      }
      return false;
    }),paths.end());return removed;
  }
  bool directLocalDateCookie(const DefUseAnalyzer::TaintPath &path,Function *&function) {
                                                                              
                                                                           
    if(!source(path.source)||!sink(path.sink)||path.path.size()!=6||path.path.front()!=path.source||path.path.back()!=path.sink)return false;
    function=path.source->getParent()->getParent();
    for(auto *node:path.path)if(!node||node->getParent()->getParent()!=function)return false;
    auto *read=llvh::dyn_cast<LoadPropertyInst>(path.path[0]);auto *call=llvh::dyn_cast<CallInst>(path.path[1]);
    auto *store=llvh::dyn_cast<StoreFrameInst>(path.path[2]);auto *load=llvh::dyn_cast<LoadFrameInst>(path.path[3]);
    auto *add=llvh::dyn_cast<BinaryOperatorInst>(path.path[4]);auto *cookie=llvh::dyn_cast<StorePropertyInst>(path.path[5]);
    auto *date=read?llvh::dyn_cast<LoadPropertyInst>(read->getObject()):nullptr;
    auto *document=cookie?llvh::dyn_cast<LoadPropertyInst>(cookie->getObject()):nullptr;
    if(!read||key(read->getProperty())!="now"||!date||!llvh::isa<GlobalObject>(date->getObject())||key(date->getProperty())!="Date"||
        date->getParent()->getParent()!=function||!call||llvh::isa<ConstructInst>(call)||llvh::isa<CallBuiltinInst>(call)||
        call->getCallee()!=read||call->getNumArguments()!=1||call->getArgument(0)!=date||!llvh::isa<LiteralUndefined>(call->getNewTarget())||
        !store||store->getValue()!=call||store->getVariable()->getParent()!=function->getFunctionScopeDesc()||!load||load->getLoadVariable()!=store->getVariable()||
        !add||add->getOperatorKind()!=BinaryOperatorInst::OpKind::AddKind||!cookie||cookie->getStoredValue()!=add||key(cookie->getProperty())!="cookie"||
        !document||!llvh::isa<GlobalObject>(document->getObject())||key(document->getProperty())!="document"||document->getParent()->getParent()!=function)return false;
    return (add->getLeftHandSide()==load&&llvh::isa<LiteralString>(add->getRightHandSide()))||
      (add->getRightHandSide()==load&&llvh::isa<LiteralString>(add->getLeftHandSide()));
  }
  unsigned guardInactiveDispatch(std::vector<DefUseAnalyzer::TaintPath> &paths,bool completed) {
    unsigned removed=0;if(!completed||failed_||paths.size()>1024)return removed;
    paths.erase(std::remove_if(paths.begin(),paths.end(),[&](const DefUseAnalyzer::TaintPath &path){
      Function *function=nullptr;
      if(observedDateSources_.count(path.source)||cookieObservations_.count(path.sink)||!directLocalDateCookie(path,function)||
          !function||exactFunctionCalls_[function])return false;
      unsigned instances=0,representative=0;
      for(auto &created:closures_)if(created.second.function==function){
        ++instances;auto proof=inactiveDispatch_.find(created.first);
        if(exactClosureCalls_[created.first]||proof==inactiveDispatch_.end())return false;
        auto slot=dispatchSlots_.find(proof->second.slot);
        if(slot==dispatchSlots_.end()||slot->second.closure!=created.first||!descriptorRecord(make(Record,slot->second.table))||
            !moduleKeyReads_.count(proof->second.keyEvent))return false;
        representative=created.first;
      }
      if(!instances)return false;
      auto &proof=inactiveDispatch_[representative];auto &slot=dispatchSlots_[proof.slot];
      ++removed;llvh::outs()<<"[MODULE_DISPATCH_SUPPRESS] source="<<id(path.source)<<" sink="<<id(path.sink)
        <<" closure="<<representative<<" environment="<<closures_[representative].environment<<" instances="<<instances
        <<" function_calls=0 source_observations=0 sink_observations=0 slot="<<proof.slot<<" table="<<slot.table
        <<" slot_key_hex="<<keyHex(slot.key)<<" key_event="<<proof.keyEvent<<" tested_key_hex="<<keyHex(proof.testedKey)
        <<" inactive_event="<<proof.event<<" effect="<<id(proof.effect)<<" reason="<<(proof.replaced?"REPLACED":"MISSING_CHECK")
        <<" contract=COMPLETE_CLOSED_ALL_CREATED_INSTANCES_UNCALLED_EXACT_LOCAL_SIX_NODE_DATE_COOKIE\n";return true;
    }),paths.end());return removed;
  }
  static bool sameDatumIdentity(const Datum &a,const Datum &b) {
    return a.kind==b.kind&&a.ref==b.ref&&a.knownString==b.knownString&&(!a.knownString||a.string==b.string)&&
      a.knownInteger==b.knownInteger&&(!a.knownInteger||a.integer==b.integer)&&a.knownBoolean==b.knownBoolean&&(!a.knownBoolean||a.boolean==b.boolean);
  }
  static bool forbiddenHandlerKey(const std::string &n) {
    return n=="get"||n=="set"||n=="has"||n=="deleteProperty"||n=="defineProperty"||n=="ownKeys"||n=="construct"||
      n=="getPrototypeOf"||n=="setPrototypeOf"||n=="isExtensible"||n=="preventExtensions"||n=="getOwnPropertyDescriptor";
  }
  bool handlerValid(unsigned object,Instruction *at) {
    if(!handlerObjects_.count(object)||!objects_[object].recordAllocation||forbiddenExportObject(make(Record,object)))
      return reject("PROXY_HANDLER_NOT_FRESH_ORDINARY_RECORD",at),false;
    for(auto &field:objects_[object].fields){
      if(!safeDataKey(field.first)||forbiddenHandlerKey(field.first))return reject("PROXY_EXTRA_TRAP_OR_SENSITIVE_FIELD",at),false;
      if(field.first!="apply"&&!primitive(field.second))return reject("PROXY_HANDLER_DATA_NOT_PRIMITIVE",at),false;
    }
    return true;
  }
  Datum handlerApplyWrite(Datum object,Datum stored,Instruction *at) {
    if(object.kind!=Record||!handlerValid(object.ref,at)||
        (!ordinaryDataClosure(stored)&&stored.kind!=Null&&stored.kind!=Undefined)||proxyApplyWrites_>=128)
      return reject("PROXY_HANDLER_APPLY_WRITE_OUTSIDE_PROFILE",at);
    auto found=objects_[object.ref].fields.find("apply");unsigned old=found==objects_[object.ref].fields.end()?0:found->second.ref;
    edge(stored,at);putOwn(object.ref,"apply",stored);++proxyApplyWrites_;
    llvh::outs()<<"[PROXY_APPLY_WRITE] event="<<proxyApplyWrites_<<" handler="<<object.ref<<" old_trap="<<old
      <<" trap="<<stored.ref<<" trap_kind="<<unsigned(stored.kind)<<" trap_env="<<(stored.kind==Closure?closures_[stored.ref].environment:0)<<" write="<<id(at)<<"\n";
    return make(Undefined);
  }
  bool formalFeedsProxyTarget(Function *fn,unsigned argument) {
    if(argument>=fn->getParameters().size())return false;
    for(auto *construct:proxyCandidates_){if(construct->getParent()->getParent()!=fn)continue;
      Value *actual=construct->getArgument(1);if(actual==fn->getParameters()[argument])return true;
      auto *load=llvh::dyn_cast<LoadFrameInst>(actual);if(!load)continue;
      for(auto &bb:*fn)for(auto &i:bb){auto *s=llvh::dyn_cast<StoreFrameInst>(&i);
        if(s&&s->getVariable()==load->getLoadVariable()&&s->getValue()==fn->getParameters()[argument])return true;}
    }
    return false;
  }
  bool knownProxy(const Datum &d) {return d.kind==ProxyCallable&&proxies_.count(d.ref);}
  Datum constructProxy(ConstructInst *call,const std::vector<Datum> &args,Datum receiver) {
    if(!proxyCandidates_.count(call)||call->getNewTarget()!=call->getCallee()||receiver.kind!=Undefined||args.size()!=2||
        !ordinaryDataClosure(args[0])||args[1].kind!=Record||!handlerValid(args[1].ref,call)||
        nextObject_>192||proxies_.size()>=32||suspended_)return reject("PROXY_CONSTRUCTION_OUTSIDE_PROFILE",call);
    unsigned n=nextObject_++;proxies_[n]={args[0].ref,args[1].ref,call};
    llvh::outs()<<"[PROXY_CREATE] proxy="<<n<<" target="<<args[0].ref<<" target_env="<<closures_[args[0].ref].environment
      <<" handler="<<args[1].ref<<" call="<<id(call)<<"\n";
    return make(ProxyCallable,n);
  }
  Datum proxyCall(Datum proxy,const std::vector<Datum> &args,Datum receiver,CallInst *call,Frame &caller) {
    if(!knownProxy(proxy)||proxyCalls_>=64||args.size()>16||suspended_||
        (receiver.kind!=Undefined&&receiver.kind!=Null&&receiver.kind!=Record)||forbiddenExportObject(receiver))
      return reject("PROXY_CALL_OUTSIDE_PROFILE",call);
    if(receiver.kind==Record){auto *read=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
      if(!read||call->getArgument(0)!=read->getObject())return reject("PROXY_MEMBER_RECEIVER_IDENTITY",call);
      Datum actual=value(read->getObject(),caller,call);if(!sameDatumIdentity(actual,receiver))return reject("PROXY_MEMBER_RECEIVER_IDENTITY",call);}
    for(auto &a:args)if(!primitive(a))return reject("PROXY_ARGUMENT_OUTSIDE_PROFILE",call);
    auto info=proxies_[proxy.ref];if(!handlerValid(info.handler,call))return {};
    auto found=objects_[info.handler].fields.find("apply");Datum trap=found==objects_[info.handler].fields.end()?make(Undefined):found->second;
    bool fallback=trap.kind==Undefined||trap.kind==Null;
    if(!fallback&&!ordinaryDataClosure(trap))return reject("PROXY_APPLY_TRAP_NOT_CALLABLE",call);
    if(nextObject_>192)return reject("PROXY_ARGUMENT_ARRAY_LIMIT",call);
    unsigned array=nextObject_++;arrays_[array].values=args;proxyArgumentArrays_.insert(array);
    unsigned event=++proxyCalls_;proxyInvocations_[event]={proxy.ref,info.target,info.handler,array,receiver,call};
    llvh::outs()<<"[PROXY_CALL] event="<<event<<" proxy="<<proxy.ref<<" target="<<info.target<<" handler="<<info.handler
      <<" trap="<<trap.ref<<" trap_kind="<<unsigned(trap.kind)<<" receiver="<<receiver.ref<<" receiver_kind="<<unsigned(receiver.kind)
      <<" array="<<array<<" argc="<<args.size()<<" mode="<<(fallback?"FALLBACK":"TRAP")<<" call="<<id(call)<<"\n";
    Datum out;
    if(fallback){++proxyFallbacks_;out=callClosure(info.target,args,receiver,call,false,false,false,false,caller.dynamicContext,event,false);}
    else {++proxyTrapCalls_;out=callClosure(trap.ref,{make(Closure,info.target),receiver,make(Array,array)},make(Record,info.handler),call,
        false,false,false,false,caller.dynamicContext,event,true);}
    if(failed_)return {};proxyEdge(out,call);observeResult(proxyResultObservations_[call],out);return out;
  }
  static bool safeDynamicKey(const std::string &name) {
    return safeDataKey(name)&&!hostName(name)&&name!="now"&&name!="resolve"&&name!="apply"&&name!="call"&&
      name!="next"&&name!="throw"&&name!="return";
  }
  static bool dataKey(const Datum &d,std::string &name) {
    return moduleKey(d,name)&&safeDynamicKey(name);
  }
                                                                              
                                                                              
                                                                              
                                                                             
  bool localDataOperand(Value *v,Function *fn,bool property) {
    if(property&&(llvh::isa<LiteralString>(v)||llvh::isa<LiteralNumber>(v)))return true;
    if(auto *p=llvh::dyn_cast<Parameter>(v))return p->getParent()==fn&&(!property||p!=fn->getThisParameter());
    if(auto *l=llvh::dyn_cast<LoadFrameInst>(v)){
      auto *scope=llvh::dyn_cast<CreateScopeInst>(l->getEnvironment());
      return scope&&scope->getParent()->getParent()==fn&&scope->getCreatedScopeDesc()==fn->getFunctionScopeDesc();
    }
    if(auto *l=llvh::dyn_cast<LoadStackInst>(v)){
      auto *slot=llvh::dyn_cast<AllocStackInst>(l->getPtr());return slot&&slot->getParent()->getParent()==fn;
    }
    if(auto *l=llvh::dyn_cast<LoadPropertyInst>(v))return llvh::isa<GlobalObject>(l->getObject())&&declaredGlobals_.count(key(l->getProperty()))&&!hostName(key(l->getProperty()));
    if(!property){
      if(auto *a=llvh::dyn_cast<AllocObjectInst>(v))return a->getParent()->getParent()==fn;
    }
    return false;
  }
  bool nestedKeyOperand(Value *v,Function *fn,unsigned depth=0) {
    if(localDataOperand(v,fn,true))return true;
    auto *read=llvh::dyn_cast<LoadPropertyInst>(v);
    if(!read||depth>=4||read->getParent()->getParent()!=fn||!safeDynamicKey(key(read->getProperty())))return false;
    return localDataOperand(read->getObject(),fn,false)||nestedKeyOperand(read->getObject(),fn,depth+1);
  }
  bool nestedReceiverOperand(Value *v,Function *fn,unsigned depth=0) {
    if(localDataOperand(v,fn,false))return true;
    auto *read=llvh::dyn_cast<LoadPropertyInst>(v);
    return read&&depth<4&&read->getParent()->getParent()==fn&&localDataOperand(read->getProperty(),fn,true)&&
      (key(read->getProperty()).empty()||safeDynamicKey(key(read->getProperty())))&&nestedReceiverOperand(read->getObject(),fn,depth+1);
  }
  void enumerationBinding(Value *slot,Value *stored) {
    if(llvh::isa<LiteralUndefined>(stored))return;
    if(enumerationBindings_.count(slot))enumerationAmbiguousBindings_.insert(slot);
    else enumerationBindings_[slot]=stored;
  }
  Value *enumerationOrigin(Value *v,unsigned depth=0) {
    if(depth>=16)return nullptr;
    Value *slot=nullptr;
    if(auto *l=llvh::dyn_cast<LoadFrameInst>(v))slot=l->getLoadVariable();
    else if(auto *l=llvh::dyn_cast<LoadStackInst>(v))slot=l->getPtr();
    if(slot){
      if(enumerationAmbiguousBindings_.count(slot))return nullptr;
      auto found=enumerationBindings_.find(slot);
      return found==enumerationBindings_.end()?nullptr:enumerationOrigin(found->second,depth+1);
    }
    if(auto *l=llvh::dyn_cast<LoadPropertyInst>(v))if(llvh::isa<GlobalObject>(l->getObject())){
      auto name=key(l->getProperty());
      if(!declaredGlobals_.count(name)||hostName(name)||enumerationAmbiguousGlobals_.count(name))return nullptr;
      auto found=enumerationGlobals_.find(name);
      return found==enumerationGlobals_.end()?nullptr:enumerationOrigin(found->second,depth+1);
    }
    return v;
  }
  Function *enumerationFunction(Value *value) {
    auto *origin=enumerationOrigin(value);
    auto *closure=origin?llvh::dyn_cast<CreateFunctionInst>(origin):nullptr;
    return closure?closure->getFunctionCode():nullptr;
  }
  void indexEnumerationLinks() {
    for(auto &f:*module_)for(auto &b:f)for(auto &i:b){
      if(auto *s=llvh::dyn_cast<StoreFrameInst>(&i))enumerationBinding(s->getVariable(),s->getValue());
      if(auto *s=llvh::dyn_cast<StoreStackInst>(&i))enumerationBinding(s->getPtr(),s->getValue());
      if(auto *s=llvh::dyn_cast<StorePropertyInst>(&i))if(llvh::isa<GlobalObject>(s->getObject())&&!llvh::isa<LiteralUndefined>(s->getStoredValue())){
        auto name=key(s->getProperty());if(!declaredGlobals_.count(name)||hostName(name))continue;
        if(enumerationGlobals_.count(name))enumerationAmbiguousGlobals_.insert(name);
        else enumerationGlobals_[name]=s->getStoredValue();
      }
    }
    for(auto &f:*module_)for(auto &b:f)for(auto &i:b){
      auto *call=llvh::dyn_cast<CallInst>(&i);
      if(!call||llvh::isa<ConstructInst>(call)||llvh::isa<CallBuiltinInst>(call)||
          call->getNumArguments()<2||call->getNumArguments()>3||!llvh::isa<LiteralUndefined>(call->getNewTarget()))continue;
      auto *read=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
      if(!read||key(read->getProperty())!="forEach"||call->getArgument(0)!=read->getObject())continue;
      auto *origin=enumerationOrigin(read->getObject());
      auto *keys=origin?llvh::dyn_cast<CallInst>(origin):nullptr;
      auto *callback=enumerationFunction(call->getArgument(1));
      if(keys&&callback)enumerationLinks_[keys].push_back({call,callback});
    }
  }
  void closeEnumerationFunctions() {
                                                                             
                                                                      
    std::vector<Function *> pending(enumerationFunctions_.begin(),enumerationFunctions_.end());
    for(size_t n=0;n<pending.size();++n){
                                                                            
                                                                          
      for(auto &b:*pending[n])for(auto &i:b){
        auto *call=llvh::dyn_cast<CallInst>(&i);
        if(!call||llvh::isa<ConstructInst>(call)||llvh::isa<CallBuiltinInst>(call))continue;
        auto *target=enumerationFunction(call->getCallee());
        if(target&&enumerationFunctions_.insert(target).second)pending.push_back(target);
      }
    }
  }
                                                                            
                                                                                
  bool nestedAliasChain(Value *v,Function *fn,std::vector<LoadPropertyInst *> &reads,unsigned depth=0) {
    if(depth>4)return false;
    auto *read=llvh::dyn_cast<LoadPropertyInst>(v);
    if(read&&read->getParent()->getParent()==fn&&!llvh::isa<GlobalObject>(read->getObject())&&safeDynamicKey(key(read->getProperty()))){
      reads.push_back(read);return nestedAliasChain(read->getObject(),fn,reads,depth+1);
    }
    if(auto *captured=llvh::dyn_cast<LoadFrameInst>(v))return captured->getParent()->getParent()==fn;
    return localDataOperand(v,fn,false);
  }
  void indexNestedAliases() {
    for(auto &fn:*module_)for(auto &bb:fn)for(auto &ins:bb){
      auto *write=llvh::dyn_cast<StorePropertyInst>(&ins);
      if(!write||!key(write->getProperty()).empty()||!localDataOperand(write->getProperty(),&fn,true)||
          helperInstructions_.count(write)||moduleCacheInstructions_.count(write)||nestedCacheWrites_.count(write)||
          dynamicWriteCandidates_.count(write)||moduleKeyWriteCandidates_.count(write)||handlerWriteCandidates_.count(write)||
          registryWriteCandidates_.count(write)||enumerationWriteCandidates_.count(write)||protectedBindingOperand(write->getObject()))continue;
      auto *stored=llvh::dyn_cast<LoadPropertyInst>(write->getStoredValue());
      if(!stored||!safeDynamicKey(key(stored->getProperty())))continue;
      std::vector<LoadPropertyInst *> receiver,source;
      if(!nestedAliasChain(write->getObject(),&fn,receiver)||receiver.empty()||!nestedAliasChain(stored,&fn,source))continue;
      if(nestedAliasCandidates_.size()>=128){reject("NESTED_ALIAS_CANDIDATE_LIMIT",write);return;}
      nestedAliasFunctions_.insert(&fn);nestedAliasCandidates_.insert(write);nestedAliasOperands_.insert(receiver.begin(),receiver.end());nestedAliasOperands_.insert(source.begin(),source.end());
    }
  }
  Datum nestedAliasStore(StorePropertyInst *write,Frame &frame,Datum owner,Datum stored) {
    Datum property=value(write->getProperty(),frame,write);std::string name;
    if(failed_)return {};
    if(!descriptorRecord(owner)||!dataKey(property,name)||!primitive(stored)||nestedAliasWrites_>=128)
      return reject("NESTED_ALIAS_OBJECT_KEY_OR_VALUE",write);
    auto prior=objects_[owner.ref].fields.find(name);unsigned oldKind=prior==objects_[owner.ref].fields.end()?unsigned(Invalid):unsigned(prior->second.kind);
    dynamicEdge(stored,write);putOwn(owner.ref,name,stored);dynamicObjects_.insert(owner.ref);
    unsigned event=++nestedAliasWrites_;nestedAliasSlots_[{owner.ref,name}]=event;
    llvh::outs()<<"[NESTED_ALIAS_WRITE] event="<<event<<" invocation="<<frame.invocation<<" object="<<owner.ref
      <<" key_hex="<<keyHex(name)<<" old_kind="<<oldKind<<" value_kind="<<unsigned(stored.kind)<<" value_ref="<<stored.ref
      <<" source_traces="<<stored.traces.size()<<" value_read="<<id(llvh::cast<LoadPropertyInst>(write->getStoredValue()))<<" write="<<id(write)<<"\n";
    return make(Undefined);
  }
  void indexFreshGetters() {
    for(auto &fn:*module_)for(auto &bb:fn)for(auto &ins:bb){
      auto *def=llvh::dyn_cast<StoreGetterSetterInst>(&ins);if(!def)continue;
      auto *object=llvh::dyn_cast<AllocObjectInst>(def->getObject());
      auto *getter=llvh::dyn_cast<CreateFunctionInst>(def->getStoredGetter());
      if(!object||!getter||object->getParent()->getParent()!=&fn||getter->getParent()->getParent()!=&fn||
          !llvh::isa<LiteralUndefined>(def->getStoredSetter())||!def->getIsEnumerable()||!safeDynamicKey(key(def->getProperty())))continue;
      if(freshGetterCandidates_.size()>=128){reject("FRESH_GETTER_CANDIDATE_LIMIT",def);return;}
      freshGetterCandidates_.insert(def);
    }
  }
  Datum defineFreshGetter(StoreGetterSetterInst *def,Frame &frame) {
    if(!freshGetterCandidates_.count(def))return reject("GETTER_DEFINITION_OUTSIDE_PROFILE",def);
    Datum object=value(def->getObject(),frame,def),getter=value(def->getStoredGetter(),frame,def),setter=value(def->getStoredSetter(),frame,def);
    std::string name=key(def->getProperty());
    if(failed_)return {};
    if(!descriptorRecord(object)||objects_[object.ref].recordAllocation!=def->getObject()||!safeDynamicKey(name)||
        setter.kind!=Undefined||!ordinaryDataClosure(getter)||closures_[getter.ref].function->getParameters().size()!=0||freshGetterDefinitions_>=128)
      return reject("FRESH_GETTER_OBJECT_CLOSURE_OR_SETTER",def);
    unsigned event=++freshGetterDefinitions_;putOwn(object.ref,name,make(FreshGetterSlot,getter.ref));
    freshGetters_[{object.ref,name}]={getter.ref,event,def};
    llvh::outs()<<"[FRESH_GETTER_DEFINE] event="<<event<<" invocation="<<frame.invocation<<" object="<<object.ref
      <<" key_hex="<<keyHex(name)<<" closure="<<getter.ref<<" environment="<<closures_[getter.ref].environment<<" definition="<<id(def)<<"\n";
    return make(Undefined);
  }
  Datum readFreshGetter(Datum object,const std::string &name,LoadPropertyInst *read) {
    auto found=freshGetters_.find({object.ref,name});
    if(!descriptorRecord(object)||found==freshGetters_.end()||freshGetterCalls_>=128)return reject("FRESH_GETTER_READ_IDENTITY",read);
    auto cert=found->second;auto &closure=closures_[cert.closure];auto *target=closure.function;
    auto field=objects_[object.ref].fields.find(name);
    if(field==objects_[object.ref].fields.end()||field->second.kind!=FreshGetterSlot||field->second.ref!=cert.closure||
        !ordinaryDataClosure(make(Closure,cert.closure))||target->getParameters().size()!=0||active_.count(target)||active_.size()>=8||++invocations_>64)
      return reject("FRESH_GETTER_CALL_KIND_OR_RECURSION",read);
    ++exactClosureCalls_[cert.closure];++exactFunctionCalls_[target];unsigned event=++freshGetterCalls_;
    Frame frame;frame.function=target;frame.entry=read;frame.invocation=invocations_;frame.receiver=object;frame.parent=closure.environment;frame.dynamicContext=true;
    llvh::outs()<<"[FRESH_GETTER_CALL] event="<<event<<" definition_event="<<cert.event<<" invocation="<<frame.invocation<<" object="<<object.ref
      <<" key_hex="<<keyHex(name)<<" closure="<<cert.closure<<" environment="<<closure.environment<<" read="<<id(read)<<"\n";
    active_.insert(target);Datum result=execute(frame,&target->front());active_.erase(target);
    if(failed_)return {};
    if(!primitive(result))return reject("FRESH_GETTER_RETURN_NOT_PRIMITIVE",read);
    dynamicEdge(result,read);++freshGetterReturns_;
    llvh::outs()<<"[FRESH_GETTER_RETURN] event="<<freshGetterReturns_<<" call_event="<<event<<" object="<<object.ref
      <<" key_hex="<<keyHex(name)<<" value_kind="<<unsigned(result.kind)<<" source_traces="<<result.traces.size()<<" read="<<id(read)<<"\n";
    return result;
  }
  bool sameCacheOperand(Value *a,Value *b,unsigned depth=0) {
    if(depth>=8)return false;
    a=enumerationOrigin(a);b=enumerationOrigin(b);if(!a||!b)return false;
    if(a==b)return true;
    auto *x=llvh::dyn_cast<LoadPropertyInst>(a),*y=llvh::dyn_cast<LoadPropertyInst>(b);
    return x&&y&&sameCacheOperand(x->getObject(),y->getObject(),depth+1)&&sameCacheOperand(x->getProperty(),y->getProperty(),depth+1);
  }
  void indexNestedCaches() {
    for(auto &inner:recordHasCandidates_){
      auto *nested=llvh::dyn_cast<LoadPropertyInst>(inner.first->getObject());
      auto *fn=inner.second->getParent()->getParent();
      if(!nested||!localDataOperand(nested->getProperty(),fn,true)||!localDataOperand(inner.second->getArgument(1),fn,true))continue;
      auto *root=enumerationOrigin(nested->getObject());
      if(!root||!llvh::isa<AllocObjectInst>(root)||protectedBindingOperand(nested->getObject()))continue;
      for(auto &outer:recordHasCandidates_){
        if(outer.second->getParent()->getParent()!=fn||
            !sameCacheOperand(outer.first->getObject(),nested->getObject())||
            !sameCacheOperand(outer.second->getArgument(1),nested->getProperty()))continue;
        nestedCacheFunctions_.insert(fn);nestedCacheChecks_.insert(outer.second);nestedCacheChecks_.insert(inner.second);
      }
    }
    for(auto *call:nestedCacheChecks_){auto *read=llvh::cast<LoadPropertyInst>(call->getCallee());auto *fn=call->getParent()->getParent();
      for(auto &bb:*fn)for(auto &i:bb)if(auto *s=llvh::dyn_cast<StorePropertyInst>(&i)){
        if(sameCacheOperand(s->getObject(),read->getObject())&&sameCacheOperand(s->getProperty(),call->getArgument(1))){
          if(nestedCacheWrites_.size()>=128){reject("NESTED_CACHE_CANDIDATE_LIMIT",s);return;}
          nestedCacheWrites_.insert(s);
        }
      }
    }
  }
  Datum nestedCacheStore(StorePropertyInst *s,Frame &f,Datum owner,Datum stored) {
    Datum property=value(s->getProperty(),f,s);std::string name;
    if(!nestedCacheFunctions_.count(f.function)||!descriptorRecord(owner)||!dataKey(property,name)||
        nestedCacheWritesCount_>=128)return reject("NESTED_CACHE_WRITE_IDENTITY_OR_KEY",s);
    auto &checks=nestedCachePresence_[f.invocation];auto found=checks.find({owner.ref,name});
    if(found==checks.end()||found->second||objects_[owner.ref].fields.count(name))return reject("NESTED_CACHE_WRITE_WITHOUT_CURRENT_ABSENCE",s);
    if(!primitive(stored)&&!(descriptorRecord(stored)&&stored.ref!=owner.ref&&objects_[stored.ref].fields.empty()))
      return reject("NESTED_CACHE_INITIALIZER_NOT_PRIMITIVE_OR_EMPTY_RECORD",s);
    dispatchEdge(stored,s);putOwn(owner.ref,name,stored);dynamicObjects_.insert(owner.ref);
    ++nestedCacheWritesCount_;
    llvh::outs()<<"[NESTED_CACHE_WRITE] event="<<nestedCacheWritesCount_<<" invocation="<<f.invocation<<" object="<<owner.ref
      <<" key_hex="<<keyHex(name)<<" value_kind="<<unsigned(stored.kind)<<" value_ref="<<stored.ref<<" write="<<id(s)<<"\n";
    return make(Undefined);
  }
  bool enumerationGraph(const Datum &d,std::set<unsigned> &seen,std::set<unsigned> &active,unsigned depth=0) {
    if(primitive(d)||ordinaryDataClosure(d))return true;
    if(!descriptorRecord(d)||depth>4||active.count(d.ref))return false;
    if(seen.count(d.ref))return true;
    if(seen.size()>=16||objects_[d.ref].fields.size()>32)return false;
    seen.insert(d.ref);active.insert(d.ref);
    for(auto &field:objects_[d.ref].fields)if(!safeDynamicKey(field.first)||!enumerationGraph(field.second,seen,active,depth+1))return false;
    active.erase(d.ref);return true;
  }
  bool enumerationData(const Datum &d,unsigned target=0) {
    std::set<unsigned> seen,active;return d.kind==Record&&enumerationGraph(d,seen,active)&&(!target||!seen.count(target));
  }
  static bool arrayIndexKey(const std::string &s,uint64_t &number) {
    if(s.empty()||s.size()>10||(s.size()>1&&s[0]=='0'))return false;number=0;
    for(char c:s){if(c<'0'||c>'9')return false;number=number*10+unsigned(c-'0');if(number>4294967294ULL)return false;}return true;
  }
  static bool exactTruth(const Datum &d,bool &truth) {
    if(!d.traces.empty())return false;
    if(d.kind==Undefined||d.kind==Null){truth=false;return true;}
    if(d.kind==Primitive){
      if(d.knownBoolean){truth=d.boolean;return true;}if(d.knownString){truth=!d.string.empty();return true;}
      if(d.knownInteger){truth=d.integer!=0;return true;}if(d.truthKnown){truth=d.truthValue;return true;}return false;
    }
    if(d.kind==Record||d.kind==Closure||d.kind==Array){truth=true;return true;}return false;
  }
  Datum objectKeys(const std::vector<Datum> &args,Datum receiver,CallInst *call) {
    auto *read=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());auto candidate=objectKeysCandidates_.find(read);
    if(!read||candidate==objectKeysCandidates_.end()||candidate->second!=call||receiver.kind!=ObjectIntrinsic||call->getArgument(0)!=read->getObject()||
        args.size()!=1||!descriptorRecord(args[0])||nextObject_>192||enumerationSnapshots_.size()>=32)return reject("ENUM_KEYS_RECEIVER_OR_INTRINSIC",call);
    auto &object=objects_[args[0].ref];if(object.fields.size()>32||object.keyOrder.size()!=object.fields.size())return reject("ENUM_KEYS_ORDER_OR_LIMIT",call);
    std::set<std::string> seen;std::vector<std::pair<uint64_t,std::string>> indices;std::vector<std::string> names;
    for(auto &name:object.keyOrder){if(!object.fields.count(name)||!seen.insert(name).second||!safeDynamicKey(name))return reject("ENUM_KEYS_UNMODELED_KEY_OR_ORDER",call);
      uint64_t index=0;if(arrayIndexKey(name,index))indices.push_back({index,name});else names.push_back(name);}
    std::sort(indices.begin(),indices.end());std::vector<std::string> keys;
    for(auto &entry:indices)keys.push_back(entry.second);keys.insert(keys.end(),names.begin(),names.end());
    unsigned array=nextObject_++;enumerationSnapshots_[array]={args[0].ref,keys};auto &items=arrays_[array].values;
    for(auto &name:keys){Datum d=make(Primitive);d.knownString=true;d.string=name;d.enumerationSnapshot=array;items.push_back(d);}
    llvh::outs()<<"[ENUM_KEYS] snapshot="<<array<<" object="<<args[0].ref<<" size="<<keys.size()<<" call="<<id(call)<<"\n";
    for(unsigned n=0;n<keys.size();++n)llvh::outs()<<"[ENUM_KEYS_ITEM] snapshot="<<array<<" index="<<n<<" key_hex="<<keyHex(keys[n])<<"\n";
    return make(Array,array);
  }
  Datum keysForEach(const std::vector<Datum> &args,Datum callee,Datum receiver,CallInst *call) {
    auto *read=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());auto snapshot=enumerationSnapshots_.find(callee.ref);
    if(!read||key(read->getProperty())!="forEach"||call->getArgument(0)!=read->getObject()||receiver.kind!=Array||receiver.ref!=callee.ref||
        snapshot==enumerationSnapshots_.end()||args.empty()||args.size()>2||!enumerationCallbackClosure(args[0])||enumerationForeach_>=32)
      return reject("ENUM_FOREACH_IDENTITY_OR_CALLBACK",call);
    Datum self=args.size()==2?args[1]:make(Undefined);if(self.kind!=Undefined&&self.kind!=Null&&self.kind!=Record)return reject("ENUM_FOREACH_THISARG",call);
    if(self.kind==Record&&!descriptorRecord(self))return reject("ENUM_FOREACH_THISARG_ROLE",call);
    unsigned event=++enumerationForeach_;
    llvh::outs()<<"[ENUM_FOREACH] event="<<event<<" snapshot="<<callee.ref<<" callback="<<args[0].ref
      <<" environment="<<closures_[args[0].ref].environment<<" this_kind="<<unsigned(self.kind)<<" this_ref="<<self.ref<<" call="<<id(call)<<"\n";
    for(unsigned n=0;n<snapshot->second.keys.size();++n){
      if(enumerationCallbacks_>=128)return reject("ENUM_CALLBACK_LIMIT",call);
      Datum keyValue=arrays_[callee.ref].values[n],index=make(Primitive);index.knownInteger=true;index.integer=n;
      ++enumerationCallbacks_;llvh::outs()<<"[ENUM_CALLBACK] event="<<enumerationCallbacks_<<" foreach="<<event<<" snapshot="<<callee.ref
        <<" object="<<snapshot->second.object<<" index="<<n<<" key_hex="<<keyHex(snapshot->second.keys[n])<<" callback="<<args[0].ref<<" call="<<id(call)<<"\n";
      callClosure(args[0].ref,{keyValue,index,make(Array,callee.ref)},self,call,false,false,false,false,false,0,false,false,false,false,false,callee.ref,true);
      if(failed_)return {};
    }
    return make(Undefined);
  }
  Datum enumerationStore(StorePropertyInst *s,Frame &frame,Datum object,Datum stored) {
    Datum property=value(s->getProperty(),frame,s);std::string name;
    if(!frame.enumerationMode||!descriptorRecord(object)||!dataKey(property,name)||enumerationWrites_>=128||
        (!primitive(stored)&&!ordinaryDataClosure(stored)&&!enumerationData(stored,object.ref)))return reject("ENUM_WRITE_OBJECT_KEY_OR_VALUE",s);
    if(ordinaryDataClosure(stored)){stored.dynamicClosure=true;stored.enumerationClosure=true;stored.enumerationSnapshot=frame.enumerationSnapshot;}
    enumerationEdge(stored,s);putOwn(object.ref,name,stored);dynamicObjects_.insert(object.ref);++enumerationWrites_;
    llvh::outs()<<"[ENUM_WRITE] event="<<enumerationWrites_<<" object="<<object.ref<<" key_hex="<<keyHex(name)<<" value_kind="<<unsigned(stored.kind)
      <<" value_ref="<<stored.ref<<" snapshot="<<frame.enumerationSnapshot<<" write="<<id(s)<<"\n";return make(Undefined);
  }
  bool closedDataGraph(const Datum &d,std::set<unsigned> &seen,std::set<unsigned> &active,unsigned depth=0) {
    if(primitive(d))return true;
    if(d.kind!=Record||depth>4||forbiddenExportObject(d)||handlerObjects_.count(d.ref)||
        (!objects_[d.ref].recordAllocation&&!exportObjects_.count(d.ref))||active.count(d.ref))return false;
    if(seen.count(d.ref))return true;
    if(seen.size()>=16||objects_[d.ref].fields.size()>32)return false;
    seen.insert(d.ref);active.insert(d.ref);
    for(auto &field:objects_[d.ref].fields)if(!safeDynamicKey(field.first)||!closedDataGraph(field.second,seen,active,depth+1))return false;
    active.erase(d.ref);return true;
  }
  bool closedNestedData(const Datum &d,unsigned target=0) {
    std::set<unsigned> seen,active;return d.kind==Record&&closedDataGraph(d,seen,active)&&(!target||!seen.count(target));
  }
  void readModuleData(Datum owner,const std::string &key,Datum &result,LoadPropertyInst *read) {
    if(!owner.moduleDataRoot)return;
    if(owner.moduleDataDepth>=4||!safeDynamicKey(key)||forbiddenExportObject(owner)||handlerObjects_.count(owner.ref)){
      reject("MODULE_DATA_DEPTH_KEY_OR_ROLE",read);return;}
    if(result.kind==Record){
      if(!closedNestedData(result)){reject("MODULE_DATA_NESTED_GRAPH",read);return;}
      result.moduleDataRoot=owner.moduleDataRoot;result.moduleDataDepth=owner.moduleDataDepth+1;result.moduleKeyEvent=0;
      llvh::outs()<<"[MODULE_DATA_OBJECT_READ] root="<<owner.moduleDataRoot<<" object="<<owner.ref<<" key_hex="<<keyHex(key)
        <<" value="<<result.ref<<" depth="<<result.moduleDataDepth<<" read="<<id(read)<<"\n";return;
    }
    std::string exact;if(!primitive(result)||!dataKey(result,exact))return;
    if(moduleKeyReads_.size()>=128){reject("MODULE_KEY_READ_LIMIT",read);return;}
    unsigned event=moduleKeyReads_.size()+1;moduleKeyReads_.emplace(event,ModuleKeyRead{owner.moduleDataRoot,owner.ref,key,exact,read});
    result.moduleDataRoot=owner.moduleDataRoot;result.moduleDataDepth=owner.moduleDataDepth+1;result.moduleKeyEvent=event;
    llvh::outs()<<"[MODULE_DATA_KEY_READ] event="<<event<<" root="<<owner.moduleDataRoot<<" object="<<owner.ref
      <<" key_hex="<<keyHex(key)<<" value_hex="<<keyHex(exact)<<" depth="<<result.moduleDataDepth<<" read="<<id(read)<<"\n";
  }
  void rememberDispatchSlot(Datum table,const std::string &key,Datum closure,Instruction *write) {
    if(!descriptorRecord(table)||!ordinaryDataClosure(closure)||!safeDynamicKey(key))return;
    if(dispatchSlots_.size()>=256){reject("MODULE_DISPATCH_SLOT_LIMIT",write);return;}
    unsigned event=dispatchSlots_.size()+1;dispatchSlots_.emplace(event,DispatchSlot{table.ref,closure.ref,key,write});
    llvh::outs()<<"[MODULE_DISPATCH_SLOT] event="<<event<<" table="<<table.ref<<" key_hex="<<keyHex(key)
      <<" closure="<<closure.ref<<" environment="<<closures_[closure.ref].environment
      <<" creation="<<id(closures_[closure.ref].creation)<<" write="<<id(write)<<"\n";
  }
  void rememberInactiveDispatch(Datum table,const std::string &slotKey,Datum closure,Datum testedKey,Instruction *effect,bool replaced) {
    if(!descriptorRecord(table)||!ordinaryDataClosure(closure)||!testedKey.moduleKeyEvent)return;
    auto proof=moduleKeyReads_.find(testedKey.moduleKeyEvent);std::string exact;
    if(proof==moduleKeyReads_.end()||!dataKey(testedKey,exact)||proof->second.value!=exact||proof->second.root!=testedKey.moduleDataRoot)return;
    unsigned slot=0;for(auto &entry:dispatchSlots_)if(entry.second.table==table.ref&&entry.second.key==slotKey&&entry.second.closure==closure.ref)slot=entry.first;
    if(!slot)return;
    if(inactiveDispatchEvents_>=256){reject("MODULE_DISPATCH_INACTIVE_LIMIT",effect);return;}
    unsigned event=++inactiveDispatchEvents_;
    inactiveDispatch_[closure.ref]={event,slot,testedKey.moduleKeyEvent,exact,effect,replaced};
    llvh::outs()<<"[MODULE_DISPATCH_INACTIVE] event="<<event<<" slot="<<slot<<" table="<<table.ref<<" slot_key_hex="<<keyHex(slotKey)
      <<" closure="<<closure.ref<<" environment="<<closures_[closure.ref].environment<<" key_event="<<testedKey.moduleKeyEvent
      <<" tested_key_hex="<<keyHex(exact)<<" effect="<<id(effect)<<" reason="<<(replaced?"REPLACED":"MISSING_CHECK")<<"\n";
  }
  Datum inheritedRecordHas(const std::vector<Datum> &args,Datum callee,Datum receiver,CallInst *call,Frame &frame) {
    auto *read=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());auto candidate=recordHasCandidates_.find(read);std::string name;
    if(!read||candidate==recordHasCandidates_.end()||candidate->second!=call||call->getArgument(0)!=read->getObject()||
        !descriptorRecord(receiver)||receiver.ref!=callee.ref||args.size()!=1||!dataKey(args[0],name)||
        objects_[receiver.ref].fields.count("hasOwnProperty")||dispatchChecks_>=128)
      return reject("RECORD_HAS_OWN_RECEIVER_KEY_OR_SHADOW",call);
                                                                          
    if(nestedCacheChecks_.count(call)&&(!closedNestedData(receiver)||nestedCacheChecksCount_>=256))
      return reject("NESTED_CACHE_CHECK_GRAPH_OR_LIMIT",call);
    bool present=objects_[receiver.ref].fields.count(name)!=0;++dispatchChecks_;
    if(nestedCacheChecks_.count(call)){
      nestedCachePresence_[frame.invocation][{receiver.ref,name}]=present;dynamicObjects_.insert(receiver.ref);
      ++nestedCacheChecksCount_;
      llvh::outs()<<"[NESTED_CACHE_HAS] event="<<nestedCacheChecksCount_<<" invocation="<<frame.invocation<<" object="<<receiver.ref
        <<" key_hex="<<keyHex(name)<<" present="<<(present?1:0)<<" call="<<id(call)<<"\n";
    }
    llvh::outs()<<"[MODULE_DISPATCH_HAS] event="<<dispatchChecks_<<" table="<<receiver.ref<<" key_hex="<<keyHex(name)
      <<" key_event="<<args[0].moduleKeyEvent<<" root="<<args[0].moduleDataRoot
      <<" present="<<(present?1:0)<<" call="<<id(call)<<" read="<<id(read)<<"\n";
    if(!present)for(auto &field:objects_[receiver.ref].fields)rememberInactiveDispatch(receiver,field.first,field.second,args[0],call,false);
    Datum result=make(Primitive);result.knownBoolean=true;result.boolean=present;result.dispatchBoolean=true;return result;
  }
  bool protectedBindingOperand(Value *v) {
    auto *i=llvh::dyn_cast<Instruction>(v);if(!i)return false;
    for(auto &entry:moduleCertificates_)if(sameClosedBinding(i,entry.second.registryBinding)||sameClosedBinding(i,entry.second.cacheBinding))return true;
    return false;
  }
  bool ordinaryDataClosure(const Datum &d) {
    if(d.kind!=Closure)return false;auto &c=closures_[d.ref];auto *fn=c.function;
    return fn&&!c.isClass&&!c.methodOwner&&!fn->isLazy()&&!fn->empty()&&fn->getParameters().size()<=16&&
      (fn->getDefinitionKind()==Function::DefinitionKind::ES5Function||fn->getDefinitionKind()==Function::DefinitionKind::ES6Method)&&
      !llvh::isa<AsyncFunction>(fn)&&!llvh::isa<GeneratorFunction>(fn)&&!llvh::isa<GeneratorInnerFunction>(fn);
  }
  bool enumerationCallbackClosure(const Datum &d) {
    if(ordinaryDataClosure(d))return true;
    if(d.kind!=Closure)return false;auto &c=closures_[d.ref];auto *fn=c.function;
    return fn&&!c.isClass&&!c.methodOwner&&!fn->isLazy()&&!fn->empty()&&fn->getParameters().size()<=3&&
      fn->getDefinitionKind()==Function::DefinitionKind::ES6Arrow&&fn->getThisParameter()->getUsers().empty()&&
      !llvh::isa<AsyncFunction>(fn)&&!llvh::isa<GeneratorFunction>(fn)&&!llvh::isa<GeneratorInnerFunction>(fn);
  }
  bool closureFormalFeedsDataWrite(Function *fn,unsigned argument) {
    if(argument>=fn->getParameters().size())return false;
    for(auto *write:dynamicWriteCandidates_){
      if(write->getParent()->getParent()!=fn)continue;
      auto *load=llvh::dyn_cast<LoadFrameInst>(write->getStoredValue());if(!load)continue;
      auto *formal=fn->getParameters()[argument];
      for(auto &bb:*fn)for(auto &i:bb){auto *store=llvh::dyn_cast<StoreFrameInst>(&i);
        if(store&&store->getVariable()==load->getLoadVariable()&&store->getValue()==formal)return true;}
    }
    return false;
  }
  bool closureFormalFeedsRegistryWrite(Function *fn,unsigned argument) {
    if(argument>=fn->getParameters().size())return false;
    for(auto *write:registryWriteCandidates_){
      if(write->getParent()->getParent()!=fn)continue;
      auto *load=llvh::dyn_cast<LoadFrameInst>(write->getStoredValue());if(!load)continue;
      for(auto &bb:*fn)for(auto &i:bb){auto *store=llvh::dyn_cast<StoreFrameInst>(&i);
        if(store&&store->getVariable()==load->getLoadVariable()&&store->getValue()==fn->getParameters()[argument])return true;}
    }
    return false;
  }
  Datum dataStore(StorePropertyInst *s,Frame &f,Datum object,Datum stored) {
    Datum property=value(s->getProperty(),f,s);std::string name;
    if(failed_)return {};
    if(moduleKeyWriteCandidates_.count(s)&&!dynamicWriteCandidates_.count(s)&&
        (!property.moduleKeyEvent||!moduleKeyReads_.count(property.moduleKeyEvent)||!ordinaryDataClosure(stored)))return reject("MODULE_KEY_WRITE_WITHOUT_OBSERVED_EXPORT_KEY",s);
    if(object.kind!=Record||!dataKey(property,name)||
        (!primitive(stored)&&!ordinaryDataClosure(stored)&&!knownProxy(stored))||dynamicWrites_>=128)
      return reject("DYNAMIC_DATA_RECEIVER_KEY_OR_VALUE",s);
    if(object.kind==Record&&(registryObjects_.count(object.ref)||cacheObjects_.count(object.ref)||moduleRecords_.count(object.ref)))
      return reject("DYNAMIC_DATA_PROTECTED_MODULE_ROLE",s);
    auto &info=objects_[object.ref];
    if(object.kind==Record&&!info.recordAllocation&&!exportObjects_.count(object.ref))return reject("DYNAMIC_RECORD_NOT_FRESH",s);
    auto prior=info.fields.find(name);unsigned oldRef=prior==info.fields.end()?0:prior->second.ref;
    unsigned oldKind=prior==info.fields.end()?unsigned(Invalid):unsigned(prior->second.kind);
    if(stored.kind==Closure||knownProxy(stored))stored.dynamicClosure=true;
    stored.dispatchRegistration=0;
    if(property.moduleKeyEvent&&ordinaryDataClosure(stored)){
      auto keyProof=moduleKeyReads_.find(property.moduleKeyEvent);
      if(!descriptorRecord(object)||keyProof==moduleKeyReads_.end()||keyProof->second.root!=property.moduleDataRoot||
          keyProof->second.value!=name||dispatchRegistrations_.size()>=128)return reject("MODULE_DISPATCH_REGISTRATION_IDENTITY",s);
      unsigned event=dispatchRegistrations_.size()+1;
      dispatchRegistrations_.emplace(event,DispatchRegistration{object.ref,stored.ref,property.moduleKeyEvent,name,s});
      stored.dispatchRegistration=event;
      llvh::outs()<<"[MODULE_DISPATCH_WRITE] event="<<event<<" table="<<object.ref<<" key_hex="<<keyHex(name)
        <<" key_event="<<property.moduleKeyEvent<<" root="<<property.moduleDataRoot<<" closure="<<stored.ref
        <<" environment="<<closures_[stored.ref].environment<<" old_kind="<<oldKind<<" old_ref="<<oldRef<<" write="<<id(s)<<"\n";
      if(prior!=info.fields.end()&&ordinaryDataClosure(prior->second)&&prior->second.ref!=stored.ref)
        rememberInactiveDispatch(object,name,prior->second,property,s,true);
    }
    rememberDispatchSlot(object,name,stored,s);if(failed_)return {};
    dynamicEdge(stored,s);if(exportObjects_.count(object.ref))moduleEdge(stored,s);
    putOwn(object.ref,name,stored);dynamicObjects_.insert(object.ref);++dynamicWrites_;
    llvh::outs()<<"[DYNAMIC_PROPERTY_WRITE] event="<<dynamicWrites_<<" object="<<object.ref<<" object_kind="<<unsigned(object.kind)
      <<" key_hex="<<keyHex(name)<<" old_kind="<<oldKind<<" old_ref="<<oldRef<<" new_kind="<<unsigned(stored.kind)<<" new_ref="<<stored.ref
      <<" closure_env="<<(stored.kind==Closure?closures_[stored.ref].environment:0)<<" source_traces="<<stored.traces.size()<<" write="<<id(s)<<"\n";
    return make(Undefined);
  }
  bool forbiddenExportObject(const Datum &d) {
    return d.kind==Record&&(registryObjects_.count(d.ref)||cacheObjects_.count(d.ref)||moduleRecords_.count(d.ref));
  }
  bool peekClosedBinding(Instruction *binding,unsigned environment,Datum &out) {
    if(auto *load=llvh::dyn_cast<LoadPropertyInst>(binding)){
      if(!llvh::isa<GlobalObject>(load->getObject()))return false;
      auto value=globals_.find(key(load->getProperty()));if(value==globals_.end())return false;out=value->second;return true;
    }
    auto *load=llvh::dyn_cast<LoadFrameInst>(binding);if(!load)return false;
    for(unsigned current=environment;current;current=environments_[current].parent){
      auto &env=environments_[current];if(env.descriptor!=load->getLoadVariable()->getParent())continue;
      auto value=env.vars.find(load->getLoadVariable());if(value==env.vars.end())return false;out=value->second;return true;
    }
    return false;
  }
  bool moduleFactoryValue(const Datum &value) {
    return ordinaryDataClosure(value)&&plainFunction(closures_[value.ref].function,3);
  }
  unsigned registryOwner(unsigned registry,Instruction *at) {
    if(!registryObjects_.count(registry)||!objects_[registry].recordAllocation)return reject("REGISTRY_NOT_CERTIFIED_ALLOCATION",at),0;
    unsigned owner=0,cacheId=0;
    for(auto &closure:closures_){auto cert=moduleCertificates_.find(closure.second.function);if(cert==moduleCertificates_.end())continue;
      if(cert->second.registryAllocation!=objects_[registry].recordAllocation)continue;
      Datum table,cache,self;
      if(!peekClosedBinding(cert->second.registryBinding,closure.second.environment,table)||table.kind!=Record||table.ref!=registry)continue;
      if(!peekClosedBinding(cert->second.cacheBinding,closure.second.environment,cache)||cache.kind!=Record||cache.ref==registry||
          objects_[cache.ref].recordAllocation!=cert->second.cacheAllocation||
          !peekClosedBinding(cert->second.selfBinding,closure.second.environment,self)||self.kind!=Closure||self.ref!=closure.first)
        return reject("REGISTRY_LOADER_CAPTURE_NOT_CLOSED",at),0;
      if(owner&&owner!=closure.first)return reject("REGISTRY_MULTIPLE_LOADER_OWNERS",at),0;
      owner=closure.first;cacheId=cache.ref;
    }
    if(!owner)return reject("REGISTRY_EXACT_LOADER_OWNER_MISSING",at),0;
    auto old=registryOwners_.find(registry);if(old!=registryOwners_.end()&&old->second!=owner)
      return reject("REGISTRY_OWNER_CHANGED",at),0;
    for(auto &state:loaderStates_){
      if(state.first==owner&&(state.second.registry!=registry||state.second.cache!=cacheId))return reject("REGISTRY_LOADER_STATE_CHANGED",at),0;
      if(state.first!=owner&&state.second.cache==cacheId)return reject("REGISTRY_CACHE_SHARED_ACROSS_LOADERS",at),0;
    }
    registryOwners_[registry]=owner;return owner;
  }
  Datum registerFactory(StorePropertyInst *write,Frame &frame,Datum registry,Datum factory) {
    Datum property=value(write->getProperty(),frame,write);std::string name;
    if(!registryWriteCandidates_.count(write)||registry.kind!=Record||!registryObjects_.count(registry.ref)||
        !moduleKey(property,name)||!moduleFactoryValue(factory)||registryWrites_>=64)
      return reject("REGISTRY_REGISTRATION_OUTSIDE_PROFILE",write);
    unsigned owner=registryOwner(registry.ref,write);if(failed_||!owner)return {};
    auto &fields=objects_[registry.ref].fields;auto old=fields.find(name);bool existed=old!=fields.end();
    if(fields.size()>32||(!existed&&fields.size()>=32)||(existed&&!moduleFactoryValue(old->second)))return reject("REGISTRY_TABLE_LIMIT_OR_OLD_FACTORY",write);
    unsigned prior=existed?old->second.ref:0;edge(factory,write);putOwn(registry.ref,name,factory);registeredKeys_[registry.ref].insert(name);++registryWrites_;
    unsigned cached=0;auto state=loaderStates_.find(owner);
    if(state!=loaderStates_.end()){auto item=state->second.entries.find(name);if(item!=state->second.entries.end())cached=item->second.complete?2:1;}
    llvh::outs()<<"[MODULE_REGISTRY_WRITE] event="<<registryWrites_<<" loader="<<owner<<" loader_environment="<<closures_[owner].environment
      <<" registry="<<registry.ref<<" key_hex="<<keyHex(name)<<" existed="<<(existed?1:0)<<" old_factory="<<prior
      <<" factory="<<factory.ref<<" factory_environment="<<closures_[factory.ref].environment<<" cache_state="<<cached
      <<" write="<<id(write)<<"\n";return make(Undefined);
  }
  Datum requireModule(unsigned closure,const std::vector<Datum> &args,Datum self,CallInst *call,const ModuleCertificate &cert) {
    if(++moduleRequires_>64||args.size()!=1||self.kind!=Undefined||suspended_||closures_[closure].isClass||closures_[closure].methodOwner)
      return reject("MODULE_REQUIRE_CALL_OUTSIDE_PROFILE",call);
    std::string name;if(!moduleKey(args[0],name))return reject("MODULE_ID_NOT_EXACT_STRING_OR_INTEGER",call);
    unsigned env=closures_[closure].environment;
    Datum cache=resolveHelperBinding(cert.cacheBinding,env,call),table=resolveHelperBinding(cert.registryBinding,env,call),same=resolveHelperBinding(cert.selfBinding,env,call);
    if(failed_)return {};
    if(cache.kind!=Record||table.kind!=Record||cache.ref==table.ref||same.kind!=Closure||same.ref!=closure||
        objects_[cache.ref].recordAllocation!=cert.cacheAllocation||objects_[table.ref].recordAllocation!=cert.registryAllocation)
      return reject("MODULE_LOADER_OBJECT_OR_SELF_BINDING",call);
    auto owner=registryOwners_.find(table.ref);if(owner!=registryOwners_.end()&&owner->second!=closure)return reject("MODULE_REGISTRY_OWNER_MISMATCH",call);
    auto found=loaderStates_.find(closure);
    if(found==loaderStates_.end()){
      for(auto &other:loaderStates_)if(other.second.cache==cache.ref)return reject("MODULE_CACHE_SHARED_ACROSS_LOADERS",call);
      if(!objects_[cache.ref].fields.empty()||objects_[table.ref].fields.empty()||objects_[table.ref].fields.size()>32)
        return reject("MODULE_TABLE_OR_CACHE_NOT_FRESH_BOUNDED",call);
      for(auto &entry:objects_[table.ref].fields){auto d=entry.second;if(!safeDataKey(entry.first)||d.kind!=Closure)return reject("MODULE_TABLE_NON_FACTORY",call);
        auto &c=closures_[d.ref];if(c.isClass||c.methodOwner||!plainFunction(c.function,3)||
            c.function->getDefinitionKind()==Function::DefinitionKind::ES6Arrow||c.function->getDefinitionKind()==Function::DefinitionKind::ES6Constructor)
          return reject("MODULE_FACTORY_KIND_OR_ARITY",call);}
      LoaderState state;state.registry=table.ref;state.cache=cache.ref;found=loaderStates_.emplace(closure,std::move(state)).first;
    }
    auto &state=found->second;if(state.registry!=table.ref||state.cache!=cache.ref)return reject("MODULE_LOADER_BINDING_CHANGED",call);
    auto old=state.entries.find(name);
    if(old!=state.entries.end()){
      auto actual=objects_[cache.ref].fields.find(name);
      if(actual==objects_[cache.ref].fields.end()||actual->second.kind!=Record||actual->second.ref!=old->second.record)
        return reject("MODULE_CACHE_ENTRY_IDENTITY_CHANGED",call);
      if(!old->second.complete)return reject("MODULE_ACTIVE_CYCLE",call);
      ++cacheHits_;Datum d=objects_[old->second.record].fields["exports"];moduleEdge(d,call);
      llvh::outs()<<"[MODULE_REQUIRE] event="<<moduleRequires_<<" closure="<<closure<<" registry="<<table.ref<<" cache="<<cache.ref
        <<" module="<<old->second.record<<" exports="<<d.ref<<" key_hex="<<keyHex(name)<<" state=HIT call="<<id(call)<<"\n";
      if(d.kind==Record){d.moduleDataRoot=d.ref;d.moduleDataDepth=0;d.moduleKeyEvent=0;}
      return d;
    }
    if(objects_[cache.ref].fields.count(name))return reject("MODULE_CACHE_ENTRY_WITHOUT_STATE",call);
    auto factory=objects_[table.ref].fields.find(name);if(factory==objects_[table.ref].fields.end())return reject("MODULE_FACTORY_MISSING",call);
    if(!moduleFactoryValue(factory->second))return reject("MODULE_CURRENT_FACTORY_KIND_OR_ARITY",call);
    bool registered=registeredKeys_[table.ref].count(name)!=0;
    if(registered){++registryReads_;llvh::outs()<<"[MODULE_REGISTRY_READ] event="<<registryReads_<<" loader="<<closure<<" registry="<<table.ref
      <<" key_hex="<<keyHex(name)<<" factory="<<factory->second.ref<<" factory_environment="<<closures_[factory->second.ref].environment
      <<" call="<<id(call)<<"\n";}
    if(nextObject_+1>192||state.entries.size()>=32)return reject("MODULE_OBJECT_OR_ENTRY_LIMIT",call);
    unsigned record=nextObject_++,exports=nextObject_++;moduleRecords_.insert(record);exportObjects_.insert(exports);
    putOwn(record,"exports",make(Record,exports));putOwn(cache.ref,name,make(Record,record));state.entries[name]={record,false};
    Datum receiver=make(Record,cert.viaCall?exports:table.ref);
    llvh::outs()<<"[MODULE_REQUIRE] event="<<moduleRequires_<<" closure="<<closure<<" registry="<<table.ref<<" cache="<<cache.ref<<" module="<<record
      <<" exports="<<exports<<" key_hex="<<keyHex(name)<<" state=MISS factory="<<factory->second.ref<<" receiver="<<receiver.ref
      <<" abi="<<(cert.viaCall?"CALL_EXPORTS":"DIRECT_REGISTRY")<<" call="<<id(call)<<" dispatch="<<id(cert.dispatch)<<"\n";
    if(registered)registeredExportObjects_.insert(exports);
    ++factoryCalls_;callClosure(factory->second.ref,{make(Record,record),make(Record,exports),make(Closure,closure)},receiver,cert.dispatch,
      false,false,true,false,false,0,false,false,false,registered);
    if(failed_)return {};
    if(suspended_)return reject("MODULE_FACTORY_ASYNC_EFFECT",call);
    state.entries[name].complete=true;Datum d=objects_[record].fields["exports"];
    if(registered){registryEdge(d,call);if(d.kind==Record)registeredExportObjects_.insert(d.ref);}
    moduleEdge(d,cert.returned);moduleEdge(d,call);
    if(d.kind==Record){d.moduleDataRoot=d.ref;d.moduleDataDepth=0;d.moduleKeyEvent=0;}
    return d;
  }
  Datum defineProperty(unsigned closure,const std::vector<Datum> &args,Datum self,CallInst *call,const PropertyCertificate &cert) {
    ++defineCalls_;
    const bool classTarget=args.size()==3&&exactClassOwnReceiver(args[0]);
    if(self.kind!=Undefined||closures_[closure].isClass||closures_[closure].methodOwner||args.size()!=3||
        (args[0].kind!=Record&&args[0].kind!=Instance&&!classTarget)||!args[1].knownString||!args[1].traces.empty()||
        !safeDataKey(args[1].string)||!primitive(args[2])||definedWrites_>=64)
      return reject("DEFINE_PROPERTY_RECEIVER_KEY_VALUE_OUTSIDE_PROFILE",call);
    Datum keyClosure=resolveHelperBinding(cert.keyBinding,closures_[closure].environment,call);
    if(failed_)return {};
    if(keyClosure.kind!=Closure||closures_[keyClosure.ref].isClass||closures_[keyClosure.ref].methodOwner)
      return reject("PROPERTY_KEY_CALLEE_IDENTITY",call);
    auto keyCertificate=keyCertificates_.find(closures_[keyClosure.ref].function);
    if(keyCertificate==keyCertificates_.end())return reject("PROPERTY_KEY_HELPER_NOT_CERTIFIED",call);
    Datum primitiveClosure=resolveHelperBinding(keyCertificate->second.primitiveBinding,closures_[keyClosure.ref].environment,call);
    if(failed_)return {};
    if(primitiveClosure.kind!=Closure||closures_[primitiveClosure.ref].isClass||closures_[primitiveClosure.ref].methodOwner||
        !primitiveStringCertificates_.count(closures_[primitiveClosure.ref].function))
      return reject("PRIMITIVE_STRING_CALLEE_NOT_CERTIFIED",call);
    if(classTarget){
      std::string exact;if(!classOwnKey(args[1],exact))return reject("CLASS_OWN_DEFINE_KEY",call);
      const bool existing=closures_[args[0].ref].ownFields.count(exact)!=0;
      Datum stored=args[2];edge(stored,call);
      edge(stored,existing?static_cast<Instruction *>(cert.defineCall):static_cast<Instruction *>(cert.store));
      classOwnWrite(args[0],args[1],stored,call,true);if(failed_)return {};
      ++definedWrites_;Datum returned=args[0];edge(returned,cert.returned);edge(returned,call);return returned;
    }
    auto &object=objects_[args[0].ref];const auto &name=args[1].string;
    if(args[0].kind==Record&&(registryObjects_.count(args[0].ref)||cacheObjects_.count(args[0].ref)||moduleRecords_.count(args[0].ref)))
      return reject("MODULE_ROLE_DESCRIPTOR_MUTATION",call);
    if(args[0].kind==Instance&&(!object.constructor||!closures_[object.constructor].isClass))
      return reject("DEFINE_PROPERTY_INSTANCE_NOT_CERTIFIED",call);
    bool existing=object.fields.count(name)||(args[0].kind==Instance&&closures_[object.constructor].methods.count(name));
    Datum stored=args[2];edge(stored,call);for(auto &t:stored.traces)t.property=true;
    edge(stored,existing?static_cast<Instruction *>(cert.defineCall):static_cast<Instruction *>(cert.store));
    putOwn(args[0].ref,name,stored);++definedWrites_;
    llvh::outs()<<"[DEFINE_PROPERTY_WRITE] object="<<args[0].ref<<" key_hex="<<keyHex(name)<<" branch="<<(existing?"DEFINE_OWN_DATA":"ASSIGN_NEW_DATA")
      <<" helper_closure="<<closure<<" key_closure="<<keyClosure.ref<<" primitive_closure="<<primitiveClosure.ref
      <<" call="<<id(call)<<" write="<<id(existing?static_cast<Instruction *>(cert.defineCall):static_cast<Instruction *>(cert.store))
      <<" source_traces="<<stored.traces.size()<<"\n";
                                                                             
    Datum returned=args[0];edge(returned,cert.returned);edge(returned,call);return returned;
  }
  static bool descriptorKey(const Datum &d,std::string &name) {
    if(!primitive(d)||!d.traces.empty())return false;
    if(d.knownString)name=d.string;else if(d.knownInteger)name=std::to_string(d.integer);else return false;
    return name=="__proto__"||safeDynamicKey(name);
  }
  bool descriptorRecord(const Datum &d) {
    return d.kind==Record&&objects_[d.ref].recordAllocation&&!forbiddenExportObject(d)&&
      !exportObjects_.count(d.ref)&&!handlerObjects_.count(d.ref);
  }
  void descriptorEdge(Datum &d,Instruction *at) {for(auto &t:d.traces)t.descriptor=true;edge(d,at);}
  Datum directDescriptor(const std::vector<Datum> &args,Datum receiver,CallInst *call) {
    auto *read=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
    auto candidate=descriptorCandidates_.find(read);std::string name;
    if(!read||candidate==descriptorCandidates_.end()||candidate->second!=call||receiver.kind!=ObjectIntrinsic||
        call->getArgument(0)!=read->getObject()||args.size()!=3||!descriptorRecord(args[0])||!descriptorRecord(args[2])||
        !descriptorKey(args[1],name)||descriptorWrites_>=64)return reject("DIRECT_DESCRIPTOR_RECEIVER_KEY_OR_IDENTITY",call);
    auto &descriptor=objects_[args[2].ref].fields;
    if(descriptor.size()!=4||!descriptor.count("value")||!primitive(descriptor["value"]))
      return reject("DIRECT_DESCRIPTOR_NOT_COMPLETE_PRIMITIVE_DATA",call);
    for(const char *flag:{"writable","enumerable","configurable"}){
      auto item=descriptor.find(flag);
      if(item==descriptor.end()||!item->second.knownBoolean||!item->second.boolean||!item->second.traces.empty())
        return reject("DIRECT_DESCRIPTOR_FLAG_NOT_EXACT_TRUE",call);
    }
    auto &fields=objects_[args[0].ref].fields;auto previous=fields.find(name);
    bool existing=previous!=fields.end();unsigned oldKind=existing?unsigned(previous->second.kind):unsigned(Invalid),oldRef=existing?previous->second.ref:0;
    Datum stored=descriptor["value"];descriptorEdge(stored,call);putOwn(args[0].ref,name,stored);descriptorKeys_[args[0].ref].insert(name);
    ++descriptorCalls_;++descriptorWrites_;
    llvh::outs()<<"[DESCRIPTOR_DATA_WRITE] event="<<descriptorWrites_<<" object="<<args[0].ref<<" descriptor="<<args[2].ref
      <<" key_hex="<<keyHex(name)<<" own_proto="<<(name=="__proto__"?1:0)<<" existed="<<(existing?1:0)
      <<" old_kind="<<oldKind<<" old_ref="<<oldRef<<" new_kind="<<unsigned(stored.kind)<<" new_ref="<<stored.ref
      <<" source_traces="<<stored.traces.size()<<" writable=true enumerable=true configurable=true"
      <<" returned_object="<<args[0].ref<<" call="<<id(call)<<"\n";
    Datum returned=args[0];edge(returned,call);return returned;
  }
  Datum descriptorRead(Datum object,const std::string &name,LoadPropertyInst *read) {
    if(!descriptorRecord(object)||!descriptorKeys_[object.ref].count(name)||descriptorReads_>=128)
      return reject("DIRECT_DESCRIPTOR_READ_IDENTITY",read);
    auto &fields=objects_[object.ref].fields;auto found=fields.find(name);
    if(found==fields.end()||!primitive(found->second))return reject("DIRECT_DESCRIPTOR_READ_NOT_OWN_PRIMITIVE",read);
    Datum result=found->second;descriptorEdge(result,read);++descriptorReads_;
    observeResult(descriptorReadObservations_[read],result);
    llvh::outs()<<"[DESCRIPTOR_DATA_READ] event="<<descriptorReads_<<" object="<<object.ref<<" key_hex="<<keyHex(name)
      <<" own_proto="<<(name=="__proto__"?1:0)<<" value_kind="<<unsigned(result.kind)<<" value_ref="<<result.ref
      <<" source_traces="<<result.traces.size()<<" read="<<id(read)<<"\n";
    return result;
  }
  Datum ownDataDelete(DeletePropertyInst *at,Frame &frame) {
    Datum object=value(at->getObject(),frame,at),property=value(at->getProperty(),frame,at);std::string name;
    if(failed_)return {};
    if(object.kind==Closure)return functionDelete(at,frame);
    if(!ownDeleteCandidates_.count(at)||!descriptorRecord(object)||!descriptorKey(property,name)||ownDeletes_>=128)
      return reject("OWN_DELETE_RECEIVER_KEY_OR_ROLE",at);
    auto &fields=objects_[object.ref].fields;auto old=fields.find(name);bool existed=old!=fields.end();
    if(name=="__proto__"&&existed&&!descriptorKeys_[object.ref].count(name))return reject("OWN_PROTO_DELETE_NOT_DATA_DESCRIPTOR",at);
    unsigned kind=existed?unsigned(old->second.kind):unsigned(Invalid),ref=existed?old->second.ref:0;
    unsigned oldTraces=existed?old->second.traces.size():0;
    eraseOwn(object.ref,name);descriptorKeys_[object.ref].erase(name);ownStateObjects_.insert(object.ref);++ownDeletes_;
    ownStateProofs_.emplace(object.ref,OwnStateProof{at,name,steps_});
    llvh::outs()<<"[OWN_DATA_DELETE] event="<<ownDeletes_<<" object="<<object.ref<<" key_hex="<<keyHex(name)
      <<" existed="<<(existed?1:0)<<" old_kind="<<kind<<" old_ref="<<ref<<" old_source_traces="<<oldTraces
      <<" own_proto="<<(name=="__proto__"?1:0)<<" result=true delete="<<id(at)<<"\n";
    Datum result=make(Primitive);result.knownBoolean=true;result.boolean=true;result.ownStateBoolean=true;
    observeResult(ownDeleteObservations_[at],result);return result;
  }
  Datum hasOwnData(const std::vector<Datum> &args,Datum receiver,CallInst *call) {
    auto *read=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());auto candidate=ownCheckCandidates_.find(read);std::string name;
    if(!read||candidate==ownCheckCandidates_.end()||candidate->second!=call||receiver.kind!=ObjectIntrinsic||
        call->getArgument(0)!=read->getObject()||args.size()!=2||!descriptorRecord(args[0])||!descriptorKey(args[1],name)||ownChecks_>=128)
      return reject("OWN_CHECK_RECEIVER_KEY_OR_INTRINSIC",call);
    auto own=objects_[args[0].ref].fields.find(name);bool present=own!=objects_[args[0].ref].fields.end();
    if(name=="__proto__"&&present&&!descriptorKeys_[args[0].ref].count(name))return reject("OWN_PROTO_CHECK_NOT_DATA_DESCRIPTOR",call);
    ownStateObjects_.insert(args[0].ref);++ownChecks_;
    ownStateProofs_.emplace(args[0].ref,OwnStateProof{call,name,steps_});
    llvh::outs()<<"[OWN_DATA_HAS] event="<<ownChecks_<<" object="<<args[0].ref<<" key_hex="<<keyHex(name)
      <<" present="<<(present?1:0)<<" value_kind="<<(present?unsigned(own->second.kind):unsigned(Invalid))
      <<" value_ref="<<(present?own->second.ref:0)<<" result="<<(present?"true":"false")<<" call="<<id(call)<<"\n";
    Datum result=make(Primitive);result.knownBoolean=true;result.boolean=present;result.ownStateBoolean=true;
    observeResult(ownCheckObservations_[call],result);return result;
  }
  Datum ownDataRead(Datum object,Datum property,LoadPropertyInst *at) {
    std::string name;if(!descriptorRecord(object)||!descriptorKey(property,name)||ownReads_>=256)
      return reject("OWN_STATE_READ_RECEIVER_OR_KEY",at);
    auto &fields=objects_[object.ref].fields;auto found=fields.find(name);bool present=found!=fields.end();
    if(name=="__proto__"&&(!present||!descriptorKeys_[object.ref].count(name)))return reject("OWN_STATE_READ_INHERITED_PROTO",at);
    Datum result=present?found->second:make(Undefined);
    if(!primitive(result))return reject("OWN_STATE_READ_NON_PRIMITIVE",at);
    ownStateEdge(result,at);++ownReads_;observeResult(ownReadObservations_[at],result);
    llvh::outs()<<"[OWN_DATA_READ] event="<<ownReads_<<" object="<<object.ref<<" key_hex="<<keyHex(name)
      <<" present="<<(present?1:0)<<" value_kind="<<unsigned(result.kind)<<" value_ref="<<result.ref
      <<" source_traces="<<result.traces.size()<<" read="<<id(at)<<"\n";return result;
  }
  static bool transportTrace(const Trace &trace) {
    return trace.iteration||trace.setter||trace.property||trace.module||trace.dynamic||trace.proxy||
      trace.functionProperty||trace.descriptor||trace.registry||trace.ownState||trace.dispatch||trace.enumeration;
  }
  void rememberOwnRead(Datum object,Datum property,Datum &result,LoadPropertyInst *at,unsigned invocation) {
                                                                             
                                                                              
    if((ownDeleteCandidates_.empty()&&ownCheckCandidates_.empty())||!primitive(result)||
        !descriptorRecord(object)||ownStateObjects_.count(object.ref))return;
    std::string name;if(!descriptorKey(property,name)||name=="__proto__")return;
    auto found=objects_[object.ref].fields.find(name);
    if(found==objects_[object.ref].fields.end()||!primitive(found->second))return;
    unsigned eligible=0;for(auto &trace:result.traces)if(!transportTrace(trace)){
      if(trace.deferredOwnReads.size()>=8){reject("OWN_DEFERRED_TRACE_LIMIT",at);return;}++eligible;
    }
    if(!eligible)return;
    if(deferredOwnReads_.size()>=256){reject("OWN_DEFERRED_READ_LIMIT",at);return;}
    unsigned event=deferredOwnReads_.size()+1;
    deferredOwnReads_.emplace(event,DeferredOwnRead{object.ref,name,at,invocation,steps_});
    for(auto &trace:result.traces)if(!transportTrace(trace))trace.deferredOwnReads.insert(event);
    llvh::outs()<<"[OWN_DATA_DEFERRED_READ] event="<<event<<" object="<<object.ref<<" key_hex="<<keyHex(name)
      <<" read="<<id(at)<<" invocation="<<invocation<<" step="<<steps_<<" source_traces="<<eligible<<"\n";
  }
  void promoteOwnReads(bool completed) {
    if(!completed||failed_)return;
    for(auto &saved:deferredOwnSinks_){
      auto &trace=saved.trace;
      if(!source(trace.source)||!sink(saved.sink)||!observedDateSources_.count(trace.source)||
          trace.path.empty()||trace.path.front()!=trace.source||trace.path.back()!=saved.sink)continue;
      auto sinkObservation=cookieObservations_.find(saved.sink);
      if(sinkObservation==cookieObservations_.end()||!sinkObservation->second.allPrimitive||
          !sinkObservation->second.sources.count(trace.source))continue;
      for(unsigned event:trace.deferredOwnReads){
        auto read=deferredOwnReads_.find(event);if(read==deferredOwnReads_.end())continue;
        auto &evidence=read->second;auto proof=ownStateProofs_.find(evidence.object);
        if(proof==ownStateProofs_.end()||!ownStateObjects_.count(evidence.object)||
            !descriptorRecord(make(Record,evidence.object))||evidence.step>saved.step||evidence.step>=proof->second.step||
            std::find(trace.path.begin(),trace.path.end(),evidence.read)==trace.path.end())continue;
        if(pending_.size()>=256){reject("PENDING_PATH_LIMIT",saved.sink);return;}
        pending_.emplace_back(trace.source,trace.path,saved.sink);++ownPromoted_;++ownTentative_;
        llvh::outs()<<"[OWN_DATA_PROMOTE] event="<<ownPromoted_<<" read_event="<<event<<" object="<<evidence.object
          <<" key_hex="<<keyHex(evidence.key)<<" source="<<id(trace.source)<<" read="<<id(evidence.read)
          <<" sink="<<id(saved.sink)<<" read_step="<<evidence.step<<" sink_step="<<saved.step
          <<" proof="<<id(proof->second.operation)<<" proof_key_hex="<<keyHex(proof->second.key)
          <<" proof_step="<<proof->second.step<<"\n";
        break;
      }
    }
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

  bool scopeWithin(unsigned env,unsigned root) const {
    for(unsigned depth=0;env&&depth<256;++depth){
      if(env==root)return true;
      auto p=environments_.find(env);if(p==environments_.end())return false;env=p->second.parent;
    }
    return false;
  }
  bool plainIterationRecord(const Datum &d) const {
    if(d.kind!=Record)return false;
    auto p=objects_.find(d.ref);
    if(p==objects_.end()||!p->second.recordAllocation||registryObjects_.count(d.ref)||cacheObjects_.count(d.ref)||
       moduleRecords_.count(d.ref)||handlerObjects_.count(d.ref))return false;
    for(const auto &field:p->second.fields)
      if(field.first=="__proto__"||field.first=="then"||field.second.kind==FreshGetterSlot)return false;
    return true;
  }
  Datum iterationField(Datum object,const std::string &name,Instruction *at) {
    if(!plainIterationRecord(object))return reject("ITERATOR_NON_DATA_RECORD",at);
    auto p=objects_[object.ref].fields.find(name);
    return p==objects_[object.ref].fields.end()?make(Undefined):p->second;
  }
  bool iterationCallable(const Datum &d) {
    if(ordinaryDataClosure(d))return true;
    if(d.kind!=Closure)return false;
    const auto &c=closures_[d.ref];auto *fn=c.function;
                                                                               
                                                                        
    return fn&&!c.isClass&&!c.methodOwner&&!fn->isLazy()&&!fn->empty()&&
      fn->getParameters().size()<=16&&llvh::isa<AsyncFunction>(fn)&&
      (fn->getDefinitionKind()==Function::DefinitionKind::ES5Function||
       fn->getDefinitionKind()==Function::DefinitionKind::ES6Method);
  }
  Datum iterationMethodCall(Datum method,Datum receiver,CallInst *at) {
    if(method.kind!=Closure||!iterationCallable(method)||!plainIterationRecord(receiver))
      return reject("ITERATOR_METHOD_RECEIVER_OR_CALLEE",at);
    return callClosure(method.ref,{},receiver,at,false,false,false,false,false,0,false,false,false,false,false,0,false,true);
  }
  Datum iterationSnapshot(Datum result,bool sync,CallInst *at) {
                                                                             
                                                                            
    if(sync&&result.kind==PromiseToken)return reject("SYNC_ITERATOR_PROMISE_RESULT_NOT_UNWRAPPED",at);
    if(result.kind==PromiseToken){
      auto p=promises_.find(result.ref);
      if(p==promises_.end()||!p->second.fulfilled)return reject("ITERATOR_PENDING_NEXT",at);
      result=p->second.value;
    }
    if(!plainIterationRecord(result))return reject("ITERATOR_RESULT_GETTER_OR_NON_OBJECT",at);
    Datum done=iterationField(result,"done",at);bool complete;
    if(failed_||!exactTruth(done,complete)||!done.traces.empty())return reject("ITERATOR_DONE_NOT_EXACT",at);
    Datum element=make(Undefined);
    if(sync||!complete){
      element=iterationField(result,"value",at);
      if(sync&&element.kind==PromiseToken){
        auto p=promises_.find(element.ref);
        if(p==promises_.end()||!p->second.fulfilled)return reject("ITERATOR_SYNC_VALUE_PENDING",at);
        element=p->second.value;
      }
                                                                      
      if(!primitive(element))return reject("ITERATOR_VALUE_OUTSIDE_PROFILE",at);
    }
    if(nextObject_>192)return reject("ITERATOR_RESULT_LIMIT",at);
    unsigned id=nextObject_++;edge(element,at);
    iterationResults_[id]={complete,element,at,nullptr,nullptr};iterationResults_[id].delay=sync?1:0;
    return make(AsyncIterationResult,id);
  }
  Datum iterationCall(Datum callee,const std::vector<Datum> &args,Datum receiver,CallInst *at,Frame &f) {
    if(receiver.kind!=Undefined)return reject("ITERATOR_INTRINSIC_RECEIVER",at);
    auto op=BuiltinMethod::Enum(callee.ref);
    if(op==BuiltinMethod::HermesBuiltin_asyncIterator){
      if(args.size()!=1||nextObject_>192)return reject("ITERATOR_CREATE_ARITY_OR_LIMIT",at);
      IterationState state;state.iterable=args[0];
      if(args[0].kind==Array){state.syncArray=true;state.receiver=args[0];}
      else {
        if(!plainIterationRecord(args[0]))return reject("ITERATOR_INPUT_NOT_CLOSED_DATA",at);
        auto p=iteratorSymbols_.find({args[0].ref,1});
        Datum method=p==iteratorSymbols_.end()?make(Undefined):p->second;
        if(method.kind==Undefined||method.kind==Null){
          state.syncRecord=true;p=iteratorSymbols_.find({args[0].ref,2});
          method=p==iteratorSymbols_.end()?make(Undefined):p->second;
        }
        state.receiver=iterationMethodCall(method,args[0],at);
        if(failed_||!plainIterationRecord(state.receiver))return reject("ITERATOR_FACTORY_RESULT",at);
        state.next=iterationField(state.receiver,"next",at);
      }
      unsigned id=nextObject_++;iterators_[id]=state;f.iteratorMode=true;++iteratorCreates_;
      llvh::outs()<<"[NATIVE_ASYNC_ITERATOR_CREATE] record="<<id<<" iterable="<<args[0].ref
        <<" receiver="<<state.receiver.ref<<" next_closure="<<state.next.ref<<" call="<<this->id(at)<<"\n";
      return make(AsyncIterationRecord,id);
    }
    if(args.empty()||args[0].kind!=AsyncIterationRecord||!iterators_.count(args[0].ref))
      return reject("ITERATOR_RECORD_IDENTITY",at);
    auto &state=iterators_[args[0].ref];f.iteratorMode=true;
    if(op==BuiltinMethod::HermesBuiltin_asyncIteratorNext){
      if(args.size()!=1||++iteratorNexts_>128)return reject("ITERATOR_NEXT_ARITY_OR_LIMIT",at);
      if(state.syncArray){
        auto &items=arrays_[state.receiver.ref].values;
        bool done=state.cursor>=items.size();Datum value=done?make(Undefined):items[state.cursor++];
        if(!primitive(value)||nextObject_>192)return reject("ITERATOR_ARRAY_ELEMENT_OR_LIMIT",at);
        unsigned id=nextObject_++;edge(value,at);iterationResults_[id]={done,value,at,nullptr,nullptr};iterationResults_[id].delay=1;
        return make(AsyncIterationResult,id);
      }
      Datum result=iterationMethodCall(state.next,state.receiver,at);
      return failed_?Datum{}:iterationSnapshot(result,state.syncRecord,at);
    }
    if(op!=BuiltinMethod::HermesBuiltin_asyncIteratorClose||args.size()!=2||!args[1].knownBoolean)
      return reject("ITERATOR_CLOSE_ARITY",at);
    ++iteratorCloses_;
    if(state.syncArray)return make(Undefined);
    Datum method=iterationField(state.receiver,"return",at);
    if(method.kind==Undefined||method.kind==Null)return make(Undefined);
    Datum result=iterationMethodCall(method,state.receiver,at);
    if(failed_)return {};
                                                                           
                                                                               
    if(result.kind==PromiseToken){auto p=promises_.find(result.ref);
      if(p==promises_.end()||!p->second.fulfilled)return reject("ITERATOR_CLOSE_PENDING",at);result=p->second.value;}
    if(!plainIterationRecord(result))return reject("ITERATOR_CLOSE_NON_DATA_RESULT",at);
    if(state.syncRecord){Datum snapshot=iterationSnapshot(result,true,at);if(failed_||snapshot.kind!=AsyncIterationResult)return {};}
    if(nextObject_>192)return reject("ITERATOR_CLOSE_RESULT_LIMIT",at);
    unsigned id=nextObject_++;iterationResults_[id]={true,make(Undefined),at,nullptr,nullptr};
    iterationResults_[id].delay=state.syncRecord?2:1;iterationResults_[id].closeOnly=true;
    return make(AsyncIterationResult,id);
  }
  Datum iterationValueRead(Datum object,Datum property,LoadPropertyInst *at) {
    auto p=iterationResults_.find(object.ref);
    if(p==iterationResults_.end()||!property.knownString||!property.traces.empty()||!p->second.resume||p->second.closeOnly)
      return reject("ITERATOR_RESULT_READ_BEFORE_EXACT_RESUME",at);
    if(property.string=="done"){Datum out=make(Primitive);out.knownBoolean=true;out.boolean=p->second.done;return out;}
    if(property.string!="value")return reject("ITERATOR_RESULT_UNKNOWN_FIELD",at);
    Datum out=p->second.value;edge(out,p->second.yield);edge(out,p->second.resume);
    for(auto &trace:out.traces){trace.awaited=true;trace.iteration=true;}
    edge(out,at);return out;
  }

  Datum globalRead(const std::string &name,Instruction *at) {
    auto p=globals_.find(name);if(p!=globals_.end()){Datum d=p->second;edge(d,at);return d;}
    if(declaredGlobals_.count(name))return reject("GLOBAL_BEFORE_INITIALIZATION",at);
    if(name=="Symbol"&&nativeIterationPresent_)return make(SymbolIntrinsic);
    if(name=="Date")return make(DateObject);
    if(name=="Proxy")return make(ProxyConstructor);
    if(name=="Object")return make(ObjectIntrinsic);
    if(name=="document")return make(AmbientDocument);
    if(name=="HermesES6Internal")return make(Helpers);
    return reject("AMBIENT_GLOBAL_UNRESOLVED",at);
  }
  Datum propertyRead(LoadPropertyInst *l,Frame &f) {
    ++readExecutions_[l];
    Datum property=value(l->getProperty(),f,l);
    Datum o=value(l->getObject(),f,l);if(failed_)return {};
    if(o.kind==AsyncIterationResult)return iterationValueRead(o,property,l);
    if(o.kind==SymbolIntrinsic){
      if(!property.knownString||!property.traces.empty())return reject("ITERATOR_SYMBOL_KEY",l);
      if(property.string=="asyncIterator")return make(IteratorSymbol,1);
      if(property.string=="iterator")return make(IteratorSymbol,2);
      return reject("ITERATOR_OTHER_SYMBOL_PROPERTY",l);
    }
    if(o.kind==ObjectIntrinsic){
      if(property.knownString&&property.traces.empty()&&property.string=="keys"&&objectKeysCandidates_.count(l))return make(ObjectKeysIntrinsic);
      if(property.knownString&&property.traces.empty()&&property.string=="hasOwn"&&ownCheckCandidates_.count(l))return make(HasOwnIntrinsic);
      if(!property.knownString||!property.traces.empty()||property.string!="defineProperty"||!descriptorCandidates_.count(l))
        return reject("OBJECT_INTRINSIC_PROPERTY_OUTSIDE_DESCRIPTOR",l);
      return make(DescriptorDefine);
    }
    if(o.kind==Record){std::string name;
      if(dataKey(property,name)){auto field=objects_[o.ref].fields.find(name);
        if(field!=objects_[o.ref].fields.end()&&field->second.kind==FreshGetterSlot)return readFreshGetter(o,name,l);}}
    if(o.kind==Record&&property.knownString&&property.traces.empty()&&property.string=="hasOwnProperty"){
      if(!recordHasCandidates_.count(l)||!descriptorRecord(o)||objects_[o.ref].fields.count("hasOwnProperty"))
        return reject("RECORD_HAS_OWN_READ_SHADOW_OR_IDENTITY",l);
      return make(RecordHasOwnIntrinsic,o.ref);
    }
    if(o.kind==Record&&ownStateObjects_.count(o.ref)&&!f.enumerationMode)return ownDataRead(o,property,l);
    if(o.kind==Array&&enumerationSnapshots_.count(o.ref)){
      if(property.knownString&&property.traces.empty()&&property.string=="forEach")return make(KeysForEachIntrinsic,o.ref);
      if(property.knownString&&property.traces.empty()&&property.string=="length"){
        Datum d=make(Primitive);d.knownInteger=true;d.integer=arrays_[o.ref].values.size();return d;}
      if(!property.knownInteger||!property.traces.empty()||property.integer<0||unsigned(property.integer)>=arrays_[o.ref].values.size())
        return reject("ENUM_SNAPSHOT_READ_OUTSIDE_PROFILE",l);
      Datum d=arrays_[o.ref].values[unsigned(property.integer)];edge(d,l);return d;
    }
    if(o.kind==Record){std::string descriptorName;
      if(descriptorKey(property,descriptorName)&&descriptorKeys_[o.ref].count(descriptorName))return descriptorRead(o,descriptorName,l);
      if(property.knownString&&property.string=="__proto__")return reject("PROTO_READ_WITHOUT_PROVEN_OWN_DATA",l);
    }
    if(o.kind==Closure){
      if(closures_[o.ref].isClass)return classOwnRead(o,property,l);
      if(property.knownString&&property.traces.empty()&&property.string=="apply"&&f.proxyInvocation&&f.proxyTrap){
        auto &context=proxyInvocations_[f.proxyInvocation];
        if(o.ref!=context.target)return reject("PROXY_FORWARD_TARGET_IDENTITY",l);
        return make(TargetApply,o.ref);
      }
      return functionRead(o,property,l);
    }
    if(o.kind==Array&&f.proxyInvocation&&f.proxyTrap&&o.ref==proxyInvocations_[f.proxyInvocation].array){
      if(!property.knownInteger||!property.traces.empty()||property.integer<0||unsigned(property.integer)>=arrays_[o.ref].values.size())
        return reject("PROXY_ARGUMENT_ARRAY_READ_OUTSIDE_PROFILE",l);
      Datum d=arrays_[o.ref].values[unsigned(property.integer)];proxyEdge(d,l);return d;
    }
    std::string name;
    if(o.kind==Record&&key(l->getProperty()).empty()&&(nestedCacheFunctions_.count(f.function)||f.enumerationMode||dynamicObjects_.count(o.ref)||property.knownInteger)){
      if(!dataKey(property,name))return reject("DYNAMIC_DATA_READ_KEY",l);}
    else {if(!property.knownString||!property.traces.empty())return reject("DYNAMIC_PROPERTY_READ",l);name=property.string;}
    if(o.kind==Global){Datum d=globalRead(name,l);if(f.dynamicContext)dynamicEdge(d,l);if(f.proxyInvocation)proxyEdge(d,l);if(f.functionContext)functionEdge(d,l);if(f.registryContext)registryEdge(d,l);if(f.ownControl)ownStateEdge(d,l);if(f.dispatchContext||f.dispatchControl)dispatchEdge(d,l);if(f.enumerationSnapshot)enumerationEdge(d,l);return d;}
    if(o.kind==DateObject&&name=="now")return make(DateNow);
    if(o.kind==Helpers){
      if(name=="defineClass")return make(DefineClass);
      if(name=="defineClassMethod")return make(DefineMethod);
    }
    if(o.kind==Record){
      auto &fields=objects_[o.ref].fields;auto found=fields.find(name);
      if(found==fields.end()){
        if(f.enumerationMode&&descriptorRecord(o)&&safeDynamicKey(name))return make(Undefined);
        return reject("RECORD_READ_NOT_OWN",l);}
      Datum d=found->second;
      if(nestedAliasOperands_.count(l)){
        if((!descriptorRecord(o)&&!exportObjects_.count(o.ref))||forbiddenExportObject(o)||!safeDynamicKey(name)||nestedAliasOperandReads_>=256)
          return reject("NESTED_ALIAS_OPERAND_OBJECT_OR_LIMIT",l);
        ++nestedAliasOperandReads_;
        llvh::outs()<<"[NESTED_ALIAS_OPERAND] event="<<nestedAliasOperandReads_<<" invocation="<<f.invocation<<" object="<<o.ref
          <<" key_hex="<<keyHex(name)<<" value_kind="<<unsigned(d.kind)<<" value_ref="<<d.ref<<" source_traces="<<d.traces.size()<<" read="<<id(l)<<"\n";
      }
      auto registration=nestedAliasSlots_.find({o.ref,name});
      if(registration!=nestedAliasSlots_.end()){
        if(!descriptorRecord(o)||!primitive(d)||nestedAliasReads_>=256)return reject("NESTED_ALIAS_READ_IDENTITY_OR_VALUE",l);
        dynamicEdge(d,l);++nestedAliasReads_;
        llvh::outs()<<"[NESTED_ALIAS_READ] event="<<nestedAliasReads_<<" registration="<<registration->second<<" invocation="<<f.invocation
          <<" object="<<o.ref<<" key_hex="<<keyHex(name)<<" value_kind="<<unsigned(d.kind)<<" value_ref="<<d.ref
          <<" source_traces="<<d.traces.size()<<" read="<<id(l)<<"\n";
      }
      if(nestedCacheFunctions_.count(f.function)){
        if(!descriptorRecord(o)||!safeDynamicKey(name)||(!primitive(d)&&!closedNestedData(d))||nestedCacheReadsCount_>=256)
          return reject("NESTED_CACHE_READ_IDENTITY_OR_VALUE",l);
        dispatchEdge(d,l);++nestedCacheReadsCount_;
        llvh::outs()<<"[NESTED_CACHE_READ] event="<<nestedCacheReadsCount_<<" invocation="<<f.invocation<<" object="<<o.ref
          <<" key_hex="<<keyHex(name)<<" value_kind="<<unsigned(d.kind)<<" value_ref="<<d.ref<<" read="<<id(l)<<"\n";
      }
      if(f.enumerationMode&&descriptorRecord(o)){
        if(!safeDynamicKey(name)||(!primitive(d)&&!ordinaryDataClosure(d)&&!enumerationData(d)))return reject("ENUM_CURRENT_SLOT_VALUE",l);
        unsigned snapshot=property.enumerationSnapshot?property.enumerationSnapshot:f.enumerationSnapshot;
        if(ordinaryDataClosure(d)&&snapshot){d.dynamicClosure=true;d.enumerationClosure=true;d.enumerationSnapshot=snapshot;}
        if(snapshot){if(enumerationReads_>=256)return reject("ENUM_READ_LIMIT",l);++enumerationReads_;
          llvh::outs()<<"[ENUM_READ] event="<<enumerationReads_<<" snapshot="<<snapshot<<" object="<<o.ref<<" key_hex="<<keyHex(name)
            <<" value_kind="<<unsigned(d.kind)<<" value_ref="<<d.ref<<" read="<<id(l)<<"\n";}
        if(snapshot)enumerationEdge(d,l);
      }
      readModuleData(o,name,d,l);if(failed_)return {};
      unsigned keyEvent=property.moduleKeyEvent;
      if(d.dispatchRegistration){
        auto registration=dispatchRegistrations_.find(d.dispatchRegistration);
        if(registration==dispatchRegistrations_.end()||registration->second.table!=o.ref||registration->second.key!=name||
            d.kind!=Closure||d.ref!=registration->second.closure)return reject("MODULE_DISPATCH_READ_IDENTITY",l);
        if(!keyEvent)keyEvent=registration->second.keyEvent;
      }
      d.dispatchSelection=0;
      if(keyEvent&&ordinaryDataClosure(d)){
        auto proof=moduleKeyReads_.find(keyEvent);
        if(!descriptorRecord(o)||proof==moduleKeyReads_.end()||proof->second.value!=name||dispatchReads_>=256)
          return reject("MODULE_DISPATCH_SELECTION_IDENTITY",l);
        unsigned event=++dispatchReads_;dispatchSelections_.emplace(event,DispatchSelection{o.ref,d.ref,keyEvent,d.dispatchRegistration,name,l});
        d.dispatchSelection=event;d.dynamicClosure=true;
        llvh::outs()<<"[MODULE_DISPATCH_READ] event="<<event<<" registration="<<d.dispatchRegistration<<" key_event="<<keyEvent
          <<" table="<<o.ref<<" key_hex="<<keyHex(name)<<" closure="<<d.ref<<" environment="<<closures_[d.ref].environment<<" read="<<id(l)<<"\n";
      }
      rememberOwnRead(o,property,d,l,f.invocation);if(failed_)return {};
      if(f.dynamicContext)dynamicEdge(d,l);
      if(f.proxyInvocation)proxyEdge(d,l);
      if(exportObjects_.count(o.ref))moduleEdge(d,l);
      if(registeredExportObjects_.count(o.ref)||f.registryContext)registryEdge(d,l);
      if(f.setterReceiver&&f.receiver.kind==Record&&f.receiver.ref==o.ref){
        for(auto &t:d.traces)t.setter=true;edge(d,f.entry);}
      edge(d,l);return d;
    }
    if(o.kind==SetterObject&&name=="_")return make(Undefined);
    if(o.kind==Instance){
      auto &object=objects_[o.ref];auto p=object.fields.find(name);
      if(p!=object.fields.end()){Datum d=p->second;
        if(f.dynamicContext)dynamicEdge(d,l);
        if(f.setterReceiver&&f.receiver.kind==Instance&&f.receiver.ref==o.ref){
          for(auto &t:d.traces)t.setter=true;edge(d,f.entry);}
        edge(d,l);return d;}
      auto &ctor=closures_[object.constructor];auto m=ctor.methods.find(name);
      if(m!=ctor.methods.end())return make(Closure,m->second);
      return reject("INSTANCE_PROPERTY_NOT_OWN_OR_CERTIFIED_METHOD",l);
    }
    return reject("PROPERTY_GETTER_OR_ALIAS_OUTSIDE_PROFILE",l);
  }
  Datum storeProperty(StorePropertyInst *s,Frame &f) {
    const auto name=key(s->getProperty());Datum o=value(s->getObject(),f,s),d=value(s->getStoredValue(),f,s);
    if(failed_)return {};
    if(nativeIterationPresent_&&iteratorWriteCandidates_.count(s)){
      Datum property=value(s->getProperty(),f,s);
      if(plainIterationRecord(o)&&property.kind==IteratorSymbol&&
          (iterationCallable(d)||d.kind==Undefined||d.kind==Null)){
        iteratorSymbols_[{o.ref,property.ref}]=d;return make(Undefined);
      }
      if(plainIterationRecord(o)&&property.knownString&&property.traces.empty()&&
          (property.string=="next"||property.string=="return"||property.string=="throw")&&
          (iterationCallable(d)||d.kind==Undefined||d.kind==Null)){
        putOwn(o.ref,property.string,d);return make(Undefined);
      }
      return reject("ITERATOR_METHOD_WRITE_NOT_EXACT_DATA",s);
    }
    if(o.kind==Record){std::string exact;Datum property=value(s->getProperty(),f,s);
      if(dataKey(property,exact)&&freshGetters_.count({o.ref,exact}))return reject("FRESH_GETTER_ASSIGNMENT_UNSUPPORTED",s);}
    if(o.kind==Array&&enumerationSnapshots_.count(o.ref))return reject("ENUM_SNAPSHOT_MUTATION",s);
    if(handlerWriteCandidates_.count(s))return handlerApplyWrite(o,d,s);
    if(o.kind==Closure){
      Datum property=value(s->getProperty(),f,s);
      if(closures_[o.ref].isClass)return classOwnWrite(o,property,d,s,false);
      return functionStore(o,property,d,s);
    }
    if(o.kind==Record&&registryObjects_.count(o.ref)&&registryWriteCandidates_.count(s))return registerFactory(s,f,o,d);
    if(nestedCacheWrites_.count(s))return nestedCacheStore(s,f,o,d);
    if(nestedAliasCandidates_.count(s))return nestedAliasStore(s,f,o,d);
    if(enumerationWriteCandidates_.count(s)&&f.enumerationMode&&
        (f.enumerationSnapshot||!localDataOperand(s->getObject(),f.function,false)||enumerationData(d,o.ref)))return enumerationStore(s,f,o,d);
    bool blockedNonRegistry=name.empty()||hostName(name)||name=="__proto__"||name=="prototype"||name=="constructor"||
      name=="now"||name=="then"||name=="resolve"||name=="apply"||name=="call"||name=="next"||name=="throw"||name=="return";
    if(registryWriteCandidates_.count(s)&&!dynamicWriteCandidates_.count(s)&&blockedNonRegistry)
      return reject("REGISTRY_CANDIDATE_NOT_ACTUAL_TABLE",s);
    if(dynamicWriteCandidates_.count(s)||moduleKeyWriteCandidates_.count(s)||((d.kind==Closure||knownProxy(d))&&localDataOperand(s->getObject(),f.function,false)&&!name.empty()))
      return dataStore(s,f,o,d);
    if(o.kind==SetterObject){
      if(name!="_"||!primitive(d)||setterWrites_>=64)return reject("SETTER_WRITE_OUTSIDE_PROFILE",s);
      auto &st=setters_[o.ref];auto &items=arrays_[st.array].values;
      if(st.slot>=items.size())return reject("SETTER_RESERVED_SLOT_LOST",s);
      edge(d,s);edge(d,st.certificate.slotWrite);items[st.slot]=d;
      std::vector<Datum> actual=items;
      for(auto &a:actual){if(!primitive(a))return reject("SETTER_APPLY_ARGUMENT_OUTSIDE_PROFILE",s);
        for(auto &t:a.traces)t.setter=true;edge(a,st.certificate.apply);}
      ++setterWrites_;
      llvh::outs()<<"[TO_SETTER_APPLY] object="<<o.ref<<" array="<<st.array<<" slot="<<st.slot
        <<" closure="<<st.closure<<" receiver="<<st.receiver.ref<<" write="<<id(s)
        <<" apply="<<id(st.certificate.apply)<<" arguments="<<actual.size()<<"\n";
      callClosure(st.closure,actual,st.receiver,st.certificate.apply,false,true);
      return failed_?Datum{}:make(Undefined);
    }
    if(o.kind==Record){
      if(registryObjects_.count(o.ref)||cacheObjects_.count(o.ref))return reject("MODULE_REGISTRY_OR_CACHE_MUTATION",s);
      if(moduleRecords_.count(o.ref)){
        if(name!="exports"||(!primitive(d)&&d.kind!=Record)||forbiddenExportObject(d))return reject("MODULE_EXPORTS_REPLACEMENT_OUTSIDE_PROFILE",s);
        if(d.kind==Record)exportObjects_.insert(d.ref);moduleEdge(d,s);putOwn(o.ref,name,d);
        llvh::outs()<<"[MODULE_EXPORTS_WRITE] module="<<o.ref<<" exports="<<d.ref<<" write="<<id(s)<<" source_traces="<<d.traces.size()<<"\n";
        return make(Undefined);
      }
      if(exportObjects_.count(o.ref)&&f.moduleFactory&&safeDynamicKey(name)&&closedNestedData(d,o.ref)){
        edge(d,s);putOwn(o.ref,name,d);
        llvh::outs()<<"[MODULE_DATA_EXPORT_WRITE] root="<<o.ref<<" key_hex="<<keyHex(name)<<" value="<<d.ref<<" write="<<id(s)<<"\n";
        return make(Undefined);
      }
      if(name.empty()||name=="__proto__"||name=="constructor"||!primitive(d))
        return reject("RECORD_WRITE_OUTSIDE_PROFILE",s);
      if(exportObjects_.count(o.ref))moduleEdge(d,s);
      edge(d,s);putOwn(o.ref,name,d);return make(Undefined);
    }
    if(o.kind==Global){
      if(f.function!=global_||name.empty()||!declaredGlobals_.count(name)||hostName(name)||
          (!primitive(d)&&d.kind!=Closure&&d.kind!=Array&&d.kind!=Record&&d.kind!=Instance&&d.kind!=SetterObject&&d.kind!=IteratorSymbol&&!knownProxy(d)))return reject("GLOBAL_WRITE_OUTSIDE_PROFILE",s);
      if(suspended_&&(globals_.count(name)||d.kind!=Closure))return reject("GLOBAL_MUTATION_AFTER_SUSPENSION",s);
      edge(d,s);globals_[name]=d;return make(Undefined);
    }
    if(o.kind==Instance){
      if(!f.constructor||f.receiver.kind!=Instance||f.receiver.ref!=o.ref||
          objects_[o.ref].constructor!=f.constructor||!primitive(d)||name.empty()||name=="__proto__"||
          name=="constructor"||closures_[f.constructor].methods.count(name))
        return reject("INSTANCE_WRITE_OUTSIDE_FRESH_CONSTRUCTOR",s);
      edge(d,s);putOwn(o.ref,name,d);return make(Undefined);
    }
    if(o.kind!=AmbientDocument||name!="cookie"||!sink(s)||!primitive(d))return reject("UNKNOWN_PROPERTY_EFFECT",s);
    if(f.registryContext)registryEdge(d,s);
    if(f.enumerationSnapshot)enumerationEdge(d,s);
    if(f.ownControl)ownStateEdge(d,s);if(f.dispatchContext||f.dispatchControl)dispatchEdge(d,s);
                                                                          
                                                                             
                                                                            
                                                                   
    if(nativeIterationPresent_&&f.iteratorMode)for(auto &trace:d.traces)trace.iteration=true;
    edge(d,s);
    observeResult(cookieObservations_[s],d);
    for(auto &t:d.traces)if(source(t.source)&&!t.path.empty()&&t.path.front()==t.source){
      if(transportTrace(t)){
        if(pending_.size()+deferredOwnSinks_.size()>=256)return reject("PENDING_PATH_LIMIT",s);
        pending_.emplace_back(t.source,t.path,s);if(t.property)++propertyTentative_;if(t.module)++moduleTentative_;if(t.dynamic)++dynamicTentative_;if(t.proxy)++proxyTentative_;if(t.functionProperty)++functionTentative_;if(t.descriptor)++descriptorTentative_;if(t.registry)++registryTentative_;if(t.ownState)++ownTentative_;if(t.dispatch)++dispatchTentative_;if(t.enumeration)++enumerationTentative_;
      }else if(!t.deferredOwnReads.empty()){
        if(pending_.size()+deferredOwnSinks_.size()>=256)return reject("OWN_DEFERRED_SINK_LIMIT",s);
        deferredOwnSinks_.push_back({t,s,steps_});
        llvh::outs()<<"[OWN_DATA_DEFERRED_SINK] event="<<deferredOwnSinks_.size()<<" source="<<id(t.source)
          <<" sink="<<id(s)<<" origin="<<t.origin<<" step="<<steps_<<" read_events=";
        bool first=true;for(unsigned event:t.deferredOwnReads){if(!first)llvh::outs()<<",";llvh::outs()<<event;first=false;}llvh::outs()<<"\n";
      }
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
        else {
          auto *c=llvh::dyn_cast<CreateFunctionInst>(s->getValue());auto p=hoists.find(c);
          if(!c||p==hoists.end()){reject("CERTIFIED_HOIST_INITIALIZATION_MISSING",s);return;}
          environments_[env].vars[s->getVariable()]=p->second;
        }
      }
    }
  }
  Datum callClosure(unsigned closure,const std::vector<Datum> &args,Datum receiver,CallInst *call,bool constructing=false,bool setterApply=false,bool moduleFactory=false,bool dynamicCall=false,bool dynamicContext=false,unsigned proxyInvocation=0,bool proxyTrap=false,bool functionContext=false,bool functionMember=false,bool registryContext=false,bool dispatchContext=false,unsigned enumerationSnapshot=0,bool enumerationCallback=false,bool iteratorInvocation=false) {
    auto &c=closures_[closure];Function *target=c.function;
    if(!target||target->isLazy()||target->empty()||active_.count(target)||active_.size()>=8||++invocations_>64)
      return reject("CALL_RECURSION_OR_LIMIT",call);
    ++exactClosureCalls_[closure];++exactFunctionCalls_[target];
    if(target->getParameters().size()>16||args.size()>16)return reject("ARGUMENT_LIMIT",call);
    if(c.isClass!=constructing)return reject("CONSTRUCTOR_CALL_KIND",call);
    if(c.methodOwner){
      auto *load=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
      if((!setterApply&&(!load||call->getArgument(0)!=load->getObject()))||receiver.kind!=Instance||
          objects_[receiver.ref].constructor!=c.methodOwner)return reject("METHOD_RECEIVER_IDENTITY",call);
    }else if(!constructing&&!moduleFactory&&!dynamicCall&&!proxyInvocation&&!functionMember&&!enumerationCallback&&!iteratorInvocation&&receiver.kind!=Undefined&&
        !(setterApply&&(receiver.kind==Null||receiver.kind==Record||receiver.kind==Instance)))
      return reject("ORDINARY_RECEIVER_OUTSIDE_PROFILE",call);
    if(setterApply)++setterCalls_;
    Frame f;f.function=target;f.entry=call;f.invocation=invocations_;f.receiver=receiver;f.arguments=args;
    f.setterReceiver=setterApply;
    f.iteratorMode=iteratorInvocation||iteratorFunctions_.count(target);
    f.moduleFactory=moduleFactory;
    f.dynamicContext=dynamicCall||dynamicContext;
    f.proxyInvocation=proxyInvocation;f.proxyTrap=proxyTrap;
    f.functionContext=functionContext;
    f.registryContext=registryContext;
    f.dispatchContext=dispatchContext;
    f.enumerationSnapshot=enumerationSnapshot;f.enumerationCallback=enumerationCallback;
    f.enumerationMode=enumerationSnapshot||enumerationFunctions_.count(target);
    bool ordinaryBoundary=!constructing&&!setterApply&&!moduleFactory&&!proxyInvocation&&!dynamicCall&&ordinaryDataClosure(make(Closure,closure));
    bool callbackBoundary=false;
                                                                             
                                                                              
                                                         
    if((receiver.kind==Undefined||receiver.kind==Null)&&!target->isStrictMode())f.receiver=make(OpaqueGlobalThis);
    if(enumerationCallback&&target->getDefinitionKind()==Function::DefinitionKind::ES6Arrow)f.receiver=make(OpaqueGlobalThis);
    f.parent=c.environment;f.constructor=constructing?closure:0;
    for(unsigned n=0;n<f.arguments.size();++n){auto &a=f.arguments[n];
      if(!primitive(a)&&a.kind!=Record&&a.kind!=Instance&&!(moduleFactory&&n==2&&a.kind==Closure&&moduleCertificates_.count(closures_[a.ref].function))&&
          !((ordinaryDataClosure(a)||knownProxy(a))&&closureFormalFeedsDataWrite(target,n))&&
          !(ordinaryBoundary&&moduleFactoryValue(a)&&closureFormalFeedsRegistryWrite(target,n))&&
          !(ordinaryDataClosure(a)&&formalFeedsProxyTarget(target,n))&&
          !(ordinaryBoundary&&ordinaryDataClosure(a)&&(formalFeedsCallback(target,n)||formalFeedsFunctionReceiver(target,n)))&&
          !(proxyTrap&&proxyInvocation&&n==0&&a.kind==Closure&&a.ref==proxyInvocations_[proxyInvocation].target)&&
          !(proxyTrap&&proxyInvocation&&n==2&&a.kind==Array&&a.ref==proxyInvocations_[proxyInvocation].array)&&
          !(enumerationCallback&&n==2&&a.kind==Array&&a.ref==enumerationSnapshot&&enumerationSnapshots_.count(a.ref)))return reject("NON_PRIMITIVE_ARGUMENT",call);
      if(ordinaryBoundary&&ordinaryDataClosure(a)&&formalFeedsCallback(target,n)){
        a.callbackClosure=true;callbackBoundary=true;f.functionContext=true;
        llvh::outs()<<"[FUNCTION_CALLBACK_BIND] invocation="<<f.invocation<<" caller="<<id(call)<<" callee="<<closure
          <<" callee_environment="<<c.environment<<" formal="<<n<<" callback="<<a.ref
          <<" callback_environment="<<closures_[a.ref].environment<<" receiver="<<receiver.ref
          <<" receiver_kind="<<unsigned(receiver.kind)<<"\n";
      }
      if(proxyInvocation)proxyEdge(a,call);if(f.functionContext)functionEdge(a,call);if(f.registryContext)registryEdge(a,call);if(f.dispatchContext)dispatchEdge(a,call);if(f.enumerationSnapshot)enumerationEdge(a,call);edge(a,call);}
    if(auto *async=llvh::dyn_cast<AsyncFunction>(target)){
      auto found=bindings_.find(async);if(found==bindings_.end())found=bindings_.emplace(async,recognize(async)).first;
      Binding &b=found->second;if(!b.valid)return reject(b.reason,call);
      if(constructing||c.isClass)return reject("ASYNC_CONSTRUCTOR",call);
                                                                             
                                                                               
                                                                 
      unsigned wrapperEnv=environment(b.wrapper,c.environment);
      unsigned generatorEnv=environment(b.generator,wrapperEnv);
      initializeCertifiedScope(b.wrapper,wrapperEnv);initializeCertifiedScope(b.generator,generatorEnv);
      if(failed_)return {};
      f.function=b.inner;f.iteratorMode=f.iteratorMode||iteratorFunctions_.count(b.inner);f.parent=generatorEnv;f.environment=environment(b.inner,generatorEnv);
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
    unsigned callbacksBefore=callbackCalls_;
    active_.insert(target);Datum d=execute(f,&target->front());active_.erase(target);
    if(failed_)return {};
    if(constructing){if(d.kind!=Undefined)return reject("CONSTRUCTOR_NON_UNDEFINED_RETURN",call);return receiver;}
    if(!primitive(d)&&d.kind!=Closure&&d.kind!=Record&&d.kind!=Instance&&!knownProxy(d))return reject("ORDINARY_RETURN_OBJECT_OR_PROMISE",call);
    if(callbackBoundary&&callbackCalls_>callbacksBefore)functionResultSites_.insert(call);
    edge(d,call);return d;
  }
                                                                           
                                                                            
                                                                                
                                                                                
  bool classDefinitionReceiverAllowed(const Frame &f) const {
    if(f.receiver.kind==Undefined)return true;
    auto *entry=llvh::dyn_cast_or_null<CallInst>(f.entry);
    if(f.receiver.kind!=OpaqueGlobalThis||!f.function||!entry||
        f.function->isStrictMode()||!f.arguments.empty()||
        !f.function->getParameters().empty()||
        f.function->getDefinitionKind()!=Function::DefinitionKind::ES5Function||
        llvh::isa<AsyncFunction>(f.function)||llvh::isa<GeneratorFunction>(f.function)||
        llvh::isa<GeneratorInnerFunction>(f.function)||
        !f.function->getThisParameter()->getUsers().empty()||
        llvh::isa<ConstructInst>(entry)||entry->getNumArguments()!=1||
        !llvh::isa<LiteralUndefined>(entry->getNewTarget())||
        !llvh::isa<LiteralUndefined>(entry->getArgument(0)))return false;
    auto *creation=llvh::dyn_cast<CreateFunctionInst>(entry->getCallee());
    auto count=creationCounts_.find(f.function);
    if(!creation||llvh::isa<CreateGeneratorInst>(creation)||
        creation->getFunctionCode()!=f.function||
        creation->getParent()->getParent()!=entry->getParent()->getParent()||
        count==creationCounts_.end()||count->second!=1)return false;
    for(auto &block:*f.function)
      for(auto &instruction:block)
        if(llvh::isa<CreateArgumentsInst>(&instruction))return false;
    return true;
  }
  Datum invoke(CallInst *call,Frame &f) {
    ++callExecutions_[call];
    if(auto *builtin=llvh::dyn_cast<CallBuiltinInst>(call)){
      if(f.iteratorMode&&builtin->getBuiltinIndex()==BuiltinMethod::HermesBuiltin_ensureObject&&call->getNumArguments()==3){
        Datum d=value(call->getArgument(1),f,call);
        if(d.kind==AsyncIterationResult||plainIterationRecord(d))return d;
        return reject("ITERATOR_ENSURE_NON_OBJECT",call);
      }
    }
    if(llvh::isa<CallBuiltinInst>(call)||call->getNumArguments()<1||call->getNumArguments()>17)
      return reject("CALL_KIND_OR_ARITY",call);
    Datum callee=value(call->getCallee(),f,call),receiver=value(call->getArgument(0),f,call);
    std::vector<Datum> args;for(unsigned n=1;n<call->getNumArguments();++n)args.push_back(value(call->getArgument(n),f,call));
    if(failed_)return {};
    if(auto *construct=llvh::dyn_cast<ConstructInst>(call)){
      if(callee.kind==ProxyConstructor)return constructProxy(construct,args,receiver);
      if(callee.kind!=Closure||!closures_[callee.ref].isClass||call->getNewTarget()!=call->getCallee()||
          receiver.kind!=Undefined||nextObject_>64||(f.function==global_&&suspended_))
        return reject("CONSTRUCT_IDENTITY_OR_TIMING",call);
      unsigned object=nextObject_++;objects_[object].constructor=callee.ref;objects_[object].allocation=construct;
      return callClosure(callee.ref,args,make(Instance,object),call,true);
    }
    if(!llvh::isa<LiteralUndefined>(call->getNewTarget()))return reject("CALL_NEWTARGET",call);
    if(callee.kind==AsyncIterationIntrinsic)return iterationCall(callee,args,receiver,call,f);
    if(callee.kind==HasOwnIntrinsic)return hasOwnData(args,receiver,call);
    if(callee.kind==ObjectKeysIntrinsic)return objectKeys(args,receiver,call);
    if(callee.kind==KeysForEachIntrinsic)return keysForEach(args,callee,receiver,call);
    if(callee.kind==RecordHasOwnIntrinsic)return inheritedRecordHas(args,callee,receiver,call,f);
    if(callee.kind==DescriptorDefine)return directDescriptor(args,receiver,call);
    if(knownProxy(callee))return proxyCall(callee,args,receiver,call,f);
    if(callee.kind==TargetApply){
      if(!f.proxyInvocation||!f.proxyTrap||args.size()!=2)return reject("PROXY_FORWARD_OUTSIDE_ACTIVE_TRAP",call);
      auto &context=proxyInvocations_[f.proxyInvocation];auto *read=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
      if(!read||call->getArgument(0)!=read->getObject()||receiver.kind!=Closure||receiver.ref!=context.target||callee.ref!=context.target||
          !sameDatumIdentity(args[0],context.receiver)||args[1].kind!=Array||args[1].ref!=context.array||!proxyArgumentArrays_.count(args[1].ref))
        return reject("PROXY_FORWARD_OPERAND_IDENTITY",call);
      ++proxyForwards_;llvh::outs()<<"[PROXY_FORWARD] event="<<proxyForwards_<<" invocation="<<f.proxyInvocation<<" proxy="<<context.proxy
        <<" target="<<context.target<<" handler="<<context.handler<<" receiver="<<context.receiver.ref<<" receiver_kind="<<unsigned(context.receiver.kind)
        <<" array="<<context.array<<" call="<<id(call)<<"\n";
      Datum out=callClosure(context.target,arrays_[context.array].values,context.receiver,call,false,false,false,false,f.dynamicContext,f.proxyInvocation,false);
      if(failed_)return {};proxyEdge(out,call);return out;
    }
    if(callee.kind==DateNow){
      auto *load=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
      if(!load||!args.empty()||receiver.kind!=DateObject||call->getArgument(0)!=load->getObject())
        return reject("DATE_NOW_IDENTITY",call);
      Instruction *src=source(call)?static_cast<Instruction *>(call):source(load)?load:nullptr;
      if(!src)return reject("DATE_SOURCE_NOT_REGISTERED",call);
      observedDateSources_.insert(src);
      Datum d=make(Primitive);d.traces.push_back({src,{src},f.invocation,false});if(f.moduleFactory)moduleEdge(d,call);if(f.dynamicContext)dynamicEdge(d,call);if(f.proxyInvocation)proxyEdge(d,call);if(f.functionContext)functionEdge(d,call);if(f.registryContext)registryEdge(d,call);if(f.ownControl)ownStateEdge(d,call);if(f.dispatchContext||f.dispatchControl)dispatchEdge(d,call);if(f.enumerationSnapshot)enumerationEdge(d,call);edge(d,call);return d;
    }
    if(callee.kind==DefineClass&&receiver.kind==Helpers&&args.size()==2&&args[0].kind==Closure){
      auto &ctor=closures_[args[0].ref];
      const bool unobservedOpaqueReceiver=f.receiver.kind==OpaqueGlobalThis;
      if(f.promise||f.constructor||!classDefinitionReceiverAllowed(f)||f.definitions||ctor.isClass||
          ctor.environment!=f.environment||!llvh::isa<LiteralNull>(call->getArgument(2))||
          !ctor.creation||ctor.creation->getParent()->getParent()!=f.function||ctor.function->getParent()!=module_||
          (ctor.function->getDefinitionKind()!=Function::DefinitionKind::ES6Constructor&&
           ctor.function->getDefinitionKind()!=Function::DefinitionKind::ES5Function)||
          llvh::isa<AsyncFunction>(ctor.function)||llvh::isa<GeneratorFunction>(ctor.function)||
          llvh::isa<GeneratorInnerFunction>(ctor.function)||suspended_)
        return reject("NONLOCAL_OR_DERIVED_CLASS_DEFINITION",call);
      ctor.isClass=true;ctor.exactBaseClassOwnState=true;++f.definitions;++classOwnDefinitions_;
      llvh::outs()<<"[CLASS_OWN_DEFINITION] closure="<<args[0].ref<<" environment="<<ctor.environment
        <<" wrapper="<<id(call)<<" unused_opaque_this="<<(unobservedOpaqueReceiver?1:0)<<"\n";
      return make(Undefined);
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
    auto moduleLoader=moduleCertificates_.find(closures_[callee.ref].function);
    if(moduleLoader!=moduleCertificates_.end())return requireModule(callee.ref,args,receiver,call,moduleLoader->second);
    auto propertyHelper=propertyCertificates_.find(closures_[callee.ref].function);
    if(propertyHelper!=propertyCertificates_.end())return defineProperty(callee.ref,args,receiver,call,propertyHelper->second);
    auto helper=helperCertificates_.find(closures_[callee.ref].function);
    if(helper!=helperCertificates_.end()){
      if(receiver.kind!=Undefined||args.empty()||args.size()>3||args[0].kind!=Closure||
          setters_.size()>=64||nextObject_>192)return reject("TO_SETTER_CALL_IDENTITY",call);
      Datum array=args.size()>1?args[1]:make(Undefined);
      if(array.kind==Undefined||array.kind==Null){array=make(Array,nextObject_++);arrays_[array.ref]={};}
      if(array.kind!=Array||enumerationSnapshots_.count(array.ref)||arrays_[array.ref].values.size()>=16)return reject("TO_SETTER_ARRAY_IDENTITY",call);
      Datum self=args.size()>2?args[2]:make(Undefined);
      if(self.kind!=Undefined&&self.kind!=Null&&self.kind!=Record&&self.kind!=Instance)
        return reject("TO_SETTER_RECEIVER_OUTSIDE_PROFILE",call);
      unsigned n=nextObject_++;auto &st=setters_[n];st.closure=args[0].ref;st.array=array.ref;
      st.slot=arrays_[array.ref].values.size();arrays_[array.ref].values.push_back(make(Undefined));
      st.receiver=self;st.certificate=helper->second;st.creation=call;
      return make(SetterObject,n);
    }
    bool functionCall=callee.functionProperty||callee.callbackClosure||functionObjects_.count(callee.ref),functionMember=false;
    if(functionCall){
      if(!ordinaryDataClosure(callee))return reject("FUNCTION_PROPERTY_CALLEE_KIND",call);
      if(receiver.kind!=Undefined){auto *read=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
        if(!read||call->getArgument(0)!=read->getObject()||receiver.kind!=Closure||!ordinaryDataClosure(receiver))
          return reject("FUNCTION_PROPERTY_MEMBER_RECEIVER",call);
        Datum actual=value(read->getObject(),f,call);if(actual.kind!=Closure||actual.ref!=receiver.ref)return reject("FUNCTION_PROPERTY_RECEIVER_IDENTITY",call);
        functionMember=true;
      }
      ++functionCalls_;if(callee.callbackClosure)++callbackCalls_;
      llvh::outs()<<"[FUNCTION_PROPERTY_CALL] event="<<functionCalls_<<" closure="<<callee.ref<<" environment="<<closures_[callee.ref].environment
        <<" receiver="<<receiver.ref<<" receiver_kind="<<unsigned(receiver.kind)<<" callback="<<(callee.callbackClosure?1:0)
        <<" member="<<(functionMember?1:0)<<" call="<<id(call)<<"\n";
    }
    bool dynamicCall=callee.dynamicClosure;
    if(dynamicCall){
      if(!ordinaryDataClosure(callee))return reject("DYNAMIC_CLOSURE_KIND",call);
      if(receiver.kind!=Undefined){auto *read=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
        if(!read||call->getArgument(0)!=read->getObject()||receiver.kind!=Record||forbiddenExportObject(receiver))
          return reject("DYNAMIC_CLOSURE_MEMBER_RECEIVER",call);
        Datum actual=value(read->getObject(),f,call);if(actual.kind!=receiver.kind||actual.ref!=receiver.ref)return reject("DYNAMIC_CLOSURE_RECEIVER_IDENTITY",call);
      }
      ++dynamicCalls_;llvh::outs()<<"[DYNAMIC_PROPERTY_CALL] event="<<dynamicCalls_<<" closure="<<callee.ref<<" closure_env="<<closures_[callee.ref].environment
        <<" receiver="<<receiver.ref<<" receiver_kind="<<unsigned(receiver.kind)<<" call="<<id(call)<<"\n";
    }
    bool dispatchCall=callee.dispatchSelection!=0;
    if(dispatchCall){
      auto selected=dispatchSelections_.find(callee.dispatchSelection);auto *read=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
      if(selected==dispatchSelections_.end()||!read||read!=selected->second.read||call->getArgument(0)!=read->getObject()||
          receiver.kind!=Record||receiver.ref!=selected->second.table||callee.ref!=selected->second.closure||!descriptorRecord(receiver)||dispatchCalls_>=128)
        return reject("MODULE_DISPATCH_CALL_RECEIVER_OR_SELECTION",call);
      Datum actual=value(read->getObject(),f,call);if(actual.kind!=Record||actual.ref!=receiver.ref)return reject("MODULE_DISPATCH_RECEIVER_VALUE",call);
      ++dispatchCalls_;llvh::outs()<<"[MODULE_DISPATCH_CALL] event="<<dispatchCalls_<<" selection="<<callee.dispatchSelection
        <<" table="<<receiver.ref<<" closure="<<callee.ref<<" environment="<<closures_[callee.ref].environment
        <<" key_hex="<<keyHex(selected->second.key)<<" key_event="<<selected->second.keyEvent<<" receiver="<<receiver.ref
        <<" argc="<<args.size()<<" call="<<id(call)<<" read="<<id(read)<<"\n";
      for(unsigned n=0;n<args.size();++n)llvh::outs()<<"[MODULE_DISPATCH_ARGUMENT] event="<<dispatchCalls_<<" index="<<n
        <<" kind="<<unsigned(args[n].kind)<<" ref="<<args[n].ref<<" source_traces="<<args[n].traces.size()<<" call="<<id(call)<<"\n";
    }
    if(callee.enumerationClosure){
      auto *read=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
      if(!read||!ordinaryDataClosure(callee)||receiver.kind!=Record||!descriptorRecord(receiver)||call->getArgument(0)!=read->getObject()||
          !enumerationSnapshots_.count(callee.enumerationSnapshot)||enumerationCalls_>=128)return reject("ENUM_HANDLER_CALL_IDENTITY",call);
      Datum actual=value(read->getObject(),f,call);if(actual.kind!=Record||actual.ref!=receiver.ref)return reject("ENUM_HANDLER_RECEIVER",call);
      ++enumerationCalls_;llvh::outs()<<"[ENUM_CALL] event="<<enumerationCalls_<<" snapshot="<<callee.enumerationSnapshot
        <<" closure="<<callee.ref<<" environment="<<closures_[callee.ref].environment<<" receiver="<<receiver.ref
        <<" argc="<<args.size()<<" read="<<id(read)<<" call="<<id(call)<<"\n";
    }
    Datum result=callClosure(callee.ref,args,receiver,call,false,false,false,dynamicCall,f.dynamicContext,f.proxyInvocation,false,
      f.functionContext||functionCall,functionMember,f.registryContext,f.dispatchContext||f.dispatchControl||dispatchCall,
      callee.enumerationSnapshot?callee.enumerationSnapshot:f.enumerationSnapshot,false);
    if(!failed_){observeResult(callbackResultObservations_[call],result);if(functionCall)functionResultSites_.insert(call);}
    return result;
  }
  Datum instruction(Instruction *i,Frame &f) {
    if(!tick(i))return {};
    if(auto *builtin=llvh::dyn_cast<GetBuiltinClosureInst>(i)){
      auto op=builtin->getBuiltinIndex();
      if(op==BuiltinMethod::HermesBuiltin_asyncIterator||op==BuiltinMethod::HermesBuiltin_asyncIteratorNext||op==BuiltinMethod::HermesBuiltin_asyncIteratorClose)
        return make(AsyncIterationIntrinsic,unsigned(op));
      return reject("ITERATOR_UNSUPPORTED_INTRINSIC",i);
    }
    if(auto *inner=llvh::dyn_cast<CreateInnerScopeInst>(i)){
      Datum parent=value(inner->getParentScope(),f,i);
      if(!nativeIterationPresent_||parent.kind!=Scope||!scopeWithin(parent.ref,f.environment)||
          inner->getCreatedScopeDesc()->getParent()!=environments_[parent.ref].descriptor||nextEnv_>256)
        return reject("ITERATOR_INNER_SCOPE_IDENTITY",i);
      unsigned id=nextEnv_++;environments_[id].descriptor=inner->getCreatedScopeDesc();environments_[id].parent=parent.ref;
      return make(Scope,id);
    }
    if(auto *tdz=llvh::dyn_cast<ThrowIfEmptyInst>(i)){
      Datum d=value(tdz->getCheckedValue(),f,i);
      if(!nativeIterationPresent_||d.kind==Empty||d.kind==Invalid)return reject("ITERATOR_TDZ_ABRUPT_OR_UNKNOWN",i);
      edge(d,i);return d;
    }
    if(auto *num=llvh::dyn_cast<AsNumericInst>(i)){
      Datum d=value(num->getSingleOperand(),f,i);
      if(!f.iteratorMode||!d.knownInteger||!d.traces.empty())return reject("ITERATOR_COUNTER_NOT_EXACT",i);
      return d;
    }
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
      if(env.kind!=Scope||(!nativeIterationPresent_?env.ref!=f.environment:!scopeWithin(env.ref,f.environment)))
        return reject("CAPTURED_FRAME_MUTATION",s);
      unsigned owner=env.ref;
      while(owner&&environments_[owner].descriptor!=s->getVariable()->getParent()){
        if(owner==f.environment){owner=0;break;}owner=environments_[owner].parent;
      }
      if(!owner||!scopeWithin(owner,f.environment))return reject("CAPTURED_FRAME_MUTATION",s);
      if(d.kind==Invalid)return reject("INVALID_FRAME_VALUE",s);
      auto &vars=environments_[owner].vars;
      if(f.function==global_&&suspended_){
        auto old=vars.find(s->getVariable());
        if(d.kind!=Closure||old==vars.end()||old->second.kind!=Undefined)
          return reject("GLOBAL_CAPTURE_MUTATION_AFTER_SUSPENSION",s);
      }
      edge(d,s);vars[s->getVariable()]=d;return make(Undefined);
    }
    if(auto *l=llvh::dyn_cast<LoadFrameInst>(i)){
      Datum env=value(l->getEnvironment(),f,l);if(env.kind!=Scope||(!nativeIterationPresent_?env.ref!=f.environment:!scopeWithin(env.ref,f.environment)))return reject("FRAME_ENVIRONMENT_IDENTITY",l);
      for(unsigned n=env.ref;n;n=environments_[n].parent){
        auto &e=environments_[n];if(e.descriptor!=l->getLoadVariable()->getParent())continue;
        auto p=e.vars.find(l->getLoadVariable());if(p==e.vars.end())return reject("LEXICAL_READ_BEFORE_INITIALIZATION",l);
        Datum d=p->second;if(f.dynamicContext)dynamicEdge(d,l);if(f.proxyInvocation)proxyEdge(d,l);if(f.functionContext)functionEdge(d,l);if(f.registryContext)registryEdge(d,l);if(f.ownControl)ownStateEdge(d,l);if(f.dispatchContext||f.dispatchControl)dispatchEdge(d,l);if(f.enumerationSnapshot)enumerationEdge(d,l);edge(d,l);return d;
      }
      return reject("LEXICAL_ENVIRONMENT_NOT_FOUND",l);
    }
    if(auto *def=llvh::dyn_cast<StoreGetterSetterInst>(i))return defineFreshGetter(def,f);
    if(auto *c=llvh::dyn_cast<CreateFunctionInst>(i)){
      Datum env=value(c->getEnvironment(),f,c);
      if(llvh::isa<CreateGeneratorInst>(c)||env.kind!=Scope||(!nativeIterationPresent_?env.ref!=f.environment:!scopeWithin(env.ref,f.environment))||nextClosure_>128)
        return reject("CLOSURE_ENVIRONMENT_OR_KIND",c);
      unsigned n=nextClosure_++;auto &closure=closures_[n];closure.function=c->getFunctionCode();closure.creation=c;closure.environment=env.ref;
      return make(Closure,n);
    }
    if(llvh::isa<GetNewTargetInst>(i)){
      if(f.function==global_||f.moduleFactory||f.proxyInvocation||f.functionContext)return make(Undefined);
                                                                          
                                                                             
      bool createsCache=false,dead=!f.constructor;
      for(auto &bb:*f.function)for(auto &ins:bb)if(auto *c=llvh::dyn_cast<CreateFunctionInst>(&ins))
        if(nestedCacheFunctions_.count(c->getFunctionCode())&&c->getFunctionCode()->getDefinitionKind()==Function::DefinitionKind::ES6Arrow)createsCache=true;
      for(auto *user:i->getUsers()){
        auto *store=llvh::dyn_cast<StoreFrameInst>(user);
        if(!store||store->getValue()!=i||store->getParent()->getParent()!=f.function){dead=false;break;}
        for(auto &fn:*module_)for(auto &bb:fn)for(auto &ins:bb)if(auto *load=llvh::dyn_cast<LoadFrameInst>(&ins))
          if(load->getLoadVariable()==store->getVariable())dead=false;
      }
      if(createsCache&&dead)return make(Undefined);
      return reject("OBSERVABLE_NEWTARGET_OUTSIDE_PROFILE",i);
    }
    if(auto *a=llvh::dyn_cast<AllocArrayInst>(i)){
      double size=a->getSizeHint()->getValue();
      if(nextObject_>192||size<0||size>16||size!=unsigned(size)||a->getElementCount()>size)
        return reject("FRESH_ARRAY_SIZE_OUTSIDE_PROFILE",a);
      unsigned n=nextObject_++;auto &items=arrays_[n].values;items.resize(unsigned(size),make(Undefined));
      for(unsigned j=0;j<a->getElementCount();++j){Datum d=value(a->getArrayElement(j),f,a);
        if(!primitive(d))return reject("FRESH_ARRAY_ELEMENT_OUTSIDE_PROFILE",a);edge(d,a);items[j]=d;}
      return make(Array,n);
    }
    if(auto *a=llvh::dyn_cast<AllocObjectInst>(i)){
      if(nextObject_>192||!llvh::isa<EmptySentinel>(a->getParentObject()))return reject("FRESH_RECORD_PARENT_OUTSIDE_PROFILE",a);
      unsigned n=nextObject_++;objects_[n].recordAllocation=a;
      if(registryAllocations_.count(a))registryObjects_.insert(n);
      if(cacheAllocations_.count(a))cacheObjects_.insert(n);
      if(handlerAllocations_.count(a))handlerObjects_.insert(n);
      return make(Record,n);
    }
    if(auto *s=llvh::dyn_cast<StoreOwnPropertyInst>(i)){
      Datum o=value(s->getObject(),f,s),d=value(s->getStoredValue(),f,s);
      if(nativeIterationPresent_&&plainIterationRecord(o)&&s->getIsEnumerable()){
        Datum property=value(s->getProperty(),f,s);
        if(property.kind==IteratorSymbol&&(iterationCallable(d)||d.kind==Undefined||d.kind==Null)){
          iteratorSymbols_[{o.ref,property.ref}]=d;return make(Undefined);
        }
        if(property.knownString&&property.traces.empty()&&(property.string=="next"||property.string=="return"||property.string=="throw")&&
            (iterationCallable(d)||d.kind==Undefined||d.kind==Null)){
          putOwn(o.ref,property.string,d);return make(Undefined);
        }
      }
      if(o.kind==Record&&moduleRecords_.count(o.ref))return reject("MODULE_RECORD_GENERIC_OWN_WRITE",s);
      if(o.kind==Record&&registryObjects_.count(o.ref)){
        Datum property=value(s->getProperty(),f,s);std::string name;
        if(!llvh::isa<StoreNewOwnPropertyInst>(s)||!s->getIsEnumerable()||!moduleKey(property,name)||d.kind!=Closure||
            s->getObject()!=objects_[o.ref].recordAllocation||objects_[o.ref].fields.count(name))return reject("MODULE_REGISTRY_INITIALIZER_OUTSIDE_PROFILE",s);
        edge(d,s);putOwn(o.ref,name,d);return make(Undefined);
      }
      if(o.kind==Record&&cacheObjects_.count(o.ref))return reject("MODULE_CACHE_INITIALIZER_NOT_EMPTY",s);
      if(o.kind==Record&&handlerObjects_.count(o.ref)&&key(s->getProperty())=="apply"){
        if(!s->getIsEnumerable())return reject("PROXY_HANDLER_NONENUMERABLE_INITIALIZER",s);
        return handlerApplyWrite(o,d,s);
      }
      if(o.kind==Record&&knownProxy(d)&&s->getObject()==objects_[o.ref].recordAllocation&&s->getIsEnumerable()&&safeDynamicKey(key(s->getProperty()))){
        edge(d,s);putOwn(o.ref,key(s->getProperty()),d);return make(Undefined);
      }
      if(o.kind==Array&&proxyArgumentArrays_.count(o.ref))return reject("PROXY_ARGUMENT_ARRAY_MUTATION",s);
      if(o.kind==Array&&enumerationSnapshots_.count(o.ref))return reject("ENUM_SNAPSHOT_MUTATION",s);
      if(f.enumerationMode&&o.kind==Record&&descriptorRecord(o)&&llvh::isa<StoreNewOwnPropertyInst>(s)&&
          s->getObject()==objects_[o.ref].recordAllocation&&s->getIsEnumerable()){
        std::string name;Datum property=value(s->getProperty(),f,s);
        if(!dataKey(property,name)||objects_[o.ref].fields.count(name)||objects_[o.ref].fields.size()>=32||
            (!primitive(d)&&!ordinaryDataClosure(d)&&!enumerationData(d,o.ref)))return reject("ENUM_NESTED_INITIALIZER",s);
        if(ordinaryDataClosure(d))d.dynamicClosure=true;
        rememberDispatchSlot(o,name,d,s);if(failed_)return {};
        edge(d,s);putOwn(o.ref,name,d);return make(Undefined);
      }
      if(o.kind==Record&&descriptorRecord(o)&&llvh::isa<StoreNewOwnPropertyInst>(s)&&
          s->getObject()==objects_[o.ref].recordAllocation&&s->getIsEnumerable()&&safeDynamicKey(key(s->getProperty()))&&
          !objects_[o.ref].fields.count(key(s->getProperty()))&&(ordinaryDataClosure(d)||closedNestedData(d,o.ref))){
        if(objects_[o.ref].fields.size()>=32)return reject("NESTED_OR_HANDLER_OWN_SLOT_LIMIT",s);
        if(ordinaryDataClosure(d))d.dynamicClosure=true;
        rememberDispatchSlot(o,key(s->getProperty()),d,s);if(failed_)return {};
        edge(d,s);putOwn(o.ref,key(s->getProperty()),d);return make(Undefined);
      }
      if(!primitive(d)||!s->getIsEnumerable())return reject("FRESH_OWN_VALUE_OUTSIDE_PROFILE",s);
      edge(d,s);
      if(o.kind==Record){auto n=key(s->getProperty());
        if(n.empty()||n=="__proto__"||n=="constructor")return reject("FRESH_RECORD_KEY_OUTSIDE_PROFILE",s);
        putOwn(o.ref,n,d);return make(Undefined);}
      if(o.kind==Array){auto *n=llvh::dyn_cast<LiteralNumber>(s->getProperty());
        if(!n||n->getValue()<0||n->getValue()>=16||n->getValue()!=unsigned(n->getValue()))
          return reject("FRESH_ARRAY_INDEX_OUTSIDE_PROFILE",s);
        auto &items=arrays_[o.ref].values;unsigned index=unsigned(n->getValue());
        if(index>=items.size())return reject("FRESH_ARRAY_INDEX_OUT_OF_RANGE",s);
        items[index]=d;return make(Undefined);}
      return reject("OWN_PROPERTY_OUTSIDE_FRESH_PROFILE",s);
    }
    if(auto *l=llvh::dyn_cast<LoadPropertyInst>(i))return propertyRead(l,f);
    if(auto *s=llvh::dyn_cast<StorePropertyInst>(i))return storeProperty(s,f);
    if(auto *d=llvh::dyn_cast<DeletePropertyInst>(i)){++deleteExecutions_[d];return ownDataDelete(d,f);}
    if(auto *c=llvh::dyn_cast<CallInst>(i))return invoke(c,f);
    if(auto *u=llvh::dyn_cast<UnaryOperatorInst>(i)){
      Datum d=value(u->getSingleOperand(),f,u);
      if(f.iteratorMode&&d.knownInteger&&d.traces.empty()&&
          (u->getOperatorKind()==UnaryOperatorInst::OpKind::IncKind||u->getOperatorKind()==UnaryOperatorInst::OpKind::DecKind)){
        d.integer+=u->getOperatorKind()==UnaryOperatorInst::OpKind::IncKind?1:-1;
        if(d.integer< -2147483647LL||d.integer>2147483647LL)return reject("ITERATOR_COUNTER_RANGE",u);
        d.truthKnown=true;d.truthValue=d.integer!=0;return d;
      }
      if(u->getOperatorKind()==UnaryOperatorInst::OpKind::VoidKind&&primitive(d))return make(Undefined);
      auto *number=llvh::dyn_cast<LiteralNumber>(u->getSingleOperand());
      if(u->getOperatorKind()==UnaryOperatorInst::OpKind::BangKind&&number&&
          (number->getValue()==0||number->getValue()==1)){Datum out=make(Primitive);out.knownBoolean=true;out.boolean=number->getValue()==0;return out;}
      if(u->getOperatorKind()==UnaryOperatorInst::OpKind::BangKind&&d.knownBoolean&&d.traces.empty()){
        Datum out=make(Primitive);out.knownBoolean=true;out.boolean=!d.boolean;out.ownStateBoolean=d.ownStateBoolean;out.dispatchBoolean=d.dispatchBoolean;return out;}
      if(f.enumerationMode&&u->getOperatorKind()==UnaryOperatorInst::OpKind::BangKind){bool truth;
        if(!exactTruth(d,truth))return reject("ENUM_UNKNOWN_TRUTHINESS",u);
        Datum out=make(Primitive);out.knownBoolean=true;out.boolean=!truth;return out;}
      return reject("UNARY_COERCION_OUTSIDE_PROFILE",u);
    }
    if(auto *b=llvh::dyn_cast<BinaryOperatorInst>(i)){
      Datum a=value(b->getLeftHandSide(),f,b),d=value(b->getRightHandSide(),f,b);
      if(f.iteratorMode&&a.knownInteger&&d.knownInteger&&a.traces.empty()&&d.traces.empty()){
        Datum out=make(Primitive);out.knownBoolean=true;auto op=b->getOperatorKind();
        if(op==BinaryOperatorInst::OpKind::LessThanKind)out.boolean=a.integer<d.integer;
        else if(op==BinaryOperatorInst::OpKind::LessThanOrEqualKind)out.boolean=a.integer<=d.integer;
        else if(op==BinaryOperatorInst::OpKind::GreaterThanKind)out.boolean=a.integer>d.integer;
        else if(op==BinaryOperatorInst::OpKind::GreaterThanOrEqualKind)out.boolean=a.integer>=d.integer;
        else if(op==BinaryOperatorInst::OpKind::StrictlyEqualKind)out.boolean=a.integer==d.integer;
        else if(op==BinaryOperatorInst::OpKind::StrictlyNotEqualKind)out.boolean=a.integer!=d.integer;
        else out.knownBoolean=false;
        if(out.knownBoolean)return out;
      }
      if(b->getOperatorKind()!=BinaryOperatorInst::OpKind::AddKind||!primitive(a)||!primitive(d))
        return reject("OPERATOR_OR_COERCION_OUTSIDE_PROFILE",b);
      Datum out=make(Primitive);out.traces=a.traces;out.traces.insert(out.traces.end(),d.traces.begin(),d.traces.end());
      if(a.knownString&&d.knownString&&a.string.size()+d.string.size()<=256){out.knownString=true;out.string=a.string+d.string;}
      edge(out,b);return out;
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
                                                                                
                                                                               
    Datum d=job.value;
    if(d.kind==AsyncIterationResult){
      auto result=iterationResults_.find(d.ref);
      if(!f.iteratorMode||result==iterationResults_.end()||result->second.resume)return reject("ITERATOR_RESULT_RESUME_IDENTITY",r),nullptr;
      result->second.yield=y;result->second.resume=r;
      if(result->second.closeOnly)d=make(Undefined);
    }else if(!primitive(d))return reject("RESUME_VALUE_NOT_PRIMITIVE",r),nullptr;
    for(auto &t:d.traces)t.awaited=true;edge(d,r);f.values[r]=d;
    ++resumed_;
    llvh::outs()<<"[TO_SETTER_ASYNC_RESUME] consumer_invocation="<<f.invocation<<" consumer_promise="<<f.promise
      <<" awaited_promise="<<job.awaitedPromise<<" yield="<<id(y)<<" resume="<<id(r);
    if(job.awaitedPromise){auto &p=promises_[job.awaitedPromise];llvh::outs()<<" producer_invocation="<<p.invocation
      <<" receiver_instance="<<p.receiver<<" call="<<id(p.call)<<" return="<<id(p.returned);}
    llvh::outs()<<"\n";
    return b->getFalseDest();
  }
  Datum execute(Frame &f,BasicBlock *block) {
    if(!block||block->getParent()!=f.function||(!f.visited.insert(block).second&&!f.iteratorMode))return reject("CONTROL_OR_LOOP_OUTSIDE_PROFILE",f.entry);
    for(auto &i:*block){
      if(failed_)return {};
      if(auto *phi=llvh::dyn_cast<PhiInst>(&i)){
        if(!f.predecessor||(!f.proxyInvocation&&!proxyFunctions_.count(f.function)&&!f.ownControl&&!f.dispatchControl&&!f.enumerationMode&&!nestedAliasFunctions_.count(f.function)&&!f.iteratorMode)||!tick(phi))return reject("PROXY_PHI_CONTEXT",phi);
        unsigned matches=0;Datum selected;
        for(unsigned n=0;n<phi->getNumEntries();++n){auto entry=phi->getEntry(n);if(entry.second==f.predecessor){selected=value(entry.first,f,phi);++matches;}}
        if(matches!=1)return reject("PROXY_PHI_PREDECESSOR",phi);edge(selected,phi);f.values[phi]=selected;continue;
      }
      if(auto *branch=llvh::dyn_cast<CondBranchInst>(&i)){
        if(!tick(branch))return {};
        Datum condition=value(branch->getCondition(),f,branch);
        if(!f.proxyInvocation&&!proxyFunctions_.count(f.function)&&!condition.ownStateBoolean&&!condition.dispatchBoolean&&!f.enumerationMode&&!nestedAliasFunctions_.count(f.function)&&!f.iteratorMode)return reject("PROXY_BRANCH_CONTEXT",branch);
        if(nestedAliasFunctions_.count(f.function)&&!condition.knownBoolean){bool truth;
          if(!exactTruth(condition,truth))return reject("NESTED_ALIAS_UNKNOWN_CONDITION",branch);
          condition.knownBoolean=true;condition.boolean=truth;}
        if(f.enumerationMode&&!condition.knownBoolean){bool truth;if(!exactTruth(condition,truth))return reject("ENUM_UNKNOWN_TRUTHINESS",branch);
          condition.knownBoolean=true;condition.boolean=truth;}
        if(!condition.knownBoolean||!condition.traces.empty()||f.visited.size()>=256)return reject("PROXY_READY_NOT_EXACT_BOOLEAN",branch);
        if(condition.ownStateBoolean){f.ownControl=true;++ownBranches_;
          llvh::outs()<<"[OWN_DATA_BRANCH] event="<<ownBranches_<<" invocation="<<f.invocation<<" value="<<(condition.boolean?"true":"false")
            <<" condition="<<id(llvh::dyn_cast<Instruction>(branch->getCondition()))<<" branch="<<id(branch)<<"\n";
        }else if(condition.dispatchBoolean){f.dispatchControl=true;++dispatchBranches_;
          llvh::outs()<<"[MODULE_DISPATCH_BRANCH] event="<<dispatchBranches_<<" invocation="<<f.invocation
            <<" value="<<(condition.boolean?"true":"false")<<" condition="<<id(llvh::dyn_cast<Instruction>(branch->getCondition()))<<" branch="<<id(branch)<<"\n";
        }else if(f.enumerationMode){++enumerationBranches_;llvh::outs()<<"[ENUM_BRANCH] event="<<enumerationBranches_
          <<" invocation="<<f.invocation<<" snapshot="<<f.enumerationSnapshot<<" value="<<(condition.boolean?"true":"false")<<" branch="<<id(branch)<<"\n";
        }else if(nestedAliasFunctions_.count(f.function)){
          ++nestedAliasBranches_;llvh::outs()<<"[NESTED_ALIAS_BRANCH] event="<<nestedAliasBranches_<<" invocation="<<f.invocation
            <<" value="<<(condition.boolean?"true":"false")<<" branch="<<id(branch)<<"\n";
        }else {++proxyBranches_;llvh::outs()<<"[PROXY_STATE_BRANCH] event="<<proxyBranches_<<" invocation="<<f.proxyInvocation
          <<" value="<<(condition.boolean?"true":"false")<<" branch="<<id(branch)<<"\n";}
        f.predecessor=block;return execute(f,condition.boolean?branch->getTrueDest():branch->getFalseDest());
      }
      if(auto *branch=llvh::dyn_cast<BranchInst>(&i)){
        if((!f.proxyInvocation&&!proxyFunctions_.count(f.function)&&!f.ownControl&&!f.dispatchControl&&!f.enumerationMode&&!nestedAliasFunctions_.count(f.function)&&!f.iteratorMode)||!tick(branch)||f.visited.size()>=256)return reject("PROXY_BRANCH_CONTEXT",branch);
        f.predecessor=block;return execute(f,branch->getBranchDest());
      }
      if(auto *start=llvh::dyn_cast<TryStartInst>(&i)){
        if(!f.iteratorMode||!tick(start))return reject("ITERATOR_TRY_OUTSIDE_PROFILE",start);
        f.predecessor=block;return execute(f,start->getTryBody());
      }
      if(llvh::isa<TryEndInst>(&i)&&f.iteratorMode){if(!tick(&i))return {};continue;}
      if(auto *ret=llvh::dyn_cast<ReturnInst>(&i)){
        if(!tick(ret))return {};Datum d=value(ret->getValue(),f,ret);if(f.dynamicContext)dynamicEdge(d,ret);if(f.proxyInvocation)proxyEdge(d,ret);if(f.functionContext)functionEdge(d,ret);if(f.registryContext)registryEdge(d,ret);if(f.ownControl)ownStateEdge(d,ret);if(f.dispatchContext||f.dispatchControl)dispatchEdge(d,ret);if(f.enumerationSnapshot)enumerationEdge(d,ret);edge(d,ret);
        if(f.promise){
          if(!primitive(d)&&!(f.iteratorMode&&plainIterationRecord(d)))return reject("ASYNC_RETURN_ASSIMILATION_OR_THENABLE",ret);
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
        if(!primitive(d)&&!(f.iteratorMode&&d.kind==AsyncIterationResult))return reject("AWAIT_THENABLE_OR_UNKNOWN_VALUE",y);
        if(queue_.size()>=64)return reject("CONTINUATION_LIMIT",y);
        edge(d,y);Continuation job;job.frame=f;job.suspension=y;job.value=d;job.awaitedPromise=token;
        if(d.kind==AsyncIterationResult)job.delay=iterationResults_[d.ref].delay;
        queue_.push_back(std::move(job));suspended_=true;++awaits_;return make(Undefined);
      }
      f.values[&i]=instruction(&i,f);
    }
    return reject("ENTRY_WITHOUT_NORMAL_RETURN",f.entry);
  }
  void index() {
    unsigned fi=0,count=0;
                                                                          
    for(auto &f:*module_)for(auto &b:f)for(auto &i:b)
      if(++metadataInstructions_>150000){reject("MODULE_METADATA_LIMIT",&i);return;}
    for(auto &fn:*module_)for(auto &bb:fn)for(auto &ins:bb)
      if(auto *builtin=llvh::dyn_cast<GetBuiltinClosureInst>(&ins)){
        auto op=builtin->getBuiltinIndex();
        if(op==BuiltinMethod::HermesBuiltin_asyncIterator||op==BuiltinMethod::HermesBuiltin_asyncIteratorNext||op==BuiltinMethod::HermesBuiltin_asyncIteratorClose){
          nativeIterationPresent_=true;iteratorFunctions_.insert(&fn);
        }
      }
    if(nativeIterationPresent_)for(auto &fn:*module_)for(auto &bb:fn)for(auto &ins:bb)
      if(auto *store=llvh::dyn_cast<StorePropertyInst>(&ins)){
        auto name=key(store->getProperty());
        if(name.empty()||name=="next"||name=="return"||name=="throw")iteratorWriteCandidates_.insert(store);
      }
    for(auto *g:module_->getGlobalProperties())if(g->isDeclared()){
      auto name=key(g->getName());declaredGlobals_.insert(name);if(hostName(name))reject("HOST_GLOBAL_SHADOWED");
    }
    for(auto &f:*module_){PropertyCertificate property;KeyCertificate key;
      if(recognizeProperty(&f,property)){
        propertyCertificates_[&f]=property;
        for(auto &b:f)for(auto &i:b)helperInstructions_.insert(&i);
      }
      if(recognizeKey(&f,key))keyCertificates_[&f]=key;
      if(recognizePrimitiveString(&f))primitiveStringCertificates_.insert(&f);
    }
    for(auto &f:*module_){SetterCertificate certificate;
      if(recognizeSetter(&f,certificate)){
        helperCertificates_[&f]=certificate;
        for(auto &b:f)for(auto &i:b)helperInstructions_.insert(&i);
        for(auto &b:*certificate.setter)for(auto &i:b)helperInstructions_.insert(&i);
      }
    }
    for(auto &f:*module_){ModuleCertificate cert;
      if(recognizeModule(&f,cert)){moduleCertificates_[&f]=cert;moduleCacheInstructions_.insert(cert.cacheWrite);
        registryAllocations_.insert(cert.registryAllocation);cacheAllocations_.insert(cert.cacheAllocation);}
    }
    indexEnumerationLinks();
    for(auto &f:*module_)for(auto &b:f)for(auto &i:b){
      auto *call=llvh::dyn_cast<CallInst>(&i);
      if(!call||llvh::isa<ConstructInst>(call)||llvh::isa<CallBuiltinInst>(call)||call->getNumArguments()!=2||
          !llvh::isa<LiteralUndefined>(call->getNewTarget()))continue;
      auto *read=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
      auto *object=read?llvh::dyn_cast<LoadPropertyInst>(read->getObject()):nullptr;
      if(!read||!object||read->getParent()->getParent()!=&f||object->getParent()->getParent()!=&f||key(read->getProperty())!="keys"||
          !llvh::isa<GlobalObject>(object->getObject())||key(object->getProperty())!="Object"||call->getArgument(0)!=object)continue;
      bool closed=true;for(auto *user:read->getUsers())if(user!=call)closed=false;if(!closed)continue;
      auto links=enumerationLinks_.find(call);if(links==enumerationLinks_.end())continue;
      if(objectKeysCandidates_.size()>=128){reject("ENUM_KEYS_CANDIDATE_LIMIT",call);continue;}
      objectKeysCandidates_[read]=call;enumerationFunctions_.insert(&f);
      for(auto &link:links->second){
        enumerationFunctions_.insert(link.first->getParent()->getParent());
        enumerationFunctions_.insert(link.second);
      }
    }
    closeEnumerationFunctions();
                                                                           
                                                                                 
                                                                                
    for(auto &f:*module_)for(auto &b:f)for(auto &i:b){
      auto *call=llvh::dyn_cast<CallInst>(&i);
      if(!call||llvh::isa<ConstructInst>(call)||llvh::isa<CallBuiltinInst>(call)||helperInstructions_.count(call)||call->getNumArguments()!=4||
          !llvh::isa<LiteralUndefined>(call->getNewTarget()))continue;
      auto *read=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
      auto *object=read?llvh::dyn_cast<LoadPropertyInst>(read->getObject()):nullptr;
      if(!read||!object||read->getParent()->getParent()!=&f||object->getParent()->getParent()!=&f||
          key(read->getProperty())!="defineProperty"||!llvh::isa<GlobalObject>(object->getObject())||
          key(object->getProperty())!="Object"||call->getArgument(0)!=object)continue;
      bool closed=true;for(auto *user:read->getUsers())if(user!=call)closed=false;
      if(!closed)continue;
      if(descriptorCandidates_.size()>=128){reject("DIRECT_DESCRIPTOR_CANDIDATE_LIMIT",call);continue;}
      descriptorCandidates_[read]=call;
    }
    for(auto &f:*module_)for(auto &b:f)for(auto &i:b){
      auto *call=llvh::dyn_cast<CallInst>(&i);
      if(!call||llvh::isa<ConstructInst>(call)||llvh::isa<CallBuiltinInst>(call)||call->getNumArguments()!=3||
          !llvh::isa<LiteralUndefined>(call->getNewTarget()))continue;
      auto *read=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
      auto *object=read?llvh::dyn_cast<LoadPropertyInst>(read->getObject()):nullptr;
      if(!read||!object||read->getParent()->getParent()!=&f||object->getParent()->getParent()!=&f||
          key(read->getProperty())!="hasOwn"||!llvh::isa<GlobalObject>(object->getObject())||key(object->getProperty())!="Object"||
          call->getArgument(0)!=object)continue;
      bool closed=true;for(auto *user:read->getUsers())if(user!=call)closed=false;if(!closed)continue;
      if(ownCheckCandidates_.size()>=128){reject("OWN_CHECK_CANDIDATE_LIMIT",call);continue;}
      ownCheckCandidates_[read]=call;
    }
    for(auto &f:*module_)for(auto &b:f)for(auto &i:b){
      auto *call=llvh::dyn_cast<CallInst>(&i);
      if(!call||llvh::isa<ConstructInst>(call)||llvh::isa<CallBuiltinInst>(call)||call->getNumArguments()!=2||
          !llvh::isa<LiteralUndefined>(call->getNewTarget()))continue;
      auto *read=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
      if(!read||key(read->getProperty())!="hasOwnProperty"||read->getParent()->getParent()!=&f||call->getArgument(0)!=read->getObject())continue;
      bool closed=true;for(auto *user:read->getUsers())if(user!=call)closed=false;if(!closed)continue;
      if(recordHasCandidates_.size()>=128){reject("RECORD_HAS_OWN_CANDIDATE_LIMIT",call);continue;}
      recordHasCandidates_[read]=call;
    }
    indexNestedCaches();
                                                                            
                                                                              
                                                                        
    for(auto &f:*module_)for(auto &b:f)for(auto &i:b){
      auto *c=llvh::dyn_cast<ConstructInst>(&i);if(!c||c->getNumArguments()!=3)continue;
      auto *load=llvh::dyn_cast<LoadPropertyInst>(c->getCallee());
      if(!load||!llvh::isa<GlobalObject>(load->getObject())||key(load->getProperty())!="Proxy")continue;
      if(proxyCandidates_.size()>=64){reject("PROXY_METADATA_CANDIDATE_LIMIT",c);continue;}
      auto *allocation=llvh::dyn_cast<AllocObjectInst>(c->getArgument(2));
      if(!allocation){auto *binding=llvh::dyn_cast<Instruction>(c->getArgument(2));if(binding)allocation=bindingAllocation(binding);}
      if(!allocation||registryAllocations_.count(allocation)||cacheAllocations_.count(allocation))continue;
      proxyCandidates_.insert(c);handlerAllocations_.insert(allocation);proxyFunctions_.insert(&f);
    }
    if(!proxyCandidates_.empty())for(auto &f:*module_)for(auto &b:f)for(auto &i:b){
      auto *s=llvh::dyn_cast<StorePropertyInst>(&i);
      if(s&&key(s->getProperty())=="apply"&&localDataOperand(s->getObject(),&f,false)&&!protectedBindingOperand(s->getObject())){
        handlerWriteCandidates_.insert(s);proxyFunctions_.insert(&f);
      }
    }
    for(auto &f:*module_)for(auto &b:f)for(auto &i:b){
      auto *s=llvh::dyn_cast<StorePropertyInst>(&i);
      if(!s||helperInstructions_.count(s)||moduleCacheInstructions_.count(s)||!key(s->getProperty()).empty())continue;
      if(localDataOperand(s->getObject(),&f,false)&&localDataOperand(s->getProperty(),&f,true)&&!protectedBindingOperand(s->getObject()))
        dynamicWriteCandidates_.insert(s);
      if(!moduleCertificates_.empty()&&!dynamicWriteCandidates_.count(s)&&localDataOperand(s->getObject(),&f,false)&&
          nestedKeyOperand(s->getProperty(),&f)&&!protectedBindingOperand(s->getObject())){
        if(moduleKeyWriteCandidates_.size()>=128){reject("MODULE_KEY_WRITE_CANDIDATE_LIMIT",s);continue;}
        moduleKeyWriteCandidates_.insert(s);
      }
    }
    if(!objectKeysCandidates_.empty())for(auto &f:*module_)if(enumerationFunctions_.count(&f))for(auto &b:f)for(auto &i:b){
      auto *s=llvh::dyn_cast<StorePropertyInst>(&i);
      if(!s||helperInstructions_.count(s)||moduleCacheInstructions_.count(s)||protectedBindingOperand(s->getObject())||
          !nestedReceiverOperand(s->getObject(),&f)||!localDataOperand(s->getProperty(),&f,true))continue;
      if(llvh::isa<LiteralString>(s->getProperty())&&!safeDynamicKey(key(s->getProperty())))continue;
      if(enumerationWriteCandidates_.size()>=256){reject("ENUM_WRITE_CANDIDATE_LIMIT",s);continue;}
      enumerationWriteCandidates_.insert(s);
    }
                                                                              
                                                                            
                                                                                
    if(!moduleCertificates_.empty())for(auto &f:*module_)for(auto &b:f)for(auto &i:b){
      auto *write=llvh::dyn_cast<StorePropertyInst>(&i);if(!write||helperInstructions_.count(write)||moduleCacheInstructions_.count(write))continue;
      bool cacheBinding=false;for(auto &cert:moduleCertificates_){auto *binding=llvh::dyn_cast<Instruction>(write->getObject());
        if(binding&&sameClosedBinding(binding,cert.second.cacheBinding))cacheBinding=true;}
      if(cacheBinding||!localDataOperand(write->getProperty(),&f,true))continue;
      if(llvh::isa<LiteralString>(write->getProperty())&&!safeDataKey(key(write->getProperty())))continue;
      bool target=localDataOperand(write->getObject(),&f,false);
      if(auto *read=llvh::dyn_cast<LoadPropertyInst>(write->getObject())){
        if(safeDynamicKey(key(read->getProperty()))&&localDataOperand(read->getObject(),&f,false))target=true;
      }
      if(target)registryWriteCandidates_.insert(write);
    }
                                                                               
                                                                            
                                                                           
    for(auto &f:*module_)for(auto &b:f)for(auto &i:b){
      auto *d=llvh::dyn_cast<DeletePropertyInst>(&i);if(!d||protectedBindingOperand(d->getObject()))continue;
      bool lexical=false;if(auto *l=llvh::dyn_cast<LoadFrameInst>(d->getObject()))
        lexical=l->getParent()->getParent()==&f;
      auto name=key(d->getProperty());Datum property=make(Primitive);property.knownString=true;property.string=name;std::string exact;
      if((lexical||localDataOperand(d->getObject(),&f,false))&&!name.empty()&&functionDataKey(property,exact))
        functionDeleteCandidates_.insert(d);
      if((lexical||localDataOperand(d->getObject(),&f,false))&&localDataOperand(d->getProperty(),&f,true)){
        if(llvh::isa<LiteralString>(d->getProperty())&&!descriptorKey(property,exact))continue;
        if(ownDeleteCandidates_.size()>=256){reject("OWN_DELETE_CANDIDATE_LIMIT",d);continue;}
        ownDeleteCandidates_.insert(d);
      }
    }
    indexNestedAliases();indexFreshGetters();
    for(auto &f:*module_){
      if(f.isGlobalScope()){if(global_)reject("MULTIPLE_GLOBAL_ENTRIES");global_=&f;}
      unsigned ii=0;
      for(auto &b:f)for(auto &i:b){
        metadataInstructions_=++count;
        if(count>150000){reject("MODULE_METADATA_LIMIT",&i);return;}
        ids_[&i]="F"+std::to_string(fi)+":I"+std::to_string(ii++);
        if(auto *c=llvh::dyn_cast<CreateFunctionInst>(&i))++creationCounts_[c->getFunctionCode()];
        if(helperInstructions_.count(&i))continue;
        auto *deletion=llvh::dyn_cast<DeletePropertyInst>(&i);
        if(llvh::isa<DirectEvalInst>(&i)||(deletion&&!functionDeleteCandidates_.count(deletion)&&!ownDeleteCandidates_.count(deletion))||(llvh::isa<StoreGetterSetterInst>(&i)&&!freshGetterCandidates_.count(llvh::cast<StoreGetterSetterInst>(&i))))
          reject("DYNAMIC_OR_DESCRIPTOR_MUTATION",&i);
        if(auto *s=llvh::dyn_cast<StorePropertyInst>(&i)){
          auto n=key(s->getProperty());
          if(!iteratorWriteCandidates_.count(s)&&!nestedAliasCandidates_.count(s)&&!nestedCacheWrites_.count(s)&&!moduleCacheInstructions_.count(s)&&!dynamicWriteCandidates_.count(s)&&!moduleKeyWriteCandidates_.count(s)&&!handlerWriteCandidates_.count(s)&&!registryWriteCandidates_.count(s)&&!enumerationWriteCandidates_.count(s)&&(n.empty()||hostName(n)||n=="__proto__"||n=="prototype"||n=="constructor"||n=="now"||
              n=="then"||n=="resolve"||n=="apply"||n=="next"||n=="throw"||n=="return"))
            reject("HOST_OR_DYNAMIC_PROPERTY_MUTATION",s);
          if(!moduleCertificates_.empty()&&n=="call"&&!registryWriteCandidates_.count(s))reject("FUNCTION_CALL_MUTATION_WITH_MODULE_LOADER",s);
        }
        if(auto *l=llvh::dyn_cast<LoadPropertyInst>(&i)){
          auto n=key(l->getProperty());
          if((n=="defineProperty"&&!descriptorCandidates_.count(l))||n=="defineProperties"||n=="__defineGetter__"||n=="__defineSetter__"||n=="setPrototypeOf")
            reject("DESCRIPTOR_API_OUTSIDE_PROFILE",l);
        }
      }++fi;
    }
    if(!global_)reject("GLOBAL_ENTRY_MISSING");
  }
 public:
  BoundedToSetterTransport(Module *m,const std::vector<Instruction *> &sources,const std::vector<Instruction *> &sinks)
    :module_(m),sources_(sources),sinks_(sinks){index();}
  void append(std::vector<DefUseAnalyzer::TaintPath> &paths) {
    bool completed=false;
    if(!failed_){Frame f;f.function=global_;f.receiver=make(OpaqueGlobalThis);f.enumerationMode=enumerationFunctions_.count(global_);Datum result=execute(f,&global_->front());completed=!failed_&&(primitive(result)||(nativeIterationPresent_&&result.kind==PromiseToken));}
    for(unsigned n=0;n<queue_.size()&&!failed_;++n){
      Continuation job=queue_[n];
      if(job.delay){
        if(queue_.size()>=64){reject("ITERATOR_JOB_LIMIT",job.suspension);break;}
        --job.delay;queue_.push_back(std::move(job));continue;
      }
      auto *next=resume(job);if(next&&!failed_)execute(job.frame,next);
    }
    completed=completed&&!failed_&&paths.size()<=1024;for(auto &p:promises_)if(!p.second.fulfilled)completed=false;
    promoteOwnReads(completed);completed=completed&&!failed_;
    llvh::outs()<<"[OWN_DATA_PROMOTION] status="<<(completed?"PROVED":"UNKNOWN")
      <<" observed_reads="<<deferredOwnReads_.size()<<" observed_paths="<<deferredOwnSinks_.size()<<" promoted="<<ownPromoted_
      <<" contract=COMPLETE_CLOSED_EXACT_PRE_PROOF_READ_COPY_AND_HISTORICAL_COOKIE_PATH_SAME_DYNAMIC_OBJECT\n";
    unsigned suppressed=guardProxyResults(paths,completed);
    llvh::outs()<<"[PROXY_RESULT_GUARD] status="<<(completed?"PROVED":"UNKNOWN")<<" observed_calls="<<proxyResultObservations_.size()
      <<" observed_sinks="<<cookieObservations_.size()<<" suppressed="<<suppressed
      <<" contract=COMPLETE_CLOSED_ALL_INVOCATIONS_EXACT_PROXY_RESULT_USE_AND_COOKIE_SOURCE_UNION\n";
    unsigned functionSuppressed=guardFunctionResults(paths,completed);
    llvh::outs()<<"[FUNCTION_PROPERTY_GUARD] status="<<(completed?"PROVED":"UNKNOWN")
      <<" observed_reads="<<functionReadObservations_.size()<<" observed_calls="<<functionResultSites_.size()
      <<" suppressed="<<functionSuppressed
      <<" contract=COMPLETE_CLOSED_ALL_EXECUTIONS_EXACT_FUNCTION_VALUE_USE_AND_COOKIE_SOURCE_UNION\n";
    unsigned descriptorSuppressed=guardDescriptorResults(paths,completed);
    llvh::outs()<<"[DESCRIPTOR_DATA_GUARD] status="<<(completed?"PROVED":"UNKNOWN")
      <<" observed_reads="<<descriptorReadObservations_.size()<<" suppressed="<<descriptorSuppressed
      <<" contract=COMPLETE_CLOSED_ALL_EXECUTIONS_EXACT_OWN_DESCRIPTOR_READ_AND_COOKIE_SOURCE_UNION\n";
    unsigned ownSuppressed=guardOwnDataResults(paths,completed);
    llvh::outs()<<"[OWN_DATA_GUARD] status="<<(completed?"PROVED":"UNKNOWN")<<" observed_reads="<<ownReadObservations_.size()
      <<" observed_deletes="<<ownDeleteObservations_.size()<<" observed_checks="<<ownCheckObservations_.size()<<" suppressed="<<ownSuppressed
      <<" contract=COMPLETE_CLOSED_ALL_EXECUTIONS_EXACT_OWN_DATA_RESULT_AND_COOKIE_SOURCE_UNION\n";
    unsigned dispatchSuppressed=guardInactiveDispatch(paths,completed);
    llvh::outs()<<"[MODULE_DISPATCH_GUARD] status="<<(completed?"PROVED":"UNKNOWN")<<" slots="<<dispatchSlots_.size()
      <<" candidates="<<inactiveDispatch_.size()<<" suppressed="<<dispatchSuppressed
      <<" contract=COMPLETE_CLOSED_REGISTERED_HANDLER_REPLACEMENT_OR_MISSING_KEY_ALL_INSTANCES_UNCALLED_LOCAL_PATH\n";
    unsigned added=0;
    llvh::outs()<<"[NATIVE_ASYNC_ITERATOR_TRANSPORT] status="<<(completed?"PROVED":"UNKNOWN")
      <<" records="<<iteratorCreates_<<" next="<<iteratorNexts_<<" closes="<<iteratorCloses_
      <<" results="<<iterationResults_.size()<<" reason="<<reason_<<" barrier="<<id(barrier_)
      <<" contract=CLOSED_COMPLETE_EXACT_ITERABLE_RECEIVER_NEXT_SNAPSHOT_AND_LEXICAL_SCOPE\n";
    if(!failed_&&(!nativeIterationPresent_||completed))for(auto &p:pending_){
      if(std::any_of(paths.begin(),paths.end(),[&](const DefUseAnalyzer::TaintPath &q){return p.source==q.source&&p.sink==q.sink;}))continue;
      paths.push_back(p);++added;llvh::outs()<<"[TO_SETTER_TRACE] source="<<id(p.source)<<" sink="<<id(p.sink)<<"\n";
    }
    llvh::outs()<<"[TO_SETTER_TRANSPORT] status="<<(failed_?"UNKNOWN":"PROVED")
      <<" invocations="<<invocations_<<" fulfillments="<<fulfilled_<<" awaits="<<awaits_<<" resumed="<<resumed_
      <<" helpers="<<helperCertificates_.size()<<" created="<<setters_.size()<<" writes="<<setterWrites_<<" applied="<<setterCalls_
      <<" class_own_definitions="<<classOwnDefinitions_<<" class_own_writes="<<classOwnWrites_
      <<" class_own_reads="<<classOwnReads_<<" class_own_overwrites="<<classOwnOverwrites_
      <<" define_helpers="<<propertyCertificates_.size()<<" define_calls="<<defineCalls_
      <<" defined_writes="<<definedWrites_<<" property_tentative="<<propertyTentative_
      <<" module_loaders="<<moduleCertificates_.size()<<" requires="<<moduleRequires_<<" factory_calls="<<factoryCalls_
      <<" cache_hits="<<cacheHits_<<" module_tentative="<<moduleTentative_
      <<" dynamic_candidates="<<dynamicWriteCandidates_.size()<<" dynamic_writes="<<dynamicWrites_
      <<" dynamic_calls="<<dynamicCalls_<<" dynamic_tentative="<<dynamicTentative_
      <<" proxy_candidates="<<proxyCandidates_.size()<<" proxy_created="<<proxies_.size()<<" proxy_calls="<<proxyCalls_
      <<" proxy_trap_calls="<<proxyTrapCalls_<<" proxy_forwards="<<proxyForwards_<<" proxy_fallbacks="<<proxyFallbacks_
      <<" proxy_apply_writes="<<proxyApplyWrites_<<" proxy_branches="<<proxyBranches_<<" proxy_tentative="<<proxyTentative_
      <<" proxy_suppressed="<<suppressed
      <<" function_candidates="<<functionDeleteCandidates_.size()<<" function_writes="<<functionWrites_
      <<" function_reads="<<functionReads_<<" function_deletes="<<functionDeletes_<<" function_calls="<<functionCalls_
      <<" callback_calls="<<callbackCalls_<<" function_tentative="<<functionTentative_<<" function_suppressed="<<functionSuppressed
      <<" descriptor_candidates="<<descriptorCandidates_.size()<<" descriptor_calls="<<descriptorCalls_
      <<" descriptor_writes="<<descriptorWrites_<<" descriptor_reads="<<descriptorReads_
      <<" descriptor_tentative="<<descriptorTentative_<<" descriptor_suppressed="<<descriptorSuppressed
      <<" registry_candidates="<<registryWriteCandidates_.size()<<" registry_writes="<<registryWrites_
      <<" registry_reads="<<registryReads_<<" registry_aliases="<<registryAliases_<<" registry_tentative="<<registryTentative_
      <<" own_delete_candidates="<<ownDeleteCandidates_.size()<<" own_check_candidates="<<ownCheckCandidates_.size()
      <<" own_deletes="<<ownDeletes_<<" own_checks="<<ownChecks_<<" own_reads="<<ownReads_
      <<" own_branches="<<ownBranches_<<" own_tentative="<<ownTentative_<<" own_suppressed="<<ownSuppressed
      <<" own_deferred_reads="<<deferredOwnReads_.size()<<" own_deferred_paths="<<deferredOwnSinks_.size()<<" own_promoted="<<ownPromoted_
      <<" dispatch_candidates="<<moduleKeyWriteCandidates_.size()<<" dispatch_has_candidates="<<recordHasCandidates_.size()
      <<" dispatch_key_reads="<<moduleKeyReads_.size()<<" dispatch_writes="<<dispatchRegistrations_.size()
      <<" dispatch_reads="<<dispatchReads_<<" dispatch_calls="<<dispatchCalls_<<" dispatch_checks="<<dispatchChecks_
      <<" dispatch_branches="<<dispatchBranches_<<" dispatch_tentative="<<dispatchTentative_
      <<" dispatch_slots="<<dispatchSlots_.size()<<" dispatch_inactive_candidates="<<inactiveDispatch_.size()<<" dispatch_suppressed="<<dispatchSuppressed
      <<" enum_candidates="<<objectKeysCandidates_.size()<<" enum_write_candidates="<<enumerationWriteCandidates_.size()
      <<" enum_scoped_functions="<<enumerationFunctions_.size()
      <<" fresh_getter_candidates="<<freshGetterCandidates_.size()<<" fresh_getter_definitions="<<freshGetterDefinitions_
      <<" fresh_getter_calls="<<freshGetterCalls_<<" fresh_getter_returns="<<freshGetterReturns_
      <<" nested_alias_candidates="<<nestedAliasCandidates_.size()<<" nested_alias_writes="<<nestedAliasWrites_
      <<" nested_alias_branches="<<nestedAliasBranches_<<" nested_alias_reads="<<nestedAliasReads_<<" nested_alias_operand_reads="<<nestedAliasOperandReads_
      <<" nested_cache_candidates="<<nestedCacheWrites_.size()<<" nested_cache_checks="<<nestedCacheChecksCount_
      <<" nested_cache_writes="<<nestedCacheWritesCount_<<" nested_cache_reads="<<nestedCacheReadsCount_
      <<" enum_snapshots="<<enumerationSnapshots_.size()<<" enum_foreach="<<enumerationForeach_<<" enum_callbacks="<<enumerationCallbacks_
      <<" enum_reads="<<enumerationReads_<<" enum_writes="<<enumerationWrites_<<" enum_calls="<<enumerationCalls_
      <<" enum_branches="<<enumerationBranches_<<" enum_tentative="<<enumerationTentative_
      <<" metadata_scanned="<<metadataInstructions_<<" metadata_limit=150000"
      <<" tentative="<<pending_.size()<<" added="<<added<<" steps="<<steps_<<" reason="<<reason_<<" barrier="<<id(barrier_)
      <<" contract=CLOSED_BOUNDED_TRANSPORT_WITH_EXACT_PROXY_FUNCTION_DESCRIPTOR_OWN_DATA_AND_INACTIVE_HANDLER_REFINEMENT\n";
  }
};
} }                    

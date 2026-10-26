                                                                                     
                                                                               
                                                                              
                                                                                
                                                                                
                                                           
                                                                                
                                                                               
                                                                         
#include <algorithm>
#include <map>
#include <set>

namespace hermes {
namespace {
class BoundedModuleClassReturnTransport {
  using Path = std::vector<Instruction *>;
  struct Trace {
    Instruction *source;
    Path path;
    unsigned originInvocation;
    bool crossedReturn{false};
  };
  enum Kind { Invalid, Empty, Primitive, Undefined, Null, Global, Scope, Closure,
              DateObject, DateNow, AmbientDocument, ClassInternal, DefineClass, DefineStatic, DefineMethod, Instance, ClassPrototype, ClassNameObject };
  struct Datum {
    Kind kind{Invalid};
    Instruction *identity{nullptr};
    unsigned environment{0};
    unsigned object{0};
    std::vector<Trace> traces;
  };
  struct Frame {
    Function *function;
    CreateScopeInst *scope{nullptr};
    CallInst *entry{nullptr};
    unsigned invocation{0};
    unsigned capturedEnvironment{0};
    std::vector<Datum> arguments;
    Datum receiver;
    Datum newTarget;
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
    auto *s = llvh::dyn_cast<LiteralString>(v);
    return s ? s->getValue().str().str() : "";
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
  Datum reject(const char *why, Instruction *at) {
    if (!failed_) { reason_ = why; barrier_ = at; }
    failed_ = true; return {};
  }
  void edge(Datum &d, Instruction *i) {
    std::vector<Trace> unique;
    for (auto t : d.traces) {
      if (std::any_of(unique.begin(), unique.end(), [&](const Trace &other) {
        return t.source == other.source && t.originInvocation == other.originInvocation &&
               t.crossedReturn == other.crossedReturn;
      })) continue;
      if (t.path.size() >= 256) { reject("PATH_LIMIT", i); return; }
      if (t.path.empty() || t.path.back() != i) t.path.push_back(i);
      unique.push_back(std::move(t));
    }
    if (unique.size() > 16) { reject("TRACE_LIMIT", i); return; }
    d.traces = std::move(unique);
  }
  Datum value(Value *v, Frame &frame, Instruction *use) {
    if (llvh::isa<LiteralNumber>(v) || llvh::isa<LiteralString>(v) || llvh::isa<LiteralBool>(v)) return make(Primitive);
    if (llvh::isa<LiteralEmpty>(v)) return make(Empty);
    if (llvh::isa<LiteralUndefined>(v)) return make(Undefined);
    if (llvh::isa<LiteralNull>(v)) return make(Null);
    if (llvh::isa<GlobalObject>(v)) return make(Global);
    if (auto *p = llvh::dyn_cast<Parameter>(v)) {
      if(p==frame.function->getThisParameter() && frame.receiver.kind!=Invalid)return frame.receiver;
      if (p->getParent() != frame.function || p == frame.function->getThisParameter())
        return reject("THIS_OR_FOREIGN_PARAMETER", use);
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
    if (name == "HermesES6Internal" && !declaredGlobals_.count(name)) return make(ClassInternal);
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
    if(object.kind==ClassNameObject){
      auto o=nameObjects_.find(object.object);
      if(o==nameObjects_.end()||!o->second.count(name))return reject("CLASS_NAME_OWN_PROPERTY_MISSING",load);
      Datum d=o->second.at(name);edge(d,load);return d;
    }
    if(object.kind==ClassInternal){
      if(name=="defineClass")return make(DefineClass,load);
      if(name=="defineStaticClassMethod")return make(DefineStatic,load);
      if(name=="defineClassMethod")return make(DefineMethod,load);
    }
    if((object.kind==Closure&&classes_.count(object.object))||object.kind==Instance)return classMember(object,name,load);
    return reject("PROPERTY_OR_GETTER_UNPROVEN", load);
  }
  Datum propertyStore(StorePropertyInst *store, Frame &frame) {
    const auto name = key(store->getProperty());
    Datum object = value(store->getObject(), frame, store);
    Datum d = value(store->getStoredValue(), frame, store);
    if (failed_) return {};
    if (object.kind == Global) {
                                                                               
                                                                               
                                                                         
      if (frame.function != global_ || !declaredGlobals_.count(name) || name.empty() ||
          name == "Date" || name == "document" || name == "HermesES6Internal" || name == "__proto__" ||
          (!primitive(d) && d.kind != Closure)) return reject("GLOBAL_WRITE_OUTSIDE_PROFILE", store);
      edge(d, store); globals_[name] = d; return make(Undefined);
    }
    if (object.kind != AmbientDocument || name != "cookie" || !sink(store) || !primitive(d))
      return reject("PROPERTY_EFFECT_OUTSIDE_PROFILE", store);
    edge(d, store);
    for (auto &trace : d.traces) {
      if (!trace.crossedReturn || !source(trace.source) || trace.path.empty() || trace.path.front() != trace.source) continue;
      if (pending_.size() >= 256) return reject("PENDING_PATH_LIMIT", store);
      pending_.emplace_back(trace.source, trace.path, store);
    }
    return make(Undefined);
  }
  struct ClassState {
    unsigned base{0};
    std::map<std::string,Datum> statics, methods;
  };
  std::map<unsigned,ClassState> classes_;
  std::map<unsigned,std::map<std::string,Datum>> nameObjects_;
  std::map<unsigned,unsigned> instanceClass_;
  unsigned nextObject_{1}, classDefinitions_{0}, methodDefinitions_{0}, classCalls_{0};
  Datum classMember(Datum object, const std::string &name, Instruction *at) {
    bool instance=object.kind==Instance;
    unsigned id=instance?(instanceClass_.count(object.object)?instanceClass_.at(object.object):0):object.object;
    for(unsigned n=0;id&&n<32;++n) {
      auto c=classes_.find(id);if(c==classes_.end())break;
      auto &table=instance?c->second.methods:c->second.statics;
      auto m=table.find(name);if(m!=table.end()){Datum d=m->second;edge(d,at);return d;}
      id=c->second.base;
    }
    return reject("CLASS_MEMBER_OR_GETTER_UNRESOLVED",at);
  }
  Datum classHelper(CallInst *call, Frame &caller, Kind kind) {
    if(value(call->getArgument(0),caller,call).kind!=ClassInternal)
      return reject("CLASS_HELPER_RECEIVER",call);
    unsigned arity=kind==DefineClass?3:4;
    if(call->getNumArguments()!=arity)return reject("CLASS_HELPER_ARITY",call);
    Datum ctor=value(call->getArgument(1),caller,call);
    auto *create=llvh::dyn_cast_or_null<CreateFunctionInst>(ctor.identity);
    if(ctor.kind!=Closure||!ctor.object||!create||llvh::isa<AsyncFunction>(create->getFunctionCode())||llvh::isa<GeneratorFunction>(create->getFunctionCode())||llvh::isa<GeneratorInnerFunction>(create->getFunctionCode()))
      return reject("CLASS_CONSTRUCTOR_IDENTITY",call);
    if(kind==DefineClass){
      if(classes_.count(ctor.object))return reject("CLASS_REDEFINITION",call);
      Datum base=value(call->getArgument(2),caller,call);
      if(base.kind!=Null&&(base.kind!=Closure||!classes_.count(base.object)))return reject("CLASS_HERITAGE_UNRESOLVED",call);
      ClassState c;c.base=base.kind==Null?0:base.object;classes_[ctor.object]=c;++classDefinitions_;
    }else{
      if(!classes_.count(ctor.object))return reject("CLASS_BEFORE_DEFINITION",call);
      const auto name=key(call->getArgument(2));Datum method=value(call->getArgument(3),caller,call);
      if(name.empty()||name=="__proto__"||name=="prototype"||method.kind!=Closure||!method.object)
        return reject("CLASS_METHOD_DEFINITION_SHAPE",call);
      auto &table=kind==DefineStatic?classes_[ctor.object].statics:classes_[ctor.object].methods;
      table[name]=method;++methodDefinitions_;
    }
    return make(Undefined);
  }
  Datum constructClass(ConstructInst *call, Frame &caller) {
    Datum ctor=value(call->getConstructor(),caller,call),nt=value(call->getNewTarget(),caller,call);
    auto *create=llvh::dyn_cast_or_null<CreateFunctionInst>(ctor.identity);
    if(ctor.kind!=Closure||!create||!classes_.count(ctor.object)||nt.kind!=Closure||nt.object!=ctor.object||classes_.at(ctor.object).base)
      return reject("CLASS_CONSTRUCT_EXACT_BASE_ONLY",call);
    Function *target=create->getFunctionCode();
    if(active_.count(target)||active_.size()>=8||++invocations_>64||nextObject_>512||call->getNumArguments()>17)
      return reject("CLASS_CONSTRUCT_BOUND",call);
    if(!ctor.environment||!environments_.count(ctor.environment)||target->getFunctionScopeDesc()->getParent()!=environments_.at(ctor.environment).descriptor)
      return reject("CLASS_CONSTRUCT_ENVIRONMENT",call);
    Datum receiver=make(Instance,call);receiver.object=nextObject_++;instanceClass_[receiver.object]=ctor.object;
    Frame child;child.function=target;child.entry=call;child.invocation=invocations_;child.capturedEnvironment=ctor.environment;child.receiver=receiver;child.newTarget=ctor;
    for(unsigned n=1;n<call->getNumArguments();++n){Datum d=value(call->getArgument(n),caller,call);if(!primitive(d))return reject("CLASS_CONSTRUCT_ARGUMENT",call);edge(d,call);child.arguments.push_back(d);}
    Datum returned=execute(child);
    if(failed_||returned.kind!=Undefined)return reject("CLASS_CONSTRUCT_RETURN_OUTSIDE_PROFILE",call);
    ++classCalls_;return receiver;
  }

  Datum classBuiltin(CallBuiltinInst *call, Frame &caller) {
    const auto op=call->getBuiltinIndex();
    if(!llvh::isa<LiteralUndefined>(call->getArgument(0)))return reject("CLASS_BUILTIN_RECEIVER",call);
    if(op==BuiltinMethod::HermesBuiltin_classHeritagePrototype && call->getNumArguments()==2){
      Datum base=value(call->getArgument(1),caller,call);
      if(base.kind!=Closure||!classes_.count(base.object))return reject("CLASS_HERITAGE_EXACT_BASE",call);
      Datum proto=make(ClassPrototype,call);proto.object=base.object;return proto;
    }
    if(op==BuiltinMethod::HermesBuiltin_initDerivedClass && call->getNumArguments()==4){
      Datum ctor=value(call->getArgument(1),caller,call),base=value(call->getArgument(2),caller,call),proto=value(call->getArgument(3),caller,call);
      auto *create=llvh::dyn_cast_or_null<CreateFunctionInst>(ctor.identity);
      if(ctor.kind!=Closure||!ctor.object||!create||classes_.count(ctor.object)||base.kind!=Closure||!classes_.count(base.object)||proto.kind!=ClassPrototype||proto.object!=base.object)
        return reject("CLASS_DERIVED_INIT_IDENTITIES",call);
      ClassState c;c.base=base.object;classes_[ctor.object]=c;++classDefinitions_;return make(Undefined);
    }
    return reject("CLASS_BUILTIN_OUTSIDE_PROFILE",call);
  }
  Datum invoke(CallInst *call, Frame &caller) {
    if(auto *b=llvh::dyn_cast<CallBuiltinInst>(call))return classBuiltin(b,caller);
    if(auto *c=llvh::dyn_cast<ConstructInst>(call))return constructClass(c,caller);
    if (llvh::isa<ConstructInst>(call) || llvh::isa<CallBuiltinInst>(call) || call->getNumArguments() < 1)
      return reject("NON_ORDINARY_CALL", call);
    Datum callee = value(call->getCallee(), caller, call);
    if(callee.kind==DefineClass||callee.kind==DefineStatic||callee.kind==DefineMethod)return classHelper(call,caller,callee.kind);
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
    if (callee.kind != Closure) return reject("CALL_TARGET_NOT_EXACT_CLOSURE", call);
    auto *creation = llvh::dyn_cast<CreateFunctionInst>(callee.identity);
    if (!creation) return reject("CLOSURE_IDENTITY_MISSING", call);
    Function *target = creation->getFunctionCode();
    if (classes_.count(callee.object) || target->getDefinitionKind() == Function::DefinitionKind::ES6Constructor)
      return reject("CLASS_CONSTRUCTOR_REQUIRES_NEW", call);
    if (active_.count(target)) return reject("RECURSIVE_CALL", call);
    if (active_.size() >= 8 || ++invocations_ > 64) return reject("CALL_BOUND", call);
    if (llvh::isa<AsyncFunction>(target) || llvh::isa<GeneratorFunction>(target) ||
        llvh::isa<GeneratorInnerFunction>(target)) return reject("ASYNC_OR_GENERATOR_CALL", call);
    Datum receiver=value(call->getArgument(0),caller,call);
    if(receiver.kind!=Undefined){
      auto *load=llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
      if(!load||load->getObject()!=call->getArgument(0)||!((receiver.kind==Closure&&classes_.count(receiver.object))||receiver.kind==Instance))
        return reject("CLASS_CALL_RECEIVER_UNRESOLVED",call);
      Datum method=classMember(receiver,key(load->getProperty()),call);
      if(failed_||method.kind!=Closure||method.object!=callee.object)return reject("CLASS_CALL_METHOD_CHANGED",call);
      ++classCalls_;
    }
    if (target->getParameters().size() > 16 || call->getNumArguments() > 17)
      return reject("RECEIVER_OR_ARITY_OUTSIDE_PROFILE", call);
    if (!callee.environment || !environments_.count(callee.environment) ||
        target->getFunctionScopeDesc()->getParent() != environments_.at(callee.environment).descriptor)
      return reject("CLOSURE_LEXICAL_PARENT_IDENTITY", call);
    Frame child; child.function = target; child.entry = call; child.invocation = invocations_;
    child.capturedEnvironment = callee.environment;child.receiver=receiver;
    for (unsigned n = 1; n < call->getNumArguments(); ++n) {
      Datum actual = value(call->getArgument(n), caller, call);
      if (!primitive(actual)) return reject("NON_PRIMITIVE_ARGUMENT", call);
      edge(actual, call); argumentEdges_ += actual.traces.size(); child.arguments.push_back(std::move(actual));
    }
    Datum returned = execute(child);
    if (failed_ || (!primitive(returned)&&returned.kind!=Closure&&returned.kind!=Instance)) return reject("NON_PRIMITIVE_RETURN", call);
    for (auto &trace : returned.traces) trace.crossedReturn = true;
    edge(returned, call); ++returns_;
    return returned;
  }
  Datum instruction(Instruction *i, Frame &frame) {
    if (++steps_ > 20000) return reject("PROOF_STEP_LIMIT", i);
    if(auto *alloc=llvh::dyn_cast<AllocObjectInst>(i)){
      if(!llvh::isa<EmptySentinel>(alloc->getParentObject())||alloc->getSize()!=1||nextObject_>512)
        return reject("CLASS_NAME_OBJECT_SHAPE",i);
      Datum d=make(ClassNameObject,i);d.object=nextObject_++;nameObjects_[d.object]={};return d;
    }
    if(auto *store=llvh::dyn_cast<StoreOwnPropertyInst>(i)){
      Datum object=value(store->getObject(),frame,store),d=value(store->getStoredValue(),frame,store);const auto name=key(store->getProperty());
      if(object.kind!=ClassNameObject||!nameObjects_.count(object.object)||name.empty()||name=="__proto__"||d.kind!=Closure||!classes_.count(d.object)||!nameObjects_[object.object].empty())
        return reject("CLASS_NAME_OWN_DEFINITION",store);
      edge(d,store);nameObjects_[object.object][name]=d;return make(Undefined);
    }
    if(llvh::isa<GetNewTargetInst>(i)){
      if(frame.entry&&llvh::isa<ConstructInst>(frame.entry))return frame.newTarget;
      return make(Undefined);
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
      if (!primitive(d) && d.kind != Closure && d.kind != Instance && d.kind != ClassPrototype && d.kind != Empty)
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
      if (environment->ownerInvocation != frame.invocation)
        for (auto &trace : d.traces) trace.crossedReturn = true;
      edge(d, l); return d;
    }
    if (auto *c = llvh::dyn_cast<CreateFunctionInst>(i)) {
      Datum scope = value(c->getEnvironment(), frame, c);
      if (scope.kind != Scope || !environments_.count(scope.environment) ||
          c->getFunctionCode()->getFunctionScopeDesc()->getParent() != environments_.at(scope.environment).descriptor)
        return reject("CLOSURE_ENVIRONMENT_UNPROVEN", c);
      Datum d = make(Closure, c); d.environment = scope.environment;if(nextObject_>512)return reject("CLASS_OBJECT_LIMIT",c);d.object=nextObject_++; return d;
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
    }
    return reject("CONTROL_OR_EFFECT_OUTSIDE_PROFILE", i);
  }
  Datum execute(Frame &frame) {
    Function *f = frame.function;
    if (!f || f->empty()) return reject("EMPTY_CALLEE", frame.entry);
    auto *ret = llvh::dyn_cast<ReturnInst>(f->front().getTerminator());
    if (!ret || f->front().getTerminator()->getNumSuccessors() != 0)
      return reject("NON_STRAIGHT_LINE_ENTRY", frame.entry);
    active_.insert(f);
    for (auto &i : f->front()) {
      if (failed_) break;
      if (&i == ret) {
        Datum d = value(ret->getValue(), frame, ret); edge(d, ret); active_.erase(f); return d;
      }
      Datum d = instruction(&i, frame); frame.values[&i] = std::move(d);
    }
    active_.erase(f); return {};
  }
  void index() {
    unsigned fi = 0, count = 0;
    for (auto *g : module_->getGlobalProperties()) if (g->isDeclared()) {
      const auto name = key(g->getName()); declaredGlobals_.insert(name);
      if (name == "Date" || name == "document" || name == "HermesES6Internal") reject("HOST_GLOBAL_SHADOWED", nullptr);
    }
    for (auto &f : *module_) {
      if (f.isGlobalScope()) { if (global_) reject("MULTIPLE_GLOBAL_ENTRIES", nullptr); global_ = &f; }
      unsigned ii = 0;
      for (auto &b : f) for (auto &i : b) {
        if (++count > 50000) { reject("MODULE_METADATA_LIMIT", &i); return; }
        ids_[&i] = "F" + std::to_string(fi) + ":I" + std::to_string(ii++);
                                                                               
                                                                                
                                                                             
        if (llvh::isa<DirectEvalInst>(&i) || llvh::isa<DeletePropertyInst>(&i) || llvh::isa<StoreGetterSetterInst>(&i))
          reject("DYNAMIC_OR_DESCRIPTOR_MUTATION", &i);
        if (auto *s = llvh::dyn_cast<StorePropertyInst>(&i)) {
          const auto name = key(s->getProperty());
          if (name.empty() || name == "Date" || name == "document" || name == "HermesES6Internal" || name == "now" || name == "__proto__")
            reject("HOST_OR_DYNAMIC_PROPERTY_MUTATION", s);
        }
        if (auto *l = llvh::dyn_cast<LoadPropertyInst>(&i)) {
          const auto name = key(l->getProperty());
          bool internalHelper=false;
          if(auto *base=llvh::dyn_cast<TryLoadGlobalPropertyInst>(l->getObject()))internalHelper=key(base->getProperty())=="HermesES6Internal";
          if ((!internalHelper&&(name == "defineClass" || name == "defineStaticClassMethod" || name == "defineClassMethod")) || name == "defineProperty" || name == "defineProperties" || name == "__defineGetter__" ||
              name == "__defineSetter__" || name == "setPrototypeOf") reject("DESCRIPTOR_API_OUTSIDE_PROFILE", l);
        }
      }
      ++fi;
    }
    if (!global_) reject("GLOBAL_ENTRY_MISSING", nullptr);
  }
 public:
  BoundedModuleClassReturnTransport(Module *m, const std::vector<Instruction *> &sources,
      const std::vector<Instruction *> &sinks) : module_(m), sources_(sources), sinks_(sinks) { index(); }
  void append(std::vector<DefUseAnalyzer::TaintPath> &paths) {
    if (!failed_) { Frame entry; entry.function = global_; execute(entry); }
    unsigned added = 0;
    if (!failed_) for (const auto &p : pending_) {
      if (std::any_of(paths.begin(), paths.end(), [&](const DefUseAnalyzer::TaintPath &existing) {
        return existing.source == p.source && existing.sink == p.sink;
      })) continue;
      paths.push_back(p); ++added;
      llvh::outs() << "[MODULE_CLASS_RETURN_TRACE] source=" << id(p.source) << " sink=" << id(p.sink) << "\n";
    }
    llvh::outs() << "[MODULE_CLASS_RETURN_TRANSPORT] status=" << (failed_ ? "UNKNOWN" : "PROVED")
                 << " invocations=" << invocations_ << " returns=" << returns_ << " argument_edges=" << argumentEdges_
                 << " classes=" << classDefinitions_ << " methods=" << methodDefinitions_ << " class_calls=" << classCalls_
                 << " tentative=" << pending_.size() << " added=" << added << " steps=" << steps_
                 << " reason=" << reason_ << " barrier=" << id(barrier_)
                 << " contract=CLOSED_STRAIGHT_LINE_EXACT_CLASS_OBJECT_METHOD_RECEIVER_AND_LEXICAL_ENV_ADDITIVE_PRISTINE_INTERNALS\n";
  }
};
}             
}                    

                                                                               
                                                                               
                                                                             
                                                                                
                                                                                
#include <algorithm>
#include <map>
#include <set>

namespace hermes {
namespace {
class BoundedAsyncArgumentTransport {
  using Path = std::vector<Instruction *>;
  struct Trace {
    Instruction *source;
    Path path;
    int formal{-1};
    CallInst *argumentCall{nullptr};
  };
  enum Kind { Invalid, Primitive, Undefined, Null, Global, Scope, Closure,
              Record, DateObject, DateNow, AmbientDocument, OpaquePromise };
  struct Datum {
    Kind kind{Invalid};
    Instruction *identity{nullptr};
    std::vector<Trace> traces;
  };
  struct Frame {
    Function *function;
    CreateScopeInst *scope{nullptr};
    CallInst *entry{nullptr};
    std::vector<Datum> arguments;
    std::map<Value *, Datum> values;
    std::map<Variable *, Datum> variables;
    std::map<AllocStackInst *, Datum> stack;
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
  std::map<Instruction *, std::string> ids_;
  std::map<Function *, std::string> functionIds_;
  std::map<Function *, unsigned> creationCounts_;
  std::map<AsyncFunction *, Binding> bindings_;
  std::map<CallInst *, Binding *> entryBindings_;
  std::set<CallInst *> reportedCalls_;
  std::map<std::string, Datum> globals_;
  std::set<std::string> declaredGlobals_;
  std::map<Instruction *, std::map<std::string, Datum>> records_;
  std::vector<DefUseAnalyzer::TaintPath> *paths_{nullptr};
  Function *global_{nullptr};
  unsigned steps_{0}, invocations_{0}, added_{0}, mappingCalls_{0};
  bool failed_{false}, tooLarge_{false}, hostShadowed_{false};
  const char *reason_{"NORMAL_ENTRY_PREFIX"};
  Instruction *barrier_{nullptr};

  static Function *owner(Instruction *i) { return i->getParent()->getParent(); }
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
  std::string fid(Function *f) const {
    auto found = functionIds_.find(f);
    return found == functionIds_.end() ? "NONE" : found->second;
  }
  static bool before(Instruction *a, Instruction *b) {
    if (!a || !b || a->getParent() != b->getParent()) return false;
    for (auto &i : *a->getParent()) {
      if (&i == b) return false;
      if (&i == a) return true;
    }
    return false;
  }
  Datum reject(const char *why, Instruction *at) {
    if (!failed_) { reason_ = why; barrier_ = at; }
    failed_ = true; return {};
  }
  bool edge(Datum &d, Instruction *i) {
                                                                             
                                                                          
    std::vector<Trace> unique;
    for (const auto &trace : d.traces) {
      bool found = std::any_of(unique.begin(), unique.end(), [&](const Trace &t) {
        return t.source == trace.source && t.formal == trace.formal && t.argumentCall == trace.argumentCall;
      });
      if (!found) unique.push_back(trace);
    }
    d.traces = std::move(unique);
    if (d.traces.size() > 16) { reject("TRACE_COUNT_LIMIT", i); return false; }
    for (auto &t : d.traces) {
      if (t.path.size() >= 512) { reject("TRACE_LENGTH_LIMIT", i); return false; }
      if (t.path.empty() || t.path.back() != i) t.path.push_back(i);
    }
    return true;
  }
                                                                                
  Binding recognize(AsyncFunction *function) {
    Binding b; b.wrapper = function;
    auto bad = [&](const char *reason) { b.reason = reason; return b; };
    if (function->isLazy() || function->empty() ||
        function->getBasicBlockList().size() != 1 ||
        function->getDefinitionKind() != Function::DefinitionKind::ES5Function ||
        !function->getParameters().empty() || creationCounts_[function] != 1)
      return bad("ASYNC_FUNCTION_KIND_OR_SHAPE");
    CreateScopeInst *scope = nullptr;
    GetBuiltinClosureInst *builtin = nullptr;
    ReturnInst *ret = nullptr;
    for (auto &i : function->front()) {
      if (auto *s = llvh::dyn_cast<CreateScopeInst>(&i)) {
        if (scope || s->getCreatedScopeDesc() != function->getFunctionScopeDesc()) return bad("WRAPPER_SCOPE");
        scope = s;
      } else if (auto *a = llvh::dyn_cast<CreateArgumentsInst>(&i)) {
        if (!scope || b.arguments) return bad("WRAPPER_ARGUMENTS");
        b.arguments = a;
      } else if (auto *s = llvh::dyn_cast<StoreFrameInst>(&i)) {
        if (!scope || b.spawn || s->getEnvironment() != scope ||
            s->getVariable()->getParent() != function->getFunctionScopeDesc() ||
            !llvh::isa<LiteralUndefined>(s->getValue())) return bad("WRAPPER_FRAME_EFFECT");
      } else if (auto *c = llvh::dyn_cast<CreateFunctionInst>(&i)) {
        if (!scope || b.generatorClosure || llvh::isa<CreateGeneratorInst>(c) ||
            c->getEnvironment() != scope) return bad("WRAPPER_GENERATOR_CLOSURE");
        b.generatorClosure = c;
        b.generator = llvh::dyn_cast<GeneratorFunction>(c->getFunctionCode());
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
        b.generator->getDefinitionKind() != Function::DefinitionKind::ES5Function ||
        !b.generator->getParameters().empty()) return bad("GENERATOR_WRAPPER_KIND");
    for (auto *u : b.arguments->getUsers()) if (u != b.spawn) return bad("ARGUMENTS_ESCAPE");
    for (auto *u : b.generatorClosure->getUsers()) if (u != b.spawn) return bad("GENERATOR_CLOSURE_ESCAPE");
    for (auto *u : builtin->getUsers()) if (u != b.spawn) return bad("BUILTIN_CLOSURE_ESCAPE");
    scope = nullptr; ret = nullptr;
    for (auto &i : b.generator->front()) {
      if (auto *s = llvh::dyn_cast<CreateScopeInst>(&i)) {
        if (scope || s->getCreatedScopeDesc() != b.generator->getFunctionScopeDesc()) return bad("GENERATOR_SCOPE");
        scope = s;
      } else if (auto *s = llvh::dyn_cast<StoreFrameInst>(&i)) {
        if (!scope || b.createGenerator || s->getEnvironment() != scope ||
            s->getVariable()->getParent() != b.generator->getFunctionScopeDesc() ||
            !llvh::isa<LiteralUndefined>(s->getValue())) return bad("GENERATOR_FRAME_EFFECT");
      } else if (auto *c = llvh::dyn_cast<CreateGeneratorInst>(&i)) {
        if (!scope || b.createGenerator || c->getEnvironment() != scope) return bad("CREATE_GENERATOR_IDENTITY");
        b.createGenerator = c;
        b.inner = llvh::dyn_cast<GeneratorInnerFunction>(c->getFunctionCode());
      } else if (auto *r = llvh::dyn_cast<ReturnInst>(&i)) {
        if (!b.createGenerator || r->getValue() != b.createGenerator) return bad("GENERATOR_RETURN");
        ret = r;
      } else return bad("GENERATOR_NON_SIMPLE_PARAMETERS_OR_EFFECT");
    }
    if (!ret || !b.inner || b.inner->isLazy() || b.inner->empty() ||
        creationCounts_[b.inner] != 1 || b.inner->getParameters().size() > 16)
      return bad("INNER_KIND_OR_LIMIT");
    for (auto *u : b.createGenerator->getUsers()) if (u != ret) return bad("GENERATOR_OBJECT_ESCAPE");
    auto *innerThis = b.inner->getThisParameter();
    if (innerThis && !innerThis->getUsers().empty()) return bad("INNER_THIS_OUTSIDE_PROFILE");
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
    b.valid = true; b.reason = "EXACT_COMPILER_ARGUMENT_BINDING"; return b;
  }

                                                                               
                                                                                 
  bool exactEntryClosure(CreateFunctionInst *creation, CallInst *site) {
    if (!global_ || owner(creation) != global_ || creation->getParent() != &global_->front() ||
        owner(site) != global_ || site->getParent() != &global_->front() ||
        !before(creation, site) || site->getNumArguments() < 1 || site->getNumArguments() > 17 ||
        !llvh::isa<LiteralUndefined>(site->getNewTarget()) ||
        !llvh::isa<LiteralUndefined>(site->getArgument(0))) return false;
    StorePropertyInst *binding = nullptr;
    for (auto *u : creation->getUsers()) {
      auto *s = llvh::dyn_cast<StorePropertyInst>(u);
      if (!s || binding || s->getStoredValue() != creation ||
          !llvh::isa<GlobalObject>(s->getObject()) || key(s->getProperty()).empty() ||
          owner(s) != global_ || s->getParent() != &global_->front() || !before(s, site)) return false;
      binding = s;
    }
    if (!binding || !declaredGlobals_.count(key(binding->getProperty()))) return false;
    const auto name = key(binding->getProperty());
    bool siteFound = false;
    for (auto &f : *module_) for (auto &block : f) for (auto &i : block) {
      if (auto *s = llvh::dyn_cast<StorePropertyInst>(&i))
        if (llvh::isa<GlobalObject>(s->getObject()) && key(s->getProperty()) == name && s != binding) return false;
      if (auto *l = llvh::dyn_cast<LoadPropertyInst>(&i)) {
        if (!llvh::isa<GlobalObject>(l->getObject()) || key(l->getProperty()) != name) continue;
        if (owner(l) != global_ || l->getParent() != &global_->front() || !before(binding, l)) return false;
        for (auto *u : l->getUsers()) {
          auto *c = llvh::dyn_cast<CallInst>(u);
          if (!c || c->getCallee() != l || llvh::isa<ConstructInst>(c) || llvh::isa<CallBuiltinInst>(c) ||
              owner(c) != global_ || c->getParent() != &global_->front()) return false;
          if (c == site) siteFound = true;
        }
      }
    }
    return siteFound;
  }
  Datum value(Value *v, Frame &frame, Instruction *use) {
    if (llvh::isa<LiteralNumber>(v) || llvh::isa<LiteralString>(v) || llvh::isa<LiteralBool>(v)) return make(Primitive);
    if (llvh::isa<LiteralUndefined>(v)) return make(Undefined);
    if (llvh::isa<LiteralNull>(v)) return make(Null);
    if (llvh::isa<GlobalObject>(v)) return make(Global);
    if (auto *p = llvh::dyn_cast<Parameter>(v)) {
      if (p->getParent() != frame.function || p == frame.function->getThisParameter())
        return reject("THIS_OR_FOREIGN_PARAMETER", use);
      auto &params = frame.function->getParameters();
      for (unsigned n = 0; n < params.size(); ++n)
        if (params[n] == p) return n < frame.arguments.size() ? frame.arguments[n] : make(Undefined);
      return reject("PARAMETER_NOT_BOUND", use);
    }
    auto found = frame.values.find(v);
    return found == frame.values.end() ? reject("VALUE_NOT_IN_PREFIX", use) : found->second;
  }
  Datum globalRead(const std::string &name, Frame &frame, Instruction *at) {
    auto found = globals_.find(name);
    if (found != globals_.end()) {
                                                                              
                                                                               
      if (frame.entry && (name != "document" || found->second.kind != Record))
        return reject("INNER_CAPTURED_GLOBAL_OUTSIDE_PROFILE", at);
      Datum d = found->second; edge(d, at); return d;
    }
    if (name == "document" && !declaredGlobals_.count(name)) return make(AmbientDocument);
    if (!frame.entry && name == "Date" && !declaredGlobals_.count(name)) return make(DateObject);
    return reject("GLOBAL_READ_UNRESOLVED", at);
  }
  Datum propertyRead(LoadPropertyInst *load, Frame &frame) {
    const auto name = key(load->getProperty());
    if (name.empty()) return reject("DYNAMIC_PROPERTY_KEY", load);
    Datum object = value(load->getObject(), frame, load);
    if (object.kind == Global) return globalRead(name, frame, load);
    if (object.kind == DateObject && name == "now") return make(DateNow);
    if (object.kind != Record) return reject("GETTER_OR_PROPERTY_NOT_PROVED", load);
    auto found = records_[object.identity].find(name);
    if (found == records_[object.identity].end()) return reject("OWN_PROPERTY_NOT_PROVED", load);
    Datum d = found->second; edge(d, load); return d;
  }
  void emitProof(CallInst *call, StorePropertyInst *store, Datum d) {
    edge(d, store);
    if (failed_) return;
    for (auto &trace : d.traces) {
      if (trace.formal < 0 || trace.argumentCall != call || !source(trace.source) || trace.path.empty() ||
          trace.path.front() != trace.source || trace.path.back() != store) continue;
      bool known = std::any_of(paths_->begin(), paths_->end(), [&](const DefUseAnalyzer::TaintPath &p) {
        return p.source == trace.source && p.sink == store;
      });
      if (!known) { paths_->emplace_back(trace.source, trace.path, store); ++added_; }
      llvh::outs() << "[ASYNC_PREFIX_TRACE] call=" << id(call) << " source=" << id(trace.source)
                   << " sink=" << id(store) << " formal=" << trace.formal
                   << " disposition=" << (known ? "ALREADY_PRESENT" : "ADDED") << " path=";
      for (auto *node : trace.path) llvh::outs() << id(node) << "/" << node->getKindStr() << " ";
      llvh::outs() << "\n";
    }
  }
  Datum propertyStore(Value *ov, Value *pv, Value *sv, Instruction *at, Frame &frame, bool own) {
    const auto name = key(pv);
    if (name.empty() || name == "__proto__" || name == "prototype" || name == "constructor")
      return reject("DYNAMIC_OR_PROTOTYPE_WRITE", at);
    Datum object = value(ov, frame, at), d = value(sv, frame, at);
    if (failed_) return {};
    if (object.kind == Global) {
      if (frame.entry || !declaredGlobals_.count(name) || name == "Date" || name == "Promise" ||
          name == "Function" || name == "Object" || name == "Reflect" ||
          (!primitive(d) && d.kind != Record && d.kind != Closure && d.kind != OpaquePromise))
        return reject("GLOBAL_WRITE_OR_ESCAPE", at);
      edge(d, at); globals_[name] = d; return make(Undefined);
    }
    auto *store = llvh::dyn_cast<StorePropertyInst>(at);
    const bool cookie = frame.entry && store && sink(store) && name == "cookie";
    if (object.kind == AmbientDocument && cookie && primitive(d)) {
      emitProof(frame.entry, store, d);
      return reject("FIRST_AMBIENT_COOKIE_BARRIER", at);
    }
    if (object.kind != Record || !primitive(d) ||
        (frame.entry && !cookie) || (!own && !records_[object.identity].count(name)))
      return reject("PROPERTY_WRITE_OR_ESCAPE", at);
    if (cookie) emitProof(frame.entry, store, d);
    edge(d, at); records_[object.identity][name] = d; return make(Undefined);
  }

  Datum invokeAsync(CallInst *call, CreateFunctionInst *creation, Frame &globalFrame) {
    auto *function = llvh::dyn_cast<AsyncFunction>(creation->getFunctionCode());
    if (!function || !bindings_.count(function)) return reject("CALL_NOT_ASYNC_WRAPPER", call);
    Binding &binding = bindings_[function];
    if (!binding.valid) return reject(binding.reason, call);
    if (!entryBindings_.count(call) || entryBindings_[call] != &binding)
      return reject("ASYNC_CALLEE_ALIAS_REBIND_OR_ESCAPE", call);
    if (++invocations_ > 32) return reject("INVOCATION_LIMIT", call);
    Frame inner{binding.inner}; inner.scope = binding.innerScope; inner.entry = call;
    inner.values[binding.innerScope] = make(Scope, binding.innerScope);
    for (unsigned n = 1; n < call->getNumArguments(); ++n) {
      Datum d = value(call->getArgument(n), globalFrame, call);
      if (!primitive(d)) return reject("NONPRIMITIVE_ACTUAL", call);
      for (auto &t : d.traces) {
        t.formal = static_cast<int>(n - 1); t.argumentCall = call;
      }
      edge(d, call); edge(d, binding.spawn); edge(d, binding.createGenerator);
      inner.arguments.push_back(d);
    }
    if (failed_) return {};
    const unsigned previousAdded = added_;
    const char *stop = "NORMAL_RETURN";
    Instruction *cutoff = nullptr;
    for (auto &i : *binding.prefix) {
      if (auto *yield = llvh::dyn_cast<SaveAndYieldInst>(&i)) {
                                                                               
                                                                            
        Datum yielded = value(yield->getResult(), inner, yield);
        if (!primitive(yielded)) reject("AWAIT_NONPRIMITIVE_OR_THENABLE", yield);
                                                                        
        stop = "FIRST_AWAIT_CUTOFF"; cutoff = yield; break;
      }
      if (auto *ret = llvh::dyn_cast<ReturnInst>(&i)) {
        Datum result = value(ret->getValue(), inner, ret);
        if (!primitive(result)) reject("ASYNC_RETURN_THENABLE_OR_UNKNOWN", ret);
        cutoff = ret; break;
      }
      Datum d = instruction(&i, inner);
      if (failed_) { stop = reason_; cutoff = barrier_; break; }
      inner.values[&i] = std::move(d);
    }
    if (!cutoff && !failed_) reject("INNER_PREFIX_NO_RETURN_OR_AWAIT", call);
    reportedCalls_.insert(call);
    llvh::outs() << "[ASYNC_ARGUMENT_BOUNDED] call=" << id(call)
                 << " mapping=1 eligible=" << (!failed_ ? 1 : 0)
                 << " added=" << added_ - previousAdded << " reason=" << (failed_ ? reason_ : stop)
                 << " barrier=" << id(failed_ ? barrier_ : cutoff) << "\n";
                                                                         
    return failed_ ? Datum{} : make(OpaquePromise, call);
  }
  Datum instruction(Instruction *i, Frame &frame) {
    if (++steps_ > 20000) return reject("PROOF_STEP_LIMIT", i);
    if (auto *scope = llvh::dyn_cast<CreateScopeInst>(i)) {
      if (frame.scope || scope->getCreatedScopeDesc() != frame.function->getFunctionScopeDesc())
        return reject("SCOPE_NOT_LOCAL", i);
      frame.scope = scope; return make(Scope, scope);
    }
    if (auto *a = llvh::dyn_cast<AllocStackInst>(i)) {
      frame.stack[a] = {}; return make(Invalid, a);
    }
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
      if (s->getEnvironment() != frame.scope ||
          s->getVariable()->getParent() != frame.function->getFunctionScopeDesc()) return reject("CAPTURED_FRAME_WRITE", s);
      Datum d = value(s->getValue(), frame, s);
      if (!primitive(d) && !(frame.entry == nullptr && (d.kind == Record || d.kind == Closure || d.kind == OpaquePromise)))
        return reject("FRAME_VALUE_NOT_SCALAR", s);
      edge(d, s); frame.variables[s->getVariable()] = d; return make(Undefined);
    }
    if (auto *l = llvh::dyn_cast<LoadFrameInst>(i)) {
      if (l->getEnvironment() != frame.scope || !frame.variables.count(l->getLoadVariable()))
        return reject("CAPTURED_OR_UNINITIALIZED_FRAME", l);
      Datum d = frame.variables[l->getLoadVariable()]; edge(d, l); return d;
    }
    if (llvh::isa<CreateGeneratorInst>(i)) return reject("DIRECT_GENERATOR_OUTSIDE_PROFILE", i);
    if (auto *c = llvh::dyn_cast<CreateFunctionInst>(i)) {
      if (frame.entry || c->getEnvironment() != frame.scope) return reject("CLOSURE_ESCAPE_OR_CAPTURE", i);
      return make(Closure, c);
    }
    if (auto *l = llvh::dyn_cast<LoadPropertyInst>(i)) return propertyRead(l, frame);
    if (auto *s = llvh::dyn_cast<StorePropertyInst>(i))
      return propertyStore(s->getObject(), s->getProperty(), s->getStoredValue(), s, frame, false);
    if (auto *s = llvh::dyn_cast<StoreOwnPropertyInst>(i))
      return propertyStore(s->getObject(), s->getProperty(), s->getStoredValue(), s, frame, true);
    if (auto *a = llvh::dyn_cast<AllocObjectInst>(i)) {
      if (frame.entry || !llvh::isa<EmptySentinel>(a->getParentObject()) || records_.size() >= 32)
        return reject("RECORD_ALLOCATION_OUTSIDE_PROFILE", a);
      records_[a] = {}; return make(Record, a);
    }
    if (auto *c = llvh::dyn_cast<CallInst>(i)) {
      if (frame.entry || llvh::isa<ConstructInst>(c) || llvh::isa<CallBuiltinInst>(c))
        return reject("UNKNOWN_CALL_BEFORE_AWAIT", c);
      Datum callee = value(c->getCallee(), frame, c);
      if (callee.kind == DateNow) {
        auto *load = llvh::dyn_cast<LoadPropertyInst>(c->getCallee());
        if (!load || c->getNumArguments() != 1 || c->getArgument(0) != load->getObject())
          return reject("DATE_CALL_SHAPE", c);
        Instruction *registered = source(c) ? static_cast<Instruction *>(c) : source(load) ? load : nullptr;
        if (!registered) return reject("DATE_SOURCE_NOT_REGISTERED", c);
        Datum d = make(Primitive); d.traces.push_back({registered, {registered}, -1}); edge(d, c); return d;
      }
      if (callee.kind != Closure) return reject("CALL_TARGET_NOT_CLOSURE", c);
      auto *creation = llvh::dyn_cast<CreateFunctionInst>(callee.identity);
      return creation ? invokeAsync(c, creation, frame) : reject("CLOSURE_IDENTITY_MISSING", c);
    }
    if (auto *b = llvh::dyn_cast<BinaryOperatorInst>(i)) {
      Datum left = value(b->getLeftHandSide(), frame, b), right = value(b->getRightHandSide(), frame, b);
      if (!primitive(left) || !primitive(right) || b->getOperatorKind() != BinaryOperatorInst::OpKind::AddKind)
        return reject("PRIMITIVE_ADD_NOT_PROVED", b);
      Datum d = make(Primitive); d.traces = left.traces;
      d.traces.insert(d.traces.end(), right.traces.begin(), right.traces.end()); edge(d, b); return d;
    }
    if (auto *m = llvh::dyn_cast<MovInst>(i)) { Datum d = value(m->getSingleOperand(), frame, m); edge(d, m); return d; }
    if (auto *u = llvh::dyn_cast<UnaryOperatorInst>(i)) {
      if (u->getOperatorKind() == UnaryOperatorInst::OpKind::VoidKind) {
        value(u->getSingleOperand(), frame, u); return make(Undefined);
      }
    }
    return reject("UNSUPPORTED_CONTROL_THIS_ARGUMENTS_OR_EFFECT", i);
  }
 public:
  BoundedAsyncArgumentTransport(Module *m, const std::vector<Instruction *> &sources,
      const std::vector<Instruction *> &sinks) : module_(m), sources_(sources), sinks_(sinks) {
    for (auto *g : m->getGlobalProperties()) if (g->isDeclared()) {
      const auto name = key(g->getName()); declaredGlobals_.insert(name);
      if (name == "Date" || name == "Promise" || name == "Function") hostShadowed_ = true;
    }
    unsigned fi = 0;
    for (auto &f : *m) {
      functionIds_[&f] = "F" + std::to_string(fi++);
      if (f.isGlobalScope()) { if (global_) tooLarge_ = true; global_ = &f; }
      unsigned ii = 0;
      for (auto &b : f) for (auto &i : b) {
        if (ids_.size() >= 50000) { tooLarge_ = true; return; }
        ids_[&i] = functionIds_[&f] + ":I" + std::to_string(ii++);
        if (auto *c = llvh::dyn_cast<CreateFunctionInst>(&i)) ++creationCounts_[c->getFunctionCode()];
      }
    }
    for (auto &f : *m) if (auto *async = llvh::dyn_cast<AsyncFunction>(&f)) {
      if (bindings_.size() >= 32) { tooLarge_ = true; return; }
      bindings_[async] = recognize(async);
    }
  }
  void append(std::vector<DefUseAnalyzer::TaintPath> &paths) {
    paths_ = &paths;
    if (tooLarge_ || !global_ || global_->empty() || sinks_.size() > 32 || hostShadowed_ ||
        !global_->front().getUsers().empty()) {
      llvh::outs() << "[ASYNC_ARGUMENT_TRANSPORT] status=UNKNOWN mapping_calls=0 added=0 reason=MODULE_LIMIT_OR_HOST_BINDING\n";
      return;
    }
                                                                           
                                                                             
                                                                            
    std::map<std::string, CreateFunctionInst *> candidates;
    for (auto &i : global_->front()) if (auto *store = llvh::dyn_cast<StorePropertyInst>(&i)) {
      auto *create = llvh::dyn_cast<CreateFunctionInst>(store->getStoredValue());
      if (create && llvh::isa<GlobalObject>(store->getObject()) &&
          llvh::isa<AsyncFunction>(create->getFunctionCode())) candidates[key(store->getProperty())] = create;
    }
    unsigned candidateCalls = 0;
    for (auto &i : global_->front()) if (auto *call = llvh::dyn_cast<CallInst>(&i)) {
      auto *load = llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
      if (!load || !llvh::isa<GlobalObject>(load->getObject()) ||
          !candidates.count(key(load->getProperty()))) continue;
      if (++candidateCalls > 32) { reject("CALLSITE_LIMIT", call); break; }
      auto *creation = candidates[key(load->getProperty())];
      auto *function = llvh::cast<AsyncFunction>(creation->getFunctionCode());
      auto &binding = bindings_[function];
      if (!binding.valid || !exactEntryClosure(creation, call)) {
        llvh::outs() << "[ASYNC_ARGUMENT_BOUNDED] call=" << id(call)
                     << " mapping=0 eligible=0 added=0 reason="
                     << (binding.valid ? "ASYNC_CALLEE_ALIAS_REBIND_OR_ESCAPE" : binding.reason)
                     << " barrier=" << id(call) << "\n";
        reportedCalls_.insert(call); continue;
      }
      entryBindings_[call] = &binding; ++mappingCalls_;
      for (unsigned n = 0; n < binding.formalStores.size(); ++n) {
        auto *actual = n + 1 < call->getNumArguments() ? call->getArgument(n + 1) : nullptr;
        auto *actualInstruction = actual ? llvh::dyn_cast<Instruction>(actual) : nullptr;
        llvh::outs() << "[ASYNC_ARGUMENT_BINDING] call=" << id(call)
                     << " wrapper=" << fid(binding.wrapper) << " spawn=" << id(binding.spawn)
                     << " generator=" << fid(binding.generator) << " create_generator=" << id(binding.createGenerator)
                     << " inner=" << fid(binding.inner) << " formal=" << n
                     << " actual=" << (actualInstruction ? id(actualInstruction) : actual ? actual->getKindStr().str() : "MISSING_UNDEFINED")
                     << " formal_store=" << id(binding.formalStores[n]) << " status=PROVED_MAPPING_ONLY\n";
      }
    }
    Frame frame{global_};
    for (auto &i : global_->front()) {
      if (failed_) break;
      if (llvh::isa<ReturnInst>(&i)) break;
      Datum d = instruction(&i, frame);
      if (failed_) break;
      frame.values[&i] = std::move(d);
    }
    for (const auto &entry : entryBindings_) if (!reportedCalls_.count(entry.first))
      llvh::outs() << "[ASYNC_ARGUMENT_BOUNDED] call=" << id(entry.first)
                   << " mapping=1 eligible=0 added=0 reason=GLOBAL_PREFIX_NOT_REACHED barrier=" << id(barrier_) << "\n";
    llvh::outs() << "[ASYNC_ARGUMENT_TRANSPORT] status=" << (failed_ ? "UNKNOWN" : "PROVED_PREFIX")
                 << " wrappers=" << bindings_.size() << " mapping_calls=" << mappingCalls_
                 << " added=" << added_ << " reason=" << reason_ << " barrier=" << id(barrier_)
                 << " contract=CALLSITE_LOCAL_FIRST_AWAIT_PREFIX_ADDITIVE\n";
  }
};
}             
}                    

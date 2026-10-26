                                                                               
                                                                                
                                                                                 
                                                                   
#include <algorithm>
#include <cmath>
#include <map>
#include <set>

namespace hermes {
namespace {
class BoundedCtorInstanceTransport {
  using Path = std::vector<Instruction *>;
  struct Witness {
    ConstructInst *allocation;
    Instruction *write;
    Instruction *read;
  };
  struct Trace {
    Instruction *source;
    Path path;
    std::vector<Witness> witnesses;
  };
  enum Kind {
    Invalid, Scalar, Undefined, Null, Global, Scope, Closure, Instance, Record,
    DateObject, DateNow, Helpers, DefineClass, CtorCall, Arguments, Array,
    AmbientDocument, DefineMethod, DefineStaticMethod, DefineField, Prototype,
    FunctionCall, ObjectBuiltin, DefineProperty, SetPrototype, GetOwnDescriptor
  };
  struct Datum {
    Kind kind{Invalid};
    unsigned ref{0};
    bool knownNumber{false};
    double number{0};
    bool knownBoolean{false};
    bool boolean{false};
    std::vector<Trace> traces;
  };
  struct Slot {
    Datum value;
    Instruction *write;
    bool accessor{false};
    unsigned getter{0}, setter{0};
    bool writable{true}, enumerable{true}, configurable{true};
  };
  struct Environment {
    unsigned parent{0};
    std::map<Variable *, Datum> variables;
  };
  struct ClosureInfo {
    Function *body;
    unsigned environment;
    CreateFunctionInst *creation;
    bool isClass{false};
    unsigned base{0};
    CallInst *definition{nullptr};
    unsigned methodOwner{0};
    bool staticMethod{false};
    std::map<std::string, unsigned> methods;
    std::map<std::string, unsigned> staticMethods;
                                                                            
                                                                            
    unsigned recordPrototype{0};
  };
  struct Object {
    ConstructInst *allocation{nullptr};
    unsigned ctor{0};
    std::map<std::string, Slot> properties;
    std::vector<Datum> elements;
  };
  enum Mode { GlobalMode, WrapperMode, ConstructorMode, MethodMode };
  struct Frame {
    Function *function;
    Mode mode;
    unsigned environment;
    unsigned ctor{0};
    Datum receiver;
    std::vector<Datum> arguments;
    std::map<Value *, Datum> values;
    std::map<AllocStackInst *, Datum> stack;
    Path calls;
    unsigned superCalls{0};
    unsigned definitions{0};
  };
  Module *module_;
  const std::vector<Instruction *> &sources_, &sinks_;
  std::map<Instruction *, std::string> ids_;
  std::map<std::string, Datum> globals_;
  std::map<unsigned, Environment> environments_;
  std::map<unsigned, ClosureInfo> closures_;
  std::map<unsigned, Object> objects_;
  std::set<Function *> active_;
  unsigned nextEnvironment_{1}, nextClosure_{1}, nextObject_{1};
  unsigned steps_{0}, reads_{0}, cleanReads_{0}, depth_{0};
  bool failed_{false};
  const char *reason_{"EXACT_INSTANCE_PREFIX"};
  Instruction *barrier_{nullptr};
  Instruction *target_{nullptr};
  Datum sinkValue_;
  bool reached_{false};
  bool declaredDocument_{false}, moduleTooLarge_{false};

  static Function *owner(Instruction *i) { return i->getParent()->getParent(); }
  std::string nodeId(Instruction *i) const {
    if (!i) return "NONE";
    auto it = ids_.find(i); return it == ids_.end() ? "UNINDEXED" : it->second;
  }
  static std::string key(Value *v) {
    auto *s = llvh::dyn_cast<LiteralString>(v);
    return s ? s->getValue().str().str() : "";
  }
  static Datum make(Kind k, unsigned ref = 0) {
    Datum d; d.kind = k; d.ref = ref; return d;
  }
  static Datum number(double n) {
    Datum d = make(Scalar); d.knownNumber = true; d.number = n; return d;
  }
  static Datum boolean(bool b) {
    Datum d = make(Scalar); d.knownBoolean = true; d.boolean = b; return d;
  }
  static bool primitive(const Datum &d) {
    return d.kind == Scalar || d.kind == Undefined || d.kind == Null;
  }
  static bool forbiddenKey(const std::string &s) {
    return s.empty() || s == "__proto__" || s == "prototype" ||
        s == "constructor" || s == "call" || s == "apply" || s == "now" ||
        s == "Date" || s == "HermesES6Internal";
  }
  Datum reject(const char *why, Instruction *at) {
    if (!failed_) { reason_ = why; barrier_ = at; }
    failed_ = true; return {};
  }
  bool spend(Instruction *at) {
    if (++steps_ <= 20000) return true;
    reject("PROOF_BUDGET_EXHAUSTED", at); return false;
  }
  bool edge(Datum &d, Instruction *i) {
    if (d.traces.size() > 16) { reject("TRACE_COUNT_LIMIT", i); return false; }
    for (auto &t : d.traces) {
      if (t.path.size() >= 512) { reject("TRACE_LENGTH_LIMIT", i); return false; }
      if (t.path.empty() || t.path.back() != i) t.path.push_back(i);
    }
    return true;
  }
  Datum value(Value *v, Frame &f, Instruction *use) {
    if (auto *n = llvh::dyn_cast<LiteralNumber>(v)) return number(n->getValue());
    if (auto *b = llvh::dyn_cast<LiteralBool>(v)) return boolean(b->getValue());
    if (llvh::isa<LiteralString>(v)) return make(Scalar);
    if (llvh::isa<LiteralUndefined>(v)) return make(Undefined);
    if (llvh::isa<LiteralNull>(v)) return make(Null);
    if (llvh::isa<GlobalObject>(v)) return make(Global);
    if (auto *p = llvh::dyn_cast<Parameter>(v)) {
      if (p->getParent() != f.function) return reject("FOREIGN_PARAMETER", use);
      if (p == f.function->getThisParameter()) return f.receiver;
      auto &params = f.function->getParameters();
      for (unsigned n = 0; n < params.size(); ++n)
        if (params[n] == p) return n < f.arguments.size() ? f.arguments[n] : make(Undefined);
      return reject("UNRESOLVED_PARAMETER", use);
    }
    auto found = f.values.find(v);
    return found == f.values.end() ? reject("UNRESOLVED_VALUE", use) : found->second;
  }
  unsigned newEnvironment(unsigned parent, Instruction *at) {
    if (nextEnvironment_ > 128) { reject("ENVIRONMENT_LIMIT", at); return 0; }
    unsigned id = nextEnvironment_++;
    environments_[id].parent = parent; return id;
  }
  Datum frameLoad(LoadFrameInst *load, Frame &f) {
    Datum env = value(load->getEnvironment(), f, load);
    if (env.kind != Scope || env.ref != f.environment)
      return reject("FRAME_ENVIRONMENT_UNPROVEN", load);
    for (unsigned id = f.environment; id; id = environments_[id].parent) {
      auto found = environments_[id].variables.find(load->getLoadVariable());
      if (found != environments_[id].variables.end()) {
        Datum d = found->second; edge(d, load); return d;
      }
    }
    return reject("FRAME_VALUE_UNRESOLVED", load);
  }
  Datum globalRead(const std::string &name, Instruction *load) {
    auto it = globals_.find(name);
    if (it != globals_.end()) { Datum d = it->second; edge(d, load); return d; }
    if (name == "Date") return make(DateObject);
    if (name == "HermesES6Internal") return make(Helpers);
    if (name == "Object") return make(ObjectBuiltin);
                                                                            
                                                                             
    if (name == "document" && !declaredDocument_) return make(AmbientDocument);
    return reject("GLOBAL_VALUE_UNRESOLVED", load);
  }
  bool readyReceiver(const Datum &object, Frame &f, Instruction *at) {
    if (f.mode == ConstructorMode && object.kind == Instance &&
        object.ref == f.receiver.ref && closures_[f.ctor].base && !f.superCalls) {
      reject("DERIVED_RECEIVER_BEFORE_SUPER", at); return false;
    }
    return true;
  }
  bool classDescendsFrom(unsigned child, unsigned parent) const {
    for (unsigned depth = 0; child && depth < 64; ++depth) {
      if (child == parent) return true;
      auto found = closures_.find(child);
      if (found == closures_.end() || !found->second.isClass) return false;
      child = found->second.base;
    }
    return false;
  }
  Datum classMethod(unsigned ctor, const std::string &name, bool isStatic,
                    Instruction *at) {
    if (forbiddenKey(name)) return reject("PROTECTED_METHOD_KEY", at);
    for (unsigned depth = 0; ctor && depth < 64; ++depth) {
      auto found = closures_.find(ctor);
      if (found == closures_.end() || !found->second.isClass)
        return reject("METHOD_CLASS_IDENTITY_UNPROVEN", at);
      const auto &methods = isStatic ? found->second.staticMethods : found->second.methods;
      auto method = methods.find(name);
      if (method != methods.end()) return make(Closure, method->second);
      if (!isStatic && found->second.recordPrototype)
        return reject("EXTERNAL_PROTOTYPE_METHOD_UNPROVEN", at);
      ctor = found->second.base;
    }
    return reject("METHOD_LOOKUP_UNPROVEN", at);
  }
  Datum propertyRead(LoadPropertyInst *load, Frame &f) {
    const std::string name = key(load->getProperty());
    if (name.empty()) return reject("DYNAMIC_PROPERTY_KEY", load);
    Datum object = value(load->getObject(), f, load);
    if (object.kind == Global) return globalRead(name, load);
    if (object.kind == DateObject && name == "now") return make(DateNow);
    if (object.kind == ObjectBuiltin && name == "defineProperty") return make(DefineProperty);
    if (object.kind == ObjectBuiltin && name == "setPrototypeOf") return make(SetPrototype);
    if (object.kind == ObjectBuiltin && name == "getOwnPropertyDescriptor") return make(GetOwnDescriptor);
    if (object.kind == Helpers && name == "defineClass") return make(DefineClass);
    if (object.kind == Helpers && name == "defineClassMethod") return make(DefineMethod);
    if (object.kind == Helpers && name == "defineStaticClassMethod") return make(DefineStaticMethod);
    if (object.kind == Helpers && name == "defineClassField") return make(DefineField);
    if (object.kind == Closure && name == "call" && f.mode == ConstructorMode &&
        closures_[object.ref].isClass && object.ref == closures_[f.ctor].base)
      return make(CtorCall, object.ref);
    if (object.kind == Closure && !closures_[object.ref].isClass && name == "call")
      return make(FunctionCall, object.ref);
    if (object.kind == Closure && closures_[object.ref].isClass) {
      if (name == "prototype") return make(Prototype, object.ref);
      return classMethod(object.ref, name, true, load);
    }
    if (object.kind == Prototype) return classMethod(object.ref, name, false, load);
    if (object.kind != Instance && object.kind != Record)
      return reject("PROPERTY_RECEIVER_UNPROVEN", load);
    if (forbiddenKey(name) || !readyReceiver(object, f, load))
      return reject("UNSUPPORTED_PROPERTY_READ", load);
    auto &props = objects_[object.ref].properties;
    auto found = props.find(name);
                                                                        
    if (found == props.end()) {
      if (object.kind == Instance)
        return classMethod(objects_[object.ref].ctor, name, false, load);
      return reject("OWN_PROPERTY_UNPROVEN", load);
    }
    Datum d = found->second.value;
    if (found->second.accessor) return reject("ACCESSOR_READ_UNPROVEN", load);
    if (!primitive(d)) return reject("NONSCALAR_PROPERTY_READ", load);
    if (object.kind == Instance) {
      ++reads_; if (d.traces.empty()) ++cleanReads_;
      for (auto &t : d.traces) {
        t.witnesses.push_back({objects_[object.ref].allocation, found->second.write, load});
        if (t.witnesses.size() > 16) return reject("WITNESS_LIMIT", load);
      }
      edge(d, objects_[object.ref].allocation);
    }
    edge(d, load); return d;
  }
  Datum propertyStore(Value *objectValue, Value *property, Value *stored,
                      Instruction *store, Frame &f, bool own) {
    Datum object = value(objectValue, f, store), d = value(stored, f, store);
    if (failed_) return {};
    if (object.kind == Array) {
      if (f.mode != ConstructorMode || !own)
        return reject("UNSUPPORTED_ARRAY_MUTATION", store);
      Datum index = value(property, f, store);
      auto &elements = objects_[object.ref].elements;
      if (!index.knownNumber || index.number != double(elements.size()) ||
          elements.size() >= 32 || (!primitive(d) &&
          !(d.kind == Instance && d.ref == f.receiver.ref && elements.empty())))
        return reject("SUPER_ARGUMENT_ARRAY_UNPROVEN", store);
      elements.push_back(d); return make(Undefined);
    }
    const std::string name = key(property);
    if (name.empty()) return reject("DYNAMIC_PROPERTY_KEY", store);
    if (forbiddenKey(name)) return reject("PROTECTED_PROPERTY_MUTATION", store);
    edge(d, store);
    if (object.kind == Global) {
      if (f.mode == WrapperMode ||
          ((f.mode == ConstructorMode || f.mode == MethodMode) && !primitive(d)))
        return reject("RECEIVER_OR_CLOSURE_ESCAPE", store);
      if (!(primitive(d) || d.kind == Instance || d.kind == Record || d.kind == Closure))
        return reject("UNSUPPORTED_GLOBAL_VALUE", store);
      if (globals_.size() >= 128 && !globals_.count(name))
        return reject("GLOBAL_LIMIT", store);
      globals_[name] = d; return make(Undefined);
    }
    const bool descriptorCallable = object.kind == Record && own && f.mode == GlobalMode &&
        (name == "get" || name == "set") && d.kind == Closure && !closures_[d.ref].isClass;
    if ((object.kind != Instance && object.kind != Record) || (!primitive(d) && !descriptorCallable))
      return reject("UNKNOWN_WRITE_OR_ESCAPE", store);
    if (!readyReceiver(object, f, store)) return {};
    if (f.mode == WrapperMode || ((f.mode == ConstructorMode || f.mode == MethodMode) &&
        (object.kind != Instance || object.ref != f.receiver.ref)))
      return reject("FOREIGN_RECEIVER_WRITE", store);
    if (object.kind == Instance && (f.mode == ConstructorMode || f.mode == MethodMode))
      for (auto it = f.calls.rbegin(); it != f.calls.rend(); ++it) edge(d, *it);
    auto &props = objects_[object.ref].properties;
    auto existing = props.find(name);
    if (existing != props.end()) {
      if ((own && !existing->second.configurable) ||
          (!own && (existing->second.accessor || !existing->second.writable)))
        return reject("PROPERTY_DESCRIPTOR_WRITE_UNPROVEN", store);
    } else if (!own && object.kind == Instance) {
                                                                          
                                                            
      unsigned ctor = objects_[object.ref].ctor;
      for (unsigned depth = 0; ctor && depth < 64; ++depth) {
        const auto &info = closures_[ctor];
        if (info.recordPrototype) {
          const auto &parentProps = objects_[info.recordPrototype].properties;
          auto inherited = parentProps.find(name);
          if (inherited != parentProps.end() &&
              (inherited->second.accessor || !inherited->second.writable))
            return reject("INHERITED_DESCRIPTOR_WRITE_UNPROVEN", store);
          break;
        }
        ctor = info.base;
      }
    }
    if (props.size() >= 64 && !props.count(name)) return reject("PROPERTY_LIMIT", store);
    if (!own && existing != props.end()) {
      existing->second.value = d; existing->second.write = store;
    } else {
      props[name] = {d, store};                                                     
    }
    return make(Undefined);
  }
  Datum objectCall(Kind kind, const std::vector<Datum> &args, Frame &f, CallInst *call) {
    if (f.mode != GlobalMode) return reject("OBJECT_CALL_CONTEXT_UNPROVEN", call);
    if (kind == SetPrototype) {
      if (args.size() != 2 || args[0].kind != Prototype || args[1].kind != Record)
        return reject("PROTOTYPE_TARGET_OR_PARENT_UNPROVEN", call);
      auto &ctor = closures_[args[0].ref];
      if (!ctor.isClass || ctor.base || !ctor.methods.empty())
        return reject("PROTOTYPE_MUTATION_CLASS_SHAPE_UNPROVEN", call);
      ctor.recordPrototype = args[1].ref;
      return args[0];
    }
    if ((kind != DefineProperty && kind != GetOwnDescriptor) ||
        args.size() != (kind == DefineProperty ? 3u : 2u))
      return reject("OBJECT_CALL_ARITY_UNPROVEN", call);
    const std::string name = key(call->getArgument(2));
    if (forbiddenKey(name)) return reject("OBJECT_PROPERTY_KEY_UNPROVEN", call);
    if (kind == DefineProperty) {
      if (args[0].kind != Record || args[2].kind != Record)
        return reject("DESCRIPTOR_TARGET_OR_RECORD_UNPROVEN", call);
      const auto &descriptor = objects_[args[2].ref].properties;
      for (const auto &p : descriptor)
        if (p.second.accessor) return reject("DESCRIPTOR_ACCESSOR_EFFECT_UNPROVEN", call);
      auto &target = objects_[args[0].ref].properties;
      auto previous = target.find(name);
      if (previous != target.end() && !previous->second.configurable)
        return reject("NONCONFIGURABLE_REDEFINITION_UNPROVEN", call);
                                                                              
                                                       
      if (previous != target.end()) return reject("DESCRIPTOR_REDEFINITION_UNPROVEN", call);
      Slot slot{make(Undefined), call};
      slot.writable = slot.enumerable = slot.configurable = false;
      for (const auto &flag : {std::string("writable"), std::string("enumerable"), std::string("configurable")}) {
        auto it = descriptor.find(flag);
        if (it == descriptor.end()) continue;
        if (!it->second.value.knownBoolean) return reject("DESCRIPTOR_FLAG_UNPROVEN", call);
        if (flag == "writable") slot.writable = it->second.value.boolean;
        if (flag == "enumerable") slot.enumerable = it->second.value.boolean;
        if (flag == "configurable") slot.configurable = it->second.value.boolean;
      }
      const bool accessor = descriptor.count("get") || descriptor.count("set");
      if (accessor && (descriptor.count("value") || descriptor.count("writable")))
        return reject("MIXED_DESCRIPTOR_INVALID", call);
      slot.accessor = accessor;
      if (accessor) {
        for (const auto &part : {std::string("get"), std::string("set")}) {
          auto it = descriptor.find(part);
          if (it == descriptor.end() || it->second.value.kind == Undefined) continue;
          const auto &fn = it->second.value;
          if (fn.kind != Closure || closures_[fn.ref].isClass)
            return reject("DESCRIPTOR_CALLABLE_UNPROVEN", call);
          if (part == "get") slot.getter = fn.ref; else slot.setter = fn.ref;
        }
      } else if (descriptor.count("value")) {
        slot.value = descriptor.at("value").value;
        if (!primitive(slot.value)) return reject("DESCRIPTOR_VALUE_UNPROVEN", call);
        edge(slot.value, call);
      }
      if (target.size() >= 64) return reject("PROPERTY_LIMIT", call);
      target[name] = slot; return args[0];
    }
    if ((args[0].kind != Instance && args[0].kind != Record) || nextObject_ > 64)
      return reject("OWN_DESCRIPTOR_TARGET_UNPROVEN", call);
    const auto &target = objects_[args[0].ref].properties;
    auto found = target.find(name);
    if (found == target.end()) return make(Undefined);
    if (found->second.accessor) return reject("OWN_ACCESSOR_DESCRIPTOR_UNSUPPORTED", call);
    unsigned object = nextObject_++;
    auto &descriptor = objects_[object].properties;
    Datum d = found->second.value;
    if (args[0].kind == Instance) {
      ++reads_; if (d.traces.empty()) ++cleanReads_;
      for (auto &trace : d.traces) {
        trace.witnesses.push_back({objects_[args[0].ref].allocation, found->second.write, call});
        if (trace.witnesses.size() > 16) return reject("WITNESS_LIMIT", call);
      }
      edge(d, objects_[args[0].ref].allocation);
    }
    edge(d, call);
    descriptor["value"] = {d, call};
    descriptor["writable"] = {boolean(found->second.writable), call};
    descriptor["enumerable"] = {boolean(found->second.enumerable), call};
    descriptor["configurable"] = {boolean(found->second.configurable), call};
    return make(Record, object);
  }
  Instruction *sourceCall(CallInst *call) const {
    if (std::find(sources_.begin(), sources_.end(), call) != sources_.end()) return call;
    auto *p = llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
    return p && std::find(sources_.begin(), sources_.end(), p) != sources_.end() ? p : nullptr;
  }
  bool wrapperShape(Function *body) const {
    if (!body || body->empty() || !llvh::isa<ReturnInst>(body->front().getTerminator())) return false;
    unsigned definitions = 0;
    for (auto &i : body->front()) {
      if (llvh::isa<CreateScopeInst>(&i) || llvh::isa<CreateFunctionInst>(&i) ||
          llvh::isa<LoadFrameInst>(&i) || llvh::isa<StoreFrameInst>(&i) ||
          llvh::isa<LoadPropertyInst>(&i) || llvh::isa<ReturnInst>(&i)) continue;
      auto *call = llvh::dyn_cast<CallInst>(&i);
      if (!call || llvh::isa<ConstructInst>(call) || llvh::isa<CallBuiltinInst>(call)) return false;
      auto *p = llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
      auto *g = p ? llvh::dyn_cast<TryLoadGlobalPropertyInst>(p->getObject()) : nullptr;
      if (!p || !g || key(g->getProperty()) != "HermesES6Internal") return false;
      const auto helper = key(p->getProperty());
      if (helper == "defineClass" && call->getNumArguments() == 3) ++definitions;
      else if ((helper == "defineClassMethod" || helper == "defineStaticClassMethod") &&
               call->getNumArguments() == 4) continue;
      else return false;
    }
    return definitions == 1;
  }
  Datum invoke(unsigned closure, const std::vector<Datum> &args, Datum receiver,
               Frame &caller, Instruction *site, Mode mode) {
    const ClosureInfo info = closures_.at(closure);
    if (args.size() > 32 || info.body->getParameters().size() > 32 ||
        depth_ >= 8 || active_.count(info.body))
      return reject("CALL_DEPTH_OR_RECURSION_LIMIT", site);
    if (mode == WrapperMode && !wrapperShape(info.body))
      return reject("CALL_NOT_CLASS_WRAPPER", site);
    if (mode == ConstructorMode && (!info.isClass || info.body->empty() ||
        !llvh::isa<ReturnInst>(info.body->front().getTerminator())))
      return reject("NONLINEAR_OR_UNKNOWN_CONSTRUCTOR", site);
    if (mode == MethodMode) {
      if (info.isClass || info.body->empty() ||
          !llvh::isa<ReturnInst>(info.body->front().getTerminator()))
        return reject("NONLINEAR_OR_UNKNOWN_METHOD", site);
      if (info.methodOwner) {
        unsigned receiverClass = 0;
        if (info.staticMethod && receiver.kind == Closure && closures_[receiver.ref].isClass)
          receiverClass = receiver.ref;
        if (!info.staticMethod && receiver.kind == Instance)
          receiverClass = objects_[receiver.ref].ctor;
        if (!receiverClass || !classDescendsFrom(receiverClass, info.methodOwner))
          return reject("METHOD_RECEIVER_IDENTITY_UNPROVEN", site);
      } else if (receiver.kind != Undefined) {
        return reject("ORDINARY_CALL_RECEIVER_UNPROVEN", site);
      }
    }
    for (const auto &arg : args)
      if (!(primitive(arg) ||
            ((mode == WrapperMode || mode == MethodMode) && arg.kind == Closure && closures_[arg.ref].isClass)))
        return reject("NONSCALAR_CALL_ARGUMENT", site);
    unsigned env = newEnvironment(info.environment, site);
    Frame frame{info.body, mode, env}; frame.receiver = receiver; frame.arguments = args;
    frame.ctor = mode == ConstructorMode ? closure : 0;
    frame.calls = caller.calls; frame.calls.push_back(site);
    ++depth_; active_.insert(info.body);
    Datum result = execute(frame);
    active_.erase(info.body); --depth_;
    if (failed_) return {};
    if (mode == WrapperMode) {
      if (frame.definitions != 1 || result.kind != Closure ||
          !closures_[result.ref].isClass || closures_[result.ref].environment != env)
        return reject("WRAPPER_RETURN_IDENTITY_UNPROVEN", site);
    } else if (mode == ConstructorMode &&
               (result.kind != Undefined || frame.superCalls != (info.base ? 1u : 0u))) {
      return reject("CONSTRUCTOR_RETURN_OR_SUPER_UNPROVEN", site);
    } else if (mode == MethodMode &&
               !(primitive(result) || (result.kind == Closure && closures_[result.ref].isClass))) {
      return reject("METHOD_RESULT_OR_ESCAPE_UNPROVEN", site);
    }
    edge(result, site); return result;
  }
  Datum superCall(unsigned ctor, Datum receiver, const std::vector<Datum> &args,
                  Frame &f, Instruction *call) {
    if (f.mode != ConstructorMode || !ctor || ctor != closures_[f.ctor].base ||
        receiver.kind != Instance || receiver.ref != f.receiver.ref || f.superCalls)
      return reject("SUPER_RECEIVER_IDENTITY_UNPROVEN", call);
    Datum result = invoke(ctor, args, receiver, f, call, ConstructorMode);
    if (!failed_) ++f.superCalls;
    return result;
  }
  Datum call(CallInst *call, Frame &f) {
    if (auto *builtin = llvh::dyn_cast<CallBuiltinInst>(call)) {
      if (f.mode != ConstructorMode || builtin->getNumArguments() != 4)
        return reject("UNSUPPORTED_BUILTIN_CALL", call);
      Datum a = value(call->getArgument(1), f, call);
      Datum b = value(call->getArgument(2), f, call);
      Datum c = value(call->getArgument(3), f, call);
      if (builtin->getBuiltinIndex() == BuiltinMethod::HermesBuiltin_arraySpread) {
        if (a.kind != Array || b.kind != Arguments || !c.knownNumber ||
            c.number != double(objects_[a.ref].elements.size()) ||
            objects_[a.ref].elements.size() + objects_[b.ref].elements.size() > 32)
          return reject("SUPER_ARGUMENT_SPREAD_UNPROVEN", call);
        auto extra = objects_[b.ref].elements;
        auto &out = objects_[a.ref].elements;
        out.insert(out.end(), extra.begin(), extra.end()); return number(out.size());
      }
      if (builtin->getBuiltinIndex() == BuiltinMethod::HermesBuiltin_apply) {
        if (a.kind != CtorCall || b.kind != Array || c.kind != Closure || a.ref != c.ref)
          return reject("SUPER_APPLY_IDENTITY_UNPROVEN", call);
        auto args = objects_[b.ref].elements;
        if (args.empty()) return reject("SUPER_APPLY_RECEIVER_MISSING", call);
        Datum receiver = args.front(); args.erase(args.begin());
        return superCall(a.ref, receiver, args, f, call);
      }
      return reject("UNSUPPORTED_BUILTIN_CALL", call);
    }
    Datum callee = value(call->getCallee(), f, call);
    Datum receiver = value(call->getArgument(0), f, call);
    std::vector<Datum> args;
    for (unsigned i = 1; i < call->getNumArguments(); ++i) args.push_back(value(call->getArgument(i), f, call));
    if (failed_) return {};
    if (auto *construct = llvh::dyn_cast<ConstructInst>(call)) {
      if (f.mode != GlobalMode || callee.kind != Closure || !closures_[callee.ref].isClass ||
          call->getNewTarget() != call->getCallee() || receiver.kind != Undefined || nextObject_ > 64)
        return reject("CONSTRUCT_IDENTITY_UNPROVEN", call);
      unsigned object = nextObject_++; objects_[object].allocation = construct;
      objects_[object].ctor = callee.ref;
      Datum instance = make(Instance, object);
      invoke(callee.ref, args, instance, f, call, ConstructorMode);
      return failed_ ? Datum{} : instance;
    }
    if (callee.kind == DateNow && receiver.kind == DateObject && args.empty()) {
      auto *source = sourceCall(call);
      if (!source) return reject("SOURCE_NOT_REGISTERED", call);
      Datum d = make(Scalar); d.traces.push_back({source, {source}, {}}); edge(d, call); return d;
    }
    if (receiver.kind == ObjectBuiltin &&
        (callee.kind == DefineProperty || callee.kind == SetPrototype || callee.kind == GetOwnDescriptor))
      return objectCall(callee.kind, args, f, call);
    if (callee.kind == DefineClass && receiver.kind == Helpers && args.size() == 2 &&
        f.mode == WrapperMode && args[0].kind == Closure) {
      auto &ctor = closures_[args[0].ref];
      if (ctor.isClass || ctor.environment != f.environment || f.definitions ||
          !(args[1].kind == Null || (args[1].kind == Closure && closures_[args[1].ref].isClass)))
        return reject("CLASS_DEFINITION_IDENTITY_UNPROVEN", call);
                                                                         
                                                                               
      if (args[1].kind == Null && !llvh::isa<LiteralNull>(call->getArgument(2)))
        return reject("NULL_HERITAGE_UNPROVEN", call);
      ctor.isClass = true; ctor.base = args[1].kind == Null ? 0 : args[1].ref;
      ctor.definition = call; ++f.definitions; return make(Undefined);
    }
    if ((callee.kind == DefineMethod || callee.kind == DefineStaticMethod) &&
        receiver.kind == Helpers && args.size() == 3 && f.mode == WrapperMode &&
        args[0].kind == Closure && args[2].kind == Closure) {
      auto &ctor = closures_[args[0].ref];
      auto &method = closures_[args[2].ref];
      const std::string name = key(call->getArgument(2));
      if (!ctor.isClass || ctor.environment != f.environment || f.definitions != 1 ||
          method.isClass || method.methodOwner || method.environment != f.environment ||
          forbiddenKey(name))
        return reject("METHOD_DEFINITION_IDENTITY_UNPROVEN", call);
      auto &methods = callee.kind == DefineStaticMethod ? ctor.staticMethods : ctor.methods;
      if (methods.size() >= 64) return reject("METHOD_COUNT_LIMIT", call);
      method.methodOwner = args[0].ref; method.staticMethod = callee.kind == DefineStaticMethod;
      methods[name] = args[2].ref;
      return make(Undefined);
    }
    if (callee.kind == DefineField && receiver.kind == Helpers && args.size() == 3 &&
        f.mode == ConstructorMode && args[0].kind == Instance &&
        args[0].ref == f.receiver.ref && primitive(args[2])) {
      const std::string name = key(call->getArgument(2));
      if (forbiddenKey(name)) return reject("FIELD_KEY_UNPROVEN", call);
      propertyStore(call->getArgument(1), call->getArgument(2), call->getArgument(3), call, f, true);
      if (failed_) return {};
                                                                                
                                                                              
      return objects_[args[0].ref].properties.at(name).value;
    }
    if (callee.kind == CtorCall && receiver.kind == Closure && receiver.ref == callee.ref) {
      if (args.empty()) return reject("SUPER_RECEIVER_MISSING", call);
      Datum self = args.front(); args.erase(args.begin());
      return superCall(callee.ref, self, args, f, call);
    }
    if (callee.kind == FunctionCall && receiver.kind == Closure && receiver.ref == callee.ref) {
      if (args.empty()) return reject("METHOD_CALL_RECEIVER_MISSING", call);
      Datum self = args.front(); args.erase(args.begin());
      return invoke(callee.ref, args, self, f, call, MethodMode);
    }
    if (callee.kind == Closure && !closures_[callee.ref].isClass) {
      if (receiver.kind == Undefined && wrapperShape(closures_[callee.ref].body))
        return invoke(callee.ref, args, receiver, f, call, WrapperMode);
      return invoke(callee.ref, args, receiver, f, call, MethodMode);
    }
    return reject("CALL_NOT_CLASS_WRAPPER", call);
  }
  Datum instruction(Instruction *i, Frame &f) {
    if (!spend(i)) return {};
    if (llvh::isa<CreateScopeInst>(i)) return make(Scope, f.environment);
    if (llvh::isa<AllocStackInst>(i)) return make(Undefined);
    if (auto *s = llvh::dyn_cast<StoreStackInst>(i)) {
      if (f.stack.size() >= 128 && !f.stack.count(s->getPtr())) return reject("STACK_SLOT_LIMIT", s);
      Datum d = value(s->getValue(), f, s); edge(d, s); f.stack[s->getPtr()] = d; return make(Undefined);
    }
    if (auto *l = llvh::dyn_cast<LoadStackInst>(i)) {
      auto it = f.stack.find(l->getPtr());
      if (it == f.stack.end()) return reject("STACK_VALUE_UNRESOLVED", l);
      Datum d = it->second; edge(d, l); return d;
    }
    if (auto *s = llvh::dyn_cast<StoreFrameInst>(i)) {
      Datum env = value(s->getEnvironment(), f, s), d = value(s->getValue(), f, s);
      if (env.kind != Scope || env.ref != f.environment ||
          s->getVariable()->getParent() != f.function->getFunctionScopeDesc())
        return reject("CAPTURED_FRAME_WRITE", s);
      auto &variables = environments_[f.environment].variables;
      if (variables.size() >= 128 && !variables.count(s->getVariable()))
        return reject("FRAME_SLOT_LIMIT", s);
      edge(d, s); variables[s->getVariable()] = d; return make(Undefined);
    }
    if (auto *l = llvh::dyn_cast<LoadFrameInst>(i)) return frameLoad(l, f);
    if (auto *c = llvh::dyn_cast<CreateFunctionInst>(i)) {
      Datum env = value(c->getEnvironment(), f, c);
      if (env.kind != Scope || env.ref != f.environment || nextClosure_ > 64)
        return reject("CLOSURE_ENVIRONMENT_UNPROVEN", c);
      unsigned id = nextClosure_++;
      closures_.emplace(id, ClosureInfo{c->getFunctionCode(), env.ref, c}); return make(Closure, id);
    }
    if (auto *l = llvh::dyn_cast<LoadPropertyInst>(i)) return propertyRead(l, f);
    if (auto *s = llvh::dyn_cast<StorePropertyInst>(i))
      return propertyStore(s->getObject(), s->getProperty(), s->getStoredValue(), s, f, false);
    if (auto *s = llvh::dyn_cast<StoreOwnPropertyInst>(i))
      return propertyStore(s->getObject(), s->getProperty(), s->getStoredValue(), s, f, true);
    if (auto *a = llvh::dyn_cast<AllocObjectInst>(i)) {
      if (f.mode != GlobalMode || !llvh::isa<EmptySentinel>(a->getParentObject()) || nextObject_ > 64)
        return reject("OBJECT_PROTOTYPE_UNPROVEN", a);
      unsigned id = nextObject_++; objects_[id] = {}; return make(Record, id);
    }
    if (auto *a = llvh::dyn_cast<AllocArrayInst>(i)) {
      if (f.mode != ConstructorMode || a->getElementCount() || nextObject_ > 64)
        return reject("UNSUPPORTED_ARGUMENT_ARRAY", a);
      unsigned id = nextObject_++; objects_[id] = {}; return make(Array, id);
    }
    if (llvh::isa<CreateArgumentsInst>(i)) {
      if (f.mode != ConstructorMode || !f.function->getParameters().empty() || nextObject_ > 64)
        return reject("ARGUMENTS_ALIAS_UNPROVEN", i);
      unsigned id = nextObject_++; objects_[id].elements = f.arguments; return make(Arguments, id);
    }
    if (auto *c = llvh::dyn_cast<CallInst>(i)) return call(c, f);
    if (auto *b = llvh::dyn_cast<BinaryOperatorInst>(i)) {
      Datum a = value(b->getLeftHandSide(), f, b), c = value(b->getRightHandSide(), f, b);
      if (b->getOperatorKind() != BinaryOperatorInst::OpKind::AddKind || !primitive(a) || !primitive(c))
        return reject("PRIMITIVE_OPERATOR_UNPROVEN", b);
      Datum d = make(Scalar);
      if (a.knownNumber && c.knownNumber) { d.knownNumber = true; d.number = a.number + c.number; }
      d.traces = a.traces; d.traces.insert(d.traces.end(), c.traces.begin(), c.traces.end()); edge(d, b); return d;
    }
    if (auto *u = llvh::dyn_cast<UnaryOperatorInst>(i)) {
      if (u->getOperatorKind() == UnaryOperatorInst::OpKind::VoidKind) {
        value(u->getSingleOperand(), f, u); return make(Undefined);
      }
      return reject("UNSUPPORTED_UNARY_OPERATOR", u);
    }
    if (auto *m = llvh::dyn_cast<MovInst>(i)) { Datum d = value(m->getSingleOperand(), f, m); edge(d, m); return d; }
    return reject("UNSUPPORTED_INSTRUCTION_OR_BRANCH", i);
  }
  Datum execute(Frame &f) {
    for (auto &i : f.function->front()) {
      if (&i == target_) {
        auto *sink = llvh::dyn_cast<StorePropertyInst>(&i);
        if (f.mode != GlobalMode || !sink || key(sink->getProperty()) != "cookie")
          return reject("UNSUPPORTED_SINK", &i);
        Datum object = value(sink->getObject(), f, sink);
        if (object.kind != Record && object.kind != AmbientDocument)
          return reject("SINK_RECEIVER_UNPROVEN", sink);
        sinkValue_ = value(sink->getStoredValue(), f, sink);
        if (!primitive(sinkValue_)) return reject("NONSCALAR_SINK_VALUE", sink);
        edge(sinkValue_, sink); reached_ = !failed_; return sinkValue_;
      }
      if (auto *ret = llvh::dyn_cast<ReturnInst>(&i)) {
        Datum d = value(ret->getValue(), f, ret); edge(d, ret); return d;
      }
      Datum d = instruction(&i, f);
      if (failed_) return {};
      f.values[&i] = std::move(d);
    }
    return reject("ENTRY_PREFIX_DID_NOT_RETURN", f.function->front().getTerminator());
  }
  bool hostBindingsDeclared() const {
    for (auto *g : module_->getGlobalProperties())
      if (g->isDeclared() && (key(g->getName()) == "Date" ||
          key(g->getName()) == "HermesES6Internal" || key(g->getName()) == "Object")) return true;
    return false;
  }
  void reset(Instruction *sink) {
    globals_.clear(); environments_.clear(); closures_.clear(); objects_.clear(); active_.clear();
    nextEnvironment_ = nextClosure_ = nextObject_ = 1;
    steps_ = reads_ = cleanReads_ = depth_ = 0; failed_ = reached_ = false;
    reason_ = "EXACT_INSTANCE_PREFIX"; barrier_ = nullptr; target_ = sink; sinkValue_ = {};
  }
 public:
  BoundedCtorInstanceTransport(Module *m, const std::vector<Instruction *> &sources,
      const std::vector<Instruction *> &sinks) : module_(m), sources_(sources), sinks_(sinks) {
    for (auto *g : module_->getGlobalProperties())
      if (g->isDeclared() && key(g->getName()) == "document") declaredDocument_ = true;
    unsigned fi = 0;
    for (auto &f : *module_) { unsigned ii = 0;
      for (auto &b : f) {
        for (auto &i : b) {
          if (ids_.size() >= 50000) { moduleTooLarge_ = true; break; }
          ids_[&i] = "F" + std::to_string(fi) + ":I" + std::to_string(ii++);
        }
        if (moduleTooLarge_) break;
      }
      if (moduleTooLarge_) break;
      ++fi;
    }
  }
  void append(std::vector<DefUseAnalyzer::TaintPath> &paths) {
    if (sinks_.size() > 16 || moduleTooLarge_) {
      llvh::outs() << "[CTOR_INSTANCE_BOUNDED] sink=UNINDEXED eligible=0 added=0 reads=0 clean_reads=0"
                      " reason=MODULE_OR_SINK_LIMIT barrier=NONE\n";
      return;
    }
    for (auto *sink : sinks_) {
      reset(sink); unsigned added = 0;
      Function *global = owner(sink);
      if (!global->isGlobalScope() || sink->getParent() != &global->front()) reject("SINK_NOT_GLOBAL_ENTRY_PREFIX", sink);
      else if (hostBindingsDeclared()) reject("HOST_INTRINSIC_SHADOWED", sink);
      else {
        Frame frame{global, GlobalMode, newEnvironment(0, sink)}; frame.receiver = make(Global);
        execute(frame);
      }
      if (!failed_ && !reached_) reject("SINK_NOT_REACHED", sink);
      if (!failed_) for (auto &trace : sinkValue_.traces) {
        if (trace.witnesses.empty() || trace.path.empty() || trace.path.front() != trace.source || trace.path.back() != sink) continue;
        const bool existing = std::any_of(paths.begin(), paths.end(), [&](const DefUseAnalyzer::TaintPath &p) {
          return p.source == trace.source && p.sink == sink;
        });
        const auto &w = trace.witnesses.back();
        if (!existing) { paths.emplace_back(trace.source, trace.path, sink); ++added; }
        llvh::outs() << "[CTOR_INSTANCE_TRACE] source=" << nodeId(trace.source) << " sink=" << nodeId(sink)
                     << " allocation=" << nodeId(w.allocation) << " write=" << nodeId(w.write) << " read=" << nodeId(w.read)
                     << " disposition=" << (existing ? "ALREADY_PRESENT" : "ADDED") << " witnesses=";
        for (const auto &v : trace.witnesses) llvh::outs() << nodeId(v.allocation) << "/" << nodeId(v.write) << "/" << nodeId(v.read) << ";";
        llvh::outs() << " path=";
        for (auto *i : trace.path) llvh::outs() << nodeId(i) << "/" << i->getKindStr() << " ";
        llvh::outs() << "\n";
      }
      llvh::outs() << "[CTOR_INSTANCE_BOUNDED] sink=" << nodeId(sink) << " eligible=" << (!failed_ ? 1 : 0)
                   << " added=" << added << " reads=" << reads_ << " clean_reads=" << cleanReads_
                   << " reason=" << reason_ << " barrier=" << nodeId(barrier_) << "\n";
    }
  }
};
}             
}                    

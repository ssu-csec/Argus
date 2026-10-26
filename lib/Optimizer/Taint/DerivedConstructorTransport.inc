                                                                    
                                                                                
                                                                                
                                                                                       
                                                                                
                                                                                 
                                                                   
#include <algorithm>
#include <cmath>
#include <map>
#include <set>

namespace hermes {
namespace {
class BoundedDerivedConstructorTransport {
  using Path = std::vector<Instruction *>;
  struct Witness {
    Instruction *allocation;
    Instruction *write;
    Instruction *read;
  };
  struct Trace {
    Instruction *source;
    Path path;
    std::vector<Witness> witnesses;
  };
  enum Kind {
    Invalid, Uninitialized, PrivateToken, Scalar, Undefined, Null, Global, Scope, Closure, Instance, Record,
    DateObject, DateNow, Helpers, DefineClass, CtorCall, Arguments, Array,
    AmbientDocument, DefineMethod, DefineStaticMethod, DefineField, Prototype,
    FunctionCall, ObjectBuiltin, DefineProperty, SetPrototype, GetOwnDescriptor,
    ArrayIterator, DateValue, DateFormat
  };
  struct Datum {
    Kind kind{Invalid};
    unsigned ref{0};
    bool knownNumber{false};
    double number{0};
    bool knownString{false};
    std::string string;
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
    unsigned parent{0}, invocation{0};
    ScopeDesc *description{nullptr};
    std::map<Variable *, Datum> variables;
  };
  struct ClosureInfo {
    Function *body;
    unsigned environment;
    CreateFunctionInst *creation;
    bool isClass{false}, nativeDerived{false};
    unsigned base{0};
    CallInst *definition{nullptr};
    unsigned methodOwner{0};
    bool staticMethod{false};
    std::map<std::string, unsigned> methods;
    std::map<std::string, unsigned> staticMethods;
                                                                            
                                                                            
    unsigned recordPrototype{0};
  };
  struct Object {
    Instruction *allocation{nullptr};
    unsigned ctor{0};
    std::map<std::string, Slot> properties;
    std::map<unsigned, Slot> privateFields;
    unsigned creationInvocation{0};
    std::vector<Datum> elements;
    std::vector<Instruction *> elementWrites;
    unsigned denseSize{0};
  };
  enum Mode { GlobalMode, WrapperMode, ConstructorMode, MethodMode, NativeConstructorMode, InitializerMode, FieldValueMode };
  struct Frame {
    Function *function;
    Mode mode;
    unsigned environment;
    unsigned ctor{0};
    Datum receiver;
    Datum newTarget;
    Instruction *construction{nullptr};
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
  struct IteratorState { unsigned array, cursor; AllocStackInst *source; };
  std::map<unsigned, IteratorState> iterators_;
  unsigned nextIterator_{1}, baseConstructions_{0};
  unsigned nextEnvironment_{1}, nextClosure_{1}, nextObject_{1};
  unsigned steps_{0}, reads_{0}, cleanReads_{0}, depth_{0};
  bool failed_{false};
  const char *reason_{"EXACT_INSTANCE_PREFIX"};
  Instruction *barrier_{nullptr};
  Instruction *target_{nullptr};
  Datum sinkValue_;
  bool reached_{false};
  bool completeGuard_{false};
  unsigned superReads_{0};
  std::vector<Datum> observedSinks_;
  std::map<Instruction *,std::vector<Datum>> observedReturns_;
  bool declaredDocument_{false}, moduleTooLarge_{false}, hasDerived_{false};
  unsigned conditionalEntryGuards_{0}, derivedConstructions_{0};

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
    if (auto *s=llvh::dyn_cast<LiteralString>(v)) {
      Datum d=make(Scalar);d.knownString=true;d.string=s->getValue().str().str();return d;
    }
    if (llvh::isa<LiteralEmpty>(v)) return make(Uninitialized);
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
    environments_[id].parent = parent; environments_[id].invocation=id; return id;
  }
  Datum frameLoad(LoadFrameInst *load, Frame &f) {
    Datum env = value(load->getEnvironment(), f, load);
    if (env.kind != Scope || !environments_.count(env.ref))
      return reject("FRAME_ENVIRONMENT_UNPROVEN", load);
    for (unsigned id = env.ref; id; id = environments_[id].parent) {
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
    Datum object = value(load->getObject(), f, load);
    if (object.kind == Array) {
      auto &elements=objects_[object.ref].elements;
      if(name=="length")return number(elements.size());
      Datum index=value(load->getProperty(),f,load);
      if(!index.knownNumber || !(index.number>=0 && index.number<elements.size()) ||
         index.number!=double(unsigned(index.number)))
        return reject("ARRAY_OWN_INDEX_UNPROVEN",load);
      Datum result=elements[unsigned(index.number)];
      edge(result,load);return result;
    }
    if (name.empty()) return reject("DYNAMIC_PROPERTY_KEY", load);
    if (object.kind == Global) return globalRead(name, load);
    if (object.kind == DateObject && name == "now") return make(DateNow);
    if (object.kind == DateValue && name == "toUTCString")return make(DateFormat,object.ref);
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
    if (objects_[object.ref].allocation) {
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
      Datum index = value(property, f, store);
      auto &elements = objects_[object.ref].elements;
                                                                             
                                                                           
      if(!own) {
        if(!index.knownNumber || !(index.number>=0 && index.number<elements.size()) ||
           index.number!=double(unsigned(index.number)) || !primitive(d))
          return reject("ARRAY_EXISTING_OWN_WRITE_UNPROVEN",store);
        edge(d,store);elements[unsigned(index.number)]=d;
        auto &writes=objects_[object.ref].elementWrites;
        if(writes.size()<elements.size())writes.resize(elements.size(),objects_[object.ref].allocation);
        writes[unsigned(index.number)]=store;return make(Undefined);
      }
      if (f.mode != ConstructorMode && f.mode != NativeConstructorMode &&
          !(f.mode==MethodMode && objects_[object.ref].creationInvocation==f.environment))
        return reject("UNSUPPORTED_ARRAY_MUTATION", store);
      if (!index.knownNumber || index.number != double(elements.size()) ||
          elements.size() >= 32 || (!primitive(d) &&
          !(d.kind == Instance && d.ref == f.receiver.ref && elements.empty())))
        return reject("SUPER_ARGUMENT_ARRAY_UNPROVEN", store);
      edge(d,store);elements.push_back(d);objects_[object.ref].elementWrites.push_back(store);
      objects_[object.ref].denseSize=std::max(objects_[object.ref].denseSize,unsigned(elements.size()));
      return make(Undefined);
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
        (object.kind != Instance || object.ref != f.receiver.ref) &&
        !(own && f.mode==MethodMode && object.kind==Record && objects_[object.ref].creationInvocation==f.environment)) ||
        ((f.mode==NativeConstructorMode || f.mode==InitializerMode) && object.ref!=f.receiver.ref &&
         !(own && object.kind==Record && objects_[object.ref].creationInvocation==f.environment)))
      return reject("FOREIGN_RECEIVER_WRITE", store);
    if ((object.kind == Instance || object.kind == Record) &&
        (f.mode == ConstructorMode || f.mode == MethodMode || f.mode==NativeConstructorMode || f.mode==InitializerMode))
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
    for(auto &i:body->front()) if(auto *b=llvh::dyn_cast<CallBuiltinInst>(&i))
      if(b->getBuiltinIndex()==BuiltinMethod::HermesBuiltin_initDerivedClass || b->getBuiltinIndex()==BuiltinMethod::HermesBuiltin_initBaseClass)++definitions;
    if(definitions) return definitions==1;                                                
    for (auto &i : body->front()) {
      if (llvh::isa<CreateScopeInst>(&i) || llvh::isa<CreateInnerScopeInst>(&i) ||
          llvh::isa<ThrowIfEmptyInst>(&i) || llvh::isa<CreateFunctionInst>(&i) ||
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
    return invoke(closure,args,receiver,caller,site,mode,make(Undefined),nullptr);
  }
  Datum invoke(unsigned closure,const std::vector<Datum> &args,Datum receiver,
               Frame &caller,Instruction *site,Mode mode,Datum newTarget,Instruction *construction) {
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
      if (info.isClass || info.body->empty())
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
    if((mode==NativeConstructorMode||mode==InitializerMode||mode==FieldValueMode) &&
       (info.body->empty()||!llvh::isa<ReturnInst>(info.body->front().getTerminator())))
      return reject("NONLINEAR_NATIVE_CONSTRUCTION",site);
    for (const auto &arg : args)
      if (!(primitive(arg) ||
            ((mode == WrapperMode || mode == MethodMode) && arg.kind == Closure && closures_[arg.ref].isClass)))
        return reject("NONSCALAR_CALL_ARGUMENT", site);
    unsigned env = newEnvironment(info.environment, site);
    Frame frame{info.body, mode, env}; frame.receiver = receiver; frame.arguments = args;
    frame.ctor = (mode==ConstructorMode || mode==NativeConstructorMode) ? closure : caller.ctor;
    frame.newTarget=newTarget;frame.construction=construction;
    frame.calls = caller.calls; frame.calls.push_back(site);
    ++depth_; active_.insert(info.body);
    Datum result = execute(frame);
    active_.erase(info.body); --depth_;
    if (failed_) return {};
    if(reached_)return result;
    if (mode == WrapperMode) {
      if (frame.definitions != 1 || result.kind != Closure ||
          !closures_[result.ref].isClass || environments_[closures_[result.ref].environment].invocation != env)
        return reject("WRAPPER_RETURN_IDENTITY_UNPROVEN", site);
    } else if (mode == ConstructorMode &&
               (result.kind != Undefined || frame.superCalls != (info.base ? 1u : 0u))) {
      return reject("CONSTRUCTOR_RETURN_OR_SUPER_UNPROVEN", site);
    } else if(mode==NativeConstructorMode) {
      if(info.nativeDerived && result.kind!=Instance && result.kind!=Record)
        return reject("DERIVED_CONSTRUCT_RESULT_UNPROVEN",site);
      if(!info.nativeDerived && !(primitive(result)||result.kind==Instance||result.kind==Record))
        return reject("BASE_CONSTRUCT_RESULT_UNPROVEN",site);
    } else if(mode==FieldValueMode && !primitive(result)) {
      return reject("FIELD_EXPRESSION_VALUE_UNPROVEN",site);
    } else if(mode==InitializerMode && result.kind!=Undefined) {
      return reject("INITIALIZER_RETURN_UNPROVEN",site);
    } else if (mode == MethodMode &&
               !(primitive(result) || (result.kind == Closure && closures_[result.ref].isClass))) {
      return reject("METHOD_RESULT_OR_ESCAPE_UNPROVEN", site);
    }
    edge(result, site);
    if(completeGuard_ && mode==MethodMode) observedReturns_[site].push_back(result);
    return result;
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
  bool objectValue(const Datum &d) const {return d.kind==Instance||d.kind==Record;}
  bool constructable(unsigned id) const {
    auto it=closures_.find(id);if(it==closures_.end())return false;
    auto kind=it->second.body->getDefinitionKind();
    return kind==Function::DefinitionKind::ES5Function||kind==Function::DefinitionKind::ES6Constructor||kind==Function::DefinitionKind::ES6DerivedConstructor;
  }
  Datum constructValue(Datum callee,std::vector<Datum> args,Datum nt,Frame &f,Instruction *site) {
    if(callee.kind!=Closure||nt.kind!=Closure||!constructable(callee.ref)||!constructable(nt.ref)||
       nextObject_>64||args.size()>32)return reject("NATIVE_CONSTRUCT_IDENTITY",site);
    const bool derived=closures_[callee.ref].nativeDerived;
    if(closures_[callee.ref].body->getDefinitionKind()==Function::DefinitionKind::ES6DerivedConstructor&&!derived)
      return reject("DERIVED_CLASS_NOT_INITIALIZED",site);
    if(derived)++derivedConstructions_;else if(closures_[callee.ref].isClass)++baseConstructions_;
    for(auto &d:args) {
      edge(d,site);
      for(auto &t:d.traces) {
        if(t.witnesses.size()>=16)return reject("WITNESS_LIMIT",site);
        t.witnesses.push_back({site,site,site});                                              
      }
    }
    Instruction *allocation=f.construction?f.construction:site;
    Datum receiver=make(Undefined);
    if(!derived) {
      unsigned id=nextObject_++;objects_[id].allocation=allocation;objects_[id].ctor=nt.ref;
      receiver=make(Instance,id);
    }
    Datum result=invoke(callee.ref,args,receiver,f,site,NativeConstructorMode,nt,allocation);
    if(failed_||reached_)return result;
    if(derived)return result;
    return objectValue(result)?result:receiver;
  }
  Datum nativeBuiltin(CallBuiltinInst *call,Frame &f,bool &handled) {
    const auto op=call->getBuiltinIndex();handled=true;
    switch(op) {
      case BuiltinMethod::HermesBuiltin_classElementKey:
      case BuiltinMethod::HermesBuiltin_superPropertyGet:
      case BuiltinMethod::HermesBuiltin_copyRestArgs:
      case BuiltinMethod::HermesBuiltin_classHeritagePrototype:
      case BuiltinMethod::HermesBuiltin_initDerivedClass:
      case BuiltinMethod::HermesBuiltin_initBaseClass:
      case BuiltinMethod::HermesBuiltin_defineInstanceClassMethod:
      case BuiltinMethod::HermesBuiltin_getSuperConstructor:
      case BuiltinMethod::HermesBuiltin_constructWithNewTarget:
      case BuiltinMethod::HermesBuiltin_assertDerivedUninitialized:
      case BuiltinMethod::HermesBuiltin_assertDerivedThis:
      case BuiltinMethod::HermesBuiltin_derivedConstructorReturn:
      case BuiltinMethod::HermesBuiltin_privateNameCreate:
      case BuiltinMethod::HermesBuiltin_privateFieldInit:
      case BuiltinMethod::HermesBuiltin_privateFieldGet:
      case BuiltinMethod::HermesBuiltin_privateFieldSet:
      case BuiltinMethod::HermesBuiltin_definePublicInstanceClassField:break;
      default:handled=false;return {};
    }
    if(!llvh::isa<LiteralUndefined>(call->getNewTarget())||call->getNumArguments()==0||
       !llvh::isa<LiteralUndefined>(call->getArgument(0)))return reject("NATIVE_BUILTIN_ABI",call);
    std::vector<Datum> args;
    for(unsigned n=1;n<call->getNumArguments();++n)args.push_back(value(call->getArgument(n),f,call));
    if(failed_)return {};
    if(op==BuiltinMethod::HermesBuiltin_classElementKey) {
      if(args.size()!=1 || !args[0].knownString || !args[0].traces.empty())
        return reject("SUPER_KEY_COERCION_UNPROVEN",call);
      return args[0];
    }
    if(op==BuiltinMethod::HermesBuiltin_superPropertyGet) {
                                                                    
                                                                           
      if(args.size()!=3 || (args[0].kind!=Closure && args[0].kind!=Prototype) ||
         !closures_[args[0].ref].isClass || !args[1].knownString ||
         !args[1].traces.empty())
        return reject("SUPER_PROPERTY_IDENTITY_UNPROVEN",call);
      auto &home=closures_[args[0].ref];unsigned receiverClass=0;
      const bool isStatic=args[0].kind==Closure;
      if(isStatic && args[2].kind==Closure &&
         closures_[args[2].ref].isClass)receiverClass=args[2].ref;
      if(!isStatic && args[2].kind==Instance)
        receiverClass=objects_[args[2].ref].ctor;
      if(!receiverClass || !classDescendsFrom(receiverClass,args[0].ref) ||
         !home.base || home.recordPrototype)
        return reject("SUPER_RECEIVER_OR_PROTOTYPE_UNPROVEN",call);
      ++superReads_;
      return classMethod(home.base,args[1].string,isStatic,call);
    }
    if(op==BuiltinMethod::HermesBuiltin_copyRestArgs) {
      if(args.size()!=1 || !args[0].knownNumber ||
         !(args[0].number>=0 && args[0].number<=32) || args[0].number!=double(unsigned(args[0].number)) ||
         f.mode==GlobalMode || f.mode==WrapperMode || nextObject_>64)
        return reject("REST_ARGUMENT_FRAME_UNPROVEN",call);
      unsigned id=nextObject_++;auto &array=objects_[id];
      array.allocation=call;array.creationInvocation=f.environment;
      for(unsigned n=unsigned(args[0].number);n<f.arguments.size();++n) {
        Datum d=f.arguments[n];
        if(!primitive(d))return reject("REST_ARGUMENT_VALUE_UNPROVEN",call);
        edge(d,call);array.elements.push_back(d);array.elementWrites.push_back(call);
        array.denseSize=unsigned(array.elements.size());
      }
      return make(Array,id);
    }
    if(op==BuiltinMethod::HermesBuiltin_classHeritagePrototype) {
      if(f.mode!=WrapperMode||args.size()!=1||args[0].kind!=Closure||!constructable(args[0].ref))
        return reject("HERITAGE_IDENTITY_UNPROVEN",call);
      return make(Prototype,args[0].ref);
    }
    if(op==BuiltinMethod::HermesBuiltin_initBaseClass) {
      if(f.mode!=WrapperMode || args.size()!=1 || args[0].kind!=Closure || f.definitions)
        return reject("BASE_DEFINITION_IDENTITY",call);
      auto &c=closures_[args[0].ref];
      if(c.isClass || c.body->getDefinitionKind()!=Function::DefinitionKind::ES6Constructor ||
         environments_[c.environment].invocation!=f.environment)
        return reject("BASE_DEFINITION_SCOPE",call);
      c.isClass=true;c.definition=call;++f.definitions;return make(Undefined);
    }
    if(op==BuiltinMethod::HermesBuiltin_initDerivedClass) {
      if(f.mode!=WrapperMode||args.size()!=3||args[0].kind!=Closure||args[1].kind!=Closure||
         args[2].kind!=Prototype||args[2].ref!=args[1].ref||!constructable(args[1].ref)||f.definitions)
        return reject("DERIVED_DEFINITION_IDENTITY",call);
      auto &c=closures_[args[0].ref];
      if(c.isClass||c.body->getDefinitionKind()!=Function::DefinitionKind::ES6DerivedConstructor||
         environments_[c.environment].invocation!=f.environment)return reject("DERIVED_DEFINITION_SCOPE",call);
      c.isClass=true;c.nativeDerived=true;c.base=args[1].ref;c.definition=call;++f.definitions;
      return make(Undefined);
    }
    if(op==BuiltinMethod::HermesBuiltin_defineInstanceClassMethod) {
      if(f.mode!=WrapperMode||args.size()!=3||args[0].kind!=Closure||args[2].kind!=Closure)
        return reject("NATIVE_METHOD_ABI",call);
      auto &c=closures_[args[0].ref];auto &m=closures_[args[2].ref];const auto name=key(call->getArgument(2));
      if(!c.isClass||environments_[c.environment].invocation!=f.environment||
         environments_[m.environment].invocation!=f.environment||forbiddenKey(name)||m.isClass||m.methodOwner)
        return reject("NATIVE_METHOD_IDENTITY",call);
      c.methods[name]=args[2].ref;m.methodOwner=args[0].ref;return make(Undefined);
    }
    if(op==BuiltinMethod::HermesBuiltin_getSuperConstructor) {
      if(f.mode!=NativeConstructorMode||args.size()!=1||args[0].kind!=Closure||args[0].ref!=f.ctor||
         !closures_[f.ctor].nativeDerived||!closures_[f.ctor].base)return reject("SUPER_CONSTRUCTOR_IDENTITY",call);
      return make(Closure,closures_[f.ctor].base);
    }
    if(op==BuiltinMethod::HermesBuiltin_constructWithNewTarget) {
      if(f.mode!=NativeConstructorMode||args.size()!=3||
         (args[1].kind!=Arguments&&args[1].kind!=Array))return reject("SUPER_ARGUMENT_PACK",call);
      return constructValue(args[0],objects_[args[1].ref].elements,args[2],f,call);
    }
    if(op==BuiltinMethod::HermesBuiltin_assertDerivedUninitialized) {
      if(f.mode!=NativeConstructorMode||args.size()!=1||args[0].kind!=Undefined)
        return reject("SECOND_SUPER_OR_BINDING_UNKNOWN",call);
      return make(Undefined);
    }
    if(op==BuiltinMethod::HermesBuiltin_assertDerivedThis) {
      if(f.mode!=NativeConstructorMode||args.size()!=1||!objectValue(args[0]))
        return reject("DERIVED_THIS_BEFORE_SUPER",call);
      return args[0];
    }
    if(op==BuiltinMethod::HermesBuiltin_derivedConstructorReturn) {
      if(f.mode!=NativeConstructorMode||args.size()!=2)return reject("DERIVED_RETURN_ABI",call);
      if(objectValue(args[1]))return args[1];
      if(args[1].kind==Undefined&&objectValue(args[0]))return args[0];
      return reject("DERIVED_RETURN_ABRUPT_OR_UNKNOWN",call);
    }
    if(op==BuiltinMethod::HermesBuiltin_privateNameCreate) {
      if(f.mode!=WrapperMode||!args.empty()||nextObject_>64)return reject("PRIVATE_TOKEN_CONTEXT",call);
      unsigned id=nextObject_++;objects_[id].creationInvocation=f.environment;return make(PrivateToken,id);
    }
    if(op==BuiltinMethod::HermesBuiltin_privateFieldInit||op==BuiltinMethod::HermesBuiltin_privateFieldGet||op==BuiltinMethod::HermesBuiltin_privateFieldSet) {
      const bool get=op==BuiltinMethod::HermesBuiltin_privateFieldGet;
      const bool init=op==BuiltinMethod::HermesBuiltin_privateFieldInit;
      if(args.size()!=(get?2u:3u)||!objectValue(args[0])||args[1].kind!=PrivateToken)
        return reject("PRIVATE_SLOT_IDENTITY",call);
      auto &fields=objects_[args[0].ref].privateFields;auto found=fields.find(args[1].ref);
      if(init) {
        if((f.mode!=InitializerMode && f.mode!=NativeConstructorMode)||args[0].ref!=f.receiver.ref||found!=fields.end()||!primitive(args[2]))
          return reject("PRIVATE_INIT_CONTEXT",call);
        Datum d=args[2];edge(d,call);fields[args[1].ref]={d,call};return make(Undefined);
      }
      if(found==fields.end())return reject("PRIVATE_BRAND_MISMATCH",call);
      if(!get) {
        if(!primitive(args[2]))return reject("PRIVATE_NONSCALAR_WRITE",call);
        Datum d=args[2];edge(d,call);found->second={d,call};return d;
      }
      Datum d=found->second.value;
      for(auto &t:d.traces) {
        if(t.witnesses.size()>=16)return reject("WITNESS_LIMIT",call);
        t.witnesses.push_back({objects_[args[0].ref].allocation,found->second.write,call});
      }
      edge(d,objects_[args[0].ref].allocation);edge(d,call);return d;
    }
    if(op==BuiltinMethod::HermesBuiltin_definePublicInstanceClassField) {
      if(f.mode!=InitializerMode||args.size()!=3||!objectValue(args[0])||args[0].ref!=f.receiver.ref||!primitive(args[2]))
        return reject("PUBLIC_INITIALIZER_IDENTITY",call);
      const auto name=key(call->getArgument(2));if(forbiddenKey(name))return reject("PUBLIC_FIELD_KEY",call);
      propertyStore(call->getArgument(1),call->getArgument(2),call->getArgument(3),call,f,true);
      return failed_?Datum{}:make(Undefined);
    }
    handled=false;return {};
  }

  Datum call(CallInst *call, Frame &f) {
    if (auto *builtin = llvh::dyn_cast<CallBuiltinInst>(call)) {
      bool handled=false;Datum native=nativeBuiltin(builtin,f,handled);
      if(handled)return native;
      if ((f.mode != ConstructorMode && f.mode != NativeConstructorMode) ||
          builtin->getNumArguments() != 4)
        return reject("UNSUPPORTED_BUILTIN_CALL", call);
      Datum a = value(call->getArgument(1), f, call);
      Datum b = value(call->getArgument(2), f, call);
      Datum c = value(call->getArgument(3), f, call);
      if (builtin->getBuiltinIndex() == BuiltinMethod::HermesBuiltin_arraySpread) {
        if (a.kind != Array || (b.kind != Arguments && b.kind != Array) ||
            !c.knownNumber ||
            c.number != double(objects_[a.ref].elements.size()) ||
            objects_[a.ref].elements.size() + objects_[b.ref].elements.size() > 32)
          return reject("SUPER_ARGUMENT_SPREAD_UNPROVEN", call);
        auto extra = objects_[b.ref].elements;
        for(auto &d:extra)edge(d,call);
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
    if(callee.kind==DateFormat && receiver.kind==DateValue &&
       callee.ref==receiver.ref && args.empty()) {
      Datum d=objects_[receiver.ref].properties.at("dateValue").value;edge(d,call);return d;
    }
    if (auto *construct=llvh::dyn_cast<ConstructInst>(call)) {
      Datum nt=value(call->getNewTarget(),f,call);
      if(callee.kind==DateObject && nt.kind==DateObject && args.size()==1 &&
         primitive(args[0]) && nextObject_<=64) {
        Datum d=args[0];auto *source=sourceCall(call);
        if(source)d.traces.push_back({source,{source},{}});
        edge(d,call);unsigned id=nextObject_++;
        objects_[id].allocation=call;objects_[id].properties["dateValue"]={d,call};
        return make(DateValue,id);
      }
      return constructValue(callee,args,nt,f,construct);
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
      if (ctor.isClass || environments_[ctor.environment].invocation != f.environment || f.definitions ||
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
      if (!ctor.isClass || environments_[ctor.environment].invocation != f.environment || f.definitions != 1 ||
          method.isClass || method.methodOwner || environments_[method.environment].invocation != f.environment ||
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
    if(callee.kind==Closure && (f.mode==NativeConstructorMode||f.mode==InitializerMode) &&
       closures_[callee.ref].body->getDefinitionKind()==Function::DefinitionKind::ES6Method &&
       !closures_[callee.ref].methodOwner &&
       environments_[closures_[callee.ref].environment].invocation==environments_[closures_[f.ctor].environment].invocation &&
       (receiver.kind==Instance||receiver.kind==Record) &&
       (f.mode!=InitializerMode || receiver.ref==f.receiver.ref))
      return invoke(callee.ref,args,receiver,f,call,
                    (f.mode==InitializerMode ||
                     (f.mode==NativeConstructorMode && closures_[f.ctor].isClass &&
                      !closures_[f.ctor].nativeDerived))?FieldValueMode:InitializerMode,
                    f.newTarget,f.construction);
    if (callee.kind == Closure && !closures_[callee.ref].isClass) {
      if (receiver.kind == Undefined && wrapperShape(closures_[callee.ref].body))
        return invoke(callee.ref, args, receiver, f, call, WrapperMode);
      return invoke(callee.ref, args, receiver, f, call, MethodMode);
    }
    return reject("CALL_NOT_CLASS_WRAPPER", call);
  }
  Datum instruction(Instruction *i, Frame &f) {
    if (!spend(i)) return {};
    if(llvh::isa<GetNewTargetInst>(i))return f.mode==NativeConstructorMode?f.newTarget:make(Undefined);
    if(auto *guard=llvh::dyn_cast<ThrowIfHasRestrictedGlobalPropertyInst>(i)) {
      if(f.mode!=GlobalMode || !f.function->isGlobalScope() || ++conditionalEntryGuards_>64)
        return reject("ENTRY_DESCRIPTOR_CONTEXT_UNPROVEN",i);
                                                                                    
      llvh::outs()<<"[DERIVED_ENTRY_CONDITION] guard="<<nodeId(guard)
        <<" branch=PASS_ASSUMED throw_branch=PREFIX_TERMINATES negative_certificate=0\n";
      return make(Undefined);
    }
    if(auto *check=llvh::dyn_cast<ThrowIfEmptyInst>(i)) {
      Datum d=value(check->getCheckedValue(),f,check);
      if(d.kind==Invalid||d.kind==Uninitialized)return reject("TDZ_OR_VALUE_UNPROVEN",check);
      edge(d,check);return d;
    }
    if(auto *scope=llvh::dyn_cast<CreateScopeInst>(i)) {
      auto &e=environments_[f.environment];
      if(e.description||scope->getCreatedScopeDesc()!=f.function->getFunctionScopeDesc())
        return reject("FUNCTION_SCOPE_IDENTITY",scope);
      e.description=scope->getCreatedScopeDesc();return make(Scope,f.environment);
    }
    if(auto *scope=llvh::dyn_cast<CreateInnerScopeInst>(i)) {
      Datum parent=value(scope->getParentScope(),f,scope);
      if(parent.kind!=Scope||environments_[parent.ref].invocation!=f.environment||
         scope->getCreatedScopeDesc()->getParent()!=environments_[parent.ref].description)
        return reject("INNER_SCOPE_IDENTITY",scope);
      unsigned id=newEnvironment(parent.ref,scope);if(failed_)return {};
      environments_[id].description=scope->getCreatedScopeDesc();environments_[id].invocation=f.environment;
      return make(Scope,id);
    }
    if(auto *begin=llvh::dyn_cast<IteratorBeginInst>(i)) {
      auto *slot=llvh::dyn_cast<AllocStackInst>(begin->getSourceOrNext());
      auto found=f.stack.find(slot);
      if(!slot || found==f.stack.end() || found->second.kind!=Array || nextIterator_>64)
        return reject("ITERATOR_SOURCE_UNPROVEN",begin);
      auto &array=objects_[found->second.ref];
      if(array.elements.size()!=array.denseSize || array.elementWrites.size()!=array.elements.size())
        return reject("ITERATOR_NOT_DENSE_OWN_ARRAY",begin);
      unsigned id=nextIterator_++;
      iterators_[id]={found->second.ref,0,slot};
                                                                         
                                                                                  
      return make(ArrayIterator,id);
    }
    if(auto *next=llvh::dyn_cast<IteratorNextInst>(i)) {
      auto *slot=llvh::dyn_cast<AllocStackInst>(next->getIterator());
      auto *source=llvh::dyn_cast<AllocStackInst>(next->getSourceOrNext());
      auto found=f.stack.find(slot);
      if(!slot || !source || found==f.stack.end())return reject("ITERATOR_SLOT_UNPROVEN",next);
      if(found->second.kind==Undefined)return make(Undefined);
      if(found->second.kind!=ArrayIterator || !iterators_.count(found->second.ref))
        return reject("ITERATOR_IDENTITY_UNPROVEN",next);
      auto &it=iterators_[found->second.ref];auto &array=objects_[it.array];
      if(it.source!=source || !f.stack.count(source) || f.stack[source].kind!=Array ||
         f.stack[source].ref!=it.array)return reject("ITERATOR_SOURCE_CHANGED",next);
      if(it.cursor>=array.elements.size()) {f.stack[slot]=make(Undefined);return make(Undefined);}
      unsigned index=it.cursor++;Datum d=array.elements[index];
      for(auto &t:d.traces) {
        if(t.witnesses.size()>=16)return reject("WITNESS_LIMIT",next);
        t.witnesses.push_back({array.allocation,array.elementWrites[index],next});
      }
      edge(d,array.allocation);edge(d,next);return d;
    }
    if(auto *close=llvh::dyn_cast<IteratorCloseInst>(i)) {
      auto *slot=llvh::dyn_cast<AllocStackInst>(close->getIterator());
      auto found=f.stack.find(slot);
      if(!slot || found==f.stack.end() ||
         (found->second.kind!=Undefined && found->second.kind!=ArrayIterator))
        return reject("ITERATOR_CLOSE_UNPROVEN",close);
      return make(Undefined);
    }
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
      if(env.kind!=Scope)return reject("FRAME_SCOPE_UNRESOLVED",s);
      unsigned target=env.ref;
      while(target && environments_[target].description!=s->getVariable()->getParent())target=environments_[target].parent;
      if(!target||environments_[target].invocation!=f.environment)return reject("CAPTURED_FRAME_WRITE",s);
      auto &variables = environments_[target].variables;
      if (variables.size() >= 128 && !variables.count(s->getVariable()))
        return reject("FRAME_SLOT_LIMIT", s);
      edge(d, s); variables[s->getVariable()] = d; return make(Undefined);
    }
    if (auto *l = llvh::dyn_cast<LoadFrameInst>(i)) return frameLoad(l, f);
    if (auto *c = llvh::dyn_cast<CreateFunctionInst>(i)) {
      Datum env = value(c->getEnvironment(), f, c);
      if (env.kind != Scope || environments_[env.ref].invocation != f.environment || nextClosure_ > 64)
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
      if (!(f.mode==GlobalMode||f.mode==NativeConstructorMode||f.mode==MethodMode) || !llvh::isa<EmptySentinel>(a->getParentObject()) || nextObject_ > 64)
        return reject("OBJECT_PROTOTYPE_UNPROVEN", a);
      unsigned id = nextObject_++; objects_[id] = {}; objects_[id].creationInvocation=f.environment;objects_[id].allocation=f.construction?f.construction:a; return make(Record, id);
    }
    if (auto *a = llvh::dyn_cast<AllocArrayInst>(i)) {
      if ((f.mode!=ConstructorMode&&f.mode!=NativeConstructorMode&&f.mode!=MethodMode) ||
          a->getElementCount()>32 || a->getSizeHint()->getValue()>32 ||
          a->getSizeHint()->getValue()<a->getElementCount() || nextObject_ > 64)
        return reject("UNSUPPORTED_ARGUMENT_ARRAY", a);
      unsigned id=nextObject_++;auto &array=objects_[id];
      array.allocation=a;array.creationInvocation=f.environment;
      array.denseSize=unsigned(a->getSizeHint()->getValue());
      for(unsigned n=0;n<a->getElementCount();++n) {
        Datum d=value(a->getArrayElement(n),f,a);
        if(!primitive(d))return reject("ARGUMENT_ARRAY_LITERAL_UNPROVEN",a);
        edge(d,a);array.elements.push_back(d);array.elementWrites.push_back(a);
      }
      return make(Array,id);
    }
    if (llvh::isa<CreateArgumentsInst>(i)) {
      if ((f.mode!=ConstructorMode&&f.mode!=NativeConstructorMode) || !f.function->getParameters().empty() || nextObject_ > 64)
        return reject("ARGUMENTS_ALIAS_UNPROVEN", i);
      unsigned id = nextObject_++; objects_[id].elements = f.arguments; return make(Arguments, id);
    }
    if (auto *c = llvh::dyn_cast<CallInst>(i)) return call(c, f);
    if (auto *b = llvh::dyn_cast<BinaryOperatorInst>(i)) {
      Datum a = value(b->getLeftHandSide(), f, b), c = value(b->getRightHandSide(), f, b);
      if(b->getOperatorKind()==BinaryOperatorInst::OpKind::StrictlyEqualKind &&
         ((a.kind==Undefined && (c.kind==Undefined||c.kind==ArrayIterator)) ||
          (c.kind==Undefined && a.kind==ArrayIterator)))
        return boolean(a.kind==c.kind);
      if (b->getOperatorKind() != BinaryOperatorInst::OpKind::AddKind || !primitive(a) || !primitive(c))
        return reject("PRIMITIVE_OPERATOR_UNPROVEN", b);
      Datum d = make(Scalar);
      if (a.knownString && c.knownString && a.string.size()+c.string.size()<=4096) {
        d.knownString=true;d.string=a.string+c.string;
      }
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
    BasicBlock *block=&f.function->front();std::set<BasicBlock *> seen;
    while(block) {
      if(seen.size()>=64 || !seen.insert(block).second)
        return reject("BRANCH_CYCLE_OR_LIMIT",block->getTerminator());
      BasicBlock *nextBlock=nullptr;
      for (auto &i : *block) {
        if(auto *branch=llvh::dyn_cast<BranchInst>(&i)) {
          if(!spend(branch))return {};
          nextBlock=branch->getBranchDest();break;
        }
        if(auto *branch=llvh::dyn_cast<CondBranchInst>(&i)) {
          if(!spend(branch))return {};
          Datum condition=value(branch->getCondition(),f,branch);
          if(!condition.knownBoolean || !condition.traces.empty())
            return reject("BRANCH_CONDITION_UNPROVEN",branch);
          nextBlock=condition.boolean?branch->getTrueDest():branch->getFalseDest();break;
        }
      if (&i == target_ || (completeGuard_ &&
          std::find(sinks_.begin(),sinks_.end(),&i)!=sinks_.end())) {
        auto *sink = llvh::dyn_cast<StorePropertyInst>(&i);
        if (!sink || key(sink->getProperty()) != "cookie")
          return reject("UNSUPPORTED_SINK", &i);
        Datum object = value(sink->getObject(), f, sink);
        if (object.kind != Record && object.kind != AmbientDocument)
          return reject("SINK_RECEIVER_UNPROVEN", sink);
        sinkValue_ = value(sink->getStoredValue(), f, sink);
        if (!primitive(sinkValue_)) return reject("NONSCALAR_SINK_VALUE", sink);
        edge(sinkValue_, sink);
        if(completeGuard_) {
          if(object.kind!=AmbientDocument)return reject("COMPLETE_SINK_NOT_AMBIENT",sink);
          if(&i==target_)observedSinks_.push_back(sinkValue_);
          f.values[&i]=make(Undefined);continue;
        }
        reached_ = !failed_; return sinkValue_;
      }
      if (auto *ret = llvh::dyn_cast<ReturnInst>(&i)) {
        Datum d = value(ret->getValue(), f, ret); edge(d, ret); return d;
      }
      Datum d = instruction(&i, f);
      if (failed_) return {};
      if(reached_)return sinkValue_;
      f.values[&i] = std::move(d);
      }
      block=nextBlock;
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
    iterators_.clear();nextIterator_=1;baseConstructions_=0;
    nextEnvironment_ = nextClosure_ = nextObject_ = 1;
    steps_ = reads_ = cleanReads_ = depth_ = 0; failed_ = reached_ = false;
    reason_ = "EXACT_DERIVED_POSITIVE_PREFIX"; barrier_ = nullptr; target_ = sink; sinkValue_ = {};
    conditionalEntryGuards_=derivedConstructions_=0;
    superReads_=0;observedSinks_.clear();observedReturns_.clear();
  }
 public:
  BoundedDerivedConstructorTransport(Module *m, const std::vector<Instruction *> &sources,
      const std::vector<Instruction *> &sinks) : module_(m), sources_(sources), sinks_(sinks) {
    for (auto *g : module_->getGlobalProperties())
      if (g->isDeclared() && key(g->getName()) == "document") declaredDocument_ = true;
    unsigned fi = 0;
    for (auto &f : *module_) { unsigned ii = 0;
      for (auto &b : f) {
        for (auto &i : b) {
          if (ids_.size() >= 50000) { moduleTooLarge_ = true; break; }
          ids_[&i] = "F" + std::to_string(fi) + ":I" + std::to_string(ii++);
          if(auto *c=llvh::dyn_cast<CallBuiltinInst>(&i))
            if(c->getBuiltinIndex()==BuiltinMethod::HermesBuiltin_initDerivedClass || c->getBuiltinIndex()==BuiltinMethod::HermesBuiltin_initBaseClass)hasDerived_=true;
        }
        if (moduleTooLarge_) break;
      }
      if (moduleTooLarge_) break;
      ++fi;
    }
  }
                                                                        
                                                                            
                                                                             
  void refine(std::vector<DefUseAnalyzer::TaintPath> &paths) {
    if(!hasDerived_ || moduleTooLarge_ || sinks_.size()>16)return;
    completeGuard_=true;
    for(auto *sink:sinks_) {
      reset(sink);Function *global=nullptr;
      for(auto &f:*module_)if(f.isGlobalScope()) {
        if(global){reject("MULTIPLE_GLOBAL_ENTRIES",sink);break;}global=&f;
      }
      if(!global || global->empty() || hostBindingsDeclared() || declaredDocument_)
        reject("COMPLETE_ENTRY_OR_HOST_UNPROVEN",sink);
      if(!failed_) {
        Frame f{global,GlobalMode,newEnvironment(0,sink)};f.receiver=make(Global);execute(f);
      }
      unsigned removed=0;
      if(!failed_ && superReads_ && !observedSinks_.empty()) {
        auto carries=[](const Datum &d,Instruction *s) {
          return std::any_of(d.traces.begin(),d.traces.end(),[&](const Trace &t){return t.source==s;});
        };
        paths.erase(std::remove_if(paths.begin(),paths.end(),[&](const DefUseAnalyzer::TaintPath &p){
          if(p.sink!=sink || std::any_of(observedSinks_.begin(),observedSinks_.end(),
              [&](const Datum &d){return carries(d,p.source);}))return false;
          for(auto *i:p.path) {
            auto q=observedReturns_.find(i);
            if(q!=observedReturns_.end() && !q->second.empty() &&
               std::none_of(q->second.begin(),q->second.end(),[&](const Datum &d){return carries(d,p.source);})) {
              ++removed;return true;
            }
          }
          return false;
        }),paths.end());
      }
      llvh::outs()<<"[SUPER_RETURN_COMPLETE_GUARD] status="<<(failed_?"UNKNOWN":"PROVED")
        <<" sink="<<nodeId(sink)<<" observations="<<observedSinks_.size()
        <<" super_reads="<<superReads_<<" removed="<<removed
        <<" reason="<<reason_<<" barrier="<<nodeId(barrier_)
        <<" contract=CLOSED_ENTRY_ALL_INVOCATIONS_PRISTINE_INTRINSICS\n";
    }
    completeGuard_=false;
  }
  void append(std::vector<DefUseAnalyzer::TaintPath> &paths) {
    if(!hasDerived_)return;
    if (sinks_.size() > 16 || moduleTooLarge_) {
      llvh::outs() << "[DERIVED_CONSTRUCTOR_BOUNDED] sink=UNINDEXED eligible=0 added=0 reads=0 clean_reads=0"
                      " reason=MODULE_OR_SINK_LIMIT barrier=NONE\n";
      return;
    }
    for (auto *sink : sinks_) {
      reset(sink); unsigned added = 0;
      Function *global=nullptr;
      for(auto &fn:*module_)if(fn.isGlobalScope()) {
        if(global){reject("MULTIPLE_GLOBAL_ENTRIES",sink);break;}global=&fn;
      }
      if(failed_||!global||global->empty())reject("GLOBAL_ENTRY_UNPROVEN",sink);
      else if (hostBindingsDeclared()) reject("HOST_INTRINSIC_SHADOWED", sink);
      else {
        Frame frame{global, GlobalMode, newEnvironment(0, sink)}; frame.receiver = make(Global);
        execute(frame);
      }
      if (!failed_ && !reached_) reject("SINK_NOT_REACHED", sink);
      if (!failed_ && (derivedConstructions_||baseConstructions_)) for (auto &trace : sinkValue_.traces) {
        if (trace.witnesses.empty() || trace.path.empty() || trace.path.front() != trace.source || trace.path.back() != sink) continue;
        const bool existing = std::any_of(paths.begin(), paths.end(), [&](const DefUseAnalyzer::TaintPath &p) {
          return p.source == trace.source && p.sink == sink;
        });
        const auto &w = trace.witnesses.back();
        if (!existing) { paths.emplace_back(trace.source, trace.path, sink); ++added; }
        llvh::outs() << "[DERIVED_CONSTRUCTOR_TRACE] source=" << nodeId(trace.source) << " sink=" << nodeId(sink)
                     << " allocation=" << nodeId(w.allocation) << " write=" << nodeId(w.write) << " read=" << nodeId(w.read)
                     << " disposition=" << (existing ? "ALREADY_PRESENT" : "ADDED") << " witnesses=";
        for (const auto &v : trace.witnesses) llvh::outs() << nodeId(v.allocation) << "/" << nodeId(v.write) << "/" << nodeId(v.read) << ";";
        llvh::outs() << " path=";
        for (auto *i : trace.path) llvh::outs() << nodeId(i) << "/" << i->getKindStr() << " ";
        llvh::outs() << "\n";
      }
      llvh::outs() << "[DERIVED_CONSTRUCTOR_BOUNDED] sink=" << nodeId(sink) << " eligible=" << (!failed_ ? 1 : 0)
                   << " added=" << added << " reads=" << reads_ << " clean_reads=" << cleanReads_
                   << " reason=" << reason_ << " barrier=" << nodeId(barrier_)
                   << " conditional_entry_guards="<<conditionalEntryGuards_<<" negative_certificate=0\n";
    }
  }
};
}             
}                    

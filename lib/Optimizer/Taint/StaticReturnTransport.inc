                                                                           
                                                                               
                                                                              
#include <algorithm>
#include <map>
#include <set>

namespace hermes {
namespace {
class BoundedStaticReturnTransport {
  using Path = std::vector<Instruction *>;
  struct Trace { Instruction *source; Path path; bool crossed{false}; };
  struct Result { bool valid{false}; std::vector<Trace> traces; };
  struct Method {
    Function *body;
    CreateFunctionInst *creation;
    CallInst *definition;
    ReturnInst *ret;
    CallInst *site{nullptr};
  };
  struct Class {
    Function *wrapper;
    Function *ctor;
    CallInst *creation{nullptr};
    StorePropertyInst *binding{nullptr};
    std::map<std::string, Method> methods;
  };
  Module *module_;
  const std::vector<Instruction *> &sources_, &sinks_;
  std::vector<Class> classes_;
  std::map<CallInst *, Method *> calls_;
  std::map<std::string, StorePropertyInst *> globals_;
  std::set<CallInst *> allowedCalls_;
  std::map<Instruction *, std::string> ids_;
  unsigned steps_{0};
  bool eligible_{true};

  static Function *owner(Instruction *i) { return i->getParent()->getParent(); }
  static std::string literal(Value *v) {
    auto *s = llvh::dyn_cast<LiteralString>(v);
    return s ? s->getValue().str().str() : "";
  }
  static bool before(Instruction *a, Instruction *b) {
    if (!a || !b || a->getParent() != b->getParent()) return false;
    for (auto &i : *a->getParent()) {
      if (&i == b) return false;
      if (&i == a) return true;
    }
    return false;
  }
  static ReturnInst *entryReturn(Function *f) {
    if (!f || f->empty()) return nullptr;
    return llvh::dyn_cast<ReturnInst>(f->front().getTerminator());
  }
  bool isSource(Instruction *i) const {
    return std::find(sources_.begin(), sources_.end(), i) != sources_.end();
  }
  bool isSink(Instruction *i) const {
    return std::find(sinks_.begin(), sinks_.end(), i) != sinks_.end();
  }
                                                                            
                                                                         
  Instruction *sourceCall(CallInst *call) const {
    if (!call || call->getNumArguments() != 1) return nullptr;
    auto *property = llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
    if (!property || call->getArgument(0) != property->getObject()) return nullptr;
    if (isSource(call)) return call;
    return isSource(property) ? property : nullptr;
  }
  static std::string helper(CallInst *call) {
    auto *property = llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
    if (!property) return "";
    auto *base = llvh::dyn_cast<TryLoadGlobalPropertyInst>(property->getObject());
    if (!base || literal(base->getProperty()) != "HermesES6Internal") return "";
    return literal(property->getProperty());
  }
                                                                               
                                                                                
  static StoreFrameInst *frameDefinition(LoadFrameInst *load) {
    StoreFrameInst *value = nullptr, *initial = nullptr;
    for (auto *u : load->getLoadVariable()->getUsers()) {
      auto *s = llvh::dyn_cast<StoreFrameInst>(u);
      if (!s || s->getVariable() != load->getLoadVariable()) continue;
      if (owner(s) != owner(load) || s->getParent() != &owner(load)->front()) return nullptr;
      if (llvh::isa<LiteralUndefined>(s->getValue())) {
        if (initial) return nullptr;
        initial = s;
      } else {
        if (value) return nullptr;
        value = s;
      }
    }
    if (!value || !before(value, load) || (initial && !before(initial, value))) return nullptr;
    return value;
  }
  static CreateFunctionInst *closure(Value *v, unsigned depth = 0) {
    if (depth > 4) return nullptr;
    if (auto *c = llvh::dyn_cast<CreateFunctionInst>(v)) return c;
    auto *load = llvh::dyn_cast<LoadFrameInst>(v);
    auto *store = load ? frameDefinition(load) : nullptr;
    return store ? closure(store->getValue(), depth + 1) : nullptr;
  }
  static bool noClosureEscape(CreateFunctionInst *create, CallInst *definition) {
    for (auto *u : create->getUsers()) {
      if (u == definition) continue;
      auto *s = llvh::dyn_cast<StoreFrameInst>(u);
      if (!s || s->getValue() != create) return false;
                                                                             
      for (auto *v : s->getVariable()->getUsers())
        if (v != s) return false;
    }
    return true;
  }
  bool expectedPropertyRead(LoadPropertyInst *load) const {
    if (llvh::isa<GlobalObject>(load->getObject()) && globals_.count(literal(load->getProperty()))) return true;
    bool used = false;
    for (auto *u : load->getUsers()) {
      used = true;
      if (auto *call = llvh::dyn_cast<CallInst>(u)) {
        if ((sourceCall(call) && (call->getCallee() == load || call->getArgument(0) == load)) ||
            (allowedCalls_.count(call) && (call->getCallee() == load || call->getArgument(0) == load))) continue;
      }
      if (auto *store = llvh::dyn_cast<StorePropertyInst>(u))
        if (isSink(store) && store->getObject() == load) continue;
      if (auto *child = llvh::dyn_cast<LoadPropertyInst>(u)) {
        bool calleeOnly = !child->getUsers().empty();
        for (auto *v : child->getUsers()) {
          auto *call = llvh::dyn_cast<CallInst>(v);
          if (!call || call->getCallee() != child ||
              (!allowedCalls_.count(call) && !sourceCall(call))) calleeOnly = false;
        }
        if (calleeOnly && llvh::isa<GlobalObject>(load->getObject())) continue;
      }
      return false;
    }
    return used;
  }
  void index() {
    unsigned fi = 0;
    for (auto &f : *module_) {
      unsigned ii = 0;
      for (auto &b : f) for (auto &i : b)
        ids_[&i] = "F" + std::to_string(fi) + ":I" + std::to_string(ii++);
      ++fi;
    }
                                                                             
    for (auto &f : *module_) {
      auto *ret = entryReturn(&f);
      if (!ret || !f.getParameters().empty()) continue;
      auto *ctorCreate = closure(ret->getValue());
      if (!ctorCreate || owner(ctorCreate) != &f) continue;
      Class cls{&f, ctorCreate->getFunctionCode(), nullptr, nullptr, {}};
      bool defined = false, bad = false;
      for (auto &i : f.front()) {
        auto *call = llvh::dyn_cast<CallInst>(&i);
        if (!call) continue;
        std::string name = helper(call);
        auto *target = call->getNumArguments() > 1 ? closure(call->getArgument(1)) : nullptr;
        if (!target || target->getFunctionCode() != cls.ctor) { bad = true; break; }
        if (name == "defineClass" && call->getNumArguments() == 3 &&
            llvh::isa<LiteralNull>(call->getArgument(2)) && !defined) {
          defined = true;
        } else if (name == "defineStaticClassMethod" && call->getNumArguments() == 4 && defined) {
          auto *create = llvh::dyn_cast<CreateFunctionInst>(call->getArgument(3));
          std::string key = literal(call->getArgument(2));
          auto *body = create ? create->getFunctionCode() : nullptr;
          auto *methodRet = entryReturn(body);
          if (!create || key.empty() || !methodRet || !body->getParameters().empty() ||
              !noClosureEscape(create, call) || cls.methods.count(key)) { bad = true; break; }
          cls.methods.emplace(key, Method{body, create, call, methodRet, nullptr});
        } else { bad = true; break; }
        allowedCalls_.insert(call);
      }
      if (!bad && defined && !cls.methods.empty()) classes_.push_back(std::move(cls));
    }
                                                                                
                                                                                
    for (auto &f : *module_) for (auto &b : f) for (auto &i : b) {
      if (llvh::isa<DeletePropertyInst>(&i) || llvh::isa<ConstructInst>(&i)) eligible_ = false;
      if (auto *s = llvh::dyn_cast<StorePropertyInst>(&i)) {
        std::string key = literal(s->getProperty());
        if (key.empty() || key == "HermesES6Internal") { eligible_ = false; continue; }
        if (llvh::isa<GlobalObject>(s->getObject())) {
          if (!f.isGlobalScope() || &b != &f.front() || !entryReturn(&f) || globals_.count(key)) eligible_ = false;
          globals_[key] = s;
        } else if (!isSink(s)) eligible_ = false;
      }
    }
    for (auto &cls : classes_) {
                                                                             
      CreateFunctionInst *create = nullptr;
      for (auto *u : cls.wrapper->getUsers()) {
        auto *c = llvh::dyn_cast<CreateFunctionInst>(u);
        if (!c || create) { eligible_ = false; break; }
        create = c;
      }
      if (!create || !owner(create)->isGlobalScope() || create->getParent() != &owner(create)->front()) { eligible_ = false; continue; }
      for (auto *u : create->getUsers()) {
        auto *call = llvh::dyn_cast<CallInst>(u);
        if (!call || call->getCallee() != create || call->getNumArguments() != 1 || cls.creation) { eligible_ = false; break; }
        cls.creation = call;
      }
      if (!cls.creation) { eligible_ = false; continue; }
      allowedCalls_.insert(cls.creation);
      for (auto *u : cls.creation->getUsers()) {
        auto *s = llvh::dyn_cast<StorePropertyInst>(u);
        if (!s || s->getStoredValue() != cls.creation || !llvh::isa<GlobalObject>(s->getObject()) || cls.binding) { eligible_ = false; break; }
        cls.binding = s;
      }
      if (!cls.binding) { eligible_ = false; continue; }
      const auto key = literal(cls.binding->getProperty());
      for (auto &f : *module_) for (auto &b : f) for (auto &i : b) {
        auto *load = llvh::dyn_cast<LoadPropertyInst>(&i);
        if (!load || !llvh::isa<GlobalObject>(load->getObject()) || literal(load->getProperty()) != key) continue;
        if (!f.isGlobalScope() || !before(cls.binding, load)) { eligible_ = false; continue; }
        for (auto *u : load->getUsers()) {
                                                                      
          if (auto *call = llvh::dyn_cast<CallInst>(u)) {
            auto *property = llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
            if (!property || property->getObject() != load || call->getArgument(0) != load) eligible_ = false;
            continue;
          }
          auto *property = llvh::dyn_cast<LoadPropertyInst>(u);
          if (!property || property->getObject() != load) { eligible_ = false; continue; }
          auto m = cls.methods.find(literal(property->getProperty()));
          if (m == cls.methods.end()) { eligible_ = false; continue; }
          for (auto *v : property->getUsers()) {
            auto *call = llvh::dyn_cast<CallInst>(v);
            if (!call || call->getCallee() != property || call->getNumArguments() != 1 ||
                call->getArgument(0) != load || m->second.site || call->getParent() != &f.front()) { eligible_ = false; continue; }
            m->second.site = call; calls_[call] = &m->second; allowedCalls_.insert(call);
          }
        }
      }
    }
                                                                                 
                                                                                  
    for (auto &f : *module_) for (auto &b : f) for (auto &i : b) {
      if (auto *call = llvh::dyn_cast<CallInst>(&i)) {
        if (!allowedCalls_.count(call) && !sourceCall(call)) eligible_ = false;
        if (sourceCall(call)) {
          auto *property = llvh::cast<LoadPropertyInst>(call->getCallee());
          auto *base = llvh::dyn_cast<LoadPropertyInst>(property->getObject());
          if (!base || !llvh::isa<GlobalObject>(base->getObject()) ||
              globals_.count(literal(base->getProperty()))) eligible_ = false;
        }
      }
      if (auto *load = llvh::dyn_cast<LoadPropertyInst>(&i))
        if (!expectedPropertyRead(load)) eligible_ = false;
    }
                                                                             
                                                                           
    for (auto &f : *module_) {
      if (!f.isGlobalScope()) continue;
      if (!entryReturn(&f)) { eligible_ = false; continue; }
      for (auto &i : f.front()) {
        if (llvh::isa<CreateScopeInst>(&i) || llvh::isa<AllocStackInst>(&i) ||
            llvh::isa<StoreStackInst>(&i) || llvh::isa<LoadStackInst>(&i) ||
            llvh::isa<CreateFunctionInst>(&i) || llvh::isa<LoadPropertyInst>(&i) ||
            llvh::isa<CallInst>(&i) || llvh::isa<ReturnInst>(&i)) continue;
        if (auto *store = llvh::dyn_cast<StorePropertyInst>(&i)) {
          auto *base = llvh::dyn_cast<LoadPropertyInst>(store->getObject());
                                                                               
          if (isSink(store) && base && llvh::isa<GlobalObject>(base->getObject()) &&
              globals_.count(literal(base->getProperty()))) eligible_ = false;
          continue;
        }
        if (auto *bin = llvh::dyn_cast<BinaryOperatorInst>(&i)) {
          steps_ = 0;
          if (bin->getOperatorKind() == BinaryOperatorInst::OpKind::AddKind &&
              eval(bin->getLeftHandSide(),bin).valid &&
              eval(bin->getRightHandSide(),bin).valid && steps_ <= 2048) continue;
        }
        eligible_ = false;
      }
    }
    for (auto &cls : classes_) for (auto &entry : cls.methods) {
      auto &method = entry.second;
                                                                          
                                                                             
      for (auto &i : method.body->front()) {
        if (llvh::isa<CreateScopeInst>(&i) || llvh::isa<StoreFrameInst>(&i) ||
            llvh::isa<LoadFrameInst>(&i) || llvh::isa<LoadPropertyInst>(&i) ||
            llvh::isa<ReturnInst>(&i)) continue;
        if (auto *call = llvh::dyn_cast<CallInst>(&i))
          if (sourceCall(call)) continue;
        eligible_ = false;
      }
    }
  }
  static void edge(Result &r, Instruction *i) {
    for (auto &t : r.traces)
      if (t.path.empty() || t.path.back() != i) t.path.push_back(i);
  }
  Result eval(Value *v, Instruction *use, unsigned depth = 0) {
    if (++steps_ > 2048 || depth > 32) return {};
    if (llvh::isa<LiteralNumber>(v) || llvh::isa<LiteralString>(v) ||
        llvh::isa<LiteralBool>(v) || llvh::isa<LiteralNull>(v) || llvh::isa<LiteralUndefined>(v)) return {true,{}};
    auto *i = llvh::dyn_cast<Instruction>(v);
    if (!i || owner(i) != owner(use) || i->getParent() != &owner(i)->front() || !before(i,use)) return {};
    if (auto *load = llvh::dyn_cast<LoadFrameInst>(i)) {
      auto *store = frameDefinition(load);
      if (!store) return {};
      Result r = eval(store->getValue(),store,depth+1); edge(r,store); edge(r,load); return r;
    }
    if (auto *load = llvh::dyn_cast<LoadPropertyInst>(i)) {
      if (!owner(i)->isGlobalScope() || !llvh::isa<GlobalObject>(load->getObject())) return {};
      auto found = globals_.find(literal(load->getProperty()));
      if (found == globals_.end() || !before(found->second,load)) return {};
      Result r = eval(found->second->getStoredValue(),found->second,depth+1); edge(r,found->second); edge(r,load); return r;
    }
    if (auto *bin = llvh::dyn_cast<BinaryOperatorInst>(i)) {
      if (bin->getOperatorKind() != BinaryOperatorInst::OpKind::AddKind) return {};
      Result a = eval(bin->getLeftHandSide(),bin,depth+1), b = eval(bin->getRightHandSide(),bin,depth+1);
      if (!a.valid || !b.valid || a.traces.size()+b.traces.size()>16) return {};
      a.traces.insert(a.traces.end(),b.traces.begin(),b.traces.end()); edge(a,bin); return a;
    }
    if (auto *call = llvh::dyn_cast<CallInst>(i)) {
      if (auto *source = sourceCall(call)) {
        Result r{true,{{source,{source},false}}}; edge(r,call); return r;
      }
      auto found = calls_.find(call);
      if (found == calls_.end()) return {};
      auto *ret = found->second->ret;
      Result r = eval(ret->getValue(),ret,depth+1); edge(r,ret); edge(r,call);
      for (auto &trace : r.traces) {
        if (owner(trace.source) != found->second->body) return {};
        trace.crossed = true;
      }
      return r;
    }
    return {};
  }

 public:
  BoundedStaticReturnTransport(Module *m, const std::vector<Instruction *> &sources,
      const std::vector<Instruction *> &sinks) : module_(m), sources_(sources), sinks_(sinks) { index(); }
  void append(std::vector<DefUseAnalyzer::TaintPath> &paths) {
    unsigned added = 0;
    if (eligible_) for (auto *sink : sinks_) {
      auto *store = llvh::dyn_cast<StorePropertyInst>(sink);
      if (!store || !owner(sink)->isGlobalScope() || !entryReturn(owner(sink)) || sink->getParent() != &owner(sink)->front()) continue;
      steps_ = 0;
      Result result = eval(store->getStoredValue(),store);
      if (!result.valid || steps_ > 2048) continue;
      for (auto &trace : result.traces) {
        if (!trace.crossed || std::any_of(paths.begin(),paths.end(),[&](const DefUseAnalyzer::TaintPath &p) { return p.source == trace.source && p.sink == sink; })) continue;
        trace.path.push_back(sink); paths.emplace_back(trace.source,trace.path,sink); ++added;
        llvh::outs() << "[STATIC_RETURN_TRACE] source=" << ids_[trace.source] << " sink=" << ids_[sink] << " path=";
        for (auto *i : trace.path) llvh::outs() << ids_[i] << "/" << i->getKindStr() << " ";
        llvh::outs() << "\n";
      }
    }
    llvh::outs() << "[STATIC_RETURN_BOUNDED] eligible=" << eligible_ << " added=" << added
                 << " contract=exact_class_identity_zero_args_single_call_entry_return_immutable_closed_input\n";
  }
};
}             
}                    

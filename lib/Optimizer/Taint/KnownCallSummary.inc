                                                                               
                                                                               
                                                                             
                                                                              
                                                                               
                                                                           
                                                                               
                                                                               
                                                                               
                                                                        
namespace {
struct ExactCallSummary {
  bool known{false};
  bool returnsPrimitive{false};
  // Diagnostic only: an unknown summary never licenses suppression. A known
  // return may be non-primitive; this does not make it an unknown dependency.
  const char *reason{"UNRESOLVED_CALLEE"};
  Instruction *barrier{nullptr};
  std::vector<std::vector<Instruction *>> parameterPaths;
};

class ExactCallSummarizer {
  using Path = std::vector<Instruction *>;
  struct Dependency {
    bool valid{false};
    bool primitive{false};                                         
    std::vector<bool> used;
    std::vector<Path> paths;
  };
  struct Context {
                                                                             
    unsigned steps{0};
    bool exhausted{false};
    int hostGlobalContract{-1};
    const char *hostReason{"HOST_CONTRACT_UNPROVEN"};
    Instruction *hostBarrier{nullptr};
    std::unordered_map<CallInst *, ExactCallSummary> known;
    std::unordered_set<CallInst *> active;
  };
  CallInst *site_;
  Function *body_{nullptr};
  unsigned nesting_;
  Context &context_;
  const char *reason_{nullptr};
  Instruction *barrier_{nullptr};
  unsigned parameterCount_{0};
  std::vector<int> parameterPrimitive_;

  void note(const char *reason, Instruction *barrier = nullptr) {
    if (!reason_) { reason_ = reason; barrier_ = barrier; }
  }
  ExactCallSummary unknown(const char *fallback = "UNRESOLVED_CALLEE") const {
    ExactCallSummary s;
    s.reason = reason_ ? reason_ : fallback;
    s.barrier = barrier_;
    return s;
  }

  static Function *owner(Instruction *i) {
    return i ? i->getParent()->getParent() : nullptr;
  }
  static bool before(Instruction *a, Instruction *b) {
    if (!a || !b || a->getParent() != b->getParent()) return false;
    for (auto &i : *a->getParent()) {
      if (&i == b) return false;
      if (&i == a) return true;
    }
    return false;
  }
  static bool singleReturningEntry(Function *f) {
    if (!f || f->empty()) return false;
                                                                             
                                                                               
                                                                           
                                                                                
                                                                            
    auto *ret = llvh::dyn_cast<ReturnInst>(f->front().getTerminator());
    return ret && ret->getNumSuccessors() == 0;
  }
  static std::string literalKey(Value *v) {
    auto *s = llvh::dyn_cast<LiteralString>(v);
    return s ? s->getValue().str().str() : "";
  }
  static bool literalPrimitive(Value *v) {
    return llvh::isa<LiteralNumber>(v) || llvh::isa<LiteralString>(v) ||
        llvh::isa<LiteralBool>(v) || llvh::isa<LiteralNull>(v) ||
        llvh::isa<LiteralUndefined>(v);
  }
  static bool numericUnary(UnaryOperatorInst *u) {
    switch (u->getOperatorKind()) {
      case UnaryOperatorInst::OpKind::PlusKind:
      case UnaryOperatorInst::OpKind::MinusKind:
      case UnaryOperatorInst::OpKind::TildeKind:
      case UnaryOperatorInst::OpKind::IncKind:
      case UnaryOperatorInst::OpKind::DecKind: return true;
      default: return false;
    }
  }
  static bool primitiveBinary(BinaryOperatorInst *b) {
    switch (b->getOperatorKind()) {
      case BinaryOperatorInst::OpKind::EqualKind:
      case BinaryOperatorInst::OpKind::NotEqualKind:
      case BinaryOperatorInst::OpKind::StrictlyEqualKind:
      case BinaryOperatorInst::OpKind::StrictlyNotEqualKind:
      case BinaryOperatorInst::OpKind::LessThanKind:
      case BinaryOperatorInst::OpKind::LessThanOrEqualKind:
      case BinaryOperatorInst::OpKind::GreaterThanKind:
      case BinaryOperatorInst::OpKind::GreaterThanOrEqualKind:
      case BinaryOperatorInst::OpKind::LeftShiftKind:
      case BinaryOperatorInst::OpKind::RightShiftKind:
      case BinaryOperatorInst::OpKind::UnsignedRightShiftKind:
      case BinaryOperatorInst::OpKind::AddKind:
      case BinaryOperatorInst::OpKind::SubtractKind:
      case BinaryOperatorInst::OpKind::MultiplyKind:
      case BinaryOperatorInst::OpKind::DivideKind:
      case BinaryOperatorInst::OpKind::ModuloKind:
      case BinaryOperatorInst::OpKind::OrKind:
      case BinaryOperatorInst::OpKind::XorKind:
      case BinaryOperatorInst::OpKind::AndKind:
      case BinaryOperatorInst::OpKind::ExponentiationKind: return true;
      default: return false;                                                 
    }
  }
  bool spend() {
    if (context_.steps >= 4096) {
      context_.exhausted = true; note("PROOF_BUDGET_EXHAUSTED"); return false;
    }
    ++context_.steps;
    return true;
  }

                                                                           
                                                                             
                                                                             
                                                                        
  bool nativeHostGlobalsUnmodified() {
    if (context_.hostGlobalContract >= 0) {
      if (!context_.hostGlobalContract) note(context_.hostReason, context_.hostBarrier);
      return context_.hostGlobalContract != 0;
    }
    context_.hostGlobalContract = 0;
    auto reject = [&](const char *why, Instruction *at = nullptr) {
      context_.hostReason = why; context_.hostBarrier = at; note(why, at);
      return false;
    };
    Module *module = owner(site_)->getParent();
    for (auto *binding : module->getGlobalProperties()) {
      if (!spend()) return reject("PROOF_BUDGET_EXHAUSTED");
      const auto name = literalKey(binding->getName());
      if (binding->isDeclared() && (name == "Date" || name == "document"))
        return reject("HOST_GLOBAL_SHADOWED");
    }
    for (auto &f : *module) for (auto &bb : f) for (auto &i : bb) {
      if (!spend()) return reject("PROOF_BUDGET_EXHAUSTED", &i);
      if (llvh::isa<DirectEvalInst>(&i) || llvh::isa<StoreGetterSetterInst>(&i))
        return reject("HOST_ACCESSOR_OR_EVAL", &i);
      Value *written = nullptr;
      if (auto *s = llvh::dyn_cast<StorePropertyInst>(&i)) written = s->getProperty();
      else if (auto *s = llvh::dyn_cast<StoreOwnPropertyInst>(&i)) written = s->getProperty();
      else if (auto *d = llvh::dyn_cast<DeletePropertyInst>(&i)) written = d->getProperty();
      if (written) {
        const auto key = literalKey(written);
        if (key.empty() || key == "Date" || key == "document" ||
            key == "now" || key == "__proto__") return reject("HOST_MUTATION_UNPROVEN", &i);
      }
      if (auto *read = llvh::dyn_cast<LoadPropertyInst>(&i)) {
        const auto key = literalKey(read->getProperty());
        if (key == "defineProperty" || key == "defineProperties" ||
            key == "__defineGetter__" || key == "__defineSetter__" ||
            key == "setPrototypeOf") return reject("HOST_DESCRIPTOR_API", &i);
      }
    }
    context_.hostGlobalContract = 1;
    return true;
  }

                                                                         
                                                                                
                                                           
  bool originalDateNow(CallInst *call) {
    if (!call || llvh::isa<ConstructInst>(call) || call->getNumArguments() != 1)
      return false;
    auto *method = llvh::dyn_cast<LoadPropertyInst>(call->getCallee());
    if (!method || literalKey(method->getProperty()) != "now" ||
        call->getArgument(0) != method->getObject()) return false;
    auto *base = llvh::dyn_cast<LoadPropertyInst>(method->getObject());
    if (!base || !llvh::isa<GlobalObject>(base->getObject()) ||
        literalKey(base->getProperty()) != "Date") return false;
    return nativeHostGlobalsUnmodified();
  }

                                                                              
                                                                               
  StoreFrameInst *frameDefinition(LoadFrameInst *load) {
    auto *f = owner(load);
    if (!f || load->getParent() != &f->front()) return nullptr;
    auto *env = llvh::dyn_cast<CreateScopeInst>(load->getEnvironment());
    if (!env || owner(env) != f) return nullptr;
    for (auto *u : load->getLoadVariable()->getUsers()) {
      if (!spend() || owner(u) != f || u->getParent() != load->getParent()) return nullptr;
      if (!llvh::isa<LoadFrameInst>(u) && !llvh::isa<StoreFrameInst>(u)) return nullptr;
    }
    StoreFrameInst *last = nullptr;
    for (auto &i : *load->getParent()) {
      if (!spend()) return nullptr;
      if (&i == load) break;
      if (auto *s = llvh::dyn_cast<StoreFrameInst>(&i))
        if (s->getVariable() == load->getLoadVariable() &&
            s->getEnvironment() == load->getEnvironment()) last = s;
    }
    return last;
  }

                                                                              
                                                                       
  StorePropertyInst *globalDefinition(LoadPropertyInst *load) {
    auto *f = owner(load);
    const auto key = literalKey(load->getProperty());
    if (!f || !f->isGlobalScope() || load->getParent() != &f->front() ||
        !llvh::isa<GlobalObject>(load->getObject()) || key.empty()) return nullptr;
    for (auto &candidate : *f->getParent()) for (auto &b : candidate) for (auto &i : b) {
      if (!spend()) return nullptr;
      if (auto *s = llvh::dyn_cast<StorePropertyInst>(&i)) {
        if (!llvh::isa<GlobalObject>(s->getObject())) continue;
        const auto written = literalKey(s->getProperty());
        if (written.empty() || (written == key &&
            (owner(s) != f || s->getParent() != load->getParent()))) return nullptr;
      }
    }
    StorePropertyInst *last = nullptr;
    for (auto &i : *load->getParent()) {
      if (!spend()) return nullptr;
      if (&i == load) break;
      if (auto *s = llvh::dyn_cast<StorePropertyInst>(&i))
        if (s->getObject() == load->getObject() &&
            literalKey(s->getProperty()) == key) last = s;
    }
    return last;
  }

  bool safeCall(CallInst *call) {
    if (originalDateNow(call)) return true;
    const auto summary = nestedSummary(call);
    if (!summary.known) note(summary.reason, summary.barrier ? summary.barrier : call);
    return summary.known;
  }

  ExactCallSummary nestedSummary(CallInst *call) {
    auto known = context_.known.find(call);
    if (known != context_.known.end()) return known->second;
    if (context_.active.count(call)) {
      ExactCallSummary s; s.reason = "RECURSIVE_CALL_PROOF"; s.barrier = call; return s;
    }
    if (nesting_ >= 6) {
      ExactCallSummary s; s.reason = "CALL_DEPTH_LIMIT"; s.barrier = call; return s;
    }
    return ExactCallSummarizer(call, context_, nesting_ + 1).run();
  }

                                                                              
                                                                           
                                                                            
  bool bindingInterval(Instruction *definition, Instruction *load, bool global) {
    if (!before(definition, load)) { note("NO_ORDERED_BINDING", load); return false; }
    bool active = global;
    for (auto &i : *load->getParent()) {
      if (!spend()) return false;
      if (&i == definition) active = true;
      if (&i == load) return true;
      if (!active || &i == definition) continue;
      if (auto *call = llvh::dyn_cast<CallInst>(&i)) {
        if (!safeCall(call)) return false;
        continue;
      }
      if (llvh::isa<DeletePropertyInst>(&i)) { note("UNKNOWN_DELETE_EFFECT", &i); return false; }
      if (auto *s = llvh::dyn_cast<StorePropertyInst>(&i)) {
        if (!llvh::isa<GlobalObject>(s->getObject()) ||
            literalKey(s->getProperty()).empty()) {
          // In particular, document.cookie may invoke a setter. The native
          // host read contract does NOT license assuming its write is inert.
          note("UNKNOWN_EXTERNAL_WRITE", s); return false;
        }
        continue;
      }
      if (auto *p = llvh::dyn_cast<LoadPropertyInst>(&i)) {
        if (llvh::isa<GlobalObject>(p->getObject())) {
          const auto key = literalKey(p->getProperty());
          if (key == "Date" || key == "document") {
            if (!nativeHostGlobalsUnmodified()) return false;
            continue;
          }
          if (!globalDefinition(p)) { note("GLOBAL_READ_UNRESOLVED", p); return false; }
          continue;
        }
        bool isIntrinsicCallee = false;
        for (auto *u : p->getUsers())
          if (auto *c = llvh::dyn_cast<CallInst>(u))
            if (c->getCallee() == p && originalDateNow(c)) isIntrinsicCallee = true;
        if (!isIntrinsicCallee) { note("UNKNOWN_PROPERTY_READ", p); return false; }
        continue;
      }
      if (auto *b = llvh::dyn_cast<BinaryOperatorInst>(&i)) {
        if (!primitiveValue(b, load, 0)) { note("COERCION_UNPROVEN", b); return false; }
        continue;
      }
      if (auto *u = llvh::dyn_cast<UnaryOperatorInst>(&i)) {
        if (!primitiveValue(u, load, 0)) { note("COERCION_UNPROVEN", u); return false; }
        continue;
      }
      if (llvh::isa<CreateScopeInst>(&i) || llvh::isa<CreateFunctionInst>(&i) ||
          llvh::isa<LoadFrameInst>(&i) || llvh::isa<StoreFrameInst>(&i) ||
          llvh::isa<AllocStackInst>(&i) || llvh::isa<StoreStackInst>(&i) ||
          llvh::isa<LoadStackInst>(&i) || llvh::isa<MovInst>(&i)) continue;
      note("UNSUPPORTED_BINDING_EFFECT", &i); return false;
    }
    return false;
  }

  Function *resolveClosure(Value *value, Instruction *use, unsigned depth = 0) {
    if (!spend()) return nullptr;
    if (depth > 12) { note("CLOSURE_DEPTH_LIMIT", use); return nullptr; }
    if (auto *f = llvh::dyn_cast<Function>(value)) return f;
    auto *i = llvh::dyn_cast<Instruction>(value);
    if (!i || owner(i) != owner(use) || !before(i, use)) {
      note("CALLEE_IDENTITY_UNPROVEN", use); return nullptr;
    }
    if (auto *c = llvh::dyn_cast<CreateFunctionInst>(i)) return c->getFunctionCode();
    if (auto *m = llvh::dyn_cast<MovInst>(i)) return resolveClosure(m->getSingleOperand(), m, depth + 1);
    if (auto *l = llvh::dyn_cast<LoadFrameInst>(i)) {
      auto *s = frameDefinition(l);
      if (!s) note("FRAME_DEFINITION_UNRESOLVED", l);
      return s && bindingInterval(s, l, false) ? resolveClosure(s->getValue(), s, depth + 1) : nullptr;
    }
    if (auto *l = llvh::dyn_cast<LoadPropertyInst>(i)) {
      auto *s = globalDefinition(l);
      if (!s) note("GLOBAL_DEFINITION_UNRESOLVED", l);
      return s && bindingInterval(s, l, true) ? resolveClosure(s->getStoredValue(), s, depth + 1) : nullptr;
    }
    note("CALLEE_IDENTITY_UNPROVEN", i);
    return nullptr;
  }

                                                                           
                                                                               
                                                             
  bool primitiveValue(Value *v, Instruction *use, unsigned depth) {
    if (!spend()) return false;
    if (depth > 20) { note("PRIMITIVE_DEPTH_LIMIT", use); return false; }
    if (literalPrimitive(v)) return true;
    auto *i = llvh::dyn_cast<Instruction>(v);
    if (!i || owner(i) != owner(use) || !before(i, use)) return false;
    if (auto *m = llvh::dyn_cast<MovInst>(i)) return primitiveValue(m->getSingleOperand(), m, depth + 1);
    if (auto *l = llvh::dyn_cast<LoadFrameInst>(i)) {
      auto *s = frameDefinition(l);
      return s && bindingInterval(s, l, false) && primitiveValue(s->getValue(), s, depth + 1);
    }
    if (auto *l = llvh::dyn_cast<LoadPropertyInst>(i)) {
      auto *s = globalDefinition(l);
      return s && bindingInterval(s, l, true) && primitiveValue(s->getStoredValue(), s, depth + 1);
    }
    if (auto *c = llvh::dyn_cast<CallInst>(i)) {
      if (originalDateNow(c)) return true;
                                                                              
                                                                             
                                                                            
      const auto summary = nestedSummary(c);
      if (!summary.known) note(summary.reason, summary.barrier ? summary.barrier : c);
      else if (!summary.returnsPrimitive) note("CALL_RETURN_NOT_PROVEN_PRIMITIVE", c);
      return summary.known && summary.returnsPrimitive;
    }
    if (auto *b = llvh::dyn_cast<BinaryOperatorInst>(i))
      return primitiveBinary(b) && primitiveValue(b->getLeftHandSide(), b, depth + 1) &&
          primitiveValue(b->getRightHandSide(), b, depth + 1);
    if (auto *u = llvh::dyn_cast<UnaryOperatorInst>(i)) {
      if (numericUnary(u)) return primitiveValue(u->getSingleOperand(), u, depth + 1);
      return u->getOperatorKind() == UnaryOperatorInst::OpKind::VoidKind ||
          u->getOperatorKind() == UnaryOperatorInst::OpKind::TypeofKind ||
          u->getOperatorKind() == UnaryOperatorInst::OpKind::BangKind;
    }
    return false;
  }

  Dependency fresh(bool primitive = false) const {
    Dependency d;
    d.valid = true; d.primitive = primitive;
    d.used.resize(parameterCount_, false); d.paths.resize(parameterCount_);
    return d;
  }
  static void edge(Dependency &d, Instruction *i) {
    for (unsigned n = 0; n < d.used.size(); ++n)
      if (d.used[n] && (d.paths[n].empty() || d.paths[n].back() != i)) d.paths[n].push_back(i);
  }
  Dependency eval(Value *v, Instruction *use, unsigned depth = 0) {
    if (!spend() || depth > 32) return {};
    if (literalPrimitive(v)) return fresh(true);
    if (auto *p = llvh::dyn_cast<Parameter>(v)) {
      if (p->getParent() != body_ || p == body_->getThisParameter()) return {};
      auto &params = body_->getParameters();
      for (unsigned n = 0; n < params.size(); ++n) if (params[n] == p) {
        if (parameterPrimitive_[n] < 0)
          parameterPrimitive_[n] = n + 1 >= site_->getNumArguments() ||
              primitiveValue(site_->getArgument(n + 1), site_, 0);
        const bool primitive = parameterPrimitive_[n] != 0;
        Dependency d = fresh(primitive); d.used[n] = true; return d;
      }
      return {};
    }
    auto *i = llvh::dyn_cast<Instruction>(v);
    if (!i || owner(i) != body_ || i->getParent() != &body_->front() || !before(i, use)) return {};
    if (auto *l = llvh::dyn_cast<LoadFrameInst>(i)) {
      auto *s = frameDefinition(l);
      if (!s) return {};
      Dependency d = eval(s->getValue(), s, depth + 1); edge(d, s); edge(d, l); return d;
    }
    if (auto *m = llvh::dyn_cast<MovInst>(i)) {
      Dependency d = eval(m->getSingleOperand(), m, depth + 1); edge(d, m); return d;
    }
    if (auto *b = llvh::dyn_cast<BinaryOperatorInst>(i)) {
      if (!primitiveBinary(b)) return {};
      Dependency a = eval(b->getLeftHandSide(), b, depth + 1);
      Dependency c = eval(b->getRightHandSide(), b, depth + 1);
      if (!a.valid || !c.valid || !a.primitive || !c.primitive) return {};
      for (unsigned n = 0; n < parameterCount_; ++n) if (c.used[n] && !a.used[n]) {
        a.used[n] = true; a.paths[n] = c.paths[n];
      }
      edge(a, b); return a;
    }
    if (auto *u = llvh::dyn_cast<UnaryOperatorInst>(i)) {
      Dependency d = eval(u->getSingleOperand(), u, depth + 1);
      if (!d.valid) return {};
      if (u->getOperatorKind() == UnaryOperatorInst::OpKind::VoidKind) return fresh(true);
      if (u->getOperatorKind() != UnaryOperatorInst::OpKind::TypeofKind &&
          u->getOperatorKind() != UnaryOperatorInst::OpKind::BangKind &&
          !(numericUnary(u) && d.primitive)) return {};
      d.primitive = true; edge(d, u); return d;
    }
    return {};
  }

  ExactCallSummarizer(CallInst *site, Context &context, unsigned nesting)
      : site_(site), nesting_(nesting), context_(context) {}

  ExactCallSummary run() {
    if (!site_ || llvh::isa<ConstructInst>(site_) || nesting_ > 6)
      return unknown("UNSUPPORTED_CALL_FORM");
    if (!context_.active.insert(site_).second) return unknown("RECURSIVE_CALL_PROOF");
    struct ActiveScope {
      Context &context;
      CallInst *site;
      ~ActiveScope() { context.active.erase(site); }
    } activeScope{context_, site_};
    body_ = resolveClosure(site_->getCallee(), site_);
    if (!singleReturningEntry(body_)) return unknown(body_ ? "NONLINEAR_RETURN_BODY" : "UNRESOLVED_CALLEE");
    auto *ret = llvh::dyn_cast<ReturnInst>(body_->front().getTerminator());
    if (!ret) return unknown("MISSING_NORMAL_RETURN");
    parameterCount_ = body_->getParameters().size();
    if (parameterCount_ > 64) return unknown("PARAMETER_LIMIT");
    parameterPrimitive_.assign(parameterCount_, -1);
                                                                             
                                                                               
    for (auto &i : body_->front()) {
      if (!spend()) return unknown();
      if (llvh::isa<CreateScopeInst>(&i)) continue;
      if (auto *s = llvh::dyn_cast<StoreFrameInst>(&i)) {
        auto *env = llvh::dyn_cast<CreateScopeInst>(s->getEnvironment());
        if (!env || owner(env) != body_ || !eval(s->getValue(), s).valid)
          return unknown("UNSUPPORTED_FRAME_VALUE");
        for (auto *u : s->getVariable()->getUsers())
          if (owner(u) != body_ || u->getParent() != &body_->front())
            return unknown("CAPTURED_FRAME_SLOT");
        continue;
      }
      if (&i == ret) continue;
      if (llvh::isa<LoadFrameInst>(&i) || llvh::isa<MovInst>(&i) ||
          llvh::isa<BinaryOperatorInst>(&i) || llvh::isa<UnaryOperatorInst>(&i)) {
        if (!eval(&i, ret).valid) return unknown("UNSUPPORTED_BODY_VALUE");
        continue;
      }
      note("UNSUPPORTED_BODY_EFFECT", &i); return unknown();
    }
    Dependency result = eval(ret->getValue(), ret);
    if (context_.exhausted) {
      ExactCallSummary exhausted; exhausted.reason = "PROOF_BUDGET_EXHAUSTED"; return exhausted;
    }
    if (!result.valid) return unknown("RETURN_DEPENDENCY_UNPROVEN");
    edge(result, ret);
    ExactCallSummary summary; summary.known = true;
    summary.returnsPrimitive = result.primitive;
    summary.reason = "EXACT_NORMAL_RETURN";
    summary.parameterPaths = std::move(result.paths);
    context_.known[site_] = summary;
    return summary;
  }

 public:
  static ExactCallSummary summarize(CallInst *site) {
    Context context;
    return ExactCallSummarizer(site, context, 0).run();
  }
};

ExactCallSummary summarizeExactCall(CallInst *call) {
  return ExactCallSummarizer::summarize(call);
}
}             

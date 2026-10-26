                                                                                
                                                                                     
                                                                               
                                                                               
                                                                                
                                                                                
                                                           
                                                                                
                                                                               
                                                                         
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cmath>
#include <map>
#include <set>

namespace hermes {
namespace {
class BoundedNativeStaticReturnTransport {
  using Path = std::vector<Instruction *>;
  struct Trace {
    Instruction *source;
    Path path;
    unsigned originInvocation;
    bool crossedReturn{false};
    bool throughOwnData{false};
  };
  enum Kind { Invalid, Empty, Primitive, Undefined, Null, Global, Scope, Closure,
              DateObject, DateNow, AmbientDocument, ClassInternal, DefineClass, DefineStatic, DefineMethod, Instance, ClassPrototype, ClassNameObject, SymbolObject, SymbolKey, HasInstanceBuiltin, ObjectBuiltin, DefineOwnData, GeneratorRecord, GeneratorNext, GeneratorReturn, GeneratorResult, DefineSetter, DefineStaticSetter, ConstructorArguments, PrivateToken };
  struct Datum {
    Kind kind{Invalid};
    Instruction *identity{nullptr};
    unsigned environment{0};
    unsigned object{0};
    std::string keyName;
    bool knownBoolean=false,booleanValue=false;
    bool knownNumber=false; double numberValue=0;
    std::vector<Trace> traces;
  };
  struct Frame {
    Function *function;
    CreateScopeInst *scope{nullptr};
    Instruction *entry{nullptr};
    unsigned invocation{0};
    unsigned capturedEnvironment{0};
    std::vector<Datum> arguments;
    Datum receiver;
    Datum newTarget;
    bool constructing{false};
    bool generatorBody{false}, suspended{false}, completed{false}, returnRequested{false};
    Datum resumeValue;
    BasicBlock *resumeBlock{nullptr}, *resumePrevious{nullptr};
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
  unsigned nestedReferenceWrites_{0},nestedReferenceReads_{0},objectComparisons_{0};
                                                                           
                                                                         
  const unsigned ownPropertyBudget_{4096};
  unsigned ownPropertySlots_{0},peakOwnPropertySlots_{0};
  bool reserveOwnProperty(unsigned object, const std::string &name, Instruction *at) {
    if(!nameObjects_.count(object)){reject("OWN_PROPERTY_OBJECT_IDENTITY",at);return false;}
    if(nameObjects_.at(object).count(name)||getters_[object].count(name))return true;
    if(ownPropertySlots_>=ownPropertyBudget_){reject("OWN_PROPERTY_BUDGET",at);return false;}
    ++ownPropertySlots_;
    if(ownPropertySlots_>peakOwnPropertySlots_)peakOwnPropertySlots_=ownPropertySlots_;
    return true;
  }
  bool knownObjectReference(const Datum &d) const {
    return d.kind==ClassNameObject&&d.object&&nameObjects_.count(d.object);
  }
  std::set<unsigned> arrayObjects_;
  unsigned arrayAllocations_{0},arrayReads_{0},arrayWrites_{0},arrayLengthWrites_{0};
  static bool arrayIndex(const std::string &name, uint32_t &index) {
    if(name.empty()||name.size()>10||(name.size()>1&&name[0]=='0'))return false;
    uint64_t n=0;
    for(char c:name){if(c<'0'||c>'9')return false;n=n*10+unsigned(c-'0');}
    if(n>=4294967295ULL)return false;
    index=uint32_t(n);return true;
  }
  Datum arrayWrite(Datum object,const std::string &k,Datum d,Instruction *at,bool defineOwn) {
    if(failed_||!arrayObjects_.count(object.object)||k.compare(0,2,"S:")!=0)
      return reject("ARRAY_OBJECT_KEY_UNPROVEN",at);
    const auto name=k.substr(2);auto &own=nameObjects_.at(object.object);
    if(name=="length") {
                                                                              
                                                                  
      if(d.kind!=Primitive||!d.knownNumber||!d.traces.empty()||!std::isfinite(d.numberValue)||
         d.numberValue<0||d.numberValue>4294967295.0||std::floor(d.numberValue)!=d.numberValue)
        return reject("ARRAY_LENGTH_VALUE_UNPROVEN",at);
      const auto length=uint32_t(d.numberValue);
      for(auto it=own.begin();it!=own.end();) {
        if(++steps_>20000)return reject("PROOF_STEP_LIMIT",at);
        uint32_t index=0;
        if(arrayIndex(it->first,index)&&index>=length) {
          if(!ownPropertySlots_)return reject("OWN_PROPERTY_ACCOUNTING",at);
          registeredProperties_[object.object].erase(it->first);it=own.erase(it);--ownPropertySlots_;
        } else ++it;
      }
      edge(d,at);own["length"]=d;++arrayLengthWrites_;return make(Undefined);
    }
    uint32_t index=0;
    if(!arrayIndex(name,index))return reject("ARRAY_NON_INDEX_PROPERTY_UNPROVEN",at);
    if(!primitive(d)&&d.kind!=Closure&&d.kind!=SymbolKey&&!knownObjectReference(d))
      return reject("ARRAY_ELEMENT_VALUE_UNPROVEN",at);
                                                                        
                                                                          
    if(!defineOwn&&!own.count(name))return reject("ARRAY_HOLE_WRITE_PROTOTYPE_UNPROVEN",at);
    if(!reserveOwnProperty(object.object,name,at))return {};
    edge(d,at);own[name]=d;
    if(knownObjectReference(d))++nestedReferenceWrites_;
    auto &length=own.at("length");
    if(double(index)>=length.numberValue)length.numberValue=double(index)+1;
    ++arrayWrites_;return make(Undefined);
  }
  Datum allocateArray(AllocArrayInst *alloc,Frame &frame) {
    const double hint=alloc->getSizeHint()->getValue();
                                                                            
                                                                             
    if(!std::isfinite(hint)||hint<0||hint>65535||std::floor(hint)!=hint||
       alloc->getElementCount()>hint||nextObject_>512)return reject("ARRAY_ALLOCATION_SHAPE_OR_BOUND",alloc);
    Datum object=make(ClassNameObject,alloc);object.object=nextObject_++;
    nameObjects_[object.object]={};arrayObjects_.insert(object.object);
    if(!reserveOwnProperty(object.object,"length",alloc))return {};
    Datum length=make(Primitive,alloc);length.knownNumber=true;length.numberValue=hint;
    nameObjects_[object.object]["length"]=length;++arrayAllocations_;
    for(unsigned i=0;i<alloc->getElementCount();++i) {
      if(++steps_>20000)return reject("PROOF_STEP_LIMIT",alloc);
      Datum d=value(alloc->getArrayElement(i),frame,alloc);
      if(d.kind==Empty)continue;
      arrayWrite(object,"S:"+std::to_string(i),d,alloc,true);
      if(failed_)return {};
    }
    return object;
  }
                                                                                 
                                                                                  
  std::map<unsigned,std::pair<Instruction *,unsigned>> closureIdentities_;
  std::set<unsigned> passedClosureIds_;
  unsigned closureArgumentEdges_{0},callsOfPassedClosures_{0};
  bool knownClosureIdentity(const Datum &d) const {
    if(d.kind!=Closure||!d.object||!d.environment)return false;
    auto *creation=llvh::dyn_cast_or_null<CreateFunctionInst>(d.identity);
    auto identity=closureIdentities_.find(d.object);
    auto environment=environments_.find(d.environment);
    return creation&&identity!=closureIdentities_.end()&&environment!=environments_.end()&&
      identity->second.first==d.identity&&identity->second.second==d.environment&&
      functionIds_.count(creation->getFunctionCode())&&
      creation->getFunctionCode()->getFunctionScopeDesc()->getParent()==environment->second.descriptor;
  }
                                                                       
                                                                        
  std::map<unsigned,Datum> functionPrototypeValues_;
  unsigned functionPrototypeCreated_{0},functionPrototypeReads_{0},functionPrototypeWrites_{0};
  bool ordinaryPrototypeFunction(const Datum &fn) const {
    if(!knownClosureIdentity(fn)||classes_.count(fn.object))return false;
    auto *creation=llvh::cast<CreateFunctionInst>(fn.identity);auto *body=creation->getFunctionCode();
    if(body->getDefinitionKind()!=Function::DefinitionKind::ES5Function||
      llvh::isa<AsyncFunction>(body)||llvh::isa<GeneratorFunction>(body)||llvh::isa<GeneratorInnerFunction>(body))return false;
                                                                            
                                                                           
                                                                            
                                                                           
    const auto range=body->getSourceRange();const char *begin=range.Start.getPointer(),*end=range.End.getPointer();
    if(!begin||!end||end-begin<=8||body->getOriginalOrInferredName().str()=="function")return false;
    if(llvh::StringRef(begin,8)!="function")return false;
    const char delimiter=begin[8];
    return delimiter=='('||delimiter==' '||delimiter=='\t'||delimiter=='\n'||delimiter=='\r'||delimiter=='\f'||delimiter=='\v'||delimiter=='/';
  }
  Datum functionPrototypeRead(Datum fn,Instruction *at,unsigned invocation) {
    if(!ordinaryPrototypeFunction(fn))return reject("FUNCTION_PROTOTYPE_KIND_OR_IDENTITY_UNPROVEN",at);
    auto entry=functionPrototypeValues_.find(fn.object);
    if(entry==functionPrototypeValues_.end()) {
      if(nextObject_>512)return reject("FUNCTION_PROTOTYPE_OBJECT_LIMIT",at);
      Datum prototype=make(ClassNameObject,at);prototype.object=nextObject_++;
      nameObjects_[prototype.object]={};
      if(!reserveOwnProperty(prototype.object,"constructor",at))return {};
                                                                           
                                                                          
      nameObjects_[prototype.object]["constructor"]=fn;
      functionPrototypeValues_[fn.object]=prototype;++functionPrototypeCreated_;
      if(functionPrototypeCreated_<=16)llvh::outs()<<"[NATIVE_FUNCTION_PROTOTYPE] read="<<id(at)
        <<" closure_id="<<fn.object<<" creation="<<id(fn.identity)<<" captured_environment="<<fn.environment
        <<" prototype_id="<<prototype.object<<" own_constructor=1 inherited_properties=UNPROVEN\n";
    }
    Datum d=functionPrototypeValues_.at(fn.object);++functionPrototypeReads_;
    for(auto &t:d.traces){t.throughOwnData=true;if(t.originInvocation!=invocation)t.crossedReturn=true;}
    edge(d,at);return d;
  }
  Datum functionPrototypeWrite(Datum fn,Datum d,Instruction *at) {
    if(!ordinaryPrototypeFunction(fn))return reject("FUNCTION_PROTOTYPE_KIND_OR_IDENTITY_UNPROVEN",at);
    if(!primitive(d)&&!knownObjectReference(d)&&!knownClosureIdentity(d))
      return reject("FUNCTION_PROTOTYPE_VALUE_UNPROVEN",at);
                                                                             
                                                                               
    edge(d,at);functionPrototypeValues_[fn.object]=d;++functionPrototypeWrites_;
    return make(Undefined);
  }
  std::map<unsigned,std::map<std::string,Datum>> functionOwnData_;
  std::map<unsigned, Frame> generators_;
  std::map<unsigned, std::pair<Datum,bool>> generatorResults_;
  std::map<unsigned,std::map<std::string,Datum>> instanceFields_;
  std::set<Instruction *> executedSinks_;
  std::set<std::pair<Instruction *,Instruction *>> observedPairs_;
  unsigned generatorCreated_{0}, generatorAdvances_{0}, generatorYields_{0}, generatorCloses_{0};
  std::map<unsigned, Environment> environments_;
  unsigned nextEnvironment_{1},dynamicScopeCreations_{0};
  Datum newEnvironment(ScopeDesc *descriptor, unsigned parent,
                       unsigned invocation, Instruction *at,bool exactDynamicInner=false) {
    if (!descriptor || nextEnvironment_ > 512 || (descriptor->getDynamic()&&!exactDynamicInner))
      return reject("LEXICAL_ENVIRONMENT_LIMIT_OR_DYNAMIC", at);
    if (parent && (!environments_.count(parent) ||
        descriptor->getParent() != environments_.at(parent).descriptor))
      return reject("LEXICAL_PARENT_IDENTITY", at);
    if(descriptor->getDynamic()) {
                                                                          
                                                                            
                                                                          
      auto *inner=llvh::dyn_cast_or_null<CreateInnerScopeInst>(at);
      if(!inner||!parent||!environments_.count(parent)||
         inner->getCreatedScopeDesc()!=descriptor||
         descriptor->getFunction()!=inner->getParent()->getParent()||
         descriptor==inner->getParent()->getParent()->getFunctionScopeDesc()||
         environments_.at(parent).ownerInvocation!=invocation)
        return reject("DYNAMIC_INNER_SCOPE_IDENTITY_UNPROVEN",at);
    }
                                                                        
    const unsigned id = nextEnvironment_++;
    environments_.emplace(id, Environment{descriptor, parent, invocation, {}});
    if(descriptor->getDynamic()) {
      ++dynamicScopeCreations_;
      if(dynamicScopeCreations_<=16)llvh::outs()<<"[NATIVE_DYNAMIC_SCOPE] at="<<this->id(at)
        <<" environment_id="<<id<<" parent_environment="<<parent<<" invocation="<<invocation
        <<" fresh_identity=1 parent_descriptor_match=1 environment=UNPROVEN\n";
    }
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
                                                                          
                                                                              
  std::map<Function *, unsigned> functionIds_;
  mutable std::map<Instruction *, std::string> diagnosticIds_;
  uint64_t metadataInstructions_{0}, metadataFunctions_{0}, metadataMicros_{0};
  bool metadataComplete_{false};
  const char *metadataStop_{"NOT_STARTED"};
  std::map<std::string, Datum> globals_;
  std::set<std::string> declaredGlobals_;
  std::set<Function *> active_;
  std::vector<DefUseAnalyzer::TaintPath> pending_;
  Function *global_{nullptr};
  unsigned steps_{0}, invocations_{0}, returns_{0}, argumentEdges_{0};
  unsigned nativeDefinitions_{0}, normalEntryGuards_{0}, propertyDeletes_{0}, getterDefinitions_{0}, getterInvocations_{0};
  unsigned registrationAttempts_{0}, registrations_{0}, registrationReads_{0};
  unsigned executedBlocks_{0}, provenBranches_{0}, directEdges_{0}, selectedPhis_{0};
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
  static bool truth(const Datum &d, bool &out) {
                                                                             
    if(!d.traces.empty())return false;
    if(d.kind==Undefined||d.kind==Null){out=false;return true;}
    if(d.kind==Primitive){
      if(d.knownBoolean){out=d.booleanValue;return true;}
      if(d.knownNumber){out=d.numberValue!=0&&!std::isnan(d.numberValue);return true;}
      if(d.keyName.compare(0,2,"S:")==0){out=d.keyName.size()>2;return true;}
    }
    if(d.kind==Closure||d.kind==ClassNameObject){out=true;return true;}
    return false;
  }
  static const char *exactType(const Datum &d) {
    if(!d.traces.empty())return nullptr;
    if(d.kind==Undefined)return "undefined";
    if(d.kind==Null||d.kind==ClassNameObject)return "object";
    if(d.kind==Closure)return "function";
    if(d.kind==Primitive){
      if(d.knownBoolean)return "boolean";
      if(d.knownNumber)return "number";
      if(d.keyName.compare(0,2,"S:")==0)return "string";
    }
    return nullptr;
  }
  unsigned exactNumericRelations_{0};
  Datum compareNumeric(const Datum &a,const Datum &b,BinaryOperatorInst *at) {
                                                                              
    if(failed_||a.kind!=Primitive||b.kind!=Primitive||!a.knownNumber||!b.knownNumber||
       !a.traces.empty()||!b.traces.empty()||!std::isfinite(a.numberValue)||!std::isfinite(b.numberValue))
      return reject("NUMERIC_RELATION_OPERANDS_UNPROVEN",at);
    using Op=BinaryOperatorInst::OpKind;bool result=false;
    switch(at->getOperatorKind()) {
      case Op::LessThanKind:result=a.numberValue<b.numberValue;break;
      case Op::LessThanOrEqualKind:result=a.numberValue<=b.numberValue;break;
      case Op::GreaterThanKind:result=a.numberValue>b.numberValue;break;
      case Op::GreaterThanOrEqualKind:result=a.numberValue>=b.numberValue;break;
      default:return reject("NUMERIC_RELATION_OPERATOR_UNPROVEN",at);
    }
    ++exactNumericRelations_;
    if(exactNumericRelations_<=16)llvh::outs()<<"[NATIVE_NUMERIC_RELATION] at="<<id(at)
      <<" left="<<a.numberValue<<" right="<<b.numberValue<<" result="<<(result?1:0)
      <<" coercion=0 date_dependent=0 environment=UNPROVEN\n";
    Datum d=make(Primitive,at);d.knownBoolean=true;d.booleanValue=result;return d;
  }
  Datum compareExact(const Datum &a,const Datum &b,BinaryOperatorInst *at) {
    using Op=BinaryOperatorInst::OpKind;
    const auto op=at->getOperatorKind();const char *ta=exactType(a),*tb=exactType(b);
    if(knownObjectReference(a)&&knownObjectReference(b)) {
                                                                                    
      const bool same=a.object==b.object;Datum d=make(Primitive,at);d.knownBoolean=true;
      d.booleanValue=(op==Op::NotEqualKind||op==Op::StrictlyNotEqualKind)?!same:same;
      ++objectComparisons_;return d;
    }
    if(!ta||!tb||!primitive(a)||!primitive(b))return reject("COMPARISON_VALUE_UNPROVEN",at);
    bool eq=false;const bool same=std::string(ta)==tb;
    if(!same && (op==Op::EqualKind||op==Op::NotEqualKind)) {
      if(!((a.kind==Null&&b.kind==Undefined)||(a.kind==Undefined&&b.kind==Null)))return reject("COERCIVE_COMPARISON_UNPROVEN",at);
      eq=true;
    } else if(same) {
      if(a.kind==Undefined||a.kind==Null)eq=true;
      else if(a.knownBoolean&&b.knownBoolean)eq=a.booleanValue==b.booleanValue;
      else if(a.knownNumber&&b.knownNumber)eq=a.numberValue==b.numberValue;
      else eq=a.keyName==b.keyName;
    }
    Datum d=make(Primitive,at);d.knownBoolean=true;
    d.booleanValue=(op==Op::NotEqualKind||op==Op::StrictlyNotEqualKind)?!eq:eq;return d;
  }
  bool source(Instruction *i) const {
    return std::find(sources_.begin(), sources_.end(), i) != sources_.end();
  }
  bool sink(Instruction *i) const {
    return std::find(sinks_.begin(), sinks_.end(), i) != sinks_.end();
  }
  std::string id(Instruction *i) const {
    if(!i)return "NONE";
    auto cached=diagnosticIds_.find(i);if(cached!=diagnosticIds_.end())return cached->second;
    auto *block=i->getParent();if(!block)return "NONE";
    auto *function=block->getParent();auto found=functionIds_.find(function);
    if(found==functionIds_.end())return "NONE";
    uint64_t ordinal=0;
    for(auto &b:*function)for(auto &node:b) {
      if(&node==i) {
        std::string result="F"+std::to_string(found->second)+":I"+std::to_string(ordinal);
        if(diagnosticIds_.size()<1024)diagnosticIds_.emplace(i,result);
        return result;
      }
      ++ordinal;
    }
    return "NONE";
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
               t.crossedReturn == other.crossedReturn && t.throughOwnData == other.throughOwnData;
      })) continue;
      if (t.path.size() >= 256) { reject("PATH_LIMIT", i); return; }
      if (t.path.empty() || t.path.back() != i) t.path.push_back(i);
      unique.push_back(std::move(t));
    }
    if (unique.size() > 16) { reject("TRACE_LIMIT", i); return; }
    d.traces = std::move(unique);
  }
  Datum value(Value *v, Frame &frame, Instruction *use) {
    if (auto *str=llvh::dyn_cast<LiteralString>(v)) { Datum d=make(Primitive);d.keyName="S:"+str->getValue().str().str();return d; }
    if(auto *b=llvh::dyn_cast<LiteralBool>(v)){Datum d=make(Primitive);d.knownBoolean=true;d.booleanValue=b->getValue();return d;}
    if(auto *n=llvh::dyn_cast<LiteralNumber>(v)){Datum d=make(Primitive);d.knownNumber=true;d.numberValue=n->getValue();return d;}
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
    if (name == "Object" && !declaredGlobals_.count(name)) return make(ObjectBuiltin);
    if (name == "Symbol" && !declaredGlobals_.count(name)) return make(SymbolObject);
    if (name == "Date" && !declaredGlobals_.count(name)) return make(DateObject);
    if (name == "document" && !declaredGlobals_.count(name)) return make(AmbientDocument);
    return reject("GLOBAL_READ_UNRESOLVED", at);
  }
  std::string propertyKey(Value *keyValue,Frame &frame,Instruction *at) {
    Datum d=value(keyValue,frame,at);
    if((d.kind==Primitive||d.kind==SymbolKey)&&!d.keyName.empty()&&d.traces.empty())return d.keyName;
    if(d.kind==Primitive&&d.knownNumber&&d.traces.empty()&&std::isfinite(d.numberValue)&&
       d.numberValue>=0&&d.numberValue<=4294967295.0&&std::floor(d.numberValue)==d.numberValue)
      return "S:"+std::to_string(uint64_t(d.numberValue));
    reject("PROPERTY_KEY_IDENTITY_UNPROVEN",at);return "";
  }
  Datum callGetter(Datum getter, Datum receiver, Instruction *at) {
    auto *creation=llvh::dyn_cast_or_null<CreateFunctionInst>(getter.identity);
    if(getter.kind!=Closure||!creation||receiver.kind!=ClassNameObject||!nameObjects_.count(receiver.object))
      return reject("GETTER_FUNCTION_RECEIVER_IDENTITY",at);
    Function *target=creation->getFunctionCode();
    if(active_.count(target)||active_.size()>=8||++invocations_>64)return reject("GETTER_RECURSION_OR_CALL_BOUND",at);
    if(!target->getParameters().empty()||llvh::isa<AsyncFunction>(target)||llvh::isa<GeneratorFunction>(target)||llvh::isa<GeneratorInnerFunction>(target))
      return reject("GETTER_FUNCTION_SHAPE",at);
    if(!getter.environment||!environments_.count(getter.environment)||target->getFunctionScopeDesc()->getParent()!=environments_.at(getter.environment).descriptor)
      return reject("GETTER_CAPTURE_IDENTITY",at);
    Frame child;child.function=target;child.entry=at;child.invocation=invocations_;child.capturedEnvironment=getter.environment;child.receiver=receiver;
    ++getterInvocations_;Datum result=execute(child);
    if(failed_||(!primitive(result)&&result.kind!=Closure&&!knownObjectReference(result)))return reject("GETTER_RETURN_OUTSIDE_PROFILE",at);
    for(auto &trace:result.traces)trace.crossedReturn=true;
    edge(result,at);++returns_;return result;
  }
  Datum defineGetter(StoreGetterSetterInst *store, Frame &frame) {
    Datum object=value(store->getObject(),frame,store),getter=value(store->getStoredGetter(),frame,store),setter=value(store->getStoredSetter(),frame,store);
    const auto k=propertyKey(store->getProperty(),frame,store);
    if(failed_||object.kind!=ClassNameObject||!nameObjects_.count(object.object)||k.compare(0,2,"S:")!=0||k=="S:__proto__"||getter.kind!=Closure||setter.kind!=Undefined)
      return reject("GETTER_DEFINITION_IDENTITY_OR_SETTER",store);
    if(arrayObjects_.count(object.object))return reject("ARRAY_ACCESSOR_DEFINITION_UNPROVEN",store);
    const auto name=k.substr(2);auto &data=nameObjects_.at(object.object);auto &accessors=getters_[object.object];
    if(!reserveOwnProperty(object.object,name,store))return {};
    data.erase(name);accessors[name]=getter;++getterDefinitions_;return make(Undefined);
  }
  Datum freshMember(Datum object, const std::string &k, Instruction *at, unsigned invocation) {
    if(object.kind!=ClassNameObject||!nameObjects_.count(object.object)||k.compare(0,2,"S:")!=0)
      return reject("FRESH_MEMBER_KEY_IDENTITY",at);
    auto accessors=getters_.find(object.object);
    if(accessors!=getters_.end()) {
      auto getter=accessors->second.find(k.substr(2));
      if(getter!=accessors->second.end()){Datum snapshot=getter->second;return callGetter(snapshot,object,at);}
    }
    auto &own=nameObjects_.at(object.object);auto found=own.find(k.substr(2));
                                                                            
    if(found==own.end()) {
      if(nullPrototypeObjects_.count(object.object))return make(Undefined,at);
      return reject("FRESH_PROTOTYPE_FALLBACK_UNPROVEN",at);
    }
    if(arrayObjects_.count(object.object))++arrayReads_;
    if(registeredProperties_[object.object].count(k.substr(2)))++registrationReads_;
    Datum d=found->second;
    if(knownObjectReference(d))++nestedReferenceReads_;
    for(auto &trace:d.traces){trace.throughOwnData=true;if(trace.originInvocation!=invocation)trace.crossedReturn=true;}
    edge(d,at);return d;
  }
  Datum propertyDelete(DeletePropertyInst *del, Frame &frame) {
    Datum object=value(del->getObject(),frame,del);
    const auto k=propertyKey(del->getProperty(),frame,del);
    if(failed_)return {};
    if(k=="S:prototype"||k=="S:__proto__"||k=="S:name"||k=="S:length"||k=="S:caller"||k=="S:arguments")
      return reject("DELETE_RESERVED_OR_DESCRIPTOR_UNPROVEN",del);
    if(object.kind==Closure&&classes_.count(object.object)) {
                                                                            
                                                                              
      classes_.at(object.object).statics.erase(k);classes_.at(object.object).staticSetters.erase(k);
    } else if(object.kind==Closure&&functionOwnData_[object.object].count(k)) {
      functionOwnData_[object.object].erase(k);
    } else if(object.kind==ClassNameObject&&nameObjects_.count(object.object)&&k.compare(0,2,"S:")==0) {
                                                                             
      const auto name=k.substr(2);
      const auto removed=nameObjects_.at(object.object).erase(name)+getters_[object.object].erase(name);
      if(removed>1||removed>ownPropertySlots_)return reject("OWN_PROPERTY_ACCOUNTING",del);
      ownPropertySlots_-=removed;registeredProperties_[object.object].erase(name);
    } else return reject("DELETE_TARGET_IDENTITY_UNPROVEN",del);
    ++propertyDeletes_;
    Datum d=make(Primitive,del);d.knownBoolean=true;d.booleanValue=true;return d;
  }
  Datum propertyRead(LoadPropertyInst *load, Frame &frame) {
    const auto name=key(load->getProperty());Datum object=value(load->getObject(),frame,load);
    if(object.kind==GeneratorRecord && (name=="next" || name=="return")) {
      if(!generators_.count(object.object))return reject("GENERATOR_RECORD_MISSING",load);
      return make(name=="next"?GeneratorNext:GeneratorReturn,load);
    }
    if(object.kind==GeneratorResult) {
      auto it=generatorResults_.find(object.object);
      if(it==generatorResults_.end())return reject("GENERATOR_RESULT_MISSING",load);
      if(name=="value"){Datum d=it->second.first;edge(d,load);return d;}
      if(name=="done"){Datum d=make(Primitive,load);d.knownBoolean=true;d.booleanValue=it->second.second;return d;}
      return reject("GENERATOR_RESULT_KEY_UNPROVEN",load);
    }
    if(object.kind==Closure&&!classes_.count(object.object)) {
      const auto k=propertyKey(load->getProperty(),frame,load);
      if(!failed_&&k=="S:prototype")return functionPrototypeRead(object,load,frame.invocation);
      if(failed_||!functionOwnData_[object.object].count(k))return reject("FUNCTION_PROPERTY_READ_UNPROVEN",load);
      Datum d=functionOwnData_[object.object].at(k);for(auto &trace:d.traces)trace.throughOwnData=true;edge(d,load);return d;
    }
    if(object.kind==Global)return globalRead(name,load);
    if(object.kind==ClassNameObject)return freshMember(object,propertyKey(load->getProperty(),frame,load),load,frame.invocation);
    if(object.kind==ClassInternal) {
      if(name=="defineStaticClassMethod")return make(DefineStatic,load);
      if(superWriteTarget_&&name=="defineClass")return make(DefineClass,load);
      if(superWriteTarget_&&name=="defineClassMethod")return make(DefineMethod,load);
      if(superWriteTarget_&&name=="defineClassPropertySetter")return make(DefineSetter,load);
      if(superWriteTarget_&&name=="defineStaticClassPropertySetter")return make(DefineStaticSetter,load);
    }
    if(object.kind==Closure&&classes_.count(object.object)&&name=="prototype") {
      Datum d=make(ClassPrototype,load);d.object=object.object;return d;
    }
    if(object.kind==ObjectBuiltin&&name=="defineProperty")return make(DefineOwnData,load);
    if(object.kind==DateObject&&name=="now")return make(DateNow,load);
    if(object.kind==SymbolObject&&name=="hasInstance") {
      Datum d=make(SymbolKey,load);d.keyName="Y:Symbol.hasInstance";return d;
    }
    if((object.kind==Closure&&classes_.count(object.object))||object.kind==Instance)
      return classMember(object,propertyKey(load->getProperty(),frame,load),load);
    return reject("PROPERTY_OR_GETTER_UNPROVEN",load);
  }
  Datum propertyStore(StorePropertyInst *store, Frame &frame) {
    const auto name = key(store->getProperty());
    Datum object = value(store->getObject(), frame, store);
    Datum d = value(store->getStoredValue(), frame, store);
    if (failed_) return {};
    if(object.kind==Closure&&!classes_.count(object.object)) {
      const auto k=propertyKey(store->getProperty(),frame,store);
      if(!failed_&&k=="S:prototype")return functionPrototypeWrite(object,d,store);
      if(failed_||k.empty()||!functionOwnData_[object.object].count(k)) {
        llvh::outs()<<"[FUNCTION_PROPERTY_WRITE_EVIDENCE] write="<<id(store)<<" target="<<id(object.identity)
          <<" object_id="<<object.object<<" key="<<k<<" value="<<id(d.identity)
          <<" own_writable_data=UNPROVEN prototype_setter=UNPROVEN environment=UNPROVEN\n";
        return reject("FUNCTION_WRITE_OWN_DESCRIPTOR_OR_PROTOTYPE_UNPROVEN",store);
      }
      if(!primitive(d)&&d.kind!=Closure)return reject("FUNCTION_OWN_WRITE_VALUE_UNPROVEN",store);
      edge(d,store);functionOwnData_[object.object][k]=d;return make(Undefined);
    }
    if (object.kind == Global) {
                                                                               
                                                                               
                                                                         
      if (frame.function != global_ || !declaredGlobals_.count(name) || name.empty() ||
          name == "Object" || name == "Symbol" || name == "Date" || name == "document" || name == "HermesES6Internal" || name == "__proto__" ||
          (!primitive(d) && d.kind != Closure)) return reject("GLOBAL_WRITE_OUTSIDE_PROFILE", store);
      edge(d, store); globals_[name] = d; return make(Undefined);
    }
    if(arrayObjects_.count(object.object)&&object.kind==ClassNameObject)
      return arrayWrite(object,propertyKey(store->getProperty(),frame,store),d,store,false);
    if(object.kind==ClassNameObject&&nameObjects_.count(object.object)) {
      const auto k=propertyKey(store->getProperty(),frame,store);
      if(failed_||k.compare(0,2,"S:")!=0||k=="S:__proto__"||(!primitive(d)&&d.kind!=Closure&&d.kind!=SymbolKey&&!knownObjectReference(d)))
        return reject("FRESH_WRITE_OWN_DATA_UNPROVEN",store);
      const auto name=k.substr(2);auto &own=nameObjects_.at(object.object);
      if(!own.count(name)) {
        if(getters_[object.object].count(name))return reject("REGISTRATION_OWN_ACCESSOR",store);
        auto *creation=llvh::dyn_cast_or_null<CreateFunctionInst>(d.identity);
        if(d.kind!=Closure||!creation||!d.object||!d.environment||!environments_.count(d.environment)||
           creation->getFunctionCode()->getFunctionScopeDesc()->getParent()!=environments_.at(d.environment).descriptor)
          return reject("REGISTRATION_CLOSURE_IDENTITY",store);
        ++registrationAttempts_;
        const bool nullPrototype=nullPrototypeObjects_.count(object.object);
        if(registrationAttempts_<=16)llvh::outs()<<"[NATIVE_PROPERTY_REGISTRATION] write="<<id(store)<<" target="<<id(object.identity)
          <<" object_id="<<object.object<<" key="<<k<<" closure="<<id(d.identity)<<" function_id="<<d.object
          <<" captured_environment="<<d.environment<<" prototype="<<(nullPrototype?"NULL":"UNPROVEN")<<" invoked=0\n";
                                                                           
                                                                                      
        if(!nullPrototype)return reject("REGISTRATION_PROTOTYPE_UNPROVEN",store);
        if(!reserveOwnProperty(object.object,name,store))return {};
        registeredProperties_[object.object].insert(name);++registrations_;
      }
      if(knownObjectReference(d))++nestedReferenceWrites_;
      edge(d,store);own[name]=d;return make(Undefined);
    }
    if(object.kind==Closure&&classes_.count(object.object)) {
      const auto k=propertyKey(store->getProperty(),frame,store);
      if(failed_||d.kind!=Closure||!classes_[object.object].statics.count(k)||k=="S:prototype"||k=="S:__proto__"||k=="S:caller"||k=="S:arguments")return reject("CLASS_OWN_WRITE_IDENTITY",store);
      edge(d,store);classes_[object.object].statics[k]=d;return make(Undefined);
    }
    if(object.kind==Instance && instanceClass_.count(object.object)) {
      const auto k=propertyKey(store->getProperty(),frame,store);
                                                                                 
      if(failed_||!instanceFields_[object.object].count(k)||(!primitive(d)&&!knownClosureIdentity(d)))return reject("INSTANCE_WRITE_OWN_FIELD_UNPROVEN",store);
      edge(d,store);instanceFields_[object.object][k]=d;return make(Undefined);
    }
    if (object.kind != AmbientDocument || name != "cookie" || !sink(store) || !primitive(d))
      return reject("PROPERTY_EFFECT_OUTSIDE_PROFILE", store);
    edge(d, store);
    executedSinks_.insert(store);
    for (auto &trace : d.traces) {
      if(source(trace.source)&&!trace.path.empty()&&trace.path.front()==trace.source) {
        if(observedPairs_.size()>=256&&!observedPairs_.count({trace.source,store}))return reject("OBSERVED_PATH_LIMIT",store);
        observedPairs_.insert({trace.source,store});
      }
      if ((!trace.crossedReturn && !frame.generatorBody && !trace.throughOwnData) || !source(trace.source) || trace.path.empty() || trace.path.front() != trace.source) continue;
      if (pending_.size() >= 256) return reject("PENDING_PATH_LIMIT", store);
      pending_.emplace_back(trace.source, trace.path, store);
    }
    return make(Undefined);
  }
  struct ClassState {
    unsigned base{0};
    std::map<std::string,Datum> statics, methods, setters, staticSetters;
  };
  std::map<unsigned,ClassState> classes_;
  std::map<unsigned,Datum> classConstructors_;
  std::map<unsigned,std::vector<Datum>> constructorArguments_;
  unsigned setterInvocations_{0};
  bool superWriteTarget_{false};
  std::map<unsigned,std::map<std::string,Datum>> nameObjects_, getters_;
  std::set<unsigned> nullPrototypeObjects_;
  std::map<unsigned,std::set<std::string>> registeredProperties_;
  std::map<unsigned,unsigned> instanceClass_;
  unsigned nextObject_{1}, classDefinitions_{0}, methodDefinitions_{0}, classCalls_{0};
  Datum classMember(Datum object, const std::string &name, Instruction *at) {
    bool instance=object.kind==Instance;
    if(instance && instanceFields_[object.object].count(name)) {
      Datum d=instanceFields_[object.object].at(name);edge(d,at);return d;
    }
    unsigned id=instance?(instanceClass_.count(object.object)?instanceClass_.at(object.object):0):object.object;
    for(unsigned n=0;id&&n<32;++n) {
      auto c=classes_.find(id);if(c==classes_.end())break;
      auto &accessors=instance?c->second.setters:c->second.staticSetters;
      if(accessors.count(name))return make(Undefined);                                
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
      ClassState c;c.base=base.kind==Null?0:base.object;classes_[ctor.object]=c;classConstructors_[ctor.object]=ctor;++classDefinitions_;
    }else{
      if(!classes_.count(ctor.object))return reject("CLASS_BEFORE_DEFINITION",call);
      const auto name=propertyKey(call->getArgument(2),caller,call);Datum method=value(call->getArgument(3),caller,call);
      if(failed_||name.empty()||name=="S:__proto__"||name=="S:prototype"||method.kind!=Closure||!method.object)
        return reject("CLASS_METHOD_DEFINITION_SHAPE",call);
      bool isStatic=kind==DefineStatic||kind==DefineStaticSetter;
      auto &data=isStatic?classes_[ctor.object].statics:classes_[ctor.object].methods;
      auto &setters=isStatic?classes_[ctor.object].staticSetters:classes_[ctor.object].setters;
      if(kind==DefineSetter||kind==DefineStaticSetter){data.erase(name);setters[name]=method;}
      else {setters.erase(name);data[name]=method;}
      ++methodDefinitions_;
    }
    return make(Undefined);
  }
                                                                             
  Datum constructKnown(Datum ctor, Datum nt, const std::vector<Datum> &args, Instruction *at) {
    auto *create=llvh::dyn_cast_or_null<CreateFunctionInst>(ctor.identity);
    if(!knownClosureIdentity(ctor)||!create||!classes_.count(ctor.object)||
       !knownClosureIdentity(nt)||!classes_.count(nt.object))return reject("CONSTRUCTOR_IDENTITIES",at);
    unsigned ancestor=nt.object;bool related=false;
    for(unsigned n=0;ancestor&&n<32;++n){if(ancestor==ctor.object){related=true;break;}ancestor=classes_.at(ancestor).base;}
    if(!related)return reject("CONSTRUCTOR_NEWTARGET_CHAIN",at);
    Function *target=create->getFunctionCode();
    if(active_.count(target)||active_.size()>=8||++invocations_>64||nextObject_>512||args.size()>16)
      return reject("CLASS_CONSTRUCT_BOUND",at);
    if(llvh::isa<AsyncFunction>(target)||llvh::isa<GeneratorFunction>(target)||llvh::isa<GeneratorInnerFunction>(target))
      return reject("CONSTRUCTOR_FUNCTION_SHAPE",at);
    const bool derived=classes_.at(ctor.object).base!=0;
    Datum receiver=make(Undefined);
    if(!derived){receiver=make(Instance,at);receiver.object=nextObject_++;instanceClass_[receiver.object]=nt.object;}
    Frame child;child.function=target;child.entry=at;child.invocation=invocations_;child.capturedEnvironment=ctor.environment;
    child.receiver=receiver;child.newTarget=nt;child.constructing=true;child.arguments=args;
    Datum result=execute(child);if(failed_)return {};
    if(derived){if(result.kind!=Instance||!instanceClass_.count(result.object)||instanceClass_.at(result.object)!=nt.object)return reject("DERIVED_CONSTRUCTOR_RETURN",at);receiver=result;}
    else if(result.kind!=Undefined)return reject("BASE_CONSTRUCTOR_RETURN_OUTSIDE_PROFILE",at);
    ++classCalls_;return receiver;
  }
  Datum constructClass(ConstructInst *call, Frame &caller) {
    Datum ctor=value(call->getConstructor(),caller,call),nt=value(call->getNewTarget(),caller,call);
    if(ctor.kind!=Closure||nt.kind!=Closure||ctor.object!=nt.object)return reject("CONSTRUCT_NEWTARGET_UNPROVEN",call);
    std::vector<Datum> args;
    if(call->getNumArguments()>17)return reject("CONSTRUCTOR_ARGUMENT_BOUND",call);
    for(unsigned n=1;n<call->getNumArguments();++n){Datum d=value(call->getArgument(n),caller,call);if(!primitive(d))return reject("CLASS_CONSTRUCT_ARGUMENT",call);edge(d,call);args.push_back(d);}
    return constructKnown(ctor,nt,args,call);
  }
  Datum superSetter(CallBuiltinInst *call, Frame &caller) {
    Datum home=value(call->getArgument(1),caller,call),receiver=value(call->getArgument(3),caller,call),actual=value(call->getArgument(4),caller,call);
    const auto k=propertyKey(call->getArgument(2),caller,call);
    bool instance=home.kind==ClassPrototype;
    if(failed_||(!instance&&home.kind!=Closure)||!classes_.count(home.object)||!primitive(actual)||
       (instance?(receiver.kind!=Instance||!instanceClass_.count(receiver.object)):(receiver.kind!=Closure||!classes_.count(receiver.object))))
      return reject("SUPER_SET_IDENTITIES",call);
    unsigned base=classes_.at(home.object).base;Datum setter;
    for(unsigned n=0;base&&n<32;++n) {
      auto &c=classes_.at(base);auto &data=instance?c.methods:c.statics;auto &accessors=instance?c.setters:c.staticSetters;
      if(data.count(k))return reject("SUPER_SET_DATA_DESCRIPTOR_OUTSIDE_PROFILE",call);
      if(accessors.count(k)){setter=accessors.at(k);break;}base=c.base;
    }
    if(!knownClosureIdentity(setter))return reject("SUPER_SETTER_OR_PROTOTYPE_UNPROVEN",call);
    auto *target=llvh::cast<CreateFunctionInst>(setter.identity)->getFunctionCode();
    if(target->getParameters().size()!=1||llvh::isa<AsyncFunction>(target)||llvh::isa<GeneratorFunction>(target)||llvh::isa<GeneratorInnerFunction>(target))return reject("SETTER_FUNCTION_SHAPE",call);
    if(active_.count(target)||active_.size()>=8||++invocations_>64)return reject("SETTER_CALL_BOUND",call);
                                                                                
    Datum passed=actual;for(auto &trace:passed.traces)trace.crossedReturn=true;edge(passed,call);
    Frame child;child.function=target;child.entry=call;child.invocation=invocations_;child.capturedEnvironment=setter.environment;child.receiver=receiver;child.arguments.push_back(passed);
    ++setterInvocations_;execute(child);if(failed_)return {};
    llvh::outs()<<"[NATIVE_SUPER_SETTER] call="<<id(call)<<" home="<<home.object<<" receiver="<<receiver.object<<" key="<<k<<" setter="<<setter.object<<" captured_environment="<<setter.environment<<" environment=UNPROVEN\n";
    edge(actual,call);return actual;
  }

                                                                             
  std::set<unsigned> privateTokens_;
  std::map<std::pair<unsigned,unsigned>,Datum> privateSlots_;
  Datum classBuiltin(CallBuiltinInst *call, Frame &caller) {
    const auto op=call->getBuiltinIndex();
    if(!call->getNumArguments())return reject("CLASS_BUILTIN_ARITY",call);
    if(!llvh::isa<LiteralUndefined>(call->getArgument(0)))return reject("CLASS_BUILTIN_RECEIVER",call);
    if(op==BuiltinMethod::HermesBuiltin_privateNameCreate&&call->getNumArguments()==1) {
      if(nextObject_>512)return reject("PRIVATE_TOKEN_BOUND",call);
      Datum token=make(PrivateToken,call);token.object=nextObject_++;
      privateTokens_.insert(token.object);return token;
    }
    if(op==BuiltinMethod::HermesBuiltin_privateFieldInit||op==BuiltinMethod::HermesBuiltin_privateFieldGet||op==BuiltinMethod::HermesBuiltin_privateFieldSet) {
      const bool get=op==BuiltinMethod::HermesBuiltin_privateFieldGet;
      const bool init=op==BuiltinMethod::HermesBuiltin_privateFieldInit;
      if(call->getNumArguments()!=(get?3:4))return reject("PRIVATE_SLOT_ARITY",call);
      Datum receiver=value(call->getArgument(1),caller,call),token=value(call->getArgument(2),caller,call);
      if(failed_||receiver.kind!=Instance||!instanceClass_.count(receiver.object)||token.kind!=PrivateToken||!privateTokens_.count(token.object))return reject("PRIVATE_SLOT_IDENTITY",call);
      const auto key=std::make_pair(token.object,receiver.object);
      const auto found=privateSlots_.find(key);
      if(init?(found!=privateSlots_.end()):(found==privateSlots_.end()))return reject("PRIVATE_BRAND_OR_REINITIALIZATION",call);
      if(get){Datum d=found->second;edge(d,call);return d;}
      Datum d=value(call->getArgument(3),caller,call);
      if(failed_||(!primitive(d)&&!knownClosureIdentity(d)))return reject("PRIVATE_SLOT_VALUE_UNPROVEN",call);
      if(init&&privateSlots_.size()>=4096)return reject("PRIVATE_SLOT_BOUND",call);
      edge(d,call);privateSlots_[key]=d;
      return init?make(Undefined):d;
    }
    if(op==BuiltinMethod::HermesBuiltin_namePublicFieldFunction&&call->getNumArguments()==3) {
      Datum key=value(call->getArgument(1),caller,call),fn=value(call->getArgument(2),caller,call);
      if(failed_||key.kind!=Primitive||key.keyName.compare(0,2,"S:")!=0||!key.traces.empty()||!knownClosureIdentity(fn))return reject("FUNCTION_NAME_INPUT_UNPROVEN",call);
                                                                              
                                                                                
      return fn;
    }
    if(op==BuiltinMethod::HermesBuiltin_initBaseClass&&call->getNumArguments()==2) {
      Datum ctor=value(call->getArgument(1),caller,call);
      auto *create=llvh::dyn_cast_or_null<CreateFunctionInst>(ctor.identity);
      if(ctor.kind!=Closure||!ctor.object||!create||classes_.count(ctor.object))return reject("NATIVE_BASE_IDENTITY",call);
      classes_[ctor.object]=ClassState{};classConstructors_[ctor.object]=ctor;++classDefinitions_;++nativeDefinitions_;return make(Undefined);
    }
    if(op==BuiltinMethod::HermesBuiltin_classElementKey&&call->getNumArguments()==2) {
      Datum d=value(call->getArgument(1),caller,call);
      if((d.kind!=Primitive&&d.kind!=SymbolKey)||d.keyName.empty()||!d.traces.empty())return reject("NATIVE_KEY_COERCION_UNPROVEN",call);
      return d;
    }
    if((op==BuiltinMethod::HermesBuiltin_defineStaticClassMethod||op==BuiltinMethod::HermesBuiltin_defineInstanceClassMethod)&&call->getNumArguments()==4) {
      Datum ctor=value(call->getArgument(1),caller,call),method=value(call->getArgument(3),caller,call);
      const auto k=propertyKey(call->getArgument(2),caller,call);
      if(failed_||ctor.kind!=Closure||!classes_.count(ctor.object)||method.kind!=Closure||!method.object||k=="S:prototype"||k=="S:__proto__")return reject("NATIVE_METHOD_IDENTITIES",call);
      auto &table=op==BuiltinMethod::HermesBuiltin_defineStaticClassMethod?classes_[ctor.object].statics:classes_[ctor.object].methods;
      (op==BuiltinMethod::HermesBuiltin_defineStaticClassMethod?classes_[ctor.object].staticSetters:classes_[ctor.object].setters).erase(k);
      table[k]=method;++methodDefinitions_;return make(Undefined);
    }
    if((op==BuiltinMethod::HermesBuiltin_definePublicClassField||op==BuiltinMethod::HermesBuiltin_definePublicInstanceClassField)&&call->getNumArguments()==4) {
      Datum object=value(call->getArgument(1),caller,call),d=value(call->getArgument(3),caller,call);
      const auto k=propertyKey(call->getArgument(2),caller,call);
      if(failed_||k.empty()||k=="S:__proto__"||k=="S:prototype"||(!primitive(d)&&d.kind!=Closure))return reject("PUBLIC_FIELD_VALUE_OR_KEY",call);
      edge(d,call);
      if(object.kind==Closure&&classes_.count(object.object)){classes_[object.object].staticSetters.erase(k);classes_[object.object].statics[k]=d;}
      else if(object.kind==Instance&&instanceClass_.count(object.object))instanceFields_[object.object][k]=d;
      else return reject("PUBLIC_FIELD_TARGET_UNPROVEN",call);
      return make(Undefined);
    }
    if(op==BuiltinMethod::HermesBuiltin_superPropertyGet&&call->getNumArguments()==5)return superSetter(call,caller);
    if(op==BuiltinMethod::HermesBuiltin_getSuperConstructor&&call->getNumArguments()==2){
      Datum ctor=value(call->getArgument(1),caller,call);
      if(!caller.constructing||!knownClosureIdentity(ctor)||!classes_.count(ctor.object)||
         llvh::cast<CreateFunctionInst>(ctor.identity)->getFunctionCode()!=caller.function||!classes_.at(ctor.object).base)
        return reject("SUPER_CONSTRUCTOR_IDENTITY",call);
      return classConstructors_.at(classes_.at(ctor.object).base);
    }
    if(op==BuiltinMethod::HermesBuiltin_constructWithNewTarget&&call->getNumArguments()==4){
      Datum ctor=value(call->getArgument(1),caller,call),args=value(call->getArgument(2),caller,call),nt=value(call->getArgument(3),caller,call);
      if(!caller.constructing||args.kind!=ConstructorArguments||args.environment!=caller.invocation||!constructorArguments_.count(args.object)||nt.kind!=Closure||nt.object!=caller.newTarget.object)
        return reject("SUPER_ARGUMENTS_SNAPSHOT_UNPROVEN",call);
      return constructKnown(ctor,nt,constructorArguments_.at(args.object),call);
    }
    if(op==BuiltinMethod::HermesBuiltin_assertDerivedUninitialized&&call->getNumArguments()==2){
      if(!caller.constructing||value(call->getArgument(1),caller,call).kind!=Undefined)return reject("DERIVED_THIS_ALREADY_INITIALIZED",call);
      return make(Undefined);
    }
    if(op==BuiltinMethod::HermesBuiltin_derivedConstructorReturn&&call->getNumArguments()==3){
      Datum receiver=value(call->getArgument(1),caller,call),returned=value(call->getArgument(2),caller,call);
      if(!caller.constructing||returned.kind!=Undefined||receiver.kind!=Instance)return reject("DERIVED_RETURN_UNPROVEN",call);
      return receiver;
    }
    if(op==BuiltinMethod::HermesBuiltin_superPropertyGet&&call->getNumArguments()==4) {
      Datum home=value(call->getArgument(1),caller,call),receiver=value(call->getArgument(3),caller,call);
      const auto k=propertyKey(call->getArgument(2),caller,call);
      if(failed_||home.kind!=Closure||!classes_.count(home.object)||classes_.at(home.object).base||(receiver.kind!=Undefined&&(receiver.kind!=Closure||!classes_.count(receiver.object)))||k!="Y:Symbol.hasInstance")return reject("SUPER_HOME_KEY_RECEIVER_UNPROVEN",call);
      Datum d=make(HasInstanceBuiltin,call);d.object=home.object;return d;
    }
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
      ClassState c;c.base=base.object;classes_[ctor.object]=c;classConstructors_[ctor.object]=ctor;++classDefinitions_;return make(Undefined);
    }
    return reject("CLASS_BUILTIN_OUTSIDE_PROFILE",call);
  }
  Datum invoke(CallInst *call, Frame &caller) {
    if(auto *b=llvh::dyn_cast<CallBuiltinInst>(call))return classBuiltin(b,caller);
    if(auto *c=llvh::dyn_cast<ConstructInst>(call))return constructClass(c,caller);
    if (llvh::isa<ConstructInst>(call) || llvh::isa<CallBuiltinInst>(call) || call->getNumArguments() < 1)
      return reject("NON_ORDINARY_CALL", call);
    Datum callee = value(call->getCallee(), caller, call);
    if(callee.kind==GeneratorNext||callee.kind==GeneratorReturn) {
      Datum receiver=value(call->getArgument(0),caller,call);
      if(receiver.kind!=GeneratorRecord||!generators_.count(receiver.object)||call->getNumArguments()>2)return reject("GENERATOR_RESUME_RECEIVER_OR_ARITY",call);
      Frame &body=generators_.at(receiver.object);
      if(active_.count(body.function)||active_.size()>=8||++generatorAdvances_>64)return reject("GENERATOR_RESUME_BOUND",call);
      Datum sent=call->getNumArguments()==2?value(call->getArgument(1),caller,call):make(Undefined);
      if(!primitive(sent))return reject("GENERATOR_RESUME_VALUE",call);
      bool first=!body.resumeBlock;
      body.returnRequested=callee.kind==GeneratorReturn;
      if(body.returnRequested)++generatorCloses_;
      body.resumeValue=first?make(Undefined):sent;
      Datum yielded;
      if(body.completed||(first&&body.returnRequested)){body.completed=true;yielded=body.returnRequested?sent:make(Undefined);}
      else {body.suspended=false;yielded=execute(body);}
      if(failed_||!primitive(yielded)||nextObject_>512)return reject("GENERATOR_RESUME_UNPROVEN",call);
      for(auto &t:yielded.traces)t.crossedReturn=true;
      edge(yielded,call);
      Datum result=make(GeneratorResult,call);result.object=nextObject_++;
      generatorResults_[result.object]={yielded,body.completed};return result;
    }
    if(callee.kind==DefineStatic||callee.kind==DefineClass||callee.kind==DefineMethod||callee.kind==DefineSetter||callee.kind==DefineStaticSetter)return classHelper(call,caller,callee.kind);
    if(callee.kind==DefineOwnData) {
      if(call->getNumArguments()!=4||value(call->getArgument(0),caller,call).kind!=ObjectBuiltin)return reject("DESCRIPTOR_BUILTIN_RECEIVER_ARITY",call);
      Datum target=value(call->getArgument(1),caller,call),desc=value(call->getArgument(3),caller,call);
      const auto k=propertyKey(call->getArgument(2),caller,call);
      if(failed_||target.kind!=Closure||!target.object||desc.kind!=ClassNameObject||!nameObjects_.count(desc.object)||k=="S:prototype"||k=="S:__proto__"||k=="S:caller"||k=="S:arguments"||k=="S:name"||k=="S:length")return reject("DESCRIPTOR_TARGET_KEY_IDENTITY",call);
      if(!getters_[desc.object].empty())return reject("DESCRIPTOR_ACCESSOR_EFFECT_UNPROVEN",call);
      const auto &fields=nameObjects_.at(desc.object);
      if(fields.size()!=4||!fields.count("value")||(!primitive(fields.at("value"))&&fields.at("value").kind!=Closure))return reject("DESCRIPTOR_NOT_EXPLICIT_DATA_METHOD",call);
      for(const auto &flag:{"writable","enumerable","configurable"}) {
        auto it=fields.find(flag);
        if(it==fields.end()||!it->second.knownBoolean||!it->second.booleanValue||!it->second.traces.empty())return reject("DESCRIPTOR_ATTRIBUTES_UNPROVEN",call);
      }
      Datum fn=fields.at("value");edge(fn,call);
      if(classes_.count(target.object)) {
        if(fn.kind!=Closure)return reject("CLASS_DESCRIPTOR_VALUE_OUTSIDE_PROFILE",call);
        classes_[target.object].staticSetters.erase(k);classes_[target.object].statics[k]=fn;
      } else {
        if(functionOwnData_[target.object].size()>=8&&!functionOwnData_[target.object].count(k))return reject("FUNCTION_OWN_PROPERTY_LIMIT",call);
        functionOwnData_[target.object][k]=fn;
      }
      return target;
    }
    if(callee.kind==HasInstanceBuiltin) {
      if(call->getNumArguments()!=2)return reject("HAS_INSTANCE_ARITY",call);
      Datum receiver=value(call->getArgument(0),caller,call),arg=value(call->getArgument(1),caller,call);
                                                                             
                                                                             
      if(receiver.kind==Undefined){Datum d=make(Primitive,call);d.knownBoolean=true;d.booleanValue=false;return d;}
      if(receiver.kind!=Closure||!classes_.count(receiver.object)||(!primitive(arg)&&arg.kind!=ClassNameObject))return reject("HAS_INSTANCE_RECEIVER_ARGUMENT",call);
      if(arg.kind==ClassNameObject&&(!nameObjects_.count(arg.object)||(!nameObjects_.at(arg.object).empty()||!getters_[arg.object].empty())))return reject("HAS_INSTANCE_OBJECT_EFFECT",call);
      return make(Primitive);
    }
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
    if(!knownClosureIdentity(callee))return reject("CLOSURE_CREATION_CAPTURE_IDENTITY_UNPROVEN",call);
    if(passedClosureIds_.count(callee.object))++callsOfPassedClosures_;
    auto *creation = llvh::dyn_cast<CreateFunctionInst>(callee.identity);
    if (!creation) return reject("CLOSURE_IDENTITY_MISSING", call);
    Function *target = creation->getFunctionCode();
    if (classes_.count(callee.object) || target->getDefinitionKind() == Function::DefinitionKind::ES6Constructor)
      return reject("CLASS_CONSTRUCTOR_REQUIRES_NEW", call);
    if (active_.count(target)) return reject("RECURSIVE_CALL", call);
    if (active_.size() >= 8 || ++invocations_ > 64) return reject("CALL_BOUND", call);
    if (llvh::isa<AsyncFunction>(target) || llvh::isa<GeneratorInnerFunction>(target) ||
        target->getDefinitionKind()==Function::DefinitionKind::ES6AsyncGenerator) return reject("ASYNC_OR_DIRECT_GENERATOR_BODY_CALL", call);
    Datum receiver=value(call->getArgument(0),caller,call);
    if(receiver.kind!=Undefined){
                                                                              
                                                                             
      if(!((receiver.kind==Closure&&receiver.object)||receiver.kind==Instance||receiver.kind==ClassNameObject))
        return reject("CLASS_CALL_RECEIVER_UNRESOLVED",call);
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
      if(actual.kind==Closure) {
        if(!knownClosureIdentity(actual))return reject("ARGUMENT_CLOSURE_IDENTITY_UNPROVEN",call);
        ++closureArgumentEdges_;passedClosureIds_.insert(actual.object);
        if(closureArgumentEdges_<=16)llvh::outs()<<"[NATIVE_CLOSURE_ARGUMENT] call="<<id(call)
          <<" argument="<<n<<" creation="<<id(actual.identity)<<" closure_id="<<actual.object
          <<" captured_environment="<<actual.environment<<" snapshot_identity=1 live_capture=1 environment=UNPROVEN\n";
      } else if(!primitive(actual)&&!knownObjectReference(actual))return reject("NON_PRIMITIVE_ARGUMENT",call);
                                                                              
                                                                               
      edge(actual, call); argumentEdges_ += actual.traces.size(); child.arguments.push_back(std::move(actual));
    }
    Datum returned = execute(child);
    if (failed_ || (!primitive(returned)&&returned.kind!=Closure&&returned.kind!=Instance&&returned.kind!=GeneratorRecord&&returned.kind!=GeneratorResult&&!knownObjectReference(returned))) return reject("NON_PRIMITIVE_RETURN", call);
    for (auto &trace : returned.traces) trace.crossedReturn = true;
    edge(returned, call); ++returns_;
    return returned;
  }
  Datum instruction(Instruction *i, Frame &frame) {
    if (++steps_ > 20000) return reject("PROOF_STEP_LIMIT", i);
    if(llvh::isa<ThrowIfHasRestrictedGlobalPropertyInst>(i)) {
      if(frame.function!=global_)return reject("ENTRY_GUARD_OUTSIDE_GLOBAL",i);
      ++normalEntryGuards_;return make(Undefined);
    }
    if(auto *alloc=llvh::dyn_cast<AllocArrayInst>(i))return allocateArray(alloc,frame);
    if(auto *alloc=llvh::dyn_cast<AllocObjectInst>(i)){
      if((!llvh::isa<EmptySentinel>(alloc->getParentObject())&&!llvh::isa<LiteralNull>(alloc->getParentObject()))||nextObject_>512)
        return reject("CLASS_NAME_OBJECT_SHAPE",i);
      Datum d=make(ClassNameObject,i);d.object=nextObject_++;nameObjects_[d.object]={};if(llvh::isa<LiteralNull>(alloc->getParentObject()))nullPrototypeObjects_.insert(d.object);return d;
    }
    if(auto *getter=llvh::dyn_cast<StoreGetterSetterInst>(i))return defineGetter(getter,frame);
    if(auto *store=llvh::dyn_cast<StoreOwnPropertyInst>(i)){
      Datum object=value(store->getObject(),frame,store),d=value(store->getStoredValue(),frame,store);
      if(arrayObjects_.count(object.object)&&object.kind==ClassNameObject)
        return arrayWrite(object,propertyKey(store->getProperty(),frame,store),d,store,true);
      const auto name=key(store->getProperty());
      if(object.kind!=ClassNameObject||!nameObjects_.count(object.object)||name.empty()||name=="__proto__"||(!primitive(d)&&d.kind!=Closure&&d.kind!=SymbolKey&&!knownObjectReference(d)))
        return reject("FRESH_OWN_DATA_DEFINITION",store);
      if(!reserveOwnProperty(object.object,name,store))return {};
      if(knownObjectReference(d))++nestedReferenceWrites_;
      edge(d,store);getters_[object.object].erase(name);nameObjects_[object.object][name]=d;return make(Undefined);
    }
    if(llvh::isa<GetNewTargetInst>(i)){
      if(frame.constructing)return frame.newTarget;
      return make(Undefined);
    }
    if(llvh::isa<CreateArgumentsInst>(i)) {
                                                                              
                                                                            
      if(!frame.constructing||frame.arguments.size()>16||nextObject_>512)return reject("CONSTRUCTOR_ARGUMENTS_PROFILE",i);
      Datum d=make(ConstructorArguments,i);d.object=nextObject_++;d.environment=frame.invocation;constructorArguments_[d.object]=frame.arguments;return d;
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
                                                                         
      return newEnvironment(inner->getCreatedScopeDesc(), parent.environment, frame.invocation, inner,!frame.generatorBody);
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
      if (!primitive(d) && d.kind != Closure && d.kind != Instance && d.kind != ClassPrototype && d.kind != Empty && d.kind != SymbolKey && d.kind != Global && d.kind != ClassNameObject && d.kind != GeneratorRecord && d.kind != GeneratorResult && d.kind != GeneratorNext && d.kind != GeneratorReturn && !(d.kind == PrivateToken && privateTokens_.count(d.object)))
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
    if(auto *create=llvh::dyn_cast<CreateGeneratorInst>(i)) {
      Datum scope=value(create->getEnvironment(),frame,create);
      auto *inner=create->getFunctionCode();
      if(!llvh::isa<GeneratorFunction>(frame.function)||!llvh::isa<GeneratorInnerFunction>(inner)||scope.kind!=Scope||!environments_.count(scope.environment)||inner->getFunctionScopeDesc()->getParent()!=environments_.at(scope.environment).descriptor||nextObject_>512||++invocations_>64)
        return reject("GENERATOR_CREATION_IDENTITY_OR_BOUND",create);
      Frame body;body.function=inner;body.entry=frame.entry;body.invocation=invocations_;body.capturedEnvironment=scope.environment;
      body.receiver=frame.receiver;body.arguments=frame.arguments;body.generatorBody=true;body.resumeValue=make(Undefined);
      Datum d=make(GeneratorRecord,create);d.object=nextObject_++;generators_.emplace(d.object,std::move(body));++generatorCreated_;return d;
    }
    if(llvh::isa<StartGeneratorInst>(i)) {
      if(!frame.generatorBody)return reject("GENERATOR_START_OUTSIDE_BODY",i);
      return make(Undefined);
    }
    if(auto *resume=llvh::dyn_cast<ResumeGeneratorInst>(i)) {
      auto *slot=llvh::dyn_cast<AllocStackInst>(resume->getIsReturn());
      if(!frame.generatorBody||!slot||!frame.stack.count(slot))return reject("GENERATOR_RESUME_SLOT",i);
      Datum flag=make(Primitive,i);flag.knownBoolean=true;flag.booleanValue=frame.returnRequested;frame.stack[slot]=flag;
      Datum d=frame.resumeValue;edge(d,i);return d;
    }
    if (auto *c = llvh::dyn_cast<CreateFunctionInst>(i)) {
      Datum scope = value(c->getEnvironment(), frame, c);
      if (scope.kind != Scope || !environments_.count(scope.environment) ||
          c->getFunctionCode()->getFunctionScopeDesc()->getParent() != environments_.at(scope.environment).descriptor)
        return reject("CLOSURE_ENVIRONMENT_UNPROVEN", c);
      Datum d = make(Closure, c); d.environment = scope.environment;if(nextObject_>512)return reject("CLASS_OBJECT_LIMIT",c);d.object=nextObject_++;closureIdentities_[d.object]={c,d.environment}; return d;
    }
    if (auto *del = llvh::dyn_cast<DeletePropertyInst>(i)) return propertyDelete(del, frame);
    if (auto *l = llvh::dyn_cast<LoadPropertyInst>(i)) return propertyRead(l, frame);
    if (auto *s = llvh::dyn_cast<StorePropertyInst>(i)) return propertyStore(s, frame);
    if (auto *c = llvh::dyn_cast<CallInst>(i)) return invoke(c, frame);
    if (auto *b = llvh::dyn_cast<BinaryOperatorInst>(i)) {
      Datum left = value(b->getLeftHandSide(), frame, b), right = value(b->getRightHandSide(), frame, b);
      using Op=BinaryOperatorInst::OpKind;auto op=b->getOperatorKind();
      if(op==Op::EqualKind||op==Op::NotEqualKind||op==Op::StrictlyEqualKind||op==Op::StrictlyNotEqualKind)return compareExact(left,right,b);
      if(op==Op::LessThanKind||op==Op::LessThanOrEqualKind||op==Op::GreaterThanKind||op==Op::GreaterThanOrEqualKind)
        return compareNumeric(left,right,b);
      if (!primitive(left) || !primitive(right) || b->getOperatorKind() != BinaryOperatorInst::OpKind::AddKind)
        return reject("PRIMITIVE_ADD_UNPROVEN", b);
      Datum d = make(Primitive); d.traces = left.traces;
      d.traces.insert(d.traces.end(), right.traces.begin(), right.traces.end()); edge(d, b); return d;
    }
    if (auto *m = llvh::dyn_cast<MovInst>(i)) { Datum d = value(m->getSingleOperand(), frame, m); edge(d, m); return d; }
    if (auto *u = llvh::dyn_cast<UnaryOperatorInst>(i)) {
      if (u->getOperatorKind() == UnaryOperatorInst::OpKind::VoidKind) { value(u->getSingleOperand(), frame, u); return make(Undefined); }
      if(u->getOperatorKind()==UnaryOperatorInst::OpKind::BangKind){
        Datum input=value(u->getSingleOperand(),frame,u);bool selected;
        if(failed_||!truth(input,selected))return reject("BOOLEAN_VALUE_UNPROVEN",u);
        Datum d=make(Primitive,u);d.knownBoolean=true;d.booleanValue=!selected;return d;
      }
      if(u->getOperatorKind()==UnaryOperatorInst::OpKind::TypeofKind){
        Datum input=value(u->getSingleOperand(),frame,u);const char *type=exactType(input);
        if(failed_||!type)return reject("TYPEOF_VALUE_UNPROVEN",u);
        Datum d=make(Primitive,u);d.keyName=std::string("S:")+type;return d;
      }
    }
    return reject("CONTROL_OR_EFFECT_OUTSIDE_PROFILE", i);
  }
  Datum execute(Frame &frame) {
    Function *f=frame.function;
    if(!f||f->empty())return reject("EMPTY_CALLEE",frame.entry);
    BasicBlock *block=frame.generatorBody&&frame.resumeBlock?frame.resumeBlock:&f->front();
    BasicBlock *previous=frame.generatorBody?frame.resumePrevious:nullptr;
                                                                                 
    std::set<BasicBlock *> visited;
    active_.insert(f);
    while(block&&!failed_) {
      if(block->getParent()!=f||visited.size()>=256||!visited.insert(block).second){reject("CONTROL_CYCLE_OR_BLOCK_LIMIT",frame.entry);break;}
      ++executedBlocks_;BasicBlock *next=nullptr;bool ended=false;
                                                                             
                                                            
      std::map<Value *,Datum> phis;
      for(auto &i:*block){
        auto *phi=llvh::dyn_cast<PhiInst>(&i);if(!phi)break;
        if(++steps_>20000){reject("STEP_LIMIT",phi);break;}
        Value *incoming=nullptr;unsigned matches=0;
        for(unsigned n=0;n<phi->getNumEntries();++n){auto entry=phi->getEntry(n);if(entry.second==previous){incoming=entry.first;++matches;}}
        if(!previous||matches!=1){reject("PHI_PREDECESSOR_UNPROVEN",phi);break;}
        Datum d=value(incoming,frame,phi);edge(d,phi);phis[phi]=std::move(d);++selectedPhis_;
      }
      for(auto &p:phis)frame.values[p.first]=std::move(p.second);
      for(auto &i:*block){
        if(failed_)break;
        if(llvh::isa<PhiInst>(&i))continue;
        if(auto *yield=llvh::dyn_cast<SaveAndYieldInst>(&i)) {
          if(!frame.generatorBody||++steps_>20000){reject("GENERATOR_YIELD_CONTEXT_OR_LIMIT",yield);break;}
          Datum d=value(yield->getResult(),frame,yield);if(failed_||!primitive(d)){reject("GENERATOR_YIELD_VALUE",yield);break;}
          edge(d,yield);frame.resumeBlock=yield->getNextBlock();frame.resumePrevious=block;frame.suspended=true;++generatorYields_;
          active_.erase(f);return d;
        }
        if(auto *ret=llvh::dyn_cast<ReturnInst>(&i)){
          if(++steps_>20000){reject("STEP_LIMIT",ret);break;}
          Datum d=value(ret->getValue(),frame,ret);edge(d,ret);if(frame.generatorBody)frame.completed=true;active_.erase(f);return d;
        }
        if(auto *branch=llvh::dyn_cast<BranchInst>(&i)){
          if(++steps_>20000){reject("STEP_LIMIT",branch);break;}
          next=branch->getBranchDest();++directEdges_;ended=true;break;
        }
        if(auto *branch=llvh::dyn_cast<CondBranchInst>(&i)){
          if(++steps_>20000){reject("STEP_LIMIT",branch);break;}
          Datum condition=value(branch->getCondition(),frame,branch);bool selected;
          if(failed_||!truth(condition,selected)){reject("BRANCH_CONDITION_UNPROVEN",branch);break;}
          next=selected?branch->getTrueDest():branch->getFalseDest();++provenBranches_;ended=true;break;
        }
        Datum d=instruction(&i,frame);frame.values[&i]=std::move(d);
      }
      if(!failed_&&!ended){reject("CONTROL_TERMINATOR_OUTSIDE_PROFILE",frame.entry);break;}
      previous=block;block=next;
    }
    active_.erase(f);return {};
  }
  void index() {
    using Clock=std::chrono::steady_clock;
    const auto started=Clock::now();
    auto budget=[&]() {
      metadataMicros_=std::chrono::duration_cast<std::chrono::microseconds>(Clock::now()-started).count();
      if(metadataMicros_<=2000000)return true;
      metadataStop_="TIME_LIMIT";reject("MODULE_METADATA_TIME_LIMIT",nullptr);return false;
    };
    metadataStop_="SCANNING";unsigned globalCount=0;
    for(auto *g:module_->getGlobalProperties()) {
      if(++globalCount>50000){metadataStop_="GLOBAL_LIMIT";reject("MODULE_METADATA_GLOBAL_LIMIT",nullptr);return;}
      if((globalCount&1023)==0&&!budget())return;
      if(g->isDeclared()) {
        const auto binding=key(g->getName());
        if(binding=="undefined"||binding=="NaN"||binding=="Infinity")reject("GLOBAL_HOST_BINDING_ATTRIBUTES_UNPROVEN",nullptr);
        const auto name=key(g->getName());declaredGlobals_.insert(name);
        if(name=="Object"||name=="Symbol"||name=="Date"||name=="document"||name=="HermesES6Internal")reject("HOST_GLOBAL_SHADOWED",nullptr);
      }
    }
    bool target=false;unsigned fi=0;
    for(auto &f:*module_) {
      if(metadataFunctions_>=50000){metadataStop_="FUNCTION_LIMIT";reject("MODULE_METADATA_FUNCTION_LIMIT",nullptr);return;}
      functionIds_[&f]=fi++;++metadataFunctions_;
      if(f.isGlobalScope()){if(global_)reject("MULTIPLE_GLOBAL_ENTRIES",nullptr);global_=&f;}
      for(auto &b:f)for(auto &i:b) {
        ++metadataInstructions_;
        if((metadataInstructions_&1023)==0&&!budget())return;
                                                                         
                                                                          
                                                                    
        if(llvh::isa<DirectEvalInst>(&i))reject("DIRECT_EVAL_OUTSIDE_PROFILE",&i);
        if(auto *c=llvh::dyn_cast<CallBuiltinInst>(&i))
          {
            bool write=c->getBuiltinIndex()==BuiltinMethod::HermesBuiltin_superPropertyGet&&c->getNumArguments()==5;
            superWriteTarget_|=write;
            target|=c->getBuiltinIndex()==BuiltinMethod::HermesBuiltin_initBaseClass||write;
          }
      }
    }
    if(!budget())return;
    metadataComplete_=true;metadataStop_="FULL_SCAN";
    if(!global_)reject("GLOBAL_ENTRY_MISSING",nullptr);
    if(!target)reject("NO_NATIVE_BASE_TARGET",nullptr);
  }

 public:
  BoundedNativeStaticReturnTransport(Module *m, const std::vector<Instruction *> &sources,
      const std::vector<Instruction *> &sinks) : module_(m), sources_(sources), sinks_(sinks) { index(); }
  void append(std::vector<DefUseAnalyzer::TaintPath> &paths) {
    if (!failed_) { Frame entry; entry.function = global_;entry.receiver=make(Global); execute(entry); }
    unsigned added = 0;
    if (!failed_) for (const auto &p : pending_) {
      if (std::any_of(paths.begin(), paths.end(), [&](const DefUseAnalyzer::TaintPath &existing) {
        return existing.source == p.source && existing.sink == p.sink;
      })) continue;
      paths.push_back(p); ++added;
      llvh::outs() << "[NATIVE_STATIC_RETURN_TRACE] source=" << id(p.source) << " sink=" << id(p.sink) << "\n";
    }
                                                                            
                                                                             
    unsigned unexecuted=0,unconfirmed=0;
    if(!failed_) {
      for(const auto &p:observedPairs_)llvh::outs()<<"[NATIVE_CONDITIONAL_ROUTE] source="<<id(p.first)<<" sink="<<id(p.second)
        <<" condition=CLOSED_ENTRY_NORMAL_PATH environment=UNPROVEN negative_certificate=0\n";
      std::set<std::pair<Instruction *,Instruction *>> emitted;
      for(const auto &p:paths) {
        if(observedPairs_.count({p.source,p.sink})||!emitted.insert({p.source,p.sink}).second)continue;
        if(!executedSinks_.count(p.sink)) {
          ++unexecuted;llvh::outs()<<"[NATIVE_UNEXECUTED_CANDIDATE] source="<<id(p.source)<<" sink="<<id(p.sink)
            <<" condition=CLOSED_ENTRY_NORMAL_PATH negative_certificate=0 environment=UNPROVEN retained_potential=1\n";
        } else {
          ++unconfirmed;llvh::outs()<<"[NATIVE_UNCONFIRMED_CANDIDATE] source="<<id(p.source)<<" sink="<<id(p.sink)
            <<" reason=SOURCE_NOT_IN_OBSERVED_VALUE condition=CLOSED_ENTRY_NORMAL_PATH negative_certificate=0 environment=UNPROVEN retained_potential=1\n";
        }
      }
    }
    llvh::outs()<<"[NATIVE_GENERATOR_EXECUTION] status="<<(failed_?"UNKNOWN":"CONDITIONAL")
      <<" created="<<generatorCreated_<<" advances="<<generatorAdvances_<<" yields="<<generatorYields_<<" closes="<<generatorCloses_
      <<" unexecuted_candidates="<<unexecuted<<" unconfirmed_candidates="<<unconfirmed
      <<" conditional_routes="<<(failed_?0:observedPairs_.size())<<" environment=UNPROVEN negative_certificate=0 suppression=0\n";
    llvh::outs()<<"[NATIVE_DYNAMIC_SCOPE_STATE] status="<<(failed_?"UNKNOWN":"CONDITIONAL")
      <<" created="<<dynamicScopeCreations_<<" environments="<<environments_.size()
      <<" environment_limit=512 block_revisit_guard=1 eval_guard=1 negative_certificate=0\n";
    llvh::outs()<<"[NATIVE_NUMERIC_RELATION_STATE] status="<<(failed_?"UNKNOWN":"CONDITIONAL")
      <<" comparisons="<<exactNumericRelations_<<" finite_known_numbers_only=1 coercion=0 loop_limit_unchanged=1 negative_certificate=0\n";
    llvh::outs()<<"[NATIVE_FUNCTION_PROTOTYPE_STATE] status="<<(failed_?"UNKNOWN":"CONDITIONAL")
      <<" created="<<functionPrototypeCreated_<<" reads="<<functionPrototypeReads_<<" writes="<<functionPrototypeWrites_
      <<" values="<<functionPrototypeValues_.size()<<" saved_aliases_preserved=1 environment=UNPROVEN negative_certificate=0\n";
    llvh::outs()<<"[NATIVE_CLOSURE_ARGUMENT_STATE] status="<<(failed_?"UNKNOWN":"CONDITIONAL")
      <<" argument_edges="<<closureArgumentEdges_<<" unique_closures="<<passedClosureIds_.size()
      <<" calls_of_passed_closures="<<callsOfPassedClosures_
      <<" registered_closures="<<closureIdentities_.size()<<" live_capture=1 environment=UNPROVEN negative_certificate=0\n";
    llvh::outs()<<"[NATIVE_ARRAY_IDENTITY_STATE] status="<<(failed_?"UNKNOWN":"CONDITIONAL")
      <<" arrays="<<arrayAllocations_<<" reads="<<arrayReads_<<" writes="<<arrayWrites_
      <<" length_writes="<<arrayLengthWrites_<<" sparse_storage=1 holes=PROTOTYPE_UNPROVEN environment=UNPROVEN negative_certificate=0\n";
    llvh::outs()<<"[NATIVE_OBJECT_REFERENCE_STATE] status="<<(failed_?"UNKNOWN":"CONDITIONAL")
      <<" nested_writes="<<nestedReferenceWrites_<<" nested_reads="<<nestedReferenceReads_
      <<" identity_comparisons="<<objectComparisons_<<" objects="<<nameObjects_.size()
      <<" own_slots="<<ownPropertySlots_<<" peak_own_slots="<<peakOwnPropertySlots_<<" own_slot_budget="<<ownPropertyBudget_
      <<" recursive_expansion=0 environment=UNPROVEN negative_certificate=0\n";
    llvh::outs() << "[NATIVE_STATIC_RETURN_TRANSPORT] status=" << (failed_ ? "UNKNOWN" : "CONDITIONAL")
                 << " invocations=" << invocations_ << " returns=" << returns_ << " argument_edges=" << argumentEdges_
                 << " classes=" << classDefinitions_ << " methods=" << methodDefinitions_ << " class_calls=" << classCalls_
                 << " tentative=" << pending_.size() << " added=" << added << " steps=" << steps_
                 << " reason=" << reason_ << " barrier=" << id(barrier_)
                 << " metadata_instructions=" << metadataInstructions_ << " metadata_functions=" << metadataFunctions_
                 << " metadata_complete=" << metadataComplete_ << " metadata_stop=" << metadataStop_
                 << " metadata_us=" << metadataMicros_ << " metadata_id_cache=" << diagnosticIds_.size()
                 << " registration_attempts=" << registrationAttempts_ << " registrations=" << registrations_ << " registration_reads=" << registrationReads_
                 << " executed_blocks=" << executedBlocks_ << " proven_branches=" << provenBranches_ << " direct_edges=" << directEdges_ << " selected_phis=" << selectedPhis_
                 << " getter_definitions=" << getterDefinitions_ << " getter_invocations=" << getterInvocations_
                 << " executed_deletes=" << propertyDeletes_ << " normal_entry_guards=" << normalEntryGuards_
                 << " environment=UNPROVEN assumptions=PRISTINE_OBJECT_SYMBOL_DATE_DOCUMENT_AND_EFFECT_FREE_NORMAL_GLOBAL_GUARDS negative_certificate=0 suppression=0 contract=CONDITIONAL_CLOSED_EXACT_NATIVE_CLASS_OBJECT_KEY_FUNCTION_RETURN\n";
  }
};
}             
}                    

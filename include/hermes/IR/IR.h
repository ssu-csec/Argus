/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_IR_IR_H
#define HERMES_IR_IR_H

#include "hermes/ADT/WordBitSet.h"
#include "hermes/AST/Context.h"
#include "hermes/FrontEndDefs/JavaScriptDeclKind.h"
#include "hermes/Support/Conversions.h"
#include "hermes/Support/ScopeChain.h"

#ifndef HERMESVM_LEAN
#include "hermes/AST/ESTree.h"
#endif

#include "llvh/ADT/FoldingSet.h"
#include "llvh/ADT/Hashing.h"
#include "llvh/ADT/SmallPtrSet.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/Twine.h"
#include "llvh/ADT/ilist_node.h"
#include "llvh/ADT/iterator_range.h"
#include "llvh/IR/SymbolTableListTraits.h"
#include "llvh/Support/Casting.h"
#include "llvh/Support/MathExtras.h"
#include "llvh/Support/raw_ostream.h"

#include <deque>
#include <unordered_map>
#include <vector>

namespace hermes {

class Module;
class Function;
class BasicBlock;
class Parameter;
class Instruction;
class Context;
class TerminatorInst;
class ScopeDesc;
class Variable;

                                             
class Type {
                                           
  enum TypeKind {
                             
    Empty,
    Undefined,
    Null,
    Boolean,
    String,
    Number,
    BigInt,
    Object,
    Closure,                      
    RegExp,                      

    LAST_TYPE
  };

  enum NumTypeKind {
    Double,
    Int32,
    Uint32,

    LAST_NUM_TYPE
  };

                                                                   
  llvh::StringRef getKindStr(TypeKind idx) const {
                                                      
    static const char *const names[] = {
        "empty",
        "undefined",
        "null",
        "boolean",
        "string",
        "number",
        "bigint",
        "object",
        "closure",
        "regexp"};
    return names[idx];
  }

#define BIT_TO_VAL(XX) (1 << TypeKind::XX)
#define IS_VAL(XX) (bitmask_ == (1 << TypeKind::XX))

#define NUM_BIT_TO_VAL(XX) (1 << NumTypeKind::XX)
#define NUM_IS_VAL(XX) (numBitmask_ == (1 << NumTypeKind::XX))

                                             
  static constexpr uint16_t TYPE_ANY_MASK = (1u << TypeKind::LAST_TYPE) - 1;

  static constexpr uint16_t PRIMITIVE_BITS = BIT_TO_VAL(Number) |
      BIT_TO_VAL(String) | BIT_TO_VAL(BigInt) | BIT_TO_VAL(Null) |
      BIT_TO_VAL(Undefined) | BIT_TO_VAL(Boolean);

  static constexpr uint16_t OBJECT_BITS =
      BIT_TO_VAL(Object) | BIT_TO_VAL(Closure) | BIT_TO_VAL(RegExp);

  static constexpr uint16_t NONPTR_BITS = BIT_TO_VAL(Number) |
      BIT_TO_VAL(Boolean) | BIT_TO_VAL(Null) | BIT_TO_VAL(Undefined);

  static constexpr uint16_t ANY_NUM_BITS =
      NUM_BIT_TO_VAL(Double) | NUM_BIT_TO_VAL(Int32) | NUM_BIT_TO_VAL(Uint32);

  static constexpr uint16_t INTEGER_BITS =
      NUM_BIT_TO_VAL(Int32) | NUM_BIT_TO_VAL(Uint32);

                                                                          
                                    
  uint16_t bitmask_{TYPE_ANY_MASK};
                                                                                
                                                                                
                                       
  uint16_t numBitmask_{ANY_NUM_BITS};

                                                                   
  constexpr explicit Type(uint16_t mask, uint16_t numMask = ANY_NUM_BITS)
      : bitmask_(mask), numBitmask_(numMask) {}

 public:
  constexpr Type() = default;

  static constexpr Type unionTy(Type A, Type B) {
    return Type(A.bitmask_ | B.bitmask_, A.numBitmask_ | B.numBitmask_);
  }

  static constexpr Type intersectTy(Type A, Type B) {
                                                                             
             
    return Type(A.bitmask_ & B.bitmask_);
  }

  static constexpr Type subtractTy(Type A, Type B) {
    return Type(A.bitmask_ & ~B.bitmask_, A.numBitmask_ & ~B.numBitmask_);
  }

  constexpr bool isNoType() const {
    return bitmask_ == 0;
  }

  static constexpr Type createNoType() {
    return Type(0);
  }
  static constexpr Type createAnyType() {
    return Type(TYPE_ANY_MASK);
  }
                                       
  static constexpr Type createEmpty() {
    return Type(BIT_TO_VAL(Empty));
  }
  static constexpr Type createUndefined() {
    return Type(BIT_TO_VAL(Undefined));
  }
  static constexpr Type createNull() {
    return Type(BIT_TO_VAL(Null));
  }
  static constexpr Type createBoolean() {
    return Type(BIT_TO_VAL(Boolean));
  }
  static constexpr Type createString() {
    return Type(BIT_TO_VAL(String));
  }
  static constexpr Type createObject() {
    return Type(BIT_TO_VAL(Object));
  }
  static constexpr Type createNumber() {
    return Type(BIT_TO_VAL(Number));
  }
  static constexpr Type createBigInt() {
    return Type(BIT_TO_VAL(BigInt));
  }
  static constexpr Type createNumeric() {
    return unionTy(createNumber(), createBigInt());
  }
  static constexpr Type createClosure() {
    return Type(BIT_TO_VAL(Closure));
  }
  static constexpr Type createRegExp() {
    return Type(BIT_TO_VAL(RegExp));
  }
  static constexpr Type createInt32() {
    return Type(BIT_TO_VAL(Number), NUM_BIT_TO_VAL(Int32));
  }
  static constexpr Type createUint32() {
    return Type(BIT_TO_VAL(Number), NUM_BIT_TO_VAL(Uint32));
  }

  constexpr bool isAnyType() const {
    return bitmask_ == TYPE_ANY_MASK;
  }

  constexpr bool isUndefinedType() const {
    return IS_VAL(Undefined);
  }
  constexpr bool isNullType() const {
    return IS_VAL(Null);
  }
  constexpr bool isBooleanType() const {
    return IS_VAL(Boolean);
  }
  constexpr bool isStringType() const {
    return IS_VAL(String);
  }

  bool isObjectType() const {
                                                                            
    return bitmask_ && !(bitmask_ & ~OBJECT_BITS);
  }

  constexpr bool isNumberType() const {
    return IS_VAL(Number);
  }
  constexpr bool isBigIntType() const {
    return IS_VAL(BigInt);
  }
  constexpr bool isClosureType() const {
    return IS_VAL(Closure);
  }
  constexpr bool isRegExpType() const {
    return IS_VAL(RegExp);
  }
  constexpr bool isInt32Type() const {
    return IS_VAL(Number) && NUM_IS_VAL(Int32);
  }
  constexpr bool isUint32Type() const {
    return IS_VAL(Number) && NUM_IS_VAL(Uint32);
  }
  constexpr bool isIntegerType() const {
    return IS_VAL(Number) && (numBitmask_ && !(numBitmask_ & ~INTEGER_BITS));
  }

                                                                              
                                                       
  constexpr bool isKnownPrimitiveType() const {
    return isPrimitive() && 1 == llvh::countPopulation(bitmask_);
  }

  constexpr bool isPrimitive() const {
                                                        
    return bitmask_ && !(bitmask_ & ~PRIMITIVE_BITS);
  }

                                                                            
  constexpr bool isNonPtr() const {
                                                                            
    return bitmask_ && !(bitmask_ & ~NONPTR_BITS);
  }
#undef BIT_TO_VAL
#undef IS_VAL
#undef NUM_BIT_TO_VAL
#undef NUM_IS_VAL

                                                     
  constexpr bool isSubsetOf(Type t) const {
    return !(bitmask_ & ~t.bitmask_);
  }

                                                                           
                                                                          
                                                                          
  constexpr bool canBeType(Type t) const {
    return t.isSubsetOf(*this);
  }

                                                              
  constexpr bool canBeString() const {
    return canBeType(Type::createString());
  }

                                                              
  constexpr bool canBeBigInt() const {
    return canBeType(Type::createBigInt());
  }

                                                              
  constexpr bool canBeNumber() const {
    return canBeType(Type::createNumber());
  }

                                                         
  constexpr bool canBeObject() const {
    return canBeType(Type::createObject());
  }

                                                                   
  constexpr bool canBeObjectSubtype() const {
    return bitmask_ & OBJECT_BITS;
  }

                                                               
  constexpr bool canBeBoolean() const {
    return canBeType(Type::createBoolean());
  }

                                                                
  constexpr bool canBeEmpty() const {
    return canBeType(Type::createEmpty());
  }

                                                                  
  constexpr bool canBeUndefined() const {
    return canBeType(Type::createUndefined());
  }

                                                            
  constexpr bool canBeNull() const {
    return canBeType(Type::createNull());
  }

                                                               
  constexpr bool canBeClosure() const {
    return canBeType(Type::createClosure());
  }

                                                             
  constexpr bool canBeRegex() const {
    return canBeType(Type::createRegExp());
  }

                                                                            
                                                 
  constexpr bool isProperSubsetOf(Type t) const {
    return bitmask_ != t.bitmask_ && !(bitmask_ & ~t.bitmask_);
  }

  void print(llvh::raw_ostream &OS) const;

                                                         
  llvh::hash_code hash() const {
    return llvh::hash_value(bitmask_);
  }

  constexpr bool operator==(Type RHS) const {
    return bitmask_ == RHS.bitmask_;
  }
  constexpr bool operator!=(Type RHS) const {
    return !(*this == RHS);
  }
};

                                                                          
                                                                          
                                                                                
                                  
enum class SideEffectKind {
                                     
  None,
                                  
  MayRead,
                                           
  MayWrite,
                                                                           
                  
  Unknown,
};

enum class ValueKind : uint8_t {
#define INCLUDE_ALL_INSTRS
#define DEF_VALUE(CLASS, PARENT) CLASS##Kind,
#define MARK_VALUE(CLASS) CLASS##Kind,
#define MARK_FIRST(CLASS) First_##CLASS##Kind,
#define MARK_LAST(CLASS) Last_##CLASS##Kind,
#include "hermes/IR/ValueKinds.def"
#undef INCLUDE_ALL_INSTRS
};

                                                                    
static inline bool kindIsA(ValueKind kind, ValueKind base) {
  switch (base) {
    default:
      return kind == base;
#define INCLUDE_ALL_INSTRS
#define MARK_FIRST(CLASS)                            \
  case ValueKind::CLASS##Kind:                       \
    return kind >= ValueKind::First_##CLASS##Kind && \
        kind <= ValueKind::Last_##CLASS##Kind;
#include "hermes/IR/ValueKinds.def"
#undef INCLUDE_ALL_INSTRS
  }
}

                                                                      
                                                                               
                                                                         
class SerializedScope {
 public:
  using Ptr = std::shared_ptr<const SerializedScope>;
                                                  
  struct Declaration {
    Identifier name;
    JavaScriptDeclKind declKind;
    bool strictImmutableBinding;
  };
                           
  Ptr parentScope;
                                            
  Identifier originalName;
                                                                             
                                                                                
                                                                          
                                                                             
                                              
  Identifier closureAlias;
                                          
  llvh::SmallVector<Declaration, 16> variables;
};

using SerializedScopePtr = SerializedScope::Ptr;

#ifndef HERMESVM_LEAN
                                  
struct LazySource {
                                                                             
  ESTree::NodeKind nodeKind{ESTree::NodeKind::Empty};
                                                              
  uint32_t bufferId{0};
                                                                               
                                   
  SMRange functionRange;
                                                      
  bool paramYield{false};
                                                      
  bool paramAwait{false};
};
#endif

class Value {
 public:
  using UseListTy = llvh::SmallVector<Instruction *, 2>;
  using Use = std::pair<Value *, unsigned>;

 private:
                                                                           
                                                                    
                                                                       
                                         
                                                                       
                                                                       
                              
  friend class Module;
  friend class IRBuilder;
  friend class ScopeDesc;
  friend class Variable;

  ValueKind Kind;

                                       
  Type valueType;

                                          
  UseListTy Users;

                                                                          
                                                                      
                                                           

                                                                  
#ifdef __cpp_sized_deallocation
  void operator delete(void *p, size_t s) {
    ::operator delete(p, s);
  }
#else
  void operator delete(void *p) {
    ::operator delete(p);
  }
#endif

 protected:
  explicit Value(ValueKind k) {
    Kind = k;
  }

 public:
  Value(const Value &) = delete;
  void operator=(const Value &) = delete;

                                                         
  static void destroy(Value *V);

                                     
  const UseListTy &getUsers() const;

                                                 
  unsigned getNumUsers() const;

                                                
  bool hasUsers() const;

                                                   
  bool hasOneUser() const;

                                                                 
  void removeUse(Use U);

                                                    
                              
  Value::Use addUser(Instruction *Inst);

                                                           
  void replaceAllUsesWith(Value *Other);

                              
  void removeAllUses();

                                                                  
  bool hasUser(Value *other);

                                     
  ValueKind getKind() const {
    return Kind;
  }

                                                           
  llvh::StringRef getKindStr() const;

                                           
  void setType(Type type) {
    valueType = type;
  }

                                                
  Type getType() const {
    return valueType;
  }

  static bool classof(const Value *) {
    return true;
  }

  using iterator = UseListTy::iterator;
  using const_iterator = UseListTy::const_iterator;

  inline const_iterator users_begin() const {
    return Users.begin();
  }
  inline const_iterator users_end() const {
    return Users.end();
  }
  inline iterator users_begin() {
    return Users.begin();
  }
  inline iterator users_end() {
    return Users.end();
  }
};

                                                                            
                                                                                
                        
class ScopeDesc : public Value {
  friend class Module;
  friend class Value;
  using VariableListType = llvh::SmallVector<Variable *, 8>;

  ScopeDesc(const ScopeDesc &) = delete;
  ScopeDesc &operator=(const ScopeDesc &) = delete;

  ~ScopeDesc();

  explicit ScopeDesc(ScopeDesc *p)
      : Value(ValueKind::ScopeDescKind), parent_(p) {}

 public:
  using ScopeListTy = llvh::SmallVector<ScopeDesc *, 8>;

                                                                           
                                                                               
                                                                        
  ScopeDesc *createInnerScope() {
    auto *S = new ScopeDesc(this);
    innerScopes_.emplace_back(S);
    return S;
  }

  ScopeDesc *getParent() const {
    return parent_;
  }

  void relocateTo(ScopeDesc *newParent) {
    assert(
        newParent == parent_->getParent() &&
        "multi-level scope nesting change");
    parent_ = newParent;
  }

  ScopeListTy &getMutableInnerScopes() {
    return innerScopes_;
  }

  const ScopeListTy &getInnerScopes() const {
    return innerScopes_;
  }

  VariableListType &getMutableVariables() {
    return variables_;
  }

  const VariableListType &getVariables() const {
    return variables_;
  }

  void addVariable(Variable *V) {
    variables_.emplace_back(V);
  }

                                                       
  bool isGlobalScope() const;

  bool hasFunction() const {
    return function_;
  }

  inline Function *getFunction() const;

  inline void setFunction(Function *F);

  void setSerializedScope(SerializedScopePtr serializedScope) {
    assert(!serializedScope_ && "scope has already been serialized");
    serializedScope_ = std::move(serializedScope);
  }

  SerializedScopePtr getSerializedScope() const {
    return serializedScope_;
  }

  void setDynamic(bool v) {
    dynamic_ = v;
  }

  bool getDynamic() const {
    return dynamic_;
  }

  static bool classof(const Value *V) {
    return V->getKind() == ValueKind::ScopeDescKind;
  }

 private:
  ScopeDesc *parent_{};
  ScopeListTy innerScopes_;

  SerializedScopePtr serializedScope_;

  Function *function_{};

  VariableListType variables_;

  bool dynamic_{};
};

                                         
class Parameter : public Value {
  Parameter(const Parameter &) = delete;
  void operator=(const Parameter &) = delete;

                                               
  Function *Parent;

                                      
  Identifier Name;

 public:
  explicit Parameter(Function *parent, Identifier name, bool isThisParameter);

  void removeFromParent();

  Context &getContext() const;
  Function *getParent() const {
    return Parent;
  }
  void setParent(Function *parent) {
    Parent = parent;
  }

                                                             
  Identifier getName() const;

                                                            
  bool isThisParameter() const;

                                                                          
                                                 
  int getIndexInParamList() const;

  static bool classof(const Value *V) {
    return V->getKind() == ValueKind::ParameterKind;
  }
};

                                             
class EmptySentinel : public Value {
  EmptySentinel(const EmptySentinel &) = delete;
  void operator=(const EmptySentinel &) = delete;

 public:
  explicit EmptySentinel() : Value(ValueKind::EmptySentinelKind) {}

  static bool classof(const Value *V) {
    return V->getKind() == ValueKind::EmptySentinelKind;
  }
};

                                                                          
class Label : public Value {
  Label(const Label &) = delete;
  void operator=(const Label &) = delete;

                                                                            
                                                                        
             

  void *operator new(size_t) {
    llvm_unreachable("Labels cannot be allocated separately");
  }

                                      
  Identifier text;

 public:
  explicit Label(Identifier txt) : Value(ValueKind::LabelKind), text(txt) {}

  Identifier get() const {
    return text;
  }

  static bool classof(const Value *V) {
    return V->getKind() == ValueKind::LabelKind;
  }
};

class Literal : public Value {
  Literal(const Literal &) = delete;
  void operator=(const Literal &) = delete;

 public:
  explicit Literal(ValueKind k) : Value(k) {}

  static bool classof(const Value *V) {
    return kindIsA(V->getKind(), ValueKind::LiteralKind);
  }
};

class LiteralEmpty : public Literal {
  LiteralEmpty(const LiteralEmpty &) = delete;
  void operator=(const LiteralEmpty &) = delete;

 public:
  explicit LiteralEmpty() : Literal(ValueKind::LiteralEmptyKind) {
    setType(Type::createEmpty());
  }

  static bool classof(const Value *V) {
    return V->getKind() == ValueKind::LiteralEmptyKind;
  }
};

class LiteralNull : public Literal {
  LiteralNull(const LiteralNull &) = delete;
  void operator=(const LiteralNull &) = delete;

 public:
  explicit LiteralNull() : Literal(ValueKind::LiteralNullKind) {
    setType(Type::createNull());
  }

  static bool classof(const Value *V) {
    return V->getKind() == ValueKind::LiteralNullKind;
  }
};

class LiteralUndefined : public Literal {
  LiteralUndefined(const LiteralUndefined &) = delete;
  void operator=(const LiteralUndefined &) = delete;

 public:
  explicit LiteralUndefined() : Literal(ValueKind::LiteralUndefinedKind) {
    setType(Type::createUndefined());
  }

  static bool classof(const Value *V) {
    return V->getKind() == ValueKind::LiteralUndefinedKind;
  }
};

class LiteralBigInt : public Literal, public llvh::FoldingSetNode {
  LiteralBigInt(const LiteralBigInt &) = delete;
  LiteralBigInt &operator=(const LiteralBigInt &) = delete;

                                                                      
  UniqueString *value;

 public:
  explicit LiteralBigInt(UniqueString *v)
      : Literal(ValueKind::LiteralBigIntKind), value(v) {
    setType(Type::createBigInt());
  }

  UniqueString *getValue() const {
    return value;
  }

  static void Profile(llvh::FoldingSetNodeID &ID, UniqueString *value) {
    ID.AddPointer(value);
  }

  void Profile(llvh::FoldingSetNodeID &ID) const {
    LiteralBigInt::Profile(ID, value);
  }

  static bool classof(const Value *V) {
    return V->getKind() == ValueKind::LiteralBigIntKind;
  }
};

class LiteralNumber : public Literal, public llvh::FoldingSetNode {
  LiteralNumber(const LiteralNumber &) = delete;
  void operator=(const LiteralNumber &) = delete;
  double value;

 public:
  double getValue() const {
    return value;
  }

                                                            
                                                            
                                                
  template <typename T>
  llvh::Optional<T> isIntTypeRepresentible() const {
                                                 
                                                                             
                                                                          
    if (value > std::numeric_limits<T>::max() ||
        value < std::numeric_limits<T>::min()) {
      return llvh::None;
    }
    if (std::isnan(value)) {
      return llvh::None;
    }
                                                
    T valAsInt = static_cast<T>(value);
    if (valAsInt == value && (valAsInt || !std::signbit(value))) {
      return valAsInt;
    }
    return llvh::None;
  }

                                                
  bool isPositiveZero() const {
    return value == 0.0 && !std::signbit(value);
  }

                                                                           
                                                  
  bool isUInt8Representible() const {
    return isIntTypeRepresentible<uint8_t>().hasValue();
  }

                                                                   
                                                  
  bool isInt32Representible() const {
    return isIntTypeRepresentible<int32_t>().hasValue();
  }

                                                                            
                                                  
  bool isUInt32Representible() const {
    return isIntTypeRepresentible<uint32_t>().hasValue();
  }

                                                                            
                          
  uint32_t asUInt8() const {
    auto tmp = isIntTypeRepresentible<uint8_t>();
    assert(tmp && "Cannot convert to uint8_t");
    return tmp.getValue();
  }

                                                                            
                          
  int32_t asInt32() const {
    auto tmp = isIntTypeRepresentible<int32_t>();
    assert(tmp && "Cannot convert to int32_t");
    return tmp.getValue();
  }

                                                                             
                          
  uint32_t asUInt32() const {
    auto tmp = isIntTypeRepresentible<uint32_t>();
    assert(tmp && "Cannot convert to uint32_t");
    return tmp.getValue();
  }

                                                                              
                                                                            
                                                           
  int32_t truncateToInt32() const {
    return hermes::truncateToInt32(value);
  }

  uint32_t truncateToUInt32() const {
    return hermes::truncateToUInt32(value);
  }

                                           
  OptValue<uint32_t> convertToArrayIndex() const {
    return doubleToArrayIndex(value);
  }

  explicit LiteralNumber(double val)
      : Literal(ValueKind::LiteralNumberKind), value(val) {
    if (isInt32Representible()) {
      setType(Type::createInt32());
    } else {
      setType(Type::createNumber());
    }
  }

  static void Profile(llvh::FoldingSetNodeID &ID, double value) {
    ID.AddInteger(llvh::DoubleToBits(value));
  }

  void Profile(llvh::FoldingSetNodeID &ID) const {
    LiteralNumber::Profile(ID, value);
  }

  static bool classof(const Value *V) {
    return V->getKind() == ValueKind::LiteralNumberKind;
  }
};

class LiteralString : public Literal, public llvh::FoldingSetNode {
  LiteralString(const LiteralString &) = delete;
  void operator=(const LiteralString &) = delete;
  Identifier value;

 public:
  Identifier getValue() const {
    return value;
  }

  explicit LiteralString(Identifier val)
      : Literal(ValueKind::LiteralStringKind), value(val) {
    setType(Type::createString());
  }

  static void Profile(llvh::FoldingSetNodeID &ID, Identifier value) {
    ID.AddPointer(value.getUnderlyingPointer());
  }

  void Profile(llvh::FoldingSetNodeID &ID) const {
    LiteralString::Profile(ID, value);
  }

  static bool classof(const Value *V) {
    return V->getKind() == ValueKind::LiteralStringKind;
  }
};

class LiteralBool : public Literal {
  LiteralBool(const LiteralBool &) = delete;
  void operator=(const LiteralBool &) = delete;
  bool value;

 public:
  bool getValue() const {
    return value;
  }

  explicit LiteralBool(bool val)
      : Literal(ValueKind::LiteralBoolKind), value(val) {
    setType(Type::createBoolean());
  }

  static bool classof(const Value *V) {
    return V->getKind() == ValueKind::LiteralBoolKind;
  }
};

                                                                         
                          
class GlobalObject : public Literal {
  GlobalObject(const GlobalObject &) = delete;
  void operator=(const GlobalObject &) = delete;

 public:
  explicit GlobalObject() : Literal(ValueKind::GlobalObjectKind) {
    setType(Type::createObject());
  }

  static bool classof(const Value *V) {
    return V->getKind() == ValueKind::GlobalObjectKind;
  }
};

                                                                            
class Variable : public Value {
 public:
  using DeclKind = JavaScriptDeclKind;

 private:
  Variable(const Variable &) = delete;
  void operator=(const Variable &) = delete;

                                      
  DeclKind declKind;

                                                                           
  Identifier text;

                                       
  ScopeDesc *parent;

                                                                                
     
                                                        
     
                                                                          
                         
  bool strictImmutableBinding_{};

 protected:
  explicit Variable(
      ValueKind k,
      ScopeDesc *scope,
      DeclKind declKind,
      Identifier txt);

 public:
  explicit Variable(ScopeDesc *scope, DeclKind declKind, Identifier txt)
      : Variable(ValueKind::VariableKind, scope, declKind, txt) {};

  ~Variable();

  DeclKind getDeclKind() const {
    return declKind;
  }

  Identifier getName() const {
    return text;
  }
  ScopeDesc *getParent() const {
    return parent;
  }

  void setParent(ScopeDesc *S) {
    assert(parent->getParent() == S && "multi-level re-home not expected.");
    parent = S;
  }

  bool getObeysTDZ() const {
    return declKind != DeclKind::Var;
  }

  bool getStrictImmutableBinding() const {
    return strictImmutableBinding_;
  }
  void setStrictImmutableBinding(bool value) {
    assert(
        declKind == DeclKind::Const &&
        "strict immutable binding is only meaningful for const Variables.");
    strictImmutableBinding_ = value;
  }

                                                                        
  int getIndexInVariableList() const;

                                                                 
  Variable *cloneIntoNewScope(ScopeDesc *newScope);

  static bool classof(const Value *V) {
    return V->getKind() == ValueKind::VariableKind;
  }
};

                                    
class GlobalObjectProperty : public Value {
                              
  Module *parent_;

                        
  LiteralString *name_;

                                                                           
  bool declared_;

 public:
  GlobalObjectProperty(Module *parent, LiteralString *name, bool declared)
      : Value(ValueKind::GlobalObjectPropertyKind),
        parent_(parent),
        name_(name),
        declared_(declared) {}

  static bool classof(const Value *v) {
    return v->getKind() == ValueKind::GlobalObjectPropertyKind;
  }

  Module *getParent() const {
    return parent_;
  }

  LiteralString *getName() const {
    return name_;
  }

  bool isDeclared() const {
    return declared_;
  }

  void orDeclared(bool declared) {
    declared_ |= declared;
  }
};

                                                                     
class Instruction
    : public llvh::ilist_node_with_parent<Instruction, BasicBlock>,
      public Value {
  friend class Value;
  Instruction(const Instruction &) = delete;
  void operator=(const Instruction &) = delete;

                                                  
  BasicBlock *Parent;
                                     
  llvh::SmallVector<Value::Use, 2> Operands;
  ScopeDesc *SourceLevelScope{};

  SMLoc location_{};
                                                        
                                                            
  uint32_t statementIndex_{0};

                                                          
  SideEffectKind getDerivedSideEffect();

 protected:
  explicit Instruction(ValueKind kind) : Value(kind), Parent(nullptr) {}

                                                                                
                                                                            
                                                                          
              
                                                                            
                                                                        
  explicit Instruction(
      const Instruction *src,
      llvh::ArrayRef<Value *> operands);

                                         
  void pushOperand(Value *Val);

 public:
  void setOperand(Value *Val, unsigned Index);
  Value *getOperand(unsigned Index) const;
  unsigned getNumOperands() const;
  void removeOperand(unsigned index);

                                                                                
         
  WordBitSet<> getChangedOperands();

  void setLocation(SMLoc loc) {
    location_ = loc;
  }
  SMLoc getLocation() const {
    return location_;
  }
  bool hasLocation() const {
    return location_.isValid();
  }

  void setSourceLevelScope(ScopeDesc *sourceLevelScope) {
    SourceLevelScope = sourceLevelScope;
  }
  ScopeDesc *getSourceLevelScope() const {
    return SourceLevelScope;
  }

                                                            
                                                                   
  void setStatementIndex(uint32_t statementIndex) {
    statementIndex_ = statementIndex;
  }

  uint32_t getStatementIndex() const {
    return statementIndex_;
  }

                                                                            
                                        
  void dump(llvh::raw_ostream &os = llvh::outs()) const;

                                                                             
                                                                          
                            
  void replaceFirstOperandWith(Value *OldValue, Value *NewValue);

                                                                          
  void eraseOperand(Value *Value);

  void insertBefore(Instruction *InsertPos);
  void insertAfter(Instruction *InsertPos);
  void moveBefore(Instruction *Later);
  void removeFromParent();
  void eraseFromParent();

                                         
  llvh::StringRef getName();

                                                            
  bool hasSideEffect() {
    return getDerivedSideEffect() != SideEffectKind::None;
  }

                                                       
  bool mayReadMemory() {
    return getDerivedSideEffect() >= SideEffectKind::MayRead;
  }
                                                           
  bool mayWriteMemory() {
    return getDerivedSideEffect() >= SideEffectKind::MayWrite;
  }
                                                                            
                                        
  bool mayExecute() {
    return getDerivedSideEffect() > SideEffectKind::MayWrite;
  }

  Context &getContext() const;
  BasicBlock *getParent() const {
    return Parent;
  }
  void setParent(BasicBlock *parent) {
    Parent = parent;
  }

  static bool classof(const Value *V) {
    return kindIsA(V->getKind(), ValueKind::InstructionKind);
  }

                                                                 
     
                                                                                
                                                                             
                                                                               
  class Variety {
    friend class Instruction;
    std::pair<unsigned, unsigned> kinds_;
    explicit Variety(std::pair<unsigned, unsigned> kinds) : kinds_(kinds) {}

   public:
    bool operator==(const Variety &other) const {
      return kinds_ == other.kinds_;
    }
    bool operator!=(const Variety &other) const {
      return kinds_ != other.kinds_;
    }
    friend llvh::hash_code hash_value(Variety variety) {
      return llvh::hash_value(variety.kinds_);
    }
  };

                                             
  Variety getVariety() const;

                                                
  llvh::hash_code getHashCode() const;

                                                         
  bool isIdenticalTo(const Instruction *RHS) const;
};

}                    

                                                                                
                               
                                                                                

namespace llvh {

template <>
struct ilist_alloc_traits<::hermes::Instruction> {
  static void deleteNode(::hermes::Instruction *V) {
    ::hermes::Value::destroy(V);
  }
};

}                  

namespace hermes {

class BasicBlock : public llvh::ilist_node_with_parent<BasicBlock, Function>,
                   public Value {
  BasicBlock(const BasicBlock &) = delete;
  void operator=(const BasicBlock &) = delete;

 public:
  using InstListType = llvh::iplist<Instruction>;

 private:
  InstListType InstList{};
  Function *Parent;

 public:
  explicit BasicBlock(Function *parent);

                                                                               
                         
  void dump(llvh::raw_ostream &os = llvh::outs()) const;

                                 
  void printAsOperand(llvh::raw_ostream &OS, bool) const;

                                                                              
                                           
  TerminatorInst *getTerminator();
  const TerminatorInst *getTerminator() const;

  InstListType &getInstList() {
    return InstList;
  }

  void push_back(Instruction *I);
  void removeFromParent();
  void eraseFromParent();
  void remove(Instruction *I);
  void erase(Instruction *I);

  Context &getContext() const;
  Function *getParent() const {
    return Parent;
  }
  void setParent(Function *parent) {
    Parent = parent;
  }

                                                                       
                                                         
  static InstListType BasicBlock::*getSublistAccess(Instruction *) {
    return &BasicBlock::InstList;
  }

  using iterator = InstListType::iterator;
  using const_iterator = InstListType::const_iterator;
  using reverse_iterator = InstListType::reverse_iterator;
  using const_reverse_iterator = InstListType::const_reverse_iterator;

  using range = llvh::iterator_range<iterator>;
  using const_range = llvh::iterator_range<const_iterator>;
  using reverse_range = llvh::iterator_range<reverse_iterator>;
  using const_reverse_range = llvh::iterator_range<const_reverse_iterator>;

  inline iterator begin() {
    return InstList.begin();
  }
  inline iterator end() {
    return InstList.end();
  }
  inline reverse_iterator rbegin() {
    return InstList.rbegin();
  }
  inline reverse_iterator rend() {
    return InstList.rend();
  }
  inline const_iterator begin() const {
    return InstList.begin();
  }
  inline const_iterator end() const {
    return InstList.end();
  }
  inline const_reverse_iterator rbegin() const {
    return InstList.rbegin();
  }
  inline const_reverse_iterator rend() const {
    return InstList.rend();
  }
  inline size_t size() const {
    return InstList.size();
  }
  inline bool empty() const {
    return InstList.empty();
  }
  inline Instruction &front() {
    return InstList.front();
  }
  inline const Instruction &front() const {
    return InstList.front();
  }
  inline Instruction &back() {
    return InstList.back();
  }
  inline const Instruction &back() const {
    return InstList.back();
  }

  static bool classof(const Value *V) {
    return V->getKind() == ValueKind::BasicBlockKind;
  }
};

}                    

                                                                                
                              
                                                                                

namespace llvh {

template <>
struct ilist_alloc_traits<::hermes::BasicBlock> {
  static void deleteNode(::hermes::BasicBlock *V) {
    ::hermes::Value::destroy(V);
  }
};

}                  

namespace hermes {

class Function : public llvh::ilist_node_with_parent<Function, Module>,
                 public Value {
  Function(const Function &) = delete;
  void operator=(const Function &) = delete;

 public:
  using BasicBlockListType = llvh::iplist<BasicBlock>;
  using ParameterListType = llvh::SmallVector<Parameter *, 8>;

  enum class DefinitionKind {
    ES5Function,
    ES6Constructor,
    ES6DerivedConstructor,
    ES6Arrow,
    ES6Method,
    ES6AsyncGenerator,
  };

 private:
                                      
  Module *parent_;

                                                 
  bool isGlobal_;

                                    
  ScopeDesc *scopeDesc_;

                                        
  BasicBlockListType BasicBlockList{};
                              
  ParameterListType Parameters;
                                                       
                                                              
                                                 
  Identifier originalOrInferredName_;
                                                            
  DefinitionKind const definitionKind_;
                                             
  const bool strictMode_{};
                                          
  SMRange SourceRange{};
                                            
  SourceVisibility sourceVisibility_;

                                                                               
                                            
  Identifier internalName_;

                           
  Parameter *thisParameter{};

                                                                                
                                
                                                                                
                               
  uint32_t expectedParamCountIncludingThis_{0};

                                                   
                                                                       
                
                                                                            
                                                                      
                                                            
  OptValue<uint32_t> statementCount_{0};

#ifndef HERMESVM_LEAN
                                                                              
  LazySource lazySource_;

                                                    
  SerializedScopePtr lazyScope_{};

                                                                               
                                                                              
                                                                     
     
                                     
                                                    
     
                                                         
                                     
                                                                                
                       
           
                                       
     
                                                                            
                                                                 
  Variable *lazyClosureAlias_{};
#endif

  template <typename H>
  void forEachScopeImpl(Function *F, ScopeDesc *scopeDesc, H handler) {
    if (scopeDesc->getFunction() != F) {
      return;
    }

    handler(scopeDesc);

    for (ScopeDesc *inner : scopeDesc->getInnerScopes()) {
      forEachScopeImpl(F, inner, handler);
    }
  }

 protected:
  explicit Function(
      ValueKind kind,
      Module *parent,
      ScopeDesc *scopeDesc,
      Identifier originalName,
      DefinitionKind definitionKind,
      bool strictMode,
      SourceVisibility sourceVisibility,
      bool isGlobal,
      SMRange sourceRange,
      Function *insertBefore = nullptr);

 public:
                                                        
                                                   
                                                                           
                                                               
                                                                      
                                                                       
                                                                           
                                                                             
  explicit Function(
      Module *parent,
      ScopeDesc *scopeDesc,
      Identifier originalName,
      DefinitionKind definitionKind,
      bool strictMode,
      SourceVisibility sourceVisibility,
      bool isGlobal,
      SMRange sourceRange,
      Function *insertBefore = nullptr)
      : Function(
            ValueKind::FunctionKind,
            parent,
            scopeDesc,
            originalName,
            definitionKind,
            strictMode,
            sourceVisibility,
            isGlobal,
            sourceRange,
            insertBefore) {}

  ~Function();

  Module *getParent() const {
    return parent_;
  }

  ScopeDesc *getFunctionScopeDesc() const {
    return scopeDesc_;
  }

                                                                          
  bool isGlobalScope() const {
    return isGlobal_;
  }

                                                   
  bool isAnonymous() const {
    return originalOrInferredName_.str().empty();
  }

                                                                     
                                          
                                                                  
  std::string getDefinitionKindStr(bool isDescriptive) const;

                                                                            
                                                                                
                                                                        
  std::string getDescriptiveDefinitionKindStr() const;

                                                                          
                                                                          
                                                                              
                                                                                
                                                                     
  llvh::Optional<llvh::StringRef> getSourceRepresentationStr() const;

                                                 
  const Identifier getInternalName() const {
    return internalName_;
  }

                                                          
  llvh::StringRef getInternalNameStr() const {
    return internalName_.str();
  }

                                                                
                                             
  const Identifier getOriginalOrInferredName() const {
    return originalOrInferredName_;
  }

                                               
  Context &getContext() const;

  void addBlock(BasicBlock *BB);
  void addParameter(Parameter *A);

  const BasicBlockListType &getBasicBlockList() const {
    return BasicBlockList;
  }
  BasicBlockListType &getBasicBlockList() {
    return BasicBlockList;
  }

                                                                   
                                                                      
                                                                             
  void eraseFromParentNoDestroy();

                                                                               
                         
  void dump(llvh::raw_ostream &os = llvh::outs()) const;

                                                           
  DefinitionKind getDefinitionKind() const {
    return definitionKind_;
  }

                                                    
  bool isStrictMode() const {
    return strictMode_;
  }

                                                      
  SMRange getSourceRange() const {
    return SourceRange;
  }

                                                   
  SourceVisibility getSourceVisibility() const {
    return sourceVisibility_;
  }

  OptValue<uint32_t> getStatementCount() const {
    return statementCount_;
  }

  void setStatementCount(uint32_t count) {
    statementCount_ = count;
  }

                                                     
                                                               
  void incrementStatementCount() {
    assert(
        statementCount_.hasValue() &&
        "cannot incrementStatementCount after clearing it");
    statementCount_ = *statementCount_ + 1;
  }

  void clearStatementCount() {
    statementCount_ = llvh::None;
  }

  ParameterListType &getParameters() {
    return Parameters;
  }

  void setExpectedParamCountIncludingThis(uint32_t count) {
    expectedParamCountIncludingThis_ = count;
  }

  uint32_t getExpectedParamCountIncludingThis() const {
    return expectedParamCountIncludingThis_;
  }

  void setThisParameter(Parameter *thisParam) {
    assert(!thisParameter && "This parameter can only be created once");
    thisParameter = thisParam;
  }
  Parameter *getThisParameter() const {
    return thisParameter;
  }

#ifndef HERMESVM_LEAN
  LazySource &getLazySource() {
    return lazySource_;
  }

  void setLazyScope(SerializedScopePtr vars) {
    lazyScope_ = std::move(vars);
  }
  SerializedScopePtr getLazyScope() const {
    return lazyScope_;
  }

  void setLazyClosureAlias(Variable *var) {
    lazyClosureAlias_ = var;
  }
  Variable *getLazyClosureAlias() const {
    return lazyClosureAlias_;
  }
#endif

                                                             
  bool isLazy() const {
#ifdef HERMESVM_LEAN
    return false;
#else
    return lazySource_.nodeKind != ESTree::NodeKind::Empty;
#endif
  }

  using iterator = BasicBlockListType::iterator;
  using const_iterator = BasicBlockListType::const_iterator;
  using reverse_iterator = BasicBlockListType::reverse_iterator;
  using const_reverse_iterator = BasicBlockListType::const_reverse_iterator;

  using arg_iterator = ParameterListType::iterator;
  using const_arg_iterator = ParameterListType::const_iterator;

  inline iterator begin() {
    return BasicBlockList.begin();
  }
  inline iterator end() {
    return BasicBlockList.end();
  }
  inline reverse_iterator rbegin() {
    return BasicBlockList.rbegin();
  }
  inline reverse_iterator rend() {
    return BasicBlockList.rend();
  }
  inline const_iterator begin() const {
    return BasicBlockList.begin();
  }
  inline const_iterator end() const {
    return BasicBlockList.end();
  }
  inline const_reverse_iterator rbegin() const {
    return BasicBlockList.rbegin();
  }
  inline const_reverse_iterator rend() const {
    return BasicBlockList.rend();
  }
  inline arg_iterator arg_begin() {
    return Parameters.begin();
  }
  inline arg_iterator arg_end() {
    return Parameters.end();
  }
  inline const_arg_iterator arg_begin() const {
    return Parameters.begin();
  }
  inline const_arg_iterator arg_end() const {
    return Parameters.end();
  }
  inline size_t size() const {
    return BasicBlockList.size();
  }
  inline bool empty() const {
    return BasicBlockList.empty();
  }
  inline BasicBlock &front() {
    return BasicBlockList.front();
  }
  inline BasicBlock &back() {
    return BasicBlockList.back();
  }

  void viewGraph();

                                                                   
  template <typename H>
  void forEachScope(H handler) {
    forEachScopeImpl(this, this->getFunctionScopeDesc(), handler);
  }

  static bool classof(const Value *V) {
    return kindIsA(V->getKind(), ValueKind::FunctionKind);
  }
};

class GeneratorFunction final : public Function {
 public:
  explicit GeneratorFunction(
      Module *parent,
      ScopeDesc *scopeDesc,
      Identifier originalName,
      DefinitionKind definitionKind,
      bool strictMode,
      SourceVisibility sourceVisibility,
      bool isGlobal,
      SMRange sourceRange,
      Function *insertBefore)
      : Function(
            ValueKind::GeneratorFunctionKind,
            parent,
            scopeDesc,
            originalName,
            definitionKind,
            strictMode,
            sourceVisibility,
            isGlobal,
            sourceRange,
            insertBefore) {}

  static bool classof(const Value *V) {
    return kindIsA(V->getKind(), ValueKind::GeneratorFunctionKind);
  }
};

class GeneratorInnerFunction final : public Function {
 public:
  explicit GeneratorInnerFunction(
      Module *parent,
      ScopeDesc *scopeDesc,
      Identifier originalName,
      DefinitionKind definitionKind,
      bool strictMode,
      bool isGlobal,
      SMRange sourceRange,
      Function *insertBefore)
      : Function(
            ValueKind::GeneratorInnerFunctionKind,
            parent,
            scopeDesc,
            originalName,
            definitionKind,
            strictMode,
                                                                                
                                                                                
            SourceVisibility::HideSource,
            isGlobal,
            sourceRange,
            insertBefore) {
    setType(Type::createAnyType());
  }

  static bool classof(const Value *V) {
    return kindIsA(V->getKind(), ValueKind::GeneratorInnerFunctionKind);
  }
};

class AsyncFunction final : public Function {
 public:
  explicit AsyncFunction(
      Module *parent,
      ScopeDesc *scopeDesc,
      Identifier originalName,
      DefinitionKind definitionKind,
      bool strictMode,
      SourceVisibility sourceVisibility,
      bool isGlobal,
      SMRange sourceRange,
      Function *insertBefore)
      : Function(
            ValueKind::AsyncFunctionKind,
            parent,
            scopeDesc,
            originalName,
            definitionKind,
            strictMode,
            sourceVisibility,
            isGlobal,
            sourceRange,
            insertBefore) {}

  static bool classof(const Value *V) {
    return kindIsA(V->getKind(), ValueKind::AsyncFunctionKind);
  }
};

}                    

                                                                                
                            
                                                                                

namespace llvh {

template <>
struct ilist_alloc_traits<::hermes::Function> {
  static void deleteNode(::hermes::Function *V) {
    ::hermes::Value::destroy(V);
  }
};

}                  

namespace hermes {

class Module : public Value {
  Module(const Module &) = delete;
  void operator=(const Module &) = delete;

 public:
  using FunctionListType = llvh::iplist<Function>;

  using RawStringList = std::vector<LiteralString *>;

  struct CJSModule {
                                                    
    uint32_t id;
                                
    Identifier filename;
                                                       
    Function *function;
  };

 private:
  using GlobalObjectPropertyList = std::vector<GlobalObjectProperty *>;

  std::shared_ptr<Context> Ctx;
                                                                           
  Function *topLevelFunction_{};

  FunctionListType FunctionList{};

                                                                   
  GlobalObjectPropertyList globalPropertyList_{};
                                                             
  llvh::DenseMap<Identifier, GlobalObjectProperty *> globalPropertyMap_{};

                                        
  ScopeDesc initialScope_{nullptr};
  GlobalObject globalObject_{};
  LiteralEmpty literalEmpty{};
  LiteralUndefined literalUndefined{};
  LiteralNull literalNull{};
  LiteralBool literalFalse{false};
  LiteralBool literalTrue{true};
  EmptySentinel emptySentinel_{};

  using LiteralNumberFoldingSet = llvh::FoldingSet<LiteralNumber>;
  using LiteralBigIntFoldingSet = llvh::FoldingSet<LiteralBigInt>;
  using LiteralStringFoldingSet = llvh::FoldingSet<LiteralString>;

  LiteralNumberFoldingSet literalNumbers{};
  LiteralBigIntFoldingSet literalBigInts{};
  LiteralStringFoldingSet literalStrings{};

                                                                              
                                                                               
                  
  llvh::DenseMap<Identifier, unsigned> internalNamesMap_;

                                  
                                                                               
                                              
  std::deque<CJSModule> cjsModules_{};

  using CJSModuleIterator = std::deque<CJSModule>::iterator;

                                                              
  llvh::DenseMap<Function *, CJSModule *> cjsModuleFunctionMap_{};
                                            
  llvh::DenseMap<Identifier, uint32_t> cjsModuleFilenameMap_{};
                                                           
                                                                       
                            
  llvh::DenseMap<uint32_t, std::vector<Function *>> cjsModuleSegmentMap_{};

                                                 
  bool cjsModulesResolved_{false};

  using CJSModuleUseGraph =
      std::unordered_map<Function *, llvh::SmallPtrSet<Function *, 2>>;

                                                                             
                                                                             
                                                                               
                                                            
                                                
  CJSModuleUseGraph cjsModuleUseGraph_{};

  struct HashRawStrings {
    std::size_t operator()(const RawStringList &rawStrings) const {
      return llvh::hash_combine_range(rawStrings.begin(), rawStrings.end());
    }
  };

                                                                                
  std::unordered_map<RawStringList, uint32_t, HashRawStrings>
      templateObjectIDMap_;

                                                              
  bool isLowered_{false};

 public:
  explicit Module(std::shared_ptr<Context> ctx)
      : Value(ValueKind::ModuleKind), Ctx(std::move(ctx)) {}

  ~Module();

  Context &getContext() const {
    return *Ctx;
  }

  std::shared_ptr<Context> shareContext() const {
    return Ctx;
  }

                                                                
  Identifier deriveUniqueInternalName(Identifier originalName);

  using iterator = FunctionListType::iterator;
  using const_iterator = FunctionListType::const_iterator;
  using reverse_iterator = FunctionListType::reverse_iterator;
  using const_reverse_iterator = FunctionListType::const_reverse_iterator;

                                       
  void push_back(Function *F);
                                                                 
  void insert(iterator position, Function *F);

  const FunctionListType &getFunctionList() const {
    return FunctionList;
  }
  FunctionListType &getFunctionList() {
    return FunctionList;
  }

                                                                           
                                           
  void setTopLevelFunction(Function *topLevelFunction) {
    assert(
        topLevelFunction->getParent() == this &&
        "topLevelFunction from a different module");
    topLevelFunction_ = topLevelFunction;
  }

                                    
  Function *getTopLevelFunction() {
    assert(
        !FunctionList.empty() && "top-level function hasn't been created yet");
                                                                         
                
    return !topLevelFunction_ ? &*FunctionList.begin() : topLevelFunction_;
  }

  using GlobalObjectPropertyIterator = GlobalObjectPropertyList::const_iterator;

  llvh::iterator_range<GlobalObjectPropertyIterator> getGlobalProperties() {
    return {globalPropertyList_.begin(), globalPropertyList_.end()};
  }

                                                                               
  GlobalObjectProperty *findGlobalProperty(Identifier name);

                                                                          
                                                              
  GlobalObjectProperty *addGlobalProperty(Identifier name, bool declared);

                                                              
  void eraseGlobalProperty(GlobalObjectProperty *prop);

                                                    
  LiteralNumber *getLiteralNumber(double value);

                                                    
  LiteralBigInt *getLiteralBigInt(UniqueString *value);

                                                    
  LiteralString *getLiteralString(Identifier value);

                                                  
  LiteralBool *getLiteralBool(bool value);

                                   
  LiteralEmpty *getLiteralEmpty() {
    return &literalEmpty;
  }

                                       
  LiteralUndefined *getLiteralUndefined() {
    return &literalUndefined;
  }

                                
  LiteralNull *getLiteralNull() {
    return &literalNull;
  }

  ScopeDesc *getInitialScope() {
    return &initialScope_;
  }

  const ScopeDesc *getInitialScope() const {
    return &initialScope_;
  }

                                    
  GlobalObject *getGlobalObject() {
    return &globalObject_;
  }

                                                  
  EmptySentinel *getEmptySentinel() {
    return &emptySentinel_;
  }

                                                                             
  void addCJSModule(
      uint32_t segmentID,
      uint32_t id,
      Identifier name,
      Function *function) {
    cjsModules_.emplace_back(CJSModule{id, name, function});
    CJSModule &module = cjsModules_.back();
    {
      auto result = cjsModuleFilenameMap_.try_emplace(name, id);
      (void)result;
      assert(
          (result.second || result.first->second == id) &&
          "Module must have the same ID for the same name");
    }
    {
      auto result = cjsModuleFunctionMap_.try_emplace(function, &module);
      (void)result;
      assert(
          result.second && "Should only insert each CJS wrapper function once");
    }
    cjsModuleSegmentMap_[segmentID].push_back(function);
  }

                                                                                
                   
  const CJSModule *findCJSModule(Function *function) const {
    auto it = cjsModuleFunctionMap_.find(function);
    return it == cjsModuleFunctionMap_.end() ? nullptr : it->second;
  }

                                                                          
                   
  llvh::Optional<uint32_t> findCJSModuleID(Identifier filename) const {
    auto it = cjsModuleFilenameMap_.find(filename);
    if (it != cjsModuleFilenameMap_.end()) {
      return it->second;
    }
    return llvh::None;
  }

                                              
  llvh::iterator_range<CJSModuleIterator> getCJSModules() {
    return {cjsModules_.begin(), cjsModules_.end()};
  }

                                                                        
  bool getCJSModulesResolved() const {
    return cjsModulesResolved_;
  }

                                                                       
  void setCJSModulesResolved(bool cjsModulesResolved) {
    cjsModulesResolved_ = cjsModulesResolved;
  }

                                                                               
                                                                        
                                                                     
  llvh::DenseSet<Function *> getFunctionsInSegment(uint32_t segment);

                                                                             
  uint32_t getTemplateObjectID(RawStringList &&rawStrings);

  bool isLowered() const {
    return isLowered_;
  }

  void setLowered(bool isLowered) {
    isLowered_ = isLowered;
  }

  inline iterator begin() {
    return FunctionList.begin();
  }
  inline iterator end() {
    return FunctionList.end();
  }
  inline reverse_iterator rbegin() {
    return FunctionList.rbegin();
  }
  inline reverse_iterator rend() {
    return FunctionList.rend();
  }
  inline const_iterator begin() const {
    return FunctionList.begin();
  }
  inline const_iterator end() const {
    return FunctionList.end();
  }
  inline const_reverse_iterator rbegin() const {
    return FunctionList.rbegin();
  }
  inline const_reverse_iterator rend() const {
    return FunctionList.rend();
  }
  inline size_t size() const {
    return FunctionList.size();
  }
  inline bool empty() const {
    return FunctionList.empty();
  }
  inline Function &front() {
    return FunctionList.front();
  }
  inline Function &back() {
    return FunctionList.back();
  }

  void viewGraph();
  void dump(llvh::raw_ostream &os = llvh::outs()) const;

  static bool classof(const Value *V) {
    return V->getKind() == ValueKind::ModuleKind;
  }

 private:
                                                                                
                                              
  void populateCJSModuleUseGraph();
};

Function *ScopeDesc::getFunction() const {
  assert(function_ && "function not set. Is this the initial scope?");
  return function_;
}

void ScopeDesc::setFunction(Function *F) {
  assert(!function_ && "Scopes shouldn't change functions.");
  function_ = F;
}

                                                       
static inline llvh::hash_code hash_value(Type V) {
  return V.hash();
}

}                        

namespace llvh {

raw_ostream &operator<<(raw_ostream &OS, const hermes::Type &T);

}                  

#endif

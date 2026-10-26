/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "llvh/ADT/SetVector.h"
#include "llvh/ADT/SmallString.h"
#include "llvh/Support/Casting.h"
#include "llvh/Support/ErrorHandling.h"
#include "llvh/Support/raw_ostream.h"

#include "hermes/AST/Context.h"
#include "hermes/IR/IR.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Utils/Dumper.h"

#include <set>
#include <type_traits>

#define INCLUDE_ALL_INSTRS

using namespace hermes;

                                                                            
#define QUOTE(X) #X
#define DEF_VALUE(CLASS, PARENT)                                           \
  static_assert(                                                           \
      std::is_base_of<PARENT, CLASS>::value,                               \
      QUOTE(CLASS) " should directly inherit from " QUOTE(PARENT));        \
  static_assert(                                                           \
      std::is_convertible<CLASS *, PARENT *>::value,                       \
      QUOTE(CLASS) " should publicly inherit from " QUOTE(PARENT));        \
  static_assert(                                                           \
      ValueKind::CLASS##Kind > ValueKind::First_##PARENT##Kind,            \
      QUOTE(CLASS) "Kind should be after First_" QUOTE(PARENT) "Kind");    \
  static_assert(                                                           \
      ValueKind::CLASS##Kind < ValueKind::Last_##PARENT##Kind,             \
      QUOTE(CLASS) "Kind should be before Last_" QUOTE(PARENT) "Kind");    \
  static_assert(                                                           \
      ValueKind::PARENT##Kind ==                                           \
          static_cast<ValueKind>(                                          \
              static_cast<unsigned>(ValueKind::First_##PARENT##Kind) + 1), \
      QUOTE(PARENT) "Kind should be right after First_" QUOTE(PARENT) "Kind");
#include "hermes/IR/ValueKinds.def"
#undef QUOTE

void Value::destroy(Value *V) {
  if (!V)
    return;

  switch (V->Kind) {
    default:
      llvm_unreachable("Invalid kind");
#define DEF_VALUE(XX, PARENT) \
  case ValueKind::XX##Kind:   \
    delete cast<XX>(V);       \
    break;
#include "hermes/IR/ValueKinds.def"
  }
}

llvh::StringRef Value::getKindStr() const {
  switch (Kind) {
    default:
      llvm_unreachable("Invalid kind");
#define DEF_VALUE(XX, PARENT) \
  case ValueKind::XX##Kind:   \
    return llvh::StringRef(#XX);
#include "hermes/IR/ValueKinds.def"
  }
}

const Value::UseListTy &Value::getUsers() const {
  return Users;
}

unsigned Value::getNumUsers() const {
  return Users.size();
}

bool Value::hasUsers() const {
  return Users.size();
}

bool Value::hasOneUser() const {
  return 1 == Users.size();
}

void Value::removeUse(Use U) {
  assert(Users.size() && "Removing a user from an empty list");
  assert(U.first == this && "Invalid user");

                                                                               
                                                                              
                                                                             
           
  Users[U.second] = Users.back();
  Users.pop_back();

                                                                           
                                    
  if (U.second != Users.size()) {
    Use oldUse = {this, static_cast<unsigned>(Users.size())};
    auto &operands = Users[U.second]->Operands;
    for (int i = 0, e = operands.size(); i < e; i++) {
      if (operands[i] == oldUse) {
        operands[i] = {this, U.second};
        return;
      }
    }
    llvm_unreachable("Can't find user in operand list");
  }
}

Value::Use Value::addUser(Instruction *Inst) {
  Users.push_back(Inst);
  return {this, static_cast<unsigned>(Users.size() - 1)};
}

void Value::replaceAllUsesWith(Value *Other) {
  if (this == Other) {
    return;
  }

                                                                                
                                                  
  while (Users.size()) {
    Users[Users.size() - 1]->replaceFirstOperandWith(this, Other);
  }
}

void Value::removeAllUses() {
                                                                              
                                                            
  while (Users.size()) {
    Users[Users.size() - 1]->eraseOperand(this);
  }
}

bool Value::hasUser(Value *other) {
  return std::find(Users.begin(), Users.end(), other) != Users.end();
}

ScopeDesc::~ScopeDesc() {
  for (ScopeDesc *inner : innerScopes_) {
    Value::destroy(inner);
  }

                        
  for (auto *v : variables_) {
    Value::destroy(v);
  }
}

bool ScopeDesc::isGlobalScope() const {
  return function_->isGlobalScope() &&
      function_->getFunctionScopeDesc() == this;
}

Function::Function(
    ValueKind kind,
    Module *parent,
    ScopeDesc *scopeDesc,
    Identifier originalName,
    DefinitionKind definitionKind,
    bool strictMode,
    SourceVisibility sourceVisibility,
    bool isGlobal,
    SMRange sourceRange,
    Function *insertBefore)
    : Value(kind),
      parent_(parent),
      isGlobal_(isGlobal),
      scopeDesc_(scopeDesc),
      originalOrInferredName_(originalName),
      definitionKind_(definitionKind),
      strictMode_(strictMode),
      SourceRange(sourceRange),
      sourceVisibility_(sourceVisibility),
      internalName_(parent->deriveUniqueInternalName(originalName)) {
  scopeDesc_->setFunction(this);
  if (insertBefore) {
    assert(insertBefore != this && "Cannot insert a function before itself!");
    assert(
        insertBefore->getParent() == parent &&
        "Function to insert before is from a different module!");
    parent->insert(insertBefore->getIterator(), this);
  } else {
    parent->push_back(this);
  }

                                           
  assert(originalName.isValid() && "Function originalName must be valid");
}

Function::~Function() {
                         
  for (auto *p : Parameters) {
    Value::destroy(p);
  }
  Value::destroy(thisParameter);
}

std::string Function::getDefinitionKindStr(bool isDescriptive) const {
  switch (definitionKind_) {
    case Function::DefinitionKind::ES5Function:
      return "function";
    case Function::DefinitionKind::ES6Constructor:
      return "constructor";
    case Function::DefinitionKind::ES6DerivedConstructor:
      return "derived constructor";
    case Function::DefinitionKind::ES6Arrow:
      return isDescriptive ? "arrow function" : "arrow";
    case Function::DefinitionKind::ES6Method:
      return "method";
    case Function::DefinitionKind::ES6AsyncGenerator:
      return "async generator";
  }
  assert(false && "Invalid DefinitionKind");
  return "function";
}

std::string Function::getDescriptiveDefinitionKindStr() const {
  return (isAnonymous() ? "anonymous " : "") + getDefinitionKindStr(true);
}

llvh::Optional<llvh::StringRef> Function::getSourceRepresentationStr() const {
  switch (getSourceVisibility()) {
    case SourceVisibility::ShowSource: {
                                              
      auto sourceRange = getSourceRange();
      assert(
          sourceRange.isValid() && "Function does not have source available");
      const auto sourceStart = sourceRange.Start.getPointer();
      llvh::StringRef strBuf{
          sourceStart, (size_t)(sourceRange.End.getPointer() - sourceStart)};
      return strBuf;
    }
    case SourceVisibility::HideSource:
    case SourceVisibility::Sensitive: {
                                                                               
                                                                           
        
                                                                               
                                                                               
                                                                         
                                                                          
                                                                              
                                                                           
      return llvh::StringRef("");
    }
    case SourceVisibility::Default:
    default: {
                                                                        
                                                                  
      return llvh::None;
    }
  }
}

BasicBlock::BasicBlock(Function *parent)
    : Value(ValueKind::BasicBlockKind), Parent(parent) {
  assert(Parent && "Invalid parent function");
  Parent->addBlock(this);
}

void BasicBlock::dump(llvh::raw_ostream &os) const {
  IRPrinter D(getParent()->getContext(), os);
  D.visit(*this);
}

void BasicBlock::printAsOperand(llvh::raw_ostream &OS, bool) const {
                                                                 
  size_t Num = (size_t)this;
  OS << "BB#" << std::to_string(Num);
}

void Instruction::dump(llvh::raw_ostream &os) const {
  IRPrinter D(getParent()->getContext(), os);
  D.visit(*this);
}

Instruction::Instruction(
    const Instruction *src,
    llvh::ArrayRef<Value *> operands)
    : Instruction(src->getKind()) {
  assert(
      src->getNumOperands() == operands.size() && "invalid number of operands");

  setType(src->getType());

  location_ = src->location_;
  statementIndex_ = src->statementIndex_;

  for (auto val : operands)
    pushOperand(val);
}

void Instruction::pushOperand(Value *Val) {
  Operands.push_back({nullptr, 0});
  setOperand(Val, getNumOperands() - 1);
}

void Instruction::setOperand(Value *Val, unsigned Index) {
  assert(Index < Operands.size() && "Not all operands have been pushed!");

  Value *CurrentValue = Operands[Index].first;

                                                                               
                                                        
  if (CurrentValue == Val) {
    return;
  }

                                                                            
  if (CurrentValue) {
    CurrentValue->removeUse(Operands[Index]);
  }

                                                                              
  if (Val) {
    Operands[Index] = Val->addUser(this);
  } else {
    Operands[Index] = {nullptr, 0};
  }
}

Value *Instruction::getOperand(unsigned Index) const {
  return Operands[Index].first;
}

unsigned Instruction::getNumOperands() const {
  return Operands.size();
}

void Instruction::removeOperand(unsigned index) {
                                                                         
                                              
  setOperand(nullptr, index);
  Operands.erase(Operands.begin() + index);
}

void Instruction::replaceFirstOperandWith(Value *OldValue, Value *NewValue) {
  for (int i = 0, e = getNumOperands(); i < e; i++) {
    if (OldValue == getOperand(i)) {
      setOperand(NewValue, i);
      return;
    }
  }
  llvm_unreachable("Can't find operand. Invalid use-def chain.");
}

void Instruction::eraseOperand(Value *Value) {
                                                                            
                                       
  for (int i = 0, e = getNumOperands(); i < e; ++i) {
    if (getOperand(i) == Value)
      setOperand(nullptr, i);
  }

                                                
  auto new_end = std::remove_if(
      Operands.begin(), Operands.end(), [](Use U) { return !U.first; });
  Operands.erase(new_end, Operands.end());

  assert(!Value->hasUser(this) && "corrupt uselist");
}

void Instruction::insertBefore(Instruction *InsertPos) {
  InsertPos->getParent()->getInstList().insert(InsertPos->getIterator(), this);
}

void Instruction::insertAfter(Instruction *InsertPos) {
  InsertPos->getParent()->getInstList().insertAfter(
      InsertPos->getIterator(), this);
}

void Instruction::moveBefore(Instruction *Later) {
  if (this == Later)
    return;

  getParent()->getInstList().remove(this);
  Later->getParent()->getInstList().insert(Later->getIterator(), this);
  setParent(Later->getParent());
}

void BasicBlock::remove(Instruction *I) {
  InstList.remove(I);
}
void BasicBlock::erase(Instruction *I) {
  InstList.erase(I);
}

void Instruction::removeFromParent() {
  getParent()->remove(this);
}
void Instruction::eraseFromParent() {
                                                                      
  for (unsigned i = 0; i < getNumOperands(); i++)
    setOperand(nullptr, i);

  getParent()->erase(this);
}

void Function::eraseFromParentNoDestroy() {
                                                                
  while (begin() != end()) {
    begin()->replaceAllUsesWith(nullptr);
    begin()->eraseFromParent();
  }
  assert(!hasUsers() && "Use list is not empty");
  getParent()->getFunctionList().remove(getIterator());
}

llvh::StringRef Instruction::getName() {
  switch (getKind()) {
    default:
      llvm_unreachable("Invalid kind");
#define DEF_VALUE(XX, PARENT) \
  case ValueKind::XX##Kind:   \
    return #XX;
#include "hermes/IR/Instrs.def"
  }
}

SideEffectKind Instruction::getDerivedSideEffect() {
  switch (getKind()) {
    default:
      llvm_unreachable("Invalid kind");
#define DEF_VALUE(XX, PARENT) \
  case ValueKind::XX##Kind:   \
    return cast<XX>(this)->getSideEffect();
#include "hermes/IR/Instrs.def"
  }
}

WordBitSet<> Instruction::getChangedOperands() {
  switch (getKind()) {
    default:
      llvm_unreachable("Invalid kind");

#define DEF_VALUE(XX, PARENT)                        \
  case ValueKind::XX##Kind:                          \
    return cast<XX>(this)->getChangedOperandsImpl(); \
    break;
#include "hermes/IR/Instrs.def"
  }
}

Parameter::Parameter(Function *parent, Identifier name, bool isThisParameter)
    : Value(ValueKind::ParameterKind), Parent(parent), Name(name) {
  assert(Parent && "Invalid parent");
  if (isThisParameter) {
    Parent->setThisParameter(this);
  } else {
    Parent->addParameter(this);
  }
}

Variable::Variable(
    ValueKind k,
    ScopeDesc *scope,
    DeclKind declKind,
    Identifier txt)
    : Value(k),
      declKind(declKind),
      text(txt),
      parent(scope),
      strictImmutableBinding_(declKind == DeclKind::Const) {
  scope->addVariable(this);
}

Variable::~Variable() {}

int Variable::getIndexInVariableList() const {
  int index = 0;
  for (auto V : parent->getVariables()) {
    if (V == this)
      return index;
    index++;
  }
  llvm_unreachable("Cannot find variable in the variable list");
}

Variable *Variable::cloneIntoNewScope(ScopeDesc *newScope) {
  Variable *clone = new Variable(parent, declKind, text);
  clone->strictImmutableBinding_ = strictImmutableBinding_;
  newScope->addVariable(clone);
  return clone;
}

Identifier Parameter::getName() const {
  return Name;
}

void BasicBlock::push_back(Instruction *I) {
  InstList.push_back(I);
}

TerminatorInst *BasicBlock::getTerminator() {
  if (InstList.empty())
    return nullptr;
  return llvh::dyn_cast<TerminatorInst>(&InstList.back());
}

const TerminatorInst *BasicBlock::getTerminator() const {
  if (InstList.empty())
    return nullptr;
  return llvh::dyn_cast<TerminatorInst>(&InstList.back());
}

void BasicBlock::removeFromParent() {
  getParent()->getBasicBlockList().remove(getIterator());
}

void BasicBlock::eraseFromParent() {
                                                                          
                                                                             
                                                                           
                                                                          
                              
  while (begin() != end()) {
    begin()->replaceAllUsesWith(nullptr);
    begin()->eraseFromParent();
  }

  assert(!hasUsers() && "Use list is not empty");
                            
  getParent()->getBasicBlockList().erase(getIterator());
}

Context &Function::getContext() const {
  return parent_->getContext();
}

void Function::addBlock(BasicBlock *BB) {
  BasicBlockList.push_back(BB);
}
void Function::addParameter(Parameter *A) {
  Parameters.push_back(A);
}

Module::~Module() {
  FunctionList.clear();

                            
  globalPropertyMap_.clear();
  for (auto *prop : globalPropertyList_) {
    Value::destroy(prop);
  }

  llvh::SmallVector<Literal *, 32> toDelete;

                          
                                                                         
                   
  for (auto &L : literalNumbers) {
    toDelete.push_back(&L);
  }
  for (auto &L : literalBigInts) {
    toDelete.push_back(&L);
  }
  for (auto &L : literalStrings) {
    toDelete.push_back(&L);
  }
                       
  for (auto *L : toDelete) {
    Value::destroy(L);
  }
}

void Module::push_back(Function *F) {
  FunctionList.push_back(F);
}

void Module::insert(iterator position, Function *F) {
  FunctionList.insert(position, F);
}

GlobalObjectProperty *Module::findGlobalProperty(Identifier name) {
  auto it = globalPropertyMap_.find(name);
  return it != globalPropertyMap_.end() ? it->second : nullptr;
}

GlobalObjectProperty *Module::addGlobalProperty(
    Identifier name,
    bool declared) {
  auto &ref = globalPropertyMap_[name];

  if (!ref) {
    ref = new GlobalObjectProperty(this, getLiteralString(name), declared);
    globalPropertyList_.push_back(ref);
  } else {
    ref->orDeclared(declared);
  }

  return ref;
}

void Module::eraseGlobalProperty(GlobalObjectProperty *prop) {
  globalPropertyMap_.erase(prop->getName()->getValue());
  auto it =
      std::find(globalPropertyList_.begin(), globalPropertyList_.end(), prop);
  if (it != globalPropertyList_.end()) {
    Value::destroy(*it);
    globalPropertyList_.erase(it);
  }
}

void Module::populateCJSModuleUseGraph() {
  if (!cjsModuleUseGraph_.empty()) {
    return;
  }

  for (Function &f : *this) {
    for (Instruction *user : f.getUsers()) {
                                                          
      cjsModuleUseGraph_[user->getParent()->getParent()].insert(&f);
    }
  }
}

llvh::DenseSet<Function *> Module::getFunctionsInSegment(uint32_t segment) {
  populateCJSModuleUseGraph();

                                                                              
  llvh::DenseSet<Function *> result{};

                                                                        
                                                                  
  llvh::SetVector<Function *> worklist{};

                                                                               
                          
  for (Function *fn : cjsModuleSegmentMap_[segment]) {
    worklist.insert(fn);
  }

  while (!worklist.empty()) {
    Function *cur = worklist.back();
    worklist.pop_back();
    if (result.count(cur)) {
                                                                                
                  
      continue;
    }
    result.insert(cur);
                                                       
    const auto targets = cjsModuleUseGraph_[cur];
    worklist.insert(targets.begin(), targets.end());
  }

  return result;
}

uint32_t Module::getTemplateObjectID(RawStringList &&rawStrings) {
                                                   
  auto res = templateObjectIDMap_.emplace(std::move(rawStrings), 0);
  if (res.second) {
                                                                    
    res.first->second = templateObjectIDMap_.size() - 1;
  }
  return res.first->second;
}

Context &Instruction::getContext() const {
  return Parent->getContext();
}
Context &BasicBlock::getContext() const {
  return Parent->getContext();
}
Context &Parameter::getContext() const {
  return Parent->getContext();
}

                                                          
bool Parameter::isThisParameter() const {
  return Parent->getThisParameter() == this;
}

int Parameter::getIndexInParamList() const {
  int index = 0;
  for (auto P : Parent->getParameters()) {
    if (P == this)
      return index;
    index++;
  }
  llvm_unreachable("Cannot find parameter in the function");
}

void Function::dump(llvh::raw_ostream &os) const {
  IRPrinter D(getParent()->getContext(), os);
  D.visit(*this);
}

void Function::viewGraph() {
  ::viewGraph(this);
}

                                                                             
                                      
static inline Identifier stripInternalNameSuffix(
    Context &context,
    Identifier originalName) {
  auto originalStr = originalName.str();
  auto e = originalStr.end();

  if (!(e - originalStr.begin() >= 3 && e[-1] == '#' && e[-2] >= '0' &&
        e[-2] <= '9')) {
    return originalName;
  }

  e -= 2;
  while (e != originalStr.begin() && e[-1] >= '0' && e[-1] <= '9') {
    --e;
  }

  if (!(e != originalStr.begin() && e[-1] == ' '))
    return originalName;

  --e;
  return context.getIdentifier(originalStr.slice(0, e - originalStr.begin()));
}

Identifier Module::deriveUniqueInternalName(Identifier originalName) {
  assert(originalName.isValid() && "originalName must be valid");

                                                                             
                             
  originalName = stripInternalNameSuffix(getContext(), originalName);

  auto insertResult = internalNamesMap_.try_emplace(originalName, 0);

                                                                   
  if (insertResult.second)
    return originalName;

                                                                            
                
  ++insertResult.first->second;
  char itoaBuf[16];
  snprintf(itoaBuf, sizeof(itoaBuf), "%u", insertResult.first->second);

  llvh::SmallString<32> buf;
  buf.append(originalName.str());
  buf.append(" ");
  buf.append(itoaBuf);
  buf.append("#");

  return getContext().getIdentifier(buf);
}

void Module::viewGraph() {
  for (auto &F : *this) {
    ::viewGraph(&F);
  }
}

void Module::dump(llvh::raw_ostream &os) const {
  IRPrinter D(getContext(), os);
  D.visit(*this);
}

LiteralNumber *Module::getLiteralNumber(double value) {
                                                          
  llvh::FoldingSetNodeID ID;

  LiteralNumber::Profile(ID, value);

                                                                              
  void *InsertPos = nullptr;
  if (LiteralNumber *LN = literalNumbers.FindNodeOrInsertPos(ID, InsertPos))
    return LN;

  auto New = new LiteralNumber(value);
  literalNumbers.InsertNode(New, InsertPos);
  return New;
}

LiteralBigInt *Module::getLiteralBigInt(UniqueString *value) {
                                                          
  llvh::FoldingSetNodeID ID;

  LiteralBigInt::Profile(ID, value);

                                                                              
  void *InsertPos = nullptr;
  if (LiteralBigInt *LN = literalBigInts.FindNodeOrInsertPos(ID, InsertPos))
    return LN;

  auto New = new LiteralBigInt(value);
  literalBigInts.InsertNode(New, InsertPos);
  return New;
}

LiteralString *Module::getLiteralString(Identifier value) {
                                                          
  llvh::FoldingSetNodeID ID;

  LiteralString::Profile(ID, value);

                                                                              
  void *InsertPos = nullptr;
  if (LiteralString *LS = literalStrings.FindNodeOrInsertPos(ID, InsertPos))
    return LS;

  auto New = new LiteralString(value);
  literalStrings.InsertNode(New, InsertPos);
  return New;
}

LiteralBool *Module::getLiteralBool(bool value) {
  if (value)
    return &literalTrue;
  return &literalFalse;
}

void Type::print(llvh::raw_ostream &OS) const {
  bool first = true;
  for (unsigned i = 0; i < (unsigned)Type::TypeKind::LAST_TYPE; i++) {
                                                                               
    if (i == (unsigned)Type::TypeKind::Object &&
        (isClosureType() || isRegExpType())) {
      continue;
    }

    if (bitmask_ & (1 << i)) {
      if (!first) {
        OS << "|";
      }

      OS << getKindStr((Type::TypeKind)i);
      first = false;
    }
  }
}

raw_ostream &llvh::operator<<(raw_ostream &OS, const hermes::Type &T) {
  T.print(OS);
  return OS;
}

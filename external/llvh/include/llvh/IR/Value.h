//===- llvm/Value.h - Definition of the Value class -------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the Value class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_VALUE_H
#define LLVM_IR_VALUE_H

#include "llvh-c/Types.h"
#include "llvh/ADT/iterator_range.h"
#include "llvh/IR/Use.h"
#include "llvh/Support/CBindingWrapping.h"
#include "llvh/Support/Casting.h"
#include <cassert>
#include <iterator>
#include <memory>

namespace llvh {

class APInt;
class Argument;
class BasicBlock;
class Constant;
class ConstantData;
class ConstantAggregate;
class DataLayout;
class Function;
class GlobalAlias;
class GlobalIFunc;
class GlobalIndirectSymbol;
class GlobalObject;
class GlobalValue;
class GlobalVariable;
class InlineAsm;
class Instruction;
class LLVMContext;
class Module;
class ModuleSlotTracker;
class raw_ostream;
template<typename ValueTy> class StringMapEntry;
class StringRef;
class Twine;
class Type;
class User;

using ValueName = StringMapEntry<Value *>;

                                                                                
                                              
                                                                                

                             
   
                                                                           
                                                                                
                                                                                
                                                                            
                                                                              
                                                    
   
                                                                           
                                                                               
                                                                     
                                      
class Value {
                                                                         
                                                                               
  Type *VTy;
  Use *UseList;

  friend class ValueAsMetadata;                               
  friend class ValueHandleBase;

  const unsigned char SubclassID;                                            
  unsigned char HasValueHandle : 1;                                       

protected:
                                             
     
                                                                       
                                                                         
                                                                    
  unsigned char SubclassOptionalData : 7;

private:
                                   
     
                                                                         
                                                                          
                                               
  unsigned short SubclassData;

protected:
                                             
     
                                                                      
                                                                           
          
     
                                                                            
                                                                         
               
     
                                                                            
                                                
  enum : unsigned { NumUserOperandsBits = 28 };
  unsigned NumUserOperands : NumUserOperandsBits;

                                                                         
  unsigned IsUsedByMD : 1;
  unsigned HasName : 1;
  unsigned HasHungOffUses : 1;
  unsigned HasDescriptor : 1;

private:
  template <typename UseT>                                
  class use_iterator_impl {
    friend class Value;

    UseT *U;

    explicit use_iterator_impl(UseT *u) : U(u) {}

  public:
    using iterator_category = std::forward_iterator_tag;
    using value_type = UseT *;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type *;
    using reference = value_type &;

    use_iterator_impl() : U() {}

    bool operator==(const use_iterator_impl &x) const { return U == x.U; }
    bool operator!=(const use_iterator_impl &x) const { return !operator==(x); }

    use_iterator_impl &operator++() {                
      assert(U && "Cannot increment end iterator!");
      U = U->getNext();
      return *this;
    }

    use_iterator_impl operator++(int) {                 
      auto tmp = *this;
      ++*this;
      return tmp;
    }

    UseT &operator*() const {
      assert(U && "Cannot dereference end iterator!");
      return *U;
    }

    UseT *operator->() const { return &operator*(); }

    operator use_iterator_impl<const UseT>() const {
      return use_iterator_impl<const UseT>(U);
    }
  };

  template <typename UserTy>                                    
  class user_iterator_impl {
    use_iterator_impl<Use> UI;
    explicit user_iterator_impl(Use *U) : UI(U) {}
    friend class Value;

  public:
    using iterator_category = std::forward_iterator_tag;
    using value_type = UserTy *;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type *;
    using reference = value_type &;

    user_iterator_impl() = default;

    bool operator==(const user_iterator_impl &x) const { return UI == x.UI; }
    bool operator!=(const user_iterator_impl &x) const { return !operator==(x); }

                                                                          
    bool atEnd() const { return *this == user_iterator_impl(); }

    user_iterator_impl &operator++() {                
      ++UI;
      return *this;
    }

    user_iterator_impl operator++(int) {                 
      auto tmp = *this;
      ++*this;
      return tmp;
    }

                                              
    UserTy *operator*() const {
      return UI->getUser();
    }

    UserTy *operator->() const { return operator*(); }

    operator user_iterator_impl<const UserTy>() const {
      return user_iterator_impl<const UserTy>(*UI);
    }

    Use &getUse() const { return *UI; }
  };

protected:
  Value(Type *Ty, unsigned scid);

                                                                            
                                                                         
                                                                             
                                                                        
                  
  ~Value();                                                

public:
  Value(const Value &) = delete;
  Value &operator=(const Value &) = delete;

                                          
  void deleteValue();

                                                       
  void dump() const;

                                    
        
  void print(raw_ostream &O, bool IsForDebug = false) const;
  void print(raw_ostream &O, ModuleSlotTracker &MST,
             bool IsForDebug = false) const;
        

                                                                    
     
                                                                       
                                                                              
                                                                        
                                      
        
  void printAsOperand(raw_ostream &O, bool PrintType = true,
                      const Module *M = nullptr) const;
  void printAsOperand(raw_ostream &O, bool PrintType,
                      ModuleSlotTracker &MST) const;
        

                                                       
  Type *getType() const { return VTy; }

                                                   
  LLVMContext &getContext() const;

                                         
  bool hasName() const { return HasName; }
  ValueName *getValueName() const;
  void setValueName(ValueName *VN);

private:
  void destroyValueName();
  enum class ReplaceMetadataUses { No, Yes };
  void doRAUW(Value *New, ReplaceMetadataUses);
  void setNameImpl(const Twine &Name);

public:
                                                      
     
                                                                              
                                                                               
               
  StringRef getName() const;

                                   
     
                                                             
     
                                                                            
  void setName(const Twine &Name);

                                             
     
                                                    
     
                                                  
  void takeName(Value *V);

                                                      
     
                                                                             
                                                                       
                             
  void replaceAllUsesWith(Value *V);

                                                               
     
                                                                             
                                                                              
  void replaceNonMetadataUsesWith(Value *V);

                                                                                
                                                                              
                                                                       
                                                                          
                               
  void replaceUsesOutsideBlock(Value *V, BasicBlock *BB);

                                                                          
                                                          
    
                                                                              
                  
                                                                      
                                                                            
                                                      
                                                                           
                        
  void assertModuleIsMaterializedImpl() const;
                                                                            
                                                                             
                                                                                
  void assertModuleIsMaterialized() const {
#ifndef NDEBUG
    assertModuleIsMaterializedImpl();
#endif
  }

  bool use_empty() const {
    assertModuleIsMaterialized();
    return UseList == nullptr;
  }

  bool materialized_use_empty() const {
    return UseList == nullptr;
  }

  using use_iterator = use_iterator_impl<Use>;
  using const_use_iterator = use_iterator_impl<const Use>;

  use_iterator materialized_use_begin() { return use_iterator(UseList); }
  const_use_iterator materialized_use_begin() const {
    return const_use_iterator(UseList);
  }
  use_iterator use_begin() {
    assertModuleIsMaterialized();
    return materialized_use_begin();
  }
  const_use_iterator use_begin() const {
    assertModuleIsMaterialized();
    return materialized_use_begin();
  }
  use_iterator use_end() { return use_iterator(); }
  const_use_iterator use_end() const { return const_use_iterator(); }
  iterator_range<use_iterator> materialized_uses() {
    return make_range(materialized_use_begin(), use_end());
  }
  iterator_range<const_use_iterator> materialized_uses() const {
    return make_range(materialized_use_begin(), use_end());
  }
  iterator_range<use_iterator> uses() {
    assertModuleIsMaterialized();
    return materialized_uses();
  }
  iterator_range<const_use_iterator> uses() const {
    assertModuleIsMaterialized();
    return materialized_uses();
  }

  bool user_empty() const {
    assertModuleIsMaterialized();
    return UseList == nullptr;
  }

  using user_iterator = user_iterator_impl<User>;
  using const_user_iterator = user_iterator_impl<const User>;

  user_iterator materialized_user_begin() { return user_iterator(UseList); }
  const_user_iterator materialized_user_begin() const {
    return const_user_iterator(UseList);
  }
  user_iterator user_begin() {
    assertModuleIsMaterialized();
    return materialized_user_begin();
  }
  const_user_iterator user_begin() const {
    assertModuleIsMaterialized();
    return materialized_user_begin();
  }
  user_iterator user_end() { return user_iterator(); }
  const_user_iterator user_end() const { return const_user_iterator(); }
  User *user_back() {
    assertModuleIsMaterialized();
    return *materialized_user_begin();
  }
  const User *user_back() const {
    assertModuleIsMaterialized();
    return *materialized_user_begin();
  }
  iterator_range<user_iterator> materialized_users() {
    return make_range(materialized_user_begin(), user_end());
  }
  iterator_range<const_user_iterator> materialized_users() const {
    return make_range(materialized_user_begin(), user_end());
  }
  iterator_range<user_iterator> users() {
    assertModuleIsMaterialized();
    return materialized_users();
  }
  iterator_range<const_user_iterator> users() const {
    assertModuleIsMaterialized();
    return materialized_users();
  }

                                                             
     
                                                                             
                                    
  bool hasOneUse() const {
    const_use_iterator I = use_begin(), E = use_end();
    if (I == E) return false;
    return ++I == E;
  }

                                                    
  bool hasNUses(unsigned N) const;

                                                    
     
                                                        
  bool hasNUsesOrMore(unsigned N) const;

                                                               
  bool isUsedInBasicBlock(const BasicBlock *BB) const;

                                                            
     
                                                                   
                                                  
  unsigned getNumUses() const;

                                                       
  void addUse(Use &U) { U.addToList(&UseList); }

                                
     
                                                                             
                                                                          
                                                                     
                     
  enum ValueTy {
#define HANDLE_VALUE(Name) Name##Val,
#include "llvh/IR/Value.def"

               
#define HANDLE_CONSTANT_MARKER(Marker, Constant) Marker = Constant##Val,
#include "llvh/IR/Value.def"
  };

                                                        
     
                                                                            
                                                                             
                                                                      
                                                 
                                                                  
                                                                               
                                                                              
                         
  unsigned getValueID() const {
    return SubclassID;
  }

                                                                  
     
                                                                       
  unsigned getRawSubclassOptionalData() const {
    return SubclassOptionalData;
  }

                                                       
  void clearSubclassOptionalData() {
    SubclassOptionalData = 0;
  }

                                            
  bool hasSameSubclassOptionalData(const Value *V) const {
    return SubclassOptionalData == V->SubclassOptionalData;
  }

                                                                        
  bool hasValueHandle() const { return HasValueHandle; }

                                                              
  bool isUsedByMetadata() const { return IsUsedByMD; }

                                                      
     
                                                                             
                           
  bool isSwiftError() const;

                                                          
     
                                                                              
                               
  const Value *stripPointerCasts() const;
  Value *stripPointerCasts() {
    return const_cast<Value *>(
                         static_cast<const Value *>(this)->stripPointerCasts());
  }

                                                                         
           
     
                                                                              
                                                                    
                     
  const Value *stripPointerCastsAndInvariantGroups() const;
  Value *stripPointerCastsAndInvariantGroups() {
    return const_cast<Value *>(
        static_cast<const Value *>(this)->stripPointerCastsAndInvariantGroups());
  }

                                                
     
                                                                              
                               
  const Value *stripPointerCastsNoFollowAliases() const;
  Value *stripPointerCastsNoFollowAliases() {
    return const_cast<Value *>(
          static_cast<const Value *>(this)->stripPointerCastsNoFollowAliases());
  }

                                                             
     
                                                                             
                               
  const Value *stripInBoundsConstantOffsets() const;
  Value *stripInBoundsConstantOffsets() {
    return const_cast<Value *>(
              static_cast<const Value *>(this)->stripInBoundsConstantOffsets());
  }

                                                                
     
                                                                            
                                                                          
                                                          
     
                                                                  
  const Value *stripAndAccumulateInBoundsConstantOffsets(const DataLayout &DL,
                                                         APInt &Offset) const;
  Value *stripAndAccumulateInBoundsConstantOffsets(const DataLayout &DL,
                                                   APInt &Offset) {
    return const_cast<Value *>(static_cast<const Value *>(this)
        ->stripAndAccumulateInBoundsConstantOffsets(DL, Offset));
  }

                                                
     
                                                                             
                               
  const Value *stripInBoundsOffsets() const;
  Value *stripInBoundsOffsets() {
    return const_cast<Value *>(
                      static_cast<const Value *>(this)->stripInBoundsOffsets());
  }

                                                                     
                    
     
                                                                               
                                                         
  uint64_t getPointerDereferenceableBytes(const DataLayout &DL,
                                          bool &CanBeNull) const;

                                                
     
                                                                         
                                                                          
  unsigned getPointerAlignment(const DataLayout &DL) const;

                                                                       
     
                                                                               
                                                                             
                                                                         
            
  const Value *DoPHITranslation(const BasicBlock *CurBB,
                                const BasicBlock *PredBB) const;
  Value *DoPHITranslation(const BasicBlock *CurBB, const BasicBlock *PredBB) {
    return const_cast<Value *>(
             static_cast<const Value *>(this)->DoPHITranslation(CurBB, PredBB));
  }

                                             
     
                                                                               
                                      
  static const unsigned MaxAlignmentExponent = 29;
  static const unsigned MaximumAlignment = 1u << MaxAlignmentExponent;

                                                                
     
                                                                         
                                                                             
                                                                          
            
  void mutateType(Type *Ty) {
    VTy = Ty;
  }

                        
     
                                                                         
                                                
  template <class Compare> void sortUseList(Compare Cmp);

                           
  void reverseUseList();

private:
                               
     
                                                                               
                                               
     
                                            
     
                                                                           
  template <class Compare>
  static Use *mergeUseLists(Use *L, Use *R, Compare Cmp) {
    Use *Merged;
    Use **Next = &Merged;

    while (true) {
      if (!L) {
        *Next = R;
        break;
      }
      if (!R) {
        *Next = L;
        break;
      }
      if (Cmp(*R, *L)) {
        *Next = R;
        Next = &R->Next;
        R = R->Next;
      } else {
        *Next = L;
        Next = &L->Next;
        L = L->Next;
      }
    }

    return Merged;
  }

protected:
  unsigned short getSubclassDataFromValue() const { return SubclassData; }
  void setValueSubclassData(unsigned short D) { SubclassData = D; }
};

struct ValueDeleter { void operator()(Value *V) { V->deleteValue(); } };

                                                                               
                                                                               
                                                          
using unique_value = std::unique_ptr<Value, ValueDeleter>;

inline raw_ostream &operator<<(raw_ostream &OS, const Value &V) {
  V.print(OS);
  return OS;
}

void Use::set(Value *V) {
  if (Val) removeFromList();
  Val = V;
  if (V) V->addUse(*this);
}

Value *Use::operator=(Value *RHS) {
  set(RHS);
  return RHS;
}

const Use &Use::operator=(const Use &RHS) {
  set(RHS.Val);
  return *this;
}

template <class Compare> void Value::sortUseList(Compare Cmp) {
  if (!UseList || !UseList->Next)
                                   
    return;

                                                                            
                            

                                                                              
                                
  const unsigned MaxSlots = 32;
  Use *Slots[MaxSlots];

                                                               
  Use *Next = UseList->Next;
  UseList->Next = nullptr;
  unsigned NumSlots = 1;
  Slots[0] = UseList;

                                  
  while (Next->Next) {
    Use *Current = Next;
    Next = Current->Next;

                                            
    Current->Next = nullptr;

                                                                       
    unsigned I;
    for (I = 0; I < NumSlots; ++I) {
      if (!Slots[I])
        break;

                                                                           
        
                                                                              
                                                                     
      Current = mergeUseLists(Slots[I], Current, Cmp);
      Slots[I] = nullptr;
    }
                                   
    if (I == NumSlots) {
      ++NumSlots;
      assert(NumSlots <= MaxSlots && "Use list bigger than 2^32");
    }

                          
    Slots[I] = Current;
  }

                                  
  assert(Next && "Expected one more Use");
  assert(!Next->Next && "Expected only one Use");
  UseList = Next;
  for (unsigned I = 0; I < NumSlots; ++I)
    if (Slots[I])
                                                                              
                                                                     
      UseList = mergeUseLists(Slots[I], UseList, Cmp);

                           
  for (Use *I = UseList, **Prev = &UseList; I; I = I->Next) {
    I->setPrev(Prev);
    Prev = &I->Next;
  }
}

                                                                             
                                                                        
  
template <> struct isa_impl<Constant, Value> {
  static inline bool doit(const Value &Val) {
    static_assert(Value::ConstantFirstVal == 0, "Val.getValueID() >= Value::ConstantFirstVal");
    return Val.getValueID() <= Value::ConstantLastVal;
  }
};

template <> struct isa_impl<ConstantData, Value> {
  static inline bool doit(const Value &Val) {
    return Val.getValueID() >= Value::ConstantDataFirstVal &&
           Val.getValueID() <= Value::ConstantDataLastVal;
  }
};

template <> struct isa_impl<ConstantAggregate, Value> {
  static inline bool doit(const Value &Val) {
    return Val.getValueID() >= Value::ConstantAggregateFirstVal &&
           Val.getValueID() <= Value::ConstantAggregateLastVal;
  }
};

template <> struct isa_impl<Argument, Value> {
  static inline bool doit (const Value &Val) {
    return Val.getValueID() == Value::ArgumentVal;
  }
};

template <> struct isa_impl<InlineAsm, Value> {
  static inline bool doit(const Value &Val) {
    return Val.getValueID() == Value::InlineAsmVal;
  }
};

template <> struct isa_impl<Instruction, Value> {
  static inline bool doit(const Value &Val) {
    return Val.getValueID() >= Value::InstructionVal;
  }
};

template <> struct isa_impl<BasicBlock, Value> {
  static inline bool doit(const Value &Val) {
    return Val.getValueID() == Value::BasicBlockVal;
  }
};

template <> struct isa_impl<Function, Value> {
  static inline bool doit(const Value &Val) {
    return Val.getValueID() == Value::FunctionVal;
  }
};

template <> struct isa_impl<GlobalVariable, Value> {
  static inline bool doit(const Value &Val) {
    return Val.getValueID() == Value::GlobalVariableVal;
  }
};

template <> struct isa_impl<GlobalAlias, Value> {
  static inline bool doit(const Value &Val) {
    return Val.getValueID() == Value::GlobalAliasVal;
  }
};

template <> struct isa_impl<GlobalIFunc, Value> {
  static inline bool doit(const Value &Val) {
    return Val.getValueID() == Value::GlobalIFuncVal;
  }
};

template <> struct isa_impl<GlobalIndirectSymbol, Value> {
  static inline bool doit(const Value &Val) {
    return isa<GlobalAlias>(Val) || isa<GlobalIFunc>(Val);
  }
};

template <> struct isa_impl<GlobalValue, Value> {
  static inline bool doit(const Value &Val) {
    return isa<GlobalObject>(Val) || isa<GlobalIndirectSymbol>(Val);
  }
};

template <> struct isa_impl<GlobalObject, Value> {
  static inline bool doit(const Value &Val) {
    return isa<GlobalVariable>(Val) || isa<Function>(Val);
  }
};

                                                                
DEFINE_ISA_CONVERSION_FUNCTIONS(Value, LLVMValueRef)

                                        
inline Value **unwrap(LLVMValueRef *Vals) {
  return reinterpret_cast<Value**>(Vals);
}

template<typename T>
inline T **unwrap(LLVMValueRef *Vals, unsigned Length) {
#ifndef NDEBUG
  for (LLVMValueRef *I = Vals, *E = Vals + Length; I != E; ++I)
    unwrap<T>(*I);                                                       
#endif
  (void)Length;
  return reinterpret_cast<T**>(Vals);
}

inline LLVMValueRef *wrap(const Value **Vals) {
  return reinterpret_cast<LLVMValueRef*>(const_cast<Value**>(Vals));
}

}                      

#endif                   

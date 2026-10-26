//===- llvm/User.h - User class definition ----------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This class defines the interface that one who uses a Value must implement.
// Each instance of the Value class keeps track of what User's have handles
// to it.
//
//  * Instructions are the largest class of Users.
//  * Constants may be users of other constants (think arrays and stuff)
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_USER_H
#define LLVM_IR_USER_H

#include "llvh/ADT/iterator.h"
#include "llvh/ADT/iterator_range.h"
#include "llvh/IR/Use.h"
#include "llvh/IR/Value.h"
#include "llvh/Support/Casting.h"
#include "llvh/Support/Compiler.h"
#include "llvh/Support/ErrorHandling.h"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iterator>

namespace llvh {

template <typename T> class ArrayRef;
template <typename T> class MutableArrayRef;

                                                
   
                                                        
template <class>
struct OperandTraits;

class User : public Value {
  template <unsigned>
  friend struct HungoffOperandTraits;

  LLVM_ATTRIBUTE_ALWAYS_INLINE inline static void *
  allocateFixedOperandUser(size_t, unsigned, unsigned);

protected:
                                                           
     
                                                                          
                                       
  void *operator new(size_t Size);

                                                     
     
                                                                        
  void *operator new(size_t Size, unsigned Us);

                                                                               
                                                                            
                                                     
     
                                                                       
                                                             
     
                                                                        
  void *operator new(size_t Size, unsigned Us, unsigned DescBytes);

  User(Type *ty, unsigned vty, Use *, unsigned NumOps)
      : Value(ty, vty) {
    assert(NumOps < (1u << NumUserOperandsBits) && "Too many operands");
    NumUserOperands = NumOps;
                                                                          
            
    assert((!HasHungOffUses || !getOperandList()) &&
           "Error in initializing hung off uses for User");
  }

                                                       
                                        
                                                                        
                                          
  void allocHungoffUses(unsigned N, bool IsPhi = false);

                                                                   
                                            
  void growHungoffUses(unsigned N, bool IsPhi = false);

protected:
  ~User() = default;                                                      

public:
  User(const User &) = delete;

                                                     
  void operator delete(void *Usr);
                                                                    
  void operator delete(void *Usr, unsigned) {
                                                                                         
                                                                                         
                                                                                             
                                       
    User::operator delete(Usr);

#ifndef LLVM_ENABLE_EXCEPTIONS
    llvm_unreachable("Constructor throws?");
#endif
  }
                                                                    
  void operator delete(void *Usr, unsigned, bool) {
                                                                                         
                                                                                         
                                                                                             
                                       
    User::operator delete(Usr);

#ifndef LLVM_ENABLE_EXCEPTIONS
    llvm_unreachable("Constructor throws?");
#endif
  }

protected:
  template <int Idx, typename U> static Use &OpFrom(const U *that) {
    return Idx < 0
      ? OperandTraits<U>::op_end(const_cast<U*>(that))[Idx]
      : OperandTraits<U>::op_begin(const_cast<U*>(that))[Idx];
  }

  template <int Idx> Use &Op() {
    return OpFrom<Idx>(this);
  }
  template <int Idx> const Use &Op() const {
    return OpFrom<Idx>(this);
  }

private:
  const Use *getHungOffOperands() const {
    return *(reinterpret_cast<const Use *const *>(this) - 1);
  }

  Use *&getHungOffOperands() { return *(reinterpret_cast<Use **>(this) - 1); }

  const Use *getIntrusiveOperands() const {
    return reinterpret_cast<const Use *>(this) - NumUserOperands;
  }

  Use *getIntrusiveOperands() {
    return reinterpret_cast<Use *>(this) - NumUserOperands;
  }

  void setOperandList(Use *NewList) {
    assert(HasHungOffUses &&
           "Setting operand list only required for hung off uses");
    getHungOffOperands() = NewList;
  }

public:
  const Use *getOperandList() const {
    return HasHungOffUses ? getHungOffOperands() : getIntrusiveOperands();
  }
  Use *getOperandList() {
    return const_cast<Use *>(static_cast<const User *>(this)->getOperandList());
  }

  Value *getOperand(unsigned i) const {
    assert(i < NumUserOperands && "getOperand() out of range!");
    return getOperandList()[i];
  }

  void setOperand(unsigned i, Value *Val) {
    assert(i < NumUserOperands && "setOperand() out of range!");
    assert((!isa<Constant>((const Value*)this) ||
            isa<GlobalValue>((const Value*)this)) &&
           "Cannot mutate a constant with setOperand!");
    getOperandList()[i] = Val;
  }

  const Use &getOperandUse(unsigned i) const {
    assert(i < NumUserOperands && "getOperandUse() out of range!");
    return getOperandList()[i];
  }
  Use &getOperandUse(unsigned i) {
    assert(i < NumUserOperands && "getOperandUse() out of range!");
    return getOperandList()[i];
  }

  unsigned getNumOperands() const { return NumUserOperands; }

                                                                  
  ArrayRef<const uint8_t> getDescriptor() const;

                                                                  
  MutableArrayRef<uint8_t> getDescriptor();

                                                     
     
                                                                      
                            
     
                                                                        
                                                                              
                              
  void setGlobalVariableNumOperands(unsigned NumOps) {
    assert(NumOps <= 1 && "GlobalVariable can only have 0 or 1 operands");
    NumUserOperands = NumOps;
  }

                                                                    
                                                                               
                                                                          
  void setNumHungOffUseOperands(unsigned NumOps) {
    assert(HasHungOffUses && "Must have hung off uses to use this method");
    assert(NumOps < (1u << NumUserOperandsBits) && "Too many operands");
    NumUserOperands = NumOps;
  }

                                                                                
                                  
    
  using op_iterator = Use*;
  using const_op_iterator = const Use*;
  using op_range = iterator_range<op_iterator>;
  using const_op_range = iterator_range<const_op_iterator>;

  op_iterator       op_begin()       { return getOperandList(); }
  const_op_iterator op_begin() const { return getOperandList(); }
  op_iterator       op_end()         {
    return getOperandList() + NumUserOperands;
  }
  const_op_iterator op_end()   const {
    return getOperandList() + NumUserOperands;
  }
  op_range operands() {
    return op_range(op_begin(), op_end());
  }
  const_op_range operands() const {
    return const_op_range(op_begin(), op_end());
  }

                                                              
  struct value_op_iterator
      : iterator_adaptor_base<value_op_iterator, op_iterator,
                              std::random_access_iterator_tag, Value *,
                              ptrdiff_t, Value *, Value *> {
    explicit value_op_iterator(Use *U = nullptr) : iterator_adaptor_base(U) {}

    Value *operator*() const { return *I; }
    Value *operator->() const { return operator*(); }
  };

  value_op_iterator value_op_begin() {
    return value_op_iterator(op_begin());
  }
  value_op_iterator value_op_end() {
    return value_op_iterator(op_end());
  }
  iterator_range<value_op_iterator> operand_values() {
    return make_range(value_op_begin(), value_op_end());
  }

  struct const_value_op_iterator
      : iterator_adaptor_base<const_value_op_iterator, const_op_iterator,
                              std::random_access_iterator_tag, const Value *,
                              ptrdiff_t, const Value *, const Value *> {
    explicit const_value_op_iterator(const Use *U = nullptr) :
      iterator_adaptor_base(U) {}

    const Value *operator*() const { return *I; }
    const Value *operator->() const { return operator*(); }
  };

  const_value_op_iterator value_op_begin() const {
    return const_value_op_iterator(op_begin());
  }
  const_value_op_iterator value_op_end() const {
    return const_value_op_iterator(op_end());
  }
  iterator_range<const_value_op_iterator> operand_values() const {
    return make_range(value_op_begin(), value_op_end());
  }

                                      
     
                                                                              
                                                                           
                                                                          
                                                                             
                                                                             
                                              
  void dropAllReferences() {
    for (Use &U : operands())
      U.set(nullptr);
  }

                                             
     
                                                                             
                      
  void replaceUsesOfWith(Value *From, Value *To);

                                                                      
  static bool classof(const Value *V) {
    return isa<Instruction>(V) || isa<Constant>(V);
  }
};

                                                                 
static_assert(alignof(Use) >= alignof(User),
              "Alignment is insufficient after objects prepended to User");
static_assert(alignof(Use *) >= alignof(User),
              "Alignment is insufficient after objects prepended to User");

template<> struct simplify_type<User::op_iterator> {
  using SimpleType = Value*;

  static SimpleType getSimplifiedValue(User::op_iterator &Val) {
    return Val->get();
  }
};
template<> struct simplify_type<User::const_op_iterator> {
  using SimpleType =           Value*;

  static SimpleType getSimplifiedValue(User::const_op_iterator &Val) {
    return Val->get();
  }
};

}                      

#endif                  

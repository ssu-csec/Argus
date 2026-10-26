//===-- llvm/Constants.h - Constant class subclass definitions --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
/// @file
/// This file contains the declarations for the subclasses of Constant,
/// which represent the different flavors of constant values that live in LLVM.
/// Note that Constants are immutable (once created they never change) and are
/// fully shared by structural equivalence.  This means that two structurally
/// equivalent constants will always have the same address.  Constants are
/// created on demand as needed and never deleted: thus clients don't have to
/// worry about the lifetime of the objects.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_CONSTANTS_H
#define LLVM_IR_CONSTANTS_H

#include "llvh/ADT/APFloat.h"
#include "llvh/ADT/APInt.h"
#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/None.h"
#include "llvh/ADT/Optional.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/IR/Constant.h"
#include "llvh/IR/DerivedTypes.h"
#include "llvh/IR/OperandTraits.h"
#include "llvh/IR/User.h"
#include "llvh/IR/Value.h"
#include "llvh/Support/Casting.h"
#include "llvh/Support/Compiler.h"
#include "llvh/Support/ErrorHandling.h"
#include <cassert>
#include <cstddef>
#include <cstdint>

namespace llvh {

class ArrayType;
class IntegerType;
class PointerType;
class SequentialType;
class StructType;
class VectorType;
template <class ConstantClass> struct ConstantAggrKeyType;

                                              
   
                                                                         
                                                                         
                                                     
class ConstantData : public Constant {
  friend class Constant;

  Value *handleOperandChangeImpl(Value *From, Value *To) {
    llvm_unreachable("Constant data does not have operands!");
  }

protected:
  explicit ConstantData(Type *Ty, ValueTy VT) : Constant(Ty, VT, nullptr, 0) {}

  void *operator new(size_t s) { return User::operator new(s, 0); }

public:
  ConstantData(const ConstantData &) = delete;

                                                                      
  static bool classof(const Value *V) {
    return V->getValueID() >= ConstantDataFirstVal &&
           V->getValueID() <= ConstantDataLastVal;
  }
};

                                                                                
                                                                         
                                                   
                                
class ConstantInt final : public ConstantData {
  friend class Constant;

  APInt Val;

  ConstantInt(IntegerType *Ty, const APInt& V);

  void destroyConstantImpl();

public:
  ConstantInt(const ConstantInt &) = delete;

  static ConstantInt *getTrue(LLVMContext &Context);
  static ConstantInt *getFalse(LLVMContext &Context);
  static Constant *getTrue(Type *Ty);
  static Constant *getFalse(Type *Ty);

                                                                         
                                                                
  static Constant *get(Type *Ty, uint64_t V, bool isSigned = false);

                                                                             
                                                                              
                                                                            
                                                                        
               
                                             
  static ConstantInt *get(IntegerType *Ty, uint64_t V,
                          bool isSigned = false);

                                                                               
                                                                             
                                                                              
                                   
                                                    
  static ConstantInt *getSigned(IntegerType *Ty, int64_t V);
  static Constant *getSigned(Type *Ty, int64_t V);

                                                                            
                                                                              
  static ConstantInt *get(LLVMContext &Context, const APInt &V);

                                                                              
            
  static ConstantInt *get(IntegerType *Ty, StringRef Str,
                          uint8_t radix);

                                                                         
                                                                
  static Constant *get(Type* Ty, const APInt& V);

                                                                             
                                                
                                  
  inline const APInt &getValue() const {
    return Val;
  }

                                                         
  unsigned getBitWidth() const { return Val.getBitWidth(); }

                                                                     
                                                                               
                                                                       
                                     
  inline uint64_t getZExtValue() const {
    return Val.getZExtValue();
  }

                                                                          
                                                                      
                                                                  
                                     
  inline int64_t getSExtValue() const {
    return Val.getSExtValue();
  }

                                                                             
                                                                            
                                                                 
                                                                     
  bool equalsInt(uint64_t V) const {
    return Val == V;
  }

                                                                                
                                                                          
     
  inline IntegerType *getType() const {
    return cast<IntegerType>(Value::getType());
  }

                                                                     
                                                                            
                                                                            
                                                                            
                                                                           
                                                                           
                                                                 
                                                     
                                                            
  static bool isValueValidForType(Type *Ty, uint64_t V);
  static bool isValueValidForType(Type *Ty, int64_t V);

  bool isNegative() const { return Val.isNegative(); }

                                                                         
                                                                        
                                                     
  bool isZero() const {
    return Val.isNullValue();
  }

                                                                         
                                                                        
                                                     
                                    
  bool isOne() const {
    return Val.isOneValue();
  }

                                                                          
              
                                                                 
                                         
  bool isMinusOne() const {
    return Val.isAllOnesValue();
  }

                                                                             
                                                           
                                                                         
                   
                                        
  bool isMaxValue(bool isSigned) const {
    if (isSigned)
      return Val.isMaxSignedValue();
    else
      return Val.isMaxValue();
  }

                                                                              
                                                            
                                                                            
                
                                        
  bool isMinValue(bool isSigned) const {
    if (isSigned)
      return Val.isMinSignedValue();
    else
      return Val.isMinValue();
  }

                                                                              
                                                                                
            
                                                                              
                                                                     
  bool uge(uint64_t Num) const {
    return Val.uge(Num);
  }

                                                                         
                                                                         
                               
                                                                           
                                                      
  uint64_t getLimitedValue(uint64_t Limit = ~0ULL) const {
    return Val.getLimitedValue(Limit);
  }

                                                                      
  static bool classof(const Value *V) {
    return V->getValueID() == ConstantIntVal;
  }
};

                                                                                
                                                      
   
class ConstantFP final : public ConstantData {
  friend class Constant;

  APFloat Val;

  ConstantFP(Type *Ty, const APFloat& V);

  void destroyConstantImpl();

public:
  ConstantFP(const ConstantFP &) = delete;

                                                                            
                                                                            
                                                                           
  static Constant *getZeroValueForNegation(Type *Ty);

                                                                                
                                                                             
                                                                               
                                           
  static Constant *get(Type* Ty, double V);

                                                                         
                                                               
  static Constant *get(Type *Ty, const APFloat &V);

  static Constant *get(Type* Ty, StringRef Str);
  static ConstantFP *get(LLVMContext &Context, const APFloat &V);
  static Constant *getNaN(Type *Ty, bool Negative = false, unsigned type = 0);
  static Constant *getNegativeZero(Type *Ty);
  static Constant *getInfinity(Type *Ty, bool Negative = false);

                                                     
  static bool isValueValidForType(Type *Ty, const APFloat &V);
  inline const APFloat &getValueAPF() const { return Val; }

                                                            
  bool isZero() const { return Val.isZero(); }

                                         
  bool isNegative() const { return Val.isNegative(); }

                                          
  bool isInfinity() const { return Val.isInfinity(); }

                                        
  bool isNaN() const { return Val.isNaN(); }

                                                                              
                                                               
                                                                               
                                                                               
                                                                             
                                   
  bool isExactlyValue(const APFloat &V) const;

  bool isExactlyValue(double V) const {
    bool ignored;
    APFloat FV(V);
    FV.convert(Val.getSemantics(), APFloat::rmNearestTiesToEven, &ignored);
    return isExactlyValue(FV);
  }

                                                                       
  static bool classof(const Value *V) {
    return V->getValueID() == ConstantFPVal;
  }
};

                                                                                
                            
   
class ConstantAggregateZero final : public ConstantData {
  friend class Constant;

  explicit ConstantAggregateZero(Type *Ty)
      : ConstantData(Ty, ConstantAggregateZeroVal) {}

  void destroyConstantImpl();

public:
  ConstantAggregateZero(const ConstantAggregateZero &) = delete;

  static ConstantAggregateZero *get(Type *Ty);

                                                                                
           
  Constant *getSequentialElement() const;

                                                                                
                            
  Constant *getStructElement(unsigned Elt) const;

                                                                             
                                                          
  Constant *getElementValue(Constant *C) const;

                                                                   
  Constant *getElementValue(unsigned Idx) const;

                                                                    
  unsigned getNumElements() const;

                                                                       
     
  static bool classof(const Value *V) {
    return V->getValueID() == ConstantAggregateZeroVal;
  }
};

                                                       
   
                                                                          
             
   
                                                              
                   
   
                                                                           
                                                                               
                 
class ConstantAggregate : public Constant {
protected:
  ConstantAggregate(CompositeType *T, ValueTy VT, ArrayRef<Constant *> V);

public:
                                                              
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Constant);

                                                                       
  static bool classof(const Value *V) {
    return V->getValueID() >= ConstantAggregateFirstVal &&
           V->getValueID() <= ConstantAggregateLastVal;
  }
};

template <>
struct OperandTraits<ConstantAggregate>
    : public VariadicOperandTraits<ConstantAggregate> {};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(ConstantAggregate, Constant)

                                                                                
                                               
   
class ConstantArray final : public ConstantAggregate {
  friend struct ConstantAggrKeyType<ConstantArray>;
  friend class Constant;

  ConstantArray(ArrayType *T, ArrayRef<Constant *> Val);

  void destroyConstantImpl();
  Value *handleOperandChangeImpl(Value *From, Value *To);

public:
                            
  static Constant *get(ArrayType *T, ArrayRef<Constant*> V);

private:
  static Constant *getImpl(ArrayType *T, ArrayRef<Constant *> V);

public:
                                                                    
                                                                          
  inline ArrayType *getType() const {
    return cast<ArrayType>(Value::getType());
  }

                                                                       
  static bool classof(const Value *V) {
    return V->getValueID() == ConstantArrayVal;
  }
};

                                                                                
                               
  
class ConstantStruct final : public ConstantAggregate {
  friend struct ConstantAggrKeyType<ConstantStruct>;
  friend class Constant;

  ConstantStruct(StructType *T, ArrayRef<Constant *> Val);

  void destroyConstantImpl();
  Value *handleOperandChangeImpl(Value *From, Value *To);

public:
                             
  static Constant *get(StructType *T, ArrayRef<Constant*> V);

  template <typename... Csts>
  static typename std::enable_if<are_base_of<Constant, Csts...>::value,
                                 Constant *>::type
  get(StructType *T, Csts *... Vs) {
    SmallVector<Constant *, 8> Values({Vs...});
    return get(T, Values);
  }

                                                                 
                                                                       
  static Constant *getAnon(ArrayRef<Constant*> V, bool Packed = false) {
    return get(getTypeForElements(V, Packed), V);
  }
  static Constant *getAnon(LLVMContext &Ctx,
                           ArrayRef<Constant*> V, bool Packed = false) {
    return get(getTypeForElements(Ctx, V, Packed), V);
  }

                                                                              
                                                  
  static StructType *getTypeForElements(ArrayRef<Constant*> V,
                                        bool Packed = false);
                                                      
  static StructType *getTypeForElements(LLVMContext &Ctx,
                                        ArrayRef<Constant*> V,
                                        bool Packed = false);

                                                
  inline StructType *getType() const {
    return cast<StructType>(Value::getType());
  }

                                                                       
  static bool classof(const Value *V) {
    return V->getValueID() == ConstantStructVal;
  }
};

                                                                                
                                
   
class ConstantVector final : public ConstantAggregate {
  friend struct ConstantAggrKeyType<ConstantVector>;
  friend class Constant;

  ConstantVector(VectorType *T, ArrayRef<Constant *> Val);

  void destroyConstantImpl();
  Value *handleOperandChangeImpl(Value *From, Value *To);

public:
                             
  static Constant *get(ArrayRef<Constant*> V);

private:
  static Constant *getImpl(ArrayRef<Constant *> V);

public:
                                                                          
  static Constant *getSplat(unsigned NumElts, Constant *Elt);

                                                                    
                                                                          
  inline VectorType *getType() const {
    return cast<VectorType>(Value::getType());
  }

                                                                            
                                                           
  Constant *getSplatValue() const;

                                                                       
  static bool classof(const Value *V) {
    return V->getValueID() == ConstantVectorVal;
  }
};

                                                                                
                                                
   
class ConstantPointerNull final : public ConstantData {
  friend class Constant;

  explicit ConstantPointerNull(PointerType *T)
      : ConstantData(T, Value::ConstantPointerNullVal) {}

  void destroyConstantImpl();

public:
  ConstantPointerNull(const ConstantPointerNull &) = delete;

                                                                    
  static ConstantPointerNull *get(PointerType *T);

                                                                      
                                                                          
  inline PointerType *getType() const {
    return cast<PointerType>(Value::getType());
  }

                                                                       
  static bool classof(const Value *V) {
    return V->getValueID() == ConstantPointerNullVal;
  }
};

                                                                                
                                                                               
                                                                            
                                                                                
                                                                             
                                        
   
                                                                              
   
class ConstantDataSequential : public ConstantData {
  friend class LLVMContextImpl;
  friend class Constant;

                                                                            
                          
  const char *DataElements;

                                                                      
                                                                           
                                                                               
                                           
  ConstantDataSequential *Next;

  void destroyConstantImpl();

protected:
  explicit ConstantDataSequential(Type *ty, ValueTy VT, const char *Data)
      : ConstantData(ty, VT), DataElements(Data), Next(nullptr) {}
  ~ConstantDataSequential() { delete Next; }

  static Constant *getImpl(StringRef Bytes, Type *Ty);

public:
  ConstantDataSequential(const ConstantDataSequential &) = delete;

                                                                            
                                          
                                                                           
                                                                    
  static bool isElementTypeCompatible(Type *Ty);

                                                                             
                                                      
  uint64_t getElementAsInteger(unsigned i) const;

                                                                             
                                    
  APInt getElementAsAPInt(unsigned i) const;

                                                                          
                                      
  APFloat getElementAsAPFloat(unsigned i) const;

                                                                                
                 
  float getElementAsFloat(unsigned i) const;

                                                                         
                          
  double getElementAsDouble(unsigned i) const;

                                                        
                                                                            
                                                    
  Constant *getElementAsConstant(unsigned i) const;

                                                                              
                                                                    
  inline SequentialType *getType() const {
    return cast<SequentialType>(Value::getType());
  }

                                                  
  Type *getElementType() const;

                                                           
  unsigned getNumElements() const;

                                                                     
                                                                     
  uint64_t getElementByteSize() const;

                                                                           
  bool isString(unsigned CharSize = 8) const;

                                                                              
                                                 
  bool isCString() const;

                                                                          
                                           
  StringRef getAsString() const {
    assert(isString() && "Not a string");
    return getRawDataValues();
  }

                                                                               
                                                                        
  StringRef getAsCString() const {
    assert(isCString() && "Isn't a C string");
    StringRef Str = getAsString();
    return Str.substr(0, Str.size()-1);
  }

                                                                          
                                                                               
                        
  StringRef getRawDataValues() const;

                                                                       
  static bool classof(const Value *V) {
    return V->getValueID() == ConstantDataArrayVal ||
           V->getValueID() == ConstantDataVectorVal;
  }

private:
  const char *getElementPointer(unsigned Elt) const;
};

                                                                                
                                                                            
                                                                
                                                                                
                                                                              
                   
class ConstantDataArray final : public ConstantDataSequential {
  friend class ConstantDataSequential;

  explicit ConstantDataArray(Type *ty, const char *Data)
      : ConstantDataSequential(ty, ConstantDataArrayVal, Data) {}

public:
  ConstantDataArray(const ConstantDataArray &) = delete;

                                                                           
                                                                             
                                                
  template <typename ElementTy>
  static Constant *get(LLVMContext &Context, ArrayRef<ElementTy> Elts) {
    const char *Data = reinterpret_cast<const char *>(Elts.data());
    return getRaw(StringRef(Data, Elts.size() * sizeof(ElementTy)), Elts.size(),
                  Type::getScalarTy<ElementTy>(Context));
  }

                                                             
                                                                       
  template <typename ArrayTy>
  static Constant *get(LLVMContext &Context, ArrayTy &Elts) {
    return ConstantDataArray::get(Context, makeArrayRef(Elts));
  }

                                                                           
                                                                              
                                                                          
                                                                           
                                                                           
                                                      
  static Constant *getRaw(StringRef Data, uint64_t NumElements, Type *ElementTy) {
    Type *Ty = ArrayType::get(ElementTy, NumElements);
    return getImpl(Data, Ty);
  }

                                                                              
                                                                           
                                                                              
                                                                          
             
  static Constant *getFP(LLVMContext &Context, ArrayRef<uint16_t> Elts);
  static Constant *getFP(LLVMContext &Context, ArrayRef<uint32_t> Elts);
  static Constant *getFP(LLVMContext &Context, ArrayRef<uint64_t> Elts);

                                                                         
                                                                      
                                                                               
                                                                              
                               
  static Constant *getString(LLVMContext &Context, StringRef Initializer,
                             bool AddNull = true);

                                                                    
                                                                          
  inline ArrayType *getType() const {
    return cast<ArrayType>(Value::getType());
  }

                                                                       
  static bool classof(const Value *V) {
    return V->getValueID() == ConstantDataArrayVal;
  }
};

                                                                                
                                                                            
                                                                
                                                                                
                                                                              
                   
class ConstantDataVector final : public ConstantDataSequential {
  friend class ConstantDataSequential;

  explicit ConstantDataVector(Type *ty, const char *Data)
      : ConstantDataSequential(ty, ConstantDataVectorVal, Data) {}

public:
  ConstantDataVector(const ConstantDataVector &) = delete;

                                                                             
                                                                             
                                                
  static Constant *get(LLVMContext &Context, ArrayRef<uint8_t> Elts);
  static Constant *get(LLVMContext &Context, ArrayRef<uint16_t> Elts);
  static Constant *get(LLVMContext &Context, ArrayRef<uint32_t> Elts);
  static Constant *get(LLVMContext &Context, ArrayRef<uint64_t> Elts);
  static Constant *get(LLVMContext &Context, ArrayRef<float> Elts);
  static Constant *get(LLVMContext &Context, ArrayRef<double> Elts);

                                                                               
                                                                               
                                                                               
                                                                          
             
  static Constant *getFP(LLVMContext &Context, ArrayRef<uint16_t> Elts);
  static Constant *getFP(LLVMContext &Context, ArrayRef<uint32_t> Elts);
  static Constant *getFP(LLVMContext &Context, ArrayRef<uint64_t> Elts);

                                                                          
                                                                      
                                                                    
  static Constant *getSplat(unsigned NumElts, Constant *Elt);

                                                                              
                     
  bool isSplat() const;

                                                                            
                                                           
  Constant *getSplatValue() const;

                                                                    
                                                                          
  inline VectorType *getType() const {
    return cast<VectorType>(Value::getType());
  }

                                                                       
  static bool classof(const Value *V) {
    return V->getValueID() == ConstantDataVectorVal;
  }
};

                                                                                
                                   
   
class ConstantTokenNone final : public ConstantData {
  friend class Constant;

  explicit ConstantTokenNone(LLVMContext &Context)
      : ConstantData(Type::getTokenTy(Context), ConstantTokenNoneVal) {}

  void destroyConstantImpl();

public:
  ConstantTokenNone(const ConstantTokenNone &) = delete;

                                   
  static ConstantTokenNone *get(LLVMContext &Context);

                                                                      
  static bool classof(const Value *V) {
    return V->getValueID() == ConstantTokenNoneVal;
  }
};

                                 
   
class BlockAddress final : public Constant {
  friend class Constant;

  BlockAddress(Function *F, BasicBlock *BB);

  void *operator new(size_t s) { return User::operator new(s, 2); }

  void destroyConstantImpl();
  Value *handleOperandChangeImpl(Value *From, Value *To);

public:
                                                                       
  static BlockAddress *get(Function *F, BasicBlock *BB);

                                                                     
                                             
  static BlockAddress *get(BasicBlock *BB);

                                                                           
     
                                                                             
  static BlockAddress *lookup(const BasicBlock *BB);

                                                              
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Value);

  Function *getFunction() const { return (Function*)Op<0>().get(); }
  BasicBlock *getBasicBlock() const { return (BasicBlock*)Op<1>().get(); }

                                                                       
  static bool classof(const Value *V) {
    return V->getValueID() == BlockAddressVal;
  }
};

template <>
struct OperandTraits<BlockAddress> :
  public FixedNumOperandTraits<BlockAddress, 2> {
};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(BlockAddress, Value)

                                                                                
                                                                 
                          
   
                                                                          
                                                                         
                                                
class ConstantExpr : public Constant {
  friend struct ConstantExprKeyType;
  friend class Constant;

  void destroyConstantImpl();
  Value *handleOperandChangeImpl(Value *From, Value *To);

protected:
  ConstantExpr(Type *ty, unsigned Opcode, Use *Ops, unsigned NumOps)
      : Constant(ty, ConstantExprVal, Ops, NumOps) {
                                                                            
    setValueSubclassData(Opcode);
  }

public:
                                                                              
                                                                     
                                                                       
                                                   

                                                                             
                                                        
  static Constant *getAlignOf(Type *Ty);

                                                                       
                                                                            
                      
     
  static Constant *getSizeOf(Type *Ty);

                                                                            
                                                               
     
  static Constant *getOffsetOf(StructType *STy, unsigned FieldNo);

                                                                            
                                                                
     
  static Constant *getOffsetOf(Type *Ty, Constant *FieldNo);

  static Constant *getNeg(Constant *C, bool HasNUW = false, bool HasNSW =false);
  static Constant *getFNeg(Constant *C);
  static Constant *getNot(Constant *C);
  static Constant *getAdd(Constant *C1, Constant *C2,
                          bool HasNUW = false, bool HasNSW = false);
  static Constant *getFAdd(Constant *C1, Constant *C2);
  static Constant *getSub(Constant *C1, Constant *C2,
                          bool HasNUW = false, bool HasNSW = false);
  static Constant *getFSub(Constant *C1, Constant *C2);
  static Constant *getMul(Constant *C1, Constant *C2,
                          bool HasNUW = false, bool HasNSW = false);
  static Constant *getFMul(Constant *C1, Constant *C2);
  static Constant *getUDiv(Constant *C1, Constant *C2, bool isExact = false);
  static Constant *getSDiv(Constant *C1, Constant *C2, bool isExact = false);
  static Constant *getFDiv(Constant *C1, Constant *C2);
  static Constant *getURem(Constant *C1, Constant *C2);
  static Constant *getSRem(Constant *C1, Constant *C2);
  static Constant *getFRem(Constant *C1, Constant *C2);
  static Constant *getAnd(Constant *C1, Constant *C2);
  static Constant *getOr(Constant *C1, Constant *C2);
  static Constant *getXor(Constant *C1, Constant *C2);
  static Constant *getShl(Constant *C1, Constant *C2,
                          bool HasNUW = false, bool HasNSW = false);
  static Constant *getLShr(Constant *C1, Constant *C2, bool isExact = false);
  static Constant *getAShr(Constant *C1, Constant *C2, bool isExact = false);
  static Constant *getTrunc(Constant *C, Type *Ty, bool OnlyIfReduced = false);
  static Constant *getSExt(Constant *C, Type *Ty, bool OnlyIfReduced = false);
  static Constant *getZExt(Constant *C, Type *Ty, bool OnlyIfReduced = false);
  static Constant *getFPTrunc(Constant *C, Type *Ty,
                              bool OnlyIfReduced = false);
  static Constant *getFPExtend(Constant *C, Type *Ty,
                               bool OnlyIfReduced = false);
  static Constant *getUIToFP(Constant *C, Type *Ty, bool OnlyIfReduced = false);
  static Constant *getSIToFP(Constant *C, Type *Ty, bool OnlyIfReduced = false);
  static Constant *getFPToUI(Constant *C, Type *Ty, bool OnlyIfReduced = false);
  static Constant *getFPToSI(Constant *C, Type *Ty, bool OnlyIfReduced = false);
  static Constant *getPtrToInt(Constant *C, Type *Ty,
                               bool OnlyIfReduced = false);
  static Constant *getIntToPtr(Constant *C, Type *Ty,
                               bool OnlyIfReduced = false);
  static Constant *getBitCast(Constant *C, Type *Ty,
                              bool OnlyIfReduced = false);
  static Constant *getAddrSpaceCast(Constant *C, Type *Ty,
                                    bool OnlyIfReduced = false);

  static Constant *getNSWNeg(Constant *C) { return getNeg(C, false, true); }
  static Constant *getNUWNeg(Constant *C) { return getNeg(C, true, false); }

  static Constant *getNSWAdd(Constant *C1, Constant *C2) {
    return getAdd(C1, C2, false, true);
  }

  static Constant *getNUWAdd(Constant *C1, Constant *C2) {
    return getAdd(C1, C2, true, false);
  }

  static Constant *getNSWSub(Constant *C1, Constant *C2) {
    return getSub(C1, C2, false, true);
  }

  static Constant *getNUWSub(Constant *C1, Constant *C2) {
    return getSub(C1, C2, true, false);
  }

  static Constant *getNSWMul(Constant *C1, Constant *C2) {
    return getMul(C1, C2, false, true);
  }

  static Constant *getNUWMul(Constant *C1, Constant *C2) {
    return getMul(C1, C2, true, false);
  }

  static Constant *getNSWShl(Constant *C1, Constant *C2) {
    return getShl(C1, C2, false, true);
  }

  static Constant *getNUWShl(Constant *C1, Constant *C2) {
    return getShl(C1, C2, true, false);
  }

  static Constant *getExactSDiv(Constant *C1, Constant *C2) {
    return getSDiv(C1, C2, true);
  }

  static Constant *getExactUDiv(Constant *C1, Constant *C2) {
    return getUDiv(C1, C2, true);
  }

  static Constant *getExactAShr(Constant *C1, Constant *C2) {
    return getAShr(C1, C2, true);
  }

  static Constant *getExactLShr(Constant *C1, Constant *C2) {
    return getLShr(C1, C2, true);
  }

                                                       
                                                                               
                                                                     
                                                                         
                                                                         
                                                     
                                                                        
  static Constant *getBinOpIdentity(unsigned Opcode, Type *Ty,
                                    bool AllowRHSConstant = false);

                                                       
                                                                          
                                                                          
                                                                        
  static Constant *getBinOpAbsorber(unsigned Opcode, Type *Ty);

                                                              
  DECLARE_TRANSPARENT_OPERAND_ACCESSORS(Constant);

                                                        
     
                                              
                                            
                                                           
                                                         
  static Constant *getCast(unsigned ops, Constant *C, Type *Ty,
                           bool OnlyIfReduced = false);

                                                      
  static Constant *getZExtOrBitCast(
    Constant *C,                                       
    Type *Ty                                      
  );

                                                      
  static Constant *getSExtOrBitCast(
    Constant *C,                                       
    Type *Ty                                      
  );

                                                       
  static Constant *getTruncOrBitCast(
    Constant *C,                                        
    Type *Ty                                       
  );

                                                                  
                 
  static Constant *getPointerCast(
    Constant *C,                                                  
    Type *Ty                                           
  );

                                                                       
                        
  static Constant *getPointerBitCastOrAddrSpaceCast(
    Constant *C,                                                
    Type *Ty                                               
  );

                                                                  
  static Constant *getIntegerCast(
    Constant *C,                                          
    Type *Ty,                                 
    bool isSigned                                                    
  );

                                                           
  static Constant *getFPCast(
    Constant *C,                                          
    Type *Ty                                 
  );

                                                          
  bool isCast() const;

                                                          
  bool isCompare() const;

                                                                       
                                              
  bool hasIndices() const;

                                                               
                                                                   
                                                                    
                                                                     
               
  bool isGEPWithNoNotionalOverIndexing() const;

                          
     
                                                           
  static Constant *getSelect(Constant *C, Constant *V1, Constant *V2,
                             Type *OnlyIfReducedTy = nullptr);

                                                                  
                          
     
                                                           
  static Constant *get(unsigned Opcode, Constant *C1, Constant *C2,
                       unsigned Flags = 0, Type *OnlyIfReducedTy = nullptr);

                                                                     
     
                                                         
  static Constant *getCompare(unsigned short pred, Constant *C1, Constant *C2,
                              bool OnlyIfReduced = false);

                                                           
                                                      
     
  static Constant *getICmp(unsigned short pred, Constant *LHS, Constant *RHS,
                           bool OnlyIfReduced = false);
  static Constant *getFCmp(unsigned short pred, Constant *LHS, Constant *RHS,
                           bool OnlyIfReduced = false);

                                                                   
                                     
     
                                                               
                                                           
  static Constant *getGetElementPtr(Type *Ty, Constant *C,
                                    ArrayRef<Constant *> IdxList,
                                    bool InBounds = false,
                                    Optional<unsigned> InRangeIndex = None,
                                    Type *OnlyIfReducedTy = nullptr) {
    return getGetElementPtr(
        Ty, C, makeArrayRef((Value * const *)IdxList.data(), IdxList.size()),
        InBounds, InRangeIndex, OnlyIfReducedTy);
  }
  static Constant *getGetElementPtr(Type *Ty, Constant *C, Constant *Idx,
                                    bool InBounds = false,
                                    Optional<unsigned> InRangeIndex = None,
                                    Type *OnlyIfReducedTy = nullptr) {
                                                                        
                                                                       
                         
    return getGetElementPtr(Ty, C, cast<Value>(Idx), InBounds, InRangeIndex,
                            OnlyIfReducedTy);
  }
  static Constant *getGetElementPtr(Type *Ty, Constant *C,
                                    ArrayRef<Value *> IdxList,
                                    bool InBounds = false,
                                    Optional<unsigned> InRangeIndex = None,
                                    Type *OnlyIfReducedTy = nullptr);

                                                                       
                                                  
  static Constant *getInBoundsGetElementPtr(Type *Ty, Constant *C,
                                            ArrayRef<Constant *> IdxList) {
    return getGetElementPtr(Ty, C, IdxList, true);
  }
  static Constant *getInBoundsGetElementPtr(Type *Ty, Constant *C,
                                            Constant *Idx) {
                                                                        
                                                                       
                         
    return getGetElementPtr(Ty, C, Idx, true);
  }
  static Constant *getInBoundsGetElementPtr(Type *Ty, Constant *C,
                                            ArrayRef<Value *> IdxList) {
    return getGetElementPtr(Ty, C, IdxList, true);
  }

  static Constant *getExtractElement(Constant *Vec, Constant *Idx,
                                     Type *OnlyIfReducedTy = nullptr);
  static Constant *getInsertElement(Constant *Vec, Constant *Elt, Constant *Idx,
                                    Type *OnlyIfReducedTy = nullptr);
  static Constant *getShuffleVector(Constant *V1, Constant *V2, Constant *Mask,
                                    Type *OnlyIfReducedTy = nullptr);
  static Constant *getExtractValue(Constant *Agg, ArrayRef<unsigned> Idxs,
                                   Type *OnlyIfReducedTy = nullptr);
  static Constant *getInsertValue(Constant *Agg, Constant *Val,
                                  ArrayRef<unsigned> Idxs,
                                  Type *OnlyIfReducedTy = nullptr);

                                                               
  unsigned getOpcode() const { return getSubclassDataFromValue(); }

                                                                               
                               
  unsigned getPredicate() const;

                                                      
                                                
  ArrayRef<unsigned> getIndices() const;

                                                   
  const char *getOpcodeName() const;

                                                                                
                                         
  Constant *getWithOperandReplaced(unsigned OpNo, Constant *Op) const;

                                                                             
                                                                              
                                     
  Constant *getWithOperands(ArrayRef<Constant*> Ops) const {
    return getWithOperands(Ops, getType());
  }

                                                            
     
                                                                               
                                                                              
                          
     
                                                                               
                                                                            
                                                                      
  Constant *getWithOperands(ArrayRef<Constant *> Ops, Type *Ty,
                            bool OnlyIfReduced = false,
                            Type *SrcTy = nullptr) const;

                                                                        
                                                                     
     
                                                                              
                                                                           
                                                                            
                                                              
  Instruction *getAsInstruction();

                                                                       
  static bool classof(const Value *V) {
    return V->getValueID() == ConstantExprVal;
  }

private:
                                                                                
                                           
  void setValueSubclassData(unsigned short D) {
    Value::setValueSubclassData(D);
  }
};

template <>
struct OperandTraits<ConstantExpr> :
  public VariadicOperandTraits<ConstantExpr, 1> {
};

DEFINE_TRANSPARENT_OPERAND_ACCESSORS(ConstantExpr, Constant)

                                                                                
                                                                  
                                                                       
                                                                             
                         
   
                                                                           
                                                              
                                         
   
class UndefValue final : public ConstantData {
  friend class Constant;

  explicit UndefValue(Type *T) : ConstantData(T, UndefValueVal) {}

  void destroyConstantImpl();

public:
  UndefValue(const UndefValue &) = delete;

                                                                              
  static UndefValue *get(Type *T);

                                                                           
                   
  UndefValue *getSequentialElement() const;

                                                                               
                                
  UndefValue *getStructElement(unsigned Elt) const;

                                                                               
                                                          
  UndefValue *getElementValue(Constant *C) const;

                                                                     
  UndefValue *getElementValue(unsigned Idx) const;

                                                                    
  unsigned getNumElements() const;

                                                                       
  static bool classof(const Value *V) {
    return V->getValueID() == UndefValueVal;
  }
};

}                      

#endif                       

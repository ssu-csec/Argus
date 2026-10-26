//===- llvm/DerivedTypes.h - Classes for handling data types ----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declarations of classes that represent "derived
// types".  These are things like "arrays of x" or "structure of x, y, z" or
// "function returning x taking (y,z) as parameters", etc...
//
// The implementations of these classes live in the Type.cpp file.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_DERIVEDTYPES_H
#define LLVM_IR_DERIVEDTYPES_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/STLExtras.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/IR/Type.h"
#include "llvh/Support/Casting.h"
#include "llvh/Support/Compiler.h"
#include <cassert>
#include <cstdint>

namespace llvh {

class Value;
class APInt;
class LLVMContext;

                                                                          
                                                                              
            
                               
class IntegerType : public Type {
  friend class LLVMContextImpl;

protected:
  explicit IntegerType(LLVMContext &C, unsigned NumBits) : Type(C, IntegerTyID){
    setSubclassData(NumBits);
  }

public:
                                                                       
  enum {
    MIN_INT_BITS = 1,                                                         
    MAX_INT_BITS = (1<<24)-1                                                  
                                                                               
                                                                           
                
  };

                                                                           
                                                                                
                                                                               
                                                              
                                            
  static IntegerType *get(LLVMContext &C, unsigned NumBits);

                                                
  unsigned getBitWidth() const { return getSubclassData(); }

                                                                              
                                                                              
  uint64_t getBitMask() const {
    return ~uint64_t(0UL) >> (64-getBitWidth());
  }

                                                                                
                                               
  uint64_t getSignBit() const {
    return 1ULL << (getBitWidth()-1);
  }

                                                                          
                                                                      
                                   
  APInt getMask() const;

                                                                             
                              
                                                       
                                                   
  bool isPowerOf2ByteWidth() const;

                                                                       
  static bool classof(const Type *T) {
    return T->getTypeID() == IntegerTyID;
  }
};

unsigned Type::getIntegerBitWidth() const {
  return cast<IntegerType>(this)->getBitWidth();
}

                                     
   
class FunctionType : public Type {
  FunctionType(Type *Result, ArrayRef<Type*> Params, bool IsVarArgs);

public:
  FunctionType(const FunctionType &) = delete;
  FunctionType &operator=(const FunctionType &) = delete;

                                                                           
  static FunctionType *get(Type *Result,
                           ArrayRef<Type*> Params, bool isVarArg);

                                                 
  static FunctionType *get(Type *Result, bool isVarArg);

                                                                  
  static bool isValidReturnType(Type *RetTy);

                                                                     
  static bool isValidArgumentType(Type *ArgTy);

  bool isVarArg() const { return getSubclassData()!=0; }
  Type *getReturnType() const { return ContainedTys[0]; }

  using param_iterator = Type::subtype_iterator;

  param_iterator param_begin() const { return ContainedTys + 1; }
  param_iterator param_end() const { return &ContainedTys[NumContainedTys]; }
  ArrayRef<Type *> params() const {
    return makeArrayRef(param_begin(), param_end());
  }

                               
  Type *getParamType(unsigned i) const { return ContainedTys[i+1]; }

                                                                        
                                     
  unsigned getNumParams() const { return NumContainedTys - 1; }

                                                                       
  static bool classof(const Type *T) {
    return T->getTypeID() == FunctionTyID;
  }
};
static_assert(alignof(FunctionType) >= alignof(Type *),
              "Alignment sufficient for objects appended to FunctionType");

bool Type::isFunctionVarArg() const {
  return cast<FunctionType>(this)->isVarArg();
}

Type *Type::getFunctionParamType(unsigned i) const {
  return cast<FunctionType>(this)->getParamType(i);
}

unsigned Type::getFunctionNumParams() const {
  return cast<FunctionType>(this)->getNumParams();
}

                                                               
class CompositeType : public Type {
protected:
  explicit CompositeType(LLVMContext &C, TypeID tid) : Type(C, tid) {}

public:
                                                                         
  Type *getTypeAtIndex(const Value *V) const;
  Type *getTypeAtIndex(unsigned Idx) const;
  bool indexValid(const Value *V) const;
  bool indexValid(unsigned Idx) const;

                                                                       
  static bool classof(const Type *T) {
    return T->getTypeID() == ArrayTyID ||
           T->getTypeID() == StructTyID ||
           T->getTypeID() == VectorTyID;
  }
};

                                                                            
                                                  
   
                                                                               
                                                                              
                                
   
                                                                                
                                                                             
                                                                               
                                                                               
                                                                       
                               
   
                                                                              
                                                                             
                                                                               
                                                                               
                                    
   
class StructType : public CompositeType {
  StructType(LLVMContext &C) : CompositeType(C, StructTyID) {}

  enum {
                                                       
    SCDB_HasBody = 1,
    SCDB_Packed = 2,
    SCDB_IsLiteral = 4,
    SCDB_IsSized = 8
  };

                                                                           
                                                                    
                                                                            
                                  
  void *SymbolTableEntry = nullptr;

public:
  StructType(const StructType &) = delete;
  StructType &operator=(const StructType &) = delete;

                                        
  static StructType *create(LLVMContext &Context, StringRef Name);
  static StructType *create(LLVMContext &Context);

  static StructType *create(ArrayRef<Type *> Elements, StringRef Name,
                            bool isPacked = false);
  static StructType *create(ArrayRef<Type *> Elements);
  static StructType *create(LLVMContext &Context, ArrayRef<Type *> Elements,
                            StringRef Name, bool isPacked = false);
  static StructType *create(LLVMContext &Context, ArrayRef<Type *> Elements);
  template <class... Tys>
  static typename std::enable_if<are_base_of<Type, Tys...>::value,
                                 StructType *>::type
  create(StringRef Name, Type *elt1, Tys *... elts) {
    assert(elt1 && "Cannot create a struct type with no elements with this");
    SmallVector<llvh::Type *, 8> StructFields({elt1, elts...});
    return create(StructFields, Name);
  }

                                                                           
  static StructType *get(LLVMContext &Context, ArrayRef<Type*> Elements,
                         bool isPacked = false);

                                     
  static StructType *get(LLVMContext &Context, bool isPacked = false);

                                                                                
                                                                                
                                                                  
  template <class... Tys>
  static typename std::enable_if<are_base_of<Type, Tys...>::value,
                                 StructType *>::type
  get(Type *elt1, Tys *... elts) {
    assert(elt1 && "Cannot create a struct type with no elements with this");
    LLVMContext &Ctx = elt1->getContext();
    SmallVector<llvh::Type *, 8> StructFields({elt1, elts...});
    return llvh::StructType::get(Ctx, StructFields);
  }

  bool isPacked() const { return (getSubclassData() & SCDB_Packed) != 0; }

                                                                                
                             
  bool isLiteral() const { return (getSubclassData() & SCDB_IsLiteral) != 0; }

                                                                               
                                                 
  bool isOpaque() const { return (getSubclassData() & SCDB_HasBody) == 0; }

                                                    
  bool isSized(SmallPtrSetImpl<Type *> *Visited = nullptr) const;

                                                                      
  bool hasName() const { return SymbolTableEntry != nullptr; }

                                                                 
                                                                              
                              
  StringRef getName() const;

                                                                             
                                                                          
  void setName(StringRef Name);

                                                   
  void setBody(ArrayRef<Type*> Elements, bool isPacked = false);

  template <typename... Tys>
  typename std::enable_if<are_base_of<Type, Tys...>::value, void>::type
  setBody(Type *elt1, Tys *... elts) {
    assert(elt1 && "Cannot create a struct type with no elements with this");
    SmallVector<llvh::Type *, 8> StructFields({elt1, elts...});
    setBody(StructFields);
  }

                                                                   
  static bool isValidElementType(Type *ElemTy);

                                     
  using element_iterator = Type::subtype_iterator;

  element_iterator element_begin() const { return ContainedTys; }
  element_iterator element_end() const { return &ContainedTys[NumContainedTys];}
  ArrayRef<Type *> const elements() const {
    return makeArrayRef(element_begin(), element_end());
  }

                                                                      
  bool isLayoutIdentical(StructType *Other) const;

                                   
  unsigned getNumElements() const { return NumContainedTys; }
  Type *getElementType(unsigned N) const {
    assert(N < NumContainedTys && "Element number out of range!");
    return ContainedTys[N];
  }

                                                                       
  static bool classof(const Type *T) {
    return T->getTypeID() == StructTyID;
  }
};

StringRef Type::getStructName() const {
  return cast<StructType>(this)->getName();
}

unsigned Type::getStructNumElements() const {
  return cast<StructType>(this)->getNumElements();
}

Type *Type::getStructElementType(unsigned N) const {
  return cast<StructType>(this)->getElementType(N);
}

                                                                              
                                                                                
                                                                                
                                                                             
                                                                               
                
class SequentialType : public CompositeType {
  Type *ContainedType;                                                          
  uint64_t NumElements;

protected:
  SequentialType(TypeID TID, Type *ElType, uint64_t NumElements)
    : CompositeType(ElType->getContext(), TID), ContainedType(ElType),
      NumElements(NumElements) {
    ContainedTys = &ContainedType;
    NumContainedTys = 1;
  }

public:
  SequentialType(const SequentialType &) = delete;
  SequentialType &operator=(const SequentialType &) = delete;

  uint64_t getNumElements() const { return NumElements; }
  Type *getElementType() const { return ContainedType; }

                                                                       
  static bool classof(const Type *T) {
    return T->getTypeID() == ArrayTyID || T->getTypeID() == VectorTyID;
  }
};

                                   
class ArrayType : public SequentialType {
  ArrayType(Type *ElType, uint64_t NumEl);

public:
  ArrayType(const ArrayType &) = delete;
  ArrayType &operator=(const ArrayType &) = delete;

                                                                     
  static ArrayType *get(Type *ElementType, uint64_t NumElements);

                                                                   
  static bool isValidElementType(Type *ElemTy);

                                                                       
  static bool classof(const Type *T) {
    return T->getTypeID() == ArrayTyID;
  }
};

uint64_t Type::getArrayNumElements() const {
  return cast<ArrayType>(this)->getNumElements();
}

                                    
class VectorType : public SequentialType {
  VectorType(Type *ElType, unsigned NumEl);

public:
  VectorType(const VectorType &) = delete;
  VectorType &operator=(const VectorType &) = delete;

                                                                       
  static VectorType *get(Type *ElementType, unsigned NumElements);

                                                                              
                                                                               
                                
  static VectorType *getInteger(VectorType *VTy) {
    unsigned EltBits = VTy->getElementType()->getPrimitiveSizeInBits();
    assert(EltBits && "Element size must be of a non-zero size");
    Type *EltTy = IntegerType::get(VTy->getContext(), EltBits);
    return VectorType::get(EltTy, VTy->getNumElements());
  }

                                                                             
                                                      
  static VectorType *getExtendedElementVectorType(VectorType *VTy) {
    unsigned EltBits = VTy->getElementType()->getPrimitiveSizeInBits();
    Type *EltTy = IntegerType::get(VTy->getContext(), EltBits * 2);
    return VectorType::get(EltTy, VTy->getNumElements());
  }

                                                                             
                                                     
  static VectorType *getTruncatedElementVectorType(VectorType *VTy) {
    unsigned EltBits = VTy->getElementType()->getPrimitiveSizeInBits();
    assert((EltBits & 1) == 0 &&
           "Cannot truncate vector element with odd bit-width");
    Type *EltTy = IntegerType::get(VTy->getContext(), EltBits / 2);
    return VectorType::get(EltTy, VTy->getNumElements());
  }

                                                                               
                                           
  static VectorType *getHalfElementsVectorType(VectorType *VTy) {
    unsigned NumElts = VTy->getNumElements();
    assert ((NumElts & 1) == 0 &&
            "Cannot halve vector with odd number of elements.");
    return VectorType::get(VTy->getElementType(), NumElts/2);
  }

                                                                                
                                           
  static VectorType *getDoubleElementsVectorType(VectorType *VTy) {
    unsigned NumElts = VTy->getNumElements();
    return VectorType::get(VTy->getElementType(), NumElts*2);
  }

                                                                   
  static bool isValidElementType(Type *ElemTy);

                                                   
                                                           
  unsigned getBitWidth() const {
    return getNumElements() * getElementType()->getPrimitiveSizeInBits();
  }

                                                                       
  static bool classof(const Type *T) {
    return T->getTypeID() == VectorTyID;
  }
};

unsigned Type::getVectorNumElements() const {
  return cast<VectorType>(this)->getNumElements();
}

                                
class PointerType : public Type {
  explicit PointerType(Type *ElType, unsigned AddrSpace);

  Type *PointeeTy;

public:
  PointerType(const PointerType &) = delete;
  PointerType &operator=(const PointerType &) = delete;

                                                                                
                    
  static PointerType *get(Type *ElementType, unsigned AddressSpace);

                                                                         
                                                 
  static PointerType *getUnqual(Type *ElementType) {
    return PointerType::get(ElementType, 0);
  }

  Type *getElementType() const { return PointeeTy; }

                                                                   
  static bool isValidElementType(Type *ElemTy);

                                                                      
  static bool isLoadableOrStorableType(Type *ElemTy);

                                                   
  inline unsigned getAddressSpace() const { return getSubclassData(); }

                                                                     
  static bool classof(const Type *T) {
    return T->getTypeID() == PointerTyID;
  }
};

unsigned Type::getPointerAddressSpace() const {
  return cast<PointerType>(getScalarType())->getAddressSpace();
}

}                      

#endif                          

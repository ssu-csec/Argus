//===- llvm/Type.h - Classes for handling data types ------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of the Type class.  For more "Type"
// stuff, look in DerivedTypes.h.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_TYPE_H
#define LLVM_IR_TYPE_H

#include "llvh/ADT/APFloat.h"
#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/SmallPtrSet.h"
#include "llvh/Support/CBindingWrapping.h"
#include "llvh/Support/Casting.h"
#include "llvh/Support/Compiler.h"
#include "llvh/Support/ErrorHandling.h"
#include <cassert>
#include <cstdint>
#include <iterator>

namespace llvh {

template<class GraphType> struct GraphTraits;
class IntegerType;
class LLVMContext;
class PointerType;
class raw_ostream;
class StringRef;

                                                                         
                                                                             
                                                                            
                                                                              
                                                                              
                                                                          
           
   
class Type {
public:
                                                                                
                                                                              
                                                               
                                                                            
                                                                 
                                                                       
     
  enum TypeID {
                                                                     
    VoidTyID = 0,                              
    HalfTyID,                                           
    FloatTyID,                                          
    DoubleTyID,                                         
    X86_FP80TyID,                                             
    FP128TyID,                                                              
    PPC_FP128TyID,                                                              
    LabelTyID,                      
    MetadataTyID,                     
    X86_MMXTyID,                                                 
    TokenTyID,                      

                                                
                                                   
    IntegerTyID,                                          
    FunctionTyID,                      
    StructTyID,                         
    ArrayTyID,                      
    PointerTyID,                      
    VectorTyID                                                          
  };

private:
                                                                    
  LLVMContext &Context;

  TypeID   ID : 8;                                                  
  unsigned SubclassData : 24;                                       
                                                                           
                                                                         

protected:
  friend class LLVMContextImpl;

  explicit Type(LLVMContext &C, TypeID tid)
    : Context(C), ID(tid), SubclassData(0) {}
  ~Type() = default;

  unsigned getSubclassData() const { return SubclassData; }

  void setSubclassData(unsigned val) {
    SubclassData = val;
                                                      
    assert(getSubclassData() == val && "Subclass data too large for field");
  }

                                                                         
  unsigned NumContainedTys = 0;

                                                                               
                                                                             
                                                                               
                                                                         
             
  Type * const *ContainedTys = nullptr;

  static bool isSequentialType(TypeID TyID) {
    return TyID == ArrayTyID || TyID == VectorTyID;
  }

public:
                             
                                                    
                                       
                                                   
                                                         
                                                             
  void print(raw_ostream &O, bool IsForDebug = false,
             bool NoDetails = false) const;

  void dump() const;

                                                            
  LLVMContext &getContext() const { return Context; }

                                                                                
                                      
    

                                                                              
                             
  TypeID getTypeID() const { return ID; }

                                    
  bool isVoidTy() const { return getTypeID() == VoidTyID; }

                                                           
  bool isHalfTy() const { return getTypeID() == HalfTyID; }

                                                            
  bool isFloatTy() const { return getTypeID() == FloatTyID; }

                                                             
  bool isDoubleTy() const { return getTypeID() == DoubleTyID; }

                                             
  bool isX86_FP80Ty() const { return getTypeID() == X86_FP80TyID; }

                                     
  bool isFP128Ty() const { return getTypeID() == FP128TyID; }

                                                 
  bool isPPC_FP128Ty() const { return getTypeID() == PPC_FP128TyID; }

                                                                
  bool isFloatingPointTy() const {
    return getTypeID() == HalfTyID || getTypeID() == FloatTyID ||
           getTypeID() == DoubleTyID ||
           getTypeID() == X86_FP80TyID || getTypeID() == FP128TyID ||
           getTypeID() == PPC_FP128TyID;
  }

  const fltSemantics &getFltSemantics() const {
    switch (getTypeID()) {
    case HalfTyID: return APFloat::IEEEhalf();
    case FloatTyID: return APFloat::IEEEsingle();
    case DoubleTyID: return APFloat::IEEEdouble();
    case X86_FP80TyID: return APFloat::x87DoubleExtended();
    case FP128TyID: return APFloat::IEEEquad();
    case PPC_FP128TyID: return APFloat::PPCDoubleDouble();
    default: llvm_unreachable("Invalid floating type");
    }
  }

                                     
  bool isX86_MMXTy() const { return getTypeID() == X86_MMXTyID; }

                                                         
  bool isFPOrFPVectorTy() const { return getScalarType()->isFloatingPointTy(); }

                                     
  bool isLabelTy() const { return getTypeID() == LabelTyID; }

                                        
  bool isMetadataTy() const { return getTypeID() == MetadataTyID; }

                                     
  bool isTokenTy() const { return getTypeID() == TokenTyID; }

                                                 
  bool isIntegerTy() const { return getTypeID() == IntegerTyID; }

                                                               
  bool isIntegerTy(unsigned Bitwidth) const;

                                                                          
  bool isIntOrIntVectorTy() const { return getScalarType()->isIntegerTy(); }

                                                                            
                      
  bool isIntOrIntVectorTy(unsigned BitWidth) const {
    return getScalarType()->isIntegerTy(BitWidth);
  }

                                                               
  bool isIntOrPtrTy() const { return isIntegerTy() || isPointerTy(); }

                                                  
  bool isFunctionTy() const { return getTypeID() == FunctionTyID; }

                                                
  bool isStructTy() const { return getTypeID() == StructTyID; }

                                               
  bool isArrayTy() const { return getTypeID() == ArrayTyID; }

                                                 
  bool isPointerTy() const { return getTypeID() == PointerTyID; }

                                                                         
  bool isPtrOrPtrVectorTy() const { return getScalarType()->isPointerTy(); }

                                                
  bool isVectorTy() const { return getTypeID() == VectorTyID; }

                                                                            
                                                                              
                                                                    
                                                              
  bool canLosslesslyBitCastTo(Type *Ty) const;

                                                                              
                             
  bool isEmptyTy() const;

                                                                                
            
  bool isFirstClassType() const {
    return getTypeID() != FunctionTyID && getTypeID() != VoidTyID;
  }

                                                                             
                                                                   
  bool isSingleValueType() const {
    return isFloatingPointTy() || isX86_MMXTy() || isIntegerTy() ||
           isPointerTy() || isVectorTy();
  }

                                                                             
                                                                           
                                                                         
  bool isAggregateType() const {
    return getTypeID() == StructTyID || getTypeID() == ArrayTyID;
  }

                                                                             
                                                                      
                                      
  bool isSized(SmallPtrSetImpl<Type*> *Visited = nullptr) const {
                                               
    if (getTypeID() == IntegerTyID || isFloatingPointTy() ||
        getTypeID() == PointerTyID ||
        getTypeID() == X86_MMXTyID)
      return true;
                                                                              
                              
    if (getTypeID() != StructTyID && getTypeID() != ArrayTyID &&
        getTypeID() != VectorTyID)
      return false;
                                                 
    return isSizedDerivedType(Visited);
  }

                                                                             
                                                 
                                                                        
                     
     
                                                                        
                                                                          
                                                                             
                                                             
     
  unsigned getPrimitiveSizeInBits() const LLVM_READONLY;

                                                                               
                                                                              
           
  unsigned getScalarSizeInBits() const LLVM_READONLY;

                                                                          
                                                                                
                                               
  int getFPMantissaWidth() const;

                                                                         
             
  Type *getScalarType() const {
    if (isVectorTy())
      return getVectorElementType();
    return const_cast<Type*>(this);
  }

                                                                                
                            
    
  using subtype_iterator = Type * const *;

  subtype_iterator subtype_begin() const { return ContainedTys; }
  subtype_iterator subtype_end() const { return &ContainedTys[NumContainedTys];}
  ArrayRef<Type*> subtypes() const {
    return makeArrayRef(subtype_begin(), subtype_end());
  }

  using subtype_reverse_iterator = std::reverse_iterator<subtype_iterator>;

  subtype_reverse_iterator subtype_rbegin() const {
    return subtype_reverse_iterator(subtype_end());
  }
  subtype_reverse_iterator subtype_rend() const {
    return subtype_reverse_iterator(subtype_begin());
  }

                                                                               
                                                                             
                   
  Type *getContainedType(unsigned i) const {
    assert(i < NumContainedTys && "Index out of range!");
    return ContainedTys[i];
  }

                                                     
  unsigned getNumContainedTypes() const { return NumContainedTys; }

                                                                                
                                                                             
                                                                                
                                                                               
                                                                             
                                      

  inline unsigned getIntegerBitWidth() const;

  inline Type *getFunctionParamType(unsigned i) const;
  inline unsigned getFunctionNumParams() const;
  inline bool isFunctionVarArg() const;

  inline StringRef getStructName() const;
  inline unsigned getStructNumElements() const;
  inline Type *getStructElementType(unsigned N) const;

  inline Type *getSequentialElementType() const {
    assert(isSequentialType(getTypeID()) && "Not a sequential type!");
    return ContainedTys[0];
  }

  inline uint64_t getArrayNumElements() const;

  Type *getArrayElementType() const {
    assert(getTypeID() == ArrayTyID);
    return ContainedTys[0];
  }

  inline unsigned getVectorNumElements() const;
  Type *getVectorElementType() const {
    assert(getTypeID() == VectorTyID);
    return ContainedTys[0];
  }

  Type *getPointerElementType() const {
    assert(getTypeID() == PointerTyID);
    return ContainedTys[0];
  }

                                                                   
  inline unsigned getPointerAddressSpace() const;

                                                                                
                                                                          
                       
    

                                           
  static Type *getPrimitiveType(LLVMContext &C, TypeID IDNumber);

                                                                                
                                                           
    
  static Type *getVoidTy(LLVMContext &C);
  static Type *getLabelTy(LLVMContext &C);
  static Type *getHalfTy(LLVMContext &C);
  static Type *getFloatTy(LLVMContext &C);
  static Type *getDoubleTy(LLVMContext &C);
  static Type *getMetadataTy(LLVMContext &C);
  static Type *getX86_FP80Ty(LLVMContext &C);
  static Type *getFP128Ty(LLVMContext &C);
  static Type *getPPC_FP128Ty(LLVMContext &C);
  static Type *getX86_MMXTy(LLVMContext &C);
  static Type *getTokenTy(LLVMContext &C);
  static IntegerType *getIntNTy(LLVMContext &C, unsigned N);
  static IntegerType *getInt1Ty(LLVMContext &C);
  static IntegerType *getInt8Ty(LLVMContext &C);
  static IntegerType *getInt16Ty(LLVMContext &C);
  static IntegerType *getInt32Ty(LLVMContext &C);
  static IntegerType *getInt64Ty(LLVMContext &C);
  static IntegerType *getInt128Ty(LLVMContext &C);
  template <typename ScalarTy> static Type *getScalarTy(LLVMContext &C) {
    int noOfBits = sizeof(ScalarTy) * CHAR_BIT;
    if (std::is_integral<ScalarTy>::value) {
      return (Type*) Type::getIntNTy(C, noOfBits);
    } else if (std::is_floating_point<ScalarTy>::value) {
      switch (noOfBits) {
      case 32:
        return Type::getFloatTy(C);
      case 64:
        return Type::getDoubleTy(C);
      }
    }
    llvm_unreachable("Unsupported type in Type::getScalarTy");
  }

                                                                                
                                                                                
                      
    
  static PointerType *getHalfPtrTy(LLVMContext &C, unsigned AS = 0);
  static PointerType *getFloatPtrTy(LLVMContext &C, unsigned AS = 0);
  static PointerType *getDoublePtrTy(LLVMContext &C, unsigned AS = 0);
  static PointerType *getX86_FP80PtrTy(LLVMContext &C, unsigned AS = 0);
  static PointerType *getFP128PtrTy(LLVMContext &C, unsigned AS = 0);
  static PointerType *getPPC_FP128PtrTy(LLVMContext &C, unsigned AS = 0);
  static PointerType *getX86_MMXPtrTy(LLVMContext &C, unsigned AS = 0);
  static PointerType *getIntNPtrTy(LLVMContext &C, unsigned N, unsigned AS = 0);
  static PointerType *getInt1PtrTy(LLVMContext &C, unsigned AS = 0);
  static PointerType *getInt8PtrTy(LLVMContext &C, unsigned AS = 0);
  static PointerType *getInt16PtrTy(LLVMContext &C, unsigned AS = 0);
  static PointerType *getInt32PtrTy(LLVMContext &C, unsigned AS = 0);
  static PointerType *getInt64PtrTy(LLVMContext &C, unsigned AS = 0);

                                                                 
                                       
  PointerType *getPointerTo(unsigned AddrSpace = 0) const;

private:
                                                                               
                                                                              
                                                
  bool isSizedDerivedType(SmallPtrSetImpl<Type*> *Visited = nullptr) const;
};

                     
inline raw_ostream &operator<<(raw_ostream &OS, const Type &T) {
  T.print(OS);
  return OS;
}

                                                                     
template <> struct isa_impl<PointerType, Type> {
  static inline bool doit(const Type &Ty) {
    return Ty.getTypeID() == Type::PointerTyID;
  }
};

                                                                                
                                                                         
                      

template <> struct GraphTraits<Type *> {
  using NodeRef = Type *;
  using ChildIteratorType = Type::subtype_iterator;

  static NodeRef getEntryNode(Type *T) { return T; }
  static ChildIteratorType child_begin(NodeRef N) { return N->subtype_begin(); }
  static ChildIteratorType child_end(NodeRef N) { return N->subtype_end(); }
};

template <> struct GraphTraits<const Type*> {
  using NodeRef = const Type *;
  using ChildIteratorType = Type::subtype_iterator;

  static NodeRef getEntryNode(NodeRef T) { return T; }
  static ChildIteratorType child_begin(NodeRef N) { return N->subtype_begin(); }
  static ChildIteratorType child_end(NodeRef N) { return N->subtype_end(); }
};

                                                                
DEFINE_ISA_CONVERSION_FUNCTIONS(Type, LLVMTypeRef)

                                       
   
inline Type **unwrap(LLVMTypeRef* Tys) {
  return reinterpret_cast<Type**>(Tys);
}

inline LLVMTypeRef *wrap(Type **Tys) {
  return reinterpret_cast<LLVMTypeRef*>(const_cast<Type**>(Tys));
}

}                      

#endif                  

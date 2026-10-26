//===-- llvm/Instrinsics.h - LLVM Intrinsic Function Handling ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines a set of enums which allow processing of intrinsic
// functions.  Values of these enum types are returned by
// Function::getIntrinsicID.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_INTRINSICS_H
#define LLVM_IR_INTRINSICS_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/None.h"
#include "llvh/ADT/Optional.h"
#include <string>

namespace llvh {

class Type;
class FunctionType;
class Function;
class LLVMContext;
class Module;
class AttributeList;

                                                                            
                                                           
                               
namespace Intrinsic {
  enum ID : unsigned {
    not_intrinsic = 0,                  

                                                           
#define GET_INTRINSIC_ENUM_VALUES
#include "llvh/IR/IntrinsicEnums.inc"
#undef GET_INTRINSIC_ENUM_VALUES
    , num_intrinsics
  };

                                                                            
                                                                            
                                                   
  StringRef getName(ID id);

                                                                            
                                                                             
                                                                       
                                                                               
              
  std::string getName(ID id, ArrayRef<Type*> Tys);

                                                
  FunctionType *getType(LLVMContext &Context, ID id,
                        ArrayRef<Type*> Tys = None);

                                                      
  bool isOverloaded(ID id);

                                                                              
                                                                             
                                                                                
  bool isLeaf(ID id);

                                             
  AttributeList getAttributes(LLVMContext &C, ID id);

                                                                                
         
     
                                                                            
                                                                              
                                                                              
                    
  Function *getDeclaration(Module *M, ID id, ArrayRef<Type*> Tys = None);

                                                                            
                                                                              
                                                                        
                                                       
  int lookupLLVMIntrinsicByName(ArrayRef<const char *> NameTable,
                                StringRef Name);

                                                
  ID getIntrinsicForGCCBuiltin(const char *Prefix, StringRef BuiltinName);

                                               
  ID getIntrinsicForMSBuiltin(const char *Prefix, StringRef BuiltinName);

                                                                          
                                                                  
  struct IITDescriptor {
    enum IITDescriptorKind {
      Void, VarArg, MMX, Token, Metadata, Half, Float, Double, Quad,
      Integer, Vector, Pointer, Struct,
      Argument, ExtendArgument, TruncArgument, HalfVecArgument,
      SameVecWidthArgument, PtrToArgument, PtrToElt, VecOfAnyPtrsToElt
    } Kind;

    union {
      unsigned Integer_Width;
      unsigned Float_Width;
      unsigned Vector_Width;
      unsigned Pointer_AddressSpace;
      unsigned Struct_NumElements;
      unsigned Argument_Info;
    };

    enum ArgKind {
      AK_Any,
      AK_AnyInteger,
      AK_AnyFloat,
      AK_AnyVector,
      AK_AnyPointer
    };

    unsigned getArgumentNumber() const {
      assert(Kind == Argument || Kind == ExtendArgument ||
             Kind == TruncArgument || Kind == HalfVecArgument ||
             Kind == SameVecWidthArgument || Kind == PtrToArgument ||
             Kind == PtrToElt);
      return Argument_Info >> 3;
    }
    ArgKind getArgumentKind() const {
      assert(Kind == Argument || Kind == ExtendArgument ||
             Kind == TruncArgument || Kind == HalfVecArgument ||
             Kind == SameVecWidthArgument || Kind == PtrToArgument);
      return (ArgKind)(Argument_Info & 7);
    }

                                                                             
                                                                             
    unsigned getOverloadArgNumber() const {
      assert(Kind == VecOfAnyPtrsToElt);
      return Argument_Info >> 16;
    }
    unsigned getRefArgNumber() const {
      assert(Kind == VecOfAnyPtrsToElt);
      return Argument_Info & 0xFFFF;
    }

    static IITDescriptor get(IITDescriptorKind K, unsigned Field) {
      IITDescriptor Result = { K, { Field } };
      return Result;
    }

    static IITDescriptor get(IITDescriptorKind K, unsigned short Hi,
                             unsigned short Lo) {
      unsigned Field = Hi << 16 | Lo;
      IITDescriptor Result = {K, {Field}};
      return Result;
    }
  };

                                                                               
                        
  void getIntrinsicInfoTableEntries(ID id, SmallVectorImpl<IITDescriptor> &T);

                                                                                
                                                                              
                                                                   
     
                                                                        
                
  bool matchIntrinsicType(Type *Ty, ArrayRef<IITDescriptor> &Infos,
                          SmallVectorImpl<Type*> &ArgTys);

                                                                                
                                                                      
     
                                        
  bool matchIntrinsicVarArg(bool isVarArg, ArrayRef<IITDescriptor> &Infos);

                                                                       
                                                                        
  llvh::Optional<Function*> remangleIntrinsicFunction(Function *F);

}                           

}                      

#endif

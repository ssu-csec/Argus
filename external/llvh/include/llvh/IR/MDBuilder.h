//===---- llvm/MDBuilder.h - Builder for LLVM metadata ----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the MDBuilder class, which is used as a convenient way to
// create LLVM metadata with a consistent and simplified interface.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_MDBUILDER_H
#define LLVM_IR_MDBUILDER_H

#include "llvh/ADT/DenseSet.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/IR/GlobalValue.h"
#include "llvh/Support/DataTypes.h"
#include <utility>

namespace llvh {

class APInt;
template <typename T> class ArrayRef;
class LLVMContext;
class Constant;
class ConstantAsMetadata;
class MDNode;
class MDString;
class Metadata;

class MDBuilder {
  LLVMContext &Context;

public:
  MDBuilder(LLVMContext &context) : Context(context) {}

                                          
  MDString *createString(StringRef Str);

                                            
  ConstantAsMetadata *createConstant(Constant *C);

                                                                              
                     
                                                                              

                                                                     
                                                                          
              
  MDNode *createFPMath(float Accuracy);

                                                                              
                   
                                                                              

                                                    
  MDNode *createBranchWeights(uint32_t TrueWeight, uint32_t FalseWeight);

                                                            
  MDNode *createBranchWeights(ArrayRef<uint32_t> Weights);

                                                                          
  MDNode *createUnpredictable();

                                                                             
                                                                        
                                                                            
                                                              
  MDNode *createFunctionEntryCount(uint64_t Count, bool Synthetic,
                                   const DenseSet<GlobalValue::GUID> *Imports);

                                                                   
  MDNode *createFunctionSectionPrefix(StringRef Prefix);

                                                                              
                    
                                                                              

                                                    
  MDNode *createRange(const APInt &Lo, const APInt &Hi);

                                                    
  MDNode *createRange(Constant *Lo, Constant *Hi);

                                                                              
                      
                                                                              

                                                                 
            
  MDNode *createCallees(ArrayRef<Function *> Callees);

                                                                              
                 
                                                                              

protected:
                                                                     
                                                                           
                                                 
  MDNode *createAnonymousAARoot(StringRef Name = StringRef(),
                                MDNode *Extra = nullptr);

public:
                                                                     
                                                                           
                                   
  MDNode *createAnonymousTBAARoot() {
    return createAnonymousAARoot();
  }

                                                                 
                                                                           
                                                 
  MDNode *createAnonymousAliasScopeDomain(StringRef Name = StringRef()) {
    return createAnonymousAARoot(Name);
  }

                                                               
                                                                           
                                                 
  MDNode *createAnonymousAliasScope(MDNode *Domain,
                                    StringRef Name = StringRef()) {
    return createAnonymousAARoot(Name, Domain);
  }

                                                                     
                                                                            
           
  MDNode *createTBAARoot(StringRef Name);

                                                                     
                                                                            
                    
  MDNode *createAliasScopeDomain(StringRef Name);

                                                              
                                                                             
                               
  MDNode *createAliasScope(StringRef Name, MDNode *Domain);

                                                                   
                                                                      
  MDNode *createTBAANode(StringRef Name, MDNode *Parent,
                         bool isConstant = false);

  struct TBAAStructField {
    uint64_t Offset;
    uint64_t Size;
    MDNode *Type;
    TBAAStructField(uint64_t Offset, uint64_t Size, MDNode *Type) :
      Offset(Offset), Size(Size), Type(Type) {}
  };

                                                           
                                
  MDNode *createTBAAStructNode(ArrayRef<TBAAStructField> Fields);

                                                            
                                                                                
  MDNode *
  createTBAAStructTypeNode(StringRef Name,
                           ArrayRef<std::pair<MDNode *, uint64_t>> Fields);

                                                          
                                                              
  MDNode *createTBAAScalarTypeNode(StringRef Name, MDNode *Parent,
                                   uint64_t Offset = 0);

                                                        
                                                                  
  MDNode *createTBAAStructTagNode(MDNode *BaseType, MDNode *AccessType,
                                  uint64_t Offset, bool IsConstant = false);

                                                                        
                                                                             
  MDNode *createTBAATypeNode(MDNode *Parent, uint64_t Size, Metadata *Id,
                             ArrayRef<TBAAStructField> Fields =
                                 ArrayRef<TBAAStructField>());

                                                                     
                                                                                
                                                                       
                                                                 
  MDNode *createTBAAAccessTag(MDNode *BaseType, MDNode *AccessType,
                              uint64_t Offset, uint64_t Size,
                              bool IsImmutable = false);

                                                                   
                 
  MDNode *createMutableTBAAAccessTag(MDNode *Tag);

                                                                   
  MDNode *createIrrLoopHeaderWeight(uint64_t Weight);
};

}                      

#endif

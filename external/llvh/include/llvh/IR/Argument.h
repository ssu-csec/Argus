//===-- llvm/Argument.h - Definition of the Argument class ------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the Argument class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_ARGUMENT_H
#define LLVM_IR_ARGUMENT_H

#include "llvh/ADT/Twine.h"
#include "llvh/ADT/ilist_node.h"
#include "llvh/IR/Attributes.h"
#include "llvh/IR/Value.h"

namespace llvh {

                                                                             
                                                                          
                                                                               
                                                                        
                                                                           
                             
class Argument final : public Value {
  Function *Parent;
  unsigned ArgNo;

  friend class Function;
  void setParent(Function *parent);

public:
                           
  explicit Argument(Type *Ty, const Twine &Name = "", Function *F = nullptr,
                    unsigned ArgNo = 0);

  inline const Function *getParent() const { return Parent; }
  inline       Function *getParent()       { return Parent; }

                                                                          
     
                                                                  
  unsigned getArgNo() const {
    assert(Parent && "can't get number of unparented arg");
    return ArgNo;
  }

                                                                               
                                                                               
                   
  bool hasNonNullAttr() const;

                                                                              
                                                                     
  uint64_t getDereferenceableBytes() const;

                                                                            
                                                                               
  uint64_t getDereferenceableOrNullBytes() const;

                                                           
  bool hasByValAttr() const;

                                                               
  bool hasSwiftSelfAttr() const;

                                                                
  bool hasSwiftErrorAttr() const;

                                                                      
                                                                            
  bool hasByValOrInAllocaAttr() const;

                                                                    
  unsigned getParamAlignment() const;

                                                          
  bool hasNestAttr() const;

                                                             
  bool hasNoAliasAttr() const;

                                                               
  bool hasNoCaptureAttr() const;

                                                          
  bool hasStructRetAttr() const;

                                                              
  bool hasReturnedAttr() const;

                                                                          
  bool onlyReadsMemory() const;

                                                              
  bool hasInAllocaAttr() const;

                                                          
  bool hasZExtAttr() const;

                                                          
  bool hasSExtAttr() const;

                                    
  void addAttrs(AttrBuilder &B);

  void addAttr(Attribute::AttrKind Kind);

  void addAttr(Attribute Attr);

                                         
  void removeAttr(Attribute::AttrKind Kind);

                                                 
  bool hasAttribute(Attribute::AttrKind Kind) const;

                                                                      
  static bool classof(const Value *V) {
    return V->getValueID() == ArgumentVal;
  }
};

}                      

#endif

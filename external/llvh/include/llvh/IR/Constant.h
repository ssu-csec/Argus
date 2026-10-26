//===-- llvm/Constant.h - Constant class definition -------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of the Constant class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_CONSTANT_H
#define LLVM_IR_CONSTANT_H

#include "llvh/IR/User.h"
#include "llvh/IR/Value.h"
#include "llvh/Support/Casting.h"

namespace llvh {

class APInt;

                                                                              
                                                                            
                                                                          
                                          
   
                                                                              
                                                                          
                                                                                
                                                                           
                                                      
   
                                                                      
                                                                        
                                                                        
                                                                             
                                                          
                                
class Constant : public User {
protected:
  Constant(Type *ty, ValueTy vty, Use *Ops, unsigned NumOps)
    : User(ty, vty, Ops, NumOps) {}

public:
  void operator=(const Constant &) = delete;
  Constant(const Constant &) = delete;

                                                                              
  bool isNullValue() const;

                                       
  bool isOneValue() const;

                                                                
                      
  bool isAllOnesValue() const;

                                                           
                              
  bool isNegativeZeroValue() const;

                                                              
  bool isZeroValue() const;

                                                                
  bool isNotMinSignedValue() const;

                                                            
  bool isMinSignedValue() const;

                                                                        
                                                                          
  bool isFiniteNonZeroFP() const;

                                                                             
                                                                    
  bool isNormalFP() const;

                                                                            
                                                                                
  bool hasExactInverseFP() const;

                                                                      
                                                    
  bool isNaN() const;

                                                                          
               
  bool containsUndefElement() const;

                                                                             
                                                                 
  bool canTrap() const;

                                                        
  bool isThreadDependent() const;

                                                                    
  bool isDLLImportDependent() const;

                                                                               
                            
  bool isConstantUsed() const;

                                                                         
                                                                             
                                                       
     
                                             
  bool needsRelocation() const;

                                                                               
                                                                                
                                                                              
  Constant *getAggregateElement(unsigned Elt) const;
  Constant *getAggregateElement(Constant *Elt) const;

                                                                               
                                                            
  Constant *getSplatValue() const;

                                                                             
                                                                               
  const APInt &getUniqueInteger() const;

                                                                 
                                                                        
                                                                           
                                                                         
                                                                   
                                                                          
                   
  void destroyConstant();

                                                                        
  static bool classof(const Value *V) {
    static_assert(ConstantFirstVal == 0, "V->getValueID() >= ConstantFirstVal always succeeds");
    return V->getValueID() <= ConstantLastVal;
  }

                                                              
                                                       
                                                                               
                                                                            
                                                                               
                                                                           
                                                                               
                                                                           
                       
     
  void handleOperandChange(Value *, Value *);

  static Constant *getNullValue(Type* Ty);

                                                                            
                                                   
                            
  static Constant *getAllOnesValue(Type* Ty);

                                                                               
                                  
  static Constant *getIntegerValue(Type *Ty, const APInt &V);

                                                                                
                                                                            
                                                                              
                                 
  void removeDeadConstantUsers() const;

  const Constant *stripPointerCasts() const {
    return cast<Constant>(Value::stripPointerCasts());
  }

  Constant *stripPointerCasts() {
    return const_cast<Constant*>(
                      static_cast<const Constant *>(this)->stripPointerCasts());
  }
};

}                      

#endif                      

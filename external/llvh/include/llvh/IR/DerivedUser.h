//===- DerivedUser.h - Base for non-IR Users --------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_DERIVEDUSER_H
#define LLVM_IR_DERIVEDUSER_H

#include "llvh/IR/User.h"

namespace llvh {

class Type;
class Use;

                                                                          
                                                                          
                                                       
   
                                                                     
                                                                          
                                                                             
                               
class DerivedUser : public User {
protected:
  using  DeleteValueTy = void (*)(DerivedUser *);

private:
  friend class Value;

  DeleteValueTy DeleteValue;

public:
  DerivedUser(Type *Ty, unsigned VK, Use *U, unsigned NumOps,
              DeleteValueTy DeleteValue)
      : User(Ty, VK, U, NumOps), DeleteValue(DeleteValue) {}
};

}                      

#endif                         

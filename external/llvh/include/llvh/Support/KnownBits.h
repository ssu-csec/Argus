//===- llvm/Support/KnownBits.h - Stores known zeros/ones -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains a class for representing known zeros and ones used by
// computeKnownBits.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_KNOWNBITS_H
#define LLVM_SUPPORT_KNOWNBITS_H

#include "llvh/ADT/APInt.h"

namespace llvh {

                                                           
struct KnownBits {
  APInt Zero;
  APInt One;

private:
                                                                   
  KnownBits(APInt Zero, APInt One)
      : Zero(std::move(Zero)), One(std::move(One)) {}

public:
                                    
  KnownBits() {}

                                                                         
  KnownBits(unsigned BitWidth) : Zero(BitWidth, 0), One(BitWidth, 0) {}

                                      
  unsigned getBitWidth() const {
    assert(Zero.getBitWidth() == One.getBitWidth() &&
           "Zero and One should have the same width!");
    return Zero.getBitWidth();
  }

                                                       
  bool hasConflict() const { return Zero.intersects(One); }

                                                    
  bool isConstant() const {
    assert(!hasConflict() && "KnownBits conflict!");
    return Zero.countPopulation() + One.countPopulation() == getBitWidth();
  }

                                                                               
                                  
  const APInt &getConstant() const {
    assert(isConstant() && "Can only get value when all bits are known");
    return One;
  }

                                             
  bool isUnknown() const { return Zero.isNullValue() && One.isNullValue(); }

                                         
  void resetAll() {
    Zero.clearAllBits();
    One.clearAllBits();
  }

                                        
  bool isZero() const {
    assert(!hasConflict() && "KnownBits conflict!");
    return Zero.isAllOnesValue();
  }

                                            
  bool isAllOnes() const {
    assert(!hasConflict() && "KnownBits conflict!");
    return One.isAllOnesValue();
  }

                                                                          
  void setAllZero() {
    Zero.setAllBits();
    One.clearAllBits();
  }

                                                                         
  void setAllOnes() {
    Zero.clearAllBits();
    One.setAllBits();
  }

                                                         
  bool isNegative() const { return One.isSignBitSet(); }

                                                             
  bool isNonNegative() const { return Zero.isSignBitSet(); }

                               
  void makeNegative() {
    One.setSignBit();
  }

                                   
  void makeNonNegative() {
    Zero.setSignBit();
  }

                                                                         
                                             
  KnownBits trunc(unsigned BitWidth) {
    return KnownBits(Zero.trunc(BitWidth), One.trunc(BitWidth));
  }

                                                                             
                                                 
  KnownBits zext(unsigned BitWidth) {
    return KnownBits(Zero.zext(BitWidth), One.zext(BitWidth));
  }

                                                                             
                                                 
  KnownBits sext(unsigned BitWidth) {
    return KnownBits(Zero.sext(BitWidth), One.sext(BitWidth));
  }

                                                                               
                                                                          
  KnownBits zextOrTrunc(unsigned BitWidth) {
    return KnownBits(Zero.zextOrTrunc(BitWidth), One.zextOrTrunc(BitWidth));
  }

                                                       
  unsigned countMinTrailingZeros() const {
    return Zero.countTrailingOnes();
  }

                                                      
  unsigned countMinTrailingOnes() const {
    return One.countTrailingOnes();
  }

                                                      
  unsigned countMinLeadingZeros() const {
    return Zero.countLeadingOnes();
  }

                                                     
  unsigned countMinLeadingOnes() const {
    return One.countLeadingOnes();
  }

                                                                           
           
  unsigned countMinSignBits() const {
    if (isNonNegative())
      return countMinLeadingZeros();
    if (isNegative())
      return countMinLeadingOnes();
    return 0;
  }

                                                                
  unsigned countMaxTrailingZeros() const {
    return One.countTrailingZeros();
  }

                                                               
  unsigned countMaxTrailingOnes() const {
    return Zero.countTrailingZeros();
  }

                                                               
  unsigned countMaxLeadingZeros() const {
    return One.countLeadingZeros();
  }

                                                              
  unsigned countMaxLeadingOnes() const {
    return Zero.countLeadingZeros();
  }

                                                 
  unsigned countMinPopulation() const {
    return One.countPopulation();
  }

                                                           
  unsigned countMaxPopulation() const {
    return getBitWidth() - Zero.countPopulation();
  }

                                                           
  static KnownBits computeForAddSub(bool Add, bool NSW, const KnownBits &LHS,
                                    KnownBits RHS);
};

}                      

#endif

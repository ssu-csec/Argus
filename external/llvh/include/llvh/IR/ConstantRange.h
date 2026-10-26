//===- ConstantRange.h - Represent a range ----------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Represent a range of possible values that may occur when the program is run
// for an integral value.  This keeps track of a lower and upper bound for the
// constant, which MAY wrap around the end of the numeric range.  To do this, it
// keeps track of a [lower, upper) bound, which specifies an interval just like
// STL iterators.  When used with boolean values, the following are important
// ranges: :
//
//  [F, F) = {}     = Empty set
//  [T, F) = {T}
//  [F, T) = {F}
//  [T, T) = {F, T} = Full set
//
// The other integral ranges use min/max values for special range values. For
// example, for 8-bit types, it uses:
// [0, 0)     = {}       = Empty set
// [255, 255) = {0..255} = Full Set
//
// Note that ConstantRange can be used to represent either signed or
// unsigned ranges.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_CONSTANTRANGE_H
#define LLVM_IR_CONSTANTRANGE_H

#include "llvh/ADT/APInt.h"
#include "llvh/IR/InstrTypes.h"
#include "llvh/IR/Instruction.h"
#include "llvh/Support/Compiler.h"
#include <cstdint>

namespace llvh {

class MDNode;
class raw_ostream;

                                            
class LLVM_NODISCARD ConstantRange {
  APInt Lower, Upper;

public:
                                                                               
  explicit ConstantRange(uint32_t BitWidth, bool isFullSet = true);

                                                            
  ConstantRange(APInt Value);

                                                                      
                                                                           
                                                               
  ConstantRange(APInt Lower, APInt Upper);

                                                                                
                                                                         
                                                           
                                                                              
                                                                                
                                   
     
                                                                       
  static ConstantRange makeAllowedICmpRegion(CmpInst::Predicate Pred,
                                             const ConstantRange &Other);

                                                                          
                                                                         
                                        
                                                                               
                                                                            
                                           
     
                                                              
  static ConstantRange makeSatisfyingICmpRegion(CmpInst::Predicate Pred,
                                                const ConstantRange &Other);

                                                                                
                                                                               
                                                                              
                                                                        
                                  
     
                                                         
  static ConstantRange makeExactICmpRegion(CmpInst::Predicate Pred,
                                           const APInt &Other);

                                                                         
                                                           
     
                                                                              
                                                                        
                                                                          
                                                                              
                                          
     
               
                                             
                                              
                                                             
                                                           
                                                            
                                                                    
                       
                                                                         
                                                             
                                                          
                                                                    
                       
  static ConstantRange makeGuaranteedNoWrapRegion(Instruction::BinaryOps BinOp,
                                                  const ConstantRange &Other,
                                                  unsigned NoWrapKind);

                                         
                                                                             
                 
  bool getEquivalentICmp(CmpInst::Predicate &Pred, APInt &RHS) const;

                                            
  const APInt &getLower() const { return Lower; }

                                            
  const APInt &getUpper() const { return Upper; }

                                              
  uint32_t getBitWidth() const { return Lower.getBitWidth(); }

                                                                   
                         
  bool isFullSet() const;

                                                  
  bool isEmptySet() const;

                                                                
                            
  bool isWrappedSet() const;

                                                         
                                               
  bool isSignWrappedSet() const;

                                                       
  bool contains(const APInt &Val) const;

                                                             
  bool contains(const ConstantRange &CR) const;

                                                                              
  const APInt *getSingleElement() const {
    if (Upper == Lower + 1)
      return &Lower;
    return nullptr;
  }

                                                                                
           
  const APInt *getSingleMissingElement() const {
    if (Lower == Upper + 1)
      return &Upper;
    return nullptr;
  }

                                                          
  bool isSingleElement() const { return getSingleElement() != nullptr; }

                                                
  APInt getSetSize() const;

                                                       
  bool isSizeStrictlySmallerThan(const ConstantRange &CR) const;

                                               
  bool isSizeLargerThan(uint64_t MaxSize) const;

                                                                       
  APInt getUnsignedMax() const;

                                                                        
  APInt getUnsignedMin() const;

                                                                     
  APInt getSignedMax() const;

                                                                      
  APInt getSignedMin() const;

                                                          
  bool operator==(const ConstantRange &CR) const {
    return Lower == CR.Lower && Upper == CR.Upper;
  }
  bool operator!=(const ConstantRange &CR) const {
    return !operator==(CR);
  }

                                                                                
  ConstantRange subtract(const APInt &CI) const;

                                                                              
                
  ConstantRange difference(const ConstantRange &CR) const;

                                                            
                                                                          
                                                                          
                                                                        
                                                                        
                                     
  ConstantRange intersectWith(const ConstantRange &CR) const;

                                                                
                                                                           
                                                                             
                                                                               
                           
  ConstantRange unionWith(const ConstantRange &CR) const;

                                                                   
                                                                          
                                                                         
                                                                             
                                                                        
                                         
  ConstantRange castOp(Instruction::CastOps CastOp,
                       uint32_t BitWidth) const;

                                                                  
                                                                        
                                                                             
                                
  ConstantRange zeroExtend(uint32_t BitWidth) const;

                                                                  
                                                                        
                                                                             
                                
  ConstantRange signExtend(uint32_t BitWidth) const;

                                                                     
                                                                      
                                                                             
                                      
  ConstantRange truncate(uint32_t BitWidth) const;

                                                                  
                                                                             
  ConstantRange zextOrTrunc(uint32_t BitWidth) const;

                                                                  
                                                                             
  ConstantRange sextOrTrunc(uint32_t BitWidth) const;

                                                                   
                                                                               
                                                      
  ConstantRange binaryOp(Instruction::BinaryOps BinOp,
                         const ConstantRange &Other) const;

                                                                   
                                                                        
  ConstantRange add(const ConstantRange &Other) const;

                                                                          
                                                                        
  ConstantRange addWithNoSignedWrap(const APInt &Other) const;

                                                                   
                                                                          
  ConstantRange sub(const ConstantRange &Other) const;

                                                                   
                                                                             
                                                         
  ConstantRange multiply(const ConstantRange &Other) const;

                                                                   
                                                                             
  ConstantRange smax(const ConstantRange &Other) const;

                                                                   
                                                                                
  ConstantRange umax(const ConstantRange &Other) const;

                                                                   
                                                                             
  ConstantRange smin(const ConstantRange &Other) const;

                                                                   
                                                                                
  ConstantRange umin(const ConstantRange &Other) const;

                                                                   
                                                                       
               
  ConstantRange udiv(const ConstantRange &Other) const;

                                                                   
                                                                        
  ConstantRange binaryAnd(const ConstantRange &Other) const;

                                                                   
                                                                       
  ConstantRange binaryOr(const ConstantRange &Other) const;

                                                                   
                                                                        
                                             
  ConstantRange shl(const ConstantRange &Other) const;

                                                                          
                                                                           
  ConstantRange lshr(const ConstantRange &Other) const;

                                                                          
                                                                              
  ConstantRange ashr(const ConstantRange &Other) const;

                                                                    
  ConstantRange inverse() const;

                                       
  void print(raw_ostream &OS) const;

                                            
  void dump() const;
};

inline raw_ostream &operator<<(raw_ostream &OS, const ConstantRange &CR) {
  CR.print(OS);
  return OS;
}

                                                                
   
                                                                            
ConstantRange getConstantRangeFromMetadata(const MDNode &RangeMD);

}                      

#endif                           

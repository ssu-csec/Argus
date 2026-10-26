//===- BranchProbability.h - Branch Probability Wrapper ---------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Definition of BranchProbability shared by IR and Machine Instructions.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_BRANCHPROBABILITY_H
#define LLVM_SUPPORT_BRANCHPROBABILITY_H

#include "llvh/Support/DataTypes.h"
#include <algorithm>
#include <cassert>
#include <climits>
#include <numeric>

namespace llvh {

class raw_ostream;

                                                                              
                                                                             
                                                                        
              
class BranchProbability {
              
  uint32_t N;

                                            
  static const uint32_t D = 1u << 31;
  static const uint32_t UnknownN = UINT32_MAX;

                                                                               
                                     
  explicit BranchProbability(uint32_t n) : N(n) {}

public:
  BranchProbability() : N(UnknownN) {}
  BranchProbability(uint32_t Numerator, uint32_t Denominator);

  bool isZero() const { return N == 0; }
  bool isUnknown() const { return N == UnknownN; }

  static BranchProbability getZero() { return BranchProbability(0); }
  static BranchProbability getOne() { return BranchProbability(D); }
  static BranchProbability getUnknown() { return BranchProbability(UnknownN); }
                                                                         
                    
  static BranchProbability getRaw(uint32_t N) { return BranchProbability(N); }
                                                            
  static BranchProbability getBranchProbability(uint64_t Numerator,
                                                uint64_t Denominator);

                                                                             
         
  template <class ProbabilityIter>
  static void normalizeProbabilities(ProbabilityIter Begin,
                                     ProbabilityIter End);

  uint32_t getNumerator() const { return N; }
  static uint32_t getDenominator() { return D; }

                              
  BranchProbability getCompl() const { return BranchProbability(D - N); }

  raw_ostream &print(raw_ostream &OS) const;

  void dump() const;

                            
     
                                                                          
             
     
                                   
  uint64_t scale(uint64_t Num) const;

                                           
     
                                                                          
                                      
     
                                        
  uint64_t scaleByInverse(uint64_t Num) const;

  BranchProbability &operator+=(BranchProbability RHS) {
    assert(N != UnknownN && RHS.N != UnknownN &&
           "Unknown probability cannot participate in arithmetics.");
                                               
    N = (uint64_t(N) + RHS.N > D) ? D : N + RHS.N;
    return *this;
  }

  BranchProbability &operator-=(BranchProbability RHS) {
    assert(N != UnknownN && RHS.N != UnknownN &&
           "Unknown probability cannot participate in arithmetics.");
                                                
    N = N < RHS.N ? 0 : N - RHS.N;
    return *this;
  }

  BranchProbability &operator*=(BranchProbability RHS) {
    assert(N != UnknownN && RHS.N != UnknownN &&
           "Unknown probability cannot participate in arithmetics.");
    N = (static_cast<uint64_t>(N) * RHS.N + D / 2) / D;
    return *this;
  }

  BranchProbability &operator*=(uint32_t RHS) {
    assert(N != UnknownN &&
           "Unknown probability cannot participate in arithmetics.");
    N = (uint64_t(N) * RHS > D) ? D : N * RHS;
    return *this;
  }

  BranchProbability &operator/=(uint32_t RHS) {
    assert(N != UnknownN &&
           "Unknown probability cannot participate in arithmetics.");
    assert(RHS > 0 && "The divider cannot be zero.");
    N /= RHS;
    return *this;
  }

  BranchProbability operator+(BranchProbability RHS) const {
    BranchProbability Prob(*this);
    return Prob += RHS;
  }

  BranchProbability operator-(BranchProbability RHS) const {
    BranchProbability Prob(*this);
    return Prob -= RHS;
  }

  BranchProbability operator*(BranchProbability RHS) const {
    BranchProbability Prob(*this);
    return Prob *= RHS;
  }

  BranchProbability operator*(uint32_t RHS) const {
    BranchProbability Prob(*this);
    return Prob *= RHS;
  }

  BranchProbability operator/(uint32_t RHS) const {
    BranchProbability Prob(*this);
    return Prob /= RHS;
  }

  bool operator==(BranchProbability RHS) const { return N == RHS.N; }
  bool operator!=(BranchProbability RHS) const { return !(*this == RHS); }

  bool operator<(BranchProbability RHS) const {
    assert(N != UnknownN && RHS.N != UnknownN &&
           "Unknown probability cannot participate in comparisons.");
    return N < RHS.N;
  }

  bool operator>(BranchProbability RHS) const {
    assert(N != UnknownN && RHS.N != UnknownN &&
           "Unknown probability cannot participate in comparisons.");
    return RHS < *this;
  }

  bool operator<=(BranchProbability RHS) const {
    assert(N != UnknownN && RHS.N != UnknownN &&
           "Unknown probability cannot participate in comparisons.");
    return !(RHS < *this);
  }

  bool operator>=(BranchProbability RHS) const {
    assert(N != UnknownN && RHS.N != UnknownN &&
           "Unknown probability cannot participate in comparisons.");
    return !(*this < RHS);
  }
};

inline raw_ostream &operator<<(raw_ostream &OS, BranchProbability Prob) {
  return Prob.print(OS);
}

template <class ProbabilityIter>
void BranchProbability::normalizeProbabilities(ProbabilityIter Begin,
                                               ProbabilityIter End) {
  if (Begin == End)
    return;

  unsigned UnknownProbCount = 0;
  uint64_t Sum = std::accumulate(Begin, End, uint64_t(0),
                                 [&](uint64_t S, const BranchProbability &BP) {
                                   if (!BP.isUnknown())
                                     return S + BP.N;
                                   UnknownProbCount++;
                                   return S;
                                 });

  if (UnknownProbCount > 0) {
    BranchProbability ProbForUnknown = BranchProbability::getZero();
                                                                                
                                                                             
                                                                            
    if (Sum < BranchProbability::getDenominator())
      ProbForUnknown = BranchProbability::getRaw(
          (BranchProbability::getDenominator() - Sum) / UnknownProbCount);

    std::replace_if(Begin, End,
                    [](const BranchProbability &BP) { return BP.isUnknown(); },
                    ProbForUnknown);

    if (Sum <= BranchProbability::getDenominator())
      return;
  }

  if (Sum == 0) {
    BranchProbability BP(1, std::distance(Begin, End));
    std::fill(Begin, End, BP);
    return;
  }

  for (auto I = Begin; I != End; ++I)
    I->N = (I->N * uint64_t(D) + Sum / 2) / Sum;
}

}

#endif

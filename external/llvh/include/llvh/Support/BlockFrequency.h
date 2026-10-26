//===-------- BlockFrequency.h - Block Frequency Wrapper --------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements Block Frequency class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_BLOCKFREQUENCY_H
#define LLVM_SUPPORT_BLOCKFREQUENCY_H

#include "llvh/Support/BranchProbability.h"
#include "llvh/Support/DataTypes.h"

namespace llvh {

class raw_ostream;

                                                           
class BlockFrequency {
  uint64_t Frequency;

public:
  BlockFrequency(uint64_t Freq = 0) : Frequency(Freq) { }

                                                                   
  static uint64_t getMaxFrequency() { return -1ULL; }

                                                                    
                
  uint64_t getFrequency() const { return Frequency; }

                                                                      
               
  BlockFrequency &operator*=(BranchProbability Prob);
  BlockFrequency operator*(BranchProbability Prob) const;

                                                              
                 
  BlockFrequency &operator/=(BranchProbability Prob);
  BlockFrequency operator/(BranchProbability Prob) const;

                                                               
  BlockFrequency &operator+=(BlockFrequency Freq);
  BlockFrequency operator+(BlockFrequency Freq) const;

                                                                    
  BlockFrequency &operator-=(BlockFrequency Freq);
  BlockFrequency operator-(BlockFrequency Freq) const;

                                                                         
  BlockFrequency &operator>>=(const unsigned count);

  bool operator<(BlockFrequency RHS) const {
    return Frequency < RHS.Frequency;
  }

  bool operator<=(BlockFrequency RHS) const {
    return Frequency <= RHS.Frequency;
  }

  bool operator>(BlockFrequency RHS) const {
    return Frequency > RHS.Frequency;
  }

  bool operator>=(BlockFrequency RHS) const {
    return Frequency >= RHS.Frequency;
  }

  bool operator==(BlockFrequency RHS) const {
    return Frequency == RHS.Frequency;
  }
};

}

#endif

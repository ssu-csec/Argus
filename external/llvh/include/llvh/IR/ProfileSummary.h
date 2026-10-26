//===- ProfileSummary.h - Profile summary data structure. -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the profile summary data structure.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_PROFILESUMMARY_H
#define LLVM_IR_PROFILESUMMARY_H

#include <algorithm>
#include <cstdint>
#include <vector>

namespace llvh {

class LLVMContext;
class Metadata;

                                                                             
                                                                             
                                                                      
                                                                             
                                                                           
          
struct ProfileSummaryEntry {
  uint32_t Cutoff;                                           
  uint64_t MinCount;                                             
  uint64_t NumCounts;                                            

  ProfileSummaryEntry(uint32_t TheCutoff, uint64_t TheMinCount,
                      uint64_t TheNumCounts)
      : Cutoff(TheCutoff), MinCount(TheMinCount), NumCounts(TheNumCounts) {}
};

using SummaryEntryVector = std::vector<ProfileSummaryEntry>;

class ProfileSummary {
public:
  enum Kind { PSK_Instr, PSK_Sample };

private:
  const Kind PSK;
  static const char *KindStr[2];
  SummaryEntryVector DetailedSummary;
  uint64_t TotalCount, MaxCount, MaxInternalCount, MaxFunctionCount;
  uint32_t NumCounts, NumFunctions;
                                          
  Metadata *getDetailedSummaryMD(LLVMContext &Context);

public:
  static const int Scale = 1000000;

  ProfileSummary(Kind K, SummaryEntryVector DetailedSummary,
                 uint64_t TotalCount, uint64_t MaxCount,
                 uint64_t MaxInternalCount, uint64_t MaxFunctionCount,
                 uint32_t NumCounts, uint32_t NumFunctions)
      : PSK(K), DetailedSummary(std::move(DetailedSummary)),
        TotalCount(TotalCount), MaxCount(MaxCount),
        MaxInternalCount(MaxInternalCount), MaxFunctionCount(MaxFunctionCount),
        NumCounts(NumCounts), NumFunctions(NumFunctions) {}

  Kind getKind() const { return PSK; }
                                             
  Metadata *getMD(LLVMContext &Context);
                                             
  static ProfileSummary *getFromMD(Metadata *MD);
  SummaryEntryVector &getDetailedSummary() { return DetailedSummary; }
  uint32_t getNumFunctions() { return NumFunctions; }
  uint64_t getMaxFunctionCount() { return MaxFunctionCount; }
  uint32_t getNumCounts() { return NumCounts; }
  uint64_t getTotalCount() { return TotalCount; }
  uint64_t getMaxCount() { return MaxCount; }
  uint64_t getMaxInternalCount() { return MaxInternalCount; }
};

}                      

#endif                            

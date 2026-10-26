/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "instructionescapeanalysis"

#include "hermes/Optimizer/Scalar/InstructionEscapeAnalysis.h"

#include "llvh/Support/Casting.h"

#include <utility>

namespace hermes {

                                                                              
                                                                             
                                                                              
                                                                                
                                                            
  
           
  
                                                                     
                                                          
                                                          
                                                          
                                                             
  
                                                                            
                                                                           
                                                                           
                                                                     
void InstructionEscapeAnalysis::addRange(BasicBlock::range range) {
  assert(range.begin() != range.end() && "Range must be nonempty!");
  auxPrefixes_.lengthToOffset.clear();

                                                                        
  struct Escape {
    unsigned offset;
    unsigned numUsers;
  };
  llvh::DenseMap<const Instruction *, Escape> escapes;

  unsigned instructionIndex = 0;
  for (auto iter = range.begin(), end = range.end(); iter != end;
       ++iter, ++instructionIndex) {
    Instruction *inst = &*iter;
                                                                               
                                                                             
    for (unsigned i = 0, e = inst->getNumOperands(); i < e; ++i) {
      Value *op = inst->getOperand(i);
      if (auto *opInst = llvh::dyn_cast<Instruction>(op)) {
        const auto it = escapes.find(opInst);
        if (it != escapes.end()) {
          assert(it->second.numUsers >= 1 && "Invalid entry in escapes!");
          if (--it->second.numUsers == 0) {
            escapes.erase(it);
          }
        }
      }
    }

                                                    
    const auto numUsers = inst->getNumUsers();
    if (numUsers > 0) {
      auto insert =
          escapes.try_emplace(inst, Escape{instructionIndex, numUsers});
      (void)insert;
      assert(insert.second && "Failed to insert instruction in escapes map!");
    }

                                             
    const auto numEscapes = escapes.size();
    if (numEscapes <= 1) {
      const auto prefixLength = instructionIndex + 1;
      auto escapeOffset = numEscapes == 0
          ? llvh::None
          : EscapeOffset(escapes.begin()->second.offset);
                                                                                
                                                                                
      const auto it = prefixes_.lengthToOffset.find(prefixLength);
      if (numRanges_ == 0 ||
          (it != prefixes_.lengthToOffset.end() &&
           tryMergeOffsets(escapeOffset, it->second))) {
        auto insert =
            auxPrefixes_.lengthToOffset.try_emplace(prefixLength, escapeOffset);
        (void)insert;
        assert(insert.second && "Failed to insert prefix!");
        auxPrefixes_.longest = Prefix(prefixLength, escapeOffset);
      }
    }
  }
  assert(
      auxPrefixes_.longest.length > 0 &&
      "Nonempty range must have a prefix of length 1");

                                                                                
                                                      
  swap(prefixes_, auxPrefixes_);
  ++numRanges_;
  canRemove_ = true;
}

void InstructionEscapeAnalysis::removeLastRange() {
  assert(numRanges_ > 0 && "No ranges added yet!");
  assert(canRemove_ && "removeLastRange() called more than once!");
                                                                    
                                                                             
  swap(prefixes_, auxPrefixes_);
                                                                   
  auxPrefixes_.lengthToOffset.clear();
  --numRanges_;
  canRemove_ = false;
}

const InstructionEscapeAnalysis::Prefix &
InstructionEscapeAnalysis::longestPrefix() const {
  assert(numRanges_ > 0 && "No ranges added yet!");
  return prefixes_.longest;
}

                                                                               
                                                                                
                                             
bool InstructionEscapeAnalysis::tryMergeOffsets(
    EscapeOffset &acc,
    EscapeOffset offset) {
  if (!acc.hasValue()) {
    acc = offset;
    return true;
  }
  if (!offset.hasValue()) {
    return true;
  }
  return acc == offset;
}

}                    

#undef DEBUG_TYPE

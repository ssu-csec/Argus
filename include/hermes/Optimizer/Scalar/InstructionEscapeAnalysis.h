/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_OPTIMIZER_SCALAR_INSTRUCTION_ESCAPE_ANALYSIS_H
#define HERMES_OPTIMIZER_SCALAR_INSTRUCTION_ESCAPE_ANALYSIS_H

#include "hermes/IR/IR.h"
#include "hermes/Support/OptValue.h"

#include <cassert>

namespace hermes {

                                                                           
   
                                                                             
                                                                               
                                                                            
   
                                                                             
                                                                              
                                                                               
                                                                              
                                                                             
                                                                  
   
                                                                                
                                               
   
                                                                              
                                                                 
   
         
                        
                                             
                        
                                                      
                        
                                                
                        
                                                         
                         
                                             
                         
                                      
            
   
                                                                              
                                                                              
                                                                              
                                                                    
class InstructionEscapeAnalysis {
 public:
  explicit InstructionEscapeAnalysis() = default;

                                                                              
                                                                           
  using EscapeOffset = OptValue<unsigned>;

                                                                          
  struct Prefix {
                                                      
    unsigned length;
                                                           
    EscapeOffset offset;

    explicit Prefix(unsigned length, EscapeOffset offset = llvh::None)
        : length(length), offset(offset) {
      assert(
          (!offset.hasValue() || offset.getValue() < length) &&
          "Offset out of bounds!");
    }

    bool operator==(const Prefix &other) const {
      return length == other.length && offset == other.offset;
    }
  };

                                  
     
                                                           
  void addRange(BasicBlock::range range);

                                                                               
                                                                
  void removeLastRange();

                                                                              
                                          
  const Prefix &longestPrefix() const;

 private:
                                                                               
                                         
  static bool tryMergeOffsets(EscapeOffset &acc, EscapeOffset offset);

                                    
  unsigned numRanges_{0};
                                                                               
                                                                               
  bool canRemove_{false};

                                                                               
                                                                         
  struct PrefixSet {
                                                     
    llvh::DenseMap<unsigned, EscapeOffset> lengthToOffset;
                                      
    Prefix longest{0};

    friend void swap(PrefixSet &lhs, PrefixSet &rhs) {
      using std::swap;
      swap(lhs.lengthToOffset, rhs.lengthToOffset);
      swap(lhs.longest, rhs.longest);
    }
  };

                                                                           
  PrefixSet prefixes_;
                                                                              
                                                                         
  PrefixSet auxPrefixes_;
};

}                    

#endif                                                         

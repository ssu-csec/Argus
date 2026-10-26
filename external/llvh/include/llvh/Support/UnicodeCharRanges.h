//===--- UnicodeCharRanges.h - Types and functions for character ranges ---===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_SUPPORT_UNICODECHARRANGES_H
#define LLVM_SUPPORT_UNICODECHARRANGES_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/SmallPtrSet.h"
#include "llvh/Support/Compiler.h"
#include "llvh/Support/Debug.h"
#include "llvh/Support/Mutex.h"
#include "llvh/Support/MutexGuard.h"
#include "llvh/Support/raw_ostream.h"
#include <algorithm>

#define DEBUG_TYPE "unicode"

namespace llvh {
namespace sys {

                                                                    
struct UnicodeCharRange {
  uint32_t Lower;
  uint32_t Upper;
};

inline bool operator<(uint32_t Value, UnicodeCharRange Range) {
  return Value < Range.Lower;
}
inline bool operator<(UnicodeCharRange Range, uint32_t Value) {
  return Range.Upper < Value;
}

                                                                        
                                                                                
          
class UnicodeCharSet {
public:
  typedef ArrayRef<UnicodeCharRange> CharRanges;

                                                           
                        
     
                                                                             
                                                                               
                                                                        
                                                      
#ifdef NDEBUG

                                                                 
                                                                       
                                                                  
                                          
  constexpr UnicodeCharSet(CharRanges Ranges) : Ranges(Ranges) {}
#else
  UnicodeCharSet(CharRanges Ranges) : Ranges(Ranges) {
    assert(rangesAreValid());
  }
#endif

                                                                       
           
  bool contains(uint32_t C) const {
    return std::binary_search(Ranges.begin(), Ranges.end(), C);
  }

private:
                                                                 
                                                                               
  bool rangesAreValid() const {
    uint32_t Prev = 0;
    for (CharRanges::const_iterator I = Ranges.begin(), E = Ranges.end();
         I != E; ++I) {
      if (I != Ranges.begin() && Prev >= I->Lower) {
        LLVM_DEBUG(dbgs() << "Upper bound 0x");
        LLVM_DEBUG(dbgs().write_hex(Prev));
        LLVM_DEBUG(dbgs() << " should be less than succeeding lower bound 0x");
        LLVM_DEBUG(dbgs().write_hex(I->Lower) << "\n");
        return false;
      }
      if (I->Upper < I->Lower) {
        LLVM_DEBUG(dbgs() << "Upper bound 0x");
        LLVM_DEBUG(dbgs().write_hex(I->Lower));
        LLVM_DEBUG(dbgs() << " should not be less than lower bound 0x");
        LLVM_DEBUG(dbgs().write_hex(I->Upper) << "\n");
        return false;
      }
      Prev = I->Upper;
    }

    return true;
  }

  const CharRanges Ranges;
};

}                 
}                  

#undef DEBUG_TYPE             

#endif                                    

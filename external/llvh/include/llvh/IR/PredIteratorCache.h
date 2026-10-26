//===- PredIteratorCache.h - pred_iterator Cache ----------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the PredIteratorCache class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_PREDITERATORCACHE_H
#define LLVM_IR_PREDITERATORCACHE_H

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/IR/CFG.h"
#include "llvh/Support/Allocator.h"

namespace llvh {

                                                                    
                                                                          
                                                   
class PredIteratorCache {
                                                        
  mutable DenseMap<BasicBlock *, BasicBlock **> BlockToPredsMap;
  mutable DenseMap<BasicBlock *, unsigned> BlockToPredCountMap;

                                                         
  BumpPtrAllocator Memory;

private:
                                                                              
                                                                 
                                                                  
                    
                 
                                                                              
  BasicBlock **GetPreds(BasicBlock *BB) {
    BasicBlock **&Entry = BlockToPredsMap[BB];
    if (Entry)
      return Entry;

    SmallVector<BasicBlock *, 32> PredCache(pred_begin(BB), pred_end(BB));
    PredCache.push_back(nullptr);                    

    BlockToPredCountMap[BB] = PredCache.size() - 1;

    Entry = Memory.Allocate<BasicBlock *>(PredCache.size());
    std::copy(PredCache.begin(), PredCache.end(), Entry);
    return Entry;
  }

  unsigned GetNumPreds(BasicBlock *BB) const {
    auto Result = BlockToPredCountMap.find(BB);
    if (Result != BlockToPredCountMap.end())
      return Result->second;
    return BlockToPredCountMap[BB] = std::distance(pred_begin(BB), pred_end(BB));
  }

public:
  size_t size(BasicBlock *BB) const { return GetNumPreds(BB); }
  ArrayRef<BasicBlock *> get(BasicBlock *BB) {
    return makeArrayRef(GetPreds(BB), GetNumPreds(BB));
  }

                                     
  void clear() {
    BlockToPredsMap.clear();
    BlockToPredCountMap.clear();
    Memory.Reset();
  }
};

}                      

#endif

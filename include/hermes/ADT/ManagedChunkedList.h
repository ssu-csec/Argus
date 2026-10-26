/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_ADT_MANAGEDCHUNKEDLIST_H
#define HERMES_ADT_MANAGEDCHUNKEDLIST_H

#include "hermes/ADT/ExponentialMovingAverage.h"
#include "hermes/Support/SlowAssert.h"
#include "llvh/Support/Compiler.h"

#include <cmath>
#include <cstddef>
#include <utility>

namespace hermes {

                                                                               
                                                                         
                                                                            
                                                                         
                                                                              
                                                           
                                                               
                                                              
                                                                   
                                                                     
                                                                              
                
template <typename Element, size_t kElementsPerChunk = 16>
class ManagedChunkedList {
 public:
  using value_type = Element;

                                                                        
                                                                    
                                                                              
                                                            
  ManagedChunkedList(double occupancyRatio, double sizingWeight)
      : targetChunkCount_(sizingWeight, 0.0), occupancyRatio_{occupancyRatio} {}

                                                                            
                                  
  ManagedChunkedList(ManagedChunkedList &&other)
      : chunks_(other.chunks_),
        chunkCount_(other.chunkCount_),
        targetChunkCount_(other.targetChunkCount_),
        freeList_(other.freeList_),
        occupancyRatio_(other.occupancyRatio_) {
    other.chunks_ = nullptr;
  }

  ManagedChunkedList(const ManagedChunkedList &) = delete;
  ManagedChunkedList &operator=(const ManagedChunkedList &) = delete;

                                                         
  ~ManagedChunkedList() {
    while (Chunk *chunk = chunks_) {
      chunks_ = chunk->nextChunk;
      delete chunk;
    }
  }

                                                                       
                
  template <typename... Args>
  Element &add(Args &&...args) {
                                                        
    if (LLVM_UNLIKELY(!freeList_)) {
                                                                               
                     
      if (chunkCount_ < targetChunkCount_) {
                                                                             
                                                           
        allocateChunk();
      } else {
                                                             
        collect();

                                                                             
        if (!freeList_) {
          allocateChunk();
        }
      }
    }
    assert(freeList_ && "Freelist must be populated before inserting");

                                                                    
    Element &element = *freeList_;
    freeList_ = freeList_->getNextFree();
    assert(element.isFree() && "Premature element reuse");
    element.emplace(std::forward<Args>(args)...);
    HERMES_SLOW_ASSERT(checkWellFormed());
    return element;
  }

                                                                           
                                                                            
                                               
  template <typename Func>
  void forEach(Func accept) const {
    for (Chunk *chunk = chunks_; chunk; chunk = chunk->nextChunk) {
      for (Element &element : chunk->elements) {
        if (!element.isFree()) {
          accept(element);
        }
      }
    }
  }

                                                                              
                                               
  size_t capacity() const {
    return chunkCount_ * kElementsPerChunk;
  }

                                                                                
              
  size_t sizeForTests() const {
    size_t size = 0;
    forEach([&size](Element &) { size++; });
    return size;
  }

                                                                             
                                                  
  void collect() {
    HERMES_SLOW_ASSERT(checkWellFormed());

    freeList_ = nullptr;
    size_t occupiedElementCount = 0;

                                                                           
                                                                          
                                                                               
                                                                      
    size_t targetChunkCount = ceil(targetChunkCount_);
    Chunk **chunkListEndLoc = &chunks_;
    for (Chunk *chunk = chunks_; chunk;) {
      size_t chunkOccupiedElementCount = 0;
      Element *newFreeList = freeList_;

                                              
      for (Element &element : chunk->elements) {
        if (element.isFree()) {
          element.setNextFree(newFreeList);
          newFreeList = &element;
        } else {
          chunkOccupiedElementCount++;
        }
      }

      Chunk *nextChunk = chunk->nextChunk;
      if (chunkOccupiedElementCount == 0 && chunkCount_ > targetChunkCount) {
                                                                       
                            
        *chunkListEndLoc = nextChunk;
        chunkCount_--;
        delete chunk;
      } else {
        freeList_ = newFreeList;
        occupiedElementCount += chunkOccupiedElementCount;
        chunkListEndLoc = &chunk->nextChunk;
      }
      chunk = nextChunk;
    }

                                                                               
                                                                             
                           
    targetChunkCount_.update(
        occupiedElementCount / occupancyRatio_ / kElementsPerChunk);

    HERMES_SLOW_ASSERT(checkWellFormed());
  }

 private:
  struct Chunk {
    Chunk *nextChunk;
    Element elements[kElementsPerChunk];
  };

                                                                             
                                                                              
               
  void allocateChunk() {
    assert(!freeList_ && "Freelist must be empty before allocating a chunk");

    Chunk *chunk = new Chunk;

                                                                     
              
    Element *next = nullptr;
    for (Element &current : chunk->elements) {
      assert(current.isFree());
      current.setNextFree(next);
      next = &current;
    }

                                 
    chunk->nextChunk = chunks_;
    chunks_ = chunk;

                                                                            
                               
    freeList_ = next;

    chunkCount_++;

    HERMES_SLOW_ASSERT(checkWellFormed());
  }

  bool checkWellFormed() {
    for (Element *freeElement = freeList_; freeElement;
         freeElement = freeElement->getNextFree()) {
      if (!freeElement->isFree()) {
        return false;
      }
    }

    size_t chunkCount = 0;
    for (Chunk *chunk = chunks_; chunk; chunk = chunk->nextChunk) {
      chunkCount++;
    }
    if (chunkCount != chunkCount_) {
      return false;
    }

    return true;
  }

  Chunk *chunks_ = nullptr;
  size_t chunkCount_ = 0;
  ExponentialMovingAverage targetChunkCount_;
  Element *freeList_ = nullptr;
  double occupancyRatio_;
};

}                    

#endif                                   

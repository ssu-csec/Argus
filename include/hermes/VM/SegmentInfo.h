/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_SEGMENTINFO_H
#define HERMES_VM_SEGMENTINFO_H

#include "hermes/VM/AlignedStorage.h"

                                                                             
                                       
#if defined(HERMESVM_ALLOW_COMPRESSED_POINTERS) && LLVM_PTR_SIZE == 8 && \
    (defined(HERMESVM_GC_HADES) || defined(HERMESVM_GC_RUNTIME))
                                       
                                                                              
#define HERMESVM_COMPRESSED_POINTERS
#ifdef HERMESVM_ALLOW_CONTIGUOUS_HEAP
#define HERMESVM_CONTIGUOUS_HEAP
#endif
#endif

namespace hermes {
namespace vm {

                                                                                
                                                                               
                     
struct SegmentInfo {
                                                                              
                                                                       
                                                                              
  static unsigned segmentIndexFromStart(const void *lowLim) {
    assert(lowLim == AlignedStorage::start(lowLim) && "Precondition.");
    return get(lowLim)->index;
  }

                                                         
  static unsigned segmentIndex(const void *ptr) {
    return segmentIndexFromStart(AlignedStorage::start(ptr));
  }

                                                                         
                                       
  static void setSegmentIndexFromStart(void *lowLim, unsigned index) {
    assert(lowLim == AlignedStorage::start(lowLim) && "Precondition.");
    get(lowLim)->index = index;
  }

 private:
                                                                               
                                                            
                         
  static SegmentInfo *get(void *lowLim) {
    assert(lowLim == AlignedStorage::start(lowLim) && "Precondition.");
    return reinterpret_cast<SegmentInfo *>(lowLim);
  }

  static const SegmentInfo *get(const void *lowLim) {
    assert(lowLim == AlignedStorage::start(lowLim) && "Precondition.");
    return reinterpret_cast<const SegmentInfo *>(lowLim);
  }

  unsigned index;
};

}                
}                    

#endif

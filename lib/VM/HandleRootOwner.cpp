/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/HandleRootOwner.h"

#include "hermes/Support/CheckedMalloc.h"
#include "hermes/VM/GC.h"
#include "hermes/VM/HandleRootOwner-inline.h"

namespace hermes {
namespace vm {

                                                                                
                        

const PinnedHermesValue HandleRootOwner::nullPointer_{
    HermesValue::encodeNullptrObjectValueUnsafe()};
const PinnedHermesValue HandleRootOwner::undefinedValue_{
    HermesValue::encodeUndefinedValue()};
const PinnedHermesValue HandleRootOwner::nullValue_{
    HermesValue::encodeNullValue()};
const PinnedHermesValue HandleRootOwner::emptyValue_{
    HermesValue::encodeEmptyValue()};
const PinnedHermesValue HandleRootOwner::trueValue_{
    HermesValue::encodeBoolValue(true)};
const PinnedHermesValue HandleRootOwner::falseValue_{
    HermesValue::encodeBoolValue(false)};
const PinnedHermesValue HandleRootOwner::zeroValue_{HVConstants::kZero};
const PinnedHermesValue HandleRootOwner::oneValue_{HVConstants::kOne};
const PinnedHermesValue HandleRootOwner::negOneValue_{HVConstants::kNegOne};

void HandleRootOwner::markGCScopes(RootAcceptor &acceptor) {
  for (GCScope *gcScope = topGCScope_; gcScope; gcScope = gcScope->prevScope_)
    gcScope->mark(acceptor);
}

                                                                                
                

GCScope::~GCScope() {
                                       
  runtime_.topGCScope_ = prevScope_;

                                                                           
               
  auto it = chunks_.begin();
  auto e = chunks_.end();

  assert(it != e && "must have at least one chunk");
  ++it;                        
                                                                          
  invalidateFreedHandleValues(0, chunks_[0]);
  for (; it != e; ++it)
    ::free(*it);                                         

#ifdef HERMESVM_DEBUG_TRACK_GCSCOPE_HANDLES
  gcScopeHandleTracker.record(name_, maxAllocatedHandles_);
#endif
}

PinnedHermesValue *GCScope::_newChunkAndPHV(HermesValue value) {
  assert(next_ == curChunkEnd_ && "current chunk is not exhausted");

                            
  ++curChunkIndex_;

                                        
  if (curChunkIndex_ == chunks_.size()) {
                                                               
    void *mem = checkedMalloc2(CHUNK_SIZE, sizeof(PinnedHermesValue));
    chunks_.push_back(static_cast<PinnedHermesValue *>(mem));

                                
    next_ = chunks_.back();
  } else {
                                            
    next_ = chunks_[curChunkIndex_];
  }

  curChunkEnd_ = next_ + CHUNK_SIZE;

                                                                    
  return new (next_++) PinnedHermesValue(value);
}

void GCScope::mark(RootAcceptor &acceptor) {
  for (auto it = chunks_.begin(), e = it + curChunkIndex_ + 1; it != e; ++it) {
    PinnedHermesValue *first = *it;
    PinnedHermesValue *last = *it + CHUNK_SIZE;

                                                        
    if (curChunkEnd_ == last)
      last = next_;

                        
    for (; first != last; ++first)
      acceptor.acceptNullable(*first);
  }
}

#ifdef HERMES_SLOW_DEBUG
void GCScope::invalidateFreedHandleValues(
    unsigned chunkStart,
    PinnedHermesValue *valueStart) {
  std::fill(
      valueStart,
      chunks_[chunkStart] + CHUNK_SIZE,
      HermesValue::encodeInvalidValue());
  for (auto i = chunkStart + 1; i < curChunkIndex_; ++i) {
    std::fill(
        chunks_[i], chunks_[i] + CHUNK_SIZE, HermesValue::encodeInvalidValue());
  }
}
#endif

#ifdef HERMESVM_DEBUG_TRACK_GCSCOPE_HANDLES
GCScopeHandleTracker gcScopeHandleTracker;

GCScopeHandleTracker::~GCScopeHandleTracker() {
  {
                                 
    std::vector<CountMapT::value_type> histogram(
        countMap_.begin(), countMap_.end());
    std::sort(
        histogram.begin(),
        histogram.end(),
        [](const CountMapT::value_type &a, const CountMapT::value_type &b) {
          return a.first < b.first;
        });

    fprintf(stderr, "GCScope\n");
    fprintf(stderr, "HCount\tInstances\n");
    for (auto &p : histogram) {
      fprintf(
          stderr,
          "%-5u\t%-5u\t%s\n",
          p.first,
          p.second.first,
          p.second.second ? p.second.second : "");
    }
  }

  {
                    
    std::vector<NameMapT::value_type> byName(nameMap_.begin(), nameMap_.end());
    std::sort(
        byName.begin(),
        byName.end(),
        [](const NameMapT::value_type &a, const NameMapT::value_type &b) {
          return ::strcmp(a.first, b.first) < 0;
        });

    fprintf(stderr, "\nGCScope\n");
    fprintf(stderr, "Name\tMax HCount\n");

    for (auto &p : byName) {
      fprintf(stderr, "%s\t%u\n", p.first, p.second);
    }
  }
}

#endif

}                
}                    

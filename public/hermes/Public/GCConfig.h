/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PUBLIC_GCCONFIG_H
#define HERMES_PUBLIC_GCCONFIG_H

#include "hermes/Public/CtorConfig.h"
#include "hermes/Public/GCTripwireContext.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace hermes {
namespace vm {

                                                                       
                                                                            
                                                                                
               
using gcheapsize_t = uint32_t;

                                                 
                                                                              
               
struct BeforeAndAfter {
  uint64_t before;
  uint64_t after;
};

struct GCAnalyticsEvent {
                                                                            
                                                                               
                                                                            
  std::string runtimeDescription;

                                                                               
                 
  std::string gcKind;

                                                                          
                                                                             
                                                                       
                                                             
  std::string collectionType;

                                                                            
                                                                              
                                                              
  std::string cause;

                                                        
  std::chrono::milliseconds duration;

                                                                              
                                                                                
  std::chrono::milliseconds cpuDuration;

                                                                                
                                                                               
                                                                            
                               
                                                   
  BeforeAndAfter allocated;

                                                                             
                                                                          
              
                                                   
  BeforeAndAfter size;

                                                                      
                 
                                                   
  BeforeAndAfter external;

                                                                         
                                                                          
                                                                               
                                         
                                                   
  double survivalRatio;

                                                          
  std::vector<std::string> tags;
};

                                                                           
                                                                          
             
#define GC_TRIPWIRE_FIELDS(F)                                                  \
                                                                               \
                                                                               \
  F(constexpr, gcheapsize_t, Limit, std::numeric_limits<gcheapsize_t>::max())  \
                                                                               \
                                                                               \
  F(HERMES_NON_CONSTEXPR,                                                      \
    std::function<void(GCTripwireContext &)>,                                  \
    Callback,                                                                  \
    nullptr)                                                                   \
                              

_HERMES_CTORCONFIG_STRUCT(GCTripwireConfig, GC_TRIPWIRE_FIELDS, {})

#undef HEAP_TRIPWIRE_FIELDS

#define GC_HANDLESAN_FIELDS(F)                                        \
                                                                      \
                                                                      \
  F(constexpr, double, SanitizeRate, 0.0)                             \
                                                                      \
                                                                      \
                                                                      \
  F(constexpr, int64_t, RandomSeed, -1)                               \
                               

_HERMES_CTORCONFIG_STRUCT(GCSanitizeConfig, GC_HANDLESAN_FIELDS, {})

#undef GC_HANDLESAN_FIELDS

                                                       
enum ReleaseUnused {
  kReleaseUnusedNone = 0,                                        
  kReleaseUnusedOld,                                       
  kReleaseUnusedYoungOnFull,                                                  
  kReleaseUnusedYoungAlways                                                   
};

enum class GCEventKind {
  CollectionStart,
  CollectionEnd,
};

                                                                       
                                                            
#define GC_FIELDS(F)                                                     \
                                                                         \
  F(constexpr, gcheapsize_t, MinHeapSize, 0)                             \
                                                                         \
                                                                         \
  F(constexpr, gcheapsize_t, InitHeapSize, 32 << 20)                     \
                                                                         \
                                                                         \
  F(constexpr, gcheapsize_t, MaxHeapSize, 3u << 30)                      \
                                                                         \
                                                                         \
  F(constexpr, double, OccupancyTarget, 0.5)                             \
                                                                         \
                                                                         \
  F(constexpr,                                                           \
    unsigned,                                                            \
    EffectiveOOMThreshold,                                               \
    std::numeric_limits<unsigned>::max())                                \
                                                                         \
                                                                         \
  F(constexpr, GCSanitizeConfig, SanitizeConfig)                         \
                                                                         \
                                                                         \
  F(constexpr, bool, ShouldRecordStats, false)                           \
                                                                         \
                                                                         \
  F(constexpr, ReleaseUnused, ShouldReleaseUnused, kReleaseUnusedOld)    \
                                                                         \
                                                                         \
  F(HERMES_NON_CONSTEXPR, std::string, Name, "")                         \
                                                                         \
                                                                         \
  F(HERMES_NON_CONSTEXPR, GCTripwireConfig, TripwireConfig)              \
                                                                         \
                                                                         \
                                                                         \
  F(constexpr, bool, AllocInYoung, true)                                 \
                                                                         \
                                                                         \
  F(constexpr, bool, OverwriteDeadYGObjects, false)                      \
                                                                         \
                                                                         \
  F(constexpr, bool, RevertToYGAtTTI, false)                             \
                                                                         \
                                                                         \
  F(constexpr, bool, ProtectMetadata, false)                             \
                                                                         \
                                                                         \
  F(HERMES_NON_CONSTEXPR,                                                \
    std::function<void(const GCAnalyticsEvent &)>,                       \
    AnalyticsCallback,                                                   \
    nullptr)                                                             \
                                                                         \
                                                                         \
                                                                         \
                                                                         \
  F(HERMES_NON_CONSTEXPR,                                                \
    std::function<void(GCEventKind, const char *)>,                      \
    Callback,                                                            \
    nullptr)                                                             \
                     

_HERMES_CTORCONFIG_STRUCT(GCConfig, GC_FIELDS, {
  if (builder.hasMinHeapSize()) {
    if (builder.hasInitHeapSize()) {
                                                                             
                      
      InitHeapSize_ = std::max(MinHeapSize_, InitHeapSize_);
    } else {
                                                                            
                                             
      InitHeapSize_ = MinHeapSize_;
    }
  }
  assert(InitHeapSize_ >= MinHeapSize_);

                                            
  MaxHeapSize_ = std::max(InitHeapSize_, MaxHeapSize_);
})

#undef GC_FIELDS

}                
}                    

#endif                            

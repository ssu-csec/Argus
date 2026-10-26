/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_STATISTIC_H
#define HERMES_SUPPORT_STATISTIC_H

namespace hermes {
struct DummyCounter {
  DummyCounter &operator++(int) {
    return *this;
  }
  DummyCounter &operator++() {
    return *this;
  }
  DummyCounter &operator+=(int) {
    return *this;
  }
  DummyCounter &operator=(int) {
    return *this;
  }
};
}                    

#if !defined(NDEBUG) || defined(LLVM_ENABLE_STATS)
                           
#include "llvh/ADT/Statistic.h"

namespace hermes {
inline bool AreStatisticsEnabled() {
  return llvh::AreStatisticsEnabled();
}
inline void EnableStatistics() {
  llvh::EnableStatistics();
}
}                    

#else
                      
#define STATISTIC(Name, Desc) static hermes::DummyCounter Name;
namespace hermes {
inline bool AreStatisticsEnabled() {
  return false;
}
inline void EnableStatistics() {}
}                    
#endif

                                                                 
                                
#ifdef HERMES_SLOW_DEBUG
#define HERMES_SLOW_STATISTIC(Name, Desc) STATISTIC(Name, Desc)
#else
#define HERMES_SLOW_STATISTIC(Name, Desc) static hermes::DummyCounter Name;
#endif

#endif

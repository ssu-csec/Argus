/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_TIMER_H
#define HERMES_SUPPORT_TIMER_H

#if !defined(NDEBUG) || defined(LLVM_ENABLE_STATS)
                           
#include "llvh/Support/Timer.h"

namespace hermes {
using Timer = llvh::Timer;
using TimerGroup = llvh::TimerGroup;
using NamedRegionTimer = llvh::NamedRegionTimer;
using TimeRegion = llvh::TimeRegion;
}                    

#else
                      
#include "llvh/ADT/StringRef.h"

namespace hermes {
struct TimerGroup {
  TimerGroup(llvh::StringRef a, llvh::StringRef b) {}
};
struct Timer {
  Timer(llvh::StringRef a, llvh::StringRef b) {}
  Timer(const Timer &t) {}
  Timer(llvh::StringRef a, llvh::StringRef b, TimerGroup &tg) {}
};
struct NamedRegionTimer {
  NamedRegionTimer(
      llvh::StringRef a,
      llvh::StringRef b,
      llvh::StringRef c,
      llvh::StringRef d,
      bool Enabled = true) {}
};
struct TimeRegion {
  TimeRegion(Timer *t) {}
};
}                    

#endif

#endif

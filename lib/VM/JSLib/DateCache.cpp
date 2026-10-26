/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/JSLib/DateCache.h"

namespace hermes {
namespace vm {

double LocalTimeOffsetCache::getLocalTimeOffset(
    double timeMs,
    TimeType timeType) {
  if (needsToReset_) {
    reset();
  }

  if (timeType == TimeType::Utc) {
                                                    
    if (timeMs < -TIME_RANGE_MS || timeMs > TIME_RANGE_MS)
      return std::numeric_limits<double>::quiet_NaN();

    return ltza_ + daylightSavingOffsetInMs(timeMs);
  }
                                                                       
                                                                            
                                                                             
                                                                             
                                                           
                                          
    
                                                                            
                                                                         
                                                                            
                                                                    
    
                                                                            
                                                                       
                                                               
    
                                                                              
                                                                           
  double guessUTC = timeMs - ltza_ - MS_PER_HOUR;
  if (guessUTC < -TIME_RANGE_MS || guessUTC > TIME_RANGE_MS)
    return std::numeric_limits<double>::quiet_NaN();
  return ltza_ + daylightSavingOffsetInMs(guessUTC);
}

int LocalTimeOffsetCache::computeDaylightSaving(int64_t utcTimeMs) {
  std::time_t t = utcTimeMs / MS_PER_SECOND;
  std::tm tm;
#ifdef _WINDOWS
  auto err = ::localtime_s(&tm, &t);
  if (err) {
    return 0;
  }
                                                                                
                                                                             
                                                                     
                                                                              
              
#else
  std::tm *brokenTime = ::localtime_r(&t, &tm);
  if (!brokenTime) {
    return 0;
  }
  int dstOffset = tm.tm_isdst ? MS_PER_HOUR : 0;
  int ltza = tm.tm_gmtoff * MS_PER_SECOND - dstOffset;
                                                 
  if (ltza != ltza_) {
    needsToReset_ = true;
  }
#endif
  return tm.tm_isdst ? MS_PER_HOUR : 0;
}

int LocalTimeOffsetCache::daylightSavingOffsetInMs(int64_t utcTimeMs) {
  if (needsToReset_) {
    reset();
  }

                                                                                
                                                                     
                                                                              
                                                                            
                                                                          
  if (utcTimeMs < 0 || utcTimeMs > kMaxEpochTimeInMs) {
    utcTimeMs =
        detail::equivalentTime(utcTimeMs / MS_PER_SECOND) * MS_PER_SECOND;
  }

                                                                        
                                                                                
                                                                             
                                             
  if (LLVM_UNLIKELY(
          epoch_ >= std::numeric_limits<decltype(epoch_)>::max() - 10)) {
    reset();
  }

               
  if (candidate_->include(utcTimeMs)) {
    candidate_->epoch = bumpEpoch();
    return candidate_->dstOffsetMs;
  }

                                                                     
  auto [before, after] = findBeforeAndAfterEntries(utcTimeMs);
                                                                          
                                
  candidate_ = before;

                                                              
  if (before->isEmpty()) {
    int dstOffset = computeDaylightSaving(utcTimeMs);
    before->dstOffsetMs = dstOffset;
    before->startMs = utcTimeMs;
    before->endMs = utcTimeMs;
    before->epoch = bumpEpoch();
    return dstOffset;
  }

                                 
  if (before->include(utcTimeMs)) {
    before->epoch = bumpEpoch();
    return before->dstOffsetMs;
  }

                                                                             
                                                                             
                                                                     
  if ((utcTimeMs - kDSTDeltaMs) > before->endMs) {
    int dstOffset = computeDaylightSaving(utcTimeMs);
    extendOrRecomputeCacheEntry(after, utcTimeMs, dstOffset);
                                                                              
                            
    candidate_ = after;
    return dstOffset;
  }

                                                                      
                  

  before->epoch = bumpEpoch();
  int64_t newAfterStart = before->endMs < kMaxEpochTimeInMs - kDSTDeltaMs
      ? before->endMs + kDSTDeltaMs
      : kMaxEpochTimeInMs;
                                                                          
  if (newAfterStart < after->startMs) {
    int dstOffset = computeDaylightSaving(newAfterStart);
    extendOrRecomputeCacheEntry(after, newAfterStart, dstOffset);
  } else {
    after->epoch = bumpEpoch();
  }

                                                                           

                                                              
  if (before->dstOffsetMs == after->dstOffsetMs) {
    before->endMs = after->endMs;
    *after = DSTCacheEntry{};
    return before->dstOffsetMs;
  }

                                                                        
                                                                        
                                                                          
                                         
                                                                      
                                                                             
                                                                             
            
  for (int i = 4; i >= 0; --i) {
    int delta = after->startMs - before->endMs;
    int64_t middle = before->endMs + delta / 2;
    int middleDstOffset = computeDaylightSaving(middle);
    if (before->dstOffsetMs == middleDstOffset) {
      before->endMs = middle;
      if (utcTimeMs <= before->endMs) {
        return middleDstOffset;
      }
    } else {
      assert(after->dstOffsetMs == middleDstOffset);
      after->startMs = middle;
      if (utcTimeMs >= after->startMs) {
                                                                             
                                     
        candidate_ = after;
        return middleDstOffset;
      }
    }
  }

  // Fallthrough path of the binary search, just compute the DST for utcTimeMs.
  return computeDaylightSaving(utcTimeMs);
}

LocalTimeOffsetCache::DSTCacheEntry *
LocalTimeOffsetCache::leastRecentlyUsedExcept(const DSTCacheEntry *const skip) {
  DSTCacheEntry *result = nullptr;
  for (auto &cache : caches_) {
    if (&cache == skip)
      continue;
    if (!result || result->epoch > cache.epoch)
      result = &cache;
  }
  *result = DSTCacheEntry{};
  return result;
}

std::tuple<
    LocalTimeOffsetCache::DSTCacheEntry *,
    LocalTimeOffsetCache::DSTCacheEntry *>
LocalTimeOffsetCache::findBeforeAndAfterEntries(int64_t timeMs) {
  LocalTimeOffsetCache::DSTCacheEntry *before = nullptr;
  LocalTimeOffsetCache::DSTCacheEntry *after = nullptr;

                                                                           
                                                         
  for (auto &cache : caches_) {
    if (cache.startMs <= timeMs) {
      if (!before || before->startMs < cache.startMs)
        before = &cache;
    } else if (timeMs < cache.endMs) {
      if (!after || after->endMs > cache.endMs)
        after = &cache;
    }
  }

                                                               
  if (!before) {
    before = leastRecentlyUsedExcept(after);
  }
  if (!after) {
    after = leastRecentlyUsedExcept(before);
  }

  assert(
      before && after && before != after &&
      "`before` and `after` interval should be valid");
  assert(
      before->isEmpty() ||
      before->startMs <= timeMs &&
          "the start time of `before` must start on or before timeMs");
  assert(
      after->isEmpty() ||
      timeMs < after->startMs &&
          "The start time of `after` must start after timeMs");
  assert(
      before->isEmpty() || after->isEmpty() ||
      before->endMs < after->startMs &&
          "`before` interval must strictly start before `after` interval");

  return {before, after};
}

void LocalTimeOffsetCache::extendOrRecomputeCacheEntry(
    DSTCacheEntry *&entry,
    int64_t timeMs,
    int dstOffsetMs) {
                                                                        
  if (entry->dstOffsetMs == dstOffsetMs &&
      entry->startMs - kDSTDeltaMs <= timeMs && timeMs <= entry->endMs) {
    entry->startMs = timeMs;
  } else {
                                              
    if (!entry->isEmpty()) {
      entry = leastRecentlyUsedExcept(candidate_);
    }
    entry->startMs = timeMs;
    entry->endMs = timeMs;
    entry->dstOffsetMs = dstOffsetMs;
    entry->epoch = bumpEpoch();
  }
}

}                
}                    

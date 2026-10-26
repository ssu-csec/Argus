/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_JSLIB_DATECACHE_H
#define HERMES_VM_JSLIB_DATECACHE_H

#include "hermes/VM/JSLib/DateUtil.h"

namespace hermes {
namespace vm {

                                         
enum class TimeType : int8_t {
  Local,
  Utc,
};

                                                               
   
                                                                              
                                                                              
                                                                                
                                                                             
                                                                           
                        
   
                                                        
                                                                              
                                                                            
                                                                              
                                                                        
                                                                               
                                                                              
                                                    
                                                                              
                                                                 
                                                            
                                                                       
                
                                                                               
                
                                                                             
                                                                             
                                                             
                                                                               
                                                               
                                                                           
                                               
                                                                            
                                                                                
                                                                                
                                              
                                                                         
                                                                     
                                                                  
                                                                    
                                                                 
                                                                          
                                                                            
                                                                             
                      
                                                      
   
                                                                
                                                                               
                                      
                                                                         
                                                                            
                                                                   
   
                                                                               
                                                                             
                                                                            
                                                                             
                                                                                
                                                                                
                                                                                
                                                                             
                                         
class LocalTimeOffsetCache {
 public:
                                                                   
                                                                               
                                                                              
                               
  LocalTimeOffsetCache() {
    reset();
  }

                                                             
  void reset() {
    ::tzset();
    ltza_ = localTZA();
    caches_.fill(DSTCacheEntry{});
    candidate_ = caches_.data();
    epoch_ = 0;
    needsToReset_ = false;
  }

                                                   
                                         
                                                             
  double getLocalTimeOffset(double timeMs, TimeType timeType);

                                                 
                                                          
  int daylightSavingOffsetInMs(int64_t utcTimeMs);

 private:
  LocalTimeOffsetCache(const LocalTimeOffsetCache &) = delete;
  LocalTimeOffsetCache operator=(const LocalTimeOffsetCache &) = delete;

                                              
  static constexpr unsigned kCacheSize = 32;
                                                                            
                                                                               
                                                                               
                                                                              
                   
  static constexpr int64_t kDSTDeltaMs = 19 * SECONDS_PER_DAY * MS_PER_SECOND;
                                                                           
  static constexpr int64_t kMaxEpochTimeInMs =
      std::numeric_limits<int32_t>::max() * MS_PER_SECOND;

  struct DSTCacheEntry {
                                                                   
    int64_t startMs{kMaxEpochTimeInMs};
    int64_t endMs{-kMaxEpochTimeInMs};
                                           
    int dstOffsetMs{0};
                     
    int epoch{0};

                                                 
    bool isEmpty() const {
      return startMs > endMs;
    }

                                                                  
    bool include(int64_t utcTimeMs) const {
      return startMs <= utcTimeMs && utcTimeMs <= endMs;
    }
  };

                                                   
                                                                       
                                          
  int computeDaylightSaving(int64_t utcTimeMs);

                                               
  int bumpEpoch() {
    ++epoch_;
    return epoch_;
  }

                                                          
                                                                               
                                                                               
                                                               
                                                                   
  DSTCacheEntry *leastRecentlyUsedExcept(const DSTCacheEntry *const skip);

                                                                          
                                                                           
                                                                            
                              
  std::tuple<DSTCacheEntry *, DSTCacheEntry *> findBeforeAndAfterEntries(
      int64_t timeMs);

                                                                          
                                                                   
                             
                                                                          
                                                                          
                                                       
  void extendOrRecomputeCacheEntry(
      DSTCacheEntry *&entry,
      int64_t timeMs,
      int dstOffsetMs);

                                                             
  int epoch_;
                                                                        
                                                                               
                                                                   
  DSTCacheEntry *candidate_;
                                                                          
                                                                         
                                                                        
                                                                
  std::array<DSTCacheEntry, kCacheSize> caches_;
                                                              
  int64_t ltza_;
                                                 
                                                                                
                                                                             
                                                                          
                                                                               
                                                                               
                  
  bool needsToReset_;
};

}                
}                    

#endif                               

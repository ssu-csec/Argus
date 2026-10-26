/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef INLINECACHE_PROFILER_H
#define INLINECACHE_PROFILER_H

#include "hermes/VM/SymbolID.h"
#include "llvh/ADT/DenseMap.h"
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace inst {
struct Inst;
}

namespace vm {

class CodeBlock;
class HiddenClass;
class JSArray;
class Runtime;

class InlineCacheProfiler {
 public:
  using ClassId = uint64_t;
  using PropertyId = uint32_t;
  using ICSrcKey = std::pair<uint32_t, CodeBlock *>;
                                                                           
                                                                           
                      
  using HiddenClassPair = std::pair<ClassId, ClassId>;
                                                 
                                                                               
                                                                                
  using ICMissKey = std::pair<PropertyId, HiddenClassPair>;

                                                                            
                                                                  
  struct ICMiss {
                                                                             
    void insertMiss(ICMissKey icRecord) {
      auto ret =
          hiddenClasses.insert(std::pair<ICMissKey, uint32_t>(icRecord, 1));
      if (!ret.second) {
        ++(ret.first->second);
      }
      ++missCount;
    }

                                                                            
    void incrementHit() {
      ++hitCount;
    }

                                                                     
    uint64_t missCount{0};

                                                                   
    uint64_t hitCount{0};

                                                            
                                                                               
    llvh::DenseMap<ICMissKey, uint64_t> hiddenClasses;
  };

  using ICMissList = std::vector<std::pair<ICSrcKey, ICMiss>>;

                                                             
                                                   
  ICMiss &getICMissBySourceLocation(CodeBlock *codeblock, uint32_t instOffset);

                                    
  bool insertICMiss(
      CodeBlock *codeblock,
      uint32_t instOffset,
      SymbolID &propertyID,
      ClassId objectHiddenClassId,
      ClassId cachedHiddenClassId);

                                   
  bool insertICHit(CodeBlock *codeblock, uint32_t instOffset);

                                                    
  uint32_t getTotalMisses() {
    return totalMisses_;
  }

                                                                    
                        
  JSArray *&getHiddenClassArray();

                                                                    
                        
  void setHiddenClassArray(JSArray *hiddenClassArray);

                                                                
                                          
  uint32_t &getHiddenClassArrayIndex();

                                                          
                                               
  llvh::DenseMap<InlineCacheProfiler::ClassId, int32_t> &getClassIdtoIndexMap();

                                                      
                                                                 
                                                         
  void dumpRankedInlineCachingMisses(
      Runtime &runtime,
      llvh::raw_ostream &ostream);

 private:
                                                               
                                          
  uint32_t hcIdx_{0};

                                                        
                                 
  JSArray *cachedHiddenClassesRawPtr_{nullptr};

                                                            
                                               
  llvh::DenseMap<InlineCacheProfiler::ClassId, int32_t> classIdToIdx_;

                                                               
                                                                  
                                                                    
                                                            
  std::unique_ptr<InlineCacheProfiler::ICMissList>
  getRankedInlineCachingMisses();

                                                                            
                                              
  void dumpInfoOfSourceLocation(
      ICSrcKey &srcLoc,
      ICMiss &icMiss,
      Runtime &runtime,
      llvh::raw_ostream &ostream);

                                              
                                                           
  void dumpInlineCachingMissRecord(
      ICMissKey &icInfo,
      uint64_t icMiss,
      Runtime &runtime,
      llvh::raw_ostream &ostream);

                                                   
  void dumpHiddenClassProperties(
      llvh::raw_ostream &ostream,
      HiddenClass *hc,
      Runtime &runtime);

                                                                         
  uint64_t totalMisses_{0};

                                                                       
  uint64_t totalHits_{0};

                                                                        
                                                                        
                                                                           
  llvh::DenseMap<ICSrcKey, ICMiss> cacheMisses_;
};

}                
}                    
#pragma GCC diagnostic pop

#endif

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifdef HERMESVM_PROFILER_BB
#ifndef INLINECACHE_PROFILER_H
#include "hermes/VM/Profiler/InlineCacheProfiler.h"
#include "hermes/Support/Algorithms.h"
#include "hermes/VM/CodeBlock.h"
#include "hermes/VM/Handle.h"
#include "hermes/VM/HiddenClass.h"
#include "hermes/VM/JSArray.h"
#include "hermes/VM/Runtime.h"
#include "hermes/VM/StringView.h"
#include "hermes/VM/SymbolID.h"

#include <iomanip>
#include <sstream>
#include <vector>

namespace hermes {
namespace vm {

InlineCacheProfiler::ICMiss &InlineCacheProfiler::getICMissBySourceLocation(
    CodeBlock *codeblock,
    uint32_t instOffset) {
                                                                      
  ICSrcKey icKey(instOffset, codeblock);
  auto it = cacheMisses_.find(icKey);
  if (it == cacheMisses_.end()) {
    ICMiss icMiss;
    auto p = cacheMisses_.try_emplace(icKey, icMiss);
    assert(p.second && "Guaranteed to insert");
    it = p.first;
  }
  return it->second;
}

bool InlineCacheProfiler::insertICMiss(
    CodeBlock *codeblock,
    uint32_t instOffset,
    SymbolID &propertyID,
    ClassId objectHiddenClassId,
    ClassId cachedHiddenClassId) {
  ICMiss &icMiss = getICMissBySourceLocation(codeblock, instOffset);
                                                         
  auto hcPair =
      std::pair<ClassId, ClassId>(objectHiddenClassId, cachedHiddenClassId);
  auto icRecord =
      std::pair<PropertyId, HiddenClassPair>(propertyID.unsafeGetRaw(), hcPair);
  icMiss.insertMiss(icRecord);

  ++totalMisses_;
  return true;
}

bool InlineCacheProfiler::insertICHit(
    CodeBlock *codeblock,
    uint32_t instOffset) {
                                                                      
  ICMiss &icMiss = getICMissBySourceLocation(codeblock, instOffset);
  icMiss.incrementHit();

  ++totalHits_;
  return true;
}

JSArray *&InlineCacheProfiler::getHiddenClassArray() {
  return cachedHiddenClassesRawPtr_;
}

void InlineCacheProfiler::setHiddenClassArray(JSArray *hiddenClassArray) {
  cachedHiddenClassesRawPtr_ = hiddenClassArray;
}

uint32_t &InlineCacheProfiler::getHiddenClassArrayIndex() {
  return hcIdx_;
}

llvh::DenseMap<InlineCacheProfiler::ClassId, int32_t> &
InlineCacheProfiler::getClassIdtoIndexMap() {
  return classIdToIdx_;
}

void InlineCacheProfiler::dumpHiddenClassProperties(
    llvh::raw_ostream &ostream,
    HiddenClass *hc,
    Runtime &runtime) {
  ostream << "\t\t";
  if (hc == nullptr) {
    ostream << "[none]\n";
    return;
  }
  if (hc->isDictionary()) {
    ostream << "[dict] ";
  }
  ostream << "<";
  bool first = true;
  HiddenClass::forEachPropertyNoAlloc(
      hc,
      runtime,
      [&ostream, &runtime, &first](
          SymbolID symId, NamedPropertyDescriptor desc) {
        if (first) {
          first = false;
        } else {
          ostream << ", ";
        }
        ostream << runtime.convertSymbolToUTF8(symId);
      });
  ostream << ">\n";
}

std::unique_ptr<InlineCacheProfiler::ICMissList>
InlineCacheProfiler::getRankedInlineCachingMisses() {
  std::unique_ptr<InlineCacheProfiler::ICMissList> icInfoList =
      std::make_unique<InlineCacheProfiler::ICMissList>();
                                         
  for (auto itr = cacheMisses_.begin(); itr != cacheMisses_.end(); ++itr) {
    icInfoList->push_back(*itr);
  }
  auto compare = [](std::pair<ICSrcKey, ICMiss> &a,
                    std::pair<ICSrcKey, ICMiss> &b) {
                               
    return a.second.missCount > b.second.missCount;
  };
  std::sort(icInfoList->begin(), icInfoList->end(), compare);
  return icInfoList;
}

void InlineCacheProfiler::dumpInlineCachingMissRecord(
    ICMissKey &icInfo,
    uint64_t icMiss,
    Runtime &runtime,
    llvh::raw_ostream &ostream) {
  GCScope gcscope(runtime);

                                         
  auto propSymbolID = SymbolID::unsafeCreate(icInfo.first);
  auto propName = runtime.convertSymbolToUTF8(propSymbolID);
  ostream << "\tproperty: " << propName << ", inline cache misses: " << icMiss
          << "\n";

                                                           
  HiddenClassPair hcPair = icInfo.second;
  HiddenClass *objectHiddenClass = runtime.resolveHiddenClassId(hcPair.first);
  HiddenClass *cachedHiddenClass = runtime.resolveHiddenClassId(hcPair.second);
  dumpHiddenClassProperties(ostream, objectHiddenClass, runtime);
  dumpHiddenClassProperties(ostream, cachedHiddenClass, runtime);
  ostream << "\n";
  ostream.flush();
}

void InlineCacheProfiler::dumpInfoOfSourceLocation(
    ICSrcKey &srcLoc,
    ICMiss &icMiss,
    Runtime &runtime,
    llvh::raw_ostream &ostream) {
                                                 
  auto locOrNull = runtime.getIPSourceLocation(
      srcLoc.second, srcLoc.second->getOffsetPtr(srcLoc.first));

                                              
  if (locOrNull.hasValue()) {
                                      
    auto loc = locOrNull.getValue();
    ostream << "[" << std::get<0>(loc) << ":" << std::get<1>(loc) << ":"
            << std::get<2>(loc) << "] ";

                                       
    std::stringstream stream;
    stream << std::fixed << std::setprecision(1)
           << (1. * icMiss.missCount) / (icMiss.missCount + icMiss.hitCount);
    std::string missRatio = stream.str();
    ostream << "total access: " << icMiss.missCount + icMiss.hitCount
            << ", miss ratio: " << missRatio << "\n";
  } else {
    ostream << "[No Loc]\n";
  }
}

                                                                      
                                                                     
                                                
                                                                         
   
                                                                      
                                                              
                                                 
                                                                  
                                                                  
   
                                                 
                                                                  
                                                                  
        
void InlineCacheProfiler::dumpRankedInlineCachingMisses(
    Runtime &runtime,
    llvh::raw_ostream &ostream) {
                                   
  std::shared_ptr<InlineCacheProfiler::ICMissList> icInfoList =
      getRankedInlineCachingMisses();

  uint64_t recordPrinted = 0;
                                                                     
  for (auto &cacheMissEntry : *icInfoList) {
    ICMiss &icMiss = cacheMissEntry.second;
                                 
    if (recordPrinted++ >= 10) {
      break;
    }

                                                      
    ICSrcKey &srcLoc = cacheMissEntry.first;
    dumpInfoOfSourceLocation(srcLoc, icMiss, runtime, ostream);

                                                                                
    for (auto &missHCEntry : icMiss.hiddenClasses) {
      ICMissKey &icInfo = missHCEntry.first;
      uint64_t icMiss = missHCEntry.second;
      dumpInlineCachingMissRecord(icInfo, icMiss, runtime, ostream);
    }
  }
}

}                
}                    
#endif
#endif

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_PROFILER_CHROMETRACESERIALIZER_H
#define HERMES_VM_PROFILER_CHROMETRACESERIALIZER_H

#include "hermes/VM/Profiler/SamplingProfilerDefs.h"

#if HERMESVM_SAMPLING_PROFILER_AVAILABLE
                                                                               
                                                                              
                                                                              

                                                                         
                       
                                                                                           

#include "hermes/Support/JSONEmitter.h"
#include "hermes/VM/Profiler/SamplingProfiler.h"

#include "llvh/ADT/DenseMap.h"

#include <thread>

namespace hermes {
namespace vm {

                                       
class ChromeFrameIdGenerator {
  uint32_t nextFrameId_{1};

 public:
  uint32_t getNextFrameNodeId() {
    return nextFrameId_++;
  }
};

                                                                     
                           
class ChromeStackFrameNode {
 private:
                                    
  uint32_t id_;
                                                           
  llvh::Optional<SamplingProfiler::StackFrame> frameInfo_;
                                              
  std::vector<std::shared_ptr<ChromeStackFrameNode>> children_;
                                                                                
  uint32_t hitCount_ = 0;

                                                   
                                             
  using DfsWalkCallback = const std::function<void(
      const ChromeStackFrameNode &node,
      const ChromeStackFrameNode *parent)>;

 private:
  void dfsWalkHelper(
      DfsWalkCallback &callback,
      const ChromeStackFrameNode *parent) const {
    callback(*this, parent);
    for (const auto &child : children_) {
      child->dfsWalkHelper(callback, this);
    }
  }

 public:
  explicit ChromeStackFrameNode(
      uint32_t nextFrameId,
      llvh::Optional<SamplingProfiler::StackFrame> frame)
      : id_(nextFrameId), frameInfo_(frame) {}

  uint32_t getId() const {
    return id_;
  }

                                                                              
                           
  const SamplingProfiler::StackFrame &getFrameInfo() const {
    return *frameInfo_;
  }

                                                
  void addHit() {
    ++hitCount_;
  }

                                      
  uint32_t getHitCount() const {
    return hitCount_;
  }

                                                                   
                     
                                         
  std::shared_ptr<ChromeStackFrameNode> findOrAddNewChild(
      ChromeFrameIdGenerator &frameIdGen,
      const SamplingProfiler::StackFrame &target);

                                                        
                                                
  void dfsWalk(DfsWalkCallback &callback) const {
    this->dfsWalkHelper(callback, nullptr);
  }

                                                        
  const std::vector<std::shared_ptr<ChromeStackFrameNode>> &getChildren()
      const {
    return children_;
  }
};

                                                                    
class ChromeSampleEvent {
 private:
                           
  int cpu_{-1};
                                
  int weight_{1};
  SamplingProfiler::ThreadId tid_;
  SamplingProfiler::TimeStampType timeStamp_;
  std::shared_ptr<ChromeStackFrameNode> leafNode_;

 public:
  explicit ChromeSampleEvent(
      SamplingProfiler::ThreadId tid,
      SamplingProfiler::TimeStampType timeStamp,
      std::shared_ptr<ChromeStackFrameNode> leaf)
      : tid_(tid), timeStamp_(timeStamp), leafNode_(leaf) {}

                     
  int getCpu() const {
    return cpu_;
  }

                     
  int getWeight() const {
    return weight_;
  }

                              
  SamplingProfiler::ThreadId getTid() const {
    return tid_;
  }

                                         
  SamplingProfiler::TimeStampType getTimeStamp() const {
    return timeStamp_;
  }

                                                                   
                                
  std::shared_ptr<ChromeStackFrameNode> getLeafNode() const {
    return leafNode_;
  }
};

                                                                  
class ChromeTraceFormat {
 private:
                           
  uint32_t pid_;
                       
  SamplingProfiler::ThreadNamesMap threadNames_;
                                       
  const std::shared_ptr<ChromeStackFrameNode> root_;
                                                    
  std::vector<ChromeSampleEvent> sampleEvents_;

  explicit ChromeTraceFormat(
      uint32_t pid,
      const SamplingProfiler::ThreadNamesMap &threadNames,
      std::unique_ptr<ChromeStackFrameNode> root)
      : pid_(pid), threadNames_(threadNames), root_(std::move(root)) {}

 public:
  static ChromeTraceFormat create(
      uint32_t pid,
      const SamplingProfiler::ThreadNamesMap &threadNames,
      const std::vector<SamplingProfiler::StackTrace> &sampledStacks);

  uint32_t getPid() const {
    return pid_;
  }

  const SamplingProfiler::ThreadNamesMap &getThreadNames() const {
    return threadNames_;
  }

  const ChromeStackFrameNode &getRoot() const {
    return *root_;
  }

  const std::vector<ChromeSampleEvent> &getSampledEvents() const {
    return sampleEvents_;
  }
};

                                                       
class ChromeTraceSerializer {
 private:
  const SamplingProfiler &samplingProfiler_;
  ChromeTraceFormat trace_;
  SamplingProfiler::TimeStampType firstEventTimeStamp_;

 private:
                                      
  void serializeProcessName(JSONEmitter &json) const;
                                 
  void serializeThreads(JSONEmitter &json) const;
                                                     
  void serializeSampledEvents(JSONEmitter &json) const;
                                
  void serializeStackFrames(JSONEmitter &json) const;

                                             
  static std::string getSerializedTimeStamp(
      SamplingProfiler::TimeStampType timeStamp);

 public:
  explicit ChromeTraceSerializer(
      const SamplingProfiler &sp,
      ChromeTraceFormat &&chromeTrace);

                                      
  void serialize(llvh::raw_ostream &OS) const;
};

                                                                            
                                         
   
                                                                                 
   
void serializeAsProfilerProfile(
    const SamplingProfiler &sp,
    llvh::raw_ostream &os,
    ChromeTraceFormat &&chromeTrace);

}                
}                    

#endif                                        

#endif                                              

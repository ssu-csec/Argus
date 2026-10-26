/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PUBLIC_SAMPLINGPROFILER_H
#define HERMES_PUBLIC_SAMPLINGPROFILER_H

#include <hermes/Public/HermesExport.h>

#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace facebook {
namespace hermes {
namespace sampling_profiler {

                                                                           
                 
template <typename Iterator>
class Range {
 public:
  Range(Iterator begin, Iterator end) : begin_(begin), end_(end) {}

  Iterator begin() const {
    return begin_;
  }
  Iterator end() const {
    return end_;
  }

 private:
  Iterator begin_;
  Iterator end_;
};

                                                                   
template <typename Iterator>
Range<Iterator> makeRange(Iterator begin, Iterator end) {
  return Range<Iterator>(begin, end);
}

                                                                            
                                                                                
                                                                              
                                                   
class HERMES_EXPORT ProfileSampleCallStackJSFunctionFrame {
 public:
  explicit ProfileSampleCallStackJSFunctionFrame(
      std::string_view functionName,
      uint32_t scriptId,
      const std::optional<std::string_view> &scriptUrl = std::nullopt,
      const std::optional<uint32_t> &lineNumber = std::nullopt,
      const std::optional<uint32_t> &columnNumber = std::nullopt)
      : functionName_(functionName),
        scriptId_(scriptId),
        scriptUrl_(scriptUrl),
        lineNumber_(lineNumber),
        columnNumber_(columnNumber) {}

                                                              
  std::string_view getFunctionName() const {
    return functionName_;
  }

                                                       
  uint32_t getScriptId() const {
    return scriptId_;
  }

  bool hasScriptUrl() const {
    return scriptUrl_.has_value();
  }

                                                               
  std::string_view getScriptUrl() const {
    return scriptUrl_.value();
  }

  bool hasFunctionLineNumber() const {
    return lineNumber_.has_value();
  }

                                                                               
             
  uint32_t getFunctionLineNumber() const {
    return lineNumber_.value();
  }

  bool hasFunctionColumnNumber() const {
    return columnNumber_.has_value();
  }

                                                                      
                        
  uint32_t getFunctionColumnNumber() const {
    return columnNumber_.value();
  }

 private:
  std::string_view functionName_;
  uint32_t scriptId_;
  std::optional<std::string_view> scriptUrl_;
  std::optional<uint32_t> lineNumber_;
  std::optional<uint32_t> columnNumber_;
};

                                                                         
                        
class HERMES_EXPORT ProfileSampleCallStackNativeFunctionFrame {
 public:
  explicit ProfileSampleCallStackNativeFunctionFrame(
      std::string_view functionName)
      : functionName_(functionName) {}

                                                              
  std::string_view getFunctionName() const {
    return functionName_;
  }

 private:
  std::string_view functionName_;
};

                                                                             
                                                                       
class HERMES_EXPORT ProfileSampleCallStackHostFunctionFrame {
 public:
  explicit ProfileSampleCallStackHostFunctionFrame(
      std::string_view functionName)
      : functionName_(functionName) {}

                                                              
  std::string_view getFunctionName() const {
    return functionName_;
  }

 private:
  std::string_view functionName_;
};

                                                                         
                        
class HERMES_EXPORT ProfileSampleCallStackSuspendFrame {
 public:
                                   
  enum class SuspendFrameKind {
    GC,                                                           
    Debugger,                                                                 
    Multiple,                                        
  };

  explicit ProfileSampleCallStackSuspendFrame(
      const SuspendFrameKind suspendFrameKind)
      : suspendFrameKind_(suspendFrameKind) {}

                                           
  SuspendFrameKind getSuspendFrameKind() const {
    return suspendFrameKind_;
  }

 private:
  SuspendFrameKind suspendFrameKind_;
};

                                                      
using ProfileSampleCallStackFrame = std::variant<
    ProfileSampleCallStackSuspendFrame,
    ProfileSampleCallStackNativeFunctionFrame,
    ProfileSampleCallStackHostFunctionFrame,
    ProfileSampleCallStackJSFunctionFrame>;

                                                                           
         
class HERMES_EXPORT ProfileSample {
 public:
  using CallStackFrameIterator =
      std::vector<ProfileSampleCallStackFrame>::const_iterator;

  ProfileSample(
      uint64_t timestamp,
      uint64_t threadId,
      std::vector<ProfileSampleCallStackFrame> callStack)
      : timestamp_(timestamp),
        threadId_(threadId),
        callStack_(std::move(callStack)) {}

                                                                        
                                           
  uint64_t getTimestamp() const {
    return timestamp_;
  }

                                                  
  uint64_t getThreadId() const {
    return threadId_;
  }

                                                                                
                                                      
  Range<CallStackFrameIterator> getCallStackFramesRange() const {
    return makeRange(callStack_.begin(), callStack_.end());
  }

                                                                        
  size_t getCallStackFramesCount() const {
    return callStack_.size();
  }

 private:
                                                  
  uint64_t timestamp_;
                                          
  uint64_t threadId_;
                                                                    
                                    
  std::vector<ProfileSampleCallStackFrame> callStack_;
};

                                                                               
class HERMES_EXPORT Profile {
 public:
  using SampleIterator = std::vector<ProfileSample>::const_iterator;

  Profile(
      std::vector<ProfileSample> samples,
      std::unique_ptr<std::deque<std::string>> stringStorage)
      : samples_(std::move(samples)),
        stringStorage_(std::move(stringStorage)) {}

  Profile(Profile &&) = default;
  Profile &operator=(Profile &&) = default;

                                                                      
  Profile(const Profile &) = delete;
  Profile &operator=(const Profile &) = delete;

  ~Profile() = default;

                                                                              
                                                  
  Range<SampleIterator> getSamplesRange() const {
    return makeRange(samples_.begin(), samples_.end());
  }

                                             
  size_t getSamplesCount() const {
    return samples_.size();
  }

 private:
                                                                 
  std::vector<ProfileSample> samples_;
                                                            
                                                                                
                                                
                                                                              
                                            
  std::unique_ptr<std::deque<std::string>> stringStorage_;
};

}                               
}                    
}                      

#endif

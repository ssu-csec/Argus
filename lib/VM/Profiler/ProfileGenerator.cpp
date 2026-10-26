/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "ProfileGenerator.h"

#if HERMESVM_SAMPLING_PROFILER_AVAILABLE

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/StringRef.h"

#include <memory>
#include <tuple>
#include <utility>

namespace fhsp = ::facebook::hermes::sampling_profiler;

namespace hermes {
namespace vm {

namespace {

                                                          
static uint64_t convertTimestampToMicroseconds(
    SamplingProfiler::TimeStampType timeStamp) {
  return std::chrono::duration_cast<std::chrono::microseconds>(
             timeStamp.time_since_epoch())
      .count();
}

static std::string getJSFunctionName(
    hbc::BCProvider *bcProvider,
    uint32_t funcId) {
  hbc::RuntimeFunctionHeader functionHeader =
      bcProvider->getFunctionHeader(funcId);
  return bcProvider->getStringRefFromID(functionHeader.functionName()).str();
}

static OptValue<hbc::DebugSourceLocation> getFunctionDefinitionSourceLocation(
    hbc::BCProvider *bcProvider,
    uint32_t funcId) {
  const hbc::DebugOffsets *debugOffsets = bcProvider->getDebugOffsets(funcId);
  if (debugOffsets &&
      debugOffsets->sourceLocations != hbc::DebugOffsets::NO_OFFSET) {
                                                                                
                   
    return bcProvider->getDebugInfo()->getLocationForAddress(
        debugOffsets->sourceLocations, 0                   );
  }
  return llvh::None;
}

static fhsp::ProfileSampleCallStackSuspendFrame::SuspendFrameKind
formatSuspendFrameKind(SamplingProfiler::SuspendFrameInfo::Kind kind) {
  switch (kind) {
    case SamplingProfiler::SuspendFrameInfo::Kind::GC:
      return fhsp::ProfileSampleCallStackSuspendFrame::SuspendFrameKind::GC;
    case SamplingProfiler::SuspendFrameInfo::Kind::Debugger:
      return fhsp::ProfileSampleCallStackSuspendFrame::SuspendFrameKind::
          Debugger;
    case SamplingProfiler::SuspendFrameInfo::Kind::Multiple:
      return fhsp::ProfileSampleCallStackSuspendFrame::SuspendFrameKind::
          Multiple;

    default:
      llvm_unreachable("Unexpected Suspend Frame kind");
  }
}

class ProfileGenerator {
                                                                           
                                      
  using NativeFunctionNameCache = llvh::
      DenseMap<SamplingProfiler::NativeFunctionFrameInfo, std::string_view>;

                                                                               
                                                                            
                                                            
  using JSFunctionFrameDetailsKey = std::pair<RuntimeModule *, uint32_t>;
  using JSFunctionFrameDetailsCacheValue = std::tuple<
      std::string_view,                  
      std::optional<std::string_view>,                      
      OptValue<hbc::DebugSourceLocation>>;
  using JSFunctionFrameDetailsCache = llvh::
      DenseMap<JSFunctionFrameDetailsKey, JSFunctionFrameDetailsCacheValue>;

                                                                                
                                                                                
                                                                             
                  
  using SourceScriptURLCache =
      llvh::DenseMap<llvh::StringRef, std::string_view>;

 public:
  ProfileGenerator(
      const SamplingProfiler &samplingProfiler,
      const std::vector<SamplingProfiler::StackTrace> &sampledStacks)
      : samplingProfiler_(samplingProfiler), sampledStacks_(sampledStacks) {}

  ProfileGenerator(const ProfileGenerator &) = delete;
  ProfileGenerator &operator=(const ProfileGenerator &) = delete;

                                      
  fhsp::Profile generate() {
    stringStorage_ = std::make_unique<std::deque<std::string>>();

    std::vector<fhsp::ProfileSample> samples;
    samples.reserve(sampledStacks_.size());
    for (const SamplingProfiler::StackTrace &sampledStack : sampledStacks_) {
      uint64_t timestamp =
          convertTimestampToMicroseconds(sampledStack.timeStamp);

      std::vector<fhsp::ProfileSampleCallStackFrame> callFrames;
      callFrames.reserve(sampledStack.stack.size());
      for (const SamplingProfiler::StackFrame &frame : sampledStack.stack) {
        callFrames.push_back(processStackFrame(frame));
      }

      samples.emplace_back(timestamp, sampledStack.tid, std::move(callFrames));
    }

    return fhsp::Profile(std::move(samples), std::move(stringStorage_));
  }

 private:
                                          
                                                                               
              
  fhsp::ProfileSampleCallStackFrame processStackFrame(
      const SamplingProfiler::StackFrame &frame) {
    switch (frame.kind) {
      case SamplingProfiler::StackFrame::FrameKind::SuspendFrame:
        return fhsp::ProfileSampleCallStackSuspendFrame(
            formatSuspendFrameKind(frame.suspendFrame.kind));

      case SamplingProfiler::StackFrame::FrameKind::NativeFunction:
        return fhsp::ProfileSampleCallStackNativeFunctionFrame(
            getNativeFunctionName(frame));

      case SamplingProfiler::StackFrame::FrameKind::FinalizableNativeFunction:
        return fhsp::ProfileSampleCallStackHostFunctionFrame(
            getNativeFunctionName(frame));

      case SamplingProfiler::StackFrame::FrameKind::JSFunction: {
        RuntimeModule *module = frame.jsFrame.module;
        auto [functionName, scriptURL, sourceLocOpt] =
            getJSFunctionDetails(frame.jsFrame);

        uint32_t scriptId = module->getScriptID();
        std::optional<uint32_t> lineNumber = std::nullopt;
        std::optional<uint32_t> columnNumber = std::nullopt;

        if (sourceLocOpt.hasValue()) {
                                                                          
                                             
          uint32_t line = sourceLocOpt.getValue().line;
          uint32_t column = sourceLocOpt.getValue().column;
          if (line != 0) {
            lineNumber = line;
          }
          if (column != 0) {
            columnNumber = column;
          }
        }

        return fhsp::ProfileSampleCallStackJSFunctionFrame(
            functionName, scriptId, scriptURL, lineNumber, columnNumber);
      }

      default:
        llvm_unreachable("Unexpected Frame kind");
    }
  }

                                                                                
                           
                                                                          
                                                         
                                                                          
                                                                             
                  
  std::string_view getNativeFunctionName(
      const SamplingProfiler::StackFrame &frame) {
    assert(
        (frame.kind ==
             SamplingProfiler::StackFrame::FrameKind::NativeFunction ||
         frame.kind ==
             SamplingProfiler::StackFrame::FrameKind::
                 FinalizableNativeFunction) &&
        "Expected only NativeFunction or FinalizableNativeFunction frame");

    auto it = nativeFunctionNameCache_.find(frame.nativeFrame);
    if (it != nativeFunctionNameCache_.end()) {
      return it->second;
    }

    std::string nativeFunctionName =
        samplingProfiler_.getNativeFunctionName(frame);
    auto nativeFunctionNameView = storeString(nativeFunctionName);
    nativeFunctionNameCache_.try_emplace(
        frame.nativeFrame, nativeFunctionNameView);

    return nativeFunctionNameView;
  }

                                                                             
                                 
                                                                             
                                                                  
                                                  
                                                                          
                                                                             
  JSFunctionFrameDetailsCacheValue getJSFunctionDetails(
      const SamplingProfiler::JSFunctionFrameInfo &frameInfo) {
    JSFunctionFrameDetailsKey key(frameInfo.module, frameInfo.functionId);
    auto it = jsFunctionFrameCache_.find(key);
    if (it != jsFunctionFrameCache_.end()) {
      return it->second;
    }

    RuntimeModule *runtimeModule = frameInfo.module;
    hbc::BCProvider *bcProvider = runtimeModule->getBytecode();
    std::string functionName =
        getJSFunctionName(bcProvider, frameInfo.functionId);
    auto functionNameEntry = storeString(functionName);

    OptValue<hbc::DebugSourceLocation> debugSourceLocation =
        getFunctionDefinitionSourceLocation(bcProvider, frameInfo.functionId);
    std::optional<std::string> maybeSourceScriptURL = std::nullopt;
    if (debugSourceLocation.hasValue()) {
                               
      auto filenameId = debugSourceLocation.getValue().filenameId;
      maybeSourceScriptURL =
          bcProvider->getDebugInfo()->getFilenameByID(filenameId);
    }

    std::optional<std::string_view> maybeSourceScriptURLView = std::nullopt;
    if (maybeSourceScriptURL.has_value()) {
      const std::string &sourceScriptURL = maybeSourceScriptURL.value();

      auto sourceScriptURLCacheIt =
          sourceScriptURLCache_.find(llvh::StringRef{sourceScriptURL});
      if (sourceScriptURLCacheIt != sourceScriptURLCache_.end()) {
        maybeSourceScriptURLView.emplace(sourceScriptURLCacheIt->second);
      } else {
        std::string_view sourceScriptURLView = storeString(sourceScriptURL);
        maybeSourceScriptURLView.emplace(sourceScriptURLView);

        sourceScriptURLCache_.try_emplace(
            llvh::StringRef{
                sourceScriptURLView.data(), sourceScriptURLView.size()},
            sourceScriptURLView);
      }
    }

    auto valueToCache = std::make_tuple(
        functionNameEntry, maybeSourceScriptURLView, debugSourceLocation);
    jsFunctionFrameCache_.try_emplace(key, valueToCache);

    return valueToCache;
  }

                                               
                                                                           
                                                                          
  std::string_view storeString(const std::string &str) {
    stringStorage_->push_back(str);
    return stringStorage_->back();
  }

                                                                     
  const SamplingProfiler &samplingProfiler_;
                                           
  const std::vector<SamplingProfiler::StackTrace> &sampledStacks_;

  NativeFunctionNameCache nativeFunctionNameCache_{};
  JSFunctionFrameDetailsCache jsFunctionFrameCache_{};
  SourceScriptURLCache sourceScriptURLCache_{};

                                                                    
                                                                              
                                                                           
                                                                              
  std::unique_ptr<std::deque<std::string>> stringStorage_;
};

}             

fhsp::Profile generateProfile(
    const SamplingProfiler &samplingProfiler,
    const std::vector<SamplingProfiler::StackTrace> &sampledStacks) {
  ProfileGenerator profileGenerator(samplingProfiler, sampledStacks);
  return profileGenerator.generate();
}

}                
}                    

#endif                                        

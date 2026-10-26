/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "JSLibInternal.h"
#include "hermes/FrontEndDefs/Builtins.h"

#include "hermes/BCGen/HBC/BytecodeFileFormat.h"
#include "hermes/Support/Base64vlq.h"
#include "hermes/Support/OSCompat.h"
#include "hermes/VM/Callable.h"
#include "hermes/VM/JSArray.h"
#include "hermes/VM/JSArrayBuffer.h"
#include "hermes/VM/JSLib.h"
#include "hermes/VM/JSTypedArray.h"
#include "hermes/VM/JSWeakMapImpl.h"
#include "hermes/VM/Operations.h"
#include "hermes/VM/StackFrame-inline.h"
#include "hermes/VM/StringView.h"

#include <cstring>
#include <random>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

                                                                              
static CallResult<HermesValue> hermesInternalDynamicModuleGraph(void *, Runtime &runtime, NativeArgs args) {
  auto result=Callable::executeCall1(runtime.makeHandle(runtime.getBuiltinCallable(
      BuiltinMethod::HermesBuiltin_dynamicModuleGraph)),runtime,
      runtime.makeHandle(HermesValue::encodeUndefinedValue()),args.getArg(0));
  if(result==ExecutionStatus::EXCEPTION)return ExecutionStatus::EXCEPTION;
  return result->get();
}

                                                  
static inline CallResult<Handle<SymbolID>> symbolForCStr(
    Runtime &rt,
    const char *s) {
  return rt.getIdentifierTable().getSymbolHandle(rt, ASCIIRef{s, strlen(s)});
}

               
CallResult<HermesValue>
hermesInternalDetachArrayBuffer(void *, Runtime &runtime, NativeArgs args) {
  auto buffer = args.dyncastArg<JSArrayBuffer>(0);
  if (!buffer) {
    return runtime.raiseTypeError(
        "Cannot use detachArrayBuffer on something which "
        "is not an ArrayBuffer foo");
  }
  if (LLVM_UNLIKELY(
          JSArrayBuffer::detach(runtime, buffer) == ExecutionStatus::EXCEPTION))
    return ExecutionStatus::EXCEPTION;
                  
  return HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue>
hermesInternalGetEpilogues(void *, Runtime &runtime, NativeArgs args) {
                                                    
  auto eps = runtime.getEpilogues();
  auto outerLen = eps.size();
  auto outerResult = JSArray::create(runtime, outerLen, outerLen);

  if (outerResult == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto outer = *outerResult;
  if (outer->setStorageEndIndex(outer, runtime, outerLen) ==
      ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                                                                           
  for (unsigned i = 0; i < outerLen; ++i) {
    auto innerLen = eps[i].size();
    if (innerLen != 0) {
      auto result = Uint8Array::allocate(runtime, innerLen);
      if (result == ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
      auto ta = result.getValue();
      std::memcpy(ta->begin(runtime), eps[i].begin(), innerLen);
      const auto shv = SmallHermesValue::encodeObjectValue(*ta, runtime);
      JSArray::unsafeSetExistingElementAt(*outer, runtime, i, shv);
    }
  }
  return HermesValue::encodeObjectValue(*outer);
}

                                                     
                                        
CallResult<HermesValue>
hermesInternalGetWeakSize(void *, Runtime &runtime, NativeArgs args) {
  if (auto M = args.dyncastArg<JSWeakMap>(0)) {
    return HermesValue::encodeUntrustedNumberValue(
        JSWeakMap::debugFreeSlotsAndGetSize(runtime, *M));
  }

  if (auto S = args.dyncastArg<JSWeakSet>(0)) {
    return HermesValue::encodeUntrustedNumberValue(
        JSWeakSet::debugFreeSlotsAndGetSize(runtime, *S));
  }

  return runtime.raiseTypeError(
      "getWeakSize can only be called on a WeakMap/WeakSet");
}

                                                                 
CallResult<HermesValue>
hermesInternalGetInstrumentedStats(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
  auto resultHandle = runtime.makeHandle(JSObject::create(runtime));
  MutableHandle<> valHandle{runtime};

                                                         
  auto addToResultHandle =
      [&gcScope, &runtime](
          Handle<JSObject> obj, llvh::StringRef key, Handle<> val) {
        GCScopeMarkerRAII marker{gcScope};
        auto keySym = symbolForCStr(runtime, key.data());
        if (LLVM_UNLIKELY(keySym == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }

        return JSObject::defineNewOwnProperty(
            obj,
            runtime,
            **keySym,
            PropertyFlags::defaultNewNamedPropertyFlags(),
            val);
      };

                                                                            
                
#define ADD_PROP(obj, name, value)                            \
  valHandle = HermesValue::encodeUntrustedNumberValue(value); \
  if (LLVM_UNLIKELY(                                          \
          addToResultHandle(obj, name, valHandle) ==          \
          ExecutionStatus::EXCEPTION)) {                      \
    return ExecutionStatus::EXCEPTION;                        \
  }

  auto &heap = runtime.getHeap();
  GCBase::HeapInfo info;
  heap.getHeapInfo(info);

  ADD_PROP(resultHandle, "js_VMExperiments", runtime.getVMExperimentFlags());
  ADD_PROP(resultHandle, "js_numGCs", heap.getNumGCs());
  ADD_PROP(resultHandle, "js_gcCPUTime", heap.getGCCPUTime());
  ADD_PROP(
      resultHandle, "js_avgGCCPUTime", info.generalStats.gcCPUTime.average());
  ADD_PROP(resultHandle, "js_maxGCCPUTime", info.generalStats.gcCPUTime.max());
  ADD_PROP(resultHandle, "js_gcTime", heap.getGCTime());
  ADD_PROP(
      resultHandle, "js_avgGCTime", info.generalStats.gcWallTime.average());
  ADD_PROP(resultHandle, "js_maxGCTime", info.generalStats.gcWallTime.max());
  ADD_PROP(resultHandle, "js_totalAllocatedBytes", info.totalAllocatedBytes);
  ADD_PROP(resultHandle, "js_allocatedBytes", info.allocatedBytes);
  ADD_PROP(resultHandle, "js_heapSize", info.heapSize);
  ADD_PROP(resultHandle, "js_mallocSizeEstimate", info.mallocSizeEstimate);
  ADD_PROP(resultHandle, "js_vaSize", info.va);
  ADD_PROP(resultHandle, "js_externalBytes", info.externalBytes);
  ADD_PROP(
      resultHandle,
      "js_peakAllocatedBytes",
      info.generalStats.usedBefore.max());
  ADD_PROP(
      resultHandle, "js_peakLiveAfterGC", info.generalStats.usedAfter.max());

#ifdef HERMESVM_GC_HADES
  Handle<JSObject> specificStatsHandle =
      runtime.makeHandle(JSObject::create(runtime));
  auto res =
      addToResultHandle(resultHandle, "js_gcSpecific", specificStatsHandle);
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  ADD_PROP(
      specificStatsHandle,
      "js_numYGCollections",
      info.youngGenStats.numCollections);
  ADD_PROP(
      specificStatsHandle,
      "js_numOGCollections",
      info.fullStats.numCollections);
  ADD_PROP(specificStatsHandle, "js_numCompactions", info.numCompactions);
#endif
#undef ADD_PROP

  return resultHandle.getHermesValue();
}

                                                                           
                                                                            
            
static const char *getCJSModuleModeDescription(Runtime &runtime) {
  bool hasCJSModulesDynamic = false;
  bool hasCJSModulesStatic = false;
  for (const auto &runtimeModule : runtime.getRuntimeModules()) {
    if (runtimeModule.hasCJSModules()) {
      hasCJSModulesDynamic = true;
    }
    if (runtimeModule.hasCJSModulesStatic()) {
      hasCJSModulesStatic = true;
    }
  }
  if (hasCJSModulesDynamic && hasCJSModulesStatic) {
    return "Mixed dynamic/static";
  }
  if (hasCJSModulesDynamic) {
    return "Dynamically resolved";
  }
  if (hasCJSModulesStatic) {
    return "Statically resolved";
  }
  return "None";
}

                                                              
CallResult<HermesValue>
hermesInternalGetRuntimeProperties(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
  auto resultHandle = runtime.makeHandle(JSObject::create(runtime));
  MutableHandle<> tmpHandle{runtime};

                                                                 
                                
  auto addProperty = [&](Handle<> value, const char *key) {
    auto keySym = symbolForCStr(runtime, key);
    if (LLVM_UNLIKELY(keySym == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    return JSObject::defineNewOwnProperty(
        resultHandle,
        runtime,
        **keySym,
        PropertyFlags::defaultNewNamedPropertyFlags(),
        value);
  };

#ifdef HERMES_FACEBOOK_BUILD
  tmpHandle =
      HermesValue::encodeBoolValue(std::strstr(__FILE__, "hermes-snapshot"));
  if (LLVM_UNLIKELY(
          addProperty(tmpHandle, "Snapshot VM") ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
#endif

  tmpHandle =
      HermesValue::encodeUntrustedNumberValue(::hermes::hbc::BYTECODE_VERSION);
  if (LLVM_UNLIKELY(
          addProperty(tmpHandle, "Bytecode Version") ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  tmpHandle = HermesValue::encodeBoolValue(runtime.builtinsAreFrozen());
  if (LLVM_UNLIKELY(
          addProperty(tmpHandle, "Builtins Frozen") ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  tmpHandle =
      HermesValue::encodeUntrustedNumberValue(runtime.getVMExperimentFlags());
  if (LLVM_UNLIKELY(
          addProperty(tmpHandle, "VM Experiments") ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  const char buildMode[] =
#ifdef HERMES_SLOW_DEBUG
      "SlowDebug"
#elif !defined(NDEBUG)
      "Debug"
#else
      "Release"
#endif
      ;
  auto buildModeRes = StringPrimitive::create(
      runtime, ASCIIRef(buildMode, sizeof(buildMode) - 1));
  if (LLVM_UNLIKELY(buildModeRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  tmpHandle = *buildModeRes;
  if (LLVM_UNLIKELY(
          addProperty(tmpHandle, "Build") == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  std::string gcKind = runtime.getHeap().getKindAsStr();
  auto gcKindRes = StringPrimitive::create(
      runtime, ASCIIRef(gcKind.c_str(), gcKind.length()));
  if (LLVM_UNLIKELY(gcKindRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  tmpHandle = *gcKindRes;
  if (LLVM_UNLIKELY(
          addProperty(tmpHandle, "GC") == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

#ifdef HERMES_RELEASE_VERSION
  auto relVerRes =
      StringPrimitive::create(runtime, createASCIIRef(HERMES_RELEASE_VERSION));
  if (LLVM_UNLIKELY(relVerRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  tmpHandle = *relVerRes;
  if (LLVM_UNLIKELY(
          addProperty(tmpHandle, "OSS Release Version") ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
#endif

  const bool debuggerEnabled =
#ifdef HERMES_ENABLE_DEBUGGER
      true
#else
      false
#endif
      ;

  tmpHandle = HermesValue::encodeBoolValue(debuggerEnabled);
  if (LLVM_UNLIKELY(
          addProperty(tmpHandle, "Debugger Enabled") ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  const char *cjsModuleMode = getCJSModuleModeDescription(runtime);
  auto cjsModuleModeRes =
      StringPrimitive::create(runtime, createASCIIRef(cjsModuleMode));
  if (LLVM_UNLIKELY(cjsModuleModeRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  tmpHandle = *cjsModuleModeRes;
  if (LLVM_UNLIKELY(
          addProperty(tmpHandle, "CommonJS Modules") ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  return resultHandle.getHermesValue();
}

#ifdef HERMESVM_PLATFORM_LOGGING
static void logGCStats(Runtime &runtime, const char *msg) {
                                                                
                              
  std::string stats;
  {
    llvh::raw_string_ostream os(stats);
    runtime.printHeapStats(os);
  }
  auto copyRegionFrom = [&stats](size_t from) -> size_t {
    size_t rBrace = stats.find("},", from);
    if (rBrace == std::string::npos) {
      std::string portion = stats.substr(from);
      hermesLog("HermesVM", "%s", portion.c_str());
      return stats.size();
    }

                                                                    
    const size_t to = rBrace + 2;
    std::string portion = stats.substr(from, to - from);
    hermesLog("HermesVM", "%s", portion.c_str());
    return to;
  };

  hermesLog("HermesVM", "%s:", msg);
  for (size_t ind = 0; ind < stats.size(); ind = copyRegionFrom(ind))
    ;
}
#endif

CallResult<HermesValue>
hermesInternalTTIReached(void *, Runtime &runtime, NativeArgs args) {
  runtime.ttiReached();
#ifdef HERMESVM_LLVM_PROFILE_DUMP
  __llvm_profile_dump();
  throw jsi::JSINativeException("TTI reached; profiling done");
#endif
#ifdef HERMESVM_PLATFORM_LOGGING
  logGCStats(runtime, "TTI call");
#endif
  return HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue>
hermesInternalTTRCReached(void *, Runtime &runtime, NativeArgs args) {
                                                            
  return HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue>
hermesInternalIsProxy(void *, Runtime &runtime, NativeArgs args) {
  Handle<JSObject> obj = args.dyncastArg<JSObject>(0);
  return HermesValue::encodeBoolValue(obj && obj->isProxyObject());
}

CallResult<HermesValue>
hermesInternalHasPromise(void *, Runtime &runtime, NativeArgs args) {
  return HermesValue::encodeBoolValue(runtime.hasES6Promise());
}

CallResult<HermesValue>
hermesInternalHasES6Class(void *, Runtime &runtime, NativeArgs args) {
  return HermesValue::encodeBoolValue(runtime.hasES6Class());
}

CallResult<HermesValue>
hermesInternalUseEngineQueue(void *, Runtime &runtime, NativeArgs args) {
  return HermesValue::encodeBoolValue(runtime.hasMicrotaskQueue());
}

         
                                                    
            
CallResult<HermesValue>
hermesInternalEnqueueJob(void *, Runtime &runtime, NativeArgs args) {
  auto callable = args.dyncastArg<Callable>(0);
  if (!callable) {
    return runtime.raiseTypeError(
        "Argument to HermesInternal.enqueueJob must be callable");
  }
  runtime.enqueueJob(callable.get());
  return HermesValue::encodeUndefinedValue();
}

         
                                               
            
                                  
CallResult<HermesValue>
hermesInternalDrainJobs(void *, Runtime &runtime, NativeArgs args) {
  auto drainRes = runtime.drainJobs();
  if (drainRes == ExecutionStatus::EXCEPTION) {
                                                   
    return ExecutionStatus::EXCEPTION;
  }
  return HermesValue::encodeUndefinedValue();
}

#ifdef HERMESVM_EXCEPTION_ON_OOM
                                                                      
                                                          
CallResult<HermesValue>
hermesInternalGetCallStack(void *, Runtime &runtime, NativeArgs args) {
  std::string stack = runtime.getCallStackNoAlloc();
  return StringPrimitive::create(runtime, ASCIIRef(stack.data(), stack.size()));
}
#endif                             

                                                                       
                                                       
static const CodeBlock *getLeafCodeBlock(
    Handle<Callable> callableHandle,
    Runtime &runtime) {
  const Callable *callable = callableHandle.get();
  while (auto *bound = dyn_vmcast<BoundFunction>(callable)) {
    callable = bound->getTarget(runtime);
  }
  if (auto *asFunction = dyn_vmcast<const JSFunction>(callable)) {
    return asFunction->getCodeBlock(runtime);
  }
  return nullptr;
}

                                                               
                                                                        
static CallResult<HermesValue> getCodeBlockFileName(
    Runtime &runtime,
    const CodeBlock *codeBlock,
    OptValue<hbc::DebugSourceLocation> location) {
  RuntimeModule *runtimeModule = codeBlock->getRuntimeModule();
  if (!runtimeModule->getBytecode()->isLazy()) {
                                                                               
                                                                   
    if (location) {
      auto debugInfo = runtimeModule->getBytecode()->getDebugInfo();
      return StringPrimitive::createEfficient(
          runtime, debugInfo->getFilenameByID(location->filenameId));
    } else {
      llvh::StringRef sourceURL = runtimeModule->getSourceURL();
      if (!sourceURL.empty()) {
        return StringPrimitive::createEfficient(runtime, sourceURL);
      }
    }
  }
  return HermesValue::encodeUndefinedValue();
}

         
                                                           
            
                                                             
                                            
                       
                                   
                                     
                                  
                                      
                        
                                        
CallResult<HermesValue>
hermesInternalGetFunctionLocation(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);

  auto callable = args.dyncastArg<Callable>(0);
  if (!callable) {
    return runtime.raiseTypeError(
        "Argument to HermesInternal.getFunctionLocation must be callable");
  }
  auto resultHandle = runtime.makeHandle(JSObject::create(runtime));
  MutableHandle<> tmpHandle{runtime};

  auto codeBlock = getLeafCodeBlock(callable, runtime);
  bool isNative = !codeBlock;
  auto res = JSObject::defineOwnProperty(
      resultHandle,
      runtime,
      Predefined::getSymbolID(Predefined::isNative),
      DefinePropertyFlags::getDefaultNewPropertyFlags(),
      runtime.getBoolValue(isNative));
  assert(res != ExecutionStatus::EXCEPTION && "Failed to set isNative");
  (void)res;

  if (codeBlock) {
    OptValue<hbc::DebugSourceLocation> location =
        codeBlock->getSourceLocation();
    if (location) {
      tmpHandle = HermesValue::encodeUntrustedNumberValue(location->line);
      res = JSObject::defineOwnProperty(
          resultHandle,
          runtime,
          Predefined::getSymbolID(Predefined::lineNumber),
          DefinePropertyFlags::getDefaultNewPropertyFlags(),
          tmpHandle);
      assert(res != ExecutionStatus::EXCEPTION && "Failed to set lineNumber");
      (void)res;

      tmpHandle = HermesValue::encodeUntrustedNumberValue(location->column);
      res = JSObject::defineOwnProperty(
          resultHandle,
          runtime,
          Predefined::getSymbolID(Predefined::columnNumber),
          DefinePropertyFlags::getDefaultNewPropertyFlags(),
          tmpHandle);
      assert(res != ExecutionStatus::EXCEPTION && "Failed to set columnNumber");
      (void)res;
    } else {
      tmpHandle = HermesValue::encodeUntrustedNumberValue(
          codeBlock->getRuntimeModule()->getBytecode()->getSegmentID());
      res = JSObject::defineOwnProperty(
          resultHandle,
          runtime,
          Predefined::getSymbolID(Predefined::segmentID),
          DefinePropertyFlags::getDefaultNewPropertyFlags(),
          tmpHandle);
      assert(res != ExecutionStatus::EXCEPTION && "Failed to set segmentID");
      (void)res;

      tmpHandle = HermesValue::encodeUntrustedNumberValue(
          codeBlock->getVirtualOffset());
      res = JSObject::defineOwnProperty(
          resultHandle,
          runtime,
          Predefined::getSymbolID(Predefined::virtualOffset),
          DefinePropertyFlags::getDefaultNewPropertyFlags(),
          tmpHandle);
      assert(
          res != ExecutionStatus::EXCEPTION && "Failed to set virtualOffset");
      (void)res;
    }

    auto fileNameRes = getCodeBlockFileName(runtime, codeBlock, location);
    if (LLVM_UNLIKELY(fileNameRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    tmpHandle = *fileNameRes;
    res = JSObject::defineOwnProperty(
        resultHandle,
        runtime,
        Predefined::getSymbolID(Predefined::fileName),
        DefinePropertyFlags::getDefaultNewPropertyFlags(),
        tmpHandle);
    assert(res != ExecutionStatus::EXCEPTION && "Failed to set fileName");
    (void)res;
  }
  JSObject::preventExtensions(*resultHandle);
  return resultHandle.getHermesValue();
}

         
                                                                         
            
                                                                         
                                    
                                                       
         
                                                     
                                                 
        
            
CallResult<HermesValue> hermesInternalSetPromiseRejectionTrackingHook(
    void *,
    Runtime &runtime,
    NativeArgs args) {
  runtime.promiseRejectionTrackingHook_ = args.getArg(0);
  return HermesValue::encodeUndefinedValue();
}

         
                                                                       
            
                                                          
CallResult<HermesValue> hermesInternalEnablePromiseRejectionTracker(
    void *,
    Runtime &runtime,
    NativeArgs args) {
  auto opts = args.getArgHandle(0);
  auto func = Handle<Callable>::dyn_vmcast(
      Handle<>(&runtime.promiseRejectionTrackingHook_));
  if (!func) {
    return runtime.raiseTypeError(
        "Promise rejection tracking hook was not registered");
  }
  return Callable::executeCall1(
             func, runtime, Runtime::getUndefinedValue(), opts.getHermesValue())
      .toCallResultHermesValue();
}

#ifdef HERMES_ENABLE_FUZZILLI

                                                            
                                                                               
                                                                            
                                                                                
                                                                            
                                                                        
                                         
   
                                       
         
                                                  
            
                                                                       
                                                                               
                                                                             
                                                                              
                                                                                
                                                                    
CallResult<HermesValue>
hermesInternalFuzzilli(void *, Runtime &runtime, NativeArgs args) {
                                       
                                                     
  constexpr int REPRL_DWFD = 103;                             

  auto operationRes = toString_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(operationRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto operation = StringPrimitive::createStringView(
      runtime, runtime.makeHandle(std::move(*operationRes)));

  if (operation.equals(createUTF16Ref(u"FUZZILLI_CRASH"))) {
    auto crashTypeRes = toIntegerOrInfinity(runtime, args.getArgHandle(1));
    if (LLVM_UNLIKELY(crashTypeRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    switch (crashTypeRes->getNumberAs<int>()) {
      case 0:
        *((int *)0x41414141) = 0x1337;
        break;
      case 1:
        assert(0);
        break;
      case 2:
        std::abort();
        break;
    }
  } else if (operation.equals(createUTF16Ref(u"FUZZILLI_PRINT"))) {
    static FILE *fzliout = fdopen(REPRL_DWFD, "w");
    if (!fzliout) {
      fprintf(
          stderr,
          "Fuzzer output channel not available, printing to stdout instead\n");
      fzliout = stdout;
    }

    auto printRes = toString_RJS(runtime, args.getArgHandle(1));
    if (LLVM_UNLIKELY(printRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    auto print = StringPrimitive::createStringView(
        runtime, runtime.makeHandle(std::move(*printRes)));

    vm::SmallU16String<32> allocator;
    std::string outputString;
    ::hermes::convertUTF16ToUTF8WithReplacements(
        outputString, print.getUTF16Ref(allocator));
    fprintf(fzliout, "%s\n", outputString.c_str());
    fflush(fzliout);
  }

  return HermesValue::encodeUndefinedValue();
}
#endif                          

static CallResult<HermesValue>
hermesInternalIsLazy(void *, Runtime &runtime, NativeArgs args) {
  auto callable = args.dyncastArg<Callable>(0);
  if (!callable) {
    return HermesValue::encodeBoolValue(false);
  }

  auto codeBlock = getLeafCodeBlock(callable, runtime);
  if (!codeBlock) {
                                     
    return HermesValue::encodeBoolValue(false);
  }

  RuntimeModule *runtimeModule = codeBlock->getRuntimeModule();
  return HermesValue::encodeBoolValue(
      runtimeModule && runtimeModule->getBytecode()->isLazy());
}

Handle<JSObject> createHermesInternalObject(
    Runtime &runtime,
    const JSLibFlags &flags) {
  namespace P = Predefined;
  Handle<JSObject> intern = runtime.makeHandle(JSObject::create(runtime));
  GCScope gcScope{runtime};

  DefinePropertyFlags constantDPF =
      DefinePropertyFlags::getDefaultNewPropertyFlags();
  constantDPF.enumerable = 0;
  constantDPF.writable = 0;
  constantDPF.configurable = 0;

  auto defineInternMethod =
      [&](Predefined::Str symID, NativeFunctionPtr func, uint8_t count = 0) {
        (void)defineMethod(
            runtime,
            intern,
            Predefined::getSymbolID(symID),
            nullptr              ,
            func,
            count,
            constantDPF);
      };

  auto defineInternMethodAndSymbol =
      [&](const char *name, NativeFunctionPtr func, uint8_t count = 0) {
        ASCIIRef ref = createASCIIRef(name);
        Handle<SymbolID> symHandle = runtime.ignoreAllocationFailure(
            runtime.getIdentifierTable().getSymbolHandle(runtime, ref));
        (void)defineMethod(
            runtime,
            intern,
            *symHandle,
            nullptr              ,
            func,
            count,
            constantDPF);
      };

                                     
  (void)defineInternMethodAndSymbol;

                                                                               
                        
                                                                          
                                                                       
                                                 
  auto propRes = JSObject::getNamed_RJS(
      runtime.makeHandle<JSObject>(runtime.stringPrototype),
      runtime,
      Predefined::getSymbolID(Predefined::concat));
  assert(
      propRes != ExecutionStatus::EXCEPTION && !(*propRes)->isUndefined() &&
      "Failed to get String.prototype.concat.");
  auto putRes = JSObject::defineOwnProperty(
      intern,
      runtime,
      Predefined::getSymbolID(Predefined::concat),
      constantDPF,
      runtime.makeHandle(std::move(*propRes)));
  assert(
      putRes != ExecutionStatus::EXCEPTION && *putRes &&
      "Failed to set HermesInternal.concat.");
  (void)putRes;

                                                                              
                                                                            
                                                       
  defineInternMethod(P::hasPromise, hermesInternalHasPromise);
  defineInternMethod(P::hasES6Class, hermesInternalHasES6Class);
  defineInternMethod(P::enqueueJob, hermesInternalEnqueueJob);
  defineInternMethod(
      P::setPromiseRejectionTrackingHook,
      hermesInternalSetPromiseRejectionTrackingHook);
  defineInternMethod(
      P::enablePromiseRejectionTracker,
      hermesInternalEnablePromiseRejectionTracker);
  defineInternMethod(P::useEngineQueue, hermesInternalUseEngineQueue);

#ifdef HERMES_ENABLE_FUZZILLI
  defineInternMethod(P::fuzzilli, hermesInternalFuzzilli);
#endif

                                                                             
  if (!flags.enableHermesInternal) {
    JSObject::preventExtensions(*intern);
    return intern;
  }

                                                                       
                                                            
  defineInternMethod(P::getEpilogues, hermesInternalGetEpilogues);
  defineInternMethod(
      P::getRuntimeProperties, hermesInternalGetRuntimeProperties);
  defineInternMethod(P::ttiReached, hermesInternalTTIReached);
  defineInternMethod(P::ttrcReached, hermesInternalTTRCReached);
  defineInternMethod(P::getFunctionLocation, hermesInternalGetFunctionLocation);

  if (LLVM_UNLIKELY(runtime.traceMode != SynthTraceMode::None)) {
                                                                         
                                                               
    (void)defineMethod(
        runtime,
        intern,
        Predefined::getSymbolID(P::getInstrumentedStats),
        nullptr              ,
        hermesInternalGetInstrumentedStats,
        0,
        DefinePropertyFlags::getNewNonEnumerableFlags());
  } else {
    defineInternMethod(
        P::getInstrumentedStats, hermesInternalGetInstrumentedStats);
  }

                                                                                
                                                               
  if (flags.enableHermesInternalTestMethods) {
    defineInternMethod(
        P::detachArrayBuffer, hermesInternalDetachArrayBuffer, 1);
    defineInternMethod(P::getWeakSize, hermesInternalGetWeakSize);
    defineInternMethod(
        P::copyDataProperties, hermesBuiltinCopyDataProperties, 3);
    defineInternMethodAndSymbol("isProxy", hermesInternalIsProxy);
    defineInternMethodAndSymbol("isLazy", hermesInternalIsLazy);
    defineInternMethod(P::drainJobs, hermesInternalDrainJobs);
    defineInternMethodAndSymbol("dynamicModuleGraph", hermesInternalDynamicModuleGraph, 1);
  }

#ifdef HERMESVM_EXCEPTION_ON_OOM
  defineInternMethodAndSymbol("getCallStack", hermesInternalGetCallStack, 0);
#endif                             

  JSObject::preventExtensions(*intern);

  return intern;
}

}                
}                    

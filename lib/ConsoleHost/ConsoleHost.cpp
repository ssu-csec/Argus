/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/ConsoleHost/ConsoleHost.h"

#include "hermes/CompilerDriver/CompilerDriver.h"
#include "hermes/Support/MemoryBuffer.h"
#include "hermes/Support/UTF8.h"
#include "hermes/VM/Callable.h"
#include "hermes/VM/Domain.h"
#include "hermes/VM/JSObject.h"
#include "hermes/VM/NativeArgs.h"
#include "hermes/VM/Profiler/SamplingProfiler.h"
#include "hermes/VM/Runtime.h"
#include "hermes/VM/StringPrimitive.h"
#include "hermes/VM/StringView.h"
#include "hermes/VM/TimeLimitMonitor.h"
#include "hermes/VM/instrumentation/PerfEvents.h"

namespace hermes {

ConsoleHostContext::ConsoleHostContext(vm::Runtime &runtime) {
  runtime.addCustomRootsFunction([this](vm::GC *, vm::RootAcceptor &acceptor) {
    for (auto &entry : taskQueue_) {
      acceptor.acceptPtr(entry.second);
    }
  });
}

                                         
static vm::CallResult<vm::HermesValue>
quit(void *, vm::Runtime &runtime, vm::NativeArgs) {
  return runtime.raiseQuitError();
}

static void printStats(vm::Runtime &runtime, llvh::raw_ostream &os) {
  std::string stats;
  {
    llvh::raw_string_ostream tmp{stats};
    runtime.printHeapStats(tmp);
  }
  vm::instrumentation::PerfEvents::endAndInsertStats(stats);
  os << stats;
}

static vm::CallResult<vm::HermesValue>
createHeapSnapshot(void *, vm::Runtime &runtime, vm::NativeArgs args) {
#ifdef HERMES_MEMORY_INSTRUMENTATION
  using namespace vm;
  std::string fileName;
  if (args.getArgCount() >= 1 && !args.getArg(0).isUndefined()) {
    if (!args.getArg(0).isString()) {
      return runtime.raiseTypeError("Filename argument must be a string");
    }
    auto str = Handle<StringPrimitive>::vmcast(args.getArgHandle(0));
    auto jsFileName = StringPrimitive::createStringView(runtime, str);
    llvh::SmallVector<char16_t, 16> buf;
    convertUTF16ToUTF8WithReplacements(fileName, jsFileName.getUTF16Ref(buf));
  }

  if (fileName.empty()) {
                                   
    fileName = "-";
  } else if (
      !llvh::StringRef{fileName}.endswith(".heapsnapshot") &&
      !llvh::StringRef{fileName}.endswith(".heaptimeline")) {
    return runtime.raiseTypeError(
        "Filename must end in .heapsnapshot or .heaptimeline");
  }
  if (auto err = runtime.getHeap().createSnapshotToFile(fileName)) {
                                                                             
                               
    return runtime.raiseTypeError(
        TwineChar16("Could not write out to the file located at \"") +
        llvh::StringRef(fileName) +
        "\". System error: " + llvh::StringRef(err.message()));
  }
  return HermesValue::encodeUndefinedValue();
#else                                           
  return runtime.raiseTypeError(
      "Heap snapshotting requires a build with memory instrumentation");
#endif                                           
}

static vm::CallResult<vm::HermesValue>
loadSegment(void *ctx, vm::Runtime &runtime, vm::NativeArgs args) {
  using namespace hermes::vm;
  const auto *baseFilename = reinterpret_cast<std::string *>(ctx);

  auto requireContext = args.dyncastArg<RequireContext>(0);
  if (!requireContext) {
    return runtime.raiseTypeError(
        "First argument to loadSegment must be context");
  }

  auto segmentRes = toUInt32_RJS(runtime, args.getArgHandle(1));
  if (LLVM_UNLIKELY(segmentRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  uint32_t segment = segmentRes->getNumberAs<uint32_t>();

  auto fileBufRes =
      llvh::MemoryBuffer::getFile(Twine(*baseFilename) + "." + Twine(segment));
  if (!fileBufRes) {
    return runtime.raiseTypeError(
        TwineChar16("Failed to open segment: ") + segment);
  }

  auto ret = hbc::BCProviderFromBuffer::createBCProviderFromBuffer(
      std::make_unique<OwnedMemoryBuffer>(std::move(*fileBufRes)));
  if (!ret.first) {
    return runtime.raiseTypeError("Error deserializing bytecode");
  }

  if (LLVM_UNLIKELY(
          runtime.loadSegment(std::move(ret.first), requireContext) ==
          ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  return HermesValue::encodeUndefinedValue();
}

static vm::CallResult<vm::HermesValue>
setTimeout(void *ctx, vm::Runtime &runtime, vm::NativeArgs args) {
  ConsoleHostContext *consoleHost = (ConsoleHostContext *)ctx;
  using namespace hermes::vm;
  Handle<Callable> callable = args.dyncastArg<Callable>(0);
  if (!callable) {
    return runtime.raiseTypeError("Argument to setTimeout must be a function");
  }
  CallResult<HermesValue> boundFunction = BoundFunction::create(
      runtime, callable, args.getArgCount() - 1, args.begin() + 1);
  if (boundFunction == ExecutionStatus::EXCEPTION)
    return ExecutionStatus::EXCEPTION;
  uint32_t taskId = consoleHost->queueTask(
      PseudoHandle<Callable>::vmcast(createPseudoHandle(*boundFunction)));
  return HermesValue::encodeTrustedNumberValue(taskId);
}

static vm::CallResult<vm::HermesValue>
clearTimeout(void *ctx, vm::Runtime &runtime, vm::NativeArgs args) {
  ConsoleHostContext *consoleHost = (ConsoleHostContext *)ctx;
  using namespace hermes::vm;
  if (!args.getArg(0).isNumber()) {
    return runtime.raiseTypeError("Argument to clearTimeout must be a number");
  }
  consoleHost->clearTask(args.getArg(0).getNumberAs<uint32_t>());
  return HermesValue::encodeUndefinedValue();
}

void installConsoleBindings(
    vm::Runtime &runtime,
    ConsoleHostContext &ctx,
    vm::StatSamplingThread *statSampler,
    const std::string *filename) {
  vm::DefinePropertyFlags normalDPF =
      vm::DefinePropertyFlags::getNewNonEnumerableFlags();

  auto defineGlobalFunc = [&](vm::SymbolID name,
                              vm::NativeFunctionPtr functionPtr,
                              void *context,
                              unsigned paramCount) -> void {
    vm::GCScopeMarkerRAII marker{runtime};
    auto func = vm::NativeFunction::createWithoutPrototype(
        runtime, context, functionPtr, name, paramCount);
    auto res = vm::JSObject::defineOwnProperty(
        runtime.getGlobal(), runtime, name, normalDPF, func);
    (void)res;
    assert(
        res != vm::ExecutionStatus::EXCEPTION && *res &&
        "global.defineOwnProperty() failed");
  };

                                
  defineGlobalFunc(
      vm::Predefined::getSymbolID(vm::Predefined::quit), quit, nullptr, 0);
  defineGlobalFunc(
      vm::Predefined::getSymbolID(vm::Predefined::createHeapSnapshot),
      createHeapSnapshot,
      nullptr,
      1);

                                       
  defineGlobalFunc(
      runtime
          .ignoreAllocationFailure(runtime.getIdentifierTable().getSymbolHandle(
              runtime, llvh::createASCIIRef("loadSegment")))
          .get(),
      loadSegment,
      reinterpret_cast<void *>(const_cast<std::string *>(filename)),
      2);

  defineGlobalFunc(
      runtime
          .ignoreAllocationFailure(runtime.getIdentifierTable().getSymbolHandle(
              runtime, llvh::createASCIIRef("setTimeout")))
          .get(),
      setTimeout,
      &ctx,
      2);
  defineGlobalFunc(
      runtime
          .ignoreAllocationFailure(runtime.getIdentifierTable().getSymbolHandle(
              runtime, llvh::createASCIIRef("clearTimeout")))
          .get(),
      clearTimeout,
      &ctx,
      1);

                                                               
                                                                      
                                                 
                                                                       
                                                                                
                
  defineGlobalFunc(
      runtime
          .ignoreAllocationFailure(runtime.getIdentifierTable().getSymbolHandle(
              runtime, llvh::createASCIIRef("setImmediate")))
          .get(),
      setTimeout,
      &ctx,
      1);
}

                                                           
                                                               
  
                                             
  
                                                                    
                                                                               
        
namespace {

template <typename F>
auto maybeCatchException(const F &f) -> decltype(f()) {
#if defined(HERMESVM_EXCEPTION_ON_OOM)
  try {
    return f();
  } catch (const std::exception &ex) {
                                                                      
    llvh::errs() << ex.what();
    exit(1);
  }
#else                             
  return f();
#endif
}

bool executeHBCBytecodeImpl(
    std::shared_ptr<hbc::BCProvider> &&bytecode,
    const ExecuteOptions &options,
    const std::string *filename) {
  bool shouldRecordGCStats =
      options.runtimeConfig.getGCConfig().getShouldRecordStats();
  if (shouldRecordGCStats) {
    vm::instrumentation::PerfEvents::begin();
  }

  std::unique_ptr<vm::StatSamplingThread> statSampler;
  auto runtime = vm::Runtime::create(options.runtimeConfig);

  if (options.timeLimit > 0) {
    runtime->timeLimitMonitor = vm::TimeLimitMonitor::getOrCreate();
    runtime->timeLimitMonitor->watchRuntime(
        *runtime, std::chrono::milliseconds(options.timeLimit));
  }

  if (shouldRecordGCStats) {
    statSampler = std::make_unique<vm::StatSamplingThread>(
        std::chrono::milliseconds(100));
  }

  if (options.heapTimeline) {
#ifdef HERMES_MEMORY_INSTRUMENTATION
    runtime->enableAllocationLocationTracker();
#else
    llvh::errs() << "Failed to track allocation locations; build does not"
                    "include memory instrumentation\n";
#endif
  }

  vm::GCScope scope(*runtime);
  ConsoleHostContext ctx{*runtime};

  installConsoleBindings(*runtime, ctx, statSampler.get(), filename);

  vm::RuntimeModuleFlags flags;
  flags.persistent = true;

  if (options.stopAfterInit) {
    vm::Handle<vm::Domain> domain =
        runtime->makeHandle(vm::Domain::create(*runtime));
    if (LLVM_UNLIKELY(
            vm::RuntimeModule::create(
                *runtime,
                domain,
                facebook::hermes::debugger::kInvalidLocation,
                std::move(bytecode),
                flags) == vm::ExecutionStatus::EXCEPTION)) {
      llvh::errs() << "Failed to initialize main RuntimeModule\n";
      return false;
    }

    return true;
  }

#if HERMESVM_SAMPLING_PROFILER_AVAILABLE
  if (options.sampleProfiling) {
    vm::SamplingProfiler::enable();
  }
#endif                                        

  llvh::StringRef sourceURL{};
  if (filename)
    sourceURL = *filename;
  vm::CallResult<vm::HermesValue> status = runtime->runBytecode(
      std::move(bytecode),
      flags,
      sourceURL,
      vm::Runtime::makeNullHandle<vm::Environment>());

#if HERMESVM_SAMPLING_PROFILER_AVAILABLE
  if (options.sampleProfiling) {
    vm::SamplingProfiler::disable();
    vm::SamplingProfiler::dumpChromeTraceGlobal(llvh::errs());
  }
#endif                                        

  bool threwException = status == vm::ExecutionStatus::EXCEPTION;

  if (threwException) {
                                             
    llvh::outs().flush();
    runtime->printException(
        llvh::errs(), runtime->makeHandle(runtime->getThrownValue()));
  }

                                                         
  microtask::performCheckpoint(*runtime);

  if (!ctx.tasksEmpty()) {
    vm::GCScopeMarkerRAII marker{scope};
                                             
    vm::MutableHandle<vm::Callable> task{*runtime};
    while (auto optTask = ctx.dequeueTask()) {
      task = std::move(*optTask);
      auto callRes = vm::Callable::executeCall0(
          task, *runtime, vm::Runtime::getUndefinedValue(), false);
      if (LLVM_UNLIKELY(callRes == vm::ExecutionStatus::EXCEPTION)) {
        threwException = true;
        llvh::outs().flush();
        runtime->printException(
            llvh::errs(), runtime->makeHandle(runtime->getThrownValue()));
        break;
      }

                                                                      
      microtask::performCheckpoint(*runtime);
    }
  }

#ifdef HERMESVM_PROFILER_OPCODE
  runtime->dumpOpcodeStats(llvh::outs());
#endif

#ifdef HERMESVM_PROFILER_JSFUNCTION
  runtime->dumpJSFunctionStats();
#endif

#ifdef HERMESVM_PROFILER_NATIVECALL
  runtime->dumpNativeCallStats(llvh::outs());
#endif

  if (shouldRecordGCStats) {
    llvh::errs() << "Process stats:\n";
    statSampler->stop().printJSON(llvh::errs());

    if (options.forceGCBeforeStats) {
      runtime->collect("forced for stats");
    }
    printStats(*runtime, llvh::errs());
  }

#ifdef HERMESVM_PROFILER_BB
  if (options.basicBlockProfiling) {
    runtime->getBasicBlockExecutionInfo().dump(llvh::errs());
  }
#endif

  return !threwException;
}

}             

                                                   
                                            
bool executeHBCBytecode(
    std::shared_ptr<hbc::BCProvider> &&bytecode,
    const ExecuteOptions &options,
    const std::string *filename) {
  return maybeCatchException([&] {
    return executeHBCBytecodeImpl(std::move(bytecode), options, filename);
  });
}

}                    

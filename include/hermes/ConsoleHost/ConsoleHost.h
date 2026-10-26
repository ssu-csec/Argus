/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_CONSOLEHOST_CONSOLEHOST_H
#define HERMES_CONSOLEHOST_CONSOLEHOST_H

#include "hermes/BCGen/HBC/BytecodeDataProvider.h"
#include "hermes/CompilerDriver/CompilerDriver.h"
#include "hermes/ConsoleHost/MemorySizeParser.h"
#include "hermes/Public/RuntimeConfig.h"
#include "hermes/VM/Runtime.h"
#include "hermes/VM/instrumentation/StatSamplingThread.h"

#include <list>
#include <memory>
#include <unordered_map>

namespace hermes {

                                                                    
                                                                               
                                                                                
                                                                             
class ConsoleHostContext {
                                                                             
                                                                         
                                                                                
  using TaskQueue = std::list<std::pair<uint32_t, vm::Callable *>>;
  TaskQueue taskQueue_;
                                
  std::unordered_map<uint32_t, TaskQueue::iterator> taskMap_;

                                                
  uint32_t nextTaskId_{1};

 public:
                                                             
  ConsoleHostContext(vm::Runtime &runtime);

                                                            
  bool tasksEmpty() const {
    return taskQueue_.empty();
  }

                     
                                 
  uint32_t queueTask(vm::PseudoHandle<vm::Callable> task) {
    auto it = taskQueue_.insert(taskQueue_.end(), {nextTaskId_, task.get()});
    taskMap_.emplace(nextTaskId_, it);
    assert(taskQueue_.size() == taskMap_.size() && "map & queue must agree");
    task.invalidate();
    return nextTaskId_++;
  }

                                                 
  void clearTask(uint32_t id) {
    auto it = taskMap_.find(id);
    if (it != taskMap_.end()) {
      taskQueue_.erase(it->second);
      taskMap_.erase(it);
      assert(taskQueue_.size() == taskMap_.size() && "map & queue must agree");
    }
  }

                                           
                                                                                
  llvh::Optional<vm::PseudoHandle<vm::Callable>> dequeueTask() {
    if (taskQueue_.empty())
      return llvh::None;
    vm::PseudoHandle<vm::Callable> result =
        createPseudoHandle(taskQueue_.front().second);
    clearTask(taskQueue_.front().first);
    return result;
  }
};

                         
                                                                 
   
                                                                              
                                                                            
                                                           
                                                                            
                                                                          
namespace microtask {

                                                                              
                                                              
                                                        
inline void performCheckpoint(vm::Runtime &runtime) {
  runtime.clearKeptObjects();
  if (!runtime.hasMicrotaskQueue())
    return;

  while (LLVM_UNLIKELY(runtime.drainJobs() == vm::ExecutionStatus::EXCEPTION)) {
    runtime.printException(
        llvh::errs(), runtime.makeHandle(runtime.getThrownValue()));
  };
}

}                       

                                                          
                             
              
                                                    
   
                                                                                
                                                                              
                                                                                
                                      
                                                                        
                                                               
void installConsoleBindings(
    vm::Runtime &runtime,
    ConsoleHostContext &ctx,
    vm::StatSamplingThread *statSampler = nullptr,
    const std::string *filename = nullptr);

                                        
struct ExecuteOptions {
                                                     
  vm::RuntimeConfig runtimeConfig;

                                   
  bool basicBlockProfiling{false};

                                            
  bool stopAfterInit{false};

                           
  uint32_t timeLimit{0};

                                                            
  bool forceGCBeforeStats{false};

                                
  bool sampleProfiling{false};

                                                            
  bool heapTimeline{false};
};

                                                   
                                                                    
                                                                                
bool executeHBCBytecode(
    std::shared_ptr<hbc::BCProvider> &&bytecode,
    const ExecuteOptions &options,
    const std::string *filename);

}                    

#endif

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_EXECTRACE_H
#define HERMES_VM_EXECTRACE_H

#include <hermes/VM/CellKind.h>

#include <cstdint>
#include <string>
#include <tuple>
#include <vector>

namespace hermes {

                       
class JSONEmitter;

namespace vm {

                                                                         
                                                                                
                                                                         
                        
                                                                          
                               
class GCExecTrace {
 public:
  GCExecTrace() = default;

  inline void addYGGC(
      const std::vector<std::tuple<CellKind, uint32_t, std::string>>
          &allocSizes,
      size_t ygUsedBefore,
      size_t ogUsedBefore,
      size_t ogUsedAfter);

  inline void addFullGC(
      size_t ygUsedBefore,
      size_t ygUsedAfter,
      size_t ogUsedBefore,
      size_t ogUsedAfter);

#ifndef HERMESVM_API_TRACE_DEBUG
  inline
#endif
      void emit(::hermes::JSONEmitter &json) const;

 private:
#ifdef HERMESVM_API_TRACE_DEBUG
                                                                   
                                                                      
                                                                       
                                   
  struct GCRecord {
    std::vector<std::tuple<CellKind, uint32_t, std::string>> allocSizes;
    bool isYG;
    size_t ygUsedBefore;
    size_t ygUsedAfter;
    size_t ogUsedBefore;
    size_t ogUsedAfter;

    GCRecord(
        const std::vector<std::tuple<CellKind, uint32_t, std::string>>
            &allocSizes,
        bool isYG,
        size_t ygUsedBefore,
        size_t ygUsedAfter,
        size_t ogUsedBefore,
        size_t ogUsedAfter)
        : allocSizes(allocSizes),
          isYG(isYG),
          ygUsedBefore(ygUsedBefore),
          ygUsedAfter(ygUsedAfter),
          ogUsedBefore(ogUsedBefore),
          ogUsedAfter(ogUsedAfter) {}
  };

  std::vector<GCRecord> gcs_;
#endif
};

void GCExecTrace::addYGGC(
    const std::vector<std::tuple<CellKind, uint32_t, std::string>> &allocSizes,
    size_t ygUsedBefore,
    size_t ogUsedBefore,
    size_t ogUsedAfter) {
#ifdef HERMESVM_API_TRACE_DEBUG
  gcs_.emplace_back(
      allocSizes, true, ygUsedBefore, 0, ogUsedBefore, ogUsedAfter);
#else
  (void)allocSizes;
  (void)ygUsedBefore;
  (void)ogUsedBefore;
  (void)ogUsedAfter;
#endif
}

void GCExecTrace::addFullGC(
    size_t ygUsedBefore,
    size_t ygUsedAfter,
    size_t ogUsedBefore,
    size_t ogUsedAfter) {
#ifdef HERMESVM_API_TRACE_DEBUG
  gcs_.emplace_back(
      std::vector<std::tuple<CellKind, uint32_t, std::string>>{},
      false,
      ygUsedBefore,
      ygUsedAfter,
      ogUsedBefore,
      ogUsedAfter);
#else
  (void)ygUsedBefore;
  (void)ygUsedAfter;
  (void)ogUsedBefore;
  (void)ogUsedAfter;
#endif
}

#ifndef HERMESVM_API_TRACE_DEBUG
void GCExecTrace::emit(::hermes::JSONEmitter &) const {}
#endif

}                
}                    

#endif                         

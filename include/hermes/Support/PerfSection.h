/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_PERFSECTION_H
#define HERMES_SUPPORT_PERFSECTION_H

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/StringRef.h"

#include <string>

#if defined(HERMES_FACEBOOK_BUILD) && !defined(_WINDOWS) &&      \
    !defined(__EMSCRIPTEN__) && !defined(HERMES_FBCODE_BUILD) && \
    !defined(HERMES_HOST_BUILD)
#define HERMES_USE_FBSYSTRACE
#endif

namespace hermes {

                                                                 
                                                                   
                                                                     
                                                               
                                       
class PerfSection {
 public:
#if defined(HERMES_USE_FBSYSTRACE) || defined(HERMESVM_PLATFORM_LOGGING)
                                                                               
  PerfSection(const char *name, const char *category = nullptr);

                                                                 
               
  ~PerfSection();

                                                                      
                                                                   
                             
  void addArg(const char *argName, size_t value);
                                                                              
                                                                               
                                                                   
  void addArgD(const char *argName, double d);
  void
  addArg(const char *argName, const llvh::StringRef value, bool copy = true);

#ifdef HERMESVM_PLATFORM_LOGGING
 protected:
  const char *name_;
  const char *category_;
#endif
                                            
  bool enabled_{false};

 private:
                                                                     
                                                                
                                                                   
               
  enum class ArgType {
    SIZE_T,
    DOUBLE,
    STRINGREF,
  };

  struct ArgValue {
    ArgType type;
    union {
      size_t sz_t;
      double d;
      struct {
        const char *data;
        size_t size;
        bool owned;
      } stringref;
    } value;

    void freeDependencies() {
      switch (type) {
        case ArgType::STRINGREF:
          if (value.stringref.owned) {
            delete[] value.stringref.data;
          }
          break;
        case ArgType::SIZE_T:
        case ArgType::DOUBLE:
          break;
      }
    }
  };

  llvh::SmallDenseMap<llvh::StringRef, ArgValue> argValues_;

  void freeDataIfExists(const char *argName) {
    auto it = argValues_.find(argName);
    if (it != argValues_.end()) {
      it->second.freeDependencies();
    }
  }

#else
                                       
  PerfSection(const char *name, const char *category = nullptr) {}
  void addArg(const char *argName, size_t value) {}
  void addArgD(const char *argName, double d) {}
  void
  addArg(const char *argName, const llvh::StringRef value, bool copy = true) {}
#endif
};

}                    

#endif                                

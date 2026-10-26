/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_INSTRUMENTATION_PERFEVENTS_H
#define HERMES_VM_INSTRUMENTATION_PERFEVENTS_H

#include <cstdint>
#include <string>

namespace hermes {
namespace vm {
namespace instrumentation {

                                                          
                                                           
struct PerfEvents {
                                               
  static bool begin();
                                                                             
                                                                              
                                                                                
  static bool endAndInsertStats(std::string &jsonStats);
};

}                             
}                
}                    

#endif                                          

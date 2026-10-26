/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PUBLIC_GCTRIPWIRECONTEXT_H
#define HERMES_PUBLIC_GCTRIPWIRECONTEXT_H

#include <hermes/Public/HermesExport.h>

#include <iosfwd>
#include <string>
#include <system_error>

namespace hermes {
namespace vm {

                                                               
class HERMES_EXPORT GCTripwireContext {
 public:
  virtual ~GCTripwireContext();

                                  
                                           
                                                                               
             
  virtual std::error_code createSnapshotToFile(const std::string &path) = 0;

                                    
                                                   
                                                                               
             
  virtual std::error_code createSnapshot(
      std::ostream &os,
      bool captureNumericValue) = 0;
};

}                
}                    

#endif                                     

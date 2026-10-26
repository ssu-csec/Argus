/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_HBC_UNIQUINGFILENAMETABLE_H
#define HERMES_BCGEN_HBC_UNIQUINGFILENAMETABLE_H

#include "hermes/BCGen/HBC/ConsecutiveStringStorage.h"
#include "hermes/Support/StringSetVector.h"

#include "llvh/ADT/StringRef.h"

namespace hermes {
namespace hbc {

                                                             
struct UniquingFilenameTable {
                                                                            
                                                                         
                                                            
  uint32_t addFilename(llvh::StringRef filename);

                                                                           
                                                                                
                                                                                
                                                                           
                 
  static ConsecutiveStringStorage toStorage(UniquingFilenameTable table);

 private:
  StringSetVector filenames_;
};

}                 
}                    

#endif                                            

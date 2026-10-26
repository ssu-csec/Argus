/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/DependencyExtractor/DependencyExtractor.h"

namespace hermes {
                                                            
class Dependencies;
class Dependencies {
 public:
  std::string error_;
  std::vector<Dependency> deps_;
};
                                                                           
                                                                            
                                                           
   
                                                                         
                                                                     
                         
                                           
Dependencies *hermesExtractDependencies(const char *source, size_t sourceSize);

                                                                      
void hermesDependencies_free(Dependencies *res);

                                                                              
const char *hermesDependencies_getError(const Dependencies *res);

                                                           
const char *hermesDependencies_getDepName(
    const Dependencies *res,
    size_t index);

                                                            
                                               
const char *hermesDependencies_getDepKind(
    const Dependencies *res,
    size_t index);

size_t hermesDependencies_getDepsLength(const Dependencies *res);
}                    

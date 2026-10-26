/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SOURCEMAP_SOURCEMAPTRANSLATOR_H
#define HERMES_SOURCEMAP_SOURCEMAPTRANSLATOR_H

#include "hermes/SourceMap/SourceMap.h"
#include "hermes/Support/SourceErrorManager.h"

#include "llvh/ADT/DenseMap.h"

namespace hermes {

                                                                             
                                                                          
class SourceMapTranslator final : public SourceErrorManager::ICoordTranslator {
                                                      
                                       
  llvh::DenseMap<unsigned, std::shared_ptr<SourceMap>> sourceMaps_;

                                                                               
  SourceErrorManager &sourceErrorManager_;

 public:
  SourceMapTranslator(SourceErrorManager &sourceErrorManager)
      : sourceErrorManager_(sourceErrorManager) {}

  ~SourceMapTranslator() override = default;

                                             
                                                                          
  void addSourceMap(unsigned fileBufId, std::unique_ptr<SourceMap> sourceMap);

                                                            
  void translate(SourceErrorManager::SourceCoords &coords) override;
};

}                    

#endif

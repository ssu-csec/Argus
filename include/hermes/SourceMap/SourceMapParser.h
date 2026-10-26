/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_SOURCEMAPPARSER_H
#define HERMES_SUPPORT_SOURCEMAPPARSER_H

#include "hermes/SourceMap/SourceMapGenerator.h"

#include "llvh/Support/MemoryBuffer.h"

namespace hermes {

                                           
                                                                      
           
class SourceMapParser {
 public:
                                                           
                                                                           
  static std::unique_ptr<SourceMap> parse(
      llvh::MemoryBufferRef sourceMap,
      SourceErrorManager &sm);

                                                                  
                                                         
                                                                           
  static std::unique_ptr<SourceMap> parse(
      llvh::StringRef sourceMapContent,
      SourceErrorManager &sm) {
    return parse(llvh::MemoryBufferRef(sourceMapContent, "<source map>"), sm);
  }

 private:
  SourceMapParser() = delete;
  SourceMapParser(SourceMapParser &) = delete;
  SourceMapParser(SourceMapParser &&) = delete;
  SourceMapParser &operator=(SourceMapParser &) = delete;
  SourceMapParser &operator=(SourceMapParser &&) = delete;

                           
  struct State {
    int32_t generatedColumn = 0;
    int32_t sourceIndex = 0;
    int32_t representedLine = 0;
    int32_t representedColumn = 0;
    int32_t nameIndex = 0;
  };

                                                                               
                               
  static bool parseMappings(
      llvh::StringRef sourceMappings,
      std::vector<SourceMap::SegmentList> &lines);

                                      
  static llvh::Optional<SourceMap::Segment>
  parseSegment(const State &state, const char *&pCur, const char *pSegEnd);
};

}                    

#endif                                    

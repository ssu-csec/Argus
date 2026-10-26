/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/SourceMap/SourceMap.h"

namespace hermes {

                                                             
                                                                          
                
llvh::Optional<SourceMapTextLocationFIndex>
SourceMap::getLocationForAddressFIndex(uint32_t line, uint32_t column) const {
  auto seg = this->getSegmentForAddress(line, column);
                      
  if (!seg.hasValue() || !seg->representedLocation.hasValue()) {
    return llvh::None;
  }
                                               
  assert(
      (size_t)seg->representedLocation->sourceIndex < sources_.size() &&
      "SourceIndex is out-of-range.");
  return SourceMapTextLocationFIndex{
      (uint32_t)seg->representedLocation->sourceIndex,
      (uint32_t)seg->representedLocation->lineIndex + 1,
      (uint32_t)seg->representedLocation->columnIndex + 1};
}

llvh::Optional<SourceMapTextLocation> SourceMap::getLocationForAddress(
    uint32_t line,
    uint32_t column) const {
  auto loc = getLocationForAddressFIndex(line, column);
  if (!loc)
    return llvh::None;

  return SourceMapTextLocation{
      getSourceFullPath(loc->fileIndex), loc->line, loc->column};
}

llvh::Optional<SourceMap::Segment> SourceMap::getSegmentForAddress(
    uint32_t line,
    uint32_t column) const {
  if (line == 0 || line > lines_.size()) {
    return llvh::None;
  }

                     
  uint32_t lineIndex = line - 1;
  auto &segments = lines_[lineIndex];
  if (segments.empty()) {
    return llvh::None;
  }
  assert(column >= 1 && "the column argument to this function is 1-based");
  uint32_t columnIndex = column - 1;
                                                        
                                                               
                                                         
                                                                          
              
  auto segIter = std::upper_bound(
      segments.begin(),
      segments.end(),
      columnIndex,
      [](uint32_t column, const Segment &seg) {
        return column < (uint32_t)seg.generatedColumn;
      });
                                                                      
  if (segIter == segments.begin()) {
    return llvh::None;
  }
                        
  const Segment &target =
      segIter == segments.end() ? segments.back() : *(--segIter);
  return target;
}

}                    

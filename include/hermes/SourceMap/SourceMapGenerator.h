/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_SOURCEMAPGENERATOR_H
#define HERMES_SUPPORT_SOURCEMAPGENERATOR_H

#include "hermes/SourceMap/SourceMap.h"
#include "hermes/Support/OSCompat.h"
#include "hermes/Support/StringSetVector.h"
#include "llvh/ADT/ArrayRef.h"

#include <llvh/ADT/DenseMap.h>
#include <vector>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {

                                                                            
                                                                                
                                                                          
                                                                      
               
class SourceMapGenerator {
 public:
                                                                            
              
                                                                     
                                                                             
         
  void addMappingsLine(SourceMap::SegmentList line, uint32_t segmentID) {
    if (lines_.size() <= segmentID) {
      lines_.resize(segmentID + 1);
    }
    lines_[segmentID] = std::move(line);
  }

                                         
  llvh::ArrayRef<SourceMap::SegmentList> getMappingsLines() const {
    return lines_;
  }

                                                   
                                                                         
              
  void setInputSourceMaps(std::vector<std::unique_ptr<SourceMap>> maps) {
    inputSourceMaps_ = std::move(maps);
  }

                                                                             
                                                                               
                                                                          
                                                         
  uint32_t addSource(
      llvh::StringRef filename,
      llvh::Optional<SourceMap::MetadataEntry> metadata = llvh::None);

                                          
  void outputAsJSON(llvh::raw_ostream &OS) const;

                                                                        
                                                       
                                                
                                       
  void addFunctionOffsets(
      std::vector<uint32_t> &&functionOffsets,
      uint32_t segmentID);

                                              
  uint32_t getSourceIndex(llvh::StringRef filename) const {
    auto it = filenameTable_.find(filename);
    assert(it != filenameTable_.end() && "unable to find filenameId");
    return std::distance(filenameTable_.begin(), it);
  }

 private:
                           
  struct State {
    int32_t generatedColumn = 0;
    int32_t sourceIndex = 0;
    int32_t representedLine = 0;
    int32_t representedColumn = 0;
    int32_t nameIndex = 0;
  };

                                                                       
  void outputAsJSONImpl(llvh::raw_ostream &OS) const;

                                                 
  std::string getVLQMappingsString() const;

                                          
                                                                          
                  
  std::vector<llvh::StringRef> getSources() const;

                                                                
                                                                               
  static SourceMapGenerator::State encodeSourceLocations(
      const SourceMapGenerator::State &lastState,
      llvh::ArrayRef<SourceMap::Segment> segments,
      llvh::raw_ostream &OS);

                                                                   
                                                                        
  SourceMapGenerator mergedWithInputSourceMaps() const;

                                                                             
                                                                          
                                                                    
  std::pair<llvh::Optional<SourceMap::Segment>, const SourceMap *>
  getInputSegmentForSegment(const SourceMap::Segment &seg) const;

  bool hasSourcesMetadata() const;

                                                         
  llvh::Optional<SourceMap::MetadataEntry> getSourceMetadata(
      uint32_t index) const {
    if (index >= sourcesMetadata_.size()) {
      return llvh::None;
    }
    return sourcesMetadata_[index];
  }

                                                           
  std::vector<std::string> symbolNames_;

                                             
  std::vector<SourceMap::SegmentList> lines_;

                                                                       
                                                                        
                       
  std::vector<std::unique_ptr<SourceMap>> inputSourceMaps_;

                                          
  StringSetVector filenameTable_{};

                                                                    
                                                      
  SourceMap::MetadataList sourcesMetadata_;

                                                                      
                  
  llvh::DenseMap<uint32_t, std::vector<uint32_t>> functionOffsets_{};
};

}                    
#pragma GCC diagnostic pop

#endif                                       

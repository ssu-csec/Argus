/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_SOURCEMAP_H
#define HERMES_SUPPORT_SOURCEMAP_H

#include "hermes/Parser/JSONParser.h"
#include "hermes/Support/OptValue.h"

#include "llvh/ADT/DenseMap.h"
#include "llvh/Support/raw_ostream.h"

#include <vector>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {

                                                           
                                                                    
                                       
struct SourceMapTextLocation {
  std::string fileName;
            
  uint32_t line;
            
  uint32_t column;
};

                                                           
                                                                     
                          
struct SourceMapTextLocationFIndex {
  uint32_t fileIndex;
            
  uint32_t line;
            
  uint32_t column;
};

                                                                
                                                       
class SourceMap {
 public:
                                                                         
                                                                          
                                            
                                                                               
                                                                             
                                                                          
               
  struct Segment {
                                                         
    int32_t generatedColumn = 0;

    struct SourceLocation {
                                                   
      int32_t sourceIndex = 0;

                                                          
      int32_t lineIndex = 0;

                                                            
      int32_t columnIndex = 0;

                                                         
      llvh::Optional<int32_t> nameIndex = llvh::None;

      SourceLocation(
          int32_t sourceIndex,
          int32_t lineIndex,
          int32_t columnIndex,
          llvh::Optional<int32_t> nameIndex = llvh::None)
          : sourceIndex(sourceIndex),
            lineIndex(lineIndex),
            columnIndex(columnIndex),
            nameIndex(nameIndex) {}

                             
      SourceLocation() = default;
    };

    llvh::Optional<SourceLocation> representedLocation;

                                                                               
                                                         
    Segment(
        int32_t genCol,
        int32_t sourceIndex,
        int32_t repLine,
        int32_t repCol,
        llvh::Optional<int32_t> repNameIndex = llvh::None)
        : generatedColumn(genCol),
          representedLocation(
              SourceLocation{sourceIndex, repLine, repCol, repNameIndex}) {}

                            
    Segment() = default;
  };
  using SegmentList = std::vector<Segment>;
  using MetadataEntry = parser::JSONSharedValue;
  using MetadataList = std::vector<llvh::Optional<MetadataEntry>>;

  SourceMap(
      const std::string &sourceRoot,
      std::vector<std::string> &&sources,
      std::vector<SegmentList> &&lines,
      MetadataList &&sourcesMetadata)
      : sourceRoot_(sourceRoot),
        sources_(std::move(sources)),
        lines_(std::move(lines)),
        sourcesMetadata_(std::move(sourcesMetadata)) {}

                                                               
                                                                            
                  
  llvh::Optional<SourceMapTextLocation> getLocationForAddress(
      uint32_t line,
      uint32_t column) const;

                                                               
                                                                            
                  
  llvh::Optional<SourceMapTextLocationFIndex> getLocationForAddressFIndex(
      uint32_t line,
      uint32_t column) const;

                                                         
                                                                               
                                           
  llvh::Optional<SourceMap::Segment> getSegmentForAddress(
      uint32_t line,
      uint32_t column) const;

                                                                  
                  
  std::vector<std::string> getAllFullPathSources() const {
    std::vector<std::string> sourceFullPath(sources_.size());
    for (uint32_t i = 0, e = sources_.size(); i < e; ++i) {
      sourceFullPath[i] = getSourceFullPath(i);
    }
    return sourceFullPath;
  }

                                         
  uint32_t getNumSourcePaths() const {
    assert(sources_.size() <= UINT32_MAX);
    return (uint32_t)sources_.size();
  }

                                                                      
  std::string getSourceFullPath(uint32_t index) const {
    assert(index < sources_.size() && "index out-of-range for sources_");
                                                     
    return sourceRoot_ + sources_[index];
  }

                                                           
  llvh::Optional<MetadataEntry> getSourceMetadata(uint32_t index) const {
    if (index >= sourcesMetadata_.size()) {
      return llvh::None;
    }
    return sourcesMetadata_[index];
  }

 private:
                                                                                
                                                                               
                                                      
  std::string sourceRoot_;

                                                                               
               
  std::vector<std::string> sources_;

                                         
  std::vector<SegmentList> lines_;

                                                                    
                                                      
  MetadataList sourcesMetadata_;
};

}                    
#pragma GCC diagnostic pop

#endif                              

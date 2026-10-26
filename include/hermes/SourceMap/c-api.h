/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_C_API_H
#define HERMES_SUPPORT_C_API_H

#include <stddef.h>
#include <stdint.h>

typedef struct HermesDataRef {
  const void *data;
  size_t length;
} HermesDataRef;

typedef struct HermesSourceMapLocation {
                        
  uint32_t path_index;
              
  uint32_t line;
              
  uint32_t column;
} HermesSourceMapLocation;

struct HermesSourceMap;
typedef struct HermesSourceMap HermesSourceMap;

#ifdef __cplusplus
extern "C" {
#endif

                                                      
HermesSourceMap *hermes_source_map_parse(const char *source, size_t len);

                                                    
void hermes_source_map_free(HermesSourceMap *map);

                                                                                
                                                          
                                                                      
HermesDataRef hermes_source_map_get_error(const HermesSourceMap *map);

                                                                   
uint32_t hermes_source_map_get_num_paths(const HermesSourceMap *map);

                                                                    
                                                                    
HermesDataRef hermes_source_map_get_full_path(
    HermesSourceMap *map,
    uint32_t index);

                                      
                                                                              
                                                                            
HermesSourceMapLocation *hermes_source_map_get_location(
    HermesSourceMap *map,
    uint32_t line,
    uint32_t column);

#ifdef __cplusplus
}
#endif

#endif                          

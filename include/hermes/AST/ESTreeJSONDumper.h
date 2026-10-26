/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_AST_ESTREEJSONDUMPER_H
#define HERMES_AST_ESTREEJSONDUMPER_H

#include "hermes/AST/ESTree.h"

#include "llvh/Support/raw_ostream.h"

namespace hermes {

class JSONEmitter;

                                                                
enum class ESTreeDumpMode {
                                                             
  Compact,
                                                                               
                                                            
  HideEmpty,
                                                                       
  DumpAll,
};

                                                                              
enum class LocationDumpMode {
                        
  None,
                                             
  Loc,
                              
  Range,
                                            
  LocAndRange,
};

                                                                    
enum class ESTreeRawProp { Exclude, Include };

                                                                              
                                                          
void dumpSMRangeJSON(
    JSONEmitter &json,
    llvh::SMRange rng,
    const llvh::MemoryBuffer *buffer);

                                                                       
void dumpESTreeJSON(
    llvh::raw_ostream &os,
    ESTree::NodePtr rootNode,
    bool pretty,
    ESTreeDumpMode mode);

                                                      
                                        
                                                                         
void dumpESTreeJSON(
    llvh::raw_ostream &os,
    ESTree::NodePtr rootNode,
    bool pretty,
    ESTreeDumpMode mode,
    SourceErrorManager &sm,
    LocationDumpMode locMode,
    ESTreeRawProp rawProp = ESTreeRawProp::Include);

                                                     
                                                                      
                                                                   
                                                                         
                                                            
void dumpESTreeJSON(
    JSONEmitter &json,
    ESTree::NodePtr rootNode,
    ESTreeDumpMode mode,
    SourceErrorManager &sm,
    LocationDumpMode locMode,
    const ESTree::NodeKindSet *includeSourceLocs,
    ESTreeRawProp rawProp = ESTreeRawProp::Include);

}                    

#endif

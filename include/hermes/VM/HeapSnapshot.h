/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_HEAPSNAPSHOT_H
#define HERMES_VM_HEAPSNAPSHOT_H

#include "hermes/Public/DebuggerTypes.h"
#include "hermes/Public/GCConfig.h"
#include "hermes/Support/JSONEmitter.h"
#include "hermes/Support/StringSetVector.h"
#include "hermes/VM/CellKind.h"
#include "hermes/VM/HermesValue.h"
#include "hermes/VM/StackTracesTree-NoRuntime.h"
#include "hermes/VM/StringRefUtils.h"

#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/Optional.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/Support/raw_ostream.h"

#include <bitset>
#include <chrono>
#include <string>

namespace hermes {
namespace vm {

using HeapSizeType = uint32_t;
class StringPrimitive;
struct StackTracesTree;

                                                   
      
std::string converter(const char *name);
std::string converter(unsigned index);
std::string converter(int index);
std::string converter(const StringPrimitive *str);
std::string converter(UTF16Ref ref);
      

                                                
   
                                                                            
                                                                           
                   
                                                                          
                                                                              
                                               
                                                                            
                           
                                                                        
void rawHeapSnapshot(llvh::raw_ostream &os, const char *start, const char *end);

class HeapSnapshot {
 public:
  enum class Section : unsigned {
#define V8_SNAPSHOT_SECTION(enumerand, label) enumerand,
#include "hermes/VM/HeapSnapshot.def"
  };

  enum class NodeType : unsigned {
#define V8_NODE_TYPE(enumerand, label) enumerand,
#include "hermes/VM/HeapSnapshot.def"
  };

  enum class EdgeType : unsigned {
#define V8_EDGE_TYPE(enumerand, label) enumerand,
#include "hermes/VM/HeapSnapshot.def"
  };

                                                               
  static constexpr uint32_t V8_SNAPSHOT_NODE_FIELD_COUNT = 1
#define V8_NODE_FIELD(label, type) +1
#include "hermes/VM/HeapSnapshot.def"
      ;

                                                               
  static constexpr uint32_t V8_SNAPSHOT_EDGE_FIELD_COUNT = 1
#define V8_EDGE_FIELD(label, type) +1
#include "hermes/VM/HeapSnapshot.def"
      ;

  static constexpr uint32_t V8_SNAPSHOT_LOCATION_FIELD_COUNT = 0
#define V8_LOCATION_FIELD(label) +1
#include "hermes/VM/HeapSnapshot.def"
      ;

  static constexpr uint32_t V8_SNAPSHOT_SAMPLE_FIELD_COUNT = 0
#define V8_SAMPLE_FIELD(label) +1
#include "hermes/VM/HeapSnapshot.def"
      ;

  using NodeID = uint32_t;
  using NodeIndex = uint32_t;
  using EdgeIndex = uint32_t;

#ifdef HERMES_MEMORY_INSTRUMENTATION
                                                                              
                                                                             
                                                                                
                                                                           
                                                           
  HeapSnapshot(
      JSONEmitter &json,
      NodeIndex nodeCount,
      EdgeIndex edgeCount,
      size_t traceFunctionCount,
      StackTracesTree *stackTracesTree);

                                              
  ~HeapSnapshot();

                                                                           
                                                                               
                       
     
                                            
                                                       
                                                                               
                                                                      
  void beginSection(Section section);

                        
     
                                                      
                                              
  void endSection(Section section);

  void beginNode();
  void endNode(
      NodeType type,
      llvh::StringRef name,
      NodeID id,
      HeapSizeType selfSize,
      HeapSizeType traceNodeID);

  void addNamedEdge(EdgeType type, llvh::StringRef name, NodeID toNode);
  void addIndexedEdge(EdgeType type, EdgeIndex index, NodeID toNode);

                                                                              
                                                                 
                                                                            
                                                                         
                                                                   
                                                                              
                                      
                                                   
                                                                        
                                                
                                                    
  void addLocation(
      NodeID id,
      ::facebook::hermes::debugger::ScriptID script,
      uint32_t line,
      uint32_t column);

  void addSample(std::chrono::microseconds timestamp, NodeID lastSeenObjectID);

  static const char *nodeTypeToName(NodeType type);

  static const char *edgeTypeToName(EdgeType type);

  void emitAllocationTraceInfo();

                                                                   
  NodeIndex getNodeCount() const {
    return nodeCount_;
  }
                                                                   
  EdgeIndex getEdgeCount() const {
    return edgeCount_;
  }
                                                   
  HeapSizeType getCurEdgeCount() const {
    return currEdgeCount_;
  }
                                                        
  size_t getTraceFunctionCount() const {
    return traceFunctionCount_;
  }

 private:
  void
  emitMeta(NodeIndex nodeCount, EdgeIndex edgeCount, size_t traceFunctionCount);
  void emitStrings();

                                                                    
                                                                   
  Section nextSection_{Section::Nodes};

                                                       
  bool sectionOpened_{false};

  JSONEmitter &json_;
  StackTracesTree *stackTracesTree_;
  llvh::DenseMap<NodeID, NodeIndex> nodeToIndex_;
  std::shared_ptr<StringSetVector> stringTable_;
  NodeIndex nodeCount_{0};
                                                        
  EdgeIndex edgeCount_{0};
                                                 
  HeapSizeType currEdgeCount_{0};
                                                                       
                                                                              
         
  size_t traceFunctionCount_{0};
  struct TraceNodeStats {
    HeapSizeType count{0};
    HeapSizeType size{0};
  };
  llvh::DenseMap<HeapSizeType, TraceNodeStats> traceNodeStats_;

#ifndef NDEBUG
                                                                    
                                  
  EdgeIndex expectedEdges_{0};
#endif

#endif                                 
};

#ifdef HERMES_MEMORY_INSTRUMENTATION
                                                                         
                                                                            
         
     
                 
                          
                                         
                                
                          
                                 
                                  
              
                          
                    
                         
                 
                                  
                                              
                                        
                                                        
                                         
                                          
                      
                                       
                            
                                     
                  
                   
             
          
                    
             
                              
                            
                             
              
               
             
                               
                            
                            
             
          
     
            
                                         
                                                                               
                                                                       
                                                                         
              
                                                                                
                            
                                                                               
                                                                        
                                                                             
                                                                              
                                                                              
                                            
                                                                                
                                                                              
                                                                            
                                                                               
                                                                                
                                                                             
                                                                          
                                                                            
                                                                              
                                                                               
                                                                   
class ChromeSamplingMemoryProfile final {
 public:
  explicit ChromeSamplingMemoryProfile(JSONEmitter &json);
  ~ChromeSamplingMemoryProfile();

  void emitTree(
      StackTracesTree *stackTracesTree,
      const llvh::DenseMap<
          StackTracesTreeNode *,
          llvh::DenseMap<size_t, size_t>> &sizesToCounts);
  void beginSamples();
  void emitSample(size_t size, StackTracesTreeNode *node, uint64_t id);
  void endSamples();

 private:
  JSONEmitter &json_;

  void emitNode(
      StackTracesTreeNode *node,
      StringSetVector &strings,
      const llvh::DenseMap<
          StackTracesTreeNode *,
          llvh::DenseMap<size_t, size_t>> &sizesToCounts);
};

#endif                                 

}                
}                    

#endif                            

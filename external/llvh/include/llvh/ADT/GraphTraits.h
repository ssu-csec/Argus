//===- llvm/ADT/GraphTraits.h - Graph traits template -----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the little GraphTraits<X> template class that should be
// specialized by classes that want to be iteratable by generic graph iterators.
//
// This file also defines the marker class Inverse that is used to iterate over
// graphs in a graph defined, inverse ordering...
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_GRAPHTRAITS_H
#define LLVM_ADT_GRAPHTRAITS_H

#include "llvh/ADT/iterator_range.h"

namespace llvh {

                                                                             
                                             
  
                                                                              
                                             
  
                                                                        
                                                                         
                                                                           
           
template<class GraphType>
struct GraphTraits {
                         

                                                                              
                                                  
                                                                             
                                                          

                                                   
                                          

                                                  
                                                  
                                                                            
                                         

                                                                    
                                                    
                                                    
                                                                              

                                                                              
                                                  
                                                                                
                                                                 

                                                           
                                                         
                                                                       
                                                
    
                                      
                                                

                                                    
                                                 

                                                                    
                                                                            
                                                                             
                                                                         
                                                                              
                     
  using NodeRef = typename GraphType::UnknownGraphTypeError;
};

                                                                          
                                                                            
                                                                           
                                                                       
               
  
                                                          
                              
  
                          
                                                                  
                              
  
template <class GraphType>
struct Inverse {
  const GraphType &Graph;

  inline Inverse(const GraphType &G) : Graph(G) {}
};

                                                                            
                                            
template <class T> struct GraphTraits<Inverse<Inverse<T>>> : GraphTraits<T> {};

                                                                  
template <class GraphType>
iterator_range<typename GraphTraits<GraphType>::nodes_iterator>
nodes(const GraphType &G) {
  return make_range(GraphTraits<GraphType>::nodes_begin(G),
                    GraphTraits<GraphType>::nodes_end(G));
}
template <class GraphType>
iterator_range<typename GraphTraits<Inverse<GraphType>>::nodes_iterator>
inverse_nodes(const GraphType &G) {
  return make_range(GraphTraits<Inverse<GraphType>>::nodes_begin(G),
                    GraphTraits<Inverse<GraphType>>::nodes_end(G));
}

template <class GraphType>
iterator_range<typename GraphTraits<GraphType>::ChildIteratorType>
children(const typename GraphTraits<GraphType>::NodeRef &G) {
  return make_range(GraphTraits<GraphType>::child_begin(G),
                    GraphTraits<GraphType>::child_end(G));
}

template <class GraphType>
iterator_range<typename GraphTraits<Inverse<GraphType>>::ChildIteratorType>
inverse_children(const typename GraphTraits<GraphType>::NodeRef &G) {
  return make_range(GraphTraits<Inverse<GraphType>>::child_begin(G),
                    GraphTraits<Inverse<GraphType>>::child_end(G));
}

template <class GraphType>
iterator_range<typename GraphTraits<GraphType>::ChildEdgeIteratorType>
children_edges(const typename GraphTraits<GraphType>::NodeRef &G) {
  return make_range(GraphTraits<GraphType>::child_edge_begin(G),
                    GraphTraits<GraphType>::child_edge_end(G));
}

}                      

#endif                          

//===- DAGDeltaAlgorithm.h - A DAG Minimization Algorithm ------*- C++ -*--===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_DAGDELTAALGORITHM_H
#define LLVM_ADT_DAGDELTAALGORITHM_H

#include <set>
#include <utility>
#include <vector>

namespace llvh {

                                                                               
                                                       
   
                                                                            
                                                                             
                                                                        
                                                                             
                                         
   
                                                                             
                                                                           
                                
   
                                
   
                                                                           
                                                                                
                                                                        
                                                                                
                                                                              
                   
class DAGDeltaAlgorithm {
  virtual void anchor();

public:
  using change_ty = unsigned;
  using edge_ty = std::pair<change_ty, change_ty>;

                                        
  using changeset_ty = std::set<change_ty>;
  using changesetlist_ty = std::vector<changeset_ty>;

public:
  virtual ~DAGDeltaAlgorithm() = default;

                                                                      
                                                                            
                                                                           
                                              
     
                                         
     
                                                                            
                                                                       
                                                                           
                                                                            
                   
  changeset_ty Run(const changeset_ty &Changes,
                   const std::vector<edge_ty> &Dependencies);

                                                                       
  virtual void UpdatedSearchState(const changeset_ty &Changes,
                                  const changesetlist_ty &Sets,
                                  const changeset_ty &Required) {}

                                                                              
  virtual bool ExecuteOneTest(const changeset_ty &S) = 0;
};

}                      

#endif                                

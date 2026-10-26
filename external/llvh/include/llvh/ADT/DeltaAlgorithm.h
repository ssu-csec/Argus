//===- DeltaAlgorithm.h - A Set Minimization Algorithm ---------*- C++ -*--===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_DELTAALGORITHM_H
#define LLVM_ADT_DELTAALGORITHM_H

#include <set>
#include <vector>

namespace llvh {

                                                                             
                                                             
   
                                                                            
                                                                             
                                                                        
                                                            
   
                                                                           
                                      
                                                                               
         
                                                                             
                                        
   
                                                                         
                                                                     
                                                                          
              
class DeltaAlgorithm {
public:
  using change_ty = unsigned;
                                        
  using changeset_ty = std::set<change_ty>;
  using changesetlist_ty = std::vector<changeset_ty>;

private:
                                                                            
                                                 
  std::set<changeset_ty> FailedTestsCache;

                                                                     
                                             
     
                                              
                                
  bool GetTestResult(const changeset_ty &Changes);

                                                                      
  void Split(const changeset_ty &S, changesetlist_ty &Res);

                                                                        
                                                               
  changeset_ty Delta(const changeset_ty &Changes,
                     const changesetlist_ty &Sets);

                                                                       
                                                                   
     
                                                                      
                
                                
  bool Search(const changeset_ty &Changes, const changesetlist_ty &Sets,
              changeset_ty &Res);

protected:
                                                                       
  virtual void UpdatedSearchState(const changeset_ty &Changes,
                                  const changesetlist_ty &Sets) {}

                                                                              
  virtual bool ExecuteOneTest(const changeset_ty &S) = 0;

  DeltaAlgorithm& operator=(const DeltaAlgorithm&) = default;

public:
  virtual ~DeltaAlgorithm();

                                                                             
                                                                             
                         
  changeset_ty Run(const changeset_ty &Changes);
};

}                      

#endif                             

//===--- ItaniumManglingCanonicalizer.h -------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines a class for computing equivalence classes of mangled names
// given a set of equivalences between name fragments.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_ITANIUMMANGLINGCANONICALIZER_H
#define LLVM_SUPPORT_ITANIUMMANGLINGCANONICALIZER_H

#include "llvh/ADT/StringRef.h"

#include <cstddef>

namespace llvh {
                                    
   
                                                                               
                                            
                                                                    
                                                                      
                                                                               
                              
   
                                                                              
                                                                         
                        
class ItaniumManglingCanonicalizer {
public:
  ItaniumManglingCanonicalizer();
  ItaniumManglingCanonicalizer(const ItaniumManglingCanonicalizer &) = delete;
  void operator=(const ItaniumManglingCanonicalizer &) = delete;
  ~ItaniumManglingCanonicalizer();

  enum class EquivalenceError {
    Success,

                                                                             
                                                                      
                    
    ManglingAlreadyUsed,

                                                 
    InvalidFirstMangling,

                                                  
    InvalidSecondMangling,
  };

  enum class FragmentKind {
                                                                           
    Name,
                                          
    Type,
                                               
    Encoding,
  };

                                                                            
                                                 
  EquivalenceError addEquivalence(FragmentKind Kind, StringRef First,
                                  StringRef Second);

  using Key = uintptr_t;

                                                                           
                                                                  
                                                             
     
                                                                            
                   
     
                                                                            
  Key canonicalize(StringRef Mangling);

                                                                              
                                      
  Key lookup(StringRef Mangling);

private:
  struct Impl;
  Impl *P;
};
}                  

#endif                                               

//===-- llvm/ADT/IntEqClasses.h - Equiv. Classes of Integers ----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Equivalence classes for small integers. This is a mapping of the integers
// 0 .. N-1 into M equivalence classes numbered 0 .. M-1.
//
// Initially each integer has its own equivalence class. Classes are joined by
// passing a representative member of each class to join().
//
// Once the classes are built, compress() will number them 0 .. M-1 and prevent
// further changes.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_INTEQCLASSES_H
#define LLVM_ADT_INTEQCLASSES_H

#include "llvh/ADT/SmallVector.h"

namespace llvh {

class IntEqClasses {
                                                                         
                                                                            
             
     
                                                           
  SmallVector<unsigned, 8> EC;

                                                                               
                   
  unsigned NumClasses;

public:
                                                                      
  IntEqClasses(unsigned N = 0) : NumClasses(0) { grow(N); }

                                                                               
                          
                                        
  void grow(unsigned N);

                                                                            
                    
  void clear() {
    EC.clear();
    NumClasses = 0;
  }

                                                                     
                                                                        
                             
  unsigned join(unsigned a, unsigned b);

                                                                           
                                   
                                        
  unsigned findLeader(unsigned a) const;

                                                                       
                                                     
  void compress();

                                                                               
                 
  unsigned getNumClasses() const { return NumClasses; }

                                                                               
                                     
  unsigned operator[](unsigned a) const {
    assert(NumClasses && "operator[] called before compress()");
    return EC[a];
  }

                                                                             
              
  void uncompress();
};

}                      

#endif

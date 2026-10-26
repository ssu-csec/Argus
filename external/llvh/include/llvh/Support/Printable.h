//===--- Printable.h - Print function helpers -------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file defines the Printable struct.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_PRINTABLE_H
#define LLVM_SUPPORT_PRINTABLE_H

#include <functional>

namespace llvh {

class raw_ostream;

                                                            
                                                                    
   
            
                                                    
                                                        
                                            
           
         
                                              
   
                                                                           
                                                                              
                                                                          
                  
class Printable {
public:
  std::function<void(raw_ostream &OS)> Print;
  Printable(std::function<void(raw_ostream &OS)> Print)
      : Print(std::move(Print)) {}
};

inline raw_ostream &operator<<(raw_ostream &OS, const Printable &P) {
  P.Print(OS);
  return OS;
}

}

#endif

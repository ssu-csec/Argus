//===- llvm/Support/Unicode.h - Unicode character properties  -*- C++ -*-=====//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines functions that allow querying certain properties of Unicode
// characters.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_UNICODE_H
#define LLVM_SUPPORT_UNICODE_H

namespace llvh {
class StringRef;

namespace sys {
namespace unicode {

enum ColumnWidthErrors {
  ErrorInvalidUTF8 = -2,
  ErrorNonPrintableCharacter = -1
};

                                                                        
                                                                       
                                                                                
                                                       
   
                                                                             
               
                                           
                                                    
                                                                            
                                                                         
                  
                                          
                                   
                                              
                                                          
bool isPrintable(int UCS);

                                                                             
                                                                      
                                                                         
                    
   
                                                                            
                                            
   
                            
                                                                         
                                                  
                                                            
                                                           
                                               
int columnWidthUTF8(StringRef Text);

                                                                          
          
int foldCharSimple(int C);

}                     
}                 
}                  

#endif

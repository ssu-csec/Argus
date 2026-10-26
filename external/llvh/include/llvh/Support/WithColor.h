//===- WithColor.h ----------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_WITHCOLOR_H
#define LLVM_SUPPORT_WITHCOLOR_H

#include "llvh/ADT/StringRef.h"
#include "llvh/Support/CommandLine.h"

namespace llvh {

extern cl::OptionCategory ColorCategory;

class raw_ostream;

                                              
enum class HighlightColor {
  Address,
  String,
  Tag,
  Attribute,
  Enumerator,
  Macro,
  Error,
  Warning,
  Note
};

                                                                           
          
class WithColor {
  raw_ostream &OS;
                                                   
  bool colorsEnabled(raw_ostream &OS);

public:
                                                                            
  WithColor(raw_ostream &OS, HighlightColor S);
  ~WithColor();

  raw_ostream &get() { return OS; }
  operator raw_ostream &() { return OS; }

                                                          
  static raw_ostream &error();
                                                            
  static raw_ostream &warning();
                                                         
  static raw_ostream &note();

                                                                    
  static raw_ostream &error(raw_ostream &OS, StringRef Prefix = "");
                                                                      
  static raw_ostream &warning(raw_ostream &OS, StringRef Prefix = "");
                                                                   
  static raw_ostream &note(raw_ostream &OS, StringRef Prefix = "");
};

}                      

#endif                                  

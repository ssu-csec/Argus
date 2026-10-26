//===- SystemUtils.h - Utilities to do low-level system stuff ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains functions used to do a variety of low-level, often
// system-specific, tasks.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_SYSTEMUTILS_H
#define LLVM_SUPPORT_SYSTEMUTILS_H

namespace llvh {
  class raw_ostream;

                                                                            
                                                                            
                                                 
                                         
bool CheckBitcodeOutputToConsole(
  raw_ostream &stream_to_check,                              
  bool print_warning = true                                              
);

}                      

#endif

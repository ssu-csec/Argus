//===- llvm/Support/Valgrind.h - Communication with Valgrind ----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Methods for communicating with a valgrind instance this program is running
// under.  These are all no-ops unless LLVM was configured on a system with the
// valgrind headers installed and valgrind is controlling this process.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_VALGRIND_H
#define LLVM_SUPPORT_VALGRIND_H

#include <cstddef>

namespace llvh {
namespace sys {
                                                  
  bool RunningOnValgrind();

                                                                              
                                                                            
  void ValgrindDiscardTranslations(const void *Addr, size_t Len);
}                 
}                      

#endif                           

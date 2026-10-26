//===-------------- lib/Support/Hashing.cpp -------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides implementation bits for the LLVM common hashing
// infrastructure. Documentation and most of the other information is in the
// header file.
//
//===----------------------------------------------------------------------===//

#include "llvh/ADT/Hashing.h"

using namespace llvh;

                                                                       
                                                                               
                                                
uint64_t llvh::hashing::detail::fixed_seed_override = 0;

                                                               
                                                                   
void llvh::set_fixed_execution_hash_seed(uint64_t fixed_value) {
  hashing::detail::fixed_seed_override = fixed_value;
}

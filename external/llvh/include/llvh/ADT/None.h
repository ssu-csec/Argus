//===-- None.h - Simple null value for implicit construction ------*- C++ -*-=//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file provides None, an enumerator for use in implicit constructors
//  of various (usually templated) types to make such construction more
//  terse.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_NONE_H
#define LLVM_ADT_NONE_H

namespace llvh {
                                                                      
                                                                            
                                                                      
enum class NoneType { None = 1 };
const NoneType None = NoneType::None;
}

#endif

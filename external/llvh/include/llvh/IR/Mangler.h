//===-- llvm/IR/Mangler.h - Self-contained name mangler ---------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Unified name mangler for various backends.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_MANGLER_H
#define LLVM_IR_MANGLER_H

#include "llvh/ADT/DenseMap.h"
#include "llvh/IR/GlobalValue.h"

namespace llvh {

class DataLayout;
template <typename T> class SmallVectorImpl;
class Triple;
class Twine;
class raw_ostream;

class Mangler {
                                                                              
                                                               
  mutable DenseMap<const GlobalValue*, unsigned> AnonGlobalIDs;

public:
                                                                            
                                                                             
                     
  void getNameWithPrefix(raw_ostream &OS, const GlobalValue *GV,
                         bool CannotUsePrivateLabel) const;
  void getNameWithPrefix(SmallVectorImpl<char> &OutName, const GlobalValue *GV,
                         bool CannotUsePrivateLabel) const;

                                                                                
                                     
  static void getNameWithPrefix(raw_ostream &OS, const Twine &GVName,
                                const DataLayout &DL);
  static void getNameWithPrefix(SmallVectorImpl<char> &OutName,
                                const Twine &GVName, const DataLayout &DL);
};

void emitLinkerFlagsForGlobalCOFF(raw_ostream &OS, const GlobalValue *GV,
                                  const Triple &TT, Mangler &Mangler);

void emitLinkerFlagsForUsedCOFF(raw_ostream &OS, const GlobalValue *GV,
                                const Triple &T, Mangler &M);

}                      

#endif

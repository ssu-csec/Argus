//===- llvm/IR/Comdat.h - Comdat definitions --------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
/// @file
/// This file contains the declaration of the Comdat class, which represents a
/// single COMDAT in LLVM.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_COMDAT_H
#define LLVM_IR_COMDAT_H

#include "llvh-c/Types.h"
#include "llvh/Support/CBindingWrapping.h"

namespace llvh {

class raw_ostream;
class StringRef;
template <typename ValueTy> class StringMapEntry;

                                                                        
                                                                           
                                                                            
                                                                               
class Comdat {
public:
  enum SelectionKind {
    Any,                                                
    ExactMatch,                                                           
    Largest,                                                     
    NoDuplicates,                                              
    SameSize,                                                                  
  };

  Comdat(const Comdat &) = delete;
  Comdat(Comdat &&C);

  SelectionKind getSelectionKind() const { return SK; }
  void setSelectionKind(SelectionKind Val) { SK = Val; }
  StringRef getName() const;
  void print(raw_ostream &OS, bool IsForDebug = false) const;
  void dump() const;

private:
  friend class Module;

  Comdat();

                                 
  StringMapEntry<Comdat> *Name = nullptr;
  SelectionKind SK = Any;
};

                                                                
DEFINE_SIMPLE_CONVERSION_FUNCTIONS(Comdat, LLVMComdatRef)

inline raw_ostream &operator<<(raw_ostream &OS, const Comdat &C) {
  C.print(OS);
  return OS;
}

}                      

#endif                    

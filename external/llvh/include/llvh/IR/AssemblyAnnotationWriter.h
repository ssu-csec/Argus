//===-- AssemblyAnnotationWriter.h - Annotation .ll files -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Clients of the assembly writer can use this interface to add their own
// special-purpose annotations to LLVM assembly language printouts.  Note that
// the assembly parser won't be able to parse these, in general, so
// implementations are advised to print stuff as LLVM comments.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_ASSEMBLYANNOTATIONWRITER_H
#define LLVM_IR_ASSEMBLYANNOTATIONWRITER_H

namespace llvh {

class Function;
class BasicBlock;
class Instruction;
class Value;
class formatted_raw_ostream;

class AssemblyAnnotationWriter {
public:
  virtual ~AssemblyAnnotationWriter();

                                                                               
                              
  virtual void emitFunctionAnnot(const Function *,
                                 formatted_raw_ostream &) {}

                                                                               
                                                                          
            
  virtual void emitBasicBlockStartAnnot(const BasicBlock *,
                                        formatted_raw_ostream &) {
  }

                                                                             
                            
  virtual void emitBasicBlockEndAnnot(const BasicBlock *,
                                      formatted_raw_ostream &) {
  }

                                                                           
                                       
  virtual void emitInstructionAnnot(const Instruction *,
                                    formatted_raw_ostream &) {}

                                                                         
                                              
  virtual void printInfoComment(const Value &, formatted_raw_ostream &) {}
};

}                      

#endif

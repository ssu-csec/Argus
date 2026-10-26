//===- DebugInfo.h - Debug Information Helpers ------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines a bunch of datatypes that are useful for creating and
// walking debug info in LLVM IR form. They essentially provide wrappers around
// the information in the global variables that's needed when constructing the
// DWARF information.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_DEBUGINFO_H
#define LLVM_IR_DEBUGINFO_H

#include "llvh/ADT/SmallPtrSet.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/iterator_range.h"
#include "llvh/IR/DebugInfoMetadata.h"

namespace llvh {

class DbgDeclareInst;
class DbgValueInst;
class Module;

                                                 
DISubprogram *getDISubprogram(const MDNode *Scope);

                                                
   
                                                                            
                                                                            
                                      
bool StripDebugInfo(Module &M);
bool stripDebugInfo(Function &F);

                                                                                
   
                                                                        
                                     
                                     
                                                           
                                                   
                                                                          
                                                 
                                                                          
bool stripNonLineTableDebugInfo(Module &M);

                                                                
unsigned getDebugMetadataVersionFromModule(const Module &M);

                                               
   
                                                                             
                                                                        
                                                                              
                                                                           
                                                                         
                    
class DebugInfoFinder {
public:
                                                           
  void processModule(const Module &M);
                                                                  
  void processInstruction(const Module &M, const Instruction &I);

                             
  void processDeclare(const Module &M, const DbgDeclareInst *DDI);
                           
  void processValue(const Module &M, const DbgValueInst *DVI);
                                  
  void processLocation(const Module &M, const DILocation *Loc);

                      
  void reset();

private:
  void InitializeTypeMap(const Module &M);

  void processCompileUnit(DICompileUnit *CU);
  void processScope(DIScope *Scope);
  void processSubprogram(DISubprogram *SP);
  void processType(DIType *DT);
  bool addCompileUnit(DICompileUnit *CU);
  bool addGlobalVariable(DIGlobalVariableExpression *DIG);
  bool addScope(DIScope *Scope);
  bool addSubprogram(DISubprogram *SP);
  bool addType(DIType *DT);

public:
  using compile_unit_iterator =
      SmallVectorImpl<DICompileUnit *>::const_iterator;
  using subprogram_iterator = SmallVectorImpl<DISubprogram *>::const_iterator;
  using global_variable_expression_iterator =
      SmallVectorImpl<DIGlobalVariableExpression *>::const_iterator;
  using type_iterator = SmallVectorImpl<DIType *>::const_iterator;
  using scope_iterator = SmallVectorImpl<DIScope *>::const_iterator;

  iterator_range<compile_unit_iterator> compile_units() const {
    return make_range(CUs.begin(), CUs.end());
  }

  iterator_range<subprogram_iterator> subprograms() const {
    return make_range(SPs.begin(), SPs.end());
  }

  iterator_range<global_variable_expression_iterator> global_variables() const {
    return make_range(GVs.begin(), GVs.end());
  }

  iterator_range<type_iterator> types() const {
    return make_range(TYs.begin(), TYs.end());
  }

  iterator_range<scope_iterator> scopes() const {
    return make_range(Scopes.begin(), Scopes.end());
  }

  unsigned compile_unit_count() const { return CUs.size(); }
  unsigned global_variable_count() const { return GVs.size(); }
  unsigned subprogram_count() const { return SPs.size(); }
  unsigned type_count() const { return TYs.size(); }
  unsigned scope_count() const { return Scopes.size(); }

private:
  SmallVector<DICompileUnit *, 8> CUs;
  SmallVector<DISubprogram *, 8> SPs;
  SmallVector<DIGlobalVariableExpression *, 8> GVs;
  SmallVector<DIType *, 8> TYs;
  SmallVector<DIScope *, 8> Scopes;
  SmallPtrSet<const MDNode *, 32> NodesSeen;
};

}                      

#endif                       

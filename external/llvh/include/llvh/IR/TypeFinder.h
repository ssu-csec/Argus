//===- llvm/IR/TypeFinder.h - Class to find used struct types ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of the TypeFinder class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_TYPEFINDER_H
#define LLVM_IR_TYPEFINDER_H

#include "llvh/ADT/DenseSet.h"
#include <cstddef>
#include <vector>

namespace llvh {

class MDNode;
class Module;
class StructType;
class Type;
class Value;

                                                                          
                       
class TypeFinder {
                                                                      
                                          
  DenseSet<const Value*> VisitedConstants;
  DenseSet<const MDNode *> VisitedMetadata;
  DenseSet<Type*> VisitedTypes;

  std::vector<StructType*> StructTypes;
  bool OnlyNamed = false;

public:
  TypeFinder() = default;

  void run(const Module &M, bool onlyNamed);
  void clear();

  using iterator = std::vector<StructType*>::iterator;
  using const_iterator = std::vector<StructType*>::const_iterator;

  iterator begin() { return StructTypes.begin(); }
  iterator end() { return StructTypes.end(); }

  const_iterator begin() const { return StructTypes.begin(); }
  const_iterator end() const { return StructTypes.end(); }

  bool empty() const { return StructTypes.empty(); }
  size_t size() const { return StructTypes.size(); }
  iterator erase(iterator I, iterator E) { return StructTypes.erase(I, E); }

  StructType *&operator[](unsigned Idx) { return StructTypes[Idx]; }

  DenseSet<const MDNode *> &getVisitedMetadata() { return VisitedMetadata; }

private:
                                                                     
                                              
  void incorporateType(Type *Ty);

                                                                                
                                                                               
                                                                              
                                    
  void incorporateValue(const Value *V);

                                                                               
                                  
  void incorporateMDNode(const MDNode *V);
};

}                      

#endif                        

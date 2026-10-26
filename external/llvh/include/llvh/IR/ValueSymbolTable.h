//===- llvm/ValueSymbolTable.h - Implement a Value Symtab -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the name/Value symbol table for LLVM.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_VALUESYMBOLTABLE_H
#define LLVM_IR_VALUESYMBOLTABLE_H

#include "llvh/ADT/StringMap.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/IR/Value.h"
#include <cstdint>

namespace llvh {

class Argument;
class BasicBlock;
class Function;
class GlobalAlias;
class GlobalIFunc;
class GlobalVariable;
class Instruction;
template <unsigned InternalLen> class SmallString;
template <typename ValueSubClass> class SymbolTableListTraits;

                                                                             
                                                                             
                                                 
   
class ValueSymbolTable {
  friend class SymbolTableListTraits<Argument>;
  friend class SymbolTableListTraits<BasicBlock>;
  friend class SymbolTableListTraits<Function>;
  friend class SymbolTableListTraits<GlobalAlias>;
  friend class SymbolTableListTraits<GlobalIFunc>;
  friend class SymbolTableListTraits<GlobalVariable>;
  friend class SymbolTableListTraits<Instruction>;
  friend class Value;

               
      
public:
                                   
  using ValueMap = StringMap<Value*>;

                                  
  using iterator = ValueMap::iterator;

                                       
  using const_iterator = ValueMap::const_iterator;

      
                      
      

  ValueSymbolTable() : vmap(0) {}
  ~ValueSymbolTable();

      
                   
      

                                                               
                       
                                                    
                           
  Value *lookup(StringRef Name) const { return vmap.lookup(Name); }

                                                 
                                            
  inline bool empty() const { return vmap.empty(); }

                                                
  inline unsigned size() const { return unsigned(vmap.size()); }

                                                                
                                                  
                                      
  void dump() const;

      
                   
      

                                                                  
  inline iterator begin() { return vmap.begin(); }

                                                                       
  inline const_iterator begin() const { return vmap.begin(); }

                                                     
  inline iterator end() { return vmap.end(); }

                                                          
  inline const_iterator end() const { return vmap.end(); }

        
                    
        
private:
  ValueName *makeUniqueName(Value *V, SmallString<256> &UniqueName);

                                                                              
                                                                            
                                                             
                                           
  void reinsertValue(Value *V);

                                                                              
                                                                            
                                                     
  ValueName *createValueName(StringRef Name, Value *V);

                                                                       
                                                                          
             
  void removeValueName(ValueName *V);

        
                         
        

  ValueMap vmap;                                                             
  mutable uint32_t LastUnique = 0;                                        

      
};

}                      

#endif                              

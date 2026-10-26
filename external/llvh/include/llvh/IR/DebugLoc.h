//===- DebugLoc.h - Debug Location Information ------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines a number of light weight data structures used
// to describe and track debug location information.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_DEBUGLOC_H
#define LLVM_IR_DEBUGLOC_H

#include "llvh/IR/TrackingMDRef.h"
#include "llvh/Support/DataTypes.h"

namespace llvh {

  class LLVMContext;
  class raw_ostream;
  class DILocation;

                            
     
                                                                             
              
     
                                                                               
                                                        
  class DebugLoc {
    TrackingMDNodeRef Loc;

  public:
    DebugLoc() = default;

                                        
    DebugLoc(const DILocation *L);

                                    
       
                                                                              
                                                                        
                                                                            
           
    explicit DebugLoc(const MDNode *N);

                                         
       
                                                         
          
    DILocation *get() const;
    operator DILocation *() const { return get(); }
    DILocation *operator->() const { return get(); }
    DILocation &operator*() const { return *get(); }
          

                       
       
                                                                            
                                                                               
                                                                               
                                      
    explicit operator bool() const { return Loc; }

                                                    
    bool hasTrivialDestructor() const { return Loc.hasTrivialDestructor(); }

                              
       
                                                                               
                                         
       
                                                                
       
                                                                
    static DebugLoc get(unsigned Line, unsigned Col, const MDNode *Scope,
                        const MDNode *InlinedAt = nullptr,
                        bool ImplicitCode = false);

    enum { ReplaceLastInlinedAt = true };
                                                                                   
                                                      
                                                                        
                                                                                
    static DebugLoc appendInlinedAt(DebugLoc DL, DILocation *InlinedAt,
                                    LLVMContext &Ctx,
                                    DenseMap<const MDNode *, MDNode *> &Cache,
                                    bool ReplaceLast = false);

    unsigned getLine() const;
    unsigned getCol() const;
    MDNode *getScope() const;
    DILocation *getInlinedAt() const;

                                                      
       
                                                 
    MDNode *getInlinedAtScope() const;

                                                                   
       
                                                                            
                         
       
                                                                            
                                                        
    DebugLoc getFnDebugLoc() const;

                                          
    MDNode *getAsMDNode() const { return Loc; }

                                                              
    bool isImplicitCode() const;
    void setImplicitCode(bool ImplicitCode);

    bool operator==(const DebugLoc &DL) const { return Loc == DL.Loc; }
    bool operator!=(const DebugLoc &DL) const { return Loc != DL.Loc; }

    void dump() const;

                                                                       
    void print(raw_ostream &OS) const;
  };

}                      

#endif                              

//===- Twine.h - Fast Temporary String Concatenation ------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_TWINE_H
#define LLVM_ADT_TWINE_H

#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/Support/ErrorHandling.h"
#include <cassert>
#include <cstdint>
#include <string>

namespace llvh {

  class formatv_object_base;
  class raw_ostream;

                                                                           
                                                   
     
                                                                            
                                                                           
                                                                              
                                                                               
                                                                     
                                                                                
                                                                           
                                        
     
                                                                            
                                                                               
                                                                               
                                                                                
                                              
     
                                                                              
                                                                               
                                                                     
     
                       
     
                                                                     
                                                                          
                                                                           
                                                                    
                                                                              
                                                   
     
                                                                             
                                                                           
                                     
     
                                                                       
                                                                               
                                                         
                                                                            
                                                         
                                                                             
                                                                      
     
                                                   
     
                                  
     
                                                                        
                                                                         
                                                                               
                                    
     
                                                                               
                                                                      
                                                                             
                                    
  class Twine {
                                                     
    enum NodeKind : unsigned char {
                                                                               
                
      NullKind,

                           
      EmptyKind,

                                        
      TwineKind,

                                           
      CStringKind,

                                               
      StdStringKind,

                                            
      StringRefKind,

                                              
      SmallStringKind,

                                                      
      FormatvObjectKind,

                                                 
      CharKind,

                                                                          
      DecUIKind,

                                                              
      DecIKind,

                                                                               
                  
      DecULKind,

                                                                           
      DecLKind,

                                                                            
                          
      DecULLKind,

                                                                                
      DecLLKind,

                                                                             
                  
      UHexKind
    };

    union Child
    {
      const Twine *twine;
      const char *cString;
      const std::string *stdString;
      const StringRef *stringRef;
      const SmallVectorImpl<char> *smallString;
      const formatv_object_base *formatvObject;
      char character;
      unsigned int decUI;
      int decI;
      const unsigned long *decUL;
      const long *decL;
      const unsigned long long *decULL;
      const long long *decLL;
      const uint64_t *uHex;
    };

                                                                             
                            
    Child LHS;

                                                                             
                            
    Child RHS;

                                                                        
    NodeKind LHSKind = EmptyKind;

                                                                         
    NodeKind RHSKind = EmptyKind;

                                                                          
    explicit Twine(NodeKind Kind) : LHSKind(Kind) {
      assert(isNullary() && "Invalid kind!");
    }

                                 
    explicit Twine(const Twine &LHS, const Twine &RHS)
        : LHSKind(TwineKind), RHSKind(TwineKind) {
      this->LHS.twine = &LHS;
      this->RHS.twine = &RHS;
      assert(isValid() && "Invalid twine!");
    }

                                               
    explicit Twine(Child LHS, NodeKind LHSKind, Child RHS, NodeKind RHSKind)
        : LHS(LHS), RHS(RHS), LHSKind(LHSKind), RHSKind(RHSKind) {
      assert(isValid() && "Invalid twine!");
    }

                                 
    bool isNull() const {
      return getLHSKind() == NullKind;
    }

                                  
    bool isEmpty() const {
      return getLHSKind() == EmptyKind;
    }

                                                         
    bool isNullary() const {
      return isNull() || isEmpty();
    }

                                       
    bool isUnary() const {
      return getRHSKind() == EmptyKind && !isNullary();
    }

                                        
    bool isBinary() const {
      return getLHSKind() != NullKind && getRHSKind() != EmptyKind;
    }

                                                                    
                                       
    bool isValid() const {
                                                     
      if (isNullary() && getRHSKind() != EmptyKind)
        return false;

                                             
      if (getRHSKind() == NullKind)
        return false;

                                                         
      if (getRHSKind() != EmptyKind && getLHSKind() == EmptyKind)
        return false;

                                               
      if (getLHSKind() == TwineKind &&
          !LHS.twine->isBinary())
        return false;
      if (getRHSKind() == TwineKind &&
          !RHS.twine->isBinary())
        return false;

      return true;
    }

                                               
    NodeKind getLHSKind() const { return LHSKind; }

                                                
    NodeKind getRHSKind() const { return RHSKind; }

                                     
    void printOneChild(raw_ostream &OS, Child Ptr, NodeKind Kind) const;

                                                           
    void printOneChildRepr(raw_ostream &OS, Child Ptr,
                           NodeKind Kind) const;

  public:
                          
          

                                       
                 Twine() {
      assert(isValid() && "Invalid twine!");
    }

    Twine(const Twine &) = default;

                                  
       
                                                                             
                                                                            
                                                                            
                 Twine(const char *Str) {
      if (Str[0] != '\0') {
        LHS.cString = Str;
        LHSKind = CStringKind;
      } else
        LHSKind = EmptyKind;

      assert(isValid() && "Invalid twine!");
    }

                                      
                 Twine(const std::string &Str) : LHSKind(StdStringKind) {
      LHS.stdString = &Str;
      assert(isValid() && "Invalid twine!");
    }

                                   
                 Twine(const StringRef &Str) : LHSKind(StringRefKind) {
      LHS.stringRef = &Str;
      assert(isValid() && "Invalid twine!");
    }

                                     
                 Twine(const SmallVectorImpl<char> &Str)
        : LHSKind(SmallStringKind) {
      LHS.smallString = &Str;
      assert(isValid() && "Invalid twine!");
    }

                                             
                 Twine(const formatv_object_base &Fmt)
        : LHSKind(FormatvObjectKind) {
      LHS.formatvObject = &Fmt;
      assert(isValid() && "Invalid twine!");
    }

                              
    explicit Twine(char Val) : LHSKind(CharKind) {
      LHS.character = Val;
    }

                                     
    explicit Twine(signed char Val) : LHSKind(CharKind) {
      LHS.character = static_cast<char>(Val);
    }

                                        
    explicit Twine(unsigned char Val) : LHSKind(CharKind) {
      LHS.character = static_cast<char>(Val);
    }

                                                                         
    explicit Twine(unsigned Val) : LHSKind(DecUIKind) {
      LHS.decUI = Val;
    }

                                                                      
    explicit Twine(int Val) : LHSKind(DecIKind) {
      LHS.decI = Val;
    }

                                                                         
    explicit Twine(const unsigned long &Val) : LHSKind(DecULKind) {
      LHS.decUL = &Val;
    }

                                                                      
    explicit Twine(const long &Val) : LHSKind(DecLKind) {
      LHS.decL = &Val;
    }

                                                                         
    explicit Twine(const unsigned long long &Val) : LHSKind(DecULLKind) {
      LHS.decULL = &Val;
    }

                                                                      
    explicit Twine(const long long &Val) : LHSKind(DecLLKind) {
      LHS.decLL = &Val;
    }

                                                                             
                                                                             
                                                                               
                        

                                                                     
                 Twine(const char *LHS, const StringRef &RHS)
        : LHSKind(CStringKind), RHSKind(StringRefKind) {
      this->LHS.cString = LHS;
      this->RHS.stringRef = &RHS;
      assert(isValid() && "Invalid twine!");
    }

                                                                     
                 Twine(const StringRef &LHS, const char *RHS)
        : LHSKind(StringRefKind), RHSKind(CStringKind) {
      this->LHS.stringRef = &LHS;
      this->RHS.cString = RHS;
      assert(isValid() && "Invalid twine!");
    }

                                                                             
                                                                              
    Twine &operator=(const Twine &) = delete;

                                                                    
                                                  
    static Twine createNull() {
      return Twine(NullKind);
    }

          
                                 
          

                                                                            
    static Twine utohexstr(const uint64_t &Val) {
      Child LHS, RHS;
      LHS.uHex = &Val;
      RHS.twine = nullptr;
      return Twine(LHS, UHexKind, RHS, EmptyKind);
    }

          
                                  
          

                                                                             
                                            
    bool isTriviallyEmpty() const {
      return isNullary();
    }

                                                                         
                                                  
    bool isSingleStringRef() const {
      if (getRHSKind() != EmptyKind) return false;

      switch (getLHSKind()) {
      case EmptyKind:
      case CStringKind:
      case StdStringKind:
      case StringRefKind:
      case SmallStringKind:
        return true;
      default:
        return false;
      }
    }

          
                               
          

    Twine concat(const Twine &Suffix) const;

          
                                  
          

                                                   
    std::string str() const;

                                                                                 
    void toVector(SmallVectorImpl<char> &Out) const;

                                                                                
                                       
    StringRef getSingleStringRef() const {
      assert(isSingleStringRef() &&"This cannot be had as a single stringref!");
      switch (getLHSKind()) {
      default: llvm_unreachable("Out of sync with isSingleStringRef");
      case EmptyKind:      return StringRef();
      case CStringKind:    return StringRef(LHS.cString);
      case StdStringKind:  return StringRef(*LHS.stdString);
      case StringRefKind:  return *LHS.stringRef;
      case SmallStringKind:
        return StringRef(LHS.smallString->data(), LHS.smallString->size());
      }
    }

                                                                 
                                                                          
                                                                          
    StringRef toStringRef(SmallVectorImpl<char> &Out) const {
      if (isSingleStringRef())
        return getSingleStringRef();
      toVector(Out);
      return StringRef(Out.data(), Out.size());
    }

                                                                          
                                                                           
                                                                                
       
                                                                           
    StringRef toNullTerminatedStringRef(SmallVectorImpl<char> &Out) const;

                                                                      
                     
    void print(raw_ostream &OS) const;

                                                                         
    void dump() const;

                                                                   
    void printRepr(raw_ostream &OS) const;

                                                        
    void dumpRepr() const;

          
  };

                                        
        

  inline Twine Twine::concat(const Twine &Suffix) const {
                                       
    if (isNull() || Suffix.isNull())
      return Twine(NullKind);

                                                      
    if (isEmpty())
      return Suffix;
    if (Suffix.isEmpty())
      return *this;

                                                                           
              
    Child NewLHS, NewRHS;
    NewLHS.twine = this;
    NewRHS.twine = &Suffix;
    NodeKind NewLHSKind = TwineKind, NewRHSKind = TwineKind;
    if (isUnary()) {
      NewLHS = LHS;
      NewLHSKind = getLHSKind();
    }
    if (Suffix.isUnary()) {
      NewRHS = Suffix.LHS;
      NewRHSKind = Suffix.getLHSKind();
    }

    return Twine(NewLHS, NewLHSKind, NewRHS, NewRHSKind);
  }

  inline Twine operator+(const Twine &LHS, const Twine &RHS) {
    return LHS.concat(RHS);
  }

                                                                                
               

  inline Twine operator+(const char *LHS, const StringRef &RHS) {
    return Twine(LHS, RHS);
  }

                                                                                
               

  inline Twine operator+(const StringRef &LHS, const char *RHS) {
    return Twine(LHS, RHS);
  }

  inline raw_ostream &operator<<(raw_ostream &OS, const Twine &RHS) {
    RHS.print(OS);
    return OS;
  }

        

}                      

#endif                    

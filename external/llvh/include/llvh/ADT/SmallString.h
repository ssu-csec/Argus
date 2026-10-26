//===- llvm/ADT/SmallString.h - 'Normally small' strings --------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the SmallString class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_SMALLSTRING_H
#define LLVM_ADT_SMALLSTRING_H

#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"
#include <cstddef>

namespace llvh {

                                                                                
                                                              
template<unsigned InternalLen>
class SmallString : public SmallVector<char, InternalLen> {
public:
                                         
  SmallString() = default;

                                  
  SmallString(StringRef S) : SmallVector<char, InternalLen>(S.begin(), S.end()) {}

                              
  template<typename ItTy>
  SmallString(ItTy S, ItTy E) : SmallVector<char, InternalLen>(S, E) {}

                                                                            
                                                                           

        
                             
        

                                     
  void assign(size_t NumElts, char Elt) {
    this->SmallVectorImpl<char>::assign(NumElts, Elt);
  }

                                   
  template<typename in_iter>
  void assign(in_iter S, in_iter E) {
    this->clear();
    SmallVectorImpl<char>::append(S, E);
  }

                              
  void assign(StringRef RHS) {
    this->clear();
    SmallVectorImpl<char>::append(RHS.begin(), RHS.end());
  }

                                
  void assign(const SmallVectorImpl<char> &RHS) {
    this->clear();
    SmallVectorImpl<char>::append(RHS.begin(), RHS.end());
  }

        
                                
        

                                   
  template<typename in_iter>
  void append(in_iter S, in_iter E) {
    SmallVectorImpl<char>::append(S, E);
  }

  void append(size_t NumInputs, char Elt) {
    SmallVectorImpl<char>::append(NumInputs, Elt);
  }

                              
  void append(StringRef RHS) {
    SmallVectorImpl<char>::append(RHS.begin(), RHS.end());
  }

                                
  void append(const SmallVectorImpl<char> &RHS) {
    SmallVectorImpl<char>::append(RHS.begin(), RHS.end());
  }

        
                             
        

                                                                            
                                                            
  bool equals(StringRef RHS) const {
    return str().equals(RHS);
  }

                                               
  bool equals_lower(StringRef RHS) const {
    return str().equals_lower(RHS);
  }

                                                                      
                                                                        
  int compare(StringRef RHS) const {
    return str().compare(RHS);
  }

                                                         
  int compare_lower(StringRef RHS) const {
    return str().compare_lower(RHS);
  }

                                                                            
              
  int compare_numeric(StringRef RHS) const {
    return str().compare_numeric(RHS);
  }

        
                             
        

                                                                        
  bool startswith(StringRef Prefix) const {
    return str().startswith(Prefix);
  }

                                                                    
  bool endswith(StringRef Suffix) const {
    return str().endswith(Suffix);
  }

        
                            
        

                                                               
     
                                                                         
            
  size_t find(char C, size_t From = 0) const {
    return str().find(C, From);
  }

                                                       
     
                                                                          
            
  size_t find(StringRef Str, size_t From = 0) const {
    return str().find(Str, From);
  }

                                                       
     
                                                                       
            
  size_t rfind(char C, size_t From = StringRef::npos) const {
    return str().rfind(C, From);
  }

                                                      
     
                                                                         
            
  size_t rfind(StringRef Str) const {
    return str().rfind(Str);
  }

                                                                         
                          
  size_t find_first_of(char C, size_t From = 0) const {
    return str().find_first_of(C, From);
  }

                                                                            
                
     
                                          
  size_t find_first_of(StringRef Chars, size_t From = 0) const {
    return str().find_first_of(Chars, From);
  }

                                                                            
            
  size_t find_first_not_of(char C, size_t From = 0) const {
    return str().find_first_not_of(C, From);
  }

                                                                      
                                     
     
                                          
  size_t find_first_not_of(StringRef Chars, size_t From = 0) const {
    return str().find_first_not_of(Chars, From);
  }

                                                                        
            
  size_t find_last_of(char C, size_t From = StringRef::npos) const {
    return str().find_last_of(C, From);
  }

                                                                           
            
     
                                          
  size_t find_last_of(
      StringRef Chars, size_t From = StringRef::npos) const {
    return str().find_last_of(Chars, From);
  }

        
                              
        

                                                             
  size_t count(char C) const {
    return str().count(C);
  }

                                                                      
             
  size_t count(StringRef Str) const {
    return str().count(Str);
  }

        
                                
        

                                                                  
     
                                                                           
                                                                         
                                       
     
                                                                             
                                                                          
                                                       
  StringRef substr(size_t Start, size_t N = StringRef::npos) const {
    return str().substr(Start, N);
  }

                                                            
     
                                                                           
                                                                         
                                       
     
                                                                         
                                                                       
                                                                     
                                                
  StringRef slice(size_t Start, size_t End) const {
    return str().slice(Start, End);
  }

                   

                                       
  StringRef str() const { return StringRef(this->begin(), this->size()); }

                                           
  const char* c_str() {
    this->push_back(0);
    this->pop_back();
    return this->data();
  }

                                       
  operator StringRef() const { return str(); }

                     
  const SmallString &operator=(StringRef RHS) {
    this->clear();
    return *this += RHS;
  }

  SmallString &operator+=(StringRef RHS) {
    this->append(RHS.begin(), RHS.end());
    return *this;
  }
  SmallString &operator+=(char C) {
    this->push_back(C);
    return *this;
  }
};

}                      

#endif                          

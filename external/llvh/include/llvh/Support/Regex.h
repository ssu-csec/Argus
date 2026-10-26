//===-- Regex.h - Regular Expression matcher implementation -*- C++ -*-----===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements a POSIX regular expression matcher.  Both Basic and
// Extended POSIX regular expressions (ERE) are supported.  EREs were extended
// to support backreferences in matches.
// This implementation also supports matching strings with embedded NUL chars.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_REGEX_H
#define LLVM_SUPPORT_REGEX_H

#include <string>

struct llvm_regex;

namespace llvh {
  class StringRef;
  template<typename T> class SmallVectorImpl;

  class Regex {
  public:
    enum {
      NoFlags=0,
                                                                          
      IgnoreCase=1,
                                                                             
                                                                         
                                                                               
                                                                       
                                                                   
      Newline=2,
                                                                           
                                                                            
                  
      BasicRegex=4
    };

    Regex();
                                                       
    Regex(StringRef Regex, unsigned Flags = NoFlags);
    Regex(const Regex &) = delete;
    Regex &operator=(Regex regex) {
      std::swap(preg, regex.preg);
      std::swap(error, regex.error);
      return *this;
    }
    Regex(Regex &&regex);
    ~Regex();

                                                                            
                         
    bool isValid(std::string &Error) const;

                                                                            
                                                                             
                                                                 
    unsigned getNumMatches() const;

                                                            
       
                                                                               
                                                                            
                                                     
       
                                                
    bool match(StringRef String, SmallVectorImpl<StringRef> *Matches = nullptr);

                                                                            
                                                                          
                                                                             
       
                                                                            
                                                                           
       
                                                                         
                                                                             
               
    std::string sub(StringRef Repl, StringRef String,
                    std::string *Error = nullptr);

                                                                   
                                                 
    static bool isLiteralERE(StringRef Str);

                                                                    
    static std::string escape(StringRef String);

  private:
    struct llvm_regex *preg;
    int error;
  };
}

#endif                        

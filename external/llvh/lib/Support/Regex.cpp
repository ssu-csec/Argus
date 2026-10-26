//===-- Regex.cpp - Regular Expression matcher implementation -------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements a POSIX regular expression matcher.
//
//===----------------------------------------------------------------------===//

#include "llvh/Support/Regex.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/Twine.h"
#include <string>

                                                                        
                                                                     
                                                                              
#include "regex_impl.h"

using namespace llvh;

Regex::Regex() : preg(nullptr), error(REG_BADPAT) {}

Regex::Regex(StringRef regex, unsigned Flags) {
  unsigned flags = 0;
  preg = new llvm_regex();
  preg->re_endp = regex.end();
  if (Flags & IgnoreCase)
    flags |= REG_ICASE;
  if (Flags & Newline)
    flags |= REG_NEWLINE;
  if (!(Flags & BasicRegex))
    flags |= REG_EXTENDED;
  error = llvh_regcomp(preg, regex.data(), flags|REG_PEND);
}

Regex::Regex(Regex &&regex) {
  preg = regex.preg;
  error = regex.error;
  regex.preg = nullptr;
  regex.error = REG_BADPAT;
}

Regex::~Regex() {
  if (preg) {
    llvh_regfree(preg);
    delete preg;
  }
}

bool Regex::isValid(std::string &Error) const {
  if (!error)
    return true;

  size_t len = llvh_regerror(error, preg, nullptr, 0);

  Error.resize(len - 1);
  llvh_regerror(error, preg, &Error[0], len);
  return false;
}

                                                                        
                        
unsigned Regex::getNumMatches() const {
  return preg->re_nsub;
}

bool Regex::match(StringRef String, SmallVectorImpl<StringRef> *Matches){
  if (error)
    return false;

  unsigned nmatch = Matches ? preg->re_nsub+1 : 0;

                                               
  SmallVector<llvm_regmatch_t, 8> pm;
  pm.resize(nmatch > 0 ? nmatch : 1);
  pm[0].rm_so = 0;
  pm[0].rm_eo = String.size();

  int rc = llvh_regexec(preg, String.data(), nmatch, pm.data(), REG_STARTEND);

  if (rc == REG_NOMATCH)
    return false;
  if (rc != 0) {
                                                                        
    error = rc;
    return false;
  }

                       

  if (Matches) {                            
    Matches->clear();

    for (unsigned i = 0; i != nmatch; ++i) {
      if (pm[i].rm_so == -1) {
                                  
        Matches->push_back(StringRef());
        continue;
      }
      assert(pm[i].rm_eo >= pm[i].rm_so);
      Matches->push_back(StringRef(String.data()+pm[i].rm_so,
                                   pm[i].rm_eo-pm[i].rm_so));
    }
  }

  return true;
}

std::string Regex::sub(StringRef Repl, StringRef String,
                       std::string *Error) {
  SmallVector<StringRef, 8> Matches;

                           
  if (Error && !Error->empty()) *Error = "";

                                            
  if (!match(String, &Matches))
    return String;

                                                                                
               
  std::string Res(String.begin(), Matches[0].begin());

                                                                  
  while (!Repl.empty()) {
                               
    std::pair<StringRef, StringRef> Split = Repl.split('\\');

                                 
    Res += Split.first;

                                                      
    if (Split.second.empty()) {
      if (Repl.size() != Split.first.size() &&
          Error && Error->empty())
        *Error = "replacement string contained trailing backslash";
      break;
    }

                                                                     
    Repl = Split.second;

                                                                             
    switch (Repl[0]) {
                                                           
    default:
      Res += Repl[0];
      Repl = Repl.substr(1);
      break;

                                  
    case 't':
      Res += '\t';
      Repl = Repl.substr(1);
      break;
    case 'n':
      Res += '\n';
      Repl = Repl.substr(1);
      break;

                                            
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9': {
                                          
      StringRef Ref = Repl.slice(0, Repl.find_first_not_of("0123456789"));
      Repl = Repl.substr(Ref.size());

      unsigned RefValue;
      if (!Ref.getAsInteger(10, RefValue) &&
          RefValue < Matches.size())
        Res += Matches[RefValue];
      else if (Error && Error->empty())
        *Error = ("invalid backreference string '" + Twine(Ref) + "'").str();
      break;
    }
    }
  }

                            
  Res += StringRef(Matches[0].end(), String.end() - Matches[0].end());

  return Res;
}

                                                                          
static const char RegexMetachars[] = "()^$|*+?.[]\\{}";

bool Regex::isLiteralERE(StringRef Str) {
                                                                          
                                                                              
                                      
  return Str.find_first_of(RegexMetachars) == StringRef::npos;
}

std::string Regex::escape(StringRef String) {
  std::string RegexStr;
  for (unsigned i = 0, e = String.size(); i != e; ++i) {
    if (strchr(RegexMetachars, String[i]))
      RegexStr += '\\';
    RegexStr += String[i];
  }

  return RegexStr;
}

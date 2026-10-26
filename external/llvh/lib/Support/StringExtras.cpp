//===-- StringExtras.cpp - Implement the StringExtras header --------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the StringExtras.h header
//
//===----------------------------------------------------------------------===//

#include "llvh/ADT/StringExtras.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/Support/raw_ostream.h"
using namespace llvh;

                                                                       
                                                                     
                                                         
StringRef::size_type llvh::StrInStrNoCase(StringRef s1, StringRef s2) {
  size_t N = s2.size(), M = s1.size();
  if (N > M)
    return StringRef::npos;
  for (size_t i = 0, e = M - N + 1; i != e; ++i)
    if (s1.substr(i, N).equals_lower(s2))
      return i;
  return StringRef::npos;
}

                                                                         
                                                                           
                                                                            
                                                                          
                                                                      
                          
std::pair<StringRef, StringRef> llvh::getToken(StringRef Source,
                                               StringRef Delimiters) {
                                       
  StringRef::size_type Start = Source.find_first_not_of(Delimiters);

                                               
  StringRef::size_type End = Source.find_first_of(Delimiters, Start);

  return std::make_pair(Source.slice(Start, End), Source.substr(End));
}

                                                                          
                                                                  
void llvh::SplitString(StringRef Source,
                       SmallVectorImpl<StringRef> &OutFragments,
                       StringRef Delimiters) {
  std::pair<StringRef, StringRef> S = getToken(Source, Delimiters);
  while (!S.first.empty()) {
    OutFragments.push_back(S.first);
    S = getToken(S.second, Delimiters);
  }
}

void llvh::printEscapedString(StringRef Name, raw_ostream &Out) {
  for (unsigned i = 0, e = Name.size(); i != e; ++i) {
    unsigned char C = Name[i];
    if (isPrint(C) && C != '\\' && C != '"')
      Out << C;
    else
      Out << '\\' << hexdigit(C >> 4) << hexdigit(C & 0x0F);
  }
}

void llvh::printHTMLEscaped(StringRef String, raw_ostream &Out) {
  for (char C : String) {
    if (C == '&')
      Out << "&amp;";
    else if (C == '<')
      Out << "&lt;";
    else if (C == '>')
      Out << "&gt;";
    else if (C == '\"')
      Out << "&quot;";
    else if (C == '\'')
      Out << "&apos;";
    else
      Out << C;
  }
}

void llvh::printLowerCase(StringRef String, raw_ostream &Out) {
  for (const char C : String)
    Out << toLower(C);
}

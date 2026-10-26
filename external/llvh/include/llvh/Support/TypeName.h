//===- TypeName.h -----------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_TYPENAME_H
#define LLVM_SUPPORT_TYPENAME_H

#include "llvh/ADT/StringRef.h"

namespace llvh {

                                                                               
               
   
                                                                              
                                                                              
                                                
   
                                                                            
                                                                            
                                       
template <typename DesiredTypeName>
inline StringRef getTypeName() {
#if defined(__clang__) || defined(__GNUC__)
  StringRef Name = __PRETTY_FUNCTION__;

  StringRef Key = "DesiredTypeName = ";
  Name = Name.substr(Name.find(Key));
  assert(!Name.empty() && "Unable to find the template parameter!");
  Name = Name.drop_front(Key.size());

  assert(Name.endswith("]") && "Name doesn't end in the substitution key!");
  return Name.drop_back(1);
#elif defined(_MSC_VER)
  StringRef Name = __FUNCSIG__;

  StringRef Key = "getTypeName<";
  Name = Name.substr(Name.find(Key));
  assert(!Name.empty() && "Unable to find the function name!");
  Name = Name.drop_front(Key.size());

  for (StringRef Prefix : {"class ", "struct ", "union ", "enum "})
    if (Name.startswith(Prefix)) {
      Name = Name.drop_front(Prefix.size());
      break;
    }

  auto AnglePos = Name.rfind('>');
  assert(AnglePos != StringRef::npos && "Unable to find the closing '>'!");
  return Name.substr(0, AnglePos);
#else
                                                                               
                                                                       
  return "UNKNOWN_TYPE";
#endif
}

}

#endif

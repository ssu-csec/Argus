//===--- Demangle.h ---------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_DEMANGLE_DEMANGLE_H
#define LLVM_DEMANGLE_DEMANGLE_H

#include <cstddef>

namespace llvh {
                                                                           
                                                
   
                                                                             
                                               
   
                                                                     
enum : int {
  demangle_unknown_error = -4,
  demangle_invalid_args = -3,
  demangle_invalid_mangled_name = -2,
  demangle_memory_alloc_failure = -1,
  demangle_success = 0,
};

char *itaniumDemangle(const char *mangled_name, char *buf, size_t *n,
                      int *status);

                                                                                
                                                                   
bool itaniumFindTypesInMangledName(const char *MangledName, void *Ctx,
                                   void (*Callback)(void *, const char *));


enum MSDemangleFlags { MSDF_None = 0, MSDF_DumpBackrefs = 1 << 0 };
char *microsoftDemangle(const char *mangled_name, char *buf, size_t *n,
                        int *status, MSDemangleFlags Flags = MSDF_None);

                                                                      
                                                                             
                                                        
struct ItaniumPartialDemangler {
  ItaniumPartialDemangler();

  ItaniumPartialDemangler(ItaniumPartialDemangler &&Other);
  ItaniumPartialDemangler &operator=(ItaniumPartialDemangler &&Other);

                                                                                
                                                  
                                            
  bool partialDemangle(const char *MangledName);

                                                                            
                                                     
  char *finishDemangle(char *Buf, size_t *N) const;

                                                                             
                                                              
  char *getFunctionBaseName(char *Buf, size_t *N) const;

                                                                               
             
  char *getFunctionDeclContextName(char *Buf, size_t *N) const;

                                           
  char *getFunctionName(char *Buf, size_t *N) const;

                                           
  char *getFunctionParameters(char *Buf, size_t *N) const;
  char *getFunctionReturnType(char *Buf, size_t *N) const;

                                                                               
                                                   
  bool hasFunctionQualifiers() const;

                                                           
  bool isCtorOrDtor() const;

                                          
  bool isFunction() const;

                                          
  bool isData() const;

                                                                        
                                                                          
  bool isSpecialName() const;

  ~ItaniumPartialDemangler();
private:
  void *RootNode;
  void *Context;
};
}                  

#endif

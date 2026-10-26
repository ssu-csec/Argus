//===- Unix/DynamicLibrary.cpp - Unix DL Implementation ---------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides the UNIX specific implementation of DynamicLibrary.
//
//===----------------------------------------------------------------------===//

#if defined(HAVE_DLFCN_H) && defined(HAVE_DLOPEN)
#include <dlfcn.h>

DynamicLibrary::HandleSet::~HandleSet() {
                                          
  for (void *Handle : llvh::reverse(Handles))
    ::dlclose(Handle);
  if (Process)
    ::dlclose(Process);

                                            
  DynamicLibrary::SearchOrder = DynamicLibrary::SO_Linker;
}

void *DynamicLibrary::HandleSet::DLOpen(const char *File, std::string *Err) {
  void *Handle = ::dlopen(File, RTLD_LAZY|RTLD_GLOBAL);
  if (!Handle) {
    if (Err) *Err = ::dlerror();
    return &DynamicLibrary::Invalid;
  }

#ifdef __CYGWIN__
                                             
                                                  
  if (!File)
    Handle = RTLD_DEFAULT;
#endif

  return Handle;
}

void DynamicLibrary::HandleSet::DLClose(void *Handle) {
  ::dlclose(Handle);
}

void *DynamicLibrary::HandleSet::DLSym(void *Handle, const char *Symbol) {
  return ::dlsym(Handle, Symbol);
}

#else                

DynamicLibrary::HandleSet::~HandleSet() {}

void *DynamicLibrary::HandleSet::DLOpen(const char *File, std::string *Err) {
  if (Err) *Err = "dlopen() not supported on this platform";
  return &Invalid;
}

void DynamicLibrary::HandleSet::DLClose(void *Handle) {
}

void *DynamicLibrary::HandleSet::DLSym(void *Handle, const char *Symbol) {
  return nullptr;
}

#endif

                                                    
static void *DoSearch(const char* SymbolName) {
#define EXPLICIT_SYMBOL(SYM) \
   extern void *SYM; if (!strcmp(SymbolName, #SYM)) return (void*)&SYM

                                                                               
                                                                        
                                                                                
                                           

#ifdef __APPLE__
  {
                                                                
      
                                                                              
                                           
#ifndef __clang__
#ifdef __i386__
    EXPLICIT_SYMBOL(__eprintf);
#endif
#endif
  }
#endif

#ifdef __CYGWIN__
  {
    EXPLICIT_SYMBOL(_alloca);
    EXPLICIT_SYMBOL(__main);
  }
#endif

#undef EXPLICIT_SYMBOL

                                                                  
#define EXPLICIT_SYMBOL(SYM) \
   if (!strcmp(SymbolName, #SYM)) return &SYM

                                                                            
                                                                        
                                                                             
#if defined(__GLIBC__)
  {
    EXPLICIT_SYMBOL(stderr);
    EXPLICIT_SYMBOL(stdout);
    EXPLICIT_SYMBOL(stdin);
  }
#else
                                                                                
                                             
  {
#ifndef stdin
    EXPLICIT_SYMBOL(stdin);
#endif
#ifndef stdout
    EXPLICIT_SYMBOL(stdout);
#endif
#ifndef stderr
    EXPLICIT_SYMBOL(stderr);
#endif
  }
#endif
#undef EXPLICIT_SYMBOL

  return nullptr;
}

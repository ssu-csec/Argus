//===- Win32/DynamicLibrary.cpp - Win32 DL Implementation -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides the Win32 specific implementation of DynamicLibrary.
//
//===----------------------------------------------------------------------===//

#include "WindowsSupport.h"
#include "llvh/Support/ConvertUTF.h"
#include "llvh/Support/raw_ostream.h"

#include <psapi.h>

                                                                                
                                                                        
                                         
                                                                                


DynamicLibrary::HandleSet::~HandleSet() {
  for (void *Handle : llvh::reverse(Handles))
    FreeLibrary(HMODULE(Handle));

                                                 
  assert((!Process || Process==this) && "Bad Handle");
                                            
  DynamicLibrary::SearchOrder = DynamicLibrary::SO_Linker;
}

void *DynamicLibrary::HandleSet::DLOpen(const char *File, std::string *Err) {
                                                                 
                                                    
  if (!File)
    return &(*OpenedHandles);

  SmallVector<wchar_t, MAX_PATH> FileUnicode;
  if (std::error_code ec = windows::UTF8ToUTF16(File, FileUnicode)) {
    SetLastError(ec.value());
    MakeErrMsg(Err, std::string(File) + ": Can't convert to UTF-16");
    return &DynamicLibrary::Invalid;
  }

  HMODULE Handle = LoadLibraryW(FileUnicode.data());
  if (Handle == NULL) {
    MakeErrMsg(Err, std::string(File) + ": Can't open");
    return &DynamicLibrary::Invalid;
  }

  return reinterpret_cast<void*>(Handle);
}

static DynamicLibrary::HandleSet *IsOpenedHandlesInstance(void *Handle) {
  if (!OpenedHandles.isConstructed())
    return nullptr;
  DynamicLibrary::HandleSet &Inst = *OpenedHandles;
  return Handle == &Inst ? &Inst : nullptr;
}

void DynamicLibrary::HandleSet::DLClose(void *Handle) {
  if (HandleSet* HS = IsOpenedHandlesInstance(Handle))
    HS->Process = nullptr;                                   
  else
    FreeLibrary((HMODULE)Handle);
}

static bool GetProcessModules(HANDLE H, DWORD &Bytes, HMODULE *Data = nullptr) {
                                                                      
                                              
  if (
#ifdef _WIN64
      !EnumProcessModulesEx(H, Data, Bytes, &Bytes, LIST_MODULES_64BIT)
#else
      !EnumProcessModules(H, Data, Bytes, &Bytes)
#endif
     ) {
    std::string Err;
    if (MakeErrMsg(&Err, "EnumProcessModules failure"))
      llvh::errs() << Err << "\n";
    return false;
  }
  return true;
}

void *DynamicLibrary::HandleSet::DLSym(void *Handle, const char *Symbol) {
  HandleSet* HS = IsOpenedHandlesInstance(Handle);
  if (!HS)
    return (void *)uintptr_t(GetProcAddress((HMODULE)Handle, Symbol));

                                                      
  if (!HS->Process)
    return nullptr;

                                                                           
                                                          
    
                                                                    
                                                                      
                                                         
                                                         
                                                         
    
                                                             
    
                                                                             
                                                                       
                                                                       

  DWORD Bytes = 0;
  HMODULE Self = HMODULE(GetCurrentProcess());
  if (!GetProcessModules(Self, Bytes))
    return nullptr;

                                                                             
                                                                               
                                                                            
                                                         
  std::vector<HMODULE> Handles;
  do {
    assert(Bytes && ((Bytes % sizeof(HMODULE)) == 0) &&
           "Should have at least one module and be aligned");
    Handles.resize(Bytes / sizeof(HMODULE));
    if (!GetProcessModules(Self, Bytes, Handles.data()))
      return nullptr;
  } while (Bytes != (Handles.size() * sizeof(HMODULE)));

                                                            
  if (FARPROC Ptr = GetProcAddress(HMODULE(Handles.front()), Symbol))
    return (void *) uintptr_t(Ptr);

  if (Handles.size() > 1) {
                                                                            
                                                                          
                                                                               
                                                                           
                                                         

    for (auto I = Handles.rbegin(), E = Handles.rend()-1; I != E; ++I) {
      if (FARPROC Ptr = GetProcAddress(HMODULE(*I), Symbol))
        return (void *) uintptr_t(Ptr);
    }
  }
  return nullptr;
}


                                                                                
                                                   
#define EXPLICIT_SYMBOL(SYM)                    \
  extern "C" { extern void *SYM; }
#define EXPLICIT_SYMBOL2(SYMFROM, SYMTO) EXPLICIT_SYMBOL(SYMTO)

#ifdef _M_IX86
                                                                             
                                                                        
                                                                          
                                                          

#define INLINE_DEF_SYMBOL1(TYP, SYM)                                           \
  extern "C" TYP inline_##SYM(TYP _X) { return SYM(_X); }
#define INLINE_DEF_SYMBOL2(TYP, SYM)                                           \
  extern "C" TYP inline_##SYM(TYP _X, TYP _Y) { return SYM(_X, _Y); }
#endif

#include "explicit_symbols.inc"

#undef EXPLICIT_SYMBOL
#undef EXPLICIT_SYMBOL2
#undef INLINE_DEF_SYMBOL1
#undef INLINE_DEF_SYMBOL2

static void *DoSearch(const char *SymbolName) {

#define EXPLICIT_SYMBOL(SYM)                                                   \
  if (!strcmp(SymbolName, #SYM))                                               \
    return (void *)&SYM;
#define EXPLICIT_SYMBOL2(SYMFROM, SYMTO)                                       \
  if (!strcmp(SymbolName, #SYMFROM))                                           \
    return (void *)&SYMTO;

#ifdef _M_IX86
#define INLINE_DEF_SYMBOL1(TYP, SYM)                                           \
  if (!strcmp(SymbolName, #SYM))                                               \
    return (void *)&inline_##SYM;
#define INLINE_DEF_SYMBOL2(TYP, SYM) INLINE_DEF_SYMBOL1(TYP, SYM)
#endif

  {
#include "explicit_symbols.inc"
  }

#undef EXPLICIT_SYMBOL
#undef EXPLICIT_SYMBOL2
#undef INLINE_DEF_SYMBOL1
#undef INLINE_DEF_SYMBOL2

  return nullptr;
}

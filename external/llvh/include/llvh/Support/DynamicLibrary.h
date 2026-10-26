//===-- llvm/Support/DynamicLibrary.h - Portable Dynamic Library -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the sys::DynamicLibrary class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_DYNAMICLIBRARY_H
#define LLVM_SUPPORT_DYNAMICLIBRARY_H

#include <string>

namespace llvh {

class StringRef;

namespace sys {

                                                                              
                                                                        
                                                                              
                                                                               
                                                                       
                                                                           
                                                                               
                                                                          
                                    
     
                                                                              
                                                                   
  class DynamicLibrary {
                                                               
                                                                               
                                                                         
    static char Invalid;

                                                                               
    void *Data;

  public:
    explicit DynamicLibrary(void *data = &Invalid) : Data(data) {}

                                                             
    bool isValid() const { return Data != &Invalid; }

                                                                           
                                                                                
                                                                           
                                                                    
                                                                          
                    
    void *getAddressOfSymbol(const char *symbolName);

                                                                              
                                                                         
                                                                              
                                                                             
                                     
       
                                                                             
                                           
    static DynamicLibrary getPermanentLibrary(const char *filename,
                                              std::string *errMsg = nullptr);

                                                                            
                                    
       
                                                                             
                                                             
       
                                                                              
    static DynamicLibrary addPermanentLibrary(void *handle,
                                              std::string *errMsg = nullptr);

                                                                              
                                                                            
                                        
       
                                                                             
    static bool LoadLibraryPermanently(const char *Filename,
                                       std::string *ErrMsg = nullptr) {
      return !getPermanentLibrary(Filename, ErrMsg).isValid();
    }

    enum SearchOrdering {
                                                                        
                                                                      
                                                             
      SO_Linker,
                                                                                
      SO_LoadedFirst,
                                                                           
                                                                             
      SO_LoadedLast,
                                                                              
                                                                         
      SO_LoadOrder = 4
    };
    static SearchOrdering SearchOrder;               

                                                                       
                                                                              
                                                                              
                                                                           
                                                       
                                     
                                                        
    static void *SearchForAddressOfSymbol(const char *symbolName);

                                            
    static void *SearchForAddressOfSymbol(const std::string &symbolName) {
      return SearchForAddressOfSymbol(symbolName.c_str());
    }

                                                                         
                                                                    
                  
                                         
    static void AddSymbol(StringRef symbolName, void *symbolValue);

    class HandleSet;
  };

}                     
}                      

#endif

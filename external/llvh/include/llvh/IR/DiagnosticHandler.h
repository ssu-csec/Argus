//===- DiagnosticHandler.h - DiagnosticHandler class for LLVM -*- C++ ---*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// Base DiagnosticHandler class declaration. Derive from this class to provide
// custom diagnostic reporting.
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_DIAGNOSTICHANDLER_H
#define LLVM_IR_DIAGNOSTICHANDLER_H

#include "llvh/ADT/StringRef.h"

namespace llvh {
class DiagnosticInfo;

                                                           
                                                                              
                                                                      
                              
struct DiagnosticHandler {
  void *DiagnosticContext = nullptr;
  DiagnosticHandler(void *DiagContext = nullptr)
      : DiagnosticContext(DiagContext) {}
  virtual ~DiagnosticHandler() = default;

  using DiagnosticHandlerTy = void (*)(const DiagnosticInfo &DI, void *Context);

                                                                            
                                                                             
                                                            
                                    
  DiagnosticHandlerTy DiagHandlerCallback = nullptr;

                                                                  
                                                                        
                                                                       
                                          
  virtual bool handleDiagnostics(const DiagnosticInfo &DI) {
    if (DiagHandlerCallback) {
      DiagHandlerCallback(DI, DiagnosticContext);
      return true;
    }
    return false;
  }

                                                           
                                          
  virtual bool isAnalysisRemarkEnabled(StringRef PassName) const;

                                                                      
                                          
  virtual bool isMissedOptRemarkEnabled(StringRef PassName) const;

                                                                      
                                          
  virtual bool isPassedOptRemarkEnabled(StringRef PassName) const;

                                                                   
  bool isAnyRemarkEnabled(StringRef PassName) const {
    return (isMissedOptRemarkEnabled(PassName) ||
            isPassedOptRemarkEnabled(PassName) ||
            isAnalysisRemarkEnabled(PassName));
  }

                                                                  
  virtual bool isAnyRemarkEnabled() const;
};
}                  

#endif                               

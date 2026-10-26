//===- llvm/LLVMContext.h - Class for managing "global" state ---*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares LLVMContext, a container of "global" state in LLVM, such
// as the global type and constant uniquing tables.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_LLVMCONTEXT_H
#define LLVM_IR_LLVMCONTEXT_H

#include "llvh-c/Types.h"
#include "llvh/IR/DiagnosticHandler.h"
#include "llvh/Support/CBindingWrapping.h"
#include "llvh/Support/Options.h"
#include <cstdint>
#include <memory>
#include <string>

namespace llvh {

class DiagnosticInfo;
enum DiagnosticSeverity : char;
class Function;
class Instruction;
class LLVMContextImpl;
class Module;
class OptPassGate;
template <typename T> class SmallVectorImpl;
class SMDiagnostic;
class StringRef;
class Twine;

namespace yaml {

class Output;

}                      

namespace SyncScope {

typedef uint8_t ID;

                                                                           
                                                                           
                                                                         
                                                                
enum {
                                                                                
  SingleThread = 0,

                                                                      
  System = 1
};

}                           

                                                                        
                                                                     
                                                                    
                                                                               
                                   
class LLVMContext {
public:
  LLVMContextImpl *const pImpl;
  LLVMContext();
  LLVMContext(LLVMContext &) = delete;
  LLVMContext &operator=(const LLVMContext &) = delete;
  ~LLVMContext();

                                                                        
                                                                           
  enum : unsigned {
    MD_dbg = 0,                               
    MD_tbaa = 1,                               
    MD_prof = 2,                               
    MD_fpmath = 3,                               
    MD_range = 4,                               
    MD_tbaa_struct = 5,                               
    MD_invariant_load = 6,                               
    MD_alias_scope = 7,                               
    MD_noalias = 8,                                
    MD_nontemporal = 9,                               
    MD_mem_parallel_loop_access = 10,                                   
    MD_nonnull = 11,                              
    MD_dereferenceable = 12,                              
    MD_dereferenceable_or_null = 13,                              
    MD_make_implicit = 14,                              
    MD_unpredictable = 15,                              
    MD_invariant_group = 16,                              
    MD_align = 17,                              
    MD_loop = 18,                                   
    MD_type = 19,                              
    MD_section_prefix = 20,                              
    MD_absolute_symbol = 21,                              
    MD_associated = 22,                              
    MD_callees = 23,                              
    MD_irr_loop = 24,                              
  };

                                                                          
                                                                             
                                                                             
                                                    
  enum : unsigned {
    OB_deopt = 0,                   
    OB_funclet = 1,                   
    OB_gc_transition = 2,                   
  };

                                                                                
                                                                   
  unsigned getMDKindID(StringRef Name) const;

                                                                             
                                                         
  void getMDKindNames(SmallVectorImpl<StringRef> &Result) const;

                                                                          
                                                                              
                               
                                             
  void getOperandBundleTags(SmallVectorImpl<StringRef> &Result) const;

                                                                               
                                                          
  uint32_t getOperandBundleTagID(StringRef Tag) const;

                                                                 
                                                                            
                                                        
  SyncScope::ID getOrInsertSyncScopeID(StringRef SSN);

                                                                    
                                                                               
                                                                      
  void getSyncScopeNames(SmallVectorImpl<StringRef> &SSNs) const;

                                  
  void setGC(const Function &Fn, std::string GCName);

                                  
  const std::string &getGC(const Function &Fn);

                                  
  void deleteGC(const Function &Fn);

                                                                            
                                                                             
         
  bool shouldDiscardValueNames() const;

                                                                          
                                                                         
                                 
  void setDiscardValueNames(bool Discard);

                                                           
                                                      
  bool isODRUniquingDebugTypes() const;
  void enableDebugTypeODRUniquing();
  void disableDebugTypeODRUniquing();

  using InlineAsmDiagHandlerTy = void (*)(const SMDiagnostic&, void *Context,
                                          unsigned LocCookie);

                                           
                                         
  using YieldCallbackTy = void (*)(LLVMContext *Context, void *OpaqueHandle);

                                                                                
                                                                           
                                                                             
                                       
     
                                                                     
               
  void setInlineAsmDiagnosticHandler(InlineAsmDiagHandlerTy DiagHandler,
                                     void *DiagContext = nullptr);

                                                                          
                                    
  InlineAsmDiagHandlerTy getInlineAsmDiagnosticHandler() const;

                                                                          
                                    
  void *getInlineAsmDiagnosticContext() const;

                                                                         
                                                                            
                                                                                  
                                                                                 
                                                           
     
                                                                     
               
  void setDiagnosticHandlerCallBack(
      DiagnosticHandler::DiagnosticHandlerTy DiagHandler,
      void *DiagContext = nullptr, bool RespectFilters = false);

                                                                                       
                                                                                       
                                                                                    
                                                                  
     
                                                            
  void setDiagnosticHandler(std::unique_ptr<DiagnosticHandler> &&DH,
                            bool RespectFilters = false);

                                                                                   
                                   
  DiagnosticHandler::DiagnosticHandlerTy getDiagnosticHandlerCallBack() const;

                                                                 
                           
  void *getDiagnosticContext() const;

                                                                               
                           
  const DiagnosticHandler *getDiagHandlerPtr() const;

                                                                                 
                
  std::unique_ptr<DiagnosticHandler> getDiagnosticHandler();

                                                                        
                  
  bool getDiagnosticsHotnessRequested() const;
                                                                     
                  
  void setDiagnosticsHotnessRequested(bool Requested);

                                                                       
                                                                              
                   
  uint64_t getDiagnosticsHotnessThreshold() const;

                                                                     
                                           
  void setDiagnosticsHotnessThreshold(uint64_t Threshold);

                                                                   
                                                                         
                                         
  yaml::Output *getDiagnosticsOutputFile();
                                                                        
     
                                                                             
                                                                             
                                                              
  void setDiagnosticsOutputFile(std::unique_ptr<yaml::Output> F);

                                                                       
                                  
  static const char *getDiagnosticMessagePrefix(DiagnosticSeverity Severity);

                                                                     
     
                                                                         
                                                                              
                                                                        
                          
     
                                                                                
                                                                        
                                                                 
  void diagnose(const DiagnosticInfo &DI);

                                                        
     
                                                                                
                                                                                
                                                                           
                                                                              
                                                                              
                                                                        
                                                                          
                                   
     
                                                                                
                                                                         
                                                                            
                                                                         
                                                                         
                                                                              
  void setYieldCallback(YieldCallbackTy Callback, void *OpaqueHandle);

                                               
     
                                                                                
                                                                              
                                                                             
  void yield();

                                                                                
                                                                                
                                                                               
                                                                        
                                                                       
  void emitError(unsigned LocCookie, const Twine &ErrorStr);
  void emitError(const Instruction *I, const Twine &ErrorStr);
  void emitError(const Twine &ErrorStr);

                                       
     
                                                                           
  template <typename ValT, typename Base, ValT(Base::*Mem)>
  ValT getOption() const {
    return OptionRegistry::instance().template get<ValT, Base, Mem>();
  }

                                                                        
                                    
  OptPassGate &getOptPassGate() const;

                                                                     
                                    
     
                                                                            
                                         
  void setOptPassGate(OptPassGate&);

private:
                                                         
  friend class Module;

                                                                              
                                                                 
  void addModule(Module*);

                                                           
  void removeModule(Module*);
};

                                                                
DEFINE_SIMPLE_CONVERSION_FUNCTIONS(LLVMContext, LLVMContextRef)

                                          
   
inline LLVMContext **unwrap(LLVMContextRef* Tys) {
  return reinterpret_cast<LLVMContext**>(Tys);
}

inline LLVMContextRef *wrap(const LLVMContext **Tys) {
  return reinterpret_cast<LLVMContextRef*>(const_cast<LLVMContext**>(Tys));
}

}                      

#endif                         

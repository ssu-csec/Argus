//===- llvm/Support/ErrorHandling.h - Fatal error handling ------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines an API used to indicate fatal error conditions.  Non-fatal
// errors (most of them) should be handled through LLVMContext.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_ERRORHANDLING_H
#define LLVM_SUPPORT_ERRORHANDLING_H

#include "llvh/Support/Compiler.h"
#include <string>

namespace llvh {
class StringRef;
  class Twine;

                                
  typedef void (*fatal_error_handler_t)(void *user_data,
                                        const std::string& reason,
                                        bool gen_crash_diag);

                                                                           
                                                                        
     
                                                                                
                                                                               
                                                                           
                                                                            
             
     
                                                                                
                                                                               
                                                                                
                   
     
                                                                              
              
  void install_fatal_error_handler(fatal_error_handler_t handler,
                                   void *user_data = nullptr);

                                                
  void remove_fatal_error_handler();

                                                                        
                                                              
                                                   
  struct ScopedFatalErrorHandler {
    explicit ScopedFatalErrorHandler(fatal_error_handler_t handler,
                                     void *user_data = nullptr) {
      install_fatal_error_handler(handler, user_data);
    }

    ~ScopedFatalErrorHandler() { remove_fatal_error_handler(); }
  };

                                                                       
                                                                            
                                                                      
   
                                                                           
                                          
                                                                         
                    
LLVM_ATTRIBUTE_NORETURN void report_fatal_error(const char *reason,
                                                bool gen_crash_diag = true);
LLVM_ATTRIBUTE_NORETURN void report_fatal_error(const std::string &reason,
                                                bool gen_crash_diag = true);
LLVM_ATTRIBUTE_NORETURN void report_fatal_error(StringRef reason,
                                                bool gen_crash_diag = true);
LLVM_ATTRIBUTE_NORETURN void report_fatal_error(const Twine &reason,
                                                bool gen_crash_diag = true);

                                                                         
                                                                        
   
                                                                             
                                                                              
                                                               
   
                                                                              
                                                                             
                                                                         
                                                                          
           
   
   
                                                                              
            
void install_bad_alloc_error_handler(fatal_error_handler_t handler,
                                     void *user_data = nullptr);

                                                       
void remove_bad_alloc_error_handler();

void install_out_of_memory_new_handler();

                                                                 
                                                                  
                                                                 
                                              
   
                                                                             
                                                                             
                        
   
                                                                          
                                                                                 
              
void report_bad_alloc_error(const char *Reason, bool GenCrashDiag = true);

                                                                           
                                                                        
                                   
LLVM_ATTRIBUTE_NORETURN void
llvm_unreachable_internal(const char *msg = nullptr, const char *file = nullptr,
                          unsigned line = 0);
}

                                                                    
                                                                      
                                                                         
                                                                     
                                                 
   
                                                                      
                                                   
#ifndef NDEBUG
#define llvm_unreachable(msg) \
  ::llvh::llvm_unreachable_internal(msg, __FILE__, __LINE__)
#elif defined(LLVM_BUILTIN_UNREACHABLE)
#define llvm_unreachable(msg) LLVM_BUILTIN_UNREACHABLE
#else
#define llvm_unreachable(msg) ::llvh::llvm_unreachable_internal()
#endif

#endif

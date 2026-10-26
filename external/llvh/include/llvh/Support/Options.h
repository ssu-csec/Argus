//===- llvm/Support/Options.h - Debug options support -----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
/// \file
/// This file declares helper objects for defining debug options that can be
/// configured via the command line. The new API currently builds on the cl::opt
/// API, but does not require the use of static globals.
///
/// With this API options are registered during initialization. For passes, this
/// happens during pass initialization. Passes with options will call a static
/// registerOptions method during initialization that registers options with the
/// OptionRegistry. An example implementation of registerOptions is:
///
/// static void registerOptions() {
///   OptionRegistry::registerOption<bool, Scalarizer,
///                                &Scalarizer::ScalarizeLoadStore>(
///       "scalarize-load-store",
///       "Allow the scalarizer pass to scalarize loads and store", false);
/// }
///
/// When reading data for options the interface is via the LLVMContext. Option
/// data for passes should be read from the context during doInitialization. An
/// example of reading the above option would be:
///
/// ScalarizeLoadStore =
///   M.getContext().getOption<bool,
///                            Scalarizer,
///                            &Scalarizer::ScalarizeLoadStore>();
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_OPTIONS_H
#define LLVM_SUPPORT_OPTIONS_H

#include "llvh/ADT/DenseMap.h"
#include "llvh/Support/CommandLine.h"

namespace llvh {

namespace detail {

                                                                            
                               
template <typename ValT, typename Base, ValT(Base::*Mem)> class OptionKey {
public:
  static char ID;
};

template <typename ValT, typename Base, ValT(Base::*Mem)>
char OptionKey<ValT, Base, Mem>::ID = 0;

}                    

                                                   
   
                                                                               
                                                                                
                                                                               
                                             
class OptionRegistry {
private:
  DenseMap<void *, cl::Option *> Options;

                                        
     
                                      
                                      
     
                                                                               
                               
  void addOption(void *Key, cl::Option *O);

public:
  ~OptionRegistry();
  OptionRegistry() {}

                                                    
  static OptionRegistry &instance();

                                                            
     
                                            
                                               
                                                              
     
                                                                             
                                                                          
                                                                             
                                                                      
  template <typename ValT, typename Base, ValT(Base::*Mem)>
  static void registerOption(StringRef ArgStr, StringRef Desc,
                             const ValT &InitValue) {
    cl::opt<ValT> *Option = new cl::opt<ValT>(ArgStr, cl::desc(Desc),
                                              cl::Hidden, cl::init(InitValue));
    instance().addOption(&detail::OptionKey<ValT, Base, Mem>::ID, Option);
  }

                                      
     
                                            
                                               
                                                              
     
                                                                                
                                                                
  template <typename ValT, typename Base, ValT(Base::*Mem)> ValT get() const {
    auto It = Options.find(&detail::OptionKey<ValT, Base, Mem>::ID);
    assert(It != Options.end() && "Option not in OptionRegistry");
    return *(cl::opt<ValT> *)It->second;
  }
};

}                  

#endif

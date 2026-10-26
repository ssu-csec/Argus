/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PLATFORMINTL_IMPLICU_COLLATOR_H
#define HERMES_PLATFORMINTL_IMPLICU_COLLATOR_H

#include "LocaleBCP47Object.h"
#include "hermes/Platform/Intl/PlatformIntl.h"
#include "hermes/Platform/Unicode/icu.h"

#include <string_view>

namespace hermes {
namespace platform_intl {
namespace impl_icu {

class Collator : public platform_intl::Collator {
 public:
     
                               
     
  Collator() = default;

     
                                   
     
  ~Collator() override;

     
                              
    
                                                         
    
                                  
                                        
                                        
                                                                           
                
     
  vm::ExecutionStatus initialize(
      vm::Runtime &runtime,
      const std::vector<std::u16string> &locales,
      const Options &options) noexcept;

     
                                  
    
                                                                              
    
                                                                           
                                                                  
     
  Options resolvedOptions() noexcept;

     
                                                      
    
                                                              
    
                                          
                                           
                                                      
                                                     
                                            
     
  double compare(const std::u16string &x, const std::u16string &y) noexcept;

     
                                                     
    
                                                                       
    
                                  
                                        
                                        
                                                                               
                                                        
     
  static vm::CallResult<std::vector<std::u16string>> supportedLocalesOf(
      vm::Runtime &runtime,
      const std::vector<std::u16string> &locales,
      const Options &options) noexcept;

 private:
     
                                                         
     
  void close();

                                                    
  vm::ExecutionStatus initializeCollator(
      vm::Runtime &runtime,
      const std::vector<std::u16string> &locales,
      const Options &options) noexcept;

     
                                                                     
                      
     
  void setAttributes();

  static bool isExtensionTypeSupported(
      std::u16string_view extensionKey,
      std::u16string_view extensionType,
      const LocaleBCP47Object &localeBCP47Object);

  std::u16string resolvedLocale_;
  std::u16string resolvedInternalLocale_;
  std::u16string resolvedUsageValue_;
  std::u16string resolvedSensitivityValue_;
  bool resolvedIgnorePunctuationValue_ = false;
  std::u16string resolvedCollationValue_;
  bool resolvedNumericValue_ = false;
  std::u16string resolvedCaseFirstValue_;
  UCollator *coll_ = nullptr;
};

}                      
}                           
}                    

#endif                                          

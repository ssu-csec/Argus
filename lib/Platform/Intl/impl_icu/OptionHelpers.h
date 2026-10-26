/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PLATFORMINTL_IMPLICU_OPTIONHELPERS_H
#define HERMES_PLATFORMINTL_IMPLICU_OPTIONHELPERS_H

#include "hermes/Platform/Intl/PlatformIntl.h"
#include "llvh/ADT/ArrayRef.h"

#include <optional>
#include <string_view>

namespace hermes {
namespace platform_intl {
namespace impl_icu {

   
                                                        
                                                       
                         
                                         
                                
                                                         
                                                
                                                  
                                    
                                                     
                                                   
                                            
                                       
   
vm::CallResult<std::optional<std::u16string>> getStringOption(
    vm::Runtime &runtime,
    const Options &options,
    const std::u16string &property,
    llvh::ArrayRef<const char16_t *> validValues,
    std::optional<std::u16string_view> defaultValue);

   
                                                      
                                                      
                
                                                         
                                                
                                    
                                                         
                                    
   
std::optional<bool> getBoolOption(
    const Options &options,
    const std::u16string &property,
    std::optional<bool> defaultValue);

   
                                                        
                                                              
                                               
                                                        
                                
                                                         
                                                
                                      
                                      
                                    
                                                     
                                                   
                                            
                                       
   
vm::CallResult<std::optional<double>> getNumberOption(
    vm::Runtime &runtime,
    const Options &options,
    const std::u16string &property,
    double minimum,
    double maximum,
    std::optional<double> defaultValue);

}                      
}                           
}                    

#endif                                               

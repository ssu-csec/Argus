/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "OptionHelpers.h"

#include <cmath>

namespace hermes {
namespace platform_intl {
namespace impl_icu {

vm::CallResult<std::optional<std::u16string>> getStringOption(
    vm::Runtime &runtime,
    const Options &options,
    const std::u16string &property,
    llvh::ArrayRef<const char16_t *> validValues,
    std::optional<std::u16string_view> defaultValue) {
                                              
  auto iter = options.find(property);
                                   
                                                               
                         
  if (iter == options.end()) {
    return std::optional<std::u16string>(defaultValue);
  }
             
                                 
                                         
  const auto &optionValue = iter->second.getString();
                                                                 
                                  
  if (!validValues.empty() &&
      llvh::find(validValues, optionValue) == validValues.end()) {
    return runtime.raiseRangeError(
        vm::TwineChar16(property.c_str()) +
        vm::TwineChar16(" value is invalid."));
  }
                     
  return std::optional<std::u16string>(optionValue);
}

std::optional<bool> getBoolOption(
    const Options &options,
    const std::u16string &property,
    std::optional<bool> defaultValue) {
                                              
  auto iter = options.find(property);
                                   
                                                               
                         
  if (iter == options.end()) {
    return defaultValue;
  }
                                
                                        
                     
  return iter->second.getBool();
}

                                               
vm::CallResult<std::optional<double>> getNumberOption(
    vm::Runtime &runtime,
    const Options &options,
    const std::u16string &property,
    double minimum,
    double maximum,
    std::optional<double> defaultValue) {
  auto iter = options.find(property);
                                                                    
                                               
  if (iter == options.end()) {
    return defaultValue;
  }
                                       
  double optionValue = iter->second.getNumber();
                                                                     
                                  
  if (std::isnan(optionValue) || optionValue < minimum ||
      optionValue > maximum) {
    return runtime.raiseRangeError(
        vm::TwineChar16(property.c_str()) +
        vm::TwineChar16(" value is invalid."));
  }
                            
  return std::optional<double>(std::floor(optionValue));
}

}                      
}                           
}                    

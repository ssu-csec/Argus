/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PLATFORMINTL_IMPLICU_LOCALERESOLVER_H
#define HERMES_PLATFORMINTL_IMPLICU_LOCALERESOLVER_H

#include "LocaleBCP47Object.h"
#include "hermes/Platform/Intl/PlatformIntl.h"
#include "llvh/ADT/ArrayRef.h"

#include <string>
#include <string_view>

namespace hermes {
namespace platform_intl {
namespace impl_icu {

struct ResolvedResult {
  Options resolvedOpts;
  LocaleBCP47Object localeBcp47Object;
};

   
                                                                   
                                              
                                                             
                               
                                                          
                                                                      
                                                        
                                         
   
ResolvedResult resolveLocale(
    const std::vector<LocaleBCP47Object> &requestedLocales,
    const Options &opt,
    llvh::ArrayRef<std::u16string_view> relevantExtensionKeys,
    const std::function<bool(
        std::u16string_view,                    
        std::u16string_view,                     
        const LocaleBCP47Object &)> &isExtensionTypeSupported);

   
                                                                
                                                       
                                
                                        
                                        
                                                                             
                                                      
   
vm::CallResult<std::vector<std::u16string>> supportedLocales(
    vm::Runtime &runtime,
    const std::vector<std::u16string> &locales,
    const Options &options) noexcept;

}                      
}                           
}                    

#endif                                                

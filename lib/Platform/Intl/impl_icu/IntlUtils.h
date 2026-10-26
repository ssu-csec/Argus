/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PLATFORMINTL_IMPLICU_INTLUTILS_H
#define HERMES_PLATFORMINTL_IMPLICU_INTLUTILS_H

#include <string>
#include <string_view>

namespace hermes {
namespace platform_intl {
namespace impl_icu {

   
                                                     
                                                         
                                                                         
   
std::string toUTF8ASCII(std::u16string_view utf16Source);

   
                                                     
                                                       
                                                                         
   
std::u16string toUTF16ASCII(std::string_view utf8Source);

   
                                 
                                     
                        
   
bool convertToBool(const std::string &str);

   
                                  
                                      
                        
   
bool convertToBool(std::u16string_view str);

   
                                                                   
                                                
                                          
                               
   
std::string toLowerASCII(std::string str);

}                      
}                           
}                    

#endif                                           

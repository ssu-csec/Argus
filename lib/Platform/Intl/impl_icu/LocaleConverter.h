/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PLATFORMINTL_IMPLICU_LOCALECONVERTER_H
#define HERMES_PLATFORMINTL_IMPLICU_LOCALECONVERTER_H

#include <string>
#include <string_view>

namespace hermes {
namespace platform_intl {
namespace impl_icu {

   
                                       
                                             
                       
   
std::string convertBCP47toICULocale(std::u16string_view localeBCP47);

   
                                       
                                           
                         
   
std::string convertICUtoBCP47Locale(const char *localeICU);

}                      
}                           
}                    

#endif                                                 

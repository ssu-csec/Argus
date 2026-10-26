/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PLATFORMINTL_IMPLICU_LOCALEBCP47OBJECT_H
#define HERMES_PLATFORMINTL_IMPLICU_LOCALEBCP47OBJECT_H

#include "hermes/Platform/Intl/BCP47Parser.h"
#include "hermes/VM/CallResult.h"
#include "hermes/VM/Runtime.h"

#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace hermes {
namespace platform_intl {
namespace impl_icu {

                                                                                                                              
                                                    
                        
                                   
                                                
                                                                             
                                                              
                                                   
class LocaleBCP47Object {
 public:
     
                                                                           
     
  LocaleBCP47Object() = default;

     
                                                   
                                       
                                                                            
            
     
  static std::optional<LocaleBCP47Object> forLanguageTag(
      const std::u16string &langTag);

     
                                                                         
                         
    
                                                                        
    
                                  
                                                 
                                                                                
                                               
     
  static vm::CallResult<std::vector<LocaleBCP47Object>> canonicalizeLocaleList(
      vm::Runtime &runtime,
      const std::vector<std::u16string> &locales) noexcept;

     
                                                      
                                                                    
     
  void updateExtensionMap(
      const std::map<std::u16string, std::u16string> &extensionMap);

     
                                                        
                                                    
     
  const std::u16string &getLocaleNoExt() const;

     
                                                            
                                                        
     
  const std::map<std::u16string, std::u16string> &getExtensionMap() const;

     
                                                   
                                               
     
  std::u16string getCanonicalizedLocaleId() const;

 private:
     
                                                 
                                         
                                     
                                     
                                               
                                            
     
  static std::u16string getBaseName(
      const std::u16string &languageSubtag,
      const std::u16string &scriptSubtag,
      const std::u16string &regionSubtag,
      const std::set<std::u16string> &variantSubtagList);

  std::u16string localeNoExt_;
  ParsedLocaleIdentifier parsedLocaleIdentifier_;
};

}                      
}                           
}                    

#endif                                                   

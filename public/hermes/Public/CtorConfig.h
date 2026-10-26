/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PUBLIC_CTORCONFIG_H
#define HERMES_PUBLIC_CTORCONFIG_H

#include <utility>

                                                                              
                                
   
                                                                           
                                                                               
                                                              
   
            
   
                                                                          
                                          
   
                    
                     
                                  
   
                                                             
   
                                                  
   
                                                     
                                                     
                                                     
                                                     
                                                     
                                                     
                                                     
                                                     
   
          
                                                                         
                              
                                                                           
                     
   
#define _HERMES_CTORCONFIG_STRUCT(NAME, FIELDS, BUILD_BODY)             \
  class NAME {                                                          \
    FIELDS(_HERMES_CTORCONFIG_FIELD_DECL)                               \
                                                                        \
   public:                                                              \
    class Builder;                                                      \
    friend Builder;                                                     \
    FIELDS(_HERMES_CTORCONFIG_GETTER)                                   \
                                                                        \
                                                                        \
    inline Builder rebuild() const;                                     \
                                                                        \
   private:                                                             \
    inline void doBuild(const Builder &builder);                        \
  };                                                                    \
                                                                        \
  class NAME::Builder {                                                 \
    NAME config_;                                                       \
                                                                        \
    FIELDS(_HERMES_CTORCONFIG_FIELD_EXPLICIT_BOOL_DECL)                 \
                                                                        \
   public:                                                              \
    Builder() = default;                                                \
                                                                        \
    explicit Builder(const NAME &config) : config_(config) {}           \
                                                                        \
    inline const NAME build() {                                         \
      config_.doBuild(*this);                                           \
      return config_;                                                   \
    }                                                                   \
                                                                        \
                                                                        \
                                                                        \
    inline Builder update(const NAME::Builder &newConfig);              \
                                                                        \
    FIELDS(_HERMES_CTORCONFIG_SETTER)                                   \
    FIELDS(_HERMES_CTORCONFIG_FIELD_EXPLICIT_BOOL_ACCESSOR)             \
  };                                                                    \
                                                                        \
  NAME::Builder NAME::rebuild() const {                                 \
    return Builder(*this);                                              \
  }                                                                     \
                                                                        \
  NAME::Builder NAME::Builder::update(const NAME::Builder &newConfig) { \
    FIELDS(_HERMES_CTORCONFIG_UPDATE)                                   \
    return *this;                                                       \
  }                                                                     \
                                                                        \
  void NAME::doBuild(const NAME::Builder &builder) {                    \
    (void)builder;                                                      \
    BUILD_BODY                                                          \
  }

                 

#define _HERMES_CTORCONFIG_FIELD_DECL(CX, TYPE, NAME, ...) \
  TYPE NAME##_{__VA_ARGS__};

                                                                       
                                                     
#define _HERMES_CTORCONFIG_FIELD_EXPLICIT_BOOL_DECL(CX, TYPE, NAME, ...) \
  bool NAME##Explicit_{false};

                                                                      
#define _HERMES_CTORCONFIG_FIELD_EXPLICIT_BOOL_ACCESSOR(CX, TYPE, NAME, ...) \
  bool has##NAME() const {                                                   \
    return NAME##Explicit_;                                                  \
  }

                                                                              
                           
#define HERMES_NON_CONSTEXPR

#define _HERMES_CTORCONFIG_GETTER(CX, TYPE, NAME, ...) \
  inline TYPE get##NAME() const {                      \
    return NAME##_;                                    \
  }                                                    \
  static CX TYPE getDefault##NAME() {                  \
                                                       \
    using TypeAsSingleToken = TYPE;                    \
    return TypeAsSingleToken{__VA_ARGS__};             \
  }

#define _HERMES_CTORCONFIG_SETTER(CX, TYPE, NAME, ...)   \
  inline auto with##NAME(TYPE NAME) -> decltype(*this) { \
    config_.NAME##_ = std::move(NAME);                   \
    NAME##Explicit_ = true;                              \
    return *this;                                        \
  }

#define _HERMES_CTORCONFIG_BUILDER_GETTER(CX, TYPE, NAME, ...) \
  TYPE get##NAME() const {                                     \
    return config_.NAME##_;                                    \
  }

#define _HERMES_CTORCONFIG_UPDATE(CX, TYPE, NAME, ...) \
  if (newConfig.has##NAME()) {                         \
    with##NAME(newConfig.config_.get##NAME());         \
  }

#endif                               

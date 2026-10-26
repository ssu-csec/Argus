/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                               
     
                                                                       
                                                                      
                                   

                                                                         
                

     
                            \
               \
               \
              
        

                                           

     
                                                       
        

                                                                       
                                                             

     
                          
                             
                          
                           
        

                                                                     
                                                                      
                                                                           
                  

                                                                     

     
                 
                      
                                                          
        
  
                                                                               

#ifndef HERMES_VM_TYPESAFEFLAGS_H
#define HERMES_VM_TYPESAFEFLAGS_H

#define _HERMES_VM__DECL_FLAG(name) bool f##name##_ : 1;
#define _HERMES_VM__IMPL_FLAG(name) \
  Self plus##name() const {         \
    auto r(*this);                  \
    r.f##name##_ = true;            \
    return r;                       \
  }                                 \
  Self minus##name() const {        \
    auto r(*this);                  \
    r.f##name##_ = false;           \
    return r;                       \
  }                                 \
  Self set##name(bool v) const {    \
    auto r(*this);                  \
    r.f##name##_ = v;               \
    return r;                       \
  }                                 \
  bool get##name() const {          \
    return f##name##_;              \
  }

#define HERMES_VM__DECLARE_FLAGS_CLASS(ClassName, listMacro) \
  union ClassName {                                          \
   private:                                                  \
    struct {                                                 \
      listMacro(_HERMES_VM__DECL_FLAG)                       \
    };                                                       \
    unsigned flags_ = 0;                                     \
                                                             \
   public:                                                   \
    typedef ClassName Self;                                  \
    unsigned getRaw() const {                                \
      return flags_;                                         \
    }                                                        \
    listMacro(_HERMES_VM__IMPL_FLAG)                         \
  }

#endif                             

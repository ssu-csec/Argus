/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_PROPERTYDESCRIPTOR_H
#define HERMES_VM_PROPERTYDESCRIPTOR_H

#include <cstdint>

namespace hermes {
namespace vm {

                            
      

                                                       
struct PropertyFlags {
  union {
    struct {
                                                                              
                                                                               
                                                               
                                                                              
                                                                               
                                                                              
                                                
      uint16_t invalidFlags : 1;
                                     
      uint16_t enumerable : 1;
                                                                     
      uint16_t writable : 1;
                                         
      uint16_t configurable : 1;
                                                                            
      uint16_t accessor : 1;
                                                                             
                                        
      uint16_t indexed : 1;
                                                                            
                            
      uint16_t internalSetter : 1;
                                                                         
                                                                        
                  
      uint16_t flagsTransition : 1;
                                                                 
                                                                      
                                                                 
                                                                     
                       
      uint16_t hostObject : 1;
                                                                      
                                                                       
                                                       
      uint16_t staticBuiltin : 1;
                                                                       
                                                               
                                                                      
                                                 
      uint16_t proxyObject : 1;
    };

    uint16_t _flags;
  };
                                      
  PropertyFlags() {
    _flags = 0;
  }

  void clear() {
    _flags = 0;
  }

  bool operator==(PropertyFlags f) const {
    return _flags == f._flags;
  }
  bool operator!=(PropertyFlags f) const {
    return _flags != f._flags;
  }

                                                                            
                    
  bool isValid() const {
    return !invalidFlags;
  }

                                                                          
                                                                  
  static PropertyFlags defaultNewNamedPropertyFlags() {
    PropertyFlags pf{};
    pf.enumerable = 1;
    pf.writable = 1;
    pf.configurable = 1;
    return pf;
  }

                                                                     
                                      
  static PropertyFlags nonEnumerablePropertyFlags() {
    PropertyFlags pf{};
    pf.enumerable = 0;
    pf.writable = 1;
    pf.configurable = 1;
    return pf;
  }

                                  
  static PropertyFlags invalid() {
    PropertyFlags pf{};
    pf.invalidFlags = 1;
    return pf;
  }

                                                                    
                                                                       
  void changeFlags(PropertyFlags clear, PropertyFlags set) {
    _flags = (_flags & ~clear._flags) | set._flags;
  }
};

                                                   
using SlotIndex = uint32_t;

static const SlotIndex INVALID_SLOT_INDEX = ~(SlotIndex)0;

                                                                  
                                                                          
                                                                      
struct PropertyDescriptor {
                                                                    
                                                                             
  struct PropertyFlags32 : public PropertyFlags {
    uint16_t _padding;

    PropertyFlags32(PropertyFlags flags) : PropertyFlags(flags), _padding(0) {}

    void clear() {
      PropertyFlags::clear();
      _padding = 0;
    }
  };
  static_assert(sizeof(PropertyFlags32) == 4, "should pad to 32 bits");

  union {
    PropertyFlags32 flags;
                                                                            
                                                        
    uint32_t _altFlags;
  };
                                   
  SlotIndex slot;

  PropertyDescriptor(PropertyFlags flags, SlotIndex slot)
      : flags(flags), slot(slot) {}

  PropertyDescriptor() : _altFlags(0), slot(INVALID_SLOT_INDEX) {}
};

                                                                               
                             
struct NamedPropertyDescriptor : public PropertyDescriptor {
  NamedPropertyDescriptor(PropertyFlags flags, SlotIndex slot)
      : PropertyDescriptor(flags, slot) {}

  NamedPropertyDescriptor() = default;
};

                                                                                
                                                  
struct ComputedPropertyDescriptor : public PropertyDescriptor {
  ComputedPropertyDescriptor(PropertyFlags flags, SlotIndex slot)
      : PropertyDescriptor(flags, slot) {}

  ComputedPropertyDescriptor() = default;

 private:
  friend class JSObject;

                                                                                
  NamedPropertyDescriptor &castToNamedPropertyDescriptorRef() {
    return *static_cast<NamedPropertyDescriptor *>(
        static_cast<PropertyDescriptor *>(this));
  }
};

inline bool operator==(PropertyDescriptor a, PropertyDescriptor b) {
  return a.flags == b.flags && a.slot == b.slot;
}

      

}                
}                    

#endif                                  

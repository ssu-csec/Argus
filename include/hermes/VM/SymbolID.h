/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_SYMBOLID_H
#define HERMES_VM_SYMBOLID_H

#include "hermes/VM/GCDecl.h"

#include "llvh/ADT/DenseMap.h"

#include <cstdint>

namespace llvh {
class raw_ostream;
}

namespace hermes {
namespace vm {

                                                                           
                                                                         
                                                                              
                                       
   
                                                                              
                                                        
                                                                            
                                   
class SymbolID {
 public:
  using RawType = uint32_t;

 private:
                                                                            
                                       
  static constexpr size_t NUM_BITS = 29;
                                                                 
  static constexpr RawType VALUE_MASK = (1 << NUM_BITS) - 1;

 public:
                                                           
  static constexpr RawType NOT_UNIQUED_MASK = 1 << (NUM_BITS - 1);
                                                                              
                                             
  static constexpr RawType LAST_INDEX = NOT_UNIQUED_MASK - 1;
                                                                                
                                                                               
                                                             
  static constexpr RawType LAST_INVALID_ID = VALUE_MASK;
                                                                       
  static constexpr RawType FIRST_INVALID_ID = LAST_INVALID_ID - 1;

                                                                              
            
  static constexpr RawType EMPTY_ID = LAST_INVALID_ID - 0;

                                                                       
                                        
  static constexpr RawType DELETED_ID = LAST_INVALID_ID - 1;

  constexpr SymbolID() : id_(EMPTY_ID) {}

  SymbolID(const SymbolID &) = default;
  ~SymbolID() = default;
  SymbolID &operator=(const SymbolID &) = default;

                                              
                                                                          
                              
  constexpr uint32_t unsafeGetIndex() const {
    return id_ & (VALUE_MASK >> 1);
  }

                                                          
                                                                          
                   
  RawType unsafeGetRaw() const {
    return id_;
  }

  bool isValid() const {
    return id_ < FIRST_INVALID_ID;
  }
  bool isInvalid() const {
    return id_ >= FIRST_INVALID_ID;
  }

                                                                             
                                   
  constexpr bool isNotUniqued() const {
    return id_ & NOT_UNIQUED_MASK;
  }
                                                                         
                                   
  constexpr bool isUniqued() const {
    return !isNotUniqued();
  }

  bool operator==(SymbolID sym) const {
    return id_ == sym.id_;
  }
  bool operator!=(SymbolID sym) const {
    return id_ != sym.id_;
  }

                                                                  
                                                                           
                                                                            
                                                                            
                                                                               
  static constexpr SymbolID unsafeCreate(RawType id) {
    assert(id <= LAST_INVALID_ID && "ID outside valid range");
    return SymbolID{id};
  }

                                                                           
                                                                         
                                            

                                                                           
  static constexpr SymbolID empty() {
    return SymbolID{EMPTY_ID};
  }

                                                                
  static constexpr SymbolID deleted() {
    return SymbolID{DELETED_ID};
  }

                                                                      
                                                                                
                                                                            
                                                                            
                                                                               
                                                                      
                                                                      
  static constexpr SymbolID unsafeCreateNotUniqued(uint32_t index) {
    assert(index <= LAST_INDEX && "Index outside valid range");
    return SymbolID{index | NOT_UNIQUED_MASK};
  }

 protected:
  RawType id_;

  explicit constexpr SymbolID(RawType id) : id_(id) {}
};

llvh::raw_ostream &operator<<(llvh::raw_ostream &OS, SymbolID symbolID);

                                                                            
                                                    
class GCSymbolID final : public SymbolID {
 public:
  constexpr GCSymbolID() : SymbolID() {}

                                               
  explicit GCSymbolID(SymbolID id) : SymbolID(id) {}

  GCSymbolID(const GCSymbolID &) = default;
  ~GCSymbolID() = default;

                                                 
  GCSymbolID &operator=(const GCSymbolID &) = delete;

                                                                         
  inline GCSymbolID &set(SymbolID sym, GC &gc);
};

                                                                         
                      
class RootSymbolID final : public SymbolID {
 public:
  constexpr RootSymbolID() : SymbolID() {}

  explicit RootSymbolID(SymbolID id) : SymbolID(id) {}
};

}                
}                    

                                     
namespace llvh {

using namespace hermes::vm;

template <>
struct DenseMapInfo<SymbolID> {
  static inline SymbolID getEmptyKey() {
    return SymbolID::empty();
  }
  static inline SymbolID getTombstoneKey() {
    return SymbolID::deleted();
  }
  static inline unsigned getHashValue(SymbolID symbolID) {
    return DenseMapInfo<SymbolID::RawType>::getHashValue(
        symbolID.unsafeGetRaw());
  }
  static inline bool isEqual(SymbolID a, SymbolID b) {
    return a == b;
  }
};

}                  

#endif                        

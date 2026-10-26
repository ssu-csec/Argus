/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_METADATA_H
#define HERMES_VM_METADATA_H

#include "hermes/Support/OptValue.h"
#include "hermes/VM/GCPointer.h"
#include "hermes/VM/HermesValue.h"

#include <cassert>
#include <cstdint>
#include <map>
#include <utility>
#include <vector>

namespace hermes {
namespace vm {

                                                            
class GCSymbolID;

                                                                     
                                                                          
                         
struct Metadata final {
  using offset_t = std::uint8_t;

                                                   
  struct ArrayData {
                                              
    enum class ArrayType : uint8_t {
#define SLOT_TYPE(type) type,
#include "hermes/VM/SlotKinds.def"
#undef SLOT_TYPE
    };
    ArrayType type;
                                             
    offset_t startOffset;
                                                                              
    offset_t lengthOffset;
                                                                         
                       
    uint8_t stride;

    explicit ArrayData() = default;
    explicit constexpr ArrayData(
        ArrayType type,
        offset_t startOffset,
        offset_t lengthOffset,
        uint8_t stride)
        : type(type),
          startOffset(startOffset),
          lengthOffset(lengthOffset),
          stride(stride) {}
    ArrayData(const ArrayData &data) = default;
    ArrayData &operator=(const ArrayData &data) = default;
  };

                                                                       
                          
                                                                               
             
  class Builder final {
   public:
                                                                  
                                                      
    Builder(const void *base);

                          
          
                                     
                                                                                
                     

                                                                          
#define SLOT_TYPE(type)                     \
  void addField(const type *fieldLocation); \
  void addField(const char *name, const type *fieldLocation);
#include "hermes/VM/SlotKinds.def"
#undef SLOT_TYPE

          

                                               
                                                                        
                                                                
#define SLOT_TYPE(type)                                     \
  void addArray(                                            \
      const type *startLocation,                            \
      const AtomicIfConcurrentGC<uint32_t> *lengthLocation, \
      std::size_t stride) {                                 \
    addArray(                                               \
        nullptr,                                            \
        ArrayData::ArrayType::type,                         \
        startLocation,                                      \
        lengthLocation,                                     \
        stride);                                            \
  }                                                         \
                                                            \
  void addArray(                                            \
      const char *name,                                     \
      const type *startLocation,                            \
      const AtomicIfConcurrentGC<uint32_t> *lengthLocation, \
      std::size_t stride) {                                 \
    addArray(                                               \
        name,                                               \
        ArrayData::ArrayType::type,                         \
        startLocation,                                      \
        lengthLocation,                                     \
        stride);                                            \
  }
#include "hermes/VM/SlotKinds.def"
#undef SLOT_TYPE

    void addArray(
        const char *name,
        ArrayData::ArrayType type,
        const void *startLocation,
        const AtomicIfConcurrentGC<uint32_t> *lengthLocation,
        std::size_t stride);

                                                                              
                                                                  
    void addJSObjectOverlapSlots(unsigned num) {
      if (!jsObjectOverlapSlots_) {
        jsObjectOverlapSlots_ = num;
      } else {
                                                                              
        assert(
            num <= *jsObjectOverlapSlots_ &&
            "most derived class should call this method first");
      }
    }

                                                                              
                                
    unsigned getJSObjectOverlapSlots() const {
      assert(
          jsObjectOverlapSlots_ && "missing call to addJSObjectOverlapSlots");
      return *jsObjectOverlapSlots_;
    }

    void setVTable(const VTable *vtp) {
      vtp_ = vtp;
    }

                                                            
    Metadata build();

   private:
                                                                              
    offset_t getOffset(const void *fieldLocation);

                                                          
    const char *base_;
                                                                           
#define SLOT_TYPE(type) std::map<offset_t, const char *> map##type##_;
#include "hermes/VM/SlotKinds.def"
#undef SLOT_TYPE

#ifndef NDEBUG
                                                                            
    bool fieldConflicts(offset_t offset, size_t size);
    std::vector<bool> coveredOffsets_;
#endif
                                                   
    OptValue<ArrayData> array_;

                                                                               
    OptValue<unsigned> jsObjectOverlapSlots_;

                                                                     
    const VTable *vtp_{nullptr};

    friend Metadata;
  };

  constexpr Metadata() = default;
                               
  Metadata(Builder &&mb);

                                                                         
                                                       
  static constexpr size_t kMaxNumFields = 8;

  struct SlotOffsets {
                                                                                
                                                                              
                           

                                                                             
                  
#define SLOT_TYPE(type) uint8_t end##type{};
#include "hermes/VM/SlotKinds.def"
#undef SLOT_TYPE

    std::array<offset_t, kMaxNumFields> fields{};

                                                   
                                                                     
    OptValue<ArrayData> array{};
  } offsets;

  using SlotNames = std::array<const char *, kMaxNumFields>;

                                                                               
                                                                        
  SlotNames names{};

                                                                   
  const VTable *vtp{};

                                                                               
                                        
  static std::array<Metadata, kNumCellKinds> metadataTable;
};

static_assert(
    std::is_trivially_destructible<Metadata>::value,
    "Metadata must not have a destructor.");

                    
      

llvh::raw_ostream &operator<<(llvh::raw_ostream &os, const Metadata &meta);
llvh::raw_ostream &operator<<(llvh::raw_ostream &os, Metadata::ArrayData array);
llvh::raw_ostream &operator<<(
    llvh::raw_ostream &os,
    Metadata::ArrayData::ArrayType arraytype);

      

}                
}                    

#endif                        

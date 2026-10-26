/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_SLOTVISITOR_H
#define HERMES_VM_SLOTVISITOR_H

#include "hermes/VM/GCCell.h"
#include "hermes/VM/GCDecl.h"
#include "hermes/VM/GCPointer.h"
#include "hermes/VM/HermesValue.h"
#include "hermes/VM/Metadata.h"

namespace hermes {
namespace vm {

                                                                            
class BaseVisitor {
 protected:
                                                                    
  template <typename Acceptor, bool WithNames>
  void
  visitArray(Acceptor &acceptor, char *base, const Metadata::ArrayData &array) {
    using ArrayType = Metadata::ArrayData::ArrayType;
    char *start = base + array.startOffset;
                                                                            
                            
    const auto length = reinterpret_cast<AtomicIfConcurrentGC<std::uint32_t> *>(
                            base + array.lengthOffset)
                            ->load(std::memory_order_acquire);
    const auto stride = array.stride;
    switch (array.type) {
#define SLOT_TYPE(type)                          \
  case ArrayType::type:                          \
    visitArrayObject<Acceptor, type, WithNames>( \
        acceptor, start, length, stride);        \
    break;
#include "hermes/VM/SlotKinds.def"
#undef SLOT_TYPE
    }
  }

 private:
                                                                             
                      
  template <typename Acceptor, typename ElementType, bool WithName>
  struct ArrayElementAccept final {
    static void impl(Acceptor &acceptor, ElementType &elem, uint32_t num);
  };

  template <typename Acceptor, typename ElementType>
  struct ArrayElementAccept<Acceptor, ElementType, true> final {
    static void impl(Acceptor &acceptor, ElementType &elem, uint32_t num) {
      auto name = std::to_string(num);
                                                                             
      acceptor.accept(elem, name.c_str());
    }
  };

  template <typename Acceptor, typename ElementType>
  struct ArrayElementAccept<Acceptor, ElementType, false> final {
    static void impl(Acceptor &acceptor, ElementType &elem, uint32_t) {
      acceptor.accept(elem);
    }
  };

                                           
     
                                                                 
                                                                             
                        
                                                          
                                                     
                                                       
  template <typename Acceptor, typename ElementType, bool WithNames>
  void visitArrayObject(
      Acceptor &acceptor,
      char *start,
      std::uint32_t length,
      std::size_t stride) {
    for (std::uint32_t i = 0; i < length; ++i) {
      ArrayElementAccept<Acceptor, ElementType, WithNames>::impl(
          acceptor, *reinterpret_cast<ElementType *>(start), i);
      start += stride;
    }
  }
};

                                                                         
                                                               
   
                                                                         
                                                          
                                                                                
                                                                               
                                                    
template <typename Acceptor>
struct SlotVisitor final : BaseVisitor {
  Acceptor &acceptor_;

                                                                               
                                           
                                                                              
                                                                             
                                 
  SlotVisitor(Acceptor &acceptor) : acceptor_(acceptor) {}

                                                                 
                                                                       
                                                                             
                                                               
                                          
  void visit(GCCell *cell, const Metadata::SlotOffsets &offsets) {
    auto *ptr = reinterpret_cast<char *>(cell);
    visitFields(ptr, offsets);
    if (offsets.array) {
      visitArray<Acceptor,               false>(acceptor_, ptr, *offsets.array);
    }
  }

                                                                             
                  
  void visitWithinRange(
      GCCell *cell,
      const Metadata::SlotOffsets &offsets,
      const char *begin,
      const char *end) {
    auto *ptr = reinterpret_cast<char *>(cell);
    visitFieldsWithinRange(ptr, offsets, begin, end);
    if (offsets.array) {
      visitArrayWithinRange(ptr, *offsets.array, begin, end);
    }
  }

 private:
                                                                          
                                                                          
  template <typename T>
  void visitSlot(char *const slot) {
    assert(
        reinterpret_cast<uintptr_t>(slot) % alignof(T) == 0 &&
        "Should be aligned to the same alignment as T");
    acceptor_.accept(*reinterpret_cast<T *>(slot));
  }

                                                                             
                                                               
  void visitFields(char *base, const Metadata::SlotOffsets &offsets) {
    size_t i = 0;
#define SLOT_TYPE(type)              \
  for (; i < offsets.end##type; ++i) \
    visitSlot<type>(base + offsets.fields[i]);
#include "hermes/VM/SlotKinds.def"
#undef SLOT_TYPE
  }

                                                                             
                                                 
  void visitFieldsWithinRange(
      char *base,
      const Metadata::SlotOffsets &offsets,
      const char *begin,
      const char *end) {
    size_t i = 0;
#define SLOT_TYPE(type)                    \
  for (; i < offsets.end##type; ++i) {     \
    char *slot = base + offsets.fields[i]; \
    if (slot < begin)                      \
      continue;                            \
    if (slot >= end) {                     \
      i = offsets.end##type;               \
      break;                               \
    }                                      \
    visitSlot<type>(slot);                 \
  }
#include "hermes/VM/SlotKinds.def"
#undef SLOT_TYPE
  }

                                                                           
                   
  template <typename ElementType>
  void visitArrayObjectWithinRange(
      char *start,
      std::size_t length,
      std::size_t stride,
      const char *begin,
      const char *end) {
                                                                         
                                                
    const char *const endOfObject = start + length * stride;
    char *const alignedStartOfCard =
        const_cast<char *>(begin - (begin - start) % stride);
    start = std::max(start, alignedStartOfCard);
    end = std::min(endOfObject, end);
    while (start < end) {
                                                                        
      acceptor_.accept(*reinterpret_cast<ElementType *>(start));
      start += stride;
    }
  }

                                                              
  void visitArrayWithinRange(
      char *base,
      const Metadata::ArrayData &array,
      const char *begin,
      const char *end) {
    using ArrayType = Metadata::ArrayData::ArrayType;
    char *start = base + array.startOffset;
    const auto length =
        *reinterpret_cast<std::uint32_t *>(base + array.lengthOffset);
    const auto stride = array.stride;
    switch (array.type) {
#define SLOT_TYPE(type)                                                   \
  case ArrayType::type:                                                   \
    visitArrayObjectWithinRange<type>(start, length, stride, begin, end); \
    break;
#include "hermes/VM/SlotKinds.def"
#undef SLOT_TYPE
    }
  }
};

template <typename Acceptor>
struct SlotVisitorWithNames final : BaseVisitor {
  Acceptor &acceptor_;

  SlotVisitorWithNames(Acceptor &acceptor) : acceptor_(acceptor) {}

  void visit(
      GCCell *cell,
      const Metadata::SlotOffsets &offsets,
      const Metadata::SlotNames &names) {
    auto *ptr = reinterpret_cast<char *>(cell);
    visitFields(ptr, offsets, names);
    if (offsets.array) {
      visitArray<Acceptor,               true>(acceptor_, ptr, *offsets.array);
    }
  }

 private:
                                                                             
                                                               
  void visitFields(
      char *base,
      const Metadata::SlotOffsets &offsets,
      const Metadata::SlotNames &names) {
                                                                              
             
    size_t i = 0;
#define SLOT_TYPE(type)              \
  for (; i < offsets.end##type; ++i) \
    visitSlot<type>(base + offsets.fields[i], names[i]);
#include "hermes/VM/SlotKinds.def"
#undef SLOT_TYPE
  }

  template <typename T>
  void visitSlot(char *slot, const char *name) {
    assert(
        reinterpret_cast<uintptr_t>(slot) % alignof(T) == 0 &&
        "Should be aligned to the same alignment as T");
    acceptor_.accept(*reinterpret_cast<T *>(slot), name);
  }
};

}                
}                    

#endif

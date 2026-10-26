/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_GCCELL_H
#define HERMES_VM_GCCELL_H

#include "hermes/Support/Algorithms.h"
#include "hermes/VM/CellKind.h"
#include "hermes/VM/CompressedPointer.h"
#include "hermes/VM/HeapAlign.h"
#include "hermes/VM/VTable.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

template <typename T>
class ExternalStringPrimitive;
class VariableSizeRuntimeCell;

                                                                              
                                                                           
                                                                               
                         
template <class C>
static constexpr uint32_t cellSize() {
  static_assert(HeapAlign % alignof(C) == 0, "insufficient heap alignment");
  return heapAlignSize(C::template cellSizeImpl<C>());
}

                                                                   
class KindAndSize {
 public:
  size_t getSize() const {
    return size_;
  }
  CellKind getKind() const {
    return static_cast<CellKind>(kind_);
  }
  const VTable *getVT() const {
    return VTable::vtableArray[kind_];
  }
  KindAndSize() = default;
  KindAndSize(CellKind kind, size_t sz)
      : size_(sz), kind_(static_cast<uint8_t>(kind)) {
    assert((sz & 1) == 0 && "LSB of size must always be zero.");
    assert(sz <= maxSize() && "Size is too large.");
  }

  static constexpr uint32_t maxSize() {
    return (1ULL << kNumSizeBits) - 1;
  }

 private:
  using RawType = CompressedPointer::RawType;
  static constexpr size_t kNumBits = sizeof(RawType) * 8;
  static constexpr size_t kNumKindBits = 8;
                                                                                
                                                                
  static constexpr size_t kNumSizeBits =
      std::min<size_t>(kNumBits - kNumKindBits, 32);
  static_assert(
      kNumCellKinds < 256,
      "More cell kinds than available kind bits.");

                                                                             
                                                                          
                                                                  
  RawType size_ : kNumSizeBits;
                               
  RawType kind_ : kNumKindBits;
};

static_assert(
    std::is_trivial<KindAndSize>::value,
    "KindAndSize must be trivial");

                                                               
                                                                     
                                                                
class GCCell {
                                                                         
              
  union {
    KindAndSize kindAndSize_;
    AssignableCompressedPointer forwardingPointer_;
  };

#ifndef NDEBUG
  static constexpr uint16_t kMagic{0xce11};
                                                                        
  const uint16_t magic_{kMagic};
                                                                               
                 
  uint32_t _debugAllocationId_;
#endif

 public:
  GCCell() = default;

                                                  
  GCCell(const GCCell &) = delete;
  void operator=(const GCCell &) = delete;

                                                       
  uint32_t getAllocatedSize() const {
    return kindAndSize_.getSize();
  }

                                                           
  template <class C>
  static constexpr uint32_t cellSizeImpl() {
    static_assert(std::is_convertible<C *, GCCell *>::value, "must be a cell");
                                                                                
                                    
    static_assert(
        !std::is_convertible<C *, VariableSizeRuntimeCell *>::value,
        "must be fixed-size");
    return sizeof(C);
  }

                                                                            
  bool isVariableSize() const {
    return isVariableSize(getVT());
  }

                                                                            
                                                         
  static bool isVariableSize(const VTable *vtp) {
    return vtp->size == 0;
  }

                                    
  CellKind getKind() const {
    return kindAndSize_.getKind();
  }

                                       
                                  
  const VTable *getVT() const {
    assert(isValid() && "Called getVT() on an invalid cell");
    return kindAndSize_.getVT();
  }

                                            
                                               
  KindAndSize getKindAndSize() const {
    return kindAndSize_;
  }

                                                           
                                               
  void setKindAndSize(KindAndSize kindAndSize) {
    kindAndSize_ = kindAndSize;
  }

                                                              
                                                                   
                                                                  
                                                                     
                                                              
                                                                    
                                                             
                                                                
                                                              
                               

                                                                 

                                                                     
                                               
  void setForwardingPointer(CompressedPointer cell) {
    forwardingPointer_ = cell;
  }

                                                                           
                                                                         
                                                          
                                               
  CompressedPointer getForwardingPointer() const {
    return forwardingPointer_;
  }

                                                                 

                                                                               
                                                                               
                                                                      
                                     
                                               
  void setMarkedForwardingPointer(CompressedPointer cell) {
    forwardingPointer_ = CompressedPointer::fromRaw(cell.getRaw() | 0x1);
  }

                                                                     
                                               
                                                  
                                               
  CompressedPointer getMarkedForwardingPointer() const {
    assert(isMarked());
    return CompressedPointer::fromRaw(forwardingPointer_.getRaw() - 0x1);
  }

                                                                        
                                 
  bool hasMarkedForwardingPointer() const {
    return isMarked();
  }

  const GCCell *nextCell() const {
    return reinterpret_cast<const GCCell *>(
        reinterpret_cast<const char *>(this) + getAllocatedSize());
  }
  GCCell *nextCell() {
    return reinterpret_cast<GCCell *>(
        reinterpret_cast<char *>(this) + getAllocatedSize());
  }

                                         
     
                             
                                             
                                                                         
  bool isValid() const {
#ifndef NDEBUG
                                                              
    return magic_ == kMagic && kindAndSize_.getVT()->isValid();
#else
    return kindAndSize_.getVT()->isValid();
#endif
  }

                                                                    
                                       
  bool isValid(CellKind expectedKind) const {
    return kindAndSize_.getVT()->isValid(expectedKind);
  }

                   
  static void *operator new(size_t, void *p) {
    return p;
  }

                                          
  static void *operator new(size_t) = delete;
  static void operator delete(void *) = delete;

                                                                           
                        
  uint64_t getDebugAllocationId() const {
#ifndef NDEBUG
    return _debugAllocationId_;
#else
    return 0;
#endif
  }

#ifndef NDEBUG
  void setDebugAllocationIdInGC(uint32_t id) {
    _debugAllocationId_ = id;
  }
#endif

                                                 
  bool isMarked() const {
    return forwardingPointer_.getRaw() & 0x1;
  }

  static constexpr uint32_t maxSize() {
    return KindAndSize::maxSize();
  }
};

                                                                         
                                                         
                                                                   
class VariableSizeRuntimeCell : public GCCell {
 public:
  uint32_t getSize() const {
    return getAllocatedSize();
  }

                                                    
                                                                           
                                      
  void setSizeFromGC(uint32_t sz) {
    assert(
        isVariableSize() &&
        "Cannot call setSizeFromGC on a non-variable size cell");
    assert(
        sz >= sizeof(VariableSizeRuntimeCell) &&
        "Should not allocate a VariableSizeRuntimeCell of size less than "
        "the size of a cell");
    setKindAndSize(KindAndSize{getKind(), sz});
  }
};

static_assert(
    alignof(GCCell) <= HeapAlign,
    "GCCell's alignment exceeds the alignment requirement of the heap");

#ifdef NDEBUG
static_assert(
    sizeof(GCCell) == sizeof(CompressedPointer) &&
        sizeof(VariableSizeRuntimeCell) == sizeof(CompressedPointer),
    "Cell metadata should only be the size of a single pointer.");
#endif

static const char kInvalidHeapValue = (char)0xcc;

}                
}                    
#pragma GCC diagnostic pop

#endif                      

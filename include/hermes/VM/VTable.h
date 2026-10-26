/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_VTABLE_H
#define HERMES_VM_VTABLE_H

#include "hermes/VM/CellKind.h"
#include "hermes/VM/GCDecl.h"
#include "hermes/VM/HeapAlign.h"
#include "hermes/VM/HeapSnapshot.h"
#include "hermes/VM/PointerBase.h"
#include "hermes/VM/SlotAcceptor.h"

#include "llvh/Support/raw_ostream.h"

#include <cstdint>

#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

                        
class GCCell;

                                                                  
                                                                      
                                                  
struct VTable {
#ifdef HERMES_MEMORY_INSTRUMENTATION
  class HeapSnapshotMetadata final {
   private:
    using NameCallback = std::string(GCCell *, GC &);
    using AddEdgesCallback = void(GCCell *, GC &, HeapSnapshot &);
    using AddNodesCallback = void(GCCell *, GC &, HeapSnapshot &);
    using AddLocationsCallback = void(GCCell *, GC &, HeapSnapshot &);

   public:
                                                                              
                                                                  
       
                                                                                
                                                                             
                                                      
                                                                                
                                                                                
                                                                            
                             
                                                                              
                                                                    
                                                                          
                                                                               
                
    constexpr explicit HeapSnapshotMetadata(
        HeapSnapshot::NodeType nodeType,
        NameCallback *name,
        AddEdgesCallback *addEdges,
        AddNodesCallback *addNodes,
        AddLocationsCallback *addLocations)
        : nodeType_(nodeType),
          name_(name),
          addEdges_(addEdges),
          addNodes_(addNodes),
          addLocations_(addLocations) {}

    HeapSnapshot::NodeType nodeType() const {
      return nodeType_;
    }
    std::string nameForNode(GCCell *cell, GC &gc) const;
                                                                       
    std::string defaultNameForNode(GCCell *cell) const;
    void addEdges(GCCell *cell, GC &gc, HeapSnapshot &snap) const;
    void addNodes(GCCell *cell, GC &gc, HeapSnapshot &snap) const;
    void addLocations(GCCell *cell, GC &gc, HeapSnapshot &snap) const;

   private:
    const HeapSnapshot::NodeType nodeType_;
    NameCallback *const name_;
    AddEdgesCallback *const addEdges_;
    AddNodesCallback *const addNodes_;
    AddLocationsCallback *const addLocations_;
  };
#endif                                           

                                                                             
                   
                          
                                                                            
                   
  static constexpr uint64_t kMagic{0xff57ab1eff57ab1e};
                                                                          
                                                                                
                                                                               
                                                                         
                                                                           
                     
                                                                    
                            
  const uint64_t magic_{kMagic};
                    
  const CellKind kind;
                                                                         
                     
                                                          
                              
  const uint32_t size;
                                                                               
                                                                       
                                                                              
            
  using FinalizeCallback = void(GCCell *, GC &gc);
  FinalizeCallback *const finalize_;
                                                                            
                                                                          
  using MallocSizeCallback = size_t(GCCell *);
  MallocSizeCallback *const mallocSize_;
                                                       
                                      
  using TrimSizeCallback = gcheapsize_t(const GCCell *);
  TrimSizeCallback *const trimSize_;

#ifdef HERMES_MEMORY_INSTRUMENTATION
                                                  
  const HeapSnapshotMetadata snapshotMetaData;
#endif

                                                                             
                                        
  static std::array<const VTable *, kNumCellKinds> vtableArray;

  static const VTable *getVTable(CellKind c) {
    return vtableArray[static_cast<size_t>(c)];
  }

  constexpr explicit VTable(
      CellKind kind,
      uint32_t size,
      FinalizeCallback *finalize = nullptr,
      MallocSizeCallback *mallocSize = nullptr,
      TrimSizeCallback *trimSize = nullptr
#ifdef HERMES_MEMORY_INSTRUMENTATION
      ,
      HeapSnapshotMetadata snapshotMetaData =
          HeapSnapshotMetadata{
              HeapSnapshot::NodeType::Object,
              nullptr,
              nullptr,
              nullptr,
              nullptr}
#endif
      )
      : kind(kind),
        size(heapAlignSize(size)),
        finalize_(finalize),
        mallocSize_(mallocSize),
        trimSize_(trimSize)
#ifdef HERMES_MEMORY_INSTRUMENTATION
        ,
        snapshotMetaData(snapshotMetaData)
#endif
  {
  }

  bool isVariableSize() const {
    return size == 0;
  }

  void finalizeIfExists(GCCell *cell, GC &gc) const {
    assert(isValid());
    if (finalize_) {
      finalize_(cell, gc);
    }
  }

  void finalize(GCCell *cell, GC &gc) const {
    assert(isValid());
    assert(
        finalize_ &&
        "Cannot unconditionally finalize if it doesn't have a finalize pointer");
    finalize_(cell, gc);
  }

  size_t getMallocSize(GCCell *cell) const {
    assert(isValid());
    return mallocSize_ ? mallocSize_(cell) : 0;
  }

                                                                       
                                              
  gcheapsize_t getTrimmedSize(GCCell *cell, size_t origSize) const {
    const size_t trimmedSize =
        trimSize_ ? heapAlignSize(trimSize_(cell)) : origSize;
    assert(
        isValid() && trimmedSize <= origSize &&
        "Growing objects is not supported.");
    return trimmedSize;
  }

                                            
                             
                                                  
                                                               
  bool isValid() const {
    return magic_ == kMagic && isSizeHeapAligned(size) &&
        kindInRange(
               kind, CellKind::AllCellsKind_first, CellKind::AllCellsKind_last);
  }

                                                                            
                            
  bool isValid(CellKind expectedKind) const {
    return magic_ == kMagic && isSizeHeapAligned(size) && kind == expectedKind;
  }
};

llvh::raw_ostream &operator<<(llvh::raw_ostream &os, const VTable &vt);

}                
}                    
#pragma GCC diagnostic pop

#endif                      

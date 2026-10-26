/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_IDENTIFIERTABLE_H
#define HERMES_VM_IDENTIFIERTABLE_H

#include "hermes/ADT/PtrOrInt.h"
#include "hermes/Support/HashString.h"
#include "hermes/VM/CallResult.h"
#include "hermes/VM/GC.h"
#include "hermes/VM/Handle.h"
#include "hermes/VM/StringRefUtils.h"
#include "hermes/VM/SymbolID.h"
#include "hermes/VM/detail/IdentifierHashTable.h"

#include <functional>
#include <mutex>
#include <vector>

#include "llvh/ADT/BitVector.h"
#include "llvh/ADT/DenseMap.h"
#pragma GCC diagnostic push

#ifdef HERMES_COMPILER_SUPPORTS_WSHORTEN_64_TO_32
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#endif
namespace hermes {
namespace vm {

class Runtime;
class RuntimeModule;
class StringPrimitive;
class StringView;

                                                                   
                                                                           
                                
   
                                                                        
                                                                          
                                                             
                                                                              
                                    
   
                                                                                
             
   
                                                                            
                                                                
   
                                                                   
                                                                              
                                                                            
                                                                              
                                                                              
                                                                       
                                                                           
                                                                                
                  
   
                                                                           
                                                                            
                                                                        
                                                                      
                                                                  
   
                                                                             
                                          
class IdentifierTable {
  friend class detail::IdentifierHashTable;
  friend class HadesGC;

 public:
                                      
  IdentifierTable();

                                                                      
             
                                                                 
                                                             
                                                                           
                                                                          
  CallResult<Handle<SymbolID>>
  getSymbolHandle(Runtime &runtime, UTF16Ref str, uint32_t hash);
  CallResult<Handle<SymbolID>> getSymbolHandle(Runtime &runtime, UTF16Ref str) {
    return getSymbolHandle(runtime, str, hermes::hashString(str));
  }

                                                                      
             
  CallResult<Handle<SymbolID>>
  getSymbolHandle(Runtime &runtime, ASCIIRef str, uint32_t hash);
  CallResult<Handle<SymbolID>> getSymbolHandle(Runtime &runtime, ASCIIRef str) {
    return getSymbolHandle(runtime, str, hermes::hashString(str));
  }

                                                                              
                                                               
  StringPrimitive *getExistingStringPrimitiveOrNull(
      Runtime &runtime,
      llvh::ArrayRef<char16_t> str);

                                                                           
                                                                               
                     
  StringPrimitive *getExistingStringPrimitiveOrNullWithHash(
      Runtime &runtime,
      llvh::ArrayRef<char16_t> str,
      uint32_t hash);

                                                                              
                 
                                                                            
  SymbolID registerLazyIdentifier(ASCIIRef str);
  SymbolID registerLazyIdentifier(ASCIIRef str, uint32_t hash);

                                                                              
                 
  SymbolID registerLazyIdentifier(UTF16Ref str);
  SymbolID registerLazyIdentifier(UTF16Ref str, uint32_t hash);

                                                          
  CallResult<Handle<SymbolID>> getSymbolHandleFromPrimitive(
      Runtime &runtime,
      PseudoHandle<StringPrimitive> str);

                                                                    
                               
  StringPrimitive *getStringPrim(Runtime &runtime, SymbolID id);
  bool symbolDescriptionUndefined(SymbolID id) const {
    return lookupVector_[id.unsafeGetIndex()].symbolDescriptionUndefined_;
  }

                                                                          
                                    
  StringView getStringView(Runtime &runtime, SymbolID id) const;

                                                                                
  StringView getStringViewForDev(Runtime &runtime, SymbolID id) const;

                                                                       
                                                                            
                                           
  std::string convertSymbolToUTF8(SymbolID id);

                                                                             
  void reserve(uint32_t count) {
    lookupVector_.reserve(count);
    hashTable_.reserve(count);
    markedSymbols_.reserve(count);
  }

                                                                       
                      
  size_t additionalMemorySize() const {
    return lookupVector_.capacity() * sizeof(LookupEntry) +
        hashTable_.additionalMemorySize() + markedSymbols_.getMemorySize();
  }

                                                     
  void markIdentifiers(RootAcceptor &acceptor, GC &gc);

#ifdef HERMES_MEMORY_INSTRUMENTATION
                                                   
  void snapshotAddNodes(HeapSnapshot &snap);
  void snapshotAddEdges(HeapSnapshot &snap);
#endif

                                                                        
                                                                             
                                                                         
                                 
  void visitIdentifiers(
      const std::function<void(SymbolID, const StringPrimitive *)> &lambda);

                                                                              
                                                                        
                                                                  
  unsigned getSymbolsEnd() const {
    return lookupVector_.size();
  }

                                           
  void unmarkSymbols();

                                                              
  void freeUnmarkedSymbols(
      const llvh::BitVector &markedSymbols,
      GC::IDTracker &gc);

#ifdef HERMES_SLOW_DEBUG
                                                                        
                                                                               
                                
  bool isSymbolLive(SymbolID id) const;

                                                                            
           
  const StringPrimitive *getStringForSymbol(SymbolID id) const;
#endif

                                                            
                                                                             
                                                                            
                         
                                           
  SymbolID createNotUniquedLazySymbol(ASCIIRef desc);

                                                            
                                                
                                                            
                                           
  CallResult<SymbolID> createNotUniquedSymbol(
      Runtime &runtime,
      Handle<StringPrimitive> desc, bool descriptionUndefined = false);

 private:
                                                                           
                                                                       
                                                                  
                                   
                                                                       
                                                                      
                                  
                                                                     
                                                                        
                                                                     
                                                                       
                                                                         
                                        
                                                                          
                                                                      
                                                                         
                                                                   
  class LookupEntry {
    static constexpr uint32_t LAZY_STRING_PRIM_TAG = (uint32_t)(1 << 30) - 1;
    static constexpr uint32_t NON_LAZY_STRING_PRIM_TAG =
        LAZY_STRING_PRIM_TAG - 1;

   public:
    static constexpr uint32_t FREE_LIST_END = LAZY_STRING_PRIM_TAG;
    static constexpr uint32_t MAX_IDENTIFIER = NON_LAZY_STRING_PRIM_TAG - 1;

   private:
    union {
      StringPrimitive *strPrim_;
      const char *asciiPtr_;
      const char16_t *utf16Ptr_;
    };

                                                                        
                                                     
                                                                     
    bool isUTF16_ : 1;

                                                                         
    bool isNotUniqued_ : 1;

    uint32_t num_ : 30;

                                             
    uint32_t hash_{};

   public:
    explicit LookupEntry(ASCIIRef str, bool isNotUniqued = false)
        : asciiPtr_(str.data()),
          isUTF16_(false),
          isNotUniqued_(isNotUniqued),
          num_(str.size()),
          hash_(hermes::hashString(str)) {}
    explicit LookupEntry(ASCIIRef str, uint32_t hash, bool isNotUniqued = false)
        : asciiPtr_(str.data()),
          isUTF16_(false),
          isNotUniqued_(isNotUniqued),
          num_(str.size()),
          hash_(hash) {}
    explicit LookupEntry(UTF16Ref str)
        : utf16Ptr_(str.data()),
          isUTF16_(true),
          isNotUniqued_(false),
          num_(str.size()),
          hash_(hermes::hashString(str)) {}
    explicit LookupEntry(UTF16Ref str, uint32_t hash)
        : utf16Ptr_(str.data()),
          isUTF16_(true),
          isNotUniqued_(false),
          num_(str.size()),
          hash_(hash) {}
    explicit LookupEntry(StringPrimitive *str, bool isNotUniqued = false);
    explicit LookupEntry(
        StringPrimitive *str,
        uint32_t hash,
        bool isNotUniqued = false)
        : strPrim_(str),
          isUTF16_(true),
          isNotUniqued_(isNotUniqued),
          num_(NON_LAZY_STRING_PRIM_TAG),
          hash_(hash) {
      assert(str && "Invalid string primitive pointer");
    }

                                   
    LookupEntry() : strPrim_(nullptr), num_(FREE_LIST_END) {}

    bool isLazyASCII() const {
      return asciiPtr_ && !isUTF16_;
    }
    bool isLazyUTF16() const {
      return utf16Ptr_ && isUTF16_;
    }
    bool isStringPrim() const {
      return strPrim_ && num_ >= NON_LAZY_STRING_PRIM_TAG;
    }
    bool isLazyStringPrim() const {
      return strPrim_ && num_ == LAZY_STRING_PRIM_TAG;
    }
    bool isNonLazyStringPrim() const {
      return strPrim_ && num_ == NON_LAZY_STRING_PRIM_TAG;
    }
    bool isFreeSlot() const {
                                                                              
                                                                         
      return !strPrim_;
    }
    bool symbolDescriptionUndefined_{false};

    bool isNotUniqued() const {
      return isNotUniqued_;
    }

                                                           
    void materialize(StringPrimitive *str) {
      assert(str && "Invalid string primitive pointer");
      strPrim_ = str;
      num_ = LAZY_STRING_PRIM_TAG;
    }

                                                                   
    void free(int32_t nextFreeSlotID) {
      assert(isStringPrim() && "Cannot free this slot");
      strPrim_ = nullptr;
      num_ = nextFreeSlotID;
    }

    ASCIIRef getLazyASCIIRef() const {
      assert(isLazyASCII() && "Not an ASCII lazy identifier");
      return ASCIIRef(asciiPtr_, num_);
    }
    UTF16Ref getLazyUTF16Ref() const {
      assert(isLazyUTF16() && "Not a UTF16 lazy identifier");
      return UTF16Ref(utf16Ptr_, num_);
    }
    StringPrimitive *&getStringPrimRef() {
      assert(isStringPrim() && "Not a valid string primitive");
      return strPrim_;
    }
    const StringPrimitive *getStringPrim() const {
      assert(isStringPrim() && "Not a valid string primitive");
      return strPrim_;
    }

    int32_t getNextFreeSlot() const {
      assert(isFreeSlot() && "Not a free slot");
      return num_;
    }
    uint32_t getHash() const {
      return hash_;
    }
  };

                                                           
  template <typename T>
  class ConservativeVector : private std::vector<T> {
    using Base = std::vector<T>;

   public:
    using Base::Base;
    using Base::capacity;
    using Base::reserve;
    using Base::size;
    using Base::operator[];
    using Base::begin;
    using Base::end;
    using Base::resize;

    void emplace_back() {
      auto cap = capacity();
      if (size() == cap) {
        reserve(cap + cap / 4);
      }
      Base::emplace_back();
    }
  };
                                                                             
                                                                          
                                                                        
                                                            
  ConservativeVector<LookupEntry> lookupVector_;

                                                                             
  llvh::BitVector markedSymbols_;

                     
  detail::IdentifierHashTable hashTable_{};

                                                     
  uint32_t firstFreeID_{LookupEntry::FREE_LIST_END};

  LookupEntry &getLookupTableEntry(SymbolID id) {
    return getLookupTableEntry(id.unsafeGetIndex());
  }

  const LookupEntry &getLookupTableEntry(SymbolID id) const {
    return getLookupTableEntry(id.unsafeGetIndex());
  }

  LookupEntry &getLookupTableEntry(uint32_t id) {
    assert(id < lookupVector_.size() && "Identifier ID out of bound");
    return lookupVector_[id];
  }

  const LookupEntry &getLookupTableEntry(uint32_t id) const {
    assert(id < lookupVector_.size() && "Identifier ID out of bound");
    return lookupVector_[id];
  }

                                                                                
                         
  void symbolReadBarrier(uint32_t id);

                                                                             
                                            
                                                
                                                                            
                                            
                                                
                           
  template <typename T>
  CallResult<SymbolID> getOrCreateIdentifier(
      Runtime &runtime,
      llvh::ArrayRef<T> str,
      Handle<StringPrimitive> primHandle,
      uint32_t hash);
  template <typename T>
  CallResult<SymbolID> getOrCreateIdentifier(
      Runtime &runtime,
      llvh::ArrayRef<T> str,
      Handle<StringPrimitive> primHandle) {
    return getOrCreateIdentifier(
        runtime, str, primHandle, hermes::hashString(str));
  }

                                                          
  template <typename T>
  SymbolID registerLazyIdentifierImpl(llvh::ArrayRef<T> str, uint32_t hash);

                                                                          
                                                                 
  uint32_t allocIDAndInsert(uint32_t hashTableIndex, StringPrimitive *str);

                                                        
                                                                      
  void freeSymbol(uint32_t index);

                                                         
  uint32_t allocNextID();

                                     
  void freeID(uint32_t id);

                                                                             
                                                                          
                                                                    
                                                                  
                                                
                                                                            
                                            
                                       
  template <typename T, bool Unique = true>
  CallResult<PseudoHandle<StringPrimitive>> allocateDynamicString(
      Runtime &runtime,
      llvh::ArrayRef<T> str,
      Handle<StringPrimitive> primHandle);

                                                              
  StringPrimitive *materializeLazyIdentifier(Runtime &runtime, SymbolID id);
};

}                    
}                        
#pragma GCC diagnostic pop

#endif

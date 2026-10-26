/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_CARDTABLE_H
#define HERMES_VM_CARDTABLE_H

#include "hermes/Support/ErrorHandling.h"
#include "hermes/Support/OSCompat.h"
#include "hermes/Support/OptValue.h"
#include "hermes/VM/AlignedStorage.h"
#include "hermes/VM/ExpectedPageSize.h"
#include "hermes/VM/GCCell.h"
#include "hermes/VM/PointerBase.h"

#include "llvh/Support/MathExtras.h"

#include <cassert>

namespace hermes {
namespace vm {

                                                                               
                                                                               
                                                                              
                                                                         
           
   
                                                                                
                                                                           
                                                                              
                                                                                
                                                         
class CardTable {
 public:
                                    
  class Boundary {
    friend class CardTable;

   public:
    Boundary() = default;

                                                              
    inline void bump();

                                                                              
                     
    inline size_t index() const;

                                                  
    inline const char *address() const;

   private:
    inline Boundary(size_t index, const char *address);

    size_t index_{0};
    const char *address_{nullptr};
  };

                                                                              
  static constexpr size_t kLogCardSize = 9;                       
  static constexpr size_t kCardSize = 1 << kLogCardSize;                       

                                                      
  static constexpr size_t kValidIndices =
      AlignedStorage::size() >> kLogCardSize;

                                 
  static constexpr size_t kCardTableSize = kValidIndices;

                                                                              
                                                                        
                                                                        
                                                                              
                                                                            
                                          
  static constexpr size_t kHeapBytesPerCardByte = kCardSize;

                                                            
                                                                   
                                                                      
                                                                      
                                                                     
                                                                     
                                                                   
                                                          
                                                            
                                                           
                                                           
                                                                     
                                          
  static constexpr size_t kFirstUsedIndex =
      (2 * kCardTableSize) >> kLogCardSize;

  CardTable() = default;
                                                                            
  CardTable(const CardTable &) = delete;
  CardTable(CardTable &&) = delete;
  CardTable &operator=(const CardTable &) = delete;
  CardTable &operator=(CardTable &&) = delete;

                                                                                
                                                                            
                                                      
     
                                                               
     
                                                                              
                                                                            
                                                                               
                          
  inline size_t addressToIndex(const void *addr) const LLVM_NO_SANITIZE("null");

                                                               
            
     
                               
     
                                     
  inline const char *indexToAddress(size_t index) const;

                                                            
                                                                          
  inline void dirtyCardForAddress(const void *addr);

                                                                            
                                                               
                                                                              
            
  void dirtyCardsForAddressRange(const void *low, const void *high);

                                                                          
                                                                          
  inline bool isCardForAddressDirty(const void *addr) const;

                                                                        
                                                               
  inline bool isCardForIndexDirty(const size_t index) const;

                                                                              
                                                                          
  inline OptValue<size_t> findNextDirtyCard(size_t fromIndex, size_t endIndex)
      const;

                                                                             
                                                                          
  inline OptValue<size_t> findNextCleanCard(size_t fromIndex, size_t endIndex)
      const;

                                                                          
                                      
  inline Boundary nextBoundary(const char *level) const;

                            
  void clear();

                                                                             
                                                                               
                                                                              
                                                                           
                            
     
                                                                          
                          
  void updateAfterCompaction(const void *newLevel);

                                                                           
                                                                           
     
                                
                                                      
                                                                         
                                             
     
                                                                         
                                   
     
                                          
  void updateBoundaries(Boundary *boundary, const char *start, const char *end);

                                                                              
                                                                                
                           
  GCCell *firstObjForCard(unsigned index) const;

#ifdef HERMES_EXTRA_DEBUG
                                                                                
                             
                                                                 
  int8_t cardObjectTableValue(unsigned index) const {
    return boundaries_[index];
  }

                                                                   
                                                                    
                                                                    
                                
                                                                 
  void protectBoundaryTable();
  void unprotectBoundaryTable();
#endif                      

#ifdef HERMES_SLOW_DEBUG
                                                                             
                              
     
                   
                                                                                
                   
     
                                 
  void verifyBoundaries(char *start, char *level) const;
#endif                     

 private:
  enum class CardStatus : char { Clean = 0, Dirty = 1 };

                                                                              
                                        
     
                                     
     
                                                                       
                                                                                
                         
  inline const char *base() const LLVM_NO_SANITIZE("null");

                                                                              
                                                                                
                                            
  static inline int8_t encodeExp(int8_t exp);
  static inline int8_t decodeExp(int8_t encodedVal);

                                           
  static inline bool isCardAligned(const void *ptr);

                                                                            
                                                          
  OptValue<size_t> findNextCardWithStatus(
      CardStatus status,
      size_t fromIndex,
      size_t endIndex) const;

                                                                    
                                       
  void cleanRange(size_t from, size_t to);
  void dirtyRange(size_t from, size_t to);

  void cleanOrDirtyRange(size_t from, size_t to, CardStatus cleanOrDirty);

                                                                               
                                  
  std::array<AtomicIfConcurrentGC<CardStatus>, kCardTableSize> cards_{};

                                                                       
                
  static_assert(
      sizeof(cards_[0]) == 1,
      "Validate assumption that card table entries are one byte");

                                                                            
                                                                          
                                                                        
                                                                               
                  
     
                                                                               
                                                                             
                                                                               
                                                                       
  int8_t boundaries_[kCardTableSize];
};

                               
inline void CardTable::Boundary::bump() {
  index_++;
  address_ += kCardSize;
}

inline size_t CardTable::Boundary::index() const {
  return index_;
}

inline const char *CardTable::Boundary::address() const {
  return address_;
}

inline CardTable::Boundary::Boundary(size_t index, const char *address)
    : index_(index), address_(address) {}

inline size_t CardTable::addressToIndex(const void *addr) const {
  auto addrPtr = reinterpret_cast<const char *>(addr);
  assert(
      base() <= addrPtr &&
      addrPtr < (static_cast<const char *>(AlignedStorage::end(base())) +
                 kCardSize) &&
      "address is required to be within range.");
  return (addrPtr - base()) >> kLogCardSize;
}

inline const char *CardTable::indexToAddress(size_t index) const {
  assert(index <= kValidIndices && "index must be within the index range");
  const char *res = base() + (index << kLogCardSize);
  assert(
      base() <= res && res <= AlignedStorage::end(base()) &&
      "result must be within the covered range");
  return res;
}

inline void CardTable::dirtyCardForAddress(const void *addr) {
  cards_[addressToIndex(addr)].store(
      CardStatus::Dirty, std::memory_order_relaxed);
}

inline bool CardTable::isCardForAddressDirty(const void *addr) const {
  return isCardForIndexDirty(addressToIndex(addr));
}

inline bool CardTable::isCardForIndexDirty(size_t index) const {
  assert(index < kValidIndices && "index is required to be in range.");
  return cards_[index].load(std::memory_order_relaxed) == CardStatus::Dirty;
}

inline OptValue<size_t> CardTable::findNextDirtyCard(
    size_t fromIndex,
    size_t endIndex) const {
  return findNextCardWithStatus(CardStatus::Dirty, fromIndex, endIndex);
}

inline OptValue<size_t> CardTable::findNextCleanCard(
    size_t fromIndex,
    size_t endIndex) const {
  return findNextCardWithStatus(CardStatus::Clean, fromIndex, endIndex);
}

inline CardTable::Boundary CardTable::nextBoundary(const char *level) const {
  assert(level != nullptr);
  size_t ix = addressToIndex(level - 1) + 1;
  const char *addr = indexToAddress(ix);

  return {ix, addr};
}

inline const char *CardTable::base() const {
                                                                              
                                                                             
             
  return reinterpret_cast<const char *>(this);
}

             inline int8_t CardTable::encodeExp(int8_t exp) {
  return -(exp + 1);
}

             inline int8_t CardTable::decodeExp(int8_t encodedVal) {
  return -encodedVal - 1;
}

             inline bool CardTable::isCardAligned(const void *ptr) {
  return (reinterpret_cast<intptr_t>(ptr) & (kCardSize - 1)) == 0;
}

}                
}                    

#endif                         

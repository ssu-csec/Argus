/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_BCGEN_REGALLOC_H
#define HERMES_BCGEN_REGALLOC_H

#include "hermes/IR/IR.h"
#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/BitVector.h"
#include "llvh/ADT/DenseMap.h"
#include "llvh/ADT/DenseSet.h"

namespace hermes {

using llvh::ArrayRef;
using llvh::BitVector;
using llvh::DenseMap;

                                                                            
                                                                             
                              
class Register {
                                     
  static const unsigned InvalidRegister = ~0u;
  static const unsigned TombstoneRegister = ~0u - 1;

 public:
  explicit Register(unsigned val = InvalidRegister) : value(val) {}

                                              
  bool isValid() const {
    return value != InvalidRegister;
  }

                                                 
  unsigned getIndex() const {
    return value;
  }

                                         
  static Register getTombstoneKey() {
    return Register(TombstoneRegister);
  }

 private:
                                         
  unsigned value;

 public:
  bool operator==(Register RHS) const {
    return value == RHS.value;
  }
  bool operator!=(Register RHS) const {
    return !(*this == RHS);
  }

                                                                   
                                     
  bool isConsecutive(Register RHS) const {
    return getIndex() + 1 == RHS.getIndex();
  }

                                                                       
  Register getConsecutive(unsigned count = 1) {
    return Register(getIndex() + count);
  }

  static bool compare(const Register &a, const Register &b) {
    return a.getIndex() < b.getIndex();
  }
};

                                                                            
                                                      
class RegisterFile {
                                                                           
                                                                                
                                                                                
                                          
  llvh::BitVector registers;

 public:
  RegisterFile(const RegisterFile &) = delete;
  void operator=(const RegisterFile &) = delete;
  RegisterFile() = default;

                                               
  bool isUsed(Register r);

                                               
  bool isFree(Register r);

                                                  
  Register allocateRegister();

                                                                          
                                                                                
  Register tailAllocateConsecutive(unsigned n);

                                                                       
  void killRegister(Register reg);

                                                           
  unsigned getNumLiveRegisters() {
    return registers.size() - registers.count();
  }

                                                              
  unsigned getMaxRegisterUsage() {
    return registers.size();
  }

                                                     
  void verify();

                                          
  void dump();
};

class Function;
class Instruction;
class ScopeCreationInst;
class PhiInst;
class CallInst;

                                                                              
                              
struct Segment {
  size_t start_;
  size_t end_;

  explicit Segment(size_t start, size_t end) : start_(start), end_(end) {
    assert(end_ >= start_ && "invalid segment range");
  }

                                                   
  size_t size() const {
    return end_ - start_;
  }

                                             
  size_t empty() const {
    return size() == 0;
  }

                                                                          
  bool contains(size_t loc) const {
    return loc < end_ && loc >= start_;
  }

                                                                        
  bool intersects(Segment other) const {
    return !(other.start_ >= end_ || start_ >= other.end_);
  }

                                                                
  bool touches(Segment other) const {
    return other.start_ == end_ || start_ == other.end_;
  }

                                                                     
  void merge(Segment other) {
    assert(
        (intersects(other) || touches(other)) &&
        "merging non overlapping segment");
    start_ = std::min(start_, other.start_);
    end_ = std::max(end_, other.end_);
  }
};

                                                                              
          
struct Interval {
  llvh::SmallVector<Segment, 2> segments_;

  explicit Interval() = default;

  explicit Interval(size_t start, size_t end) {
    add(Segment(start, end));
  }

                                                        
  bool intersects(Segment other) const {
    for (auto &s : segments_) {
      if (s.intersects(other))
        return true;
    }
    return false;
  }

                                                        
  bool intersects(const Interval &other) const {
    Segment a(start(), end());
    Segment b(other.start(), other.end());
    return a.intersects(b);
  }

                                                                     
  void add(const Interval &other) {
    for (auto &S : other.segments_) {
      add(S);
    }
  }

                                                                    
  void add(Segment other) {
    for (auto &s : segments_) {
      if (s.intersects(other) || s.touches(other)) {
        s.merge(other);
        return;
      }
    }
    segments_.push_back(other);
  }

                                         
  Interval compress() const {
    Interval t;
    for (auto &s : segments_) {
      t.add(s);
    }
    return t;
  }

                                                    
  size_t size() const {
    if (segments_.size())
      return end() - start();

    return 0;
  }

  size_t start() const {
    assert(segments_.size() && "No segments in interval!");
    size_t start = segments_[0].start_;
    for (auto &S : segments_) {
      start = std::min(start, S.start_);
    }
    return start;
  }

  size_t end() const {
    assert(segments_.size() && "No segments in interval!");
    size_t start = segments_[0].end_;
    for (auto &S : segments_) {
      start = std::max(start, S.end_);
    }
    return start;
  }
};

                                                                            
              
class RegisterAllocator {
                                                 
  struct BlockLifetimeInfo {
    BlockLifetimeInfo() = default;
    void init(unsigned size) {
      gen_.resize(size);
      kill_.resize(size);
      liveIn_.resize(size);
      liveOut_.resize(size);
      maskIn_.resize(size);
    }
                                                 
    BitVector gen_;
                                                    
    BitVector kill_;
                                                                         
    BitVector liveIn_;
                                                                           
    BitVector liveOut_;
                                                                               
                                                                            
                                                                              
                 
    BitVector maskIn_;
  };

                                                       
  llvh::DenseMap<BasicBlock *, BlockLifetimeInfo> blockLiveness_;

                                         
  llvh::DenseMap<Instruction *, unsigned> instructionNumbers_;
                                           
  llvh::SmallVector<Instruction *, 32> instructionsByNumbers_;
                                                  
  llvh::SmallVector<Interval, 32> instructionInterval_;

                                       
  unsigned getMaxInstrIndex() {
    return instructionsByNumbers_.size();
  }

                                                                           
  void calculateLocalLiveness(BlockLifetimeInfo &livenessInfo, BasicBlock *BB);

                                                             
  void calculateGlobalLiveness(ArrayRef<BasicBlock *> order);

                                                         
  void calculateLiveIntervals(ArrayRef<BasicBlock *> order);

                                                                               
                                                                              
                                                                        
                                  
                                                          
  void coalesce(
      DenseMap<Instruction *, Instruction *> &map,
      ArrayRef<BasicBlock *> order);

 protected:
                                                  
  llvh::DenseMap<Value *, Register> allocated{};

                        
  RegisterFile file{};

                                                                 
                                                                    
  unsigned fastPassThreshold = 0;

                                                                         
                                                                         
                       
  uint64_t memoryLimit = -1;

                                                                               
                                    
  void allocateFastPass(ArrayRef<BasicBlock *> order);

  Function *F;

 public:
                                                         
  void dump();

                                                                   
  Interval &getInstructionInterval(Instruction *I);

                                                                                
                                                                
  Register getRegisterForInstructionAt(Instruction *Value, Instruction *At);

  explicit RegisterAllocator(Function *func) : F(func) {}

  virtual ~RegisterAllocator() = default;

  Context &getContext() {
    return F->getContext();
  }

  void setFastPassThreshold(unsigned maxInstCount) {
    fastPassThreshold = maxInstCount;
  }

  void setMemoryLimit(uint64_t memoryLimitInBytes) {
    memoryLimit = memoryLimitInBytes;
  }

                                             
  unsigned getInstructionNumber(Instruction *I);

                                                               
  bool hasInstructionNumber(Instruction *I);

                                                                  
  virtual bool hasTargetSpecificLowering(Instruction *I) {
    return false;
  }

                                                                   
  bool isManuallyAllocatedInterval(Instruction *I);

                                                 
  virtual void handleInstruction(Instruction *I) {}

                                                                       
                         
  void lowerPhis(ArrayRef<BasicBlock *> order);

                                                                             
                                                                             
                                
  void allocate(ArrayRef<BasicBlock *> order);

                                                                               
                                                                         
                                                                       
                                                  
  Register reserve(ArrayRef<Value *> values);

                                                                            
  Register reserve(unsigned count = 1);

                                                        
  void free(Register reg);

                                                        
  Register getRegister(Value *I);

                                                    
  void updateRegister(Value *I, Register R);

                                                        
  bool isAllocated(Value *I);

                                                                          
                                                                      
                                                                        
                                                                       
  virtual unsigned getMaxRegisterUsage() {
    return file.getMaxRegisterUsage();
  }
};

                                                                            
                                                                               
   
                            
                               
                               
                       
                       
   
                                                       
                                         
                                         
                                         
                                                       
   
                                                                              
                                                        
                                                                           
                                                                             
                                                                                
                                             
class ScopeRegisterAnalysis {
  ScopeRegisterAnalysis(const ScopeRegisterAnalysis &) = delete;
  void operator=(const ScopeRegisterAnalysis &) = delete;

 public:
                                                                         
                                                                             
                
  explicit ScopeRegisterAnalysis(Function *F, RegisterAllocator &RA);

                                                                            
                                                                               
                                                                           
                                                                   
                                                     
  std::pair<Register, ScopeDesc *> registerAndScopeForInstruction(
      Instruction *Inst);

 private:
                                                                            
                                                                             
                                                                         
                                                                   
                                                     
  std::pair<Register, ScopeDesc *> registerAndScopeAt(
      Instruction *Inst,
      ScopeCreationInst *SCI);

  RegisterAllocator &RA_;
  llvh::DenseMap<ScopeDesc *, ScopeCreationInst *> scopeCreationInsts_;
};

}                    

namespace llvh {
class raw_ostream;

                                              
raw_ostream &operator<<(raw_ostream &OS, const hermes::Register &reg);
raw_ostream &operator<<(raw_ostream &OS, const hermes::Interval &interval);
raw_ostream &operator<<(raw_ostream &OS, const hermes::Segment &segment);
template <>
struct DenseMapInfo<hermes::Register> {
  static inline hermes::Register getEmptyKey() {
    return hermes::Register();
  }
  static inline hermes::Register getTombstoneKey() {
    return hermes::Register::getTombstoneKey();
  }
  static unsigned getHashValue(hermes::Register Val);
  static bool isEqual(hermes::Register LHS, hermes::Register RHS);
};

}                  

#endif

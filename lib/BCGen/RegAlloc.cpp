/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/BCGen/RegAlloc.h"
#include "hermes/IR/CFG.h"
#include "hermes/IR/IR.h"
#include "hermes/IR/IRBuilder.h"
#include "hermes/IR/Instrs.h"
#include "hermes/Support/PerfSection.h"
#include "hermes/Utils/Dumper.h"

#include "llvh/Support/Debug.h"
#include "llvh/Support/raw_ostream.h"

#include <algorithm>
#include <queue>

#define DEBUG_TYPE "regalloc"

using namespace hermes;

using llvh::dbgs;

raw_ostream &llvh::operator<<(raw_ostream &OS, const Register &reg) {
  if (!reg.isValid()) {
    OS << "Null";
  } else {
    OS << "Reg" << reg.getIndex();
  }

  return OS;
}

raw_ostream &llvh::operator<<(raw_ostream &OS, const Segment &segment) {
  if (segment.empty()) {
    OS << "[empty]";
    return OS;
  }

  OS << "[" << segment.start_ << "..." << segment.end_ << ") ";
  return OS;
}

raw_ostream &llvh::operator<<(raw_ostream &OS, const Interval &interval) {
  Interval t = interval.compress();
  for (auto &s : t.segments_) {
    OS << s;
  }
  return OS;
}

bool RegisterFile::isUsed(Register r) {
  return !registers.test(r.getIndex());
}

bool RegisterFile::isFree(Register r) {
  return !isUsed(r);
}

void RegisterFile::killRegister(Register reg) {
  LLVM_DEBUG(dbgs() << "-- Releasing the register " << reg << "\n");

  assert(isUsed(reg) && "Killing an unused register!");
  registers.set(reg.getIndex());
  assert(isFree(reg) && "Error freeing register!");
}

void RegisterFile::verify() {}

void RegisterFile::dump() {
  llvh::outs() << "\n";
  for (unsigned i = 0; i < registers.size(); i++) {
    llvh::outs() << (int)!registers.test(i);
  }
  llvh::outs() << "\n";
}

Register RegisterFile::allocateRegister() {
                                                                                
                                                                            
          
  if (registers.none()) {
                                                                
    unsigned numRegs = registers.size();
    registers.resize(numRegs + 1, false);
    Register R = Register(numRegs);
    assert(isUsed(R) && "Error allocating a new register.");
    LLVM_DEBUG(dbgs() << "-- Creating the new register " << R << "\n");
    return R;
  }

                                       
  int i = registers.find_first();
  assert(i >= 0 && "Unexpected failure to allocate a register");
  Register R(i);
  LLVM_DEBUG(dbgs() << "-- Assigning the free register " << R << "\n");
  assert(isFree(R) && "Error finding a free register");
  registers.reset(i);
  return R;
}

Register RegisterFile::tailAllocateConsecutive(unsigned n) {
  assert(n > 0 && "Can't request zero registers");

  int lastUsed = registers.size() - 1;
  while (lastUsed >= 0) {
    if (!registers.test(lastUsed))
      break;

    lastUsed--;
  }

  int firstClear = lastUsed + 1;

  LLVM_DEBUG(
      dbgs() << "-- Found the last set bit at offset " << lastUsed << "\n");
  registers.resize(std::max(registers.size(), firstClear + n), true);
  registers.reset(firstClear, firstClear + n);

  LLVM_DEBUG(
      dbgs() << "-- Allocated tail consecutive registers of length " << n
             << ", starting at " << Register(firstClear) << "\n");
  return Register(firstClear);
}

                                                                       
                                      
static bool phiReadWrite(PhiInst *P) {
  bool localPhiUse = false;
  bool externalUse = false;
  bool terminatorUse = false;

  BasicBlock *parent = P->getParent();

  for (auto *U : P->getUsers()) {
    terminatorUse |= llvh::isa<TerminatorInst>(U);
    localPhiUse |=
        (llvh::isa<PhiInst>(U) && U->getParent() == parent && P != U);
    externalUse |= U->getParent() != parent;
  }

                                                                             
                                                   
                             
                                                                               
      
                                   
                                                                
      
                                                                        

  return terminatorUse || localPhiUse || externalUse;
}

void RegisterAllocator::lowerPhis(ArrayRef<BasicBlock *> order) {
  llvh::SmallVector<PhiInst *, 8> PHIs;
  IRBuilder builder(F);

                      
  for (auto &BB : order) {
    for (auto &Inst : *BB) {
      if (auto *P = llvh::dyn_cast<PhiInst>(&Inst)) {
        PHIs.push_back(P);
      }
    }
  }

                                                                               
                                                                             
                                                                                
                                                                                
                                                                             
                                                         
  for (PhiInst *P : PHIs) {
    if (!phiReadWrite(P))
      continue;

                                                           
    builder.setInsertionPoint(P->getParent()->getTerminator());
    auto *mov = builder.createMovInst(P);

    Value::UseListTy users = P->getUsers();
                                 
    for (auto *U : users) {
                                           
      if (!llvh::isa<PhiInst>(U) && !llvh::isa<TerminatorInst>(U) &&
          U->getParent() == P->getParent())
        continue;

      U->replaceFirstOperandWith(P, mov);
    }
  }

                                                                          
                                            
  DenseMap<Value *, MovInst *> copied;

                                                                           
  for (PhiInst *P : PHIs) {
    for (unsigned i = 0, e = P->getNumEntries(); i < e; ++i) {
      auto E = P->getEntry(i);
      auto *term = E.second->getTerminator();
      builder.setInsertionPoint(term);
      auto *mov = builder.createMovInst(E.first);
      P->updateEntry(i, mov, E.second);

                                                                               
                                                                              
                                                                               
                                                                          
      copied[E.first] = mov;
    }
  }

                                                                          
                       
  for (auto &BB : order) {
    auto *term = BB->getTerminator();

    for (int i = 0, e = term->getNumOperands(); i < e; i++) {
      auto *op = term->getOperand(i);
      if (llvh::isa<Literal>(op))
        continue;
      auto it = copied.find(op);
      if (it != copied.end()) {
        if (it->second->getParent() == BB) {
          term->setOperand(it->second, i);
          it->second->moveBefore(term);
        }
      }
    }
  }
}

void RegisterAllocator::calculateLocalLiveness(
    BlockLifetimeInfo &livenessInfo,
    BasicBlock *BB) {
                                       
  for (auto &it : *BB) {
    Instruction *I = &it;

    unsigned idx = getInstructionNumber(I);
    livenessInfo.kill_.set(idx);

                                                                               
                                                                  
    if (auto *P = llvh::dyn_cast<PhiInst>(I)) {
      llvh::SmallVector<unsigned, 4> incomingValueNum;

                                            
      for (int i = 0, e = P->getNumEntries(); i < e; i++) {
        auto E = P->getEntry(i);
                                         
        if (!blockLiveness_.count(E.second))
          continue;
        if (auto *II = llvh::dyn_cast<Instruction>(E.first)) {
          incomingValueNum.push_back(getInstructionNumber(II));
        }
      }

                                                                      
      for (int i = 0, e = P->getNumEntries(); i < e; i++) {
        auto E = P->getEntry(i);
                                         
        if (!blockLiveness_.count(E.second))
          continue;
        for (auto num : incomingValueNum) {
          blockLiveness_[E.second].maskIn_.set(num);
        }
      }

                                                                  
      for (int i = 0, e = P->getNumEntries(); i < e; i++) {
        auto E = P->getEntry(i);
                                         
        if (!blockLiveness_.count(E.second))
          continue;
        if (auto *II = llvh::dyn_cast<Instruction>(E.first)) {
          unsigned idxII = getInstructionNumber(II);
          blockLiveness_[E.second].maskIn_.reset(idxII);
        }
      }
    }

                                                               
    for (unsigned opIdx = 0, e = I->getNumOperands(); opIdx != e; ++opIdx) {
      auto *opInst = llvh::dyn_cast<Instruction>(I->getOperand(opIdx));
      if (!opInst)
        continue;
                                                   
      if (!blockLiveness_.count(opInst->getParent()))
        continue;

                                      
      auto opInstIdx = getInstructionNumber(opInst);
      livenessInfo.gen_.set(opInstIdx);
    }
  }
}

#ifndef NDEBUG
static void dumpVector(
    const BitVector &bv,
    llvh::StringRef text,
    llvh::raw_ostream &ost = llvh::errs()) {
  ost << text;
  for (unsigned i = 0; i < bv.size(); i++) {
    ost << bv.test(i);
  }
  ost << "\n";
}
#endif

void RegisterAllocator::calculateGlobalLiveness(ArrayRef<BasicBlock *> order) {
  unsigned iterations = 0;
  bool changed = false;

                                            
  for (auto &it : blockLiveness_) {
    BlockLifetimeInfo &livenessInfo = it.second;
    livenessInfo.liveIn_ |= livenessInfo.gen_;
    livenessInfo.liveIn_.reset(livenessInfo.kill_);
    livenessInfo.liveIn_.reset(livenessInfo.maskIn_);
  }

  do {
    iterations++;
    changed = false;

    for (auto it = order.rbegin(), e = order.rend(); it != e; it++) {
      BasicBlock *BB = *it;
      BlockLifetimeInfo &livenessInfo = blockLiveness_[BB];

                                              
      for (auto *succ : successors(BB)) {
        BlockLifetimeInfo &succInfo = blockLiveness_[succ];
                                                                       
        if (succInfo.liveIn_.test(livenessInfo.liveOut_)) {
          changed = true;
        }

        livenessInfo.liveOut_ |= succInfo.liveIn_;
      }

                                      
                                                                               
                                                                               
      livenessInfo.liveIn_ = livenessInfo.liveOut_;
      livenessInfo.liveIn_ |= livenessInfo.gen_;
      livenessInfo.liveIn_.reset(livenessInfo.kill_);
      livenessInfo.liveIn_.reset(livenessInfo.maskIn_);
    }
  } while (changed);

#ifndef NDEBUG
  for (auto &it : blockLiveness_) {
    BasicBlock *BB = it.first;
    BlockLifetimeInfo &livenessInfo = it.second;
    LLVM_DEBUG(llvh::dbgs() << "Block " << BB << "\n");
    LLVM_DEBUG(dumpVector(livenessInfo.gen_, "gen     ", llvh::dbgs()));
    LLVM_DEBUG(dumpVector(livenessInfo.kill_, "kill    ", llvh::dbgs()));
    LLVM_DEBUG(dumpVector(livenessInfo.liveIn_, "liveIn  ", llvh::dbgs()));
    LLVM_DEBUG(dumpVector(livenessInfo.liveOut_, "liveOut ", llvh::dbgs()));
    LLVM_DEBUG(dumpVector(livenessInfo.maskIn_, "maskIn  ", llvh::dbgs()));
    LLVM_DEBUG(llvh::dbgs() << "------\n");
  }
#endif

  LLVM_DEBUG(
      dbgs() << "Completed liveness in " << iterations << " iterations\n");
                                                                   
  (void)iterations;
}

Interval &RegisterAllocator::getInstructionInterval(Instruction *I) {
  auto idx = getInstructionNumber(I);
  return instructionInterval_[idx];
}

Register RegisterAllocator::getRegisterForInstructionAt(
    Instruction *Value,
    Instruction *At) {
  if (hasInstructionNumber(Value) && hasInstructionNumber(At)) {
    Register valueReg = getRegister(Value);
    unsigned loc = getInstructionNumber(At);
    if (valueReg.isValid()) {
                                                                                
      const Interval &i = getInstructionInterval(Value);
      auto itBegin = i.segments_.begin(), itEnd = i.segments_.end();
      if (std::find_if(itBegin, itEnd, [loc](const Segment &s) {
            return s.contains(loc);
          })) {
        return valueReg;
      }
    }
  }

                                                              
  return Register{};
}

bool RegisterAllocator::isManuallyAllocatedInterval(Instruction *I) {
  if (hasTargetSpecificLowering(I))
    return true;

  for (auto *U : I->getUsers()) {
    if (hasTargetSpecificLowering(U))
      return true;
  }

  return false;
}

void RegisterAllocator::coalesce(
    DenseMap<Instruction *, Instruction *> &map,
    ArrayRef<BasicBlock *> order) {
                                                                          
                                                                               
  for (BasicBlock *BB : order) {
    for (Instruction &I : *BB) {
      auto *P = llvh::dyn_cast<PhiInst>(&I);
      if (!P)
        continue;

      unsigned phiNum = getInstructionNumber(P);
      for (unsigned i = 0, e = P->getNumEntries(); i < e; ++i) {
        auto *mov = cast<MovInst>(P->getEntry(i).first);

                                                                               
                 
        if (map.count(mov))
          continue;

        if (!hasInstructionNumber(mov))
          continue;

        unsigned idx = getInstructionNumber(mov);
        instructionInterval_[phiNum].add(instructionInterval_[idx]);

                                                                                
        map[mov] = P;
      }
    }
  }

                                                                            
                                                                         
                                                    
                    
                    
  for (BasicBlock *BB : order) {
    DenseMap<Value *, MovInst *> lastCopy;

    for (Instruction &I : *BB) {
      auto *mov = llvh::dyn_cast<MovInst>(&I);
      if (!mov)
        continue;

      Value *op = mov->getSingleOperand();
      if (llvh::isa<Literal>(op))
        continue;

                                                                        
      auto it = lastCopy.find(op);
      if (it != lastCopy.end()) {
        mov->setOperand(it->second, 0);
      }

      lastCopy[op] = mov;
    }
  }

                                                                             
                                           
  for (BasicBlock *BB : order) {
    for (Instruction &I : *BB) {
      auto *mov = llvh::dyn_cast<MovInst>(&I);
      if (!mov)
        continue;

      auto *op = llvh::dyn_cast<Instruction>(mov->getSingleOperand());
      if (!op)
        continue;

                                                                               
                                                                            
                                       
      if (map.count(op) || isAllocated(op) || isAllocated(mov))
        continue;

                                                                                
                                    
      Instruction *dest = mov;

                                                                             
                                                                             
                                           
      if (isManuallyAllocatedInterval(op))
        continue;

                                                                         
                                                                            
      while (map.count(dest)) {
        dest = map[dest];
      }

      unsigned destIdx = getInstructionNumber(dest);
      unsigned opIdx = getInstructionNumber(op);
      Interval &destIvl = instructionInterval_[destIdx];
      Interval &opIvl = instructionInterval_[opIdx];

      if (destIvl.intersects(opIvl))
        continue;

      LLVM_DEBUG(
          dbgs() << "Coalescing instruction @" << opIdx << "  " << opIvl
                 << " -> @" << destIdx << "  " << destIvl << "\n");

      for (auto &it : map) {
        if (it.second == op) {
          LLVM_DEBUG(
              dbgs() << "Remapping @" << getInstructionNumber(it.first)
                     << " from @" << opIdx << " to @" << destIdx << "\n");
          it.second = dest;
        }
      }

      instructionInterval_[destIdx].add(opIvl);
      map[op] = dest;
    }
  }
}

void RegisterAllocator::allocateFastPass(ArrayRef<BasicBlock *> order) {
                                                          
  for (auto *bb : order) {
    for (auto &inst : *bb) {
      handleInstruction(&inst);
      if (auto *phi = llvh::dyn_cast<PhiInst>(&inst)) {
        auto reg = file.allocateRegister();
        updateRegister(phi, reg);
        for (int i = 0, e = phi->getNumEntries(); i < e; i++) {
          updateRegister(phi->getEntry(i).first, reg);
        }
      }
    }
  }

                                                                              
                               
  llvh::BitVector blockLocals;

                                                                             
                                                                           
                                                                             
                                        
  llvh::SmallVector<Register, 8> freeBlockLocals;

                                                                   
  Register deadReg = file.allocateRegister();

                                                                           
                                                    
  for (auto *bb : llvh::reverse(order)) {
    for (auto &inst : llvh::reverse(*bb)) {
      if (isAllocated(&inst)) {
                                                                                
                                   
        auto reg = getRegister(&inst);
        auto idx = reg.getIndex();
        if (idx < blockLocals.size() && blockLocals.test(idx))
          freeBlockLocals.push_back(reg);
      } else {
                                                                              
                                                            
                                                                                
                                             
        updateRegister(&inst, deadReg);
      }

                                                     
      for (size_t i = 0, e = inst.getNumOperands(); i < e; ++i) {
        auto *op = llvh::dyn_cast<Instruction>(inst.getOperand(i));

                                                                      
        if (!op || isAllocated(op))
          continue;

        if (op->getParent() != bb) {
                                                             
          updateRegister(op, file.allocateRegister());
          continue;
        }

                                                 
                                                           
                                                                   
                                                                      
                                   
        if (!freeBlockLocals.empty()) {
          updateRegister(op, freeBlockLocals.pop_back_val());
          continue;
        }

                                                        
        Register reg = file.allocateRegister();
        if (blockLocals.size() <= reg.getIndex())
          blockLocals.resize(reg.getIndex() + 1);
        blockLocals.set(reg.getIndex());
        updateRegister(op, reg);
      }
    }
  }
}

void RegisterAllocator::allocate(ArrayRef<BasicBlock *> order) {
  PerfSection regAlloc("Register Allocation");

                                             
  lowerPhis(order);

  {
                                                                       
                                                                             
                                                                        
                                                                          
                                                                          
             

    unsigned int instructionCount = 0;
    for (const auto &BB : order) {
      instructionCount += BB->getInstList().size();
    }
                                                                           
            
    uint64_t estimatedMemoryUsage =
        (uint64_t)order.size() * instructionCount * 5 / 8;
    if (instructionCount < fastPassThreshold ||
        estimatedMemoryUsage > memoryLimit) {
      allocateFastPass(order);
      return;
    }
  }

                         
  for (auto *BB : order) {
    for (auto &it : *BB) {
      Instruction *I = &it;
      auto idx = getInstructionNumber(I);
      (void)idx;
      assert(idx == getInstructionNumber(I) && "Invalid numbering");
    }
  }

                                                                         
                                   
  unsigned maxIdx = getMaxInstrIndex();
  for (auto *BB : order) {
    blockLiveness_[BB].init(maxIdx);
  }
  for (auto *BB : order) {
    calculateLocalLiveness(blockLiveness_[BB], BB);
  }

                                                                        
  calculateGlobalLiveness(order);

                                                       
  calculateLiveIntervals(order);

                                       
  blockLiveness_.clear();

                                                                               
  DenseMap<Instruction *, Instruction *> coalesced;

  coalesce(coalesced, order);

                                                                
  auto startsFirst = [&](unsigned a, unsigned b) {
    Interval &IA = instructionInterval_[a];
    Interval &IB = instructionInterval_[b];
    return IA.start() < IB.start() || (IA.start() == IB.start() && a < b);
  };

                                                                       
                                                                         
              

  auto endsFirst = [&](unsigned a, unsigned b) {
    auto &aInterval = instructionInterval_[a];
    auto &bInterval = instructionInterval_[b];
    if (bInterval.end() == aInterval.end()) {
      return bInterval.start() > aInterval.start() ||
          (bInterval.start() == aInterval.start() && b > a);
    }
    return bInterval.end() > aInterval.end();
  };

  using InstList = llvh::SmallVector<unsigned, 32>;

  std::priority_queue<unsigned, InstList, decltype(endsFirst)> intervals(
      endsFirst);

  for (int i = 0, e = getMaxInstrIndex(); i < e; i++) {
    intervals.push(i);
  }

  std::priority_queue<unsigned, InstList, decltype(startsFirst)>
      liveIntervalsQueue(startsFirst);

                                     
  while (!intervals.empty()) {
    unsigned instIdx = intervals.top();
    intervals.pop();
    Instruction *inst = instructionsByNumbers_[instIdx];
    Interval &instInterval = instructionInterval_[instIdx];
    unsigned currentIndex = instInterval.end();

    LLVM_DEBUG(
        dbgs() << "Looking at index " << currentIndex << ": " << instInterval
               << " " << inst->getName() << "\n");

                                                                    
    while (!liveIntervalsQueue.empty()) {
      LLVM_DEBUG(
          dbgs() << "\t Cleaning up for index " << currentIndex << " PQ("
                 << liveIntervalsQueue.size() << ")\n");

      unsigned topIdx = liveIntervalsQueue.top();
      Interval &range = instructionInterval_[topIdx];
      LLVM_DEBUG(dbgs() << "\t Earliest interval: " << range << "\n");

                                                                           
      bool nonEmptyInterval = range.size();
      if (range.start() < currentIndex && nonEmptyInterval) {
        break;
      }

      liveIntervalsQueue.pop();

      Instruction *I = instructionsByNumbers_[topIdx];
      Register R = getRegister(I);
      LLVM_DEBUG(
          dbgs() << "\t Reached idx #" << currentIndex << " deleting inverval "
                 << range << " that's allocated to register " << R
                 << " used by instruction " << I->getName() << "\n");
      file.killRegister(R);

      handleInstruction(I);
    }

                                                                       
                 
    if (coalesced.count(inst)) {
      continue;
    }

                                                                                
    if (!isAllocated(inst)) {
      Register R = file.allocateRegister();
      updateRegister(inst, R);
    }

                                                                          
                                                       
    liveIntervalsQueue.push(instIdx);
  }                                         

                                  
  while (!liveIntervalsQueue.empty()) {
    Instruction *I = instructionsByNumbers_[liveIntervalsQueue.top()];
    LLVM_DEBUG(
        dbgs() << "Free register used by instruction " << I->getName() << "\n");
    file.killRegister(getRegister(I));
    handleInstruction(I);
    liveIntervalsQueue.pop();
  }

                                                    
  for (auto &RP : coalesced) {
    assert(!isAllocated(RP.first) && "Register should not be allocated");
    Instruction *dest = RP.second;
    updateRegister(RP.first, getRegister(dest));
  }
}

void RegisterAllocator::calculateLiveIntervals(ArrayRef<BasicBlock *> order) {
                                                                             
                                                         
  for (int i = 0, e = instructionsByNumbers_.size(); i < e; ++i) {
                                                                          
                                                                              
                                       
    instructionInterval_[i] = Interval(i + 1, i + 1);
  }

                                              
  for (BasicBlock *BB : order) {
    BlockLifetimeInfo &liveness = blockLiveness_[BB];

    auto startOffset = getInstructionNumber(&*BB->begin());
    auto endOffset = getInstructionNumber(BB->getTerminator());

                                                                              
                                                               
    for (int i = 0, e = liveness.liveOut_.size(); i < e; i++) {
      bool leavs = liveness.liveOut_.test(i);
      bool enters = liveness.liveIn_.test(i);
      if (leavs && enters) {
        instructionInterval_[i].add(Segment(startOffset, endOffset + 1));
      }
    }

                                         
    for (auto &it : *BB) {
      auto instOffset = getInstructionNumber(&it);
                                                                               
                                                                        
      if (liveness.liveOut_.test(instOffset)) {
        instructionInterval_[instOffset].add(
            Segment(instOffset + 1, endOffset + 1));
        assert(
            !liveness.liveIn_.test(instOffset) &&
            "Livein but also killed in this block?");
      }

                                             
      for (int i = 0, e = it.getNumOperands(); i < e; i++) {
        auto instOp = llvh::dyn_cast<Instruction>(it.getOperand(i));
        if (!instOp)
          continue;

        if (!hasInstructionNumber(instOp)) {
          assert(
              llvh::isa<PhiInst>(&it) &&
              "Only PhiInst should reference values from dead code");
          continue;
        }

        auto operandIdx = getInstructionNumber(instOp);
                                                                         
                                                                              
                                                    

        auto start = operandIdx + 1;
        auto end = instOffset + 1;
        if (start < end) {
          auto seg = Segment(operandIdx + 1, instOffset + 1);
          instructionInterval_[operandIdx].add(seg);
        }
      }

                                                                           
      if (auto *P = llvh::dyn_cast<PhiInst>(&it)) {
        for (int i = 0, e = P->getNumEntries(); i < e; i++) {
          auto E = P->getEntry(i);
                                                                      
                                                                       
                                                           
          if (!hasInstructionNumber(E.second->getTerminator()))
            continue;

          unsigned termIdx = getInstructionNumber(E.second->getTerminator());
          Segment S(termIdx, termIdx + 1);
          instructionInterval_[instOffset].add(S);

                                                                         
          if (auto *instOp = llvh::dyn_cast<Instruction>(E.first)) {
            auto predIdx = getInstructionNumber(instOp);
            auto S2 = Segment(predIdx + 1, termIdx);
            instructionInterval_[predIdx].add(S2);
          }
        }              
      }

    }                                      
  }                   
}

struct LivenessRegAllocIRPrinter : IRPrinter {
  RegisterAllocator &allocator;

  explicit LivenessRegAllocIRPrinter(
      RegisterAllocator &RA,
      llvh::raw_ostream &ost,
      bool escape = false)
      : IRPrinter(RA.getContext(), ost, escape), allocator(RA) {}

  void printInstructionDestination(Instruction *I) override {
    if (!allocator.isAllocated(I)) {
      os << "$??? ";
    } else {
      os << "$" << allocator.getRegister(I) << " ";
    }

    if (allocator.hasInstructionNumber(I)) {
      auto idx = allocator.getInstructionNumber(I);
      Interval &ivl = allocator.getInstructionInterval(I);
      os << "@" << idx << " " << ivl << "\t";
    } else {
      os << "          \t";
    }

    IRPrinter::printInstructionDestination(I);
  }

  void printValueLabel(Instruction *I, Value *V, unsigned opIndex) override {
    IRPrinter::printValueLabel(I, V, opIndex);
    auto codeGenOpts = I->getContext().getCodeGenerationSettings();
    if (codeGenOpts.dumpOperandRegisters && allocator.isAllocated(V)) {
      os << " @ $" << allocator.getRegister(V);
    }
  }
};

void RegisterAllocator::dump() {
  LivenessRegAllocIRPrinter Printer(*this, llvh::outs());
  Printer.visitFunction(*F);
}

Register RegisterAllocator::getRegister(Value *I) {
  assert(isAllocated(I) && "Instruction is not allocated!");
  return allocated[I];
}

void RegisterAllocator::updateRegister(Value *I, Register R) {
  allocated[I] = R;
}

bool RegisterAllocator::isAllocated(Value *I) {
  return allocated.count(I);
}

Register RegisterAllocator::reserve(unsigned count) {
  return file.tailAllocateConsecutive(count);
}

Register RegisterAllocator::reserve(ArrayRef<Value *> values) {
  assert(!values.empty() && "Can't reserve zero registers");
  Register first = file.tailAllocateConsecutive(values.size());

  Register T = first;
  for (auto *v : values) {
    if (v)
      allocated[v] = T;
    T = T.getConsecutive();
  }

  return first;
}

bool RegisterAllocator::hasInstructionNumber(Instruction *I) {
  return instructionNumbers_.count(I);
}

unsigned RegisterAllocator::getInstructionNumber(Instruction *I) {
  auto it = instructionNumbers_.find(I);
  if (it != instructionNumbers_.end()) {
    return it->second;
  }

  instructionsByNumbers_.push_back(I);
  instructionInterval_.push_back(Interval());

  unsigned newIdx = instructionsByNumbers_.size() - 1;
  instructionNumbers_[I] = newIdx;
  return newIdx;
}

unsigned llvh::DenseMapInfo<Register>::getHashValue(Register Val) {
  return Val.getIndex();
}

bool llvh::DenseMapInfo<Register>::isEqual(Register LHS, Register RHS) {
  return LHS.getIndex() == RHS.getIndex();
}

namespace {
static bool preallocateScopeRegisters(const Context &c) {
  return c.getDebugInfoSetting() == DebugInfoSetting::ALL;
}
}             

ScopeRegisterAnalysis::ScopeRegisterAnalysis(Function *F, RegisterAllocator &RA)
    : RA_(RA) {
                                                                              
                                                                      
                                           
  llvh::SmallVector<Value *, 4> scopeCreationInsts;
  for (BasicBlock &BB : *F) {
    for (Instruction &I : BB) {
      if (llvh::isa<HBCResolveEnvironment>(I)) {
                                                                              
                                                                             
                       
        continue;
      } else if (auto *SCI = llvh::dyn_cast<ScopeCreationInst>(&I)) {
        assert(
            SCI->getCreatedScopeDesc()->getFunction() == F &&
            "ScopeCreationInst that is creating a scope of another function");
        scopeCreationInsts_[SCI->getCreatedScopeDesc()] = SCI;
        if (preallocateScopeRegisters(F->getContext())) {
          LLVM_DEBUG(
              llvh::dbgs() << "Reserving register for ScopeCreationInst in "
                           << F->getOriginalOrInferredName() << "\n");
          scopeCreationInsts.push_back(SCI);
        }
      }
    }
  }

  if (!scopeCreationInsts.empty()) {
    RA_.reserve(scopeCreationInsts);
  }
}

std::pair<Register, ScopeDesc *> ScopeRegisterAnalysis::registerAndScopeAt(
    Instruction *Value,
    ScopeCreationInst *SCI) {
                                                                           
                                 
  Register sciReg = RA_.getRegisterForInstructionAt(Value, SCI);
  if (sciReg.isValid()) {
    return std::make_pair(sciReg, SCI->getCreatedScopeDesc());
  }

                                                                          
  auto parentIt =
      scopeCreationInsts_.find(SCI->getCreatedScopeDesc()->getParent());
  if (parentIt == scopeCreationInsts_.end()) {
                                                           
    return std::make_pair(Register{}, nullptr);
  }

                                                      
  return registerAndScopeAt(Value, parentIt->second);
}

std::pair<Register, ScopeDesc *>
ScopeRegisterAnalysis::registerAndScopeForInstruction(Instruction *Inst) {
  if (ScopeDesc *originalScope = Inst->getSourceLevelScope()) {
    auto sciIt = scopeCreationInsts_.find(originalScope);
    if (sciIt != scopeCreationInsts_.end()) {
      ScopeCreationInst *originalScopeCreation = sciIt->second;
      if (!preallocateScopeRegisters(Inst->getContext())) {
        return registerAndScopeAt(Inst, originalScopeCreation);
      }
                                                                               
                                                                            
                                                                               
                                                
      assert(RA_.isAllocated(originalScopeCreation) && "should be allocated");
      Register sciReg = RA_.getRegister(originalScopeCreation);
      assert(sciReg.isValid() && "scope register should be valid.");
      return std::make_pair(sciReg, originalScope);
    }
  }

  return std::make_pair(Register{}, nullptr);
}

#undef DEBUG_TYPE

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Regex/Executor.h"
#include "hermes/Regex/RegexTraits.h"
#include "hermes/Support/OptValue.h"

#include "llvh/ADT/ScopeExit.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/Support/TrailingObjects.h"
#include "llvh/Support/raw_ostream.h"

                                                                                

namespace hermes {
namespace regex {

template <class Traits>
struct State;

                                                                      
                                
enum class ExecutionStatus : uint8_t { RETURNED, STACK_OVERFLOW };

                                                                      
                                                                       
                                                
                                                            
template <typename T>
class ExecutorResult {
  static_assert(std::is_trivial<T>::value, "T must be trivial.");

 private:
  ExecutionStatus status_;
  T value_;

 public:
                 ExecutorResult(const T &v)
      : status_(ExecutionStatus::RETURNED), value_(v) {}

                 ExecutorResult(ExecutionStatus status) : status_(status) {
    assert(status != ExecutionStatus::RETURNED);
  }

  const T &operator*() const {
    return getValue();
  }

  bool hasValue() const {
    return status_ == ExecutionStatus::RETURNED;
  }

  explicit operator bool() const {
    return hasValue();
  }

  const T &getValue() const {
    assert(getStatus() == ExecutionStatus::RETURNED);
    return *reinterpret_cast<const T *>(&value_);
  }

  ExecutionStatus getStatus() const {
    return status_;
  }
};
                                                                             
                                                                                
                                                                              
                                     
enum class Width1Opcode : uint8_t {
  MatchChar8 = (uint8_t)Opcode::MatchChar8,
  MatchChar16 = (uint8_t)Opcode::MatchChar16,
  MatchCharICase8 = (uint8_t)Opcode::MatchCharICase8,
  MatchCharICase16 = (uint8_t)Opcode::MatchCharICase16,
  MatchAny = (uint8_t)Opcode::MatchAny,
  MatchAnyButNewline = (uint8_t)Opcode::MatchAnyButNewline,
  Bracket = (uint8_t)Opcode::Bracket,
};

                                                                               
                              
struct LoopData {
                                                                    
  uint32_t iterations;

                                                   
  uint32_t entryPosition;
};

                                                                                
                                               
                                                                              
                                                                               
                                                                                
                                                                          
                                      
template <class Traits>
class Cursor {
  using CodeUnit = typename Traits::CodeUnit;
  using CodePoint = typename Traits::CodePoint;

 public:
                                                                        
                                                                            
                                                                         
                                             
  Cursor(
      const CodeUnit *first,
      const CodeUnit *current,
      const CodeUnit *last,
      bool forwards)
      : first_(first),
        last_(last),
        current_(current),
        end_(forwards ? last : first),
        forwards_(forwards) {
    assert(first_ <= last_ && "first and last out of order");
    assert(
        first_ <= current_ && current <= last_ &&
        "current pointer not in range");
  }

                                                    
  bool forwards() const {
    return forwards_;
  }

                                                           
  void setForwards(bool flag) {
    forwards_ = flag;
    end_ = forwards_ ? last_ : first_;
  }

                                                 
  uint32_t remaining() const {
    return forwards_ ? last_ - current_ : current_ - first_;
  }

                                                     
  bool atEnd() const {
    return current_ == end_;
  }

                                                                            
                                                                                
                                                  
  uint32_t offsetFromLeft() const {
    return current_ - first_;
  }

                                                                               
                    
                                                                               
                                                  
  uint32_t offsetFromRight() const {
    return last_ - current_;
  }

                                                      
                                                    
  bool atLeft() const {
    return current_ == first_;
  }

                                                       
                                                    
  bool atRight() const {
    return current_ == last_;
  }

                                    
  CodeUnit current() const {
                                                                    
    assert(!atEnd() && "Cursor is at end");
    return current_[(int)forwards_ - 1];
  }

                                          
  const CodeUnit *currentPointer() const {
    return current_;
  }

                                                    
  void setCurrentPointer(const CodeUnit *current) {
    assert(first_ <= current && current <= last_ && "Current not in range");
    current_ = current;
  }

                                                               
  CodeUnit consume() {
    CodeUnit result = current();
    current_ += forwards_ ? 1 : -1;
    return result;
  }

                                                                        
                                                                                
                     
  CodePoint consumeUTF16() {
    assert(!atEnd() && "At end");

                                      
    if (sizeof(CodeUnit) >= 2 && remaining() >= 2) {
      CodeUnit hi = forwards_ ? current_[0] : current_[-2];
      CodeUnit lo = forwards_ ? current_[1] : current_[-1];
      if (isHighSurrogate(hi) && isLowSurrogate(lo)) {
        current_ += forwards_ ? 2 : -2;
        return utf16SurrogatePairToCodePoint(hi, lo);
      }
    }
    return consume();
  }

                                                                          
                                              
  bool satisfiesConstraints(
      constants::MatchFlagType flags,
      MatchConstraintSet constraints) const {
    if ((constraints & MatchConstraintNonASCII) &&
        (flags & constants::matchInputAllAscii))
      return false;
    if ((constraints & MatchConstraintAnchoredAtStart) && current_ != first_)
      return false;
    return true;
  }

 private:
                                       
  const CodeUnit *first_;

                                               
  const CodeUnit *last_;

                                           
                                                                   
                                                                     
  const CodeUnit *current_;

                                                                             
                                                                      
  const CodeUnit *end_;

                                                   
  bool forwards_;
};

                                                               
template <class Traits>
struct Context {
  using CodeUnit = typename Traits::CodeUnit;
  using CodePoint = typename Traits::CodePoint;

                                                                               
               
  enum class BacktrackOp : uint8_t {
                                                           
    SetCaptureGroup,

                                                       
    SetLoopData,

                                                                      
    SetPosition,

                                                            
    EnterNonGreedyLoop,

                                                                              
                
    GreedyWidth1Loop,

                                                                            
                      
    NongreedyWidth1Loop,
  };

                                                 
  union BacktrackInsn {
                                 
    BacktrackOp op;

                                                                               
                                                                       
                        

                                                   
    struct {
      BacktrackOp op;
      uint16_t mexp;                                
      CapturedRange range;                  
    } setCaptureGroup;

                                               
    struct {
      BacktrackOp op;
      uint16_t loopId;                       
      LoopData loopData;                  
    } setLoopData;

                                               
    struct {
      BacktrackOp op;
      uint32_t ip;                                
      const CodeUnit *value;                                  
    } setPosition;

                                                      
    struct {
      BacktrackOp op;
      uint32_t bodyIp;                             
      LoopData loopData;                              
      const BeginLoopInsn *loopInsn;                          
    } enterNonGreedyLoop;

                                                                
    struct {
      BacktrackOp op;                
      uint32_t continuation;                                                 
      const CodeUnit *min;                                         
      const CodeUnit *max;                                         
    } width1Loop;

                   BacktrackInsn(BacktrackOp op) : op(op) {}

                                              
    static BacktrackInsn makeSetCaptureGroup(
        uint16_t mexp,
        CapturedRange range) {
      BacktrackInsn result{BacktrackOp::SetCaptureGroup};
      result.setCaptureGroup.mexp = mexp;
      result.setCaptureGroup.range = range;
      return result;
    }

                                          
    static BacktrackInsn makeSetLoopData(uint16_t loopId, LoopData loopData) {
      BacktrackInsn result{BacktrackOp::SetLoopData};
      result.setLoopData.loopId = loopId;
      result.setLoopData.loopData = loopData;
      return result;
    }

                                          
    static BacktrackInsn makeSetPosition(
        uint32_t ip,
        const CodeUnit *inputPos) {
      BacktrackInsn result = BacktrackOp::SetPosition;
      result.setPosition.ip = ip;
      result.setPosition.value = inputPos;
      return result;
    }

                                                  
    static BacktrackInsn makeEnterNonGreedyLoop(
        const BeginLoopInsn *loopInsn,
        uint32_t bodyIp,
        LoopData loopData) {
      BacktrackInsn result = BacktrackOp::EnterNonGreedyLoop;
      result.enterNonGreedyLoop.bodyIp = bodyIp;
      result.enterNonGreedyLoop.loopInsn = loopInsn;
      result.enterNonGreedyLoop.loopData = loopData;
      return result;
    }
  };

                                          
  using BacktrackStack = llvh::SmallVector<BacktrackInsn, 64>;

                                                                                
                     
  static constexpr size_t kMaxBacktrackDepth = 1u << 24;

                                                                
  llvh::ArrayRef<uint8_t> bytecodeStream_;

                                                  
  constants::MatchFlagType flags_;

                                             
  SyntaxFlags syntaxFlags_;

                                              
  const CodeUnit *first_;

                                                      
  const CodeUnit *last_;

                          
  uint32_t markedCount_;

                     
  uint32_t loopCount_;

                                       
  Traits traits_;

                                                                 
                                                            
  uint32_t backtracksRemaining_ = kBacktrackLimit;

                                                                  
                                              
  StackOverflowGuard overflowGuard_;

  Context(
      llvh::ArrayRef<uint8_t> bytecodeStream,
      constants::MatchFlagType flags,
      SyntaxFlags syntaxFlags,
      const CodeUnit *first,
      const CodeUnit *last,
      uint32_t markedCount,
      uint32_t loopCount,
      StackOverflowGuard guard)
      : bytecodeStream_(bytecodeStream),
        flags_(flags),
        syntaxFlags_(syntaxFlags),
        first_(first),
        last_(last),
        markedCount_(markedCount),
        loopCount_(loopCount),
        overflowGuard_(guard) {}

                                                                               
                                                                           
                                                                                
                         
                                                                                
                                                                              
                                                                          
                                                   
                                      
  ExecutorResult<const CodeUnit *> match(
      State<Traits> *state,
      bool onlyAtStart);

                                                                     
                                                                      
  LLVM_NODISCARD
  ExecutorResult<bool> backtrack(BacktrackStack &bts, State<Traits> *s);

                                                                
                                                                              
  LLVM_NODISCARD
  ExecutionStatus performEnterNonGreedyLoop(
      State<Traits> *s,
      const BeginLoopInsn *loop,
      uint32_t bodyIp,
      LoopData loopData,
      BacktrackStack &backtrackStack);

                                                                
                                                           
  LLVM_NODISCARD
  ExecutionStatus pushBacktrack(BacktrackStack &bts, BacktrackInsn insn) {
    bts.push_back(insn);
    if (LLVM_UNLIKELY(bts.size() > kMaxBacktrackDepth) ||
        LLVM_UNLIKELY(backtracksRemaining_ == 0)) {
      return ExecutionStatus::STACK_OVERFLOW;
    }
    backtracksRemaining_--;
    return ExecutionStatus::RETURNED;
  }

                                                                       
                             
                                                            
  LLVM_NODISCARD
  ExecutorResult<bool> matchWidth1Loop(
      const Width1LoopInsn *insn,
      State<Traits> *s,
      BacktrackStack &bts);

 private:
                                                                         
                                                                              
            
                                                                        
  LLVM_NODISCARD
  ExecutionStatus prepareToEnterLoopBody(
      State<Traits> *state,
      const BeginLoopInsn *loop,
      BacktrackStack &bts);

                                                                          
                                                         
  template <Width1Opcode w1opcode>
  inline bool matchWidth1(const Insn *insn, CodeUnit c) const;

                                                                           
                                                                             
                                             
  inline bool matchesNCharICase8(
      const MatchNCharICase8Insn *insn,
      State<Traits> &s);

                                                                              
                                                                          
                                                
  template <Width1Opcode w1opcode>
  inline uint32_t
  matchWidth1LoopBody(const Insn *loopBody, Cursor<Traits> c, uint32_t max);

                                        
                                                      
                                                                                
                              
  inline size_t advanceStringIndex(
      const CodeUnit *start,
      size_t index,
      size_t lastIndex) const;
};

                                                                                
                                                               
                          
union LoopOrCapturedRange {
  struct LoopData loopData;
  struct CapturedRange capturedRange;
};

                                                                            
                                   
template <typename Traits>
struct State {
  using CharT = typename Traits::CodeUnit;

                                     
  Cursor<Traits> cursor_;

                                                              
  uint32_t ip_ = 0;

                                                                          
                                   
  llvh::SmallVector<CapturedRange, 16> capturedRanges_;

                                                                            
            
  llvh::SmallVector<LoopData, 16> loopDatas_;

                                            
  LoopData &getLoop(uint32_t idx) {
    assert(idx < loopDatas_.size() && "Invalid loop index");
    return loopDatas_[idx];
  }

                                                 
  CapturedRange &getCapturedRange(uint32_t idx) {
                                                                        
    assert(idx < capturedRanges_.size() && "Invalid captured range index");
    return capturedRanges_[idx];
  }

                                                                         
                                                         
  State(Cursor<Traits> cursor, uint32_t markedCount, uint32_t loopCount)
      : cursor_(cursor),
        capturedRanges_(markedCount, {kNotMatched, kNotMatched}),
        loopDatas_(loopCount, {0, 0}) {}

  State(const State &) = default;
  State &operator=(const State &) = default;
  State(State &&) = default;
  State &operator=(State &&) = default;
};

             
template <class CharT>
bool isLineTerminator(CharT c) {
  return c == u'\u000A' || c == u'\u000D' || c == u'\u2028' || c == u'\u2029';
}

template <class Traits>
bool matchesLeftAnchor(Context<Traits> &ctx, State<Traits> &s) {
  bool matchesAnchor = false;
  const Cursor<Traits> &c = s.cursor_;
  if (c.atLeft()) {
                         
    matchesAnchor = true;
  } else if (
      (ctx.syntaxFlags_.multiline) && !c.atLeft() &&
      isLineTerminator(c.currentPointer()[-1])) {
                                           
    matchesAnchor = true;
  }
  return matchesAnchor;
}

template <class Traits>
bool matchesRightAnchor(Context<Traits> &ctx, State<Traits> &s) {
  bool matchesAnchor = false;
  const Cursor<Traits> &c = s.cursor_;
  if (c.atRight() && !(ctx.flags_ & constants::matchNotEndOfLine)) {
    matchesAnchor = true;
  } else if (
      (ctx.syntaxFlags_.multiline) && (!c.atRight()) &&
      isLineTerminator(c.currentPointer()[0])) {
    matchesAnchor = true;
  }
  return matchesAnchor;
}

                                                                         
                                                                            
                        
template <class Traits>
bool matchesNChar8(const MatchNChar8Insn *insn, State<Traits> &s) {
  Cursor<Traits> &c = s.cursor_;
  auto insnCharPtr = reinterpret_cast<const char *>(insn + 1);
  auto charCount = insn->charCount;
  for (int idx = 0; idx < charCount; idx++) {
    if (c.consume() != insnCharPtr[idx]) {
      return false;
    }
  }
  return true;
}

template <class Traits>
bool Context<Traits>::matchesNCharICase8(
    const MatchNCharICase8Insn *insn,
    State<Traits> &s) {
  Cursor<Traits> &c = s.cursor_;
  auto insnCharPtr = reinterpret_cast<const char *>(insn + 1);
  auto charCount = insn->charCount;
  bool unicode = syntaxFlags_.unicode;
  for (int idx = 0; idx < charCount; idx++) {
    auto c1 = c.consume();
    char instC = insnCharPtr[idx];
    if (c1 != instC &&
        (char32_t)traits_.canonicalize(c1, unicode) != (char32_t)instC) {
      return false;
    }
  }
  return true;
}

                                                                              
                                                                              
               
template <class Traits>
bool bracketMatchesChar(
    const Context<Traits> &ctx,
    const BracketInsn *insn,
    const BracketRange32 *ranges,
    typename Traits::CodePoint ch) {
  const auto &traits = ctx.traits_;
                                                                               
                                                                              

                             
                                                                               
                                                                             
                                       
  if (insn->positiveCharClasses || insn->negativeCharClasses) {
    for (auto charClass :
         {CharacterClass::Digits,
          CharacterClass::Spaces,
          CharacterClass::Words}) {
      if ((insn->positiveCharClasses & charClass) &&
          traits.characterHasType(ch, charClass))
        return true ^ insn->negate;
      if ((insn->negativeCharClasses & charClass) &&
          !traits.characterHasType(ch, charClass))
        return true ^ insn->negate;
    }
  }

  bool contained =
      traits.rangesContain(llvh::makeArrayRef(ranges, insn->rangeCount), ch);
  return contained ^ insn->negate;
}

template <class Traits>
ExecutionStatus Context<Traits>::prepareToEnterLoopBody(
    State<Traits> *s,
    const BeginLoopInsn *loop,
    BacktrackStack &bts) {
  LoopData &loopData = s->getLoop(loop->loopId);
  auto res = pushBacktrack(
      bts, BacktrackInsn::makeSetLoopData(loop->loopId, loopData));
  if (res != ExecutionStatus::RETURNED) {
    return res;
  }
  loopData.iterations++;
  loopData.entryPosition = s->cursor_.offsetFromLeft();

                                                  
  for (uint32_t mexp = loop->mexpBegin; mexp != loop->mexpEnd; mexp++) {
    auto &captureRange = s->getCapturedRange(mexp);
    res = pushBacktrack(
        bts, BacktrackInsn::makeSetCaptureGroup(mexp, captureRange));
    if (res != ExecutionStatus::RETURNED) {
      return res;
    }
    captureRange = {kNotMatched, kNotMatched};
  }
  return ExecutionStatus::RETURNED;
}

template <class Traits>
ExecutionStatus Context<Traits>::performEnterNonGreedyLoop(
    State<Traits> *s,
    const BeginLoopInsn *loop,
    uint32_t bodyIp,
    LoopData loopData,
    BacktrackStack &backtrackStack) {
  assert(loop->opcode == Opcode::BeginLoop && "Not a BeginLoopInsn");
  s->getLoop(loop->loopId) = loopData;

                                                                             
          
  s->ip_ = bodyIp;
  s->cursor_.setCurrentPointer(first_ + loopData.entryPosition);
  return prepareToEnterLoopBody(s, loop, backtrackStack);
}

template <class Traits>
ExecutorResult<bool> Context<Traits>::backtrack(
    BacktrackStack &bts,
    State<Traits> *s) {
  while (!bts.empty()) {
    BacktrackInsn &binsn = bts.back();
    switch (binsn.op) {
      case BacktrackOp::SetCaptureGroup:
        s->getCapturedRange(binsn.setCaptureGroup.mexp) =
            binsn.setCaptureGroup.range;
        bts.pop_back();
        break;

      case BacktrackOp::SetLoopData:
        s->getLoop(binsn.setLoopData.loopId) = binsn.setLoopData.loopData;
        bts.pop_back();
        break;

      case BacktrackOp::SetPosition:
        s->cursor_.setCurrentPointer(binsn.setPosition.value);
        s->ip_ = binsn.setPosition.ip;
        bts.pop_back();
        return true;

      case BacktrackOp::EnterNonGreedyLoop: {
        auto fields = binsn.enterNonGreedyLoop;
        bts.pop_back();
        auto res = performEnterNonGreedyLoop(
            s, fields.loopInsn, fields.bodyIp, fields.loopData, bts);
        if (res != ExecutionStatus::RETURNED) {
          return res;
        }
        return true;
      }

      case BacktrackOp::GreedyWidth1Loop:
      case BacktrackOp::NongreedyWidth1Loop: {
                                                                               
                                                                             
                                                                           
                                                                       
                                                                                
                                                                              
                                                                       
                                            
        bool forwards = s->cursor_.forwards();
        assert(
            (forwards ? binsn.width1Loop.min <= binsn.width1Loop.max
                      : binsn.width1Loop.min >= binsn.width1Loop.max) &&
            "Loop min should be <= max (or >= max if backwards)");
        if (binsn.width1Loop.min == binsn.width1Loop.max) {
                                                             
          bts.pop_back();
          break;
        }
        if (binsn.op == BacktrackOp::GreedyWidth1Loop) {
          binsn.width1Loop.max += forwards ? -1 : 1;
          s->cursor_.setCurrentPointer(binsn.width1Loop.max);
        } else {
          binsn.width1Loop.min += forwards ? 1 : -1;
          s->cursor_.setCurrentPointer(binsn.width1Loop.min);
        }
        s->ip_ = binsn.width1Loop.continuation;
        return true;
      }
    }
  }
                                      
  return false;
}

template <class Traits>
template <Width1Opcode w1opcode>
bool Context<Traits>::matchWidth1(const Insn *base, CodeUnit c) const {
                                                     
  assert(
      base->opcode == static_cast<Opcode>(w1opcode) &&
      "Instruction has wrong opcode");
  switch (w1opcode) {
    case Width1Opcode::MatchChar8: {
      const auto *insn = llvh::cast<MatchChar8Insn>(base);
      return c == insn->c;
    }

    case Width1Opcode::MatchChar16: {
      const auto *insn = llvh::cast<MatchChar16Insn>(base);
      return c == insn->c;
    }

    case Width1Opcode::MatchCharICase8: {
      const auto *insn = llvh::cast<MatchCharICase8Insn>(base);
      return c == (CodePoint)insn->c ||
          (CodePoint)traits_.canonicalize(c, syntaxFlags_.unicode) ==
          (CodePoint)insn->c;
    }

    case Width1Opcode::MatchCharICase16: {
      const auto *insn = llvh::cast<MatchCharICase16Insn>(base);
      return c == insn->c ||
          (char32_t)traits_.canonicalize(c, syntaxFlags_.unicode) ==
          (char32_t)insn->c;
    }

    case Width1Opcode::MatchAny:
      return true;

    case Width1Opcode::MatchAnyButNewline:
      return !isLineTerminator(c);

    case Width1Opcode::Bracket: {
                                                              
      assert(
          !(syntaxFlags_.unicode) &&
          "Unicode should not be set for Width 1 brackets");
      const BracketInsn *insn = llvh::cast<BracketInsn>(base);
      const BracketRange32 *ranges =
          reinterpret_cast<const BracketRange32 *>(insn + 1);
      return bracketMatchesChar<Traits>(*this, insn, ranges, c);
    }
  }
  llvm_unreachable("Invalid width 1 opcode");
}

template <class Traits>
template <Width1Opcode w1opcode>
uint32_t Context<Traits>::matchWidth1LoopBody(
    const Insn *insn,
    Cursor<Traits> c,
    uint32_t max) {
  uint32_t iters = 0;
  for (; iters < max; iters++) {
    if (!matchWidth1<w1opcode>(insn, c.consume()))
      break;
  }
  return iters;
}

template <class Traits>
ExecutorResult<bool> Context<Traits>::matchWidth1Loop(
    const Width1LoopInsn *insn,
    State<Traits> *s,
    BacktrackStack &bts) {
                                  
  Cursor<Traits> c = s->cursor_;
  uint32_t matched = 0, minMatch = insn->min, maxMatch = insn->max;

                                                                          
                                                                               
                                   
  maxMatch = std::min(c.remaining(), maxMatch);

                                                
  const Insn *body = static_cast<const Insn *>(&insn[1]);

                                                                               
                                                                          
                                                                          
  using W1 = Width1Opcode;
  switch (static_cast<Width1Opcode>(body->opcode)) {
    case W1::MatchChar8:
      matched = matchWidth1LoopBody<W1::MatchChar8>(body, c, maxMatch);
      break;
    case W1::MatchChar16:
      matched = matchWidth1LoopBody<W1::MatchChar16>(body, c, maxMatch);
      break;
    case W1::MatchCharICase8:
      matched = matchWidth1LoopBody<W1::MatchCharICase8>(body, c, maxMatch);
      break;
    case W1::MatchCharICase16:
      matched = matchWidth1LoopBody<W1::MatchCharICase16>(body, c, maxMatch);
      break;
    case W1::MatchAny:
      matched = matchWidth1LoopBody<W1::MatchAny>(body, c, maxMatch);
      break;
    case W1::MatchAnyButNewline:
      matched = matchWidth1LoopBody<W1::MatchAnyButNewline>(body, c, maxMatch);
      break;
    case W1::Bracket:
      matched = matchWidth1LoopBody<W1::Bracket>(body, c, maxMatch);
      break;
  }

                                                              
  if (matched < minMatch) {
    return false;
  }
  assert(
      minMatch <= matched && matched <= maxMatch &&
      "matched should be between min and max match count");

                                       
                                                          
  bool forwards = s->cursor_.forwards();
  const CodeUnit *pos = s->cursor_.currentPointer();
  const CodeUnit *minPos = forwards ? pos + minMatch : pos - minMatch;
  const CodeUnit *maxPos = forwards ? pos + matched : pos - matched;

                                                                                
                                                                            
  if (minMatch < matched) {
    BacktrackInsn backtrack{
        insn->greedy ? BacktrackOp::GreedyWidth1Loop
                     : BacktrackOp::NongreedyWidth1Loop};
    backtrack.width1Loop.continuation = insn->notTakenTarget;
    backtrack.width1Loop.min = minPos;
    backtrack.width1Loop.max = maxPos;
    auto res = pushBacktrack(bts, backtrack);
    if (res != ExecutionStatus::RETURNED)
      return res;
  }
                                                                                
                                          
  s->cursor_.setCurrentPointer(insn->greedy ? maxPos : minPos);
  s->ip_ = insn->notTakenTarget;
  return true;
}

                                                                                
                     
template <class Traits>
inline size_t Context<Traits>::advanceStringIndex(
    const CodeUnit *start,
    size_t index,
    size_t length) const {
  if (sizeof(CodeUnit) == 1) {
                                                                           
    return index + 1;
  }
                                           
                                            
  if (LLVM_LIKELY(!(syntaxFlags_.unicode)) || (index + 1 >= length))
    return index + 1;

                                                         
                                                        
                                                             
                                                           
  CodeUnit first = start[index];
  CodeUnit second = start[index + 1];
  if (LLVM_LIKELY(!isHighSurrogate(first)) ||
      LLVM_LIKELY(!isLowSurrogate(second))) {
    return index + 1;
  }
                    
  return index + 2;
}

template <class Traits>
auto Context<Traits>::match(State<Traits> *s, bool onlyAtStart)
    -> ExecutorResult<const CodeUnit *> {
  using State = State<Traits>;
  BacktrackStack backtrackStack;

                                     
  Cursor<Traits> &c = s->cursor_;

                                                                            
  const uint8_t *const bytecode = &bytecodeStream_[sizeof(RegexBytecodeHeader)];

                                                  
  const auto startIp = s->ip_;

  const CodeUnit *const startLoc = c.currentPointer();

                                                                                
                                                                               
  const size_t charsToRight = c.offsetFromRight();

                                                   
                                                                            
                  
  const size_t locsToCheckCount = onlyAtStart ? 1 : 1 + charsToRight;

                                                                               
                                                                            
  assert(
      (c.forwards() || locsToCheckCount == 1) &&
      "Can only check one location when cursor is backwards");

#ifndef HERMES_CHECK_NATIVE_STACK
  ++overflowGuard_.callDepth;
  auto decrement =
      llvh::make_scope_exit([this] { --overflowGuard_.callDepth; });
#endif

                                                                               
             
  if (overflowGuard_.isOverflowing()) {
    return ExecutionStatus::STACK_OVERFLOW;
  }

                                            
#define BACKTRACK()                            \
  do {                                         \
    auto btRes = backtrack(backtrackStack, s); \
    if (LLVM_UNLIKELY(!btRes))                 \
      return btRes.getStatus();                \
    if (*btRes)                                \
      goto backtrackingSucceeded;              \
    goto backtrackingExhausted;                \
  } while (0)

  for (size_t locIndex = 0; locIndex < locsToCheckCount;
       locIndex = advanceStringIndex(startLoc, locIndex, charsToRight)) {
    const CodeUnit *potentialMatchLocation = startLoc + locIndex;
    c.setCurrentPointer(potentialMatchLocation);
    s->ip_ = startIp;
  backtrackingSucceeded:
    for (;;) {
      const Insn *base = reinterpret_cast<const Insn *>(&bytecode[s->ip_]);
      switch (base->opcode) {
        case Opcode::Goal:
          return potentialMatchLocation;

        case Opcode::LeftAnchor:
          if (!matchesLeftAnchor(*this, *s))
            BACKTRACK();
          s->ip_ += sizeof(LeftAnchorInsn);
          break;

        case Opcode::RightAnchor:
          if (!matchesRightAnchor(*this, *s))
            BACKTRACK();
          s->ip_ += sizeof(RightAnchorInsn);
          break;

        case Opcode::MatchAny:
          if (c.atEnd() ||
              !matchWidth1<Width1Opcode::MatchAny>(base, c.consume()))
            BACKTRACK();
          s->ip_ += sizeof(MatchAnyInsn);
          break;

        case Opcode::U16MatchAny:
          if (c.atEnd())
            BACKTRACK();
          c.consumeUTF16();
          s->ip_ += sizeof(U16MatchAnyInsn);
          break;

        case Opcode::MatchAnyButNewline:
          if (c.atEnd() ||
              !matchWidth1<Width1Opcode::MatchAnyButNewline>(base, c.consume()))
            BACKTRACK();
          s->ip_ += sizeof(MatchAnyButNewlineInsn);
          break;

        case Opcode::U16MatchAnyButNewline:
          if (c.atEnd() || isLineTerminator(c.consumeUTF16()))
            BACKTRACK();
          s->ip_ += sizeof(U16MatchAnyButNewlineInsn);
          break;

        case Opcode::MatchChar8: {
          if (c.atEnd() ||
              !matchWidth1<Width1Opcode::MatchChar8>(base, c.consume()))
            BACKTRACK();
          s->ip_ += sizeof(MatchChar8Insn);
          break;
        }

        case Opcode::MatchChar16: {
          if (c.atEnd() ||
              !matchWidth1<Width1Opcode::MatchChar16>(base, c.consume()))
            BACKTRACK();
          s->ip_ += sizeof(MatchChar16Insn);
          break;
        }

        case Opcode::U16MatchChar32: {
          const auto *insn = llvh::cast<U16MatchChar32Insn>(base);
          if (c.atEnd() || c.consumeUTF16() != (CodePoint)insn->c)
            BACKTRACK();
          s->ip_ += sizeof(U16MatchChar32Insn);
          break;
        }

        case Opcode::MatchCharICase8: {
          if (c.atEnd() ||
              !matchWidth1<Width1Opcode::MatchCharICase8>(base, c.consume()))
            BACKTRACK();
          s->ip_ += sizeof(MatchCharICase8Insn);
          break;
        }

        case Opcode::MatchCharICase16: {
          if (c.atEnd() ||
              !matchWidth1<Width1Opcode::MatchCharICase16>(base, c.consume()))
            BACKTRACK();
          s->ip_ += sizeof(MatchCharICase16Insn);
          break;
        }

        case Opcode::U16MatchCharICase32: {
          const auto *insn = llvh::cast<U16MatchCharICase32Insn>(base);
          bool matched = false;
          if (!c.atEnd()) {
            CodePoint cp = c.consumeUTF16();
            matched =
                (cp == (CodePoint)insn->c ||
                 traits_.canonicalize(cp, true) == (CodePoint)insn->c);
          }
          if (!matched)
            BACKTRACK();
          s->ip_ += sizeof(U16MatchCharICase32Insn);
          break;
        }

        case Opcode::MatchNChar8: {
          const auto *insn = llvh::cast<MatchNChar8Insn>(base);
          if (c.remaining() < insn->charCount || !matchesNChar8(insn, *s))
            BACKTRACK();
          s->ip_ += insn->totalWidth();
          break;
        }

        case Opcode::MatchNCharICase8: {
          const auto *insn = llvh::cast<MatchNCharICase8Insn>(base);
          if (c.remaining() < insn->charCount || !matchesNCharICase8(insn, *s))
            BACKTRACK();
          s->ip_ += insn->totalWidth();
          break;
        }

        case Opcode::Alternation: {
                                                                            
                                                                          
          const AlternationInsn *alt = llvh::cast<AlternationInsn>(base);
          bool primaryViable =
              c.satisfiesConstraints(flags_, alt->primaryConstraints);
          bool secondaryViable =
              c.satisfiesConstraints(flags_, alt->secondaryConstraints);
          if (primaryViable && secondaryViable) {
                                                                           
                                                     
            s->ip_ += sizeof(AlternationInsn);
            auto res = pushBacktrack(
                backtrackStack,
                BacktrackInsn::makeSetPosition(
                    alt->secondaryBranch, c.currentPointer()));
            if (res != ExecutionStatus::RETURNED) {
              return res;
            }
          } else if (primaryViable) {
            s->ip_ += sizeof(AlternationInsn);
          } else if (secondaryViable) {
            s->ip_ = alt->secondaryBranch;
          } else {
            BACKTRACK();
          }
          break;
        }

        case Opcode::Jump32:
          s->ip_ = llvh::cast<Jump32Insn>(base)->target;
          break;

        case Opcode::Bracket: {
          if (c.atEnd() ||
              !matchWidth1<Width1Opcode::Bracket>(base, c.consume()))
            BACKTRACK();
          s->ip_ += llvh::cast<BracketInsn>(base)->totalWidth();
          break;
        }

        case Opcode::U16Bracket: {
          const U16BracketInsn *insn = llvh::cast<U16BracketInsn>(base);
                                                                     
          const BracketRange32 *ranges =
              reinterpret_cast<const BracketRange32 *>(insn + 1);
          if (c.atEnd() ||
              !bracketMatchesChar<Traits>(
                  *this, insn, ranges, c.consumeUTF16()))
            BACKTRACK();
          s->ip_ += insn->totalWidth();
          break;
        }

        case Opcode::WordBoundary: {
          const WordBoundaryInsn *insn = llvh::cast<WordBoundaryInsn>(base);
          const auto *charPointer = c.currentPointer();

          bool prevIsWordchar = false;
          if (!c.atLeft())
            prevIsWordchar = traits_.characterHasType(
                charPointer[-1], CharacterClass::Words);

          bool currentIsWordchar = false;
          if (!c.atRight())
            currentIsWordchar =
                traits_.characterHasType(charPointer[0], CharacterClass::Words);

          bool isWordBoundary = (prevIsWordchar != currentIsWordchar);
          if (isWordBoundary ^ insn->invert)
            s->ip_ += sizeof(WordBoundaryInsn);
          else
            BACKTRACK();
          break;
        }

        case Opcode::BeginMarkedSubexpression: {
          const auto *insn = llvh::cast<BeginMarkedSubexpressionInsn>(base);
          auto res = pushBacktrack(
              backtrackStack,
              BacktrackInsn::makeSetCaptureGroup(
                  insn->mexp, {kNotMatched, kNotMatched}));
          if (res != ExecutionStatus::RETURNED) {
            return res;
          }
                                                                                
                                                              
          auto &range = s->getCapturedRange(insn->mexp);
          if (c.forwards()) {
            range.start = c.offsetFromLeft();
          } else {
            range.end = c.offsetFromLeft();
          }
          s->ip_ += sizeof(BeginMarkedSubexpressionInsn);
          break;
        }

        case Opcode::EndMarkedSubexpression: {
          const auto *insn = llvh::cast<EndMarkedSubexpressionInsn>(base);
          auto &range = s->getCapturedRange(insn->mexp);
          if (c.forwards()) {
            assert(
                range.start != kNotMatched && "Capture group was not entered");
            range.end = c.offsetFromLeft();
          } else {
            assert(range.end != kNotMatched && "Capture group was not entered");
            range.start = c.offsetFromLeft();
          }
          assert(range.start <= range.end && "Captured range end before start");
          s->ip_ += sizeof(EndMarkedSubexpressionInsn);
          break;
        }

                          
        case Opcode::BackRef: {
          const auto insn = llvh::cast<BackRefInsn>(base);
                                             
                                
          CapturedRange cr = s->getCapturedRange(insn->mexp);

                                               
                                                                           
                                                                              
                                                                  
          if (cr.start == kNotMatched || cr.end == kNotMatched) {
                                                                          
                                      
            s->ip_ += sizeof(BackRefInsn);
            break;
          }

                                                                            
                  
          bool icase = syntaxFlags_.ignoreCase;
          bool unicode = syntaxFlags_.unicode;
          auto capturedStart = first_ + cr.start;
          auto capturedEnd = first_ + cr.end;
          Cursor<Traits> cursor2(
              capturedStart,
              c.forwards() ? capturedStart : capturedEnd,
              capturedEnd,
              c.forwards());
          Cursor<Traits> cursor1 = c;
          bool matched = true;
          while (matched && !cursor2.atEnd()) {
            if (cursor1.atEnd()) {
              matched = false;
            } else if (!icase) {
                                                                          
                       
              matched = (cursor1.consume() == cursor2.consume());
            } else if (!unicode) {
                                                                        
                                 
              auto c1 = cursor1.consume();
              auto c2 = cursor2.consume();
              matched =
                  (c1 == c2 ||
                   traits_.canonicalize(c1, unicode) ==
                       traits_.canonicalize(c2, unicode));
            } else {
                                                               
              auto cp1 = cursor1.consumeUTF16();
              auto cp2 = cursor2.consumeUTF16();
              matched =
                  (cp1 == cp2 ||
                   traits_.canonicalize(cp1, unicode) ==
                       traits_.canonicalize(cp2, unicode));
            }
          }
          if (!matched) {
            BACKTRACK();
          }
          s->ip_ += sizeof(BackRefInsn);
          c.setCurrentPointer(cursor1.currentPointer());
          break;
        }

        case Opcode::Lookaround: {
          const LookaroundInsn *insn = llvh::cast<LookaroundInsn>(base);
          bool matched = false;
          if (c.satisfiesConstraints(flags_, insn->constraints)) {
                                                                               
                                                               
            State savedState{*s};

                                               
            c.setForwards(insn->forwards);

                                                              
                                                                              
                        
            s->ip_ += sizeof(LookaroundInsn);
            auto match = this->match(s, true                  );
                                                                              
                                            
            if (LLVM_UNLIKELY(!match)) {
              return match.getStatus();
            }
                                                       
            matched = match.getValue() != nullptr;
            c.setCurrentPointer(savedState.cursor_.currentPointer());
            c.setForwards(savedState.cursor_.forwards());

                                                                              
                                                                               
                                                                                
                                                                        
                                                                                
                                                       
            if (matched && !insn->invert) {
                                                                      
              for (uint32_t i = insn->mexpBegin, e = insn->mexpEnd; i < e;
                   i++) {
                CapturedRange cr = savedState.getCapturedRange(i);
                auto res = pushBacktrack(
                    backtrackStack, BacktrackInsn::makeSetCaptureGroup(i, cr));
                if (res != ExecutionStatus::RETURNED)
                  return res;
              }
            } else {
                                         
              *s = std::move(savedState);
            }
          }

                                                                         
                                                                             
                                                                             
                                                                            
                                              
          if (matched ^ insn->invert)
            s->ip_ = insn->continuation;
          else
            BACKTRACK();
          break;
        }

        case Opcode::BeginLoop: {
                                                                            
                
          const BeginLoopInsn *loop = llvh::cast<BeginLoopInsn>(base);
          s->getLoop(loop->loopId).iterations = 0;
                                                                              
                                                                            
                                                                              
                                                                          
                                                                       
                                           
          if (!c.satisfiesConstraints(flags_, loop->loopeeConstraints)) {
            if (loop->min > 0) {
              BACKTRACK();
            } else {
              s->ip_ = loop->notTakenTarget;
              break;
            }
          }
          goto runLoop;
        }

        case Opcode::EndLoop:
                                                                         
                                                                  
          s->ip_ = llvh::cast<EndLoopInsn>(base)->target;
          base = reinterpret_cast<const Insn *>(&bytecode[s->ip_]);
          // Note fall through.

        runLoop: {
          const BeginLoopInsn *loop = llvh::cast<BeginLoopInsn>(base);
          auto &loopData = s->getLoop(loop->loopId);
          uint32_t iteration = loopData.iterations;

          const uint32_t loopTakenIp = s->ip_ + sizeof(BeginLoopInsn);

          assert(loop->min <= loop->max && "Inconsistent loop bounds");

                                                                           
                                                                            
                                                                      
                                                                       
                                                                           
                                                     
          if (iteration > loop->min &&
              loopData.entryPosition == c.offsetFromLeft())
            BACKTRACK();

          if (iteration < loop->min) {
            auto res = prepareToEnterLoopBody(s, loop, backtrackStack);
            if (res != ExecutionStatus::RETURNED)
              return res;
            s->ip_ = loopTakenIp;
          } else if (iteration == loop->max) {
            s->ip_ = loop->notTakenTarget;
          } else {
                                                                              
                                       
            assert(iteration >= loop->min && iteration < loop->max);
            if (!loop->greedy) {
                                                            
              loopData.entryPosition = c.offsetFromLeft();
              auto res = pushBacktrack(
                  backtrackStack,
                  BacktrackInsn::makeEnterNonGreedyLoop(
                      loop, loopTakenIp, loopData));
              if (res != ExecutionStatus::RETURNED) {
                return res;
              }
              s->ip_ = loop->notTakenTarget;
            } else {
                                                       
              auto pushRes = pushBacktrack(
                  backtrackStack,
                  BacktrackInsn::makeSetPosition(
                      loop->notTakenTarget, c.currentPointer()));
              if (pushRes != ExecutionStatus::RETURNED)
                return pushRes;

              auto prepRes = prepareToEnterLoopBody(s, loop, backtrackStack);
              if (prepRes != ExecutionStatus::RETURNED)
                return prepRes;
              s->ip_ = loopTakenIp;
            }
          }
          break;
        }

        case Opcode::BeginSimpleLoop: {
                                                             
                                      
          const BeginSimpleLoopInsn *loop =
              llvh::cast<BeginSimpleLoopInsn>(base);

          if (!c.satisfiesConstraints(flags_, loop->loopeeConstraints)) {
            s->ip_ = loop->notTakenTarget;
            break;
          }

          goto runSimpleLoop;
        }

        case Opcode::EndSimpleLoop:
          s->ip_ = llvh::cast<EndSimpleLoopInsn>(base)->target;
          base = reinterpret_cast<const Insn *>(&bytecode[s->ip_]);
          // Note: fall-through.

        runSimpleLoop: {
          const BeginSimpleLoopInsn *loop =
              llvh::cast<BeginSimpleLoopInsn>(base);
                                                                           
                                                                   
                                                 
          auto res = pushBacktrack(
              backtrackStack,
              BacktrackInsn::makeSetPosition(
                  loop->notTakenTarget, c.currentPointer()));
          if (res != ExecutionStatus::RETURNED) {
            return res;
          }
          s->ip_ += sizeof(BeginSimpleLoopInsn);
          break;
        }

        case Opcode::Width1Loop: {
          const Width1LoopInsn *loop = llvh::cast<Width1LoopInsn>(base);
          auto matchRes = matchWidth1Loop(loop, s, backtrackStack);
          if (LLVM_UNLIKELY(!matchRes))
            return matchRes.getStatus();
          if (!*matchRes)
            BACKTRACK();
          break;
        }
      }
    }
                                        
  backtrackingExhausted:
    continue;
  }
#undef BACKTRACK
                      
  return nullptr;
}

                                                                   
                                                                               
                                                                       
                                                                             
                                                                             
                    
template <typename CharT, class Traits>
MatchRuntimeResult searchWithBytecodeImpl(
    llvh::ArrayRef<uint8_t> bytecode,
    const CharT *first,
    uint32_t start,
    uint32_t length,
    std::vector<CapturedRange> *m,
    constants::MatchFlagType matchFlags,
    StackOverflowGuard guard) {
  assert(
      bytecode.size() >= sizeof(RegexBytecodeHeader) && "Bytecode too small");
  auto header = reinterpret_cast<const RegexBytecodeHeader *>(bytecode.data());

                                                              
  Cursor<Traits> cursor{
      first, first + start, first + length, true               };
  if (!cursor.satisfiesConstraints(matchFlags, header->constraints))
    return MatchRuntimeResult::NoMatch;

  auto markedCount = header->markedCount;
  auto loopCount = header->loopCount;

  Context<Traits> ctx(
      bytecode,
      matchFlags,
      SyntaxFlags::fromByte(header->syntaxFlags),
      first,
      first + length,
      header->markedCount,
      header->loopCount,
      guard);
  State<Traits> state{cursor, markedCount, loopCount};

                                                                                
                                                    
  bool onlyAtStart = (header->constraints & MatchConstraintAnchoredAtStart) ||
      (matchFlags & constants::matchOnlyAtStart);

  auto res = ctx.match(&state, onlyAtStart);
  if (!res) {
    assert(res.getStatus() == ExecutionStatus::STACK_OVERFLOW);
    return MatchRuntimeResult::StackOverflow;
  }
  if (const CharT *matchStartLoc = res.getValue()) {
                                                                            
                                             
    if (m != nullptr) {
      uint32_t totalStart = static_cast<uint32_t>(matchStartLoc - first);
      uint32_t totalEnd =
          static_cast<uint32_t>(state.cursor_.currentPointer() - first);
      m->clear();
      m->push_back(CapturedRange{totalStart, totalEnd});
      std::copy_n(
          state.capturedRanges_.begin(), markedCount, std::back_inserter(*m));
    }
    return MatchRuntimeResult::Match;
  }
  return MatchRuntimeResult::NoMatch;
}

MatchRuntimeResult searchWithBytecode(
    llvh::ArrayRef<uint8_t> bytecode,
    const char16_t *first,
    uint32_t start,
    uint32_t length,
    std::vector<CapturedRange> *m,
    constants::MatchFlagType matchFlags,
    StackOverflowGuard guard) {
  return searchWithBytecodeImpl<char16_t, UTF16RegexTraits>(
      bytecode, first, start, length, m, matchFlags, guard);
}

MatchRuntimeResult searchWithBytecode(
    llvh::ArrayRef<uint8_t> bytecode,
    const char *first,
    uint32_t start,
    uint32_t length,
    std::vector<CapturedRange> *m,
    constants::MatchFlagType matchFlags,
    StackOverflowGuard guard) {
  return searchWithBytecodeImpl<char, ASCIIRegexTraits>(
      bytecode, first, start, length, m, matchFlags, guard);
}

}                   
}                    

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Platform/Unicode/CharacterProperties.h"
#include "hermes/Platform/Unicode/CodePointSet.h"

#include "hermes/Regex/Regex.h"
#include "hermes/Regex/RegexTraits.h"
namespace hermes {
namespace regex {

using llvh::Optional;

                                                                         
                                                                
template <class RegexType, class ForwardIterator>
class Parser {
                                            
  using CharT = typename std::iterator_traits<ForwardIterator>::value_type;

                          
  using CodePoint = uint32_t;

                                     
  using Node = typename RegexType::Node;

                                  
                                                          
  struct ClassAtom {
    CodePoint codePoint = -1;
    llvh::Optional<CharacterClass> charClass{};
    llvh::Optional<CharacterClassCodepointRanges> codePointRanges{};

    explicit ClassAtom(CodePoint cp) : codePoint(cp) {}
    ClassAtom(CharacterClass::Type cc, bool invert)
        : charClass(CharacterClass(cc, invert)) {}
    ClassAtom(llvh::ArrayRef<UnicodeRangePoolRef> ranges, bool invert)
        : codePointRanges(CharacterClassCodepointRanges(ranges, invert)) {}
  };

                                                                      
                                                            
  RegexType *re_;

                                                             
  ForwardIterator current_;
  const ForwardIterator end_;

                                    
  constants::ErrorType error_ = constants::ErrorType::None;

                         
  const SyntaxFlags flags_;

                                   
  const uint32_t backRefLimit_;
  uint32_t maxBackRef_ = 0;

                                                                          
                                                                  
  bool hasNamedGroups_;

                                                                    
                                                   
                                     
  void setError(constants::ErrorType err) {
    if (error_ == constants::ErrorType::None) {
      error_ = err;
      current_ = end_;
    }
  }

                                    
                                                                         
  struct Quantifier {
                                      
    uint32_t min_ = 0;

                                                                      
    uint32_t max_ = std::numeric_limits<uint32_t>::max();

                                          
    bool greedy_ = true;

                                                                        
                                                                                
                                                               
    uint16_t startMarkedSubexprs_;

                                                                                
                                                                        
    Node *quantifiedNodeStart_ = nullptr;
  };

                                                               
  Quantifier prepareQuantifier() {
    Quantifier q;
    q.startMarkedSubexprs_ = re_->markedCount();
    q.quantifiedNodeStart_ = re_->currentNode();
    return q;
  }

                                                                            
                            
  void applyQuantifier(const Quantifier &quant) {
    if (quant.min_ > quant.max_) {
      setError(constants::ErrorType::BraceRange);
      return;
    }
    auto quantifiedExpression = re_->spliceOut(quant.quantifiedNodeStart_);
    re_->pushLoop(
        quant.min_,
        quant.max_,
        std::move(quantifiedExpression),
        quant.startMarkedSubexprs_,
        quant.greedy_);
  }

                                                                                
                            
  CharT consume(CharT c) {
    assert(check(c) && "Could not consume char");
    current_++;
    return c;
  }

                                          
                                                                        
  bool tryConsume(const char *seq) {
    auto cursor = current_;
    for (size_t i = 0; seq[i]; i++) {
      if (cursor == end_ || *cursor != seq[i])
        return false;
      ++cursor;
    }
    current_ = cursor;
    return true;
  }

                                            
                                                                        
  bool tryConsume(CharT c) {
    if (!check(c))
      return false;
    consume(c);
    return true;
  }

                                                        
                                                          
  bool check(CharT c) const {
    return current_ != end_ && *current_ == c;
  }

                                                                            
                                                             
                                                                          
  template <typename Pred>
  Optional<CharT> consumeCharIf(const Pred &pred) {
    if (current_ != end_ && pred(*current_)) {
      CharT c = *current_;
      consume(c);
      return c;
    }
    return llvh::None;
  }

                                                                          
                                                           
  struct ParseStackElement {
    enum Type {
                                              
      Alternation,

                                               
      CapturingGroup,

                                                              
      NamedCapturingGroup,

                                                     
      NonCapturingGroup,

                                      
                                
                                
                                  
                                  
      LookAround,

    } type;

                         
                                                                            
                                                                   
    Node *splicePoint{nullptr};

                                                                            
                                                                         
                                                     
                                         
    uint32_t mexp{0};

                                                             
                                                              
    Quantifier quant{};

                                                           
                                   
    std::vector<NodeList> alternatives;

                                                                            
                      
    bool negateLookaround;

                                                                           
    bool forwardLookaround;

    explicit ParseStackElement(Type type) : type(type) {}
  };

  using ParseStack = llvh::SmallVector<ParseStackElement, 4>;

                                                              
  void openAlternation(ParseStack &stack) {
                                                               
    assert(
        stack.empty() || stack.back().type != ParseStackElement::Alternation);
    ParseStackElement elem(ParseStackElement::Alternation);
    elem.splicePoint = re_->currentNode();
    stack.push_back(std::move(elem));
  }

                                                
  void closeAlternation(ParseStack &stack) {
    if (!stack.empty() && stack.back().type == ParseStackElement::Alternation) {
      auto alternatives = std::move(stack.back().alternatives);
      auto last = re_->spliceOut(stack.back().splicePoint);
      stack.pop_back();
      alternatives.push_back(std::move(last));
      re_->pushAlternation(std::move(alternatives));
    }
  }

                                                       
  void openCapturingGroup(ParseStack &stack) {
    ParseStackElement elem(ParseStackElement::CapturingGroup);
                                                                         
                                                                               
             
    elem.quant = prepareQuantifier();
    if (LLVM_UNLIKELY(re_->markedCount() >= constants::kMaxCaptureGroupCount)) {
      setError(constants::ErrorType::PatternExceedsParseLimits);
      return;
    }
    elem.mexp = re_->incrementMarkedCount();
    elem.splicePoint = re_->currentNode();
    stack.push_back(std::move(elem));
  }

                                                   
  void openNamedCapturingGroup(ParseStack &stack) {
    ParseStackElement elem(ParseStackElement::NamedCapturingGroup);
                                                                         
                                                                               
             
    elem.quant = prepareQuantifier();
    if (LLVM_UNLIKELY(re_->markedCount() >= constants::kMaxCaptureGroupCount)) {
      setError(constants::ErrorType::PatternExceedsParseLimits);
      return;
    }
    elem.mexp = re_->incrementMarkedCount();
    elem.splicePoint = re_->currentNode();

    GroupName identifier;
    if (!tryConsumeGroupName(identifier)) {
      setError(constants::ErrorType::InvalidCaptureGroupName);
      return;
    }

                                                                              
    if (!re_->addNamedCaptureGroup(std::move(identifier), elem.mexp)) {
      setError(constants::ErrorType::DuplicateCaptureGroupName);
      return;
    }

    hasNamedGroups_ = true;
    stack.push_back(std::move(elem));
  }
                                                           
  void openNonCapturingGroup(ParseStack &stack) {
    ParseStackElement elem(ParseStackElement::NonCapturingGroup);
    elem.quant = prepareQuantifier();
    elem.splicePoint = re_->currentNode();
    stack.push_back(std::move(elem));
  }

                                                  
  void openLookaround(ParseStack &stack, bool negate, bool forwards) {
    ParseStackElement elem(ParseStackElement::LookAround);
    elem.mexp = re_->markedCount();
    elem.forwardLookaround = forwards;
    elem.negateLookaround = negate;
    elem.quant = prepareQuantifier();
    elem.splicePoint = re_->currentNode();
    stack.push_back(std::move(elem));
  }

                                                                               
                     
  void closeGroup(ParseStack &stack) {
    assert(!stack.empty() && "Stack must not be empty");
    ParseStackElement elem = std::move(stack.back());
    stack.pop_back();
    bool quantifierAllowed = true;
    switch (elem.type) {
      case ParseStackElement::Alternation:
        llvm_unreachable("Alternations must be popped via closeAlternation()");
        break;

      case ParseStackElement::NamedCapturingGroup:
      case ParseStackElement::CapturingGroup:
        re_->pushMarkedSubexpression(
            re_->spliceOut(elem.splicePoint), elem.mexp);
        break;

      case ParseStackElement::NonCapturingGroup:
        break;

      case ParseStackElement::LookAround: {
        bool negate = elem.negateLookaround;
        bool forwards = elem.forwardLookaround;
                                                                   
                                               
        quantifierAllowed = !(flags_.unicode) && forwards;
        auto mexpStart = elem.mexp;
        auto mexpEnd = re_->markedCount();
        auto expr = re_->spliceOut(elem.splicePoint);
        re_->pushLookaround(
            std::move(expr), mexpStart, mexpEnd, negate, forwards);
        break;
      }
    }

                                                                  
    if (tryConsumeQuantifier(&elem.quant)) {
      if (!quantifierAllowed) {
        setError(constants::ErrorType::InvalidRepeat);
        return;
      }
      applyQuantifier(elem.quant);
    }
  }

                               
  void consumeDisjunction() {
    Node *const firstNode = re_->currentNode();
    ParseStack stack;

    while (current_ != end_) {
      switch (*current_) {
        case '|': {
          consume('|');
          auto *splicePoint =
              stack.empty() ? firstNode : stack.back().splicePoint;
          auto nodes = re_->spliceOut(splicePoint);
          if (stack.empty() ||
              stack.back().type != ParseStackElement::Alternation) {
                                     
            openAlternation(stack);
          }
          stack.back().alternatives.push_back(std::move(nodes));
          break;
        }

        case '(': {
                                                
          if (tryConsume("(?=")) {
                                                                  
            openLookaround(stack, false, true);
          } else if (tryConsume("(?!")) {
                                                                 
            openLookaround(stack, true, true);
          } else if (tryConsume("(?<=")) {
                                                                    
            openLookaround(stack, false, false);
          } else if (tryConsume("(?<!")) {
                                                                   
            openLookaround(stack, true, false);
          } else if (tryConsume("(?<")) {
            openNamedCapturingGroup(stack);
          } else if (tryConsume("(?:")) {
            openNonCapturingGroup(stack);
          } else {
            consume('(');
            openCapturingGroup(stack);
          }
          break;
        }

        case ')': {
                                                                  
                     
          consume(')');
          closeAlternation(stack);
          if (stack.empty()) {
            setError(constants::ErrorType::UnbalancedParenthesis);
            return;
          }
          closeGroup(stack);
          break;
        }
      }
      consumeTerm();
    }

    assert(current_ == end_ && "Should have consumed all input");
    closeAlternation(stack);
    if (!stack.empty()) {
      setError(constants::ErrorType::UnbalancedParenthesis);
    }
  }

                        
  void consumeTerm() {
    while (current_ != end_) {
      Quantifier quant = prepareQuantifier();
      bool quantifierAllowed = true;
      const CharT c = *current_;
      switch (c) {
        case '^':
          re_->pushLeftAnchor();
          consume('^');
          quantifierAllowed = false;
          break;

        case '$':
          re_->pushRightAnchor();
          consume('$');
          quantifierAllowed = false;
          break;

        case '\\': {
          consume('\\');
                                                                                
          if (current_ == end_) {
            setError(constants::ErrorType::EscapeIncomplete);
            return;
          } else if (*current_ == 'b' || *current_ == 'B') {
            re_->pushWordBoundary(*current_ == 'B'             );
            consume(*current_);
            quantifierAllowed = false;
          } else {
            consumeAtomEscape();
          }
          break;
        }

        case '.': {
          consume('.');
          re_->pushMatchAny();
          break;
        }

        case '[': {
          consumeCharacterClass();
          break;
        }

        case '*':
        case '+':
        case '?': {
          setError(constants::ErrorType::InvalidRepeat);
          return;
        }

        case '{': {
                                                    
                                                                         
                                              
          Quantifier tmp;
          if (tryConsumeQuantifier(&tmp)) {
            setError(constants::ErrorType::InvalidRepeat);
            return;
          } else if (flags_.unicode) {
            setError(constants::ErrorType::InvalidQuantifierBracket);
            return;
          }
          re_->pushChar(consume('{'));
          break;
        }

        case '|':
        case '(':
        case ')': {
                                                                             
                                                                               
                       
          return;
        }

        case '}':
        case ']': {
                                                            
                                                                    
                                                                              
                   
          if (flags_.unicode) {
            setError(
                c == '}' ? constants::ErrorType::InvalidQuantifierBracket
                         : constants::ErrorType::UnbalancedBracket);
            return;
          }
        }
          [[fallthrough]];

        default: {
                                                  
          if (auto cp = tryConsumeSurrogatePair()) {
            re_->pushChar(*cp);
          } else {
            re_->pushChar(consume(c));
          }
          break;
        }
      }

                                                           
      if (tryConsumeQuantifier(&quant)) {
        if (!quantifierAllowed) {
          setError(constants::ErrorType::InvalidRepeat);
          return;
        }
        applyQuantifier(quant);
      }
    }
  }

                                                         
  Optional<CodePoint> tryConsumeSurrogatePair() {
    if (!(flags_.unicode))
      return llvh::None;
    auto saved = current_;
    auto hi = consumeCharIf(isHighSurrogate);
    auto lo = consumeCharIf(isLowSurrogate);
    if (hi && lo) {
      return utf16SurrogatePairToCodePoint(*hi, *lo);
    }
    current_ = saved;
    return llvh::None;
  }

                                                                            
                                          
  bool tryConsumeAndAppendSurrogatePair(
      GroupName &str,
      bool (*lambdaPredicate)(uint32_t)) {
    auto saved = current_;
    auto hi = consumeCharIf(isHighSurrogate);
    auto lo = consumeCharIf(isLowSurrogate);
    if (hi && lo && lambdaPredicate(utf16SurrogatePairToCodePoint(*hi, *lo))) {
      str.push_back(*hi);
      str.push_back(*lo);
      return true;
    }
    current_ = saved;
    return false;
  }

                                        
                                                            
                          
  bool tryConsumeGroupName(GroupName &identifierName) {
    bool firstChar = true;
    for (;;) {
      if (current_ == end_) {
        return false;
      }
      const CharT c = *current_;
      switch (c) {
        case '>':
          if (identifierName.size() == 0) {
            return false;
          }
          consume('>');
          return true;
        default: {
          if (firstChar) {
            bool matchedIdentifierStart =
                tryConsumeRegExpIdentifier(identifierName, isUnicodeIDStart);
            if (!matchedIdentifierStart) {
              return false;
            }
          } else {
            bool matchedIdentifierPart =
                tryConsumeRegExpIdentifier(identifierName, isUnicodeIDContinue);
            if (!matchedIdentifierPart) {
              return false;
            }
          }
        }
      }
      firstChar = false;
    }
  }

                                                           
                                                                      
                                                                             
                           
  bool tryConsumeRegExpIdentifier(
      GroupName &identifierName,
      bool (*lambdaPredicate)(uint32_t)) {
    auto c = *current_;
    if (lambdaPredicate(c)) {
      consume(c);
      identifierName.push_back(c);
      return true;
    }
    auto saved = current_;
    if (tryConsume("\\") && check('u')) {
      if (auto cp = tryConsumeUnicodeEscapeSequence(true)) {
        if (!lambdaPredicate(*cp)) {
          return false;
        }
        writeCodePointToUTF16(*cp, identifierName);
        return true;
      }
      saved = current_;
    }
    if (tryConsumeAndAppendSurrogatePair(identifierName, lambdaPredicate)) {
      return true;
    }
    return false;
  }

  void writeCodePointToUTF16(uint32_t cp, GroupName &output) {
    assert(isValidCodePoint(cp) && "Invalid Unicode code point");
    if (cp <= 0x10000) {
      output.push_back((char16_t)cp);
      return;
    }
                                                                    
                       
    char16_t hi = (((cp - 0x10000) >> 10) & 0x3ff) + UTF16_HIGH_SURROGATE;
    char16_t lo = ((cp - 0x10000) & 0x3ff) + UTF16_LOW_SURROGATE;
    output.push_back(hi);
    output.push_back(lo);
  }

                              
  bool tryConsumeQuantifier(Quantifier *quantifier) {
    if (!tryConsumeQuantifierPrefix(quantifier)) {
      return false;
    }
    quantifier->greedy_ = !tryConsume('?');
    return true;
  }

                                    
  bool tryConsumeQuantifierPrefix(Quantifier *quantifier) {
    if (current_ == end_) {
      return false;
    }
    constexpr uint32_t uintmax = std::numeric_limits<uint32_t>::max();
    switch (*current_) {
      case '*':
        consume('*');
        quantifier->min_ = 0;
        quantifier->max_ = uintmax;
        return true;

      case '+':
        consume('+');
        quantifier->min_ = 1;
        quantifier->max_ = uintmax;
        return true;

      case '?':
        consume('?');
        quantifier->min_ = 0;
        quantifier->max_ = 1;
        return true;

      case '{': {
        auto saved = current_;
        consume('{');
        if (auto v1 = tryConsumeDecimalIntegerLiteral()) {
          quantifier->min_ = *v1;
          if (!tryConsume(',')) {
                       
            quantifier->max_ = *v1;
          } else if (auto v2 = tryConsumeDecimalIntegerLiteral()) {
                         
            quantifier->max_ = *v2;
          } else {
                        
            quantifier->max_ = uintmax;
          }
          if (tryConsume('}')) {
            return true;
          }
        }
        current_ = saved;
        return false;
      }

      default:
        return false;
    }
  }

                                   
  void consumeCharacterClass() {
    consume('[');
    bool unicode = flags_.unicode;
    bool negate = tryConsume('^');
    auto bracket = re_->startBracketList(negate);

                                                
    auto addClassAtom = [&bracket](const ClassAtom &atom) {
      if (atom.charClass) {
        bracket->addClass(*atom.charClass);
      } else if (atom.codePointRanges) {
        bracket->addCodePointRanges(
            atom.codePointRanges->rangeArray, atom.codePointRanges->inverted_);
      } else {
        bracket->addChar(atom.codePoint);
      }
      return true;
    };

    for (;;) {
      if (current_ == end_) {
        setError(constants::ErrorType::UnbalancedBracket);
        return;
      }

      if (tryConsume(']')) {
                          
        return;
      }

                                               
      Optional<ClassAtom> first = tryConsumeBracketClassAtom();
      if (!first)
        continue;

                               
      if (!tryConsume('-')) {
        if (!addClassAtom(*first)) {
          return;
        }
        continue;
      }

                                             
      Optional<ClassAtom> second = tryConsumeBracketClassAtom();
      if (!second) {
                                             
        addClassAtom(*first);
        addClassAtom(ClassAtom('-'));
        continue;
      }

                                    
      if (unicode &&
          (first->codePointRanges || second->codePointRanges ||
           first->charClass || second->charClass)) {
                                                                          
                                                           
        setError(constants::ErrorType::CharacterRange);
        return;
      }

      if (first->charClass || second->charClass) {
                                                                      
                                            
                                                                  
                   
                                                      
                                             
        addClassAtom(*first);
        addClassAtom(ClassAtom('-'));
        addClassAtom(*second);
        continue;
      }

                                                              
                                                
                                                                  
      if (first->codePoint > second->codePoint) {
        setError(constants::ErrorType::CharacterRange);
        return;
      }
                                       
      bracket->addRange(first->codePoint, second->codePoint);
    }
  }

  Optional<ClassAtom> tryConsumeBracketClassAtom() {
    if (current_ == end_) {
      return llvh::None;
    }
    CharT c = *current_;
    switch (c) {
      case ']': {
                                                         
        return llvh::None;
      }

      case '\\': {
        consume('\\');
        if (current_ == end_) {
          setError(constants::ErrorType::EscapeIncomplete);
          return llvh::None;
        }
        CharT ec = *current_;
        switch (ec) {
                                                   
                                                                    
          case 'd':
          case 'D': {
            consume(ec);
            return ClassAtom(CharacterClass::Digits, ec == 'D'             );
          }
          case 's':
          case 'S': {
            consume(ec);
            return ClassAtom(CharacterClass::Spaces, ec == 'S'             );
          }
          case 'w':
          case 'W': {
            consume(ec);
            return ClassAtom(CharacterClass::Words, ec == 'W'             );
          }

#ifdef HERMES_ENABLE_UNICODE_REGEXP_PROPERTY_ESCAPES
          case 'p':
          case 'P': {
            if (flags_.unicode) {
              consume(ec);
              std::string propertyName;
              std::string propertyValue;
              if (!tryConsume('{') ||
                  !tryConsumeUnicodePropertyValueExpression(
                      propertyName, propertyValue)) {
                setError(constants::ErrorType::InvalidPropertyName);
                return llvh::None;
              }

              auto codePointRanges =
                  unicodePropertyRanges(propertyName, propertyValue);
              if (codePointRanges.empty()) {
                setError(constants::ErrorType::InvalidPropertyName);
                return llvh::None;
              }
              return ClassAtom(codePointRanges, ec == 'P'             );
            } else {
                                                                            
                                      
              return ClassAtom(consumeCharacterEscape());
            }
          }
#endif

          case 'b': {
                                                                       
                                  
            consume('b');
            return ClassAtom(0x08);
          }

          case '-':
                                                                           
                    
            if ((flags_.unicode) && tryConsume('-')) {
              return ClassAtom('-');
            }
            [[fallthrough]];

          default: {
            return ClassAtom(consumeCharacterEscape());
          }
        }
      }

      default: {
                                                
        if (auto cp = tryConsumeSurrogatePair()) {
          return ClassAtom(*cp);
        } else {
          return ClassAtom(consume(c));
        }
      }
    }
  }

                                        
                                                                     
  CodePoint consumeLegacyOctalEscapeSequence() {
                                 
                                              
                                                          
                               
                                          
                                       
                                         
    if (flags_.unicode) {
      setError(constants::ErrorType::EscapeInvalid);
      return 0;
    }
    auto isOctalDigit = [](CharT c) { return '0' <= c && c <= '7'; };
    assert(
        current_ != end_ && isOctalDigit(*current_) &&
        "Should have leading octal digit");
    auto d1 = *current_++;
    auto d2 = consumeCharIf(isOctalDigit);
    auto d3 = (d1 <= '3' ? consumeCharIf(isOctalDigit) : llvh::None);

    char16_t result = d1 - '0';
    if (d2)
      result = result * 8 + (*d2 - '0');
    if (d3)
      result = result * 8 + (*d3 - '0');
    return result;
  }

                                        
                                                               
                                                 
  CodePoint consumeDecimalIntegerLiteral() {
    auto decimalDigit = [](CharT c) { return '0' <= c && c <= '9'; };
    assert(
        current_ != end_ && decimalDigit(*current_) &&
        "Not a decimal integer literal");
                                                                      
    const uint64_t u32max = std::numeric_limits<uint32_t>::max();
    uint64_t bigResult = 0;
    while (auto digit = consumeCharIf(decimalDigit)) {
      bigResult = bigResult * 10 + (*digit - '0');
      if (bigResult > u32max) {
        bigResult = u32max;
      }
    }
    return static_cast<uint32_t>(bigResult);
  }

                                        
  Optional<CodePoint> tryConsumeDecimalIntegerLiteral() {
    if (current_ != end_ && '0' <= *current_ && *current_ <= '9')
      return consumeDecimalIntegerLiteral();
    return llvh::None;
  }

                           
                                                                       
  Optional<CodePoint> tryConsumeHexDigits(uint32_t count) {
    auto hexDigitValue = [](CharT c) -> Optional<uint32_t> {
      if ('0' <= c && c <= '9')
        return c - '0';
      if ('a' <= c && c <= 'f')
        return c - 'a' + 10;
      if ('A' <= c && c <= 'F')
        return c - 'A' + 10;
      return llvh::None;
    };

    auto saved = current_;
    uint32_t result = 0;
    for (uint32_t i = 0; i < count; i++) {
      if (auto c = consumeCharIf(hexDigitValue)) {
        result = result * 16 + *hexDigitValue(*c);
      } else {
        current_ = saved;
        return llvh::None;
      }
    }
    return result;
  }

                                    
                                                                      
                                                                             
                                                                              
                                     
  CodePoint consumeCharacterEscape() {
    if (current_ == end_) {
      setError(constants::ErrorType::EscapeIncomplete);
      return 0;
    }
    const CharT c = *current_;
    switch (c) {
      case 'f':
        consume('f');
        return 0xC;
      case 'n':
        consume('n');
        return 0xA;
      case 'r':
        consume('r');
        return 0xD;
      case 't':
        consume('t');
        return 0x9;
      case 'v':
        consume('v');
        return 0xB;

      case 'c': {
        consume('c');
        auto isControlLetter = [](CharT c) {
          return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z');
        };
        if (auto cc = consumeCharIf(isControlLetter)) {
          return *cc % 32;
        } else {
          return identityEscape('c');
        }
      }

      case '0': {
                                                             
        auto saved = current_;
        consume('0');
        if (current_ == end_ || !('0' <= *current_ && *current_ <= '9')) {
          return '\0';
        } else {
          current_ = saved;
          return consumeLegacyOctalEscapeSequence();
        }
      }

      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7': {
        return consumeLegacyOctalEscapeSequence();
      }

      case 'u': {
        if (auto ret = tryConsumeUnicodeEscapeSequence()) {
          return *ret;
        } else {
                           
          return identityEscape(consume(c));
        }
      }

      case 'x': {
        consume(c);
        if (auto ret = tryConsumeHexDigits(2)) {
          return *ret;
        } else {
                                                   
                                                                            
                            
          return identityEscape(c);
        }
      }

      default: {
                         
        return identityEscape(consume(c));
      }
    }
  }

                               
  CodePoint identityEscape(CharT c) {
                                                                         
    if (flags_.unicode) {
      if (c == 0 || c > 127 || !strchr("^$\\.*+?()[]{}|/", c)) {
        setError(constants::ErrorType::EscapeInvalid);
      }
    }
                                          
    return c;
  }

                                               
  Optional<CodePoint> tryConsumeUnicodeEscapeSequence(
      bool overrideUnicodeFlag = false) {
    auto saved = current_;
    if (!consume('u')) {
      return llvh::None;
    }

                                                           
    if (!overrideUnicodeFlag && !(flags_.unicode)) {
      if (auto ret = tryConsumeHexDigits(4)) {
        return *ret;
      }
      current_ = saved;
      return llvh::None;
    }

                    
                                           
                                                                               
                                                                            
    if (tryConsume('{')) {
      uint32_t result = 0;
      size_t digitCount = 0;
      while (auto digit = tryConsumeHexDigits(1)) {
        digitCount++;
        result = result * 16 + *digit;
                                                                          
        if (result > 1114111) {
          setError(constants::ErrorType::EscapeOverflow);
          return 0;
        }
      }
      if (!tryConsume('}')) {
        setError(constants::ErrorType::EscapeInvalid);
        return 0;
      }
      if (digitCount == 0) {
                              
        setError(constants::ErrorType::EscapeInvalid);
        return 0;
      }
      return result;
    }

                                      
    if (auto hi = tryConsumeHexDigits(4)) {
      if (isHighSurrogate(*hi)) {
                                       
                                         
        auto saved2 = current_;
        if (tryConsume("\\u")) {
          if (auto lo = tryConsumeHexDigits(4)) {
            if (isLowSurrogate(*lo)) {
              return utf16SurrogatePairToCodePoint(*hi, *lo);
            }
          }
        }
                                 
        current_ = saved2;
      }
      return *hi;
    }

                                                             
    setError(constants::ErrorType::EscapeInvalid);
    return 0;
  }

  bool tryConsumeUnicodeProperty(
      std::string &propertyName,
      std::string &propertyValue) {
    if (current_ == end_) {
      return false;
    }

    while (auto ch = consumeCharIf(isUnicodePropertyName)) {
      propertyName.push_back(*ch);
    }
    if (tryConsume('=')) {
      while (auto ch = consumeCharIf(isUnicodePropertyValue)) {
        propertyValue.push_back(*ch);
      }
      return !propertyValue.empty();
    }

    return true;
  }

                                                  
                                                
                                                                             
                                                          
  bool tryConsumeUnicodePropertyValueExpression(
      std::string &propertyName,
      std::string &propertyValue) {
    assert(
        flags_.unicode &&
        "Non-unicode regexps do not support property escapes");

                    
                                                                                
    if (!tryConsumeUnicodeProperty(propertyName, propertyValue)) {
      setError(constants::ErrorType::InvalidPropertyName);
      return false;
    }

    if (!tryConsume('}')) {
      setError(constants::ErrorType::InvalidPropertyName);
      return false;
    }
    return true;
  }

                          
                                           
  void consumeAtomEscape() {
    if (current_ == end_) {
      setError(constants::ErrorType::EscapeIncomplete);
      return;
    }

    CharT c = *current_;
    switch (c) {
      case 'd':
      case 'D':
        consume(c);
        re_->pushCharClass({CharacterClass::Digits, c == 'D'             });
        break;

      case 's':
      case 'S':
        consume(c);
        re_->pushCharClass({CharacterClass::Spaces, c == 'S'             });
        break;

      case 'w':
      case 'W':
        consume(c);
        re_->pushCharClass({CharacterClass::Words, c == 'W'             });
        break;

#ifdef HERMES_ENABLE_UNICODE_REGEXP_PROPERTY_ESCAPES
      case 'p':
      case 'P': {
        if (flags_.unicode) {
          consume(c);
          std::string propertyName;
          std::string propertyValue;
          if (!tryConsume('{') ||
              !tryConsumeUnicodePropertyValueExpression(
                  propertyName, propertyValue)) {
            setError(constants::ErrorType::InvalidPropertyName);
            return;
          }
          auto bracket = re_->startBracketList(c == 'P'             );
          auto codePointRanges =
              unicodePropertyRanges(propertyName, propertyValue);
          if (codePointRanges.empty()) {
            setError(constants::ErrorType::InvalidPropertyName);
            return;
          }
          bracket->addCodePointRanges(codePointRanges);
          break;
        } else {
                                                                        
                                  
          re_->pushChar(consumeCharacterEscape());
        }
        break;
      }
#endif

                                                    
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9': {
                                                           
                                                                             
                                                                               
                                                                 
        auto saved = current_;
        uint32_t decimal = consumeDecimalIntegerLiteral();
        bool unicode = flags_.unicode;
        if (unicode || decimal <= backRefLimit_) {
                           
          maxBackRef_ = std::max(maxBackRef_, decimal);
                                                                            
                                             
          re_->pushBackRef(decimal - 1);
        } else if (c < '8' && !unicode) {
                   
          current_ = saved;
          re_->pushChar(consumeLegacyOctalEscapeSequence());
        } else {
                            
          current_ = saved;
          re_->pushChar(identityEscape(consume(c)));
        }
        break;
      }

      case 'k': {
        if (flags_.unicode || hasNamedGroups_) {
          consume('k');
          GroupName refIdentifer;
          if (!tryConsume('<') || !tryConsumeGroupName(refIdentifer)) {
            setError(constants::ErrorType::InvalidNamedReference);
            return;
          }
          re_->pushNamedBackRef(std::move(refIdentifer));
          break;
        }
        re_->sawNamedBackrefBeforeGroup();
                                                                             
                                                                   
        [[fallthrough]];
      }
      default: {
        re_->pushChar(consumeCharacterEscape());
        break;
      }
    }
  }

 public:
                                                                         
                                                                      
                                                  
  Parser(
      RegexType *re,
      ForwardIterator start,
      ForwardIterator end,
      SyntaxFlags flags,
      uint32_t backRefLimit,
      bool hasNamedGroups)
      : re_(re),
        current_(start),
        end_(end),
        flags_(flags),
        backRefLimit_(backRefLimit),
        hasNamedGroups_(hasNamedGroups) {}

  constants::ErrorType performParse() {
    consumeDisjunction();
    assert(
        current_ == end_ && "We should always consume all input even on error");
    return error_;
  }

                                                              
  uint32_t maxBackRef() const {
    return maxBackRef_;
  }
};

template <typename Receiver>
constants::ErrorType parseRegex(
    const char16_t *start,
    const char16_t *end,
    Receiver *receiver,
    SyntaxFlags flags,
    uint32_t backRefLimit,
    bool hasNamedGroups,
    uint32_t *outMaxBackRef) {
  Parser<Receiver, const char16_t *> parser(
      receiver, start, end, flags, backRefLimit, hasNamedGroups);
  auto result = parser.performParse();
  *outMaxBackRef = parser.maxBackRef();
  return result;
}

                                                               
template constants::ErrorType parseRegex(
    const char16_t *start,
    const char16_t *end,
    Regex<UTF16RegexTraits> *receiver,
    SyntaxFlags flags,
    uint32_t backRefLimit,
    bool hasNamedGroups,
    uint32_t *outMaxBackRef);

}                   
}                    

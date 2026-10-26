/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Parser/JSLexer.h"
#include "hermes/Platform/Unicode/CharacterProperties.h"

#include "dtoa/dtoa.h"
#include "hermes/Support/Conversions.h"

#include "llvh/ADT/ScopeExit.h"
#include "llvh/ADT/StringSwitch.h"

namespace hermes {
namespace parser {

namespace {

                                                                         
                                                                          
                                                                                
inline bool isLexerIDStart(uint32_t cp) {
  return isUnicodeIDStart(cp) || cp==0x1885 || cp==0x1886 ||
      cp==0x2118 || cp==0x212e || cp==0x309b || cp==0x309c;
}
inline bool isLexerIDContinue(uint32_t cp) {
  return isUnicodeIDContinue(cp) || isLexerIDStart(cp) ||
      cp==0x00b7 || cp==0x0387 || (cp>=0x1369 && cp<=0x1371) || cp==0x19da;
}


const char *g_tokenStr[] = {
#define TOK(name, str) str,
#include "hermes/Parser/TokenKinds.def"
};

const int UTF8_LINE_TERMINATOR_CHAR0 = 0xe2;

inline bool matchUnicodeLineTerminatorOffset1(const char *curCharPtr_) {
                                                          
                                                         
  return (unsigned char)curCharPtr_[1] == 0x80 &&
      ((unsigned char)curCharPtr_[2] == 0xa8 ||
       (unsigned char)curCharPtr_[2] == 0xa9);
}
}             

const char *tokenKindStr(TokenKind kind) {
  assert(kind <= TokenKind::_last_token);
  return g_tokenStr[static_cast<unsigned>(kind)];
}

#if HERMES_PARSE_JSX
static llvh::DenseMap<llvh::StringRef, uint32_t> initializeHTMLEntities() {
  llvh::DenseMap<llvh::StringRef, uint32_t> entities{};

#define HTML_ENTITY(NAME, VALUE) \
  entities.insert({llvh::StringLiteral(#NAME), VALUE});
#include "hermes/Parser/HTMLEntities.def"

  return entities;
}

static const llvh::DenseMap<llvh::StringRef, uint32_t> &getHTMLEntities() {
  static const auto entities = initializeHTMLEntities();
  return entities;
}
#endif

JSLexer::JSLexer(
    uint32_t bufId,
    SourceErrorManager &sm,
    Allocator &allocator,
    StringTable *strTab,
    bool strictMode,
    bool convertSurrogates)
    : sm_(sm),
      allocator_(allocator),
      ownStrTab_(strTab ? nullptr : new StringTable(allocator_)),
      strTab_(strTab ? *strTab : *ownStrTab_),
#if HERMES_PARSE_JSX
      htmlEntities_(getHTMLEntities()),
#endif
      strictMode_(strictMode),
      convertSurrogates_(convertSurrogates) {
  initializeWithBufferId(bufId);
  initializeReservedIdentifiers();
}

JSLexer::JSLexer(
    std::unique_ptr<llvh::MemoryBuffer> input,
    SourceErrorManager &sm,
    Allocator &allocator,
    StringTable *strTab,
    bool strictMode,
    bool convertSurrogates)
    : sm_(sm),
      allocator_(allocator),
      ownStrTab_(strTab ? nullptr : new StringTable(allocator_)),
      strTab_(strTab ? *strTab : *ownStrTab_),
#if HERMES_PARSE_JSX
      htmlEntities_(getHTMLEntities()),
#endif
      strictMode_(strictMode),
      convertSurrogates_(convertSurrogates) {
  auto bufId = sm_.addNewSourceBuffer(std::move(input));
  initializeWithBufferId(bufId);
  initializeReservedIdentifiers();
}

void JSLexer::initializeWithBufferId(uint32_t bufId) {
  auto *buffer = sm_.getSourceBuffer(bufId);
  bufId_ = bufId;
  bufferStart_ = buffer->getBufferStart();
  bufferEnd_ = buffer->getBufferEnd();
  curCharPtr_ = bufferStart_;
  assert(*bufferEnd_ == 0 && "buffer must be zero terminated");
}

void JSLexer::initializeReservedIdentifiers() {
                                                   
#define RESWORD(name) resWordIdent(TokenKind::rw_##name) = getIdentifier(#name);
#include "hermes/Parser/TokenKinds.def"
}

bool JSLexer::isLetFollowedByDeclStart() {
  assert(
      token_.getKind() == TokenKind::identifier &&
      token_.getIdentifier()->str() == "let");

                                                                                
                                                                    
                                  
                              
                                                      
  auto optimisticSkipWhitespace = [this]() -> char {
    while (char cur = *curCharPtr_) {
      switch (cur) {
        case ' ':
        case '\t':
        case '\v':
        case '\f':
          ++curCharPtr_;
          continue;

        default:
          return cur;
      }
    }
    return '\0';
  };

  const char curChar = optimisticSkipWhitespace();

               
                                                                    
                                                                    
  if (curChar == '{' || curChar == '[') {
    return true;
  }

               
                                                      
                                
                                                                   
                                                  
  if (isASCIIIdentifierStart(curChar)) {
                                                                                
                                                
    if (!(curChar == 'i' && curCharPtr_[1] == 'n')) {
      return true;
    }
  }

               
                                                               
                                                                             
                                      
                                        
          
             
                                                                 
                                                                 
  OptValue<TokenKind> nextTokenKind =
      lookahead1<                      false>(llvh::None);
  return nextTokenKind.hasValue() &&
      (*nextTokenKind == TokenKind::identifier ||
       *nextTokenKind == TokenKind::l_brace ||
       *nextTokenKind == TokenKind::l_square);
}

const Token *JSLexer::advance(GrammarContext grammarContext) {
  newLineBeforeCurrentToken_ = false;

  for (;;) {
    assert(curCharPtr_ <= bufferEnd_ && "lexing past end of input");
#define PUNC_L1_1(ch, tok)        \
  case ch:                        \
    token_.setStart(curCharPtr_); \
    token_.setPunctuator(tok);    \
    ++curCharPtr_;                \
    break

#define PUNC_L2_3(ch1, tok1, ch2a, tok2a, ch2b, tok2b) \
  case ch1:                                            \
    token_.setStart(curCharPtr_);                      \
    if (curCharPtr_[1] == ch2a) {                      \
      token_.setPunctuator(tok2a);                     \
      curCharPtr_ += 2;                                \
    } else if (curCharPtr_[1] == ch2b) {               \
      token_.setPunctuator(tok2b);                     \
      curCharPtr_ += 2;                                \
    } else {                                           \
      token_.setPunctuator(tok1);                      \
      curCharPtr_ += 1;                                \
    }                                                  \
    break

#define PUNC_L2_2(ch1, tok1, ch2, tok2) \
  case ch1:                             \
    token_.setStart(curCharPtr_);       \
    if (curCharPtr_[1] == (ch2)) {      \
      token_.setPunctuator(tok2);       \
      curCharPtr_ += 2;                 \
    } else {                            \
      token_.setPunctuator(tok1);       \
      curCharPtr_ += 1;                 \
    }                                   \
    break

#define PUNC_L3_3(ch1, tok1, ch2, tok2, ch3, tok3) \
  case ch1:                                        \
    token_.setStart(curCharPtr_);                  \
    if (curCharPtr_[1] != (ch2)) {                 \
      token_.setPunctuator(tok1);                  \
      curCharPtr_ += 1;                            \
    } else if (curCharPtr_[2] == (ch3)) {          \
      token_.setPunctuator(tok3);                  \
      curCharPtr_ += 3;                            \
    } else {                                       \
      token_.setPunctuator(tok2);                  \
      curCharPtr_ += 2;                            \
    }                                              \
    break

    switch ((unsigned char)*curCharPtr_) {
      case 0:
        token_.setStart(curCharPtr_);
        if (curCharPtr_ == bufferEnd_) {
          token_.setEof();
        } else {
          if (!error(
                  token_.getStartLoc(),
                  "unrecognized Unicode character \\u0000")) {
            token_.setEof();
          } else {
            ++curCharPtr_;
            continue;
          }
        }
        break;

        // clang-format off
      PUNC_L1_1('}', TokenKind::r_brace);
      PUNC_L1_1('(', TokenKind::l_paren);
      PUNC_L1_1(')', TokenKind::r_paren);
      PUNC_L1_1('[', TokenKind::l_square);
      PUNC_L1_1(']', TokenKind::r_square);
      PUNC_L1_1(';', TokenKind::semi);
      PUNC_L1_1(',', TokenKind::comma);
      PUNC_L1_1('~', TokenKind::tilde);
      PUNC_L1_1(':', TokenKind::colon);

             
      case '{':
        token_.setStart(curCharPtr_);
        if (HERMES_PARSE_FLOW &&
            LLVM_UNLIKELY(grammarContext == GrammarContext::Type) &&
            curCharPtr_[1] == '|') {
          token_.setPunctuator(TokenKind::l_bracepipe);
          curCharPtr_ += 2;
        } else {
          token_.setPunctuator(TokenKind::l_brace);
          curCharPtr_ += 1;
        }
        break;

                    
      case '=':
        token_.setStart(curCharPtr_);
        if (curCharPtr_[1] == '>') {
          token_.setPunctuator(TokenKind::equalgreater);
          curCharPtr_ += 2;
        } else if (curCharPtr_[1] != '=') {
          token_.setPunctuator(TokenKind::equal);
          curCharPtr_ += 1;
        } else if (curCharPtr_[2] == '=') {
          token_.setPunctuator(TokenKind::equalequalequal);
          curCharPtr_ += 3;
        } else {
          token_.setPunctuator(TokenKind::equalequal);
          curCharPtr_ += 2;
        }
        break;

                 
      PUNC_L3_3('!', TokenKind::exclaim, '=', TokenKind::exclaimequal, '=', TokenKind::exclaimequalequal);

                
                
                
                
      PUNC_L2_3('+', TokenKind::plus,  '+', TokenKind::plusplus,   '=', TokenKind::plusequal);
      PUNC_L2_3('-', TokenKind::minus, '-', TokenKind::minusminus, '=', TokenKind::minusequal);

      case '&':
        token_.setStart(curCharPtr_);
        if (curCharPtr_[1] == '&') {
          if (curCharPtr_[2] == '=') {
            token_.setPunctuator(TokenKind::ampampequal);
            curCharPtr_ += 3;
          } else {
            token_.setPunctuator(TokenKind::ampamp);
            curCharPtr_ += 2;
          }
        } else if (curCharPtr_[1] == '=') {
          token_.setPunctuator(TokenKind::ampequal);
          curCharPtr_ += 2;
        } else {
          token_.setPunctuator(TokenKind::amp);
          curCharPtr_ += 1;
        }
        break;

      case '|':
        token_.setStart(curCharPtr_);
        if (HERMES_PARSE_FLOW &&
            LLVM_UNLIKELY(grammarContext == GrammarContext::Type) &&
            curCharPtr_[1] == '}') {
          token_.setPunctuator(TokenKind::piper_brace);
          curCharPtr_ += 2;
        } else {
          if (curCharPtr_[1] == '|') {
            if (curCharPtr_[2] == '=') {
              token_.setPunctuator(TokenKind::pipepipeequal);
              curCharPtr_ += 3;
            } else {
              token_.setPunctuator(TokenKind::pipepipe);
              curCharPtr_ += 2;
            }
          } else if (curCharPtr_[1] == '=') {
            token_.setPunctuator(TokenKind::pipeequal);
            curCharPtr_ += 2;
          } else {
            token_.setPunctuator(TokenKind::pipe);
            curCharPtr_ += 1;
          }
        }
        break;

                
      case '?':
        token_.setStart(curCharPtr_);
        if (curCharPtr_[1] == '.' && !isdigit(curCharPtr_[2])) {
                                          
                                                         
                                                                   
                                                     
          token_.setPunctuator(TokenKind::questiondot);
          curCharPtr_ += 2;
        } else if (
            curCharPtr_[1] == '?' &&
            LLVM_LIKELY(grammarContext != GrammarContext::Type)) {
          if (curCharPtr_[2] == '=') {
            token_.setPunctuator(TokenKind::questionquestionequal);
            curCharPtr_ += 3;
          } else {
            token_.setPunctuator(TokenKind::questionquestion);
            curCharPtr_ += 2;
          }
        } else {
          token_.setPunctuator(TokenKind::question);
          curCharPtr_ += 1;
        }
        break;

                    
      case '*':
        token_.setStart(curCharPtr_);
        if (curCharPtr_[1] == '=') {
          token_.setPunctuator(TokenKind::starequal);
          curCharPtr_ += 2;
        } else if (curCharPtr_[1] != '*') {
          token_.setPunctuator(TokenKind::star);
          curCharPtr_ += 1;
        } else if (curCharPtr_[2] == '=') {
          token_.setPunctuator(TokenKind::starstarequal);
          curCharPtr_ += 3;
        } else {
          token_.setPunctuator(TokenKind::starstar);
          curCharPtr_ += 2;
        }
        break;

               
               
               
        PUNC_L2_2('^', TokenKind::caret, '=', TokenKind::caretequal);

             
      case '%':
        token_.setStart(curCharPtr_);
        if (HERMES_PARSE_FLOW &&
            LLVM_UNLIKELY(grammarContext == GrammarContext::Type) &&
            curCharPtr_ + 7 <= bufferEnd_ &&
            llvh::StringRef(curCharPtr_, 7) == "%checks") {
          token_.setIdentifier(getStringLiteral("%checks"));
          curCharPtr_ += 7;
        } else if (curCharPtr_[1] == ('=')) {
          token_.setPunctuator(TokenKind::percentequal);
          curCharPtr_ += 2;
        } else {
          token_.setPunctuator(TokenKind::percent);
          curCharPtr_ += 1;
        }
        break;

        // clang-format on

      case '\r':
      case '\n':
        ++curCharPtr_;
        newLineBeforeCurrentToken_ = true;
        continue;

                                                              
                                                              
      case UTF8_LINE_TERMINATOR_CHAR0:
        if (matchUnicodeLineTerminatorOffset1(curCharPtr_)) {
          curCharPtr_ += 3;
          newLineBeforeCurrentToken_ = true;
          continue;
        } else {
          goto default_label;
        }

      case '\v':
      case '\f':
        ++curCharPtr_;
        continue;

      case '\t':
      case ' ':
                                                                               
        do
          ++curCharPtr_;
        while (*curCharPtr_ == '\t' || *curCharPtr_ == ' ');
        continue;

                                                        
      case 0xc2:
        if ((unsigned char)curCharPtr_[1] == 0xa0) {
          curCharPtr_ += 2;
          continue;
        } else {
          goto default_label;
        }

                                                       
      case 0xef:
        if ((unsigned char)curCharPtr_[1] == 0xbb &&
            (unsigned char)curCharPtr_[2] == 0xbf) {
          curCharPtr_ += 3;
          continue;
        } else {
          goto default_label;
        }

      case '/':
        if (curCharPtr_[1] == '/') {                 
          scanLineComment(curCharPtr_);
          continue;
        } else if (curCharPtr_[1] == '*') {                  
          curCharPtr_ = skipBlockComment(curCharPtr_);
          continue;
        } else {
          token_.setStart(curCharPtr_);
          if (grammarContext == AllowRegExp) {
            scanRegExp();
          } else if (curCharPtr_[1] == '=') {
            token_.setPunctuator(TokenKind::slashequal);
            curCharPtr_ += 2;
          } else {
            token_.setPunctuator(TokenKind::slash);
            curCharPtr_ += 1;
          }
        }
        break;

      case '#':
        if (LLVM_UNLIKELY(
                curCharPtr_ == bufferStart_ && curCharPtr_[1] == '!')) {
                                                           
          scanLineComment(curCharPtr_);
          continue;
        }
        token_.setStart(curCharPtr_);
        if (!scanPrivateIdentifier()) {
          continue;
        }
        break;

                     
      case '<':
        token_.setStart(curCharPtr_);
        if (HERMES_PARSE_FLOW &&
            LLVM_UNLIKELY(grammarContext == JSLexer::GrammarContext::Type)) {
          token_.setPunctuator(TokenKind::less);
          curCharPtr_ += 1;
        } else if (curCharPtr_[1] == '=') {
          token_.setPunctuator(TokenKind::lessequal);
          curCharPtr_ += 2;
        } else if (curCharPtr_[1] == '<') {
          if (curCharPtr_[2] == '=') {
            token_.setPunctuator(TokenKind::lesslessequal);
            curCharPtr_ += 3;
          } else {
            token_.setPunctuator(TokenKind::lessless);
            curCharPtr_ += 2;
          }
        } else {
          token_.setPunctuator(TokenKind::less);
          curCharPtr_ += 1;
        }
        break;

                             
      case '>':
        token_.setStart(curCharPtr_);
        if ((HERMES_PARSE_FLOW &&
             LLVM_UNLIKELY(grammarContext == JSLexer::GrammarContext::Type)) ||
            (HERMES_PARSE_JSX &&
             LLVM_UNLIKELY(
                 grammarContext ==
                 JSLexer::GrammarContext::AllowJSXIdentifier))) {
          token_.setPunctuator(TokenKind::greater);
          curCharPtr_ += 1;
        } else if (curCharPtr_[1] == '=') {      
          token_.setPunctuator(TokenKind::greaterequal);
          curCharPtr_ += 2;
        } else if (curCharPtr_[1] == '>') {      
          if (curCharPtr_[2] == '=') {       
            token_.setPunctuator(TokenKind::greatergreaterequal);
            curCharPtr_ += 3;
          } else if (curCharPtr_[2] == '>') {       
            if (curCharPtr_[3] == '=') {        
              token_.setPunctuator(TokenKind::greatergreatergreaterequal);
              curCharPtr_ += 4;
            } else {
              token_.setPunctuator(TokenKind::greatergreatergreater);
              curCharPtr_ += 3;
            }
          } else {
            token_.setPunctuator(TokenKind::greatergreater);
            curCharPtr_ += 2;
          }
        } else {
          token_.setPunctuator(TokenKind::greater);
          curCharPtr_ += 1;
        }
        break;

      case '.':
        token_.setStart(curCharPtr_);
        if (curCharPtr_[1] >= '0' && curCharPtr_[1] <= '9') {
          scanNumber(grammarContext);
        } else if (curCharPtr_[1] == '.' && curCharPtr_[2] == '.') {
          token_.setPunctuator(TokenKind::dotdotdot);
          curCharPtr_ += 3;
        } else {
          token_.setPunctuator(TokenKind::period);
          ++curCharPtr_;
        }
        break;

        // clang-format off
      case '0': case '1': case '2': case '3': case '4':
      case '5': case '6': case '7': case '8': case '9':
        // clang-format on
        token_.setStart(curCharPtr_);
        scanNumber(grammarContext);
        break;

        // clang-format off
      case '_': case '$':
      case 'a': case 'b': case 'c': case 'd': case 'e': case 'f': case 'g':
      case 'h': case 'i': case 'j': case 'k': case 'l': case 'm': case 'n':
      case 'o': case 'p': case 'q': case 'r': case 's': case 't': case 'u':
      case 'v': case 'w': case 'x': case 'y': case 'z':
      case 'A': case 'B': case 'C': case 'D': case 'E': case 'F': case 'G':
      case 'H': case 'I': case 'J': case 'K': case 'L': case 'M': case 'N':
      case 'O': case 'P': case 'Q': case 'R': case 'S': case 'T': case 'U':
      case 'V': case 'W': case 'X': case 'Y': case 'Z':
        // clang-format on
        token_.setStart(curCharPtr_);
        scanIdentifierFastPathInContext(curCharPtr_, grammarContext);
        break;

      case '@':
        token_.setStart(curCharPtr_);
        if (HERMES_PARSE_FLOW &&
            LLVM_UNLIKELY(grammarContext == GrammarContext::Type)) {
          scanIdentifierFastPathInContext(curCharPtr_, grammarContext);
        } else {
          curCharPtr_ += 1;
          errorRange(token_.getStartLoc(), "unrecognized character '@'");
          continue;
        }
        break;

      case '\\': {
        token_.setStart(curCharPtr_);
        tmpStorage_.clear();
        uint32_t cp = consumeUnicodeEscape();
        if (!isLexerIDStart(cp)) {
          errorRange(
              token_.getStartLoc(),
              "Unicode escape \\u" + Twine::utohexstr(cp) +
                  " is not a valid identifier start");
          continue;
        } else {
          appendUnicodeToStorage(cp);
        }
        scanIdentifierPartsInContext(grammarContext);
        break;
      }

      case '\'':
      case '"':
        token_.setStart(curCharPtr_);
        scanStringInContext(grammarContext);
        break;

      case '`':
        token_.setStart(curCharPtr_);
        scanTemplateLiteral();
        break;

      default_label:
      default: {
        token_.setStart(curCharPtr_);
        uint32_t ch = decodeUTF8();

        if (isLexerIDStart(ch)) {
          tmpStorage_.clear();
          appendUnicodeToStorage(ch);
          scanIdentifierPartsInContext(grammarContext);
        } else if (isUnicodeOnlySpace(ch)) {
          continue;
        } else {
          if (ch > 31 && ch < 127)
            errorRange(
                token_.getStartLoc(),
                "unrecognized character '" + Twine((char)ch) + "'");
          else
            errorRange(
                token_.getStartLoc(),
                "unrecognized Unicode character \\u" + Twine::utohexstr(ch));
          continue;
        }

        break;
      }
    }

                                                            
    break;
  }           

  finishToken(curCharPtr_);

  return &token_;
}

#if HERMES_PARSE_JSX

const Token *JSLexer::advanceInJSXChild() {
  token_.setStart(curCharPtr_);
  for (;;) {
    assert(curCharPtr_ <= bufferEnd_ && "lexing past end of input");
    switch (*curCharPtr_) {
      PUNC_L1_1('{', TokenKind::l_brace);
      PUNC_L1_1('<', TokenKind::less);

      case 0:
        if (curCharPtr_ == bufferEnd_) {
          token_.setEof();
          break;
        }
        // Fall-through to start scanning text.
        [[fallthrough]];

      default: {
        const char *start = curCharPtr_;
        token_.setStart(start);

                                                     
        tmpStorage_.clear();
        rawStorage_.clear();
        for (;;) {
          char c = *curCharPtr_;

          if (LLVM_UNLIKELY(isUTF8Start(*curCharPtr_))) {
            uint32_t codepoint = _decodeUTF8SlowPath(curCharPtr_);
            appendUnicodeToStorage(codepoint);
            appendUnicodeToStorage(codepoint, rawStorage_);
            continue;
          } else if (c == '&') {
            const char *htmlStart = curCharPtr_;
            auto codePoint = consumeHTMLEntityOptional();
            if (codePoint.hasValue()) {
              appendUnicodeToStorage(*codePoint);
              rawStorage_.append(
                  {htmlStart, (size_t)(curCharPtr_ - htmlStart)});
              continue;
            }
          } else if (
              (c == 0 && curCharPtr_ == bufferEnd_) || c == '{' || c == '<') {
            token_.setJSXText(
                getStringLiteral(tmpStorage_.str()),
                getStringLiteral(rawStorage_.str()));
            break;
          }
          tmpStorage_.push_back(c);
          rawStorage_.push_back(c);
          ++curCharPtr_;
        }
        break;
      }
    }

                                                            
    break;
  }
  finishToken(curCharPtr_);
  return &token_;
}

llvh::Optional<uint32_t> JSLexer::consumeHTMLEntityOptional() {
  assert(*curCharPtr_ == '&');
  const char *start = curCharPtr_;

  if (curCharPtr_[1] == '#') {
    if (curCharPtr_[2] == 'x') {
                                       
      curCharPtr_ += 3;
      const char *numberStart = curCharPtr_;

      uint32_t codePoint = 0;
      char ch = *curCharPtr_;

                                                                               
                     
      for (;;) {
        if (ch == ';' && curCharPtr_ != numberStart) {
          curCharPtr_++;
          return codePoint;
        } else if (isdigit(ch)) {
          ch -= '0';
        } else {
          ch |= 32;
          if (ch >= 'a' && ch <= 'f') {
            ch -= 'a' - 10;
          } else {
            break;
          }
        }

                                                                  
        codePoint = (codePoint << 4) + ch;
        if (codePoint > UNICODE_MAX_VALUE) {
          break;
        }

        ++curCharPtr_;
        ch = *curCharPtr_;
      }
    } else {
                                        
      curCharPtr_ += 2;
      const char *numberStart = curCharPtr_;

      uint32_t codePoint = 0;
      char ch = *curCharPtr_;

                                                                                
                        
      for (;;) {
        if (ch == ';' && curCharPtr_ != numberStart) {
          curCharPtr_++;
          return codePoint;
        } else if (isdigit(ch)) {
                                                                    
          codePoint = codePoint * 10 + (ch - '0');
          if (codePoint > UNICODE_MAX_VALUE) {
            break;
          }
        } else {
          break;
        }

        ++curCharPtr_;
        ch = *curCharPtr_;
      }
    }
  } else {
                                   
    ++curCharPtr_;

                                                                              
                                                                              
                                                                            
                                                                           
                                  
    for (int i = 0; i < 9; i++) {
      char ch = *curCharPtr_;
      if (ch == ';') {
        auto it = htmlEntities_.find(llvh::StringRef(curCharPtr_ - i, i));
        if (it == htmlEntities_.end()) {
          break;
        }

        curCharPtr_++;
        return it->second;
      } else if (((ch | 32) >= 'a' && (ch | 32) <= 'z') || isdigit(ch)) {
        ++curCharPtr_;
      } else {
        break;
      }
    }
  }

  curCharPtr_ = start;
  return llvh::None;
}

#endif

bool JSLexer::isCurrentTokenADirective() {
                                                                
  if (token_.getKind() != TokenKind::string_literal ||
      token_.getStringLiteralContainsEscapes()) {
    return false;
  }

  const char *ptr = curCharPtr_;

                                                                        
                                                                             
                                                                               
                        
                                         
                                               
                                                 
                                                
                                                                           
                                                
                                                  

  for (;;) {
    assert(ptr <= bufferEnd_ && "lexing past end of input");

    switch (*((const unsigned char *)ptr)) {
      case 0:
               
        if (ptr == bufferEnd_)
          return true;
                                              
        return false;

      case ';':
      case '}':
        return true;

      case '\r':
      case '\n':
        return true;

                                                              
                                                              
      case UTF8_LINE_TERMINATOR_CHAR0:
        if (matchUnicodeLineTerminatorOffset1(ptr))
          return true;
        return false;

      case '\v':
      case '\f':
                           
        ++ptr;
        continue;

      case '\t':
      case ' ':
                                                                               
        do
          ++ptr;
        while (*ptr == '\t' || *ptr == ' ');
        continue;

                                                        
      case 0xc2:
        if ((unsigned char)ptr[1] == 0xa0) {
          ptr += 2;
          continue;
        } else {
          goto default_label;
        }

                                                       
      case 0xef:
        if ((unsigned char)ptr[1] == 0xbb && (unsigned char)ptr[2] == 0xbf) {
          ptr += 3;
          continue;
        } else {
          goto default_label;
        }

      case '/':
        if (ptr[1] == '/') {                 
                                                   
          return true;
        } else if (ptr[1] == '*') {                  
          auto savedCommentStorageSize = commentStorage_.size();
          auto commentScope = llvh::make_scope_exit([&] {
            if (storeComments_)
              commentStorage_.erase(
                  commentStorage_.begin() + savedCommentStorageSize,
                  commentStorage_.end());
          });
          SourceErrorManager::SaveAndSuppressMessages suppress(&sm_);
          ptr = skipBlockComment(ptr);
          continue;
        } else {
          return false;
        }

                                                                        
                                  
      default_label:
      default: {
        if (hermes::isUTF8Start(*ptr)) {
          auto peeked = _peekUTF8(ptr);
          if (isUnicodeOnlySpace(peeked.first)) {
            ptr = peeked.second;
            continue;
          }
        }
        return false;
      }
    }
  }

                                                                            
  return true;
}

const Token *JSLexer::rescanRBraceInTemplateLiteral() {
  assert(token_.getKind() == TokenKind::r_brace && "need } to rescan");
  --curCharPtr_;
                                  
  if (LLVM_UNLIKELY(storeTokens_)) {
    tokenStorage_.pop_back();
  }
  assert(*curCharPtr_ == '}' && "non-} was scanned as r_brace");
  token_.setStart(curCharPtr_);
  scanTemplateLiteral();
  finishToken(curCharPtr_);
  return &token_;
}

template <bool RequireNoNewLine>
OptValue<TokenKind> JSLexer::lookahead1(OptValue<TokenKind> expectedToken) {
                                                                        
                                                                            
                                                                        
                                                                             
                                                                           
                                                                          
  assert(
      (token_.getKind() == TokenKind::identifier || token_.isResWord() ||
       token_.getKind() == TokenKind::question) &&
      "unsupported current token");
  UniqueString *savedIdent;
  if (token_.getKind() == TokenKind::identifier || token_.isResWord()) {
    savedIdent = token_.getResWordOrIdentifier();
  }
  TokenKind savedKind = token_.getKind();
  SMLoc start = token_.getStartLoc();
  SMLoc end = token_.getEndLoc();
  const char *cur = curCharPtr_;
  SourceErrorManager::SaveAndSuppressMessages suppress(&sm_);

                                                              
  auto savedCommentStorageSize = commentStorage_.size();
  auto commentScope = llvh::make_scope_exit([&] {
    if (storeComments_)
      commentStorage_.erase(
          commentStorage_.begin() + savedCommentStorageSize,
          commentStorage_.end());
  });

  advance();
  OptValue<TokenKind> kind = token_.getKind();
  if (RequireNoNewLine && isNewLineBeforeCurrentToken()) {
                                               
    kind = llvh::None;
  } else if (expectedToken == kind) {
                                   
    return kind;
  }

  token_.setStart(start.getPointer());
  token_.setEnd(end.getPointer());
  if (savedKind == TokenKind::identifier) {
    token_.setIdentifier(savedIdent);
  } else if (savedKind == TokenKind::question) {
    token_.setPunctuator(TokenKind::question);
  } else {
    token_.setResWord(savedKind, savedIdent);
  }
  seek(SMLoc::getFromPointer(cur));

                                                        
  if (LLVM_UNLIKELY(storeTokens_)) {
    tokenStorage_.pop_back();
  }

  return kind;
}

template OptValue<TokenKind> JSLexer::lookahead1<true>(OptValue<TokenKind>);
template OptValue<TokenKind> JSLexer::lookahead1<false>(OptValue<TokenKind>);

uint32_t JSLexer::consumeUnicodeEscape() {
  assert(*curCharPtr_ == '\\');
  ++curCharPtr_;

  if (*curCharPtr_ != 'u') {
    error(
        {SMLoc::getFromPointer(curCharPtr_ - 1),
         SMLoc::getFromPointer(curCharPtr_ + 1)},
        "invalid Unicode escape");
    return UNICODE_REPLACEMENT_CHARACTER;
  }
  ++curCharPtr_;

  if (*curCharPtr_ == '{') {
    auto cp = consumeBracedCodePoint();
    if (!cp.hasValue()) {
                                                      
      return UNICODE_REPLACEMENT_CHARACTER;
    }
    return *cp;
  }

  auto cp = consumeHex(4);
  if (!cp)
    return UNICODE_REPLACEMENT_CHARACTER;

                                                                                
                                                                           
                                                                                
                                                                               
             
  return cp.getValue();
}

llvh::Optional<uint32_t> JSLexer::consumeUnicodeEscapeOptional() {
  const char *start = curCharPtr_;
  assert(*curCharPtr_ == '\\');
  ++curCharPtr_;

  if (*curCharPtr_ != 'u') {
    curCharPtr_ = start;
    return llvh::None;
  }
  ++curCharPtr_;

  if (*curCharPtr_ == '{') {
                                                                               
    auto cp = consumeBracedCodePoint(false);
    if (!cp) {
      curCharPtr_ = start;
      return llvh::None;
    }
    return *cp;
  }

  auto cp = consumeHex(4, false);
  if (!cp) {
    curCharPtr_ = start;
    return llvh::None;
  }

                                                                                
                                                                           
                                                                                
                                                                               
             
  return cp.getValue();
}

bool JSLexer::consumeIdentifierStart() {
  if (*curCharPtr_ == '_' || *curCharPtr_ == '$' ||
      ((*curCharPtr_ | 32) >= 'a' && (*curCharPtr_ | 32) <= 'z')) {
    tmpStorage_.clear();
    tmpStorage_.push_back(*curCharPtr_++);
    return true;
  }

  if (*curCharPtr_ == '\\') {
    SMLoc startLoc = SMLoc::getFromPointer(curCharPtr_);
    tmpStorage_.clear();
    uint32_t cp = consumeUnicodeEscape();
    if (!isLexerIDStart(cp)) {
      errorRange(
          startLoc,
          "Unicode escape \\u" + Twine::utohexstr(cp) +
              "is not a valid identifier start");
    } else {
      appendUnicodeToStorage(cp);
    }
    return true;
  }

  if (LLVM_LIKELY(!isUTF8Start(*curCharPtr_)))
    return false;

  auto decoded = _peekUTF8();
  if (isLexerIDStart(decoded.first)) {
    tmpStorage_.clear();
    appendUnicodeToStorage(decoded.first);
    curCharPtr_ = decoded.second;
    return true;
  }

  return false;
}

template <JSLexer::IdentifierMode Mode>
bool JSLexer::consumeOneIdentifierPartNoEscape() {
  char ch = *curCharPtr_;
  if (ch == '_' || ch == '$' || ((ch | 32) >= 'a' && (ch | 32) <= 'z') ||
      (ch >= '0' && ch <= '9') || (Mode == IdentifierMode::JSX && ch == '-') ||
      (Mode == IdentifierMode::Flow && ch == '@')) {
    tmpStorage_.push_back(*curCharPtr_++);
    return true;
  } else if (LLVM_UNLIKELY(isUTF8Start(ch))) {
                                                                             
                                                                            
             
    auto decoded = _peekUTF8();
    if (isLexerIDContinue(decoded.first)) {
      appendUnicodeToStorage(decoded.first);
      curCharPtr_ = decoded.second;
      return true;
    }
  }
  return false;
}

template <JSLexer::IdentifierMode Mode>
void JSLexer::consumeIdentifierParts() {
  for (;;) {
                                                                               
              
    if (consumeOneIdentifierPartNoEscape<Mode>())
      continue;
    else if (*curCharPtr_ == '\\') {
                           
      SMLoc startLoc = SMLoc::getFromPointer(curCharPtr_);
      uint32_t cp = consumeUnicodeEscape();
      if (!isLexerIDContinue(cp)) {
        errorRange(
            startLoc,
            "Unicode escape \\u" + Twine::utohexstr(cp) +
                " is not a valid identifier codepoint");
      } else {
        appendUnicodeToStorage(cp);
      }
    } else
      break;
  }
}

unsigned char JSLexer::consumeOctal(unsigned maxLen) {
  assert(*curCharPtr_ >= '0' && *curCharPtr_ <= '7');

  if (strictMode_) {
    if (!error(
            SMLoc::getFromPointer(curCharPtr_ - 1),
            "octals not allowed in strict mode")) {
      return 0;
    }
  }

  auto res = (unsigned char)(*curCharPtr_++ - '0');
  while (--maxLen && *curCharPtr_ >= '0' && *curCharPtr_ <= '7')
    res = (res << 3) + *curCharPtr_++ - '0';

  return res;
}

llvh::Optional<uint32_t> JSLexer::consumeHex(
    unsigned requiredLen,
    bool errorOnFail) {
  uint32_t cp = 0;
  for (unsigned i = 0; i != requiredLen; ++i) {
    unsigned ch = *curCharPtr_;
    if (ch >= '0' && ch <= '9') {
      ch -= '0';
    } else {
                                                                     
      ch |= 32;
      if (ch >= 'a' && ch <= 'f') {
        ch -= 'a' - 10;
      } else {
        if (errorOnFail) {
          error(SMLoc::getFromPointer(curCharPtr_), "invalid hex number");
        }
        return llvh::None;
      }
    }
    cp = (cp << 4) + ch;
    ++curCharPtr_;
  }

  return cp;
}

llvh::Optional<uint32_t> JSLexer::consumeBracedCodePoint(bool errorOnFail) {
  assert(*curCharPtr_ == '{' && "braced codepoint must begin with {");
  ++curCharPtr_;
  const char *start = curCharPtr_;

                                                                          
                          
  bool failed = false;

                                                                               
  uint32_t cp = 0;
  for (; *curCharPtr_ != '}'; ++curCharPtr_) {
    int ch = *curCharPtr_;
    if (ch >= '0' && ch <= '9') {
      ch -= '0';
    } else if (ch >= 'a' && ch <= 'f') {
      ch -= 'a' - 10;
    } else if (ch >= 'A' && ch <= 'F') {
      ch -= 'A' - 10;
    } else {
                                                                           
                                                                         
                                                             
      if (curCharPtr_ == bufferEnd_) {
        if (!failed && errorOnFail) {
          error(
              SMLoc::getFromPointer(start),
              "non-terminated unicode codepoint escape");
        }
        return llvh::None;
      }
                                                             
      if (!failed && errorOnFail) {
        if (!error(
                SMLoc::getFromPointer(curCharPtr_),
                "invalid character in unicode codepoint escape")) {
          return llvh::None;
        }
      }
      failed = true;
      continue;
    }
    cp = (cp << 4) + ch;
    if (cp > UNICODE_MAX_VALUE) {
                                                               
      if (!failed && errorOnFail) {
        if (!error(
                SMLoc::getFromPointer(start),
                "unicode codepoint escape is too large")) {
          return llvh::None;
        }
      }
      failed = true;
    }
  }

  assert(curCharPtr_ < bufferEnd_ && "bufferEnd_ should cause early return");

                                         
  if (curCharPtr_ == start) {
    if (!failed && errorOnFail) {
      if (!error(
              SMLoc::getFromPointer(start), "empty unicode codepoint escape")) {
        return llvh::None;
      }
    }
    failed = true;
  }

                                    
  ++curCharPtr_;
  return failed ? llvh::None : llvh::Optional<uint32_t>{cp};
}

llvh::StringRef JSLexer::lineCommentHelper(const char *start) {
  assert(
      (start[0] == '/' && start[1] == '/') ||
      (start[0] == '#' && start[1] == '!'));
  const char *lineCommentEnd;
  const char *cur = start + 2;

  for (;;) {
    switch ((unsigned char)*cur) {
      case 0:
        if (cur == bufferEnd_) {
          lineCommentEnd = cur;
          goto endLoop;
        } else {
          ++cur;
        }
        break;

      case '\r':
      case '\n':
        lineCommentEnd = cur;
        ++cur;
        newLineBeforeCurrentToken_ = true;
        goto endLoop;

                                                                
                                                               
      case UTF8_LINE_TERMINATOR_CHAR0:
        if (matchUnicodeLineTerminatorOffset1(cur)) {
          lineCommentEnd = cur;
          cur += 3;
          newLineBeforeCurrentToken_ = true;
          goto endLoop;
        } else {
          _decodeUTF8SlowPath(cur);
        }
        break;

      default:
        if (LLVM_UNLIKELY(isUTF8Start(*cur)))
          _decodeUTF8SlowPath(cur);
        else
          ++cur;
        break;
    }
  }
endLoop:

  curCharPtr_ = cur;
  return llvh::StringRef(start, lineCommentEnd - start);
}

void JSLexer::scanLineComment(const char *start) {
  llvh::StringRef comment = lineCommentHelper(start);

  if (storeComments_) {
    commentStorage_.emplace_back(
        start[0] == '/' ? StoredComment::Kind::Line
                        : StoredComment::Kind::Hashbang,
        SMRange{
            SMLoc::getFromPointer(comment.begin()),
            SMLoc::getFromPointer(comment.end())});
  }

                                                 
                             
  if (!comment.consume_front(llvh::StringLiteral("//# ")))
    return;

  if (comment.consume_front(llvh::StringLiteral("sourceURL="))) {
    sourceURL_ = comment;
#ifndef STATIC_HERMES
    sm_.setSourceUrl(bufId_, comment);
#endif
  } else if (comment.consume_front(llvh::StringLiteral("sourceMappingURL="))) {
    sourceMappingURL_ = comment;
#ifndef STATIC_HERMES
    sm_.setSourceMappingUrl(bufId_, comment);
#endif
  }
}

const char *JSLexer::skipBlockComment(const char *start) {
  assert(start[0] == '/' && start[1] == '*');
  SMLoc blockCommentStart = SMLoc::getFromPointer(start);
  const char *cur = start + 2;

  for (;;) {
    switch ((unsigned char)*cur) {
      case 0:
        if (cur == bufferEnd_) {
          error(SMLoc::getFromPointer(cur), "non-terminated block comment");
          sm_.note(blockCommentStart, "comment started here");
          goto endLoop;
        } else {
          ++cur;
        }
        break;

      case '\r':
      case '\n':
        ++cur;
        newLineBeforeCurrentToken_ = true;
        break;

                                                              
                                                             
      case UTF8_LINE_TERMINATOR_CHAR0:
        if (matchUnicodeLineTerminatorOffset1(cur)) {
          cur += 3;
          newLineBeforeCurrentToken_ = true;
        } else {
          _decodeUTF8SlowPath(cur);
        }
        break;

      case '*':
        ++cur;
        if (*cur == '/') {
          ++cur;
          goto endLoop;
        }
        break;

      default:
        if (LLVM_UNLIKELY(isUTF8Start(*cur)))
          _decodeUTF8SlowPath(cur);
        else
          ++cur;
        break;
    }
  }
endLoop:

  if (storeComments_) {
    commentStorage_.emplace_back(
        StoredComment::Kind::Block,
        SMRange{blockCommentStart, SMLoc::getFromPointer(cur)});
  }

  return cur;
}

void JSLexer::scanNumber(GrammarContext grammarContext) {
                                                        

  unsigned radix = 10;
  bool real = false;
  bool ok = true;
  const char *rawStart = curCharPtr_;
  const char *start = curCharPtr_;

                                                               
  bool seenSeparator = false;

                                                                    
  bool legacyOctal = false;

                     
  if (*curCharPtr_ == '0') {
    if ((curCharPtr_[1] | 32) == 'x') {
      radix = 16;
      curCharPtr_ += 2;
      start += 2;
    } else if ((curCharPtr_[1] | 32) == 'o') {
      radix = 8;
      curCharPtr_ += 2;
      start += 2;
    } else if ((curCharPtr_[1] | 32) == 'b') {
      radix = 2;
      curCharPtr_ += 2;
      start += 2;
    } else if (curCharPtr_[1] == '.') {
      curCharPtr_ += 2;
      goto fraction;
    } else if ((curCharPtr_[1] | 32) == 'e') {
      curCharPtr_ += 2;
      goto exponent;
    } else {
      radix = 8;
      legacyOctal = true;
      ++curCharPtr_;
    }
  }

  while (isdigit(*curCharPtr_) ||
         (radix == 16 && (*curCharPtr_ | 32) >= 'a' &&
          (*curCharPtr_ | 32) <= 'f') ||
         (*curCharPtr_ == '_')) {
    seenSeparator |= *curCharPtr_ == '_';
    ++curCharPtr_;
  }

  if (radix == 10 || legacyOctal) {
                                        
                                                                          
                               
    if (*curCharPtr_ == '.') {
      ++curCharPtr_;
      goto fraction;
    }

    if ((*curCharPtr_ | 32) == 'e') {
      ++curCharPtr_;
      goto exponent;
    }
  }

  goto end;

fraction:
                                                               
    
  real = true;
  while (isdigit(*curCharPtr_) || *curCharPtr_ == '_') {
    seenSeparator |= *curCharPtr_ == '_';
    ++curCharPtr_;
  }

  if ((*curCharPtr_ | 32) == 'e') {
    ++curCharPtr_;
    goto exponent;
  } else {
    goto end;
  }

exponent:
                                                                             
    
  real = true;
  if (*curCharPtr_ == '+' || *curCharPtr_ == '-')
    ++curCharPtr_;
  if (isdigit(*curCharPtr_)) {
    do {
      seenSeparator |= *curCharPtr_ == '_';
      ++curCharPtr_;
    } while (isdigit(*curCharPtr_) || *curCharPtr_ == '_');
  } else {
    ok = false;
  }

end:
                                                                           
                                                                            
                                                                           
  if (consumeIdentifierStart()) {
    consumeIdentifierParts<IdentifierMode::JS>();

    llvh::StringRef raw{rawStart, (size_t)(curCharPtr_ - rawStart)};
    if (ok && !real && (!legacyOctal || raw == "0n") && tmpStorage_ == "n") {
      assert(curCharPtr_ > start && "Must consume at least the trailing n.");
      llvh::ArrayRef<char> digits{start, curCharPtr_ - 1};
                                                                             
                                                                             
                                                 
      if (digits.size() &&
          parseIntWithRadixDigits<                            true>(
              digits, radix, [](uint8_t) {})) {
                            
        rawStorage_.clear();
        rawStorage_.append(raw);
        token_.setBigIntLiteral(getStringLiteral(rawStorage_));
        return;
      }

                                                    
    }

    ok = false;
  }

  double val;

                 
                                                                          
                                                                 
  const auto updateLegacyOctalRadix =
      [this, &radix, start, &legacyOctal]() -> void {
    assert(
        legacyOctal &&
        "updateLegacyOctalRadix can only be called in legacyOctal mode");
    (void)legacyOctal;
    for (auto *scanPtr = start; scanPtr != curCharPtr_; ++scanPtr) {
      if (*scanPtr == '.' || *scanPtr == 'e') {
        break;
      }
      if (LLVM_UNLIKELY(*scanPtr >= '8') && LLVM_LIKELY(*scanPtr != '_')) {
        sm_.warning(
            SMRange(token_.getStartLoc(), SMLoc::getFromPointer(curCharPtr_)),
            "Numeric literal starts with 0 but contains an 8 or 9 digit. "
            "Interpreting as decimal (not octal).");
        radix = 10;
        break;
      }
    }
  };

  if (!ok) {
    errorRange(token_.getStartLoc(), "invalid numeric literal");
    val = std::numeric_limits<double>::quiet_NaN();
  } else if (
      !real && radix == 10 && curCharPtr_ - start <= 9 &&
      LLVM_LIKELY(!seenSeparator)) {
                                                                           
                                                            
    int32_t ival = *start - '0';
    while (++start != curCharPtr_)
      ival = ival * 10 + (*start - '0');
    val = ival;
  } else if (real || radix == 10) {
    if (legacyOctal) {
      if (strictMode_ || grammarContext == GrammarContext::Type) {
        if (!errorRange(
                token_.getStartLoc(),
                "Decimals with leading zeros are not allowed in strict mode")) {
          val = std::numeric_limits<double>::quiet_NaN();
          goto done;
        }
      } else {
                                                                 
                                                                      
        updateLegacyOctalRadix();
        if (LLVM_LIKELY(radix != 10)) {
          if (!errorRange(
                  token_.getStartLoc(),
                  "Octal numeric literals must be integers")) {
            val = std::numeric_limits<double>::quiet_NaN();
            goto done;
          }
        }
      }
    }

                                                              
    llvh::SmallString<32> buf;
    buf.reserve(curCharPtr_ - start + 1);
    if (LLVM_UNLIKELY(seenSeparator)) {
      for (const char *it = start; it != curCharPtr_; ++it) {
        if (LLVM_LIKELY(*it != '_')) {
          buf.push_back(*it);
        } else {
                                                              
                                                                          
                                                                    
                                                                         
                                                     
          char prev = *(it - 1);
          char next = *(it + 1);
          if (!isdigit(prev) &&
              !(radix == 16 && 'a' <= (prev | 32) && (prev | 32) <= 'f')) {
            errorRange(
                token_.getStartLoc(),
                "numeric separator must come after a digit");
          } else if (
              !isdigit(next) &&
              !(radix == 16 && 'a' <= (next | 32) && (next | 32) <= 'f')) {
            errorRange(
                token_.getStartLoc(),
                "numeric separator must come before a digit");
          }
        }
      }
    } else {
      buf.append(start, curCharPtr_);
    }
    buf.push_back(0);
    char *endPtr;
    val = ::hermes_g_strtod(buf.data(), &endPtr);
    if (endPtr != &buf.back()) {
      errorRange(token_.getStartLoc(), "invalid numeric literal");
      val = std::numeric_limits<double>::quiet_NaN();
    }
  } else {
    if (legacyOctal &&
        (strictMode_ || grammarContext == GrammarContext::Type) &&
        curCharPtr_ - start > 1) {
      if (!errorRange(
              token_.getStartLoc(),
              "Octal literals must use '0o' in strict mode")) {
        val = std::numeric_limits<double>::quiet_NaN();
        goto done;
      }
    }

                                                                       
                                                          
    if (curCharPtr_ == start) {
      errorRange(
          token_.getStartLoc(),
          llvh::Twine("No digits after ") + llvh::StringRef(start - 2, 2));
      val = std::numeric_limits<double>::quiet_NaN();
    } else {
                                      
      if (legacyOctal) {
        updateLegacyOctalRadix();
                                                                          
        if (LLVM_UNLIKELY(seenSeparator)) {
          errorRange(
              token_.getStartLoc(),
              "Numeric separator cannot be used in literal after leading 0");
        }
      }
      auto parsedInt = parseIntWithRadix<                            true>(
          llvh::ArrayRef<char>{start, (size_t)(curCharPtr_ - start)}, radix);
      if (!parsedInt) {
        errorRange(token_.getStartLoc(), "invalid integer literal");
        val = std::numeric_limits<double>::quiet_NaN();
      } else {
        val = parsedInt.getValue();
      }
    }
  }

done:
  token_.setNumericLiteral(val);
}

static TokenKind matchReservedWord(const char *str, unsigned len) {
  return llvh::StringSwitch<TokenKind>(llvh::StringRef(str, len))
#define RESWORD(name) .Case(#name, TokenKind::rw_##name)
#include "hermes/Parser/TokenKinds.def"
      .Default(TokenKind::identifier);
}

TokenKind JSLexer::scanReservedWord(const char *start, unsigned length) {
  TokenKind rw = matchReservedWord(start, length);

                                                                             
                 
  if (!strictMode_ && rw != TokenKind::identifier) {
    switch (rw) {
      case TokenKind::rw_implements:
      case TokenKind::rw_interface:
      case TokenKind::rw_package:
      case TokenKind::rw_private:
      case TokenKind::rw_protected:
      case TokenKind::rw_public:
      case TokenKind::rw_static:
      case TokenKind::rw_yield:
        rw = TokenKind::identifier;
        break;
      default:
        break;
    }
  }
  return rw;
}

template <JSLexer::IdentifierMode Mode>
void JSLexer::scanIdentifierFastPath(const char *start) {
  const char *end = start;

                                               
  char ch;
  do
    ch = (unsigned char)*++end;
  while (ch == '_' || ch == '$' || ((ch | 32) >= 'a' && (ch | 32) <= 'z') ||
         (ch >= '0' && ch <= '9') ||
         (Mode == IdentifierMode::JSX && ch == '-') ||
         (Mode == IdentifierMode::Flow && ch == '@'));

                                                         
  if (LLVM_UNLIKELY(ch == '\\')) {
                                                  
    initStorageWith(start, end);
    curCharPtr_ = end;
    scanIdentifierParts<Mode>();
    return;
  } else if (LLVM_UNLIKELY(isUTF8Start(ch))) {
                                                                             
                                       
                                                  
    auto decoded = _peekUTF8(end);
    if (isLexerIDContinue(decoded.first)) {
      initStorageWith(start, end);
      appendUnicodeToStorage(decoded.first);
      curCharPtr_ = decoded.second;
      scanIdentifierParts<Mode>();
      return;
    }
  }

  curCharPtr_ = end;

  size_t length = end - start;

  auto rw = scanReservedWord(start, (unsigned)length);
  if (rw != TokenKind::identifier) {
    token_.setResWord(rw, resWordIdent(rw));
  } else {
    token_.setIdentifier(getIdentifier(llvh::StringRef(start, length)));
  }
}

template <JSLexer::IdentifierMode Mode>
void JSLexer::scanIdentifierParts() {
  consumeIdentifierParts<Mode>();
  auto rw =
      scanReservedWord(tmpStorage_.str().begin(), tmpStorage_.str().size());
  if (rw != TokenKind::identifier) {
    token_.setResWord(rw, resWordIdent(rw));
    sm_.warning(
        {token_.getStartLoc(), SMLoc::getFromPointer(curCharPtr_)},
        "scanning identifier with unicode escape as reserved word",
        Subsystem::Lexer);
  } else {
    token_.setIdentifier(getIdentifier(tmpStorage_.str()));
  }
}

bool JSLexer::scanPrivateIdentifier() {
  assert(*curCharPtr_ == '#');

                  
  const char *start = curCharPtr_;
  ++curCharPtr_;

                                
  if (LLVM_LIKELY(isASCIIIdentifierStart(*curCharPtr_))) {
    scanIdentifierFastPath<IdentifierMode::JS>(curCharPtr_);
  } else if (consumeIdentifierStart()) {
                                                              
    scanIdentifierParts<IdentifierMode::JS>();
  } else {
    error(SMLoc::getFromPointer(start), "empty private identifier");
    return false;
  }

                                    
                                                                
                                                       
  token_.setPrivateIdentifier(token_.getResWordOrIdentifier());

  return true;
}

template <bool JSX>
void JSLexer::scanString() {
  assert(*curCharPtr_ == '\'' || *curCharPtr_ == '"');
  char quoteCh = *curCharPtr_++;

                                                                              
                                                    
  bool escapes = false;

  tmpStorage_.clear();

  for (;;) {
    if (*curCharPtr_ == quoteCh) {
      ++curCharPtr_;
      break;
    } else if (!JSX && *curCharPtr_ == '\\') {
      escapes = true;
      ++curCharPtr_;
      switch ((unsigned char)*curCharPtr_) {
        case '\'':
        case '"':
        case '\\':
          tmpStorage_.push_back((unsigned char)*curCharPtr_++);
          break;

        case 'b':
          ++curCharPtr_;
          tmpStorage_.push_back(8);
          break;
        case 'f':
          ++curCharPtr_;
          tmpStorage_.push_back(12);
          break;
        case 'n':
          ++curCharPtr_;
          tmpStorage_.push_back(10);
          break;
        case 'r':
          ++curCharPtr_;
          tmpStorage_.push_back(13);
          break;
        case 't':
          ++curCharPtr_;
          tmpStorage_.push_back(9);
          break;
        case 'v':
          ++curCharPtr_;
          tmpStorage_.push_back(11);
          break;

        case '\0':        
          if (curCharPtr_ == bufferEnd_) {        
            error(SMLoc::getFromPointer(curCharPtr_), "non-terminated string");
            sm_.note(token_.getStartLoc(), "string started here");
            goto breakLoop;
          } else {
            tmpStorage_.push_back((unsigned char)*curCharPtr_++);
          }
          break;

        case '0':
                                                          
          if (!(curCharPtr_[1] >= '0' && curCharPtr_[1] <= '7')) {
            ++curCharPtr_;
            appendUnicodeToStorage(0);
            break;
          }
          [[fallthrough]];
        case '1':
        case '2':
        case '3':
          appendUnicodeToStorage(consumeOctal(3));
          break;
        case '4':
        case '5':
        case '6':
        case '7':
          appendUnicodeToStorage(consumeOctal(2));
          break;

        case 'x': {
          ++curCharPtr_;
          auto v = consumeHex(2);
          appendUnicodeToStorage(v ? *v : 0);
          break;
        }

        case 'u':
          --curCharPtr_;
          appendUnicodeToStorage(consumeUnicodeEscape());
          break;

                                                            
        case '\n':
          ++curCharPtr_;
          break;
        case '\r':
          ++curCharPtr_;
          if (*curCharPtr_ == '\n')              
            ++curCharPtr_;
          break;
        case UTF8_LINE_TERMINATOR_CHAR0:
          if (matchUnicodeLineTerminatorOffset1(curCharPtr_)) {
            curCharPtr_ += 3;
            break;
          }
          appendUnicodeToStorage(_decodeUTF8SlowPath(curCharPtr_));
          break;

        default:
          if (LLVM_UNLIKELY(isUTF8Start(*curCharPtr_)))
            appendUnicodeToStorage(_decodeUTF8SlowPath(curCharPtr_));
          else
            tmpStorage_.push_back((unsigned char)*curCharPtr_++);
          break;
      }
    } else if (LLVM_UNLIKELY(*curCharPtr_ == '\n' || *curCharPtr_ == '\r')) {
      if (JSX) {
        tmpStorage_.push_back(*curCharPtr_++);
      } else {
        error(SMLoc::getFromPointer(curCharPtr_), "non-terminated string");
        sm_.note(token_.getStartLoc(), "string started here");
        break;
      }
#if HERMES_PARSE_JSX
    } else if (LLVM_UNLIKELY(JSX && *curCharPtr_ == '&')) {
      auto codePoint = consumeHTMLEntityOptional();
      if (codePoint.hasValue()) {
        appendUnicodeToStorage(*codePoint);
      } else {
        tmpStorage_.push_back(*curCharPtr_++);
      }
#endif
    } else if (LLVM_UNLIKELY(*curCharPtr_ == 0 && curCharPtr_ == bufferEnd_)) {
      error(SMLoc::getFromPointer(curCharPtr_), "non-terminated string");
      sm_.note(token_.getStartLoc(), "string started here");
      break;
    } else {
      if (LLVM_UNLIKELY(isUTF8Start(*curCharPtr_))) {
                                                                         
                  
        appendUnicodeToStorage(_decodeUTF8SlowPath(curCharPtr_));
      } else {
        tmpStorage_.push_back(*curCharPtr_++);
      }
    }
  }
breakLoop:
  token_.setStringLiteral(getStringLiteral(tmpStorage_.str()), escapes);
}

void JSLexer::scanTemplateLiteral() {
  assert(*curCharPtr_ == '`' || *curCharPtr_ == '}');

                                                                        
                                                                             
                             
  bool isHead = *curCharPtr_ == '`';

                                                                              
                                                    
  bool isTail = false;

                                
  ++curCharPtr_;

                                                                
                                                             
  bool foundNotEscapeSequence = false;

                                                      
  tmpStorage_.clear();

                                                           
  rawStorage_.clear();

                                                            
                                                                    
                                                               
  const auto trv = [](char c) -> char {
    if (c == '\r') {
                                                  
                                                                              
                               
                                                               
      return 0x0a;
    }
    return c;
  };

  for (;;) {
    if (*curCharPtr_ == '`') {
      isTail = true;
      ++curCharPtr_;
      break;
    } else if (*curCharPtr_ == '$' && curCharPtr_[1] == '{') {
                                       
      isTail = false;
      curCharPtr_ += 2;
      break;
    } else if (*curCharPtr_ == '\\') {
      rawStorage_.push_back(*curCharPtr_);
      ++curCharPtr_;
      rawStorage_.push_back(trv(*curCharPtr_));
      switch ((unsigned char)*curCharPtr_) {
        case '\'':
        case '"':
        case '\\':
          tmpStorage_.push_back((unsigned char)*curCharPtr_++);
          break;

        case 'b':
          ++curCharPtr_;
          tmpStorage_.push_back(8);
          break;
        case 'f':
          ++curCharPtr_;
          tmpStorage_.push_back(12);
          break;
        case 'n':
          ++curCharPtr_;
          tmpStorage_.push_back(10);
          break;
        case 'r':
          ++curCharPtr_;
          tmpStorage_.push_back(13);
          break;
        case 't':
          ++curCharPtr_;
          tmpStorage_.push_back(9);
          break;
        case 'v':
          ++curCharPtr_;
          tmpStorage_.push_back(11);
          break;

        case '\0':        
          if (curCharPtr_ == bufferEnd_) {        
            error(
                SMLoc::getFromPointer(curCharPtr_),
                "non-terminated template literal");
            sm_.note(token_.getStartLoc(), "template literal started here");
            goto breakLoop;
          } else {
            tmpStorage_.push_back((unsigned char)*curCharPtr_++);
          }
          break;

        case '0':
                                                                      
                          
          if (!(curCharPtr_[1] >= '0' && curCharPtr_[1] <= '9')) {
            ++curCharPtr_;
            appendUnicodeToStorage(0);
            break;
          }
          [[fallthrough]];

        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
                                                        
                                                
                                                                 
                                                                             
          ++curCharPtr_;
          foundNotEscapeSequence = true;
          break;

        case 'x': {
          ++curCharPtr_;
          const char *start = curCharPtr_;
          auto v = consumeHex(2, false);
          if (!v) {
            foundNotEscapeSequence = true;
          }
          appendUnicodeToStorage(v ? *v : 0);
          rawStorage_.append({start, (size_t)(curCharPtr_ - start)});
          break;
        }

        case 'u': {
                                                                            
                                                                       
          const char *start = curCharPtr_ + 1;
                                                                     
          --curCharPtr_;
          assert(*curCharPtr_ == '\\' && "must have started with \\");
          auto codepoint = consumeUnicodeEscapeOptional();
          if (!codepoint) {
            foundNotEscapeSequence = true;
            curCharPtr_ = start;
            break;
          }
          appendUnicodeToStorage(*codepoint);
          rawStorage_.append({start, (size_t)(curCharPtr_ - start)});
          break;
        }

                                                                           
                                                                         
        case '\n':
          ++curCharPtr_;
          break;
        case '\r':
          ++curCharPtr_;
          if (*curCharPtr_ == '\n')              
            ++curCharPtr_;
          break;
        case UTF8_LINE_TERMINATOR_CHAR0: {
          bool isLineTerminator =
              matchUnicodeLineTerminatorOffset1(curCharPtr_);
          uint32_t codepoint = _decodeUTF8SlowPath(curCharPtr_);
                                                             
                                                                              
                              
          rawStorage_.pop_back();
          appendUnicodeToStorage(codepoint, rawStorage_);
          if (!isLineTerminator) {
                                                                           
                          
            appendUnicodeToStorage(codepoint);
          }
          break;
        }

        default:
          if (LLVM_UNLIKELY(isUTF8Start(*curCharPtr_))) {
            uint32_t codepoint = _decodeUTF8SlowPath(curCharPtr_);
            appendUnicodeToStorage(codepoint);
                                                                        
                                                                             
                                                            
            rawStorage_.pop_back();
            appendUnicodeToStorage(codepoint, rawStorage_);
          } else {
                                                                    
            tmpStorage_.push_back((unsigned char)*curCharPtr_++);
          }
          break;
      }
    } else if (LLVM_UNLIKELY(*curCharPtr_ == 0 && curCharPtr_ == bufferEnd_)) {
      error(
          SMLoc::getFromPointer(curCharPtr_),
          "non-terminated template literal");
      sm_.note(token_.getStartLoc(), "template literal started here");
      break;
    } else if (*curCharPtr_ == '\r') {
                                                       
                                                                         
                                                                             
                
      tmpStorage_.push_back(trv(*curCharPtr_));
      rawStorage_.push_back(trv(*curCharPtr_));
      curCharPtr_++;
      if (*curCharPtr_ == '\n') {
                             
        curCharPtr_++;
      }
    } else {
      if (LLVM_UNLIKELY(isUTF8Start(*curCharPtr_))) {
                                                                         
                  
        uint32_t codepoint = _decodeUTF8SlowPath(curCharPtr_);
        appendUnicodeToStorage(codepoint);
        appendUnicodeToStorage(codepoint, rawStorage_);
      } else {
        rawStorage_.push_back(*curCharPtr_);
        tmpStorage_.push_back(*curCharPtr_++);
      }
    }
  }
breakLoop:
                                                                         
                                                                             
                                                                           
                                                    
  UniqueString *cookedStr =
      foundNotEscapeSequence ? nullptr : getStringLiteral(tmpStorage_.str());
  UniqueString *rawStr = getStringLiteral(rawStorage_.str());
  if (isHead) {
    if (isTail) {
                       
      token_.setTemplateLiteral(
          TokenKind::no_substitution_template, cookedStr, rawStr);
    } else {
                        
      token_.setTemplateLiteral(TokenKind::template_head, cookedStr, rawStr);
    }
  } else {
    if (isTail) {
                       
      token_.setTemplateLiteral(TokenKind::template_tail, cookedStr, rawStr);
    } else {
                        
      token_.setTemplateLiteral(TokenKind::template_middle, cookedStr, rawStr);
    }
  }
}

                                              
void JSLexer::scanRegExp() {
  SMLoc startLoc = SMLoc::getFromPointer(curCharPtr_);
  assert(*curCharPtr_ == '/');
  ++curCharPtr_;

  tmpStorage_.clear();
  bool inClass = false;

  for (;;) {
    switch ((unsigned char)*curCharPtr_) {
      case '/':
        if (!inClass) {
          ++curCharPtr_;
          goto exitLoop;
        }
        break;

      case '[':
        inClass = true;                                        
        break;

      case ']':
        inClass = false;                                         
        break;

      case '\\':             
        tmpStorage_.push_back((unsigned char)*curCharPtr_);
        ++curCharPtr_;
        switch ((unsigned char)*curCharPtr_) {
          case '\0':
            if (curCharPtr_ == bufferEnd_)
              goto unterminated;
            break;
          case UTF8_LINE_TERMINATOR_CHAR0:
            if (matchUnicodeLineTerminatorOffset1(curCharPtr_))
              goto unterminated;
            break;
          case '\n':
          case '\r':
            goto unterminated;
        }
        break;

      case '\0':
        if (curCharPtr_ == bufferEnd_)
          goto unterminated;
        break;
      case UTF8_LINE_TERMINATOR_CHAR0:
        if (matchUnicodeLineTerminatorOffset1(curCharPtr_))
          goto unterminated;
        break;

      case '\n':
      case '\r':
      unterminated:
        error(
            SMLoc::getFromPointer(curCharPtr_),
            "non-terminated regular expression literal");
        sm_.note(startLoc, "regular expression started here");
        goto exitLoop;
    }

    if (LLVM_UNLIKELY(isUTF8Start((unsigned char)*curCharPtr_)))
      appendUnicodeToStorage(_decodeUTF8SlowPath(curCharPtr_));
    else
      tmpStorage_.push_back((unsigned char)*curCharPtr_++);
  }
exitLoop:
  UniqueString *body = getStringLiteral(tmpStorage_.str());

                                                            
                                                            
                                                                    
                                                         
  tmpStorage_.clear();
  bool escapingBackslash = false;
  for (;;) {
    if (consumeOneIdentifierPartNoEscape<IdentifierMode::JS>()) {
      escapingBackslash = false;
      continue;
    } else if (*curCharPtr_ == '\\') {
      tmpStorage_.push_back(*curCharPtr_++);

                                                                        
                                 
      escapingBackslash = !escapingBackslash;
      if (escapingBackslash && *curCharPtr_ == 'u') {
        error(
            SMLoc::getFromPointer(curCharPtr_),
            "Unicode escape sequences are not allowed in regular expression flags");
      }
    } else {
      break;
    }
  }

  UniqueString *flags = getStringLiteral(tmpStorage_.str());

  token_.setRegExpLiteral(new (allocator_.Allocate<RegExpLiteral>(1))
                              RegExpLiteral(body, flags));
}

UniqueString *JSLexer::convertSurrogatesInString(llvh::StringRef str) {
  std::string output;
  convertUTF8WithSurrogatesToUTF8WithReplacements(output, str);
  return strTab_.getString(output);
}

bool JSLexer::error(llvh::SMLoc loc, const llvh::Twine &msg) {
  sm_.error(loc, msg, Subsystem::Lexer);
  if (!sm_.isErrorLimitReached())
    return true;
  forceEOF();
  return false;
}

bool JSLexer::error(llvh::SMRange range, const llvh::Twine &msg) {
  sm_.error(range, msg, Subsystem::Lexer);
  if (!sm_.isErrorLimitReached())
    return true;
  forceEOF();
  return false;
}

bool JSLexer::error(
    llvh::SMLoc loc,
    llvh::SMRange range,
    const llvh::Twine &msg) {
  sm_.error(loc, range, msg, Subsystem::Lexer);
  if (!sm_.isErrorLimitReached())
    return true;
  forceEOF();
  return false;
}

}                    
}                    

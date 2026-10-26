/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PARSER_JSLEXER_H
#define HERMES_PARSER_JSLEXER_H

#include "hermes/AST/Config.h"
#include "hermes/Support/Allocator.h"
#include "hermes/Support/OptValue.h"
#include "hermes/Support/SourceErrorManager.h"
#include "hermes/Support/StringTable.h"
#include "hermes/Support/UTF8.h"

#include "llvh/ADT/Optional.h"
#include "llvh/ADT/SmallString.h"
#include "llvh/ADT/StringRef.h"

#include <functional>
#include <utility>

namespace hermes {
namespace parser {

using llvh::SMLoc;
using llvh::SMRange;

class Token;
class JSLexer;

enum class TokenKind {
#define TOK(name, str) name,
#include "TokenKinds.def"
};

inline constexpr int ord(TokenKind kind) {
  return static_cast<int>(kind);
}

#ifndef NDEBUG
                                                  
inline bool isPunctuatorDbg(TokenKind kind) {
  switch (kind) {
#define PUNCTUATOR(name, str) \
  case TokenKind::name:       \
    return true;
#include "TokenKinds.def"
    default:
      return false;
  }
}
#endif

const unsigned NUM_JS_TOKENS = ord(TokenKind::_last_token) + 1;
const char *tokenKindStr(TokenKind kind);

class RegExpLiteral {
  UniqueString *body_;
  UniqueString *flags_;

 public:
  RegExpLiteral(UniqueString *body, UniqueString *flags)
      : body_(body), flags_(flags) {}

  UniqueString *getBody() const {
    return body_;
  }
  UniqueString *getFlags() const {
    return flags_;
  }
};

                                                                
                                                                        
                        
class Token {
  TokenKind kind_{TokenKind::none};
  SMRange range_{};
  double numeric_{};
  UniqueString *ident_{nullptr};

                                                                       
                                                                      
                                                                               
                                                        
  UniqueString *stringLiteral_{nullptr};

  RegExpLiteral *regExpLiteral_{nullptr};

                                                             
                                                                               
                                            
                                    
  UniqueString *rawString_{nullptr};

                                                                              
                                                                              
                        
  bool stringLiteralContainsEscapes_ = false;

  Token(const Token &) = delete;
  const Token &operator=(const Token &) = delete;

 public:
  Token() = default;
  ~Token() = default;

  TokenKind getKind() const {
    return kind_;
  }
  bool isResWord() const {
    return kind_ > TokenKind::_first_resword &&
        kind_ < TokenKind::_last_resword;
  }
  bool isTemplateLiteral() const {
    return getKind() == TokenKind::no_substitution_template ||
        getKind() == TokenKind::template_head ||
        getKind() == TokenKind::template_middle ||
        getKind() == TokenKind::template_tail;
  }

  SMLoc getStartLoc() const {
    return range_.Start;
  }
  SMLoc getEndLoc() const {
    return range_.End;
  }
  SMRange getSourceRange() const {
    return range_;
  }

  llvh::StringRef inputStr() const {
    return llvh::StringRef(
        range_.Start.getPointer(),
        range_.End.getPointer() - range_.Start.getPointer());
  }

  double getNumericLiteral() const {
    assert(getKind() == TokenKind::numeric_literal);
    return numeric_;
  }

  UniqueString *getIdentifier() const {
    assert(getKind() == TokenKind::identifier);
    return ident_;
  }
  UniqueString *getPrivateIdentifier() const {
    assert(getKind() == TokenKind::private_identifier);
    return ident_;
  }
  UniqueString *getResWordIdentifier() const {
    assert(isResWord());
    return ident_;
  }
  UniqueString *getResWordOrIdentifier() const {
    assert(getKind() == TokenKind::identifier || isResWord());
    return ident_;
  }

  UniqueString *getStringLiteral() const {
    assert(getKind() == TokenKind::string_literal);
    return stringLiteral_;
  }
  UniqueString *getStringLiteralRawValue() const {
    assert(getKind() == TokenKind::string_literal);
    return rawString_;
  }
  bool getStringLiteralContainsEscapes() const {
    assert(getKind() == TokenKind::string_literal);
    return stringLiteralContainsEscapes_;
  }

                                                                              
                                   
                                                                        
  bool getTemplateLiteralContainsNotEscapes() const {
    assert(isTemplateLiteral());
    return stringLiteral_ == nullptr;
  }

  UniqueString *getTemplateValue() const {
    assert(isTemplateLiteral());
    return stringLiteral_;
  }

  UniqueString *getTemplateRawValue() const {
    assert(isTemplateLiteral());
    return rawString_;
  }

  UniqueString *getBigIntLiteral() const {
    assert(getKind() == TokenKind::bigint_literal);
    return rawString_;
  }

  RegExpLiteral *getRegExpLiteral() const {
    assert(getKind() == TokenKind::regexp_literal);
    return regExpLiteral_;
  }

  UniqueString *getJSXTextValue() const {
    assert(getKind() == TokenKind::jsx_text);
    return stringLiteral_;
  }

  UniqueString *getJSXTextRaw() const {
    assert(getKind() == TokenKind::jsx_text);
    return rawString_;
  }

                                                              
                                                                              
                                                                               
                                                                               
                                                                              
                                                    
     
                                                                             
                             
  bool checkFollowingCharacter(char c) const {
                                                                                
                                          
    assert((unsigned)c < 128 && "test character must be ASCII");
    return *getEndLoc().getPointer() == c;
  }

 private:
  void setStart(const char *start) {
    range_.Start = SMLoc::getFromPointer(start);
  }
  void setEnd(const char *end) {
    range_.End = SMLoc::getFromPointer(end);
  }

  void setRange(SMRange range) {
    range_ = range;
  }

  void setPunctuator(TokenKind kind) {
    kind_ = kind;
  }
                                                  
                                                                           
  void setIdentOp(TokenKind kind) {
    kind_ = kind;
  }
  void setEof() {
    kind_ = TokenKind::eof;
  }

  void setBigIntLiteral(UniqueString *raw) {
    kind_ = TokenKind::bigint_literal;
    rawString_ = raw;
  }
  void setNumericLiteral(double literal) {
    kind_ = TokenKind::numeric_literal;
    numeric_ = literal;
  }
  void setIdentifier(UniqueString *ident) {
    kind_ = TokenKind::identifier;
    ident_ = ident;
  }
  void setPrivateIdentifier(UniqueString *ident) {
    kind_ = TokenKind::private_identifier;
    ident_ = ident;
  }
  void setStringLiteral(UniqueString *literal, bool containsEscapes) {
    kind_ = TokenKind::string_literal;
    stringLiteral_ = literal;
    stringLiteralContainsEscapes_ = containsEscapes;
  }
  void setJSXStringLiteral(UniqueString *literal, UniqueString *raw) {
    kind_ = TokenKind::string_literal;
    stringLiteral_ = literal;
    rawString_ = raw;
    stringLiteralContainsEscapes_ = false;
  }
  void setRegExpLiteral(RegExpLiteral *literal) {
    kind_ = TokenKind::regexp_literal;
    regExpLiteral_ = literal;
  }
  void setResWord(TokenKind kind, UniqueString *ident) {
    assert(kind > TokenKind::_first_resword && kind < TokenKind::_last_resword);
    kind_ = kind;
    ident_ = ident;
  }

  void
  setTemplateLiteral(TokenKind kind, UniqueString *cooked, UniqueString *raw) {
    assert(
        kind == TokenKind::no_substitution_template ||
        kind == TokenKind::template_head ||
        kind == TokenKind::template_middle || kind == TokenKind::template_tail);
    kind_ = kind;
    stringLiteral_ = cooked;
    rawString_ = raw;
  }

  void setJSXText(UniqueString *value, UniqueString *raw) {
    kind_ = TokenKind::jsx_text;
    stringLiteral_ = value;
    rawString_ = raw;
  }

  friend class JSLexer;
};

                                                      
class StoredComment {
 public:
                                     
  enum class Kind {
                                      
    Line,
                                                   
    Block,
                                                                              
    Hashbang,
  };

  StoredComment(Kind kind, SMRange range) : kind_(kind), range_(range) {}

  Kind getKind() const {
    return kind_;
  }

                                                                    
                                                               
  llvh::StringRef getString() const {
                                
    const char *start = range_.Start.getPointer() + 2;
                                              
    const char *end = kind_ == Kind::Block ? range_.End.getPointer() - 2
                                           : range_.End.getPointer();
    assert(end >= start && "invalid comment range");
    return llvh::StringRef{start, (size_t)(end - start)};
  }

                                                                    
                                                               
  llvh::StringRef getFullString() const {
    return llvh::StringRef{
        range_.Start.getPointer(),
        (size_t)(range_.End.getPointer() - range_.Start.getPointer())};
  }

  SMRange getSourceRange() const {
    return range_;
  }

 private:
                                 
  Kind kind_;

                                         
  SMRange range_;
};

                             
class StoredToken {
 public:
  StoredToken(TokenKind kind, SMRange range) : kind_(kind), range_(range) {}

  TokenKind getKind() const {
    return kind_;
  }

  SMRange getSourceRange() const {
    return range_;
  }

 private:
                        
  TokenKind kind_;

                                
  SMRange range_;
};

class JSLexer {
 public:
  using Allocator = hermes::BumpPtrAllocator;

 private:
  SourceErrorManager &sm_;
  Allocator &allocator_;

                                                 
  uint32_t bufId_;

                                                                        
           
  std::unique_ptr<StringTable> ownStrTab_;

  StringTable &strTab_;

#if HERMES_PARSE_JSX
                                                                           
  const llvh::DenseMap<llvh::StringRef, uint32_t> &htmlEntities_;
#endif

  bool strictMode_;

                                                             
  bool storeComments_{false};

                                            
  bool storeTokens_{false};

                                                                                
                                                                       
               
  bool convertSurrogates_;

  Token token_;

                                                                              
  SMLoc prevTokenEndLoc_;

  const char *bufferStart_;
  const char *curCharPtr_;
  const char *bufferEnd_;

  bool newLineBeforeCurrentToken_ = false;

  llvh::SmallString<256> tmpStorage_;

                                                                              
  llvh::SmallString<256> rawStorage_;

                                                       
  UniqueString *resWordIdent_
      [ord(TokenKind::_last_resword) - ord(TokenKind::_first_resword) + 1];

  UniqueString *&resWordIdent(TokenKind kind) {
    assert(
        kind >= TokenKind::_first_resword && kind <= TokenKind::_last_resword);
    return resWordIdent_[ord(kind) - ord(TokenKind::_first_resword)];
  }

                                    
  llvh::StringRef sourceURL_{};
                                            
  llvh::StringRef sourceMappingURL_{};

                                                                 
                                                                   
                                                                     
                 
  std::vector<StoredComment> commentStorage_{};

                                                            
  std::vector<StoredToken> tokenStorage_{};

 public:
                                                                         
  explicit JSLexer(
      std::unique_ptr<llvh::MemoryBuffer> input,
      SourceErrorManager &sm,
      Allocator &allocator,
      StringTable *strTab = nullptr,
      bool strictMode = true,
      bool convertSurrogates = false);

                                                                         
  explicit JSLexer(
      uint32_t bufId,
      SourceErrorManager &sm,
      Allocator &allocator,
      StringTable *strTab = nullptr,
      bool strictMode = true,
      bool convertSurrogates = false);

                                                                         
  JSLexer(
      llvh::StringRef input,
      SourceErrorManager &sm,
      Allocator &allocator,
      StringTable *strTab = nullptr,
      bool strictMode = true,
      bool convertSurrogates = false)
      : JSLexer(
            llvh::MemoryBuffer::getMemBuffer(input, "JavaScript"),
            sm,
            allocator,
            strTab,
            strictMode,
            convertSurrogates) {}

                                                                         
  JSLexer(
      llvh::MemoryBufferRef input,
      SourceErrorManager &sm,
      Allocator &allocator,
      StringTable *strTab = nullptr,
      bool strictMode = true,
      bool convertSurrogates = false)
      : JSLexer(
            llvh::MemoryBuffer::getMemBuffer(input),
            sm,
            allocator,
            strTab,
            strictMode,
            convertSurrogates) {}

  SourceErrorManager &getSourceMgr() {
    return sm_;
  }

  Allocator &getAllocator() {
    return allocator_;
  }
  StringTable &getStringTable() {
    return strTab_;
  }

  bool isStrictMode() const {
    return strictMode_;
  }

  void setStrictMode(bool strictMode) {
    strictMode_ = strictMode;
  }

  void setStoreComments(bool storeComments) {
    storeComments_ = storeComments;
  }

  bool getStoreTokens() const {
    return storeTokens_;
  }

  void setStoreTokens(bool storeTokens) {
    storeTokens_ = storeTokens;
  }

                                                                   
  void storeCurrentToken() {
    assert(storeTokens_ && "Tokens shouldn't be stored unless the flag is set");
    tokenStorage_.emplace_back(token_.getKind(), token_.getSourceRange());
  }

                                                                              
     
                                                                           
                         
  bool isNewLineBeforeCurrentToken() const {
    return newLineBeforeCurrentToken_;
  }

                                
  const Token *getCurToken() const {
    return &token_;
  }

                                                
  SMLoc getCurLoc() const {
    return SMLoc::getFromPointer(curCharPtr_);
  }

                                                     
  SMLoc getPrevTokenEndLoc() const {
    return prevTokenEndLoc_;
  }

                                                       
                                                     
                                         
                                                       
                                                        
                                                                
                                                          
  bool isLetFollowedByDeclStart();

                                     
  void forceEOF() {
    curCharPtr_ = bufferEnd_;
  }

                                                
                                      
                                
                                                                       
                                          
                                                                       
  enum GrammarContext { AllowRegExp, AllowDiv, AllowJSXIdentifier, Type };

                                                                            
                                                                          
                                                                               
          
                                                                              
  const Token *advance(GrammarContext grammarContext = AllowRegExp);

#if HERMES_PARSE_JSX
                                                                      
                                                               
  const Token *advanceInJSXChild();
#endif

                                                                            
                                                                           
                                                
                                                                           
                                                                              
     
                                                                  
  bool isCurrentTokenADirective();

                                                             
                                                                   
  const Token *rescanRBraceInTemplateLiteral();

                                                                     
                                                          
                                                                 
                                               
               
            
                                                            
               
                                                           
                                                           
                                                                             
                                                   
                                                                                
                                                                  
                                                                         
  template <bool RequireNoNewLine = true>
  OptValue<TokenKind> lookahead1(OptValue<TokenKind> expectedToken);

  UniqueString *getIdentifier(llvh::StringRef name) {
    return strTab_.getString(name);
  }

  UniqueString *getStringLiteral(llvh::StringRef str) {
    if (LLVM_UNLIKELY(convertSurrogates_)) {
      return convertSurrogatesInString(str);
    }
    return strTab_.getString(str);
  }

                                                                      
                                                                           
                   
  void seek(SMLoc loc) {
    curCharPtr_ = loc.getPointer();
  }

                                                       
  uint32_t getBufferId() {
    return bufId_;
  }

                                                       
  const char *getBufferStart() const {
    return bufferStart_;
  }

                                                 
  const char *getBufferEnd() const {
    return bufferEnd_;
  }

                                                                                
                           
  llvh::StringRef getSourceURL() const {
    return sourceURL_;
  }

                                                                               
                                    
  llvh::StringRef getSourceMappingURL() const {
    return sourceMappingURL_;
  }

                                                                           
                                            
  std::vector<StoredComment> moveStoredComments() {
    std::vector<StoredComment> result{};
    std::swap(result, commentStorage_);
    return result;
  }

                                                
  llvh::ArrayRef<StoredComment> getStoredComments() const {
    return commentStorage_;
  }

                                                
  llvh::ArrayRef<StoredToken> getStoredTokens() const {
    return tokenStorage_;
  }

                                                                    
                                                                   
                            
  class SavePoint {
    JSLexer *const lexer_;

                                               
    TokenKind kind_;

                                                         
    UniqueString *ident_;

                                         
    SMLoc loc_;

                                         
    SMRange range_;

                                                        
    SMLoc prevTokenEndLoc_;

                                                                               
                                                                         
    size_t commentStorageSize_;

                                  
                                                                          
    size_t tokenStorageSize_;

   public:
    SavePoint(JSLexer *lexer)
        : lexer_(lexer),
          kind_(lexer_->getCurToken()->getKind()),
          ident_(
              kind_ == TokenKind::identifier
                  ? lexer_->getCurToken()->getIdentifier()
                  : nullptr),
          loc_(lexer_->getCurLoc()),
          range_(lexer_->getCurToken()->getSourceRange()),
          prevTokenEndLoc_(lexer->getPrevTokenEndLoc()),
          commentStorageSize_(lexer->getStoredComments().size()),
          tokenStorageSize_(lexer_->getStoredTokens().size()) {
      assert(
          (isPunctuatorDbg(kind_) || kind_ == TokenKind::identifier ||
           kind_ == TokenKind::rw_extends) &&
          "SavePoint can only be used for punctuators, identifier or `extends` keyword");
    }

                                                                     
    void restore() {
      if (kind_ == TokenKind::identifier) {
        lexer_->unsafeSetIdentifier(ident_, loc_, range_);
      } else if (kind_ == TokenKind::rw_extends) {
        lexer_->unsafeSetReservedWord(kind_, loc_, range_);
      } else {
        lexer_->unsafeSetPunctuator(kind_, loc_, range_);
      }

      lexer_->prevTokenEndLoc_ = prevTokenEndLoc_;

      if (lexer_->storeComments_ &&
          commentStorageSize_ < lexer_->commentStorage_.size()) {
        lexer_->commentStorage_.erase(
            lexer_->commentStorage_.begin() + commentStorageSize_,
            lexer_->commentStorage_.end());
      }

      if (LLVM_UNLIKELY(lexer_->getStoreTokens())) {
        lexer_->tokenStorage_.erase(
            lexer_->tokenStorage_.begin() + tokenStorageSize_,
            lexer_->tokenStorage_.end());
      }
    }
  };

                                                                
                                                       
                                                                            
                                                   
  void convertCurTokenToIdentOp(TokenKind kind) {
    assert(token_.getKind() == TokenKind::identifier);
    assert(token_.getIdentifier()->str() == tokenKindStr(kind));
    token_.setIdentOp(kind);
  }

 private:
                                                                             
  inline void initStorageWith(const char *begin, const char *end);

                                                                         
                                                                       
                                                                         
  static inline void appendUnicodeToStorage(
      uint32_t cp,
      llvh::SmallVectorImpl<char> &storage);

                                                                           
                                                                           
                                                                         
  inline void appendUnicodeToStorage(uint32_t cp) {
    appendUnicodeToStorage(cp, tmpStorage_);
  }

                                                                         
             
  inline uint32_t decodeUTF8();

                                                                           
                                              
                                                                  
  inline uint32_t _decodeUTF8SlowPath(const char *&at);

                                                                   
                       
     
                                                                            
                                                                               
              
     
                                                           
  inline std::pair<uint32_t, const char *> _peekUTF8(const char *at) const;

                                                                              
                       
     
                                                                            
                                                                               
              
     
                                                                   
  inline std::pair<uint32_t, const char *> _peekUTF8() const;

                                                            
     
                                                                             
                                                               
  uint32_t consumeUnicodeEscape();

                                                            
                                 
     
                                                                             
                                                               
                                                                             
                 
                                                                 
  llvh::Optional<uint32_t> consumeUnicodeEscapeOptional();

                                                                             
                  
  enum class IdentifierMode {
                                             
    JS,
                                       
    JSX,
                                                                    
    Flow,
  };

                                                         
                                                                  
  bool consumeIdentifierStart();

                                                           
  template <IdentifierMode Mode>
  void consumeIdentifierParts();

                                                                       
                
                                                                         
                                                         
  template <IdentifierMode Mode>
  bool consumeOneIdentifierPartNoEscape();

                                                                        
                                                                           
                      
  unsigned char consumeOctal(unsigned maxLen);

                                                                             
               
                                                                    
                                                                               
               
  llvh::Optional<uint32_t> consumeHex(
      unsigned requiredLen,
      bool errorOnFail = true);

                                                           
                                                            
                                                                          
                                              
                                                               
  llvh::Optional<uint32_t> consumeBracedCodePoint(bool errorOnFail = true);

#if HERMES_PARSE_JSX
                                                                           
     
                                                                               
                                                                                
                                                                              
             
     
                                                                         
                                                   
  llvh::Optional<uint32_t> consumeHTMLEntityOptional();
#endif

                                                                                
                                                                               
                 
  llvh::StringRef lineCommentHelper(const char *start);

                                                                              
                                                                            
                 
                             
  void scanLineComment(const char *start);

                                                    
                                         
  const char *skipBlockComment(const char *start);

  void scanNumber(GrammarContext grammarContext);

                                                                             
                                                                            
                                           
  TokenKind scanReservedWord(const char *start, unsigned length);

                                                                         
                                                                                
                                                                    
                                                                                
                                                   
  template <IdentifierMode Mode>
  void scanIdentifierFastPath(const char *start);
  void scanIdentifierFastPathInContext(
      const char *start,
      GrammarContext grammarContext) {
    if (HERMES_PARSE_JSX &&
        LLVM_UNLIKELY(grammarContext == GrammarContext::AllowJSXIdentifier)) {
      scanIdentifierFastPath<IdentifierMode::JSX>(start);
    } else if (
        HERMES_PARSE_FLOW &&
        LLVM_UNLIKELY(grammarContext == GrammarContext::Type)) {
      scanIdentifierFastPath<IdentifierMode::Flow>(start);
    } else {
      scanIdentifierFastPath<IdentifierMode::JS>(start);
    }
  }

  template <IdentifierMode Mode>
  void scanIdentifierParts();
  void scanIdentifierPartsInContext(GrammarContext grammarContext) {
    if (HERMES_PARSE_JSX &&
        LLVM_UNLIKELY(grammarContext == GrammarContext::AllowJSXIdentifier)) {
      scanIdentifierParts<IdentifierMode::JSX>();
    } else if (
        HERMES_PARSE_FLOW &&
        LLVM_UNLIKELY(grammarContext == GrammarContext::Type)) {
      scanIdentifierParts<IdentifierMode::Flow>();
    } else {
      scanIdentifierParts<IdentifierMode::JS>();
    }
  }

                                
                                     
                                              
  bool scanPrivateIdentifier();

  template <bool JSX>
  void scanString();
  void scanStringInContext(GrammarContext grammarContext) {
#if HERMES_PARSE_JSX
    LLVM_UNLIKELY(grammarContext == GrammarContext::AllowJSXIdentifier)
    ? scanString<true>() :
#endif
    scanString<false>();
  }

  void scanRegExp();

                                                               
  void scanTemplateLiteral();

                                                                                
                               
  UniqueString *convertSurrogatesInString(llvh::StringRef str);

                                                                          
             
                                                   
  void unsafeSetPunctuator(TokenKind kind, SMLoc loc, SMRange range) {
    assert(isPunctuatorDbg(kind) && "must set a punctuator");
    token_.setPunctuator(kind);
    token_.setRange(range);
    seek(loc);
  }

                                                                          
             
                                                   
  void unsafeSetIdentifier(UniqueString *ident, SMLoc loc, SMRange range) {
    token_.setIdentifier(ident);
    token_.setRange(range);
    seek(loc);
  }

                                                                          
             
                                                   
  void unsafeSetReservedWord(TokenKind kind, SMLoc loc, SMRange range) {
    token_.setResWord(kind, resWordIdent(kind));
    token_.setRange(range);
    seek(loc);
  }

                                                               
                                                                 
                                                                    
  inline void finishToken(const char *end) {
    prevTokenEndLoc_ = token_.getEndLoc();
    token_.setEnd(end);
    if (LLVM_UNLIKELY(storeTokens_)) {
      storeCurrentToken();
    }
  }

                                                         
  void initializeWithBufferId(uint32_t bufId);

                                                                           
  void initializeReservedIdentifiers();

                                                                
  bool errorRange(SMLoc startLoc, const llvh::Twine &msg) {
    return error({startLoc, SMLoc::getFromPointer(curCharPtr_)}, msg);
  }

                                                         
  bool error(const llvh::Twine &msg) {
    return error(token_.getSourceRange(), msg);
  }

                                                                              
                                                                            
          
                                                                              
  bool error(SMLoc loc, const llvh::Twine &msg);

                                                                           
                                                                            
          
                                                                              
  bool error(SMRange range, const llvh::Twine &msg);

                                                                              
                                                                           
                     
                                                                              
  bool error(SMLoc loc, SMRange range, const llvh::Twine &msg);
};

inline void JSLexer::initStorageWith(const char *begin, const char *end) {
  tmpStorage_.clear();
  tmpStorage_.append(begin, end);
}

inline void JSLexer::appendUnicodeToStorage(
    uint32_t cp,
    llvh::SmallVectorImpl<char> &storage) {
                                                        
                                                             
  char buf[8];
  char *d = buf;
                                                                             
                                                             
  if (LLVM_LIKELY(cp < 0x10000)) {
    hermes::encodeUTF8(d, cp);
  } else {
    assert(cp <= UNICODE_MAX_VALUE && "invalid Unicode value");
    cp -= 0x10000;
    hermes::encodeUTF8(d, UTF16_HIGH_SURROGATE + ((cp >> 10) & 0x3FF));
    hermes::encodeUTF8(d, UTF16_LOW_SURROGATE + (cp & 0x3FF));
  }
  storage.append(buf, d);
}

inline uint32_t JSLexer::decodeUTF8() {
  const char *saveStart = curCharPtr_;
  return hermes::decodeUTF8<false>(curCharPtr_, [=, this](const Twine &msg) {
    error(SMLoc::getFromPointer(saveStart), msg);
  });
}

inline uint32_t JSLexer::_decodeUTF8SlowPath(const char *&at) {
  return hermes::_decodeUTF8SlowPath<false>(at, [=, this](const Twine &msg) {
    error(SMLoc::getFromPointer(at), msg);
  });
}

inline std::pair<uint32_t, const char *> JSLexer::_peekUTF8(
    const char *at) const {
  uint32_t ch =
      hermes::_decodeUTF8SlowPath<false>(at, [](const llvh::Twine &) {});
  return std::make_pair(ch, at);
}

inline std::pair<uint32_t, const char *> JSLexer::_peekUTF8() const {
  return _peekUTF8(curCharPtr_);
}

}                    
}                    

#endif                           

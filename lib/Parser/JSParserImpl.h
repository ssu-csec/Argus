/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PARSER_JSPARSERIMPL_H
#define HERMES_PARSER_JSPARSERIMPL_H

#include "hermes/AST/Config.h"
#include "hermes/AST/Context.h"
#include "hermes/AST/ESTree.h"
#include "hermes/Parser/JSLexer.h"
#include "hermes/Parser/JSParser.h"
#include "hermes/Parser/PreParser.h"
#include "hermes/Support/Compiler.h"

#include "llvh/ADT/ArrayRef.h"
#include "llvh/ADT/Optional.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/Support/DataTypes.h"

#include <utility>

namespace hermes {
namespace parser {
namespace detail {

using llvh::ArrayRef;
using llvh::None;
using llvh::Optional;

                                                                          
                             
class Param {
  unsigned flags_;

 public:
  constexpr Param() : flags_(0) {}
  constexpr explicit Param(unsigned f) : flags_(f) {}

  constexpr Param operator+(Param b) const {
    return Param{flags_ | b.flags_};
  }
  constexpr Param operator-(Param b) const {
    return Param{flags_ & ~(b.flags_)};
  }

                                                                        
  bool has(Param p) const {
    return flags_ & p.flags_;
  }

                                                                        
  bool hasAll(Param p) const {
    return (flags_ & p.flags_) == p.flags_;
  }

                                                                      
                                         
  constexpr Param get(Param p) const {
    return Param{flags_ & p.flags_};
  }

  template <typename... T>
  constexpr Param get(Param p, T... tail) const {
    return Param{get(p).flags_ | get(tail...).flags_};
  }
};

                                                                            
static constexpr Param ParamIn{1 << 0};
static constexpr Param ParamReturn{1 << 1};
static constexpr Param ParamDefault{1 << 2};
static constexpr Param ParamTagged{1 << 3};

                             
                                                                            
                                                                             
                               
                                                                            
                                                                           
                                     
class JSParserImpl {
 public:
  explicit JSParserImpl(
      Context &context,
      std::unique_ptr<llvh::MemoryBuffer> input);

  explicit JSParserImpl(Context &context, uint32_t bufferId, ParserPass pass);

  JSParserImpl(Context &context, llvh::StringRef input)
      : JSParserImpl(
            context,
            llvh::MemoryBuffer::getMemBuffer(input, "JavaScript")) {}

  JSParserImpl(Context &context, llvh::MemoryBufferRef input)
      : JSParserImpl(context, llvh::MemoryBuffer::getMemBuffer(input)) {}

  Context &getContext() {
    return context_;
  }

  JSLexer &getLexer() {
    return lexer_;
  }

  bool isStrictMode() const {
    return lexer_.isStrictMode();
  }

  void setStrictMode(bool mode) {
    lexer_.setStrictMode(mode);
  }

  llvh::SmallVector<UniqueString *, 1> &getSeenDirectives() {
    return seenDirectives_;
  }

                                                                              
                                                                       
  llvh::SmallVector<llvh::SmallString<24>, 1> copySeenDirectives() const;

  Optional<ESTree::ProgramNode *> parse();

  void seek(SMLoc startPos) {
    lexer_.seek(startPos);
    tok_ = lexer_.advance();
  }

                                                                               
                                             
                                                                             
                                                                             
                             
  static std::shared_ptr<JSParserImpl> preParseBuffer(
      Context &context,
      uint32_t bufferId);

                                                                           
                                                                            
                     
  Optional<ESTree::NodePtr> parseLazyFunction(
      ESTree::NodeKind kind,
      bool paramYield,
      bool paramAwait,
      SMLoc start);

                                                                                
             
  bool getUseStaticBuiltin() const {
    return useStaticBuiltin_;
  }

 private:
                                                                            
             
  void setUseStaticBuiltin() {
    useStaticBuiltin_ = true;
  }

                                                                            
                                                                             
             
  void initializeIdentifiers();

                                  
  Context &context_;
                                      
  SourceErrorManager &sm_;
                        
  JSLexer lexer_;
                    
  const Token *tok_{};
                                                  
  ParserPass pass_{FullParse};
                                                                         
                                  
  PreParsedBufferInfo *preParsed_{nullptr};

                                                               
                                                                            
                                     
  unsigned recursionDepth_{0};

                                                              
  static constexpr unsigned MAX_RECURSION_DEPTH =
#ifdef HERMES_LIMIT_STACK_DEPTH
      128
#elif defined(_MSC_VER) && defined(HERMES_SLOW_DEBUG)
      128
#elif defined(_MSC_VER) && defined(__clang__) && !defined(NDEBUG)
      128
#elif defined(_MSC_VER)
      512
#else
      1024
#endif
      ;

                                                                               
  bool useStaticBuiltin_{false};

                                                         
                                                                       
  bool paramYield_{false};

                                                      
                                                                       
  bool paramAwait_{false};

                                                                         
                                                           
                                         
                                                                               
                                                                   
  llvh::SmallVector<UniqueString *, 1> seenDirectives_{};

#if HERMES_PARSE_JSX
                                                                        
                                                        
  uint32_t jsxDepth_{0};
#endif

#if HERMES_PARSE_FLOW
  bool allowAnonFunctionType_{false};
  Optional<UniqueString *> parseRenderTypeOperator();
#endif
#if HERMES_PARSE_FLOW || HERMES_PARSE_TS
  bool allowConditionalType_{false};
#endif

                                                                         
                            
  UniqueString *getIdent_;
  UniqueString *setIdent_;
  UniqueString *initIdent_;
  UniqueString *useStrictIdent_;
  UniqueString *showSourceIdent_;
  UniqueString *hideSourceIdent_;
  UniqueString *sensitiveIdent_;
  UniqueString *useStaticBuiltinIdent_;
  UniqueString *letIdent_;
  UniqueString *ofIdent_;
  UniqueString *fromIdent_;
  UniqueString *asIdent_;
  UniqueString *implementsIdent_;
  UniqueString *interfaceIdent_;
  UniqueString *packageIdent_;
  UniqueString *privateIdent_;
  UniqueString *protectedIdent_;
  UniqueString *publicIdent_;
  UniqueString *staticIdent_;
  UniqueString *methodIdent_;
  UniqueString *constructorIdent_;
  UniqueString *yieldIdent_;
  UniqueString *newIdent_;
  UniqueString *importIdent_;
  UniqueString *targetIdent_;
  UniqueString *metaIdent_;
  UniqueString *valueIdent_;
  UniqueString *typeIdent_;
  UniqueString *asyncIdent_;
  UniqueString *awaitIdent_;
  UniqueString *assertIdent_;

#if HERMES_PARSE_FLOW

  UniqueString *typeofIdent_;
  UniqueString *keyofIdent_;
  UniqueString *declareIdent_;
  UniqueString *protoIdent_;
  UniqueString *opaqueIdent_;
  UniqueString *plusIdent_;
  UniqueString *minusIdent_;
  UniqueString *moduleIdent_;
  UniqueString *exportsIdent_;
  UniqueString *esIdent_;
  UniqueString *commonJSIdent_;
  UniqueString *mixinsIdent_;
  UniqueString *thisIdent_;

  UniqueString *anyIdent_;
  UniqueString *mixedIdent_;
  UniqueString *emptyIdent_;
  UniqueString *booleanIdent_;
  UniqueString *boolIdent_;
  UniqueString *numberIdent_;
  UniqueString *stringIdent_;
  UniqueString *voidIdent_;
  UniqueString *nullIdent_;
  UniqueString *symbolIdent_;
  UniqueString *bigintIdent_;

  UniqueString *mappedTypeOptionalIdent_;
  UniqueString *mappedTypePlusOptionalIdent_;
  UniqueString *mappedTypeMinusOptionalIdent_;

  UniqueString *checksIdent_;
  UniqueString *assertsIdent_;
  UniqueString *impliesIdent_;

  UniqueString *componentIdent_;
  UniqueString *hookIdent_;
  UniqueString *rendersIdent_;
  UniqueString *rendersMaybeOperator_;
  UniqueString *rendersStarOperator_;

  UniqueString *matchIdent_;
  UniqueString *underscoreIdent_;
#endif

#if HERMES_PARSE_TS
  UniqueString *readonlyIdent_;
  UniqueString *neverIdent_;
  UniqueString *undefinedIdent_;
  UniqueString *unknownIdent_;
#endif

#if HERMES_PARSE_FLOW || HERMES_PARSE_TS
  UniqueString *namespaceIdent_;
  UniqueString *isIdent_;
  UniqueString *inferIdent_;
  UniqueString *constIdent_;
#endif

                                          
  UniqueString *tokenIdent_[NUM_JS_TOKENS];

  UniqueString *getTokenIdent(TokenKind kind) const {
    return tokenIdent_[(unsigned)kind];
  }

                                                                          
                                                                        
                
  template <class Node, class StartLoc, class EndLoc>
  Node *setLocation(StartLoc start, EndLoc end, Node *node) {
    node->setStartLoc(getStartLoc(start));
    node->setEndLoc(getEndLoc(end));
    node->setDebugLoc(getStartLoc(start));
    return node;
  }

                                                          
  template <class Node, class StartLoc, class EndLoc, class DebugLoc>
  Node *setLocation(StartLoc start, EndLoc end, DebugLoc debugLoc, Node *node) {
    node->setStartLoc(getStartLoc(start));
    node->setEndLoc(getEndLoc(end));
    node->setDebugLoc(getStartLoc(debugLoc));
    return node;
  }

                                                                          
                                                                           
                                                                           
                                      

  static SMLoc getStartLoc(const Token *tok) {
    return tok->getStartLoc();
  }
  static SMLoc getStartLoc(const ESTree::Node *from) {
    return from->getStartLoc();
  }
  static SMLoc getStartLoc(SMLoc loc) {
    return loc;
  }
  static SMLoc getStartLoc(const SMRange &rng) {
    return rng.Start;
  }

  static SMLoc getEndLoc(const Token *tok) {
    return tok->getEndLoc();
  }
  static SMLoc getEndLoc(const ESTree::Node *from) {
    return from->getEndLoc();
  }
  static SMLoc getEndLoc(SMLoc loc) {
    return loc;
  }
  static SMLoc getEndLoc(const SMRange &rng) {
    return rng.End;
  }

  SMLoc getPrevTokenEndLoc() const {
    return lexer_.getPrevTokenEndLoc();
  }

                                                                
                                                                                
                                                                        
  SMRange advance(
      JSLexer::GrammarContext grammarContext = JSLexer::AllowRegExp) {
    SMRange loc = tok_->getSourceRange();
    tok_ = lexer_.advance(grammarContext);
    return loc;
  }

                                                                          
                                    
                                                                               
                                                                            
                                                 
                                                                                
                                                                              
                                                                               
                                                                     
  void errorExpected(
      ArrayRef<TokenKind> toks,
      const char *where,
      const char *what,
      SMLoc whatLoc);

                                                 
  void errorExpected(
      TokenKind k1,
      const char *where,
      const char *what,
      SMLoc whatLoc) {
    errorExpected(ArrayRef<TokenKind>(k1), where, what, whatLoc);
  }

                                                 
  void errorExpected(
      TokenKind k1,
      TokenKind k2,
      const char *where,
      const char *what,
      SMLoc whatLoc) {
    TokenKind toks[] = {k1, k2};
    errorExpected(ArrayRef<TokenKind>(toks, 2), where, what, whatLoc);
  };

                                                                              
                                                          
                                                                            
                                    
  bool need(TokenKind kind, const char *where, const char *what, SMLoc whatLoc);

                                                
  void error(SMLoc loc, const llvh::Twine &message) {
    sm_.error(loc, message, Subsystem::Parser);
  }

                                                
  void error(SMRange range, const llvh::Twine &message) {
    sm_.error(range, message, Subsystem::Parser);
  }

                                                         
  void error(const llvh::Twine &msg) {
    error(tok_->getSourceRange(), msg);
  }

                                                                              
                                                                           
                     
                                                                              
  bool error(SMLoc loc, SMRange range, const llvh::Twine &msg);

                                                                                
                                                                               
                                                                               
                                        
                                                                            
                                    
  bool eat(
      TokenKind kind,
      JSLexer::GrammarContext grammarContext,
      const char *where,
      const char *what,
      SMLoc whatLoc);

                                                                                
                                         
  bool checkAndEat(
      TokenKind kind,
      JSLexer::GrammarContext grammarContext =
          JSLexer::GrammarContext::AllowRegExp);
                                                                                
                                                
  bool checkAndEat(
      UniqueString *ident,
      JSLexer::GrammarContext grammarContext =
          JSLexer::GrammarContext::AllowRegExp);
                                                                               
         
  bool check(TokenKind kind) const {
    return tok_->getKind() == kind;
  }
                                                                    
  bool check(UniqueString *ident) const {
    return tok_->getKind() == TokenKind::identifier &&
        tok_->getIdentifier() == ident;
  }
                                                                            
                    
  bool check(TokenKind kind1, TokenKind kind2) const {
    return tok_->getKind() == kind1 || tok_->getKind() == kind2;
  }

  template <typename T>
  inline bool checkN(T t) const {
    return check(t);
  }
                                                                               
                                                               
  template <typename Head, typename... Tail>
  inline bool checkN(Head h, Tail... tail) const {
    return check(h) || checkN(tail...);
  }

                                                                
  bool checkAssign() const;

                                                           
  bool checkDeclaration() {
    if (checkN(
            TokenKind::rw_function, TokenKind::rw_const, TokenKind::rw_class) ||
        (check(asyncIdent_) && checkAsyncFunction())) {
      return true;
    }

    if (check(letIdent_)) {
      if (isStrictMode()) {
        return true;
      }
                                                          
                       
              
              
                                              
                                                           
      return lexer_.isLetFollowedByDeclStart();
    }

#if HERMES_PARSE_FLOW
    if (context_.getParseFlow()) {
      if (context_.getParseFlowComponentSyntax() &&
          checkComponentDeclarationFlow()) {
        return true;
      }
      if (context_.getParseFlowComponentSyntax() &&
          checkHookDeclarationFlow()) {
        return true;
      }
      if (check(opaqueIdent_)) {
        auto optNext = lexer_.lookahead1(llvh::None);
        return optNext.hasValue() && (*optNext == TokenKind::identifier);
      }
      if (checkN(typeIdent_, interfaceIdent_)) {
        auto optNext = lexer_.lookahead1(llvh::None);
        return optNext.hasValue() && *optNext == TokenKind::identifier;
      }
      if (check(TokenKind::rw_interface)) {
        return true;
      }
      if (check(TokenKind::rw_enum)) {
        return true;
      }
    }
#endif

#if HERMES_PARSE_TS
    if (context_.getParseTS()) {
      if (checkN(typeIdent_, interfaceIdent_, namespaceIdent_)) {
        auto optNext = lexer_.lookahead1(llvh::None);
        return optNext.hasValue() && *optNext == TokenKind::identifier;
      }
      if (check(TokenKind::rw_interface)) {
        return true;
      }
      if (check(TokenKind::rw_enum)) {
        return true;
      }
    }
#endif

    return false;
  }

  bool checkDeclareType() {
#if HERMES_PARSE_FLOW
    if (check(declareIdent_)) {
      auto optNext = lexer_.lookahead1(llvh::None);
      if (!optNext)
        return false;
      TokenKind next = *optNext;
      return next == TokenKind::identifier || next == TokenKind::rw_interface ||
          next == TokenKind::rw_var || next == TokenKind::rw_const ||
          next == TokenKind::rw_function || next == TokenKind::rw_class ||
          next == TokenKind::rw_export || next == TokenKind::rw_enum;
    }
#endif
    return false;
  }

                                                                
  bool checkTemplateLiteral() const {
    return check(TokenKind::no_substitution_template, TokenKind::template_head);
  }

                                                                        
                           
  enum class OfEndsAssignment { No, Yes };

                                                                          
                           
                                                                                
                         
                    
  bool checkEndAssignmentExpression(
      OfEndsAssignment ofEndsAssignment = OfEndsAssignment::Yes) const;

                                                                       
                                        
  bool checkAsyncFunction();

                                                                            
                                                       
                                                                    
                                                                         
  bool eatSemi(bool optional = false);

                                                                             
                                      
  void processDirective(UniqueString *directive);

                                                                             
                                
                                                      
                                                                               
                                  
  inline bool recursionDepthCheck() {
    if (LLVM_LIKELY(recursionDepth_ < MAX_RECURSION_DEPTH)) {
      return false;
    }
    return recursionDepthExceeded();
  }

                                        
  bool recursionDepthExceeded();

                                                                               
                                                                               
                                         

  Optional<ESTree::ProgramNode *> parseProgram();
                                                                        
                                                                                
                          
  Optional<ESTree::FunctionDeclarationNode *> parseFunctionDeclaration(
      Param param,
      bool forceEagerly = false);

                                                                               
                                                                             
               
                                   
  Optional<ESTree::FunctionLikeNode *> parseFunctionHelper(
      Param param,
      bool isDeclaration,
      bool forceEagerly = false);

                                                                               
                       
                                         
                                                                
                                                
  bool parseFormalParameters(Param param, ESTree::NodeList &paramList);

                                  
  Optional<ESTree::Node *> parseStatement(Param param);

  enum class AllowImportExport {
    No,
    Yes,
  };

                             
                          
                                                             
                                                                              
                                                                          
                    
                                            
  template <typename... Tail>
  Optional<bool> parseStatementList(
      Param param,
      TokenKind until,
      bool parseDirectives,
      AllowImportExport allowImportExport,
      ESTree::NodeList &stmtList,
      Tail... otherUntil);

  bool parseStatementListItem(
      Param param,
      AllowImportExport allowImportExport,
      ESTree::NodeList &stmtList);

                              
                                  
                                                                                
                                                                              
                                                                          
                    
  Optional<ESTree::BlockStatementNode *> parseBlock(
      Param param,
      JSLexer::GrammarContext grammarContext = JSLexer::AllowRegExp,
      bool parseDirectives = false);

                                                                        
                               
                                                                             
                                  
                                                                             
                                  
                          
  Optional<ESTree::BlockStatementNode *> parseFunctionBody(
      Param param,
      bool eagerly,
      bool paramYield,
      bool paramAwait,
      JSLexer::GrammarContext grammarContext = JSLexer::AllowRegExp,
      bool parseDirectives = false);

                          
                          
  Optional<ESTree::Node *> parseDeclaration(Param param);

                                                                 
                                                                         
                                                                       
                          
                                                                  
                                           
                                                                   
                                                          
  bool validateBindingIdentifier(
      Param param,
      SMRange range,
      UniqueString *id,
      TokenKind kind);

                  
                                                                            
                          
  Optional<ESTree::IdentifierNode *> parseBindingIdentifier(Param param);
                                                      
                              
  Optional<ESTree::VariableDeclarationNode *> parseLexicalDeclaration(
      Param param);
                                                      
                          
  Optional<ESTree::VariableDeclarationNode *> parseVariableStatement(
      Param param);

                                                
  Optional<ESTree::PrivateNameNode *> parsePrivateName();

                                                                           
                                                    
                              
                                                                                
              
  Optional<const char *> parseVariableDeclarationList(
      Param param,
      ESTree::NodeList &declList,
      SMLoc declLoc);

                              
                                                                               
                    
  Optional<ESTree::VariableDeclaratorNode *> parseVariableDeclaration(
      Param param,
      SMLoc declLoc);

                                                                             
                                                             
  void ensureDestructuringInitialized(
      ESTree::VariableDeclarationNode *declNode);

  Optional<ESTree::Node *> parseBindingPattern(Param param);
  Optional<ESTree::ArrayPatternNode *> parseArrayBindingPattern(Param param);
  Optional<ESTree::Node *> parseBindingElement(Param param);
  Optional<ESTree::Node *> parseBindingRestElement(Param param);
                                                   
  Optional<ESTree::AssignmentPatternNode *> parseBindingInitializer(
      Param param,
      ESTree::Node *left);
  Optional<ESTree::ObjectPatternNode *> parseObjectBindingPattern(Param param);
  Optional<ESTree::PropertyNode *> parseBindingProperty(Param param);
  Optional<ESTree::Node *> parseBindingRestProperty(Param param);

  Optional<ESTree::EmptyStatementNode *> parseEmptyStatement();
                                  
  Optional<ESTree::Node *> parseExpressionOrLabelledStatement(Param param);
                                  
  Optional<ESTree::IfStatementNode *> parseIfStatement(Param param);
                                  
  Optional<ESTree::WhileStatementNode *> parseWhileStatement(Param param);
                                  
  Optional<ESTree::DoWhileStatementNode *> parseDoWhileStatement(Param param);
                                  
  Optional<ESTree::Node *> parseForStatement(Param param);
  Optional<ESTree::ContinueStatementNode *> parseContinueStatement();
  Optional<ESTree::BreakStatementNode *> parseBreakStatement();
  Optional<ESTree::ReturnStatementNode *> parseReturnStatement();
                                  
  Optional<ESTree::WithStatementNode *> parseWithStatement(Param param);
                                  
  Optional<ESTree::SwitchStatementNode *> parseSwitchStatement(Param param);
                          
  Optional<ESTree::ThrowStatementNode *> parseThrowStatement(Param param);
                                  
  Optional<ESTree::TryStatementNode *> parseTryStatement(Param param);
  Optional<ESTree::DebuggerStatementNode *> parseDebuggerStatement();

  Optional<ESTree::Node *> parsePrimaryExpression();
  Optional<ESTree::ArrayExpressionNode *> parseArrayLiteral();
  Optional<ESTree::ObjectExpressionNode *> parseObjectLiteral();
  Optional<ESTree::Node *> parseSpreadElement();
  Optional<ESTree::Node *> parsePropertyAssignment(bool eagerly);

                                                                            
                                
  Optional<ESTree::Node *> parsePropertyName();

                                                                 
                             
                                  
  Optional<ESTree::Node *> parseTemplateLiteral(Param param);

  Optional<ESTree::FunctionExpressionNode *> parseFunctionExpression(
      bool forceEagerly = false);

                                                                             
                                                                    
  enum class IsConstructorCall { No, Yes };

                                                                              
                 
  Optional<ESTree::Node *> parseOptionalExpressionExceptNew(
      IsConstructorCall isConstructorCall);

                                                                        
                                                                           
                                                                             
                                                       
  Optional<ESTree::Node *> parseOptionalExpressionExceptNew_tail(
      IsConstructorCall isConstructorCall,
      SMLoc startLoc,
      ESTree::Node *expr);

                                                                             
                      
  Optional<const char *> parseArguments(
      ESTree::NodeList &argList,
      SMLoc &endLoc);

                                                          
                                                                               
                                 
                                                                       
                                                                 
  Optional<ESTree::Node *> parseMemberSelect(
      SMLoc startLoc,
      SMLoc objectLoc,
      ESTree::NodePtr expr,
      bool seenOptionalChain);

                                                                          
                  
                                                                        
                                                                          
                                 
                                                                                
  Optional<ESTree::Node *> parseCallExpression(
      SMLoc startLoc,
      ESTree::NodePtr expr,
      ESTree::NodePtr typeArgs,
      bool seenOptionalChain,
      bool optional);

                                                          
                                                                           
                                                               
     
           
                        
                              
                               
     
                           
                                            
              
     
                                                                            
                  
                                                                              
                                                                       
                                                                               
                                             
  Optional<ESTree::Node *> parseNewExpressionOrOptionalExpression(
      IsConstructorCall isConstructorCall);
  Optional<ESTree::Node *> parseLeftHandSideExpression();
                                                                              
                                                                
  Optional<ESTree::Node *> parseLeftHandSideExpressionTail(
      SMLoc startLoc,
      ESTree::Node *expr);
  Optional<ESTree::Node *> parsePostfixExpression();
  Optional<ESTree::Node *> parseUnaryExpression();

                                                         
                                                                                
                                                         
  inline void convertIdentOpIfPossible();

                                                                              
                      
  Optional<ESTree::Node *> parseBinaryExpression(Param param);

                                                                           
  enum class AllowTypedArrowFunction { No, Yes };

                                                                    
                                                                     
  enum class CoverTypedParameters { No, Yes };

  Optional<ESTree::Node *> parseConditionalExpression(
      Param param = ParamIn,
      CoverTypedParameters coverTypedParameters = CoverTypedParameters::Yes);
  Optional<ESTree::YieldExpressionNode *> parseYieldExpression(
      Param param = ParamIn);

  Optional<ESTree::ClassDeclarationNode *> parseClassDeclaration(Param param);
  Optional<ESTree::ClassExpressionNode *> parseClassExpression();

  enum class ClassParseKind { Declaration, Expression };

                                                                  
                                                             
                                                                          
                
                                                                   
  Optional<ESTree::Node *> parseClassTail(
      SMLoc startLoc,
      ESTree::Node *name,
      ESTree::Node *typeParams,
      ClassParseKind kind);

  Optional<ESTree::ClassBodyNode *> parseClassBody(SMLoc startLoc);

  Optional<ESTree::Node *> parseClassElement(
      bool isStatic,
      SMRange startRange,
      bool declare,
      bool readonly,
      ESTree::NodeLabel accessibility,
      bool eagerly = false);

                                                                               
                                                                               
                            
                                                                         
                                                                                
                                                                              
                                                                            
                                   
  bool reparseArrowParameters(
      ESTree::Node *node,
      bool hasNewLine,
      ESTree::NodeList &paramList,
      bool &isAsync);

                                                           
                                            
                                                                           
                                                                            
                                 
  Optional<ESTree::Node *> parseArrowFunctionExpression(
      Param param,
      ESTree::Node *leftExpr,
      bool hasNewLine,
      ESTree::Node *typeParams,
      ESTree::Node *returnType,
      ESTree::Node *predicate,
      SMLoc startLoc,
      AllowTypedArrowFunction allowTypedArrowFunction,
      bool forceAsync);

#if HERMES_PARSE_FLOW
  Optional<ESTree::Node *> tryParseTypedAsyncArrowFunction(Param param);

                                                                     
                                                                
                                                                    
                                                                       
                                                                               
                                                                       
                                                                         
                                                                  
  Optional<ESTree::Node *> tryParseCoverTypedIdentifierNode(
      ESTree::Node *test,
      bool optional);
#endif

                                                      
                                                                        
  Optional<ESTree::Node *> reparseArrayAsignmentPattern(
      ESTree::ArrayExpressionNode *AEN,
      bool inDecl);

                                                        
                                                                        
  Optional<ESTree::Node *> reparseObjectAssignmentPattern(
      ESTree::ObjectExpressionNode *OEN,
      bool inDecl);

                                                                         
                    
                                                                        
  Optional<ESTree::Node *> reparseAssignmentPattern(
      ESTree::Node *node,
      bool inDecl);

  Optional<ESTree::Node *> parseAssignmentExpression(
      Param param = ParamIn,
      AllowTypedArrowFunction allowTypedArrowFunction =
          AllowTypedArrowFunction::Yes,
      CoverTypedParameters coverTypedParameters = CoverTypedParameters::Yes,
      ESTree::Node *typeParams = nullptr);

  Optional<ESTree::Node *> parseExpression(
      Param param = ParamIn,
      CoverTypedParameters coverTypedParameters = CoverTypedParameters::Yes);

                                                                               
  Optional<ESTree::StringLiteralNode *> parseFromClause();

  bool parseAssertClause(ESTree::NodeList &attributes);

  Optional<ESTree::ImportDeclarationNode *> parseImportDeclaration();

                                     
  Optional<UniqueString *> parseImportClause(ESTree::NodeList &specifiers);

  Optional<ESTree::Node *> parseNameSpaceImport();
  bool parseNamedImports(ESTree::NodeList &specifiers);
  Optional<ESTree::ImportSpecifierNode *> parseImportSpecifier(SMLoc importLoc);

  Optional<ESTree::Node *> parseExportDeclaration();

                                                           
                                                                          
                                                                            
  bool parseExportClause(
      ESTree::NodeList &specifiers,
      llvh::SmallVectorImpl<SMRange> &invalids);

                                                                          
                                                                            
                                                                 
  Optional<ESTree::Node *> parseExportSpecifier(
      SMLoc exportLoc,
      llvh::SmallVectorImpl<SMRange> &invalids);

                                                                         
                                                                         
                                                              
                                                                          
                          
  ESTree::ExpressionStatementNode *parseDirective();

#if HERMES_PARSE_JSX
  Optional<ESTree::Node *> parseJSX();
  Optional<ESTree::Node *> parseJSXElement(SMLoc start);
  Optional<ESTree::Node *> parseJSXFragment(SMLoc start);

  Optional<ESTree::JSXOpeningElementNode *> parseJSXOpeningElement(SMLoc start);
  Optional<ESTree::Node *> parseJSXSpreadAttribute();
  Optional<ESTree::Node *> parseJSXAttribute();

                                                      
                                                          
  Optional<ESTree::Node *> parseJSXChildren(ESTree::NodeList &children);
  Optional<ESTree::Node *> parseJSXChildExpression(SMLoc start);

                                                    
  Optional<ESTree::Node *> parseJSXClosing(SMLoc start);

  enum class AllowJSXMemberExpression { No, Yes };

                                                                             
                                        
  Optional<ESTree::Node *> parseJSXElementName(
      AllowJSXMemberExpression allowJSXMemberExpression);
#endif

#if HERMES_PARSE_FLOW || HERMES_PARSE_TS
  enum class AllowAnonFunctionType { No, Yes };

  Optional<ESTree::Node *> parseTypeAnnotation(
      Optional<SMLoc> wrappedStart = None,
      AllowAnonFunctionType allowAnonFunctionType =
          AllowAnonFunctionType::Yes) {
    assert(context_.getParseFlow() || context_.getParseTS());
#if HERMES_PARSE_FLOW
    if (context_.getParseFlow())
      return parseTypeAnnotationFlow(wrappedStart, allowAnonFunctionType);
#endif
#if HERMES_PARSE_TS
    return parseTypeAnnotationTS(wrappedStart);
#endif
    llvm_unreachable("Must be parsing types");
  }

  Optional<ESTree::Node *> parseReturnTypeAnnotation(
      Optional<SMLoc> wrappedStart = None,
      AllowAnonFunctionType allowAnonFunctionType =
          AllowAnonFunctionType::Yes) {
    assert(context_.getParseFlow() || context_.getParseTS());
#if HERMES_PARSE_FLOW
    if (context_.getParseFlow())
      return parseReturnTypeAnnotationFlow(wrappedStart, allowAnonFunctionType);
#endif
#if HERMES_PARSE_TS
    return parseTypeAnnotationTS(wrappedStart);
#endif
    llvm_unreachable("Must be parsing types");
  }

  Optional<ESTree::Node *> parseTypeArguments() {
    assert(context_.getParseFlow() || context_.getParseTS());
#if HERMES_PARSE_FLOW
    if (context_.getParseFlow())
      return parseTypeArgsFlow();
#endif
#if HERMES_PARSE_TS
    return parseTSTypeArguments();
#endif
    llvm_unreachable("Must be parsing types");
  }
#endif

#if HERMES_PARSE_FLOW
                                                                             
                                              
                                      
                                       
                      
         
                                                                            
                                                                           
                                                             
                                       
                   
                                                  
                   
                                                                  
                                                                          
                                                                              
                                                                             
                                                                              
                                                              
                                            
  Optional<ESTree::Node *> parseTypeAnnotationBeforeColonFlow();
                                                                            
                                                                        
                                                               
  Optional<ESTree::Node *> parseTypeAnnotationFlow(
      Optional<SMLoc> wrappedStart = None,
      AllowAnonFunctionType allowAnonFunctionType = AllowAnonFunctionType::Yes);
                                                                            
                                                                        
                                                               
  Optional<ESTree::Node *> parseReturnTypeAnnotationFlow(
      Optional<SMLoc> wrappedStart = None,
      AllowAnonFunctionType allowAnonFunctionType = AllowAnonFunctionType::Yes);

  Optional<ESTree::Node *> parseFlowDeclaration();
  Optional<ESTree::Node *> parseDeclareFLow(SMLoc start);
  bool checkComponentDeclarationFlow();
  Optional<ESTree::Node *> parseComponentDeclarationFlow(
      SMLoc start,
      bool declare);
  bool checkHookDeclarationFlow();
  Optional<ESTree::Node *> parseHookDeclarationFlow(SMLoc start);

                                                                         
                                                                         
                                                                                
                            
  Optional<ESTree::Node *> parseComponentRenderTypeFlow(bool componentType);

                                                                          
                                                                         
                                                                              
  bool parseComponentParametersFlow(Param param, ESTree::NodeList &paramList);
  Optional<ESTree::Node *> parseComponentParameterFlow(Param param);

  Optional<ESTree::Node *> parseComponentTypeAnnotationFlow();
                                                                              
                                                                         
                                       
                                                                            
                         
  Optional<ESTree::Node *> parseComponentTypeParametersFlow(
      Param param,
      ESTree::NodeList &paramList);
  Optional<ESTree::Node *> parseComponentTypeRestParameterFlow(Param param);
  Optional<ESTree::Node *> parseComponentTypeParameterFlow(Param param);

                                                                         
                                                      
  bool checkMaybeFlowMatch() {
    if (!check(matchIdent_))
      return false;
    return checkMaybeFlowMatchSlowPath();
  }
  bool checkMaybeFlowMatchSlowPath();
                                                                          
                                                             
  ESTree::Node *reparseArgumentsAsMatchArgumentFlow(
      SMRange range,
      ESTree::NodeList &&argList);
                                                                       
                                                                         
                                                                
                                                                             
                                                                                
                                                                       
                    
  Optional<ESTree::Node *> tryParseMatchStatementFlow(Param param);
                                                                   
                          
  Optional<ESTree::Node *> parseMatchCallOrMatchExpressionFlow();
  Optional<ESTree::Node *> parseMatchExpressionFlow(
      SMLoc start,
      ESTree::Node *argument);
  Optional<ESTree::Node *> parseMatchPatternFlow();
  Optional<ESTree::Node *> parseMatchSubpatternFlow();
  Optional<ESTree::IdentifierNode *> parseMatchBindingIdentifierFlow();
  Optional<ESTree::MatchBindingPatternNode *> parseMatchBindingPatternFlow();
  Optional<ESTree::Node *> parseMatchRestPatternFlow();
  Optional<ESTree::Node *> parseMatchObjectPatternFlow();
  Optional<ESTree::Node *> parseMatchArrayPatternFlow();

  enum class TypeAliasKind { None, Declare, Opaque, DeclareOpaque };
  Optional<ESTree::Node *> parseTypeAliasFlow(SMLoc start, TypeAliasKind kind);

                                                                          
                                                                   
  Optional<ESTree::Node *> parseInterfaceDeclarationFlow(
      Optional<SMLoc> declareStart = None);

                                             
                                                                        
                                       
  Optional<ESTree::Node *> parseInterfaceTailFlow(
      SMLoc start,
      ESTree::NodeList &extends);
  bool parseInterfaceExtends(SMLoc start, ESTree::NodeList &extends);

  Optional<ESTree::Node *> parseDeclareFunctionFlow(SMLoc start);
  Optional<ESTree::Node *> parseDeclareHookFlow(SMLoc start);
  Optional<ESTree::Node *> parseDeclareFunctionOrHookFlow(
      SMLoc start,
      bool hook);
  Optional<ESTree::Node *> parseDeclareClassFlow(SMLoc start);
  Optional<ESTree::Node *> parseDeclareExportFlow(SMLoc start);
  Optional<ESTree::Node *> parseDeclareModuleFlow(SMLoc start);
  Optional<ESTree::Node *> parseDeclareNamespaceFlow(SMLoc start);

  Optional<ESTree::Node *> parseExportTypeDeclarationFlow(SMLoc start);

  Optional<ESTree::Node *> parseConditionalTypeAnnotationFlow();
  Optional<ESTree::Node *> parseUnionTypeAnnotationFlow();
  Optional<ESTree::Node *> parseIntersectionTypeAnnotationFlow();
  Optional<ESTree::Node *> parseAnonFunctionWithoutParensTypeAnnotationFlow();
  Optional<ESTree::Node *> parsePrefixTypeAnnotationFlow();
  Optional<ESTree::Node *> parsePostfixTypeAnnotationFlow();
  Optional<ESTree::Node *> parsePrimaryTypeAnnotationFlow();
  Optional<ESTree::Node *> parseTypeofTypeAnnotationFlow();
  Optional<ESTree::Node *> parseTupleTypeAnnotationFlow();
                                                                      
  Optional<ESTree::Node *> parseTupleElementFlow(
      SMLoc startLoc,
      bool startsWithDotDotDot);
  Optional<ESTree::Node *> parseFunctionTypeAnnotationFlow();
  Optional<ESTree::Node *> parseHookTypeAnnotationFlow();
  Optional<ESTree::Node *> parseFunctionOrHookTypeAnnotationFlow(bool hook);
  Optional<ESTree::Node *> parseFunctionTypeAnnotationWithParamsFlow(
      SMLoc start,
      ESTree::NodeList &&params,
      ESTree::Node *thisConstraint,
      ESTree::Node *rest,
      ESTree::Node *typeParams,
      bool hook);
  Optional<ESTree::Node *> parseFunctionOrGroupTypeAnnotationFlow();

                                                                       
  enum class AllowProtoProperty { No, Yes };

                                                                        
  enum class AllowStaticProperty { No, Yes };

                                                                      
  enum class AllowSpreadProperty { No, Yes };

  Optional<ESTree::Node *> parseObjectTypeAnnotationFlow(
      AllowProtoProperty allowProtoProperty,
      AllowStaticProperty allowStaticProperty,
      AllowSpreadProperty allowSpreadProperty);
  bool parseObjectTypePropertiesFlow(
      AllowProtoProperty allowProtoProperty,
      AllowStaticProperty allowStaticProperty,
      AllowSpreadProperty allowSpreadProperty,
      ESTree::NodeList &properties,
      ESTree::NodeList &indexers,
      ESTree::NodeList &callProperties,
      ESTree::NodeList &internalSlots,
      bool &inexact);
  bool parsePropertyTypeAnnotationFlow(
      AllowProtoProperty allowProtoProperty,
      AllowStaticProperty allowStaticProperty,
      ESTree::NodeList &properties,
      ESTree::NodeList &indexers,
      ESTree::NodeList &callProperties,
      ESTree::NodeList &internalSlots);

                                                                      
  Optional<ESTree::Node *> parseTypeMappedTypePropertyFlow(
      SMLoc start,
      ESTree::Node *left,
      ESTree::Node *variance);
                                                                      
  Optional<ESTree::Node *> parseTypeIndexerPropertyFlow(
      SMLoc start,
      ESTree::Node *left,
      ESTree::Node *variance,
      bool isStatic);

  Optional<ESTree::Node *> parseTypePropertyFlow(
      SMLoc start,
      ESTree::Node *variance,
      bool isStatic,
      bool proto,
      ESTree::Node *key);
  Optional<ESTree::Node *>
  parseMethodTypePropertyFlow(SMLoc start, bool isStatic, ESTree::Node *key);
  Optional<ESTree::Node *> parseGetOrSetTypePropertyFlow(
      SMLoc start,
      bool isStatic,
      bool isGetter,
      ESTree::Node *key);

  Optional<ESTree::Node *> parseTypeParamsFlow();
  Optional<ESTree::Node *> parseTypeParamFlow();
  Optional<ESTree::Node *> parseTypeArgsFlow();

                                                                
                                                                
                                                                            
                         
  Optional<ESTree::FunctionTypeParamNode *>
  parseFunctionTypeAnnotationParamsFlow(
      ESTree::NodeList &params,
      ESTree::NodePtr &thisConstraint,
      bool hook);
  Optional<ESTree::FunctionTypeParamNode *> parseHookTypeAnnotationParamFlow();
  Optional<ESTree::FunctionTypeParamNode *>
  parseFunctionTypeAnnotationParamFlow();

  Optional<ESTree::Node *> parseTypeCallPropertyFlow(
      SMLoc start,
      bool isStatic);

  Optional<ESTree::GenericTypeAnnotationNode *> parseGenericTypeFlow();

  Optional<ESTree::ClassImplementsNode *> parseClassImplementsFlow();

                                                                              
                                                                              
  Optional<ESTree::FunctionTypeAnnotationNode *>
  parseMethodishTypeAnnotationFlow(SMLoc start, ESTree::Node *typeParams);

  Optional<ESTree::Node *> parsePredicateFlow();

                                                                             
                        
                                                                                
                         
  Optional<UniqueString *> reparseTypeAnnotationAsIdFlow(
      ESTree::Node *typeAnnotation);
                                                                 
                                                                                
                         
  Optional<ESTree::IdentifierNode *> reparseTypeAnnotationAsIdentifierFlow(
      ESTree::Node *typeAnnotation);

  enum class EnumKind {
    String,
    Number,
    BigInt,
    Boolean,
    Symbol,
  };

  static llvh::StringRef enumKindStrFlow(EnumKind kind) {
    switch (kind) {
      case EnumKind::String:
        return "string";
      case EnumKind::Number:
        return "number";
      case EnumKind::BigInt:
        return "bigint";
      case EnumKind::Boolean:
        return "boolean";
      case EnumKind::Symbol:
        return "symbol";
    }
    llvm_unreachable("No other kind of enum");
  }

  static OptValue<EnumKind> getMemberEnumKindFlow(ESTree::Node *member) {
    switch (member->getKind()) {
      case ESTree::NodeKind::EnumStringMember:
        return EnumKind::String;
      case ESTree::NodeKind::EnumNumberMember:
        return EnumKind::Number;
      case ESTree::NodeKind::EnumBigIntMember:
        return EnumKind::BigInt;
      case ESTree::NodeKind::EnumBooleanMember:
        return EnumKind::Boolean;
      default:
        return None;
    }
  }

                                                   
  Optional<ESTree::Node *> parseEnumDeclarationFlow(SMLoc start, bool declare);
  Optional<ESTree::Node *> parseEnumBodyFlow(
      OptValue<EnumKind> optKind,
      Optional<SMLoc> explicitTypeStart);
  Optional<ESTree::Node *> parseEnumMemberFlow();
#endif

#if HERMES_PARSE_TS
                                                  
  enum class IsConstructorType { No, Yes };

  Optional<ESTree::Node *> parseTypeAnnotationTS(
      Optional<SMLoc> wrappedStart = None);

  Optional<ESTree::Node *> parseTSDeclaration();
  Optional<ESTree::Node *> parseTSTypeAliasDeclaration(SMLoc start);
  Optional<ESTree::Node *> parseTSInterfaceDeclaration();
  Optional<ESTree::Node *> parseTSEnumDeclaration();
  Optional<ESTree::Node *> parseTSEnumMember();
  Optional<ESTree::Node *> parseTSNamespaceDeclaration();

  Optional<ESTree::Node *> parseTSTypeParameters();
  Optional<ESTree::Node *> parseTSTypeParameter();

  Optional<ESTree::Node *> parseTSUnionType();
  Optional<ESTree::Node *> parseTSIntersectionType();
  Optional<ESTree::Node *> parseTSTupleType();
  Optional<ESTree::Node *> parseTSFunctionOrParenthesizedType(
      SMLoc start,
      ESTree::Node *typeParams,
      IsConstructorType isConstructorType);
  bool parseTSFunctionTypeParams(SMLoc start, ESTree::NodeList &params);
  Optional<ESTree::Node *> parseTSFunctionTypeParam();

  Optional<ESTree::Node *> parseTSObjectType();
  Optional<ESTree::Node *> parseTSObjectTypeMember();
  Optional<ESTree::Node *> parseTSIndexSignature(SMLoc start);

  Optional<ESTree::Node *> parseTSPostfixType();
  Optional<ESTree::Node *> parseTSPrimaryType();
  Optional<ESTree::TSTypeReferenceNode *> parseTSTypeReference();
  Optional<ESTree::Node *> parseTSQualifiedName();
  Optional<ESTree::Node *> parseTSTypeQuery();
  Optional<ESTree::Node *> parseTSTypeArguments();

  ESTree::Node *reparseIdentifierAsTSTypeAnnotation(
      ESTree::IdentifierNode *ident);

                                                                    
                                                                             
                                                      
     
                                                      
                                                                               
                             
  static bool canFollowModifierTS(OptValue<TokenKind> optTokenKind) {
    if (!optTokenKind.hasValue()) {
      return false;
    }
    switch (*optTokenKind) {
      case TokenKind::identifier:
      case TokenKind::private_identifier:
      case TokenKind::rw_private:
      case TokenKind::rw_protected:
      case TokenKind::rw_public:
      case TokenKind::rw_static:
        return true;
      default:
        return false;
    }
  }
#endif

                                                                       
                        
  class SaveStrictModeAndSeenDirectives {
    JSParserImpl *const parser_;
    const bool oldStrictMode_;
    const unsigned oldSeenDirectiveSize_;

   public:
    explicit SaveStrictModeAndSeenDirectives(JSParserImpl *parser)
        : parser_(parser),
          oldStrictMode_(parser->isStrictMode()),
          oldSeenDirectiveSize_(parser->getSeenDirectives().size()) {}
    ~SaveStrictModeAndSeenDirectives() {
      parser_->setStrictMode(oldStrictMode_);
      parser_->getSeenDirectives().resize(oldSeenDirectiveSize_);
    }
  };

                                        
  class TrackRecursion {
    JSParserImpl *const parser_;

   public:
    TrackRecursion(JSParserImpl *parser) : parser_(parser) {
      ++parser_->recursionDepth_;
    }
    ~TrackRecursion() {
      --parser_->recursionDepth_;
    }
  };

                                                                           
                                                                  
                     
                                                          
#define CHECK_RECURSION                \
  TrackRecursion trackRecursion{this}; \
  if (recursionDepthCheck())           \
    return llvh::None;
};

}                    
}                    
}                    

#endif                                

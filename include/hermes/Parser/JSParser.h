/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_PARSER_JSPARSER_H
#define HERMES_PARSER_JSPARSER_H

#include "hermes/AST/Context.h"
#include "hermes/AST/ESTree.h"
#include "hermes/Parser/JSLexer.h"

#include "llvh/ADT/Optional.h"
#include "llvh/ADT/StringRef.h"

namespace hermes {
namespace parser {

namespace detail {
class JSParserImpl;
}

                                                              
enum ParserPass {
                                                                    
  PreParse,

                                                                             
                                      
  LazyParse,

                                                                              
  FullParse
};

                             
class JSParser {
  explicit JSParser(std::shared_ptr<detail::JSParserImpl> &&impl)
      : impl_(std::move(impl)) {}

 public:
  explicit JSParser(
      Context &context,
      std::unique_ptr<llvh::MemoryBuffer> input);

  explicit JSParser(Context &context, uint32_t bufferId, ParserPass pass);

  JSParser(Context &context, llvh::StringRef input)
      : JSParser(
            context,
            llvh::MemoryBuffer::getMemBuffer(input, "JavaScript")) {}

  JSParser(Context &context, llvh::MemoryBufferRef input)
      : JSParser(context, llvh::MemoryBuffer::getMemBuffer(input)) {}

  ~JSParser();

  Context &getContext();

  bool isStrictMode() const;

  void setStrictMode(bool mode);

                                                                                
                           
  llvh::StringRef getSourceURL() const;

                                                                               
                                    
  llvh::StringRef getSourceMappingURL() const;

                                              
  struct MCFlag {
    using Type = uint8_t;
    enum : Type {
      SourceURL = 1 << 0,
      SourceMappingURL = 1 << 1,
      All = SourceURL | SourceMappingURL,
    };
  };
                                                                              
                                                   
                                                 
  void registerMagicURLs(MCFlag::Type flags = MCFlag::All) const;

  llvh::ArrayRef<StoredComment> getStoredComments() const;

  std::vector<StoredComment> moveStoredComments() const;

  llvh::ArrayRef<StoredToken> getStoredTokens() const;

  void setStoreComments(bool storeComments);

  void setStoreTokens(bool storeTokens);

                                                                                
             
  bool getUseStaticBuiltin() const;

  llvh::Optional<ESTree::ProgramNode *> parse();

  void seek(SMLoc startPos);

                                                                               
                                             
                                                                         
                                                                             
                             
  static std::unique_ptr<JSParser> preParseBuffer(
      Context &context,
      uint32_t bufferId);

                                                                           
                                                                            
                     
  llvh::Optional<ESTree::NodePtr> parseLazyFunction(
      ESTree::NodeKind kind,
      bool paramYield,
      bool paramAwait,
      SMLoc start);

 private:
                       
                                                                               
  std::shared_ptr<detail::JSParserImpl> const impl_;
};

}                    
}                    

#endif                            

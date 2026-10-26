/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Parser/FlowHelpers.h"

#include "hermes/AST/Context.h"
#include "hermes/Parser/JSLexer.h"
#include "hermes/Support/SimpleDiagHandler.h"

namespace hermes {
namespace parser {

std::vector<StoredComment> getCommentsInDocBlock(
    Context &context,
    uint32_t bufferId) {
                                                                              
  SourceErrorManager::SaveAndSuppressMessages saveAndSupress{
      &context.getSourceErrorManager()};
  parser::JSLexer lexer(
      bufferId,
      context.getSourceErrorManager(),
      context.getAllocator(),
      &context.getStringTable(),
      context.isStrictMode());
  lexer.setStoreComments(true);

                                                                         
  lexer.advance();
  size_t numComments = lexer.getStoredComments().size();

  while (lexer.isCurrentTokenADirective()) {
    const parser::Token *token = lexer.advance();

                                                                  
    if (token->getKind() == parser::TokenKind::semi) {
      lexer.advance();
    }

    numComments = lexer.getStoredComments().size();
  }

                                                                               
  std::vector<StoredComment> result = lexer.moveStoredComments();
  result.erase(result.begin() + numComments, result.end());
  return result;
}

bool hasFlowPragma(llvh::ArrayRef<StoredComment> comments) {
                                                                 
  for (auto &comment : comments) {
    if (comment.getKind() == parser::StoredComment::Kind::Hashbang) {
      continue;
    }

    llvh::StringRef value = comment.getString();

    size_t offset = value.find("@flow");
    while (offset < value.size() - 4) {
      const char *ptr = value.data() + offset;
                                                  
      if (offset == value.size() - 5) {
        return true;
      }

                                                      
                                           
      const char ch = ptr[5];
      if (!(((ch | 32) >= 'a' && (ch | 32) <= 'z') ||
            (ch >= '0' && ch <= '9') || ch == '_')) {
        return true;
      }

      offset = value.find("@flow", offset + 1);
    }
  }

  return false;
}

std::string getDocBlock(llvh::ArrayRef<StoredComment> comments) {
  std::string result{};
  for (const auto &comment : comments) {
    result += comment.getFullString();
    result.push_back('\n');
  }
  return result;
}

}                    
}                    

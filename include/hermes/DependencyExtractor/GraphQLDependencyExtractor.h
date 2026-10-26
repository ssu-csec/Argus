/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_DEPENDENCYEXTRACTOR_GRAPHQLDEPENDENCYEXTRACTOR_H
#define HERMES_DEPENDENCYEXTRACTOR_GRAPHQLDEPENDENCYEXTRACTOR_H

#include "hermes/Regex/Executor.h"
#include "hermes/Regex/Regex.h"
#include "hermes/Regex/RegexTraits.h"

namespace hermes {

namespace graphql {

                                                                            
inline std::vector<uint8_t> getCompiledGraphQLRegex() {
                                                                          
               
  regex::Regex<regex::UTF16RegexTraits> graphqlQueryRegex{
      u"(?:^\\s*?(?:query|fragment|mutation|subscription) +(\\w+))", u"m"};
  return graphqlQueryRegex.compile();
}

                                                                 
                                                                    
                                                                      
                 
                                                                 
                                                           
template <typename ElementCB>
void getGraphQLDependencies(
    llvh::StringRef templateString,
    std::vector<uint8_t> &graphqlQueryRegexBytecode,
    ElementCB callback) {
  std::vector<regex::CapturedRange> captures{};
  uint32_t searchStart = 0;
  for (;;) {
    captures.clear();
    regex::MatchRuntimeResult matchResult = regex::searchWithBytecode(
        graphqlQueryRegexBytecode,
        templateString.data(),
        searchStart,
        templateString.size(),
        &captures,
        regex::constants::MatchFlagType::matchDefault);
    if (matchResult != regex::MatchRuntimeResult::Match) {
      return;
    }
    callback(templateString.slice(captures[1].start, captures[1].end));
    searchStart = captures[0].end;
  }
}
}                     
}                    

#endif

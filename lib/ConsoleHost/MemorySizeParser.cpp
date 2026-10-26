/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/ConsoleHost/MemorySizeParser.h"

namespace cl {

bool MemorySizeParser::parse(
    cl::Option &O,
    llvh::StringRef ArgName,
    const std::string &Arg,
    MemorySize &Val) {
  const char *ArgStart = Arg.c_str();
  char *End;

                                                                             
  Val.bytes = (unsigned)strtol(ArgStart, &End, 0);

  if (End == ArgStart) {
    return O.error("'" + Arg + "' value invalid for file size argument!");
  }

  enum ParserState {
    SawNum,
    SawPrefix,
    SawPrefixPlusI,
    SawWholeSpec,
    Error,
  };

  ParserState state = SawNum;

  while (1) {
    if (state == Error) {
      return O.error("'" + Arg + "' value invalid for file size argument!");
    }
    char c = *End++;
    switch (c) {
      case 0:
        if (state == SawPrefixPlusI) {
          state = Error;
        } else {
          return false;            
        }
        break;
      case 'i':                                            
        if (state == SawPrefix) {
          state = SawPrefixPlusI;
        } else {
          state = Error;
        }
        break;
      case 'b':
      case 'B':                   
        if (state == SawWholeSpec) {
          state = Error;
        } else {
          state = SawWholeSpec;
        }
        break;

      case 'g':
      case 'G':
      case 'm':
      case 'M':
      case 'k':
      case 'K':
        if (state != SawNum) {
          state = Error;
        } else {
          switch (c) {
            case 'g':
            case 'G':
              Val.bytes *= 1024 * 1024 * 1024;
              break;
            case 'm':
            case 'M':
              Val.bytes *= 1024 * 1024;
              break;
            case 'k':
            case 'K':
              Val.bytes *= 1024;
              break;
          }
          state = SawPrefix;
        }
        break;

      default:
                                                            
        return O.error("'" + Arg + "' value invalid for file size argument!");
    }
  }
}

}                

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_PREDEFINEDSTRINGIDS_H
#define HERMES_VM_PREDEFINEDSTRINGIDS_H

#include "hermes/VM/Predefined.h"
#include "hermes/VM/SymbolID.h"

#include "llvh/ADT/Optional.h"
#include "llvh/ADT/StringRef.h"

namespace hermes {
namespace vm {

                                                                           
                                                
llvh::Optional<vm::SymbolID> getPredefinedStringID(llvh::StringRef str);

                                           
extern const llvh::ArrayRef<uint8_t> predefPropertyLengths;

                                         
extern const llvh::ArrayRef<uint8_t> predefStringLengths;

                                         
extern const llvh::ArrayRef<uint8_t> predefSymbolLengths;

                                                               
                                                               
extern const llvh::ArrayRef<char> predefStringAndSymbolChars;

}                
}                    

#endif                                   

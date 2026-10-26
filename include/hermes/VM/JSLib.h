/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                                
         
                                               
                                                                                
#ifndef HERMES_VM_JSLIB_H
#define HERMES_VM_JSLIB_H

#include "hermes/Support/ScopeChain.h"
#include "hermes/VM/CallResult.h"
#include "hermes/VM/Domain.h"
#include "hermes/VM/Handle.h"
#include "hermes/VM/HermesValue.h"

#include <memory>

namespace hermes {
namespace vm {

                                 
class Runtime;
struct JSLibStorage;

                                                              
class JSLibFlags {
 public:
                                                                                
            
  bool enableHermesInternal = true;
  bool enableHermesInternalTestMethods = false;
};

void initGlobalObject(Runtime &runtime, const JSLibFlags &jsLibFlags);
void populateAsyncGeneratorPrototype(Runtime &runtime);

                                                                                
                                
void createHermesBuiltins(
    Runtime &runtime,
    llvh::MutableArrayRef<Callable *> builtins);

std::unique_ptr<JSLibStorage> createJSLibStorage();

                                                                              
                                                                         
                                                                           
                                                                         
                                               
CallResult<HermesValue> evalInEnvironment(
    Runtime &runtime,
    llvh::StringRef utf8code,
    Handle<Environment> environment,
    const ScopeChain &scopeChain,
    Handle<> thisArg,
    bool isStrict,
    bool singleFunction);

                                                            
                                                                  
                                                                
                                                
CallResult<HermesValue> runRequireCall(
    Runtime &runtime,
    Handle<RequireContext> context,
    Handle<Domain> domain,
    uint32_t cjsModuleOffset);

                                             
CallResult<HermesValue>
throwTypeError(void *, Runtime &runtime, NativeArgs args);

enum class TypeErrorKind {
  NonStrictOnly,
  InvalidDynamicRequire,
                                         
  NumKinds
};

}                
}                    

#endif                     

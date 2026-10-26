/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_AST2JS_AST2JS_H
#define HERMES_AST2JS_AST2JS_H

namespace llvh {
class raw_ostream;
}

namespace hermes {
namespace ESTree {
class Node;
}

                                  
                               
                                 
                                      
void generateJS(llvh::raw_ostream &OS, ESTree::Node *root, bool pretty);

}                    

#endif

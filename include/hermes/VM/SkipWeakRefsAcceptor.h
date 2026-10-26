/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_SKIPWEAKACCEPTOR_H
#define HERMES_VM_SKIPWEAKACCEPTOR_H

#include "hermes/VM/GC.h"
#include "hermes/VM/RootAndSlotAcceptorDefault.h"

namespace hermes {
namespace vm {

                                                                     
                                                                   
                                                               
                                                                    
                                                                               
                                                                            
                                               
template <typename TargetAcceptor>
class SkipWeakRefsAcceptor final : public SlotAcceptor {
 public:
  SkipWeakRefsAcceptor(GC &gc, TargetAcceptor *acceptor)
      : acceptor_(acceptor) {}
  void accept(GCPointerBase &ptr) override {
    acceptor_->accept(ptr);
  }
  void accept(GCHermesValue &hv) override {
    acceptor_->accept(hv);
  }
  void accept(GCSmallHermesValue &hv) override {
    acceptor_->accept(hv);
  }
  void accept(const GCSymbolID &sym) override {
    acceptor_->accept(sym);
  }

 private:
  TargetAcceptor *acceptor_;
};

}                
}                    

#endif                                

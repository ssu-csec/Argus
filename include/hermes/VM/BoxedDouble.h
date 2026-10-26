/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_VM_BOXEDDOUBLE_H
#define HERMES_VM_BOXEDDOUBLE_H

#include "hermes/VM/Runtime.h"

namespace hermes {
namespace vm {

                                                                                
                                                                         
             
class BoxedDouble final : public GCCell {
  friend void BoxedDoubleBuildMeta(const GCCell *cell, Metadata::Builder &mb);

  static const VTable vt;

  double value_;

 public:
  static constexpr CellKind getCellKind() {
    return CellKind::BoxedDoubleKind;
  }
  static bool classof(const GCCell *cell) {
    return cell->getKind() == CellKind::BoxedDoubleKind;
  }

  static BoxedDouble *create(double d, Runtime &runtime) {
    return runtime.makeAFixed<BoxedDouble>(d);
  }

  BoxedDouble(double d) : value_(d) {}

  double get() const {
    return value_;
  }
};

}                
}                    

#endif                           

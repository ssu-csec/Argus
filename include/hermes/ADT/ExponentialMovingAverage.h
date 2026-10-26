/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_ADT_EXPONENTIALMOVINGAVERAGE_H
#define HERMES_ADT_EXPONENTIALMOVINGAVERAGE_H

#include <cassert>

namespace hermes {

                                                                             
                                                                         
                                                        
class ExponentialMovingAverage {
  double weight_;
  double avg_;

 public:
                                                                           
                                                                           
                                                     
  explicit ExponentialMovingAverage(double weight, double init)
      : weight_(weight), avg_(init) {
    assert(weight >= 0 && weight <= 1 && "Weight must be between 0 and 1");
  }

                                                            
  operator double() const {
    return avg_;
  }

  void update(double value) {
    avg_ = avg_ * (1 - weight_) + weight_ * value;
  }
};

}                    

#endif

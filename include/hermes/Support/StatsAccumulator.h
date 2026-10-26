/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_STATSACCUMULATOR_H
#define HERMES_SUPPORT_STATSACCUMULATOR_H

#include <algorithm>
#include <cmath>

namespace hermes {

                                                              
                                                                     
                                                                    
                                                                  
                                       
template <typename T, typename SumT = T>
class StatsAccumulator {
 public:
  StatsAccumulator() = default;

                                                                   
  inline void record(T value) {
    if (n_ == 0) {
      min_ = value;
      max_ = value;
    } else {
      min_ = std::min(min_, value);
      max_ = std::max(max_, value);
    }
    n_++;
    sum_ += value;
    double valD = static_cast<double>(value);
    sumOfSquares_ += valD * valD;
  }

               

                                             
  inline unsigned count() const {
    return n_;
  }

                                                  
  inline T min() const {
    return min_;
  }

                                                  
  inline T max() const {
    return max_;
  }

                                              
  inline SumT sum() const {
    return sum_;
  }

                                                  
  inline double average() const {
    return n_ == 0 ? 0.0 : static_cast<double>(sum_) / n_;
  }

                                                             
  inline double sumOfSquares() const {
    return sumOfSquares_;
  }

                                                             
  inline double stddev() const;

 private:
                                 
  unsigned n_{0};
                         
  SumT sum_{0};
                     
  T min_{0};
                     
  T max_{0};
                                                                 
                                                                     
                                                 
  double sumOfSquares_{0.0};
};

template <typename T, typename SumT>
inline double StatsAccumulator<T, SumT>::stddev() const {
  if (n_ == 0) {
    return 0.0;
  }
  double avg = average();
               
                                                                                                              
                        
  double variance = (sumOfSquares_ / n_) - (avg * avg);
  return std::sqrt(variance);
}

}                    

#endif                                     

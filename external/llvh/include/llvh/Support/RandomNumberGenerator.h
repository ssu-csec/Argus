//==- llvm/Support/RandomNumberGenerator.h - RNG for diversity ---*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines an abstraction for deterministic random number
// generation (RNG).  Note that the current implementation is not
// cryptographically secure as it uses the C++11 <random> facilities.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_RANDOMNUMBERGENERATOR_H_
#define LLVM_SUPPORT_RANDOMNUMBERGENERATOR_H_

#include "llvh/Support/Compiler.h"
#include "llvh/Support/DataTypes.h"                                   
#include <random>
#include <system_error>

namespace llvh {
class StringRef;

                              
   
                                                                    
                                                                    
                                                                    
           
class RandomNumberGenerator {

                                                             
                                                                            
                                                        
                     
  using generator_type = std::mt19937_64;

public:
  using result_type = generator_type::result_type;

                                                    
  result_type operator()();

  static constexpr result_type min() { return generator_type::min(); }
  static constexpr result_type max() { return generator_type::max(); }

private:
                                                
     
                                                               
                                                                      
  RandomNumberGenerator(StringRef Salt);

  generator_type Generator;

                 
  RandomNumberGenerator(const RandomNumberGenerator &other) = delete;
  RandomNumberGenerator &operator=(const RandomNumberGenerator &other) = delete;

  friend class Module;
};

                                      
std::error_code getRandomBytes(void *Buffer, size_t Size);
}

#endif

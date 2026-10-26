/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_SEMAPHORE_H
#define HERMES_SUPPORT_SEMAPHORE_H

#ifdef _WINDOWS
#error "Semaphore is not implemented because no code uses it in Windows"
#else

#include <semaphore.h>

namespace hermes {

                                                         
                                                                           
                                                                             
class Semaphore {
 private:
#ifdef __APPLE__
  sem_t *semPtr_{nullptr};
#else
  sem_t sem_;
#endif

 private:
                                        
  sem_t *getSemaphorePtr();

 public:
                                         
                                                                         
                                                                           
                               
                                                                               
                                                                        
                                             
  bool open(const char *semaphorePrefix);

                                          
  bool close();

                                                             
  bool notifyOne();

                          
  bool wait();
};

}                    

#endif            

#endif                              

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_THREADLOCAL_H
#define HERMES_SUPPORT_THREADLOCAL_H

#ifdef _WINDOWS
#error "ThreadLocal is not implemented because no code uses it in Windows"
#else

#include <hermes/Support/ErrorHandling.h>

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>

namespace hermes {

                                                     
                                                                        
template <typename T>
class ThreadLocal {
 public:
                                                                    
  ThreadLocal() : key_(0) {
    initialize();
  }

                                                                  
  T *operator->() const {
    return get();
  }

                                                          
  T *get() const {
    return (T *)pthread_getspecific(key_);
  }

                                            
  T *release() {
    T *obj = get();
    pthread_setspecific(key_, nullptr);
    return obj;
  }

                                        
  void set(T *other = nullptr) {
    T *old = (T *)pthread_getspecific(key_);
    if (old != other) {
      pthread_setspecific(key_, other);
    }
  }

 private:
  void initialize() {
    int ret = pthread_key_create(&key_, nullptr);
    if (ret != 0) {
      const char *msg = "pthread_key_create failed: (unknown error)";
      switch (ret) {
        case EAGAIN:
          msg =
              "pthread_key_create failed: PTHREAD_KEYS_MAX (1024) is exceeded";
          break;
        case ENOMEM:
          msg = "pthread_key_create failed: Out-of-memory";
          break;
      }
      hermes_fatal(msg);
    }
  }

  pthread_key_t key_;
};

}                    

#endif            

#endif                                

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_OSCOMPAT_H
#define HERMES_SUPPORT_OSCOMPAT_H

#include "llvh/ADT/SmallVector.h"
#include "llvh/Support/Compiler.h"
#include "llvh/Support/ErrorOr.h"

#ifdef _WINDOWS
#include <io.h>
                                               
                                                                     
                                                      
#include <malloc.h>
#else
#include <unistd.h>
#endif

#include <chrono>
#include <cmath>
#include <cstddef>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

                                                                           
                     

namespace hermes {
namespace oscompat {

#ifndef NDEBUG
void set_test_page_size(size_t pageSz);
void reset_test_page_size();
#endif           

                                  
size_t page_size();

#ifndef NDEBUG
                                                                          
                                                                                
                                                                            
                                   
void set_test_vm_allocate_limit(size_t totSz);

                                                      
void unset_test_vm_allocate_limit();
#endif           

                                                                      
                                                                  
                                                                         
                                                                
                                 
llvh::ErrorOr<void *> vm_allocate(size_t sz, void *hint = nullptr);

                                                                         
                                                                                
                                                                            
                                                                              
                                                                              
llvh::ErrorOr<void *>
vm_allocate_aligned(size_t sz, size_t alignment, void *hint = nullptr);

                                                             
                                                                            
                                                                     
                                                          
                                                                             
                                                
void vm_free(void *p, size_t sz);

                                                             
                           
void vm_free_aligned(void *p, size_t sz);

                                                                            
                                                                         
                                                                              
llvh::ErrorOr<void *>
vm_reserve_aligned(size_t sz, size_t alignment, void *hint = nullptr);

                                                             
                          
void vm_release_aligned(void *p, size_t sz);

                                                                                
                                                                   
                                                                   
llvh::ErrorOr<void *> vm_commit(void *p, size_t sz);

                                                                               
                                                                           
                          
void vm_uncommit(void *p, size_t sz);

                                                                         
                             
                                                        
void vm_hugepage(void *p, size_t sz);

                                                                             
                                                               
void vm_unused(void *p, size_t sz);

                                                                               
                                                              
void vm_prefetch(void *p, size_t sz);

                                                                           
                                                                              
                                                                              
                                             
void vm_name(void *p, size_t sz, const char *name);

                                                                   
                                                                
enum class ProtectMode { ReadWrite, None };

                                                                         
                                                                   
                   
bool vm_protect(void *p, size_t sz, ProtectMode mode);

enum class MAdvice { Random, Sequential };

                            
                                            
bool vm_madvise(void *p, size_t sz, MAdvice advice);

                                                                               
                                                                              
                                                                     
   
                                                                                
                                                             
                                                                          
                                                                              
                                                                              
   
                                                                       
            
llvh::ErrorOr<size_t> vm_footprint(char *start, char *end);

                                                                             
                                                                        
                                                                             
                                                                          
                                                                   
   
                                                   
int pages_in_ram(
    const void *p,
    size_t sz,
    llvh::SmallVectorImpl<int> *runs = nullptr);

                                                                        
                                                               
                                                                       
                                                               
std::vector<std::string> get_vm_protect_modes(const void *p, size_t sz);

                                                                             
                                                                           
                                                             
uint64_t peak_rss();

                                                                             
                                                                           
                              
uint64_t current_rss();

                                                                           
                                                                         
uint64_t current_private_dirty();

                                                                          
                                                            
bool num_context_switches(long &voluntary, long &involuntary);

                                                 
uint64_t process_id();

                                                                               
                                                                       
                        
uint64_t global_thread_id();

                                                                               
                                                                            
                            
                                                             
                                                             
                                     
                                                                           
                   
std::pair<const void *, size_t> thread_stack_bounds(unsigned gap = 0);

namespace detail {
                                                                        
                                              
                                                             
                                                             
                                     
                                                                           
                   
std::pair<const void *, size_t> thread_stack_bounds_impl();
}                    

                                                                             
                            
                                       
void set_thread_name(const char *name);

                                                                                
                                                                   
std::chrono::microseconds thread_cpu_time();

                                                                          
                                                       
bool thread_page_fault_count(int64_t *outMinorFaults, int64_t *outMajorFaults);

                                   
std::string thread_name();

                                                                        
                                
std::vector<bool> sched_getaffinity();

                                                                  
                   
int sched_getcpu();

                                                                               
                       
uint64_t cpu_cycle_counter();

#ifdef _WINDOWS

#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

                                                              
inline int isatty(int fd) {
  return ::_isatty(fd);
}

inline bool should_color(int fd) {
  return false;
}

#else

                                                              
inline int isatty(int fd) {
  return ::isatty(fd);
}

inline bool should_color(int fd) {
  char *term = getenv("TERM");
  if (term == nullptr || strcmp("dumb", term) == 0) {
    return false;
  }
  return isatty(fd);
}

#endif

                                        
                                         
                                                                 
                           
                                               
bool set_env(const char *name, const char *value);

                              
                                               
bool unset_env(const char *name);

                                                                     
                                                                     
                                                                     
                                                              
                                                                
                                                                 
                                                               
                                                                    
                                                                
                                                                      
                                                                      
                   
class SigAltStackLeakSuppressor {
 public:
  SigAltStackLeakSuppressor() = default;
  ~SigAltStackLeakSuppressor();

 private:
                                                             
  static void *stackRoot_;
};

}                      
}                    

#endif                        

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#ifndef HERMES_SUPPORT_PAGEACCESSTRACKERPOSIX_H
#define HERMES_SUPPORT_PAGEACCESSTRACKERPOSIX_H

#include <sigmux.h>
#include <signal.h>
#include <memory>
#include <vector>

#include "llvh/Support/raw_ostream.h"

#include "hermes/Support/JSONEmitter.h"

namespace hermes {

                                                       
          
                                     
                                                    
                           
                               
class PageAccessTracker {
 private:
  uint32_t pageSize_{0};
                                                           
  void *bufStartPage_{nullptr};
                                                                      
                    
  uint32_t totalPages_{0};
                                                       
  std::unique_ptr<uint32_t[]> accessedPageIds_{nullptr};
                                                  
  std::unique_ptr<uint32_t[]> accessedMicros_{nullptr};
                                                               
  uint32_t accessedPageCount_{0};
                                         
  const int signal_;
                                     
  sigmux_registration *sigmuxCookie_{nullptr};

  PageAccessTracker(
      uint32_t pageSize,
      void *bufStartPage,
      uint32_t totalPages,
      int signal);

                                                                               
                                              
                                                       
  void recordPageAccess(void *accessedPage, uint32_t micros);

                                                               
  bool isTracking(void *addr);

                                                                          
                                                                       
  void printStats(llvh::raw_ostream &OS);
  void printStatsJSON(llvh::raw_ostream &OS);

                                                                        
                                                                                
                       
  void getJSONStats(JSONEmitter &json);

                                                    
  void printPageAccessedOrder(llvh::raw_ostream &OS);
  void printPageAccessedOrderJSON(llvh::raw_ostream &OS);

                                                                               
                                                                            
                                                                        
                                    
  static sigmux_action signalHandler(
      struct sigmux_siginfo *siginfo,
      void *             );

                                                                           
                                                
  PageAccessTracker *uninstall() volatile;

                                                                  
  volatile PageAccessTracker *install();

 public:
                                                                              
                                                                             
                                                                              
                                                         
                                            
                                                            
  static std::unique_ptr<volatile PageAccessTracker> create(
      void *bufStart,
      size_t bufSize);

                                                       
  std::vector<uint32_t> getPagesAccessed() volatile;

                                           
  std::vector<uint32_t> getMicros() volatile;

                                                                          
                                                                       
                                                                             
             
                                                                        
  bool printStats(llvh::raw_ostream &OS, bool json) volatile;

                                                                    
  void getJSONStats(JSONEmitter &json) volatile;

                                                    
                                                                             
             
                                                                        
  bool printPageAccessedOrder(llvh::raw_ostream &OS, bool json) volatile;

                                     
  ~PageAccessTracker();
};

}                    

#endif                                           

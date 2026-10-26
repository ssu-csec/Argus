//===--- LockFileManager.h - File-level locking utility ---------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_SUPPORT_LOCKFILEMANAGER_H
#define LLVM_SUPPORT_LOCKFILEMANAGER_H

#include "llvh/ADT/Optional.h"
#include "llvh/ADT/SmallString.h"
#include <system_error>
#include <utility>                 

namespace llvh {
class StringRef;

                                                         
                                                      
   
                                                                        
                                                                         
                                                                             
                                                                      
              
class LockFileManager {
public:
                                         
  enum LockFileState {
                                                                    
                      
    LFS_Owned,
                                                               
                 
    LFS_Shared,
                                                                 
             
    LFS_Error
  };

                                                                        
  enum WaitForUnlockResult {
                                           
    Res_Success,
                                          
    Res_OwnerDied,
                                                                        
    Res_Timeout
  };

private:
  SmallString<128> FileName;
  SmallString<128> LockFileName;
  SmallString<128> UniqueLockFileName;

  Optional<std::pair<std::string, int> > Owner;
  std::error_code ErrorCode;
  std::string ErrorDiagMsg;

  LockFileManager(const LockFileManager &) = delete;
  LockFileManager &operator=(const LockFileManager &) = delete;

  static Optional<std::pair<std::string, int> >
  readLockFile(StringRef LockFileName);

  static bool processStillExecuting(StringRef Hostname, int PID);

public:

  LockFileManager(StringRef FileName);
  ~LockFileManager();

                                           
  LockFileState getState() const;

  operator LockFileState() const { return getState(); }

                                                                
  WaitForUnlockResult waitForUnlock();

                                                                       
                                                 
  std::error_code unsafeRemoveLockFile();

                                                    
  std::string getErrorMessage() const;

                                 
  void setError(const std::error_code &EC, StringRef ErrorMsg = "") {
    ErrorCode = EC;
    ErrorDiagMsg = ErrorMsg.str();
  }
};

}                      

#endif                                  

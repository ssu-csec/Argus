//===- llvm/Support/FileSystem.h - File System OS Concept -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the llvh::sys::fs namespace. It is designed after
// TR2/boost filesystem (v3), but modified to remove exception handling and the
// path class.
//
// All functions return an error_code and their actual work via the last out
// argument. The out argument is defined if and only if errc::success is
// returned. A function may return any error code in the generic or system
// category. However, they shall be equivalent to any error conditions listed
// in each functions respective documentation if the condition applies. [ note:
// this does not guarantee that error_code will be in the set of explicitly
// listed codes, but it does guarantee that if any of the explicitly listed
// errors occur, the correct error_code will be used ]. All functions may
// return errc::not_enough_memory if there is not enough memory to complete the
// operation.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_FILESYSTEM_H
#define LLVM_SUPPORT_FILESYSTEM_H

#include "llvh/ADT/SmallString.h"
#include "llvh/ADT/StringRef.h"
#include "llvh/ADT/Twine.h"
#include "llvh/Config/llvm-config.h"
#include "llvh/Support/Chrono.h"
#include "llvh/Support/Error.h"
#include "llvh/Support/ErrorHandling.h"
#include "llvh/Support/ErrorOr.h"
#include "llvh/Support/MD5.h"
#include <cassert>
#include <cstdint>
#include <ctime>
#include <memory>
#include <stack>
#include <string>
#include <system_error>
#include <tuple>
#include <vector>

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

namespace llvh {
namespace sys {
namespace fs {

#if defined(_WIN32)
                                       
using file_t = void *;
#else
using file_t = int;
#endif

extern const file_t kInvalidFile;

                                                          
enum class file_type {
  status_error,
  file_not_found,
  regular_file,
  directory_file,
  symlink_file,
  block_file,
  character_file,
  fifo_file,
  socket_file,
  type_unknown
};

                                  
struct space_info {
  uint64_t capacity;
  uint64_t free;
  uint64_t available;
};

enum perms {
  no_perms = 0,
  owner_read = 0400,
  owner_write = 0200,
  owner_exe = 0100,
  owner_all = owner_read | owner_write | owner_exe,
  group_read = 040,
  group_write = 020,
  group_exe = 010,
  group_all = group_read | group_write | group_exe,
  others_read = 04,
  others_write = 02,
  others_exe = 01,
  others_all = others_read | others_write | others_exe,
  all_read = owner_read | group_read | others_read,
  all_write = owner_write | group_write | others_write,
  all_exe = owner_exe | group_exe | others_exe,
  all_all = owner_all | group_all | others_all,
  set_uid_on_exe = 04000,
  set_gid_on_exe = 02000,
  sticky_bit = 01000,
  all_perms = all_all | set_uid_on_exe | set_gid_on_exe | sticky_bit,
  perms_not_known = 0xFFFF
};

                                                                         
inline perms operator|(perms l, perms r) {
  return static_cast<perms>(static_cast<unsigned short>(l) |
                            static_cast<unsigned short>(r));
}
inline perms operator&(perms l, perms r) {
  return static_cast<perms>(static_cast<unsigned short>(l) &
                            static_cast<unsigned short>(r));
}
inline perms &operator|=(perms &l, perms r) {
  l = l | r;
  return l;
}
inline perms &operator&=(perms &l, perms r) {
  l = l & r;
  return l;
}
inline perms operator~(perms x) {
                                                               
  return static_cast<perms>(
      static_cast<unsigned short>(~static_cast<unsigned short>(x)));
}

class UniqueID {
  uint64_t Device;
  uint64_t File;

public:
  UniqueID() = default;
  UniqueID(uint64_t Device, uint64_t File) : Device(Device), File(File) {}

  bool operator==(const UniqueID &Other) const {
    return Device == Other.Device && File == Other.File;
  }
  bool operator!=(const UniqueID &Other) const { return !(*this == Other); }
  bool operator<(const UniqueID &Other) const {
    return std::tie(Device, File) < std::tie(Other.Device, Other.File);
  }

  uint64_t getDevice() const { return Device; }
  uint64_t getFile() const { return File; }
};

                                                                              
                                                                               
                                                                              
class basic_file_status {
protected:
  #if defined(LLVM_ON_UNIX)
  time_t fs_st_atime = 0;
  time_t fs_st_mtime = 0;
  uid_t fs_st_uid = 0;
  gid_t fs_st_gid = 0;
  off_t fs_st_size = 0;
  #elif defined (_WIN32)
  uint32_t LastAccessedTimeHigh = 0;
  uint32_t LastAccessedTimeLow = 0;
  uint32_t LastWriteTimeHigh = 0;
  uint32_t LastWriteTimeLow = 0;
  uint32_t FileSizeHigh = 0;
  uint32_t FileSizeLow = 0;
  #endif
  file_type Type = file_type::status_error;
  perms Perms = perms_not_known;

public:
  basic_file_status() = default;

  explicit basic_file_status(file_type Type) : Type(Type) {}

  #if defined(LLVM_ON_UNIX)
  basic_file_status(file_type Type, perms Perms, time_t ATime, time_t MTime,
                    uid_t UID, gid_t GID, off_t Size)
      : fs_st_atime(ATime), fs_st_mtime(MTime), fs_st_uid(UID), fs_st_gid(GID),
        fs_st_size(Size), Type(Type), Perms(Perms) {}
#elif defined(_WIN32)
  basic_file_status(file_type Type, perms Perms, uint32_t LastAccessTimeHigh,
                    uint32_t LastAccessTimeLow, uint32_t LastWriteTimeHigh,
                    uint32_t LastWriteTimeLow, uint32_t FileSizeHigh,
                    uint32_t FileSizeLow)
      : LastAccessedTimeHigh(LastAccessTimeHigh),
        LastAccessedTimeLow(LastAccessTimeLow),
        LastWriteTimeHigh(LastWriteTimeHigh),
        LastWriteTimeLow(LastWriteTimeLow), FileSizeHigh(FileSizeHigh),
        FileSizeLow(FileSizeLow), Type(Type), Perms(Perms) {}
  #endif

            
  file_type type() const { return Type; }
  perms permissions() const { return Perms; }
  TimePoint<> getLastAccessedTime() const;
  TimePoint<> getLastModificationTime() const;

  #if defined(LLVM_ON_UNIX)
  uint32_t getUser() const { return fs_st_uid; }
  uint32_t getGroup() const { return fs_st_gid; }
  uint64_t getSize() const { return fs_st_size; }
  #elif defined (_WIN32)
  uint32_t getUser() const {
    return 9999;                                    
  }

  uint32_t getGroup() const {
    return 9999;                                    
  }

  uint64_t getSize() const {
    return (uint64_t(FileSizeHigh) << 32) + FileSizeLow;
  }
  #endif

            
  void type(file_type v) { Type = v; }
  void permissions(perms p) { Perms = p; }
};

                                                         
class file_status : public basic_file_status {
  friend bool equivalent(file_status A, file_status B);

  #if defined(LLVM_ON_UNIX)
  dev_t fs_st_dev = 0;
  nlink_t fs_st_nlinks = 0;
  ino_t fs_st_ino = 0;
  #elif defined (_WIN32)
  uint32_t NumLinks = 0;
  uint32_t VolumeSerialNumber = 0;
  uint32_t FileIndexHigh = 0;
  uint32_t FileIndexLow = 0;
  #endif

public:
  file_status() = default;

  explicit file_status(file_type Type) : basic_file_status(Type) {}

  #if defined(LLVM_ON_UNIX)
  file_status(file_type Type, perms Perms, dev_t Dev, nlink_t Links, ino_t Ino,
              time_t ATime, time_t MTime, uid_t UID, gid_t GID, off_t Size)
      : basic_file_status(Type, Perms, ATime, MTime, UID, GID, Size),
        fs_st_dev(Dev), fs_st_nlinks(Links), fs_st_ino(Ino) {}
  #elif defined(_WIN32)
  file_status(file_type Type, perms Perms, uint32_t LinkCount,
              uint32_t LastAccessTimeHigh, uint32_t LastAccessTimeLow,
              uint32_t LastWriteTimeHigh, uint32_t LastWriteTimeLow,
              uint32_t VolumeSerialNumber, uint32_t FileSizeHigh,
              uint32_t FileSizeLow, uint32_t FileIndexHigh,
              uint32_t FileIndexLow)
      : basic_file_status(Type, Perms, LastAccessTimeHigh, LastAccessTimeLow,
                          LastWriteTimeHigh, LastWriteTimeLow, FileSizeHigh,
                          FileSizeLow),
        NumLinks(LinkCount), VolumeSerialNumber(VolumeSerialNumber),
        FileIndexHigh(FileIndexHigh), FileIndexLow(FileIndexLow) {}
  #endif

  UniqueID getUniqueID() const;
  uint32_t getLinkCount() const;
};

      
                            
      

                                  
   
                                                                               
                                                             
   
                                      
                                                            
   
                                                               
                                                                         
                                          
std::error_code make_absolute(const Twine &current_directory,
                              SmallVectorImpl<char> &path);

                                  
   
                                                                               
                                                       
   
                                      
                                                            
   
                                                               
                                                                         
                                          
std::error_code make_absolute(SmallVectorImpl<char> &path);

                                                    
   
                                      
                                                                      
                                                                          
                                                    
std::error_code create_directories(const Twine &path,
                                   bool IgnoreExisting = true,
                                   perms Perms = owner_all | group_all);

                                 
   
                                    
                                                                      
                                                                          
                                                    
std::error_code create_directory(const Twine &path, bool IgnoreExisting = true,
                                 perms Perms = owner_all | group_all);

                                        
   
                                                                                
                                                                               
                                                                              
                                              
   
                                       
                                                            
                                                                        
                        
std::error_code create_link(const Twine &to, const Twine &from);

                                                                 
   
                                       
                                                            
                                                                        
                        
std::error_code create_hard_link(const Twine &to, const Twine &from);

                                                                        
                                                             
   
                                    
                                                          
                                                                          
                                  
std::error_code real_path(const Twine &path, SmallVectorImpl<char> &output,
                          bool expand_tilde = false);

                         
   
                                                   
                                                                         
                                                      
std::error_code current_path(SmallVectorImpl<char> &result);

                         
   
                                
                                                                    
                                                      
std::error_code set_current_path(const Twine &path);

                                              
   
                           
                                                                                
                                                                              
                                                    
std::error_code remove(const Twine &path, bool IgnoreNonExisting = true);

                                   
   
                           
                                                                                
                                          
std::error_code remove_directories(const Twine &path, bool IgnoreErrors = true);

                            
   
                                                                               
                                                                          
          
   
                                        
                                                     
std::error_code rename(const Twine &from, const Twine &to);

                                          
   
                                      
                                                   
std::error_code copy_file(const Twine &From, const Twine &To);

                                          
   
                                      
                                                                 
std::error_code copy_file(const Twine &From, int ToFD);

                                                                   
   
                                    
                                  
                                                                              
                                          
std::error_code resize_file(int FD, uint64_t Size);

                                             
   
                                    
                                                                            
                             
ErrorOr<MD5::MD5Result> md5_contents(int FD);

                                                                        
ErrorOr<MD5::MD5Result> md5_contents(const Twine &Path);

      
                            
      

                    
   
                                                                    
                                                                            
                 
bool exists(const basic_file_status &status);

enum class AccessMode { Exist, Write, Execute };

                             
   
                           
                                                                   
                                          
std::error_code access(const Twine &Path, AccessMode Mode);

                    
   
                           
                                                
inline bool exists(const Twine &Path) {
  return !access(Path, AccessMode::Exist);
}

                             
   
                           
                                                        
bool can_execute(const Twine &Path);

                           
   
                           
                                                         
inline bool can_write(const Twine &Path) {
  return !access(Path, AccessMode::Write);
}

                                              
   
                               
                               
   
                                               
   
                                                                              
                       
bool equivalent(file_status A, file_status B);

                                      
   
                                               
   
                          
                          
                                                                             
                                        
                                                                           
                                          
std::error_code equivalent(const Twine &A, const Twine &B, bool &result);

                                                                
                                                    
inline bool equivalent(const Twine &A, const Twine &B) {
  bool result;
  return !equivalent(A, B, result) && result;
}

                                              
   
                           
                                                                               
                                     
                                                                           
                                          
std::error_code is_local(const Twine &path, bool &result);

                                                          
std::error_code is_local(int FD, bool &result);

                                                              
                                                    
inline bool is_local(const Twine &Path) {
  bool Result;
  return !is_local(Path, Result) && Result;
}

                                                                     
                                                                               
inline bool is_local(int FD) {
  bool Result;
  return !is_local(FD, Result) && Result;
}

                                      
   
                                            
                                                                               
                                                       
                                                                                
file_type get_file_type(const Twine &Path, bool Follow = true);

                                      
   
                                                                      
                                                        
bool is_directory(const basic_file_status &status);

                        
   
                           
                                                                        
                                                                    
                                                                           
                                          
std::error_code is_directory(const Twine &path, bool &result);

                                                                  
                                                    
inline bool is_directory(const Twine &Path) {
  bool Result;
  return !is_directory(Path, Result) && Result;
}

                                         
   
                                                                      
                                                                              
bool is_regular_file(const basic_file_status &status);

                           
   
                           
                                                                           
                                                                     
                                                                           
                                          
std::error_code is_regular_file(const Twine &path, bool &result);

                                                                     
                                                    
inline bool is_regular_file(const Twine &Path) {
  bool Result;
  if (is_regular_file(Path, Result))
    return false;
  return Result;
}

                                         
   
                                                                      
                                                                              
bool is_symlink_file(const basic_file_status &status);

                           
   
                           
                                                                               
                                      
                                                                           
                                          
std::error_code is_symlink_file(const Twine &path, bool &result);

                                                                     
                                                    
inline bool is_symlink_file(const Twine &Path) {
  bool Result;
  if (is_symlink_file(Path, Result))
    return false;
  return Result;
}

                                                                 
                                     
   
                                                                      
                                                                 
bool is_other(const basic_file_status &status);

                                                         
                                    
   
                           
                                                                                
                                                                                
                                                                           
                                          
std::error_code is_other(const Twine &path, bool &result);

                                          
   
                           
                                         
                                                                                
                          
                                                                           
                                          
std::error_code status(const Twine &path, file_status &result,
                       bool follow = true);

                                                              
std::error_code status(int FD, file_status &Result);

                         
   
                                           
                                            
                                                                              
                                            
                                                                              
                                                                             
                                                          
std::error_code setPermissions(const Twine &Path, perms Permissions);

                         
   
                                             
                                                                             
                                          
                                                                           
                                                                            
                           
ErrorOr<perms> getPermissions(const Twine &Path);

                  
   
                           
                                                         
                                                                           
                                          
inline std::error_code file_size(const Twine &Path, uint64_t &Result) {
  file_status Status;
  std::error_code EC = status(Path, Status);
  if (EC)
    return EC;
  Result = Status.getSize();
  return std::error_code();
}

                                              
   
                                                                               
                                                                            
                                                               
std::error_code setLastAccessAndModificationTime(int FD, TimePoint<> AccessTime,
                                                 TimePoint<> ModificationTime);

                                                                                
         
inline std::error_code setLastAccessAndModificationTime(int FD,
                                                        TimePoint<> Time) {
  return setLastAccessAndModificationTime(FD, Time, Time);
}

                        
   
                               
                                              
bool status_known(const basic_file_status &s);

                        
   
                           
                                                          
                                                                           
                                          
std::error_code status_known(const Twine &path, bool &result);

enum CreationDisposition : unsigned {
                                            
                                            
                                                          
  CD_CreateAlways = 0,

                                         
                                     
                                                          
  CD_CreateNew = 1,

                                            
                                                                       
                                             
  CD_OpenExisting = 2,

                                          
                                                                       
                                                          
  CD_OpenAlways = 3,
};

enum FileAccess : unsigned {
  FA_Read = 1,
  FA_Write = 2,
};

enum OpenFlags : unsigned {
  OF_None = 0,
  F_None = 0,                     

                                                                        
                  
  OF_Text = 1,
  F_Text = 1,                     

                                               
  OF_Append = 2,
  F_Append = 2,                     

                                                                   
  OF_Delete = 4,

                                                                           
                    
  OF_ChildInherit = 8,

                                                                                    
  OF_UpdateAtime = 16,
};

                                 
   
                                                                                
                                                                             
                                                                             
                                     
   
                                                             
   
                                                                              
                                  
   
                                                                     
                                                                           
                                                      
   
                                                 
                                                             
                                                             
                                                                         
                                                      
std::error_code createUniqueFile(const Twine &Model, int &ResultFD,
                                 SmallVectorImpl<char> &ResultPath,
                                 unsigned Mode = all_read | all_write);

                                                                      
                               
std::error_code createUniqueFile(const Twine &Model,
                                 SmallVectorImpl<char> &ResultPath,
                                 unsigned Mode = all_read | all_write);

                                
   
                                                                             
         
   
                                                                        
                                           
class TempFile {
  bool Done = false;
  TempFile(StringRef Name, int FD);

public:
                                                                              
                                            
  static Expected<TempFile> create(const Twine &Model,
                                   unsigned Mode = all_read | all_write);
  TempFile(TempFile &&Other);
  TempFile &operator=(TempFile &&Other);

                                
  std::string TmpName;

                              
  int FD = -1;

                                   
  Error keep(const Twine &Name);

                                       
  Error keep();

                     
  Error discard();

                                                
  ~TempFile();
};

                                                    
   
                                                                               
                                                                             
                                         
   
                                                                            
                          
std::error_code createTemporaryFile(const Twine &Prefix, StringRef Suffix,
                                    int &ResultFD,
                                    SmallVectorImpl<char> &ResultPath);

                                                                      
                               
std::error_code createTemporaryFile(const Twine &Prefix, StringRef Suffix,
                                    SmallVectorImpl<char> &ResultPath);

std::error_code createUniqueDirectory(const Twine &Prefix,
                                      SmallVectorImpl<char> &ResultPath);

                                                                         
                                                               
   
                                                                    
                                                                            
                                                                
                             
std::error_code getPotentiallyUniqueFileName(const Twine &Model,
                                             SmallVectorImpl<char> &ResultPath);

                                                                    
                                                                             
            
   
                                                                       
                                                                            
                                                                
                                
std::error_code
getPotentiallyUniqueTempFileName(const Twine &Prefix, StringRef Suffix,
                                 SmallVectorImpl<char> &ResultPath);

inline OpenFlags operator|(OpenFlags A, OpenFlags B) {
  return OpenFlags(unsigned(A) | unsigned(B));
}

inline OpenFlags &operator|=(OpenFlags &A, OpenFlags B) {
  A = A | B;
  return A;
}

inline FileAccess operator|(FileAccess A, FileAccess B) {
  return FileAccess(unsigned(A) | unsigned(B));
}

inline FileAccess &operator|=(FileAccess &A, FileAccess B) {
  A = A | B;
  return A;
}

                                                                             
                                            
   
                                                                           
                     
   
                                                                   
                                                                            
                                                                             
                                                            
                                                                              
                                  
                                  
                                                                         
                                                                  
                                          
std::error_code openFile(const Twine &Name, int &ResultFD,
                         CreationDisposition Disp, FileAccess Access,
                         OpenFlags Flags, unsigned Mode = 0666);

                                                                             
                                                          
   
                                                                       
                     
   
                                                                   
                                                            
                                                                              
                                  
                                  
                                                                         
                                                                  
                                          
Expected<file_t> openNativeFile(const Twine &Name, CreationDisposition Disp,
                                FileAccess Access, OpenFlags Flags,
                                unsigned Mode = 0666);

                                                                           
                                                                            
               
   
                                                                           
                     
   
                                                                   
                                                                            
                                                                             
                                                                              
                                                                          
                                                                         
                                                                  
                                          
inline std::error_code
openFileForWrite(const Twine &Name, int &ResultFD,
                 CreationDisposition Disp = CD_CreateAlways,
                 OpenFlags Flags = OF_None, unsigned Mode = 0666) {
  return openFile(Name, ResultFD, Disp, FA_Write, Flags, Mode);
}

                                                                           
                                                                            
               
   
                                                                            
                     
   
                                                                   
                                                                              
                                                                          
                                                                         
                                                                            
                                       
inline Expected<file_t> openNativeFileForWrite(const Twine &Name,
                                               CreationDisposition Disp,
                                               OpenFlags Flags,
                                               unsigned Mode = 0666) {
  return openNativeFile(Name, Disp, FA_Write, Flags, Mode);
}

                                                                           
                                                                            
               
   
                                                                           
                     
   
                                                                   
                                                                            
                                                                             
                                                                              
                                                                          
                                                                         
                                                                  
                                          
inline std::error_code openFileForReadWrite(const Twine &Name, int &ResultFD,
                                            CreationDisposition Disp,
                                            OpenFlags Flags,
                                            unsigned Mode = 0666) {
  return openFile(Name, ResultFD, Disp, FA_Write | FA_Read, Flags, Mode);
}

                                                                           
                                                                            
               
   
                                                                            
                     
   
                                                                   
                                                                              
                                                                          
                                                                         
                                                                            
                                       
inline Expected<file_t> openNativeFileForReadWrite(const Twine &Name,
                                                   CreationDisposition Disp,
                                                   OpenFlags Flags,
                                                   unsigned Mode = 0666) {
  return openNativeFile(Name, Disp, FA_Write | FA_Read, Flags, Mode);
}

                                                                            
                             
   
                                                                           
                     
   
                                                                   
                                                                            
                                                                             
                                                                             
                                                                       
                             
                                                                  
                                          
std::error_code openFileForRead(const Twine &Name, int &ResultFD,
                                OpenFlags Flags = OF_None,
                                SmallVectorImpl<char> *RealPath = nullptr);

                                                                            
                             
   
                                                                            
                     
   
                                                                   
                                                                             
                                                                       
                             
                                                                            
                                       
Expected<file_t>
openNativeFileForRead(const Twine &Name, OpenFlags Flags = OF_None,
                      SmallVectorImpl<char> *RealPath = nullptr);

                                                                             
                
   
                                                                         
                        
void closeFile(file_t &F);

std::error_code getUniqueID(const Twine Path, UniqueID &Result);

                                     
   
                                                                               
                                                                               
   
                           
                                                                       
                                                                               
                         
ErrorOr<space_info> disk_space(const Twine &Path);

                                                              
                                  
class mapped_file_region {
public:
  enum mapmode {
    readonly,                                                      
    readwrite,                                                             
    priv                                                               
  };

private:
                                      
  size_t Size;
  void *Mapping;
#ifdef _WIN32
  void *FileHandle;
#endif
  mapmode Mode;

  std::error_code init(int FD, uint64_t Offset, mapmode Mode);

public:
  mapped_file_region() = delete;
  mapped_file_region(mapped_file_region&) = delete;
  mapped_file_region &operator =(mapped_file_region&) = delete;

                                                                        
                                                                              
             
  mapped_file_region(int fd, mapmode mode, size_t length, uint64_t offset,
                     std::error_code &ec);

  ~mapped_file_region();

  size_t size() const;
  char *data() const;

                                                                       
               
  const char *const_data() const;

                                                    
  static int alignment();
};

                                                                           
                                                                              
                                      
std::string getMainExecutable(const char *argv0, void *MainExecAddr);

      
                   
      

                                                    
class directory_entry {
                                                                               
                                                                            
                                                                              
                                                              
                                                            
  std::string Path;
  file_type Type;                                              
  bool FollowSymlinks;                                          
  basic_file_status Status;                 

public:
  explicit directory_entry(const Twine &Path, bool FollowSymlinks = true,
                           file_type Type = file_type::type_unknown,
                           basic_file_status Status = basic_file_status())
      : Path(Path.str()), Type(Type), FollowSymlinks(FollowSymlinks),
        Status(Status) {}

  directory_entry() = default;

  void replace_filename(const Twine &Filename, file_type Type,
                        basic_file_status Status = basic_file_status());

  const std::string &path() const { return Path; }
                                                                       
                                             
                                                                         
  ErrorOr<basic_file_status> status() const;
                               
                                                                           
                                                            
  file_type type() const {
    if (Type != file_type::type_unknown)
      return Type;
    auto S = status();
    return S ? S->type() : file_type::type_unknown;
  }

  bool operator==(const directory_entry& RHS) const { return Path == RHS.Path; }
  bool operator!=(const directory_entry& RHS) const { return !(*this == RHS); }
  bool operator< (const directory_entry& RHS) const;
  bool operator<=(const directory_entry& RHS) const;
  bool operator> (const directory_entry& RHS) const;
  bool operator>=(const directory_entry& RHS) const;
};

namespace detail {

  struct DirIterState;

  std::error_code directory_iterator_construct(DirIterState &, StringRef, bool);
  std::error_code directory_iterator_increment(DirIterState &);
  std::error_code directory_iterator_destruct(DirIterState &);

                                             
  struct DirIterState {
    ~DirIterState() {
      directory_iterator_destruct(*this);
    }

    intptr_t IterationHandle = 0;
    directory_entry CurrentEntry;
  };

}                        

                                                                          
                                                                               
                                        
class directory_iterator {
  std::shared_ptr<detail::DirIterState> State;
  bool FollowSymlinks = true;

public:
  explicit directory_iterator(const Twine &path, std::error_code &ec,
                              bool follow_symlinks = true)
      : FollowSymlinks(follow_symlinks) {
    State = std::make_shared<detail::DirIterState>();
    SmallString<128> path_storage;
    ec = detail::directory_iterator_construct(
        *State, path.toStringRef(path_storage), FollowSymlinks);
  }

  explicit directory_iterator(const directory_entry &de, std::error_code &ec,
                              bool follow_symlinks = true)
      : FollowSymlinks(follow_symlinks) {
    State = std::make_shared<detail::DirIterState>();
    ec = detail::directory_iterator_construct(
        *State, de.path(), FollowSymlinks);
  }

                             
  directory_iterator() = default;

                                              
  directory_iterator &increment(std::error_code &ec) {
    ec = directory_iterator_increment(*State);
    return *this;
  }

  const directory_entry &operator*() const { return State->CurrentEntry; }
  const directory_entry *operator->() const { return &State->CurrentEntry; }

  bool operator==(const directory_iterator &RHS) const {
    if (State == RHS.State)
      return true;
    if (!RHS.State)
      return State->CurrentEntry == directory_entry();
    if (!State)
      return RHS.State->CurrentEntry == directory_entry();
    return State->CurrentEntry == RHS.State->CurrentEntry;
  }

  bool operator!=(const directory_iterator &RHS) const {
    return !(*this == RHS);
  }
};

namespace detail {

                                                       
  struct RecDirIterState {
    std::stack<directory_iterator, std::vector<directory_iterator>> Stack;
    uint16_t Level = 0;
    bool HasNoPushRequest = false;
  };

}                        

                                                                           
                                         
class recursive_directory_iterator {
  std::shared_ptr<detail::RecDirIterState> State;
  bool Follow;

public:
  recursive_directory_iterator() = default;
  explicit recursive_directory_iterator(const Twine &path, std::error_code &ec,
                                        bool follow_symlinks = true)
      : State(std::make_shared<detail::RecDirIterState>()),
        Follow(follow_symlinks) {
    State->Stack.push(directory_iterator(path, ec, Follow));
    if (State->Stack.top() == directory_iterator())
      State.reset();
  }

                                              
  recursive_directory_iterator &increment(std::error_code &ec) {
    const directory_iterator end_itr = {};

    if (State->HasNoPushRequest)
      State->HasNoPushRequest = false;
    else {
      file_type type = State->Stack.top()->type();
      if (type == file_type::symlink_file && Follow) {
                                                                  
        ErrorOr<basic_file_status> status = State->Stack.top()->status();
        if (status)
          type = status->type();
                                                        
      }
      if (type == file_type::directory_file) {
        State->Stack.push(directory_iterator(*State->Stack.top(), ec, Follow));
        if (State->Stack.top() != end_itr) {
          ++State->Level;
          return *this;
        }
        State->Stack.pop();
      }
    }

    while (!State->Stack.empty()
           && State->Stack.top().increment(ec) == end_itr) {
      State->Stack.pop();
      --State->Level;
    }

                                                           
    if (State->Stack.empty())
      State.reset();

    return *this;
  }

  const directory_entry &operator*() const { return *State->Stack.top(); }
  const directory_entry *operator->() const { return &*State->Stack.top(); }

              
                                                          
  int level() const { return State->Level; }

                                                                       
  bool no_push_request() const { return State->HasNoPushRequest; }

              
                                     
  void pop() {
    assert(State && "Cannot pop an end iterator!");
    assert(State->Level > 0 && "Cannot pop an iterator with level < 1");

    const directory_iterator end_itr = {};
    std::error_code ec;
    do {
      if (ec)
        report_fatal_error("Error incrementing directory iterator.");
      State->Stack.pop();
      --State->Level;
    } while (!State->Stack.empty()
             && State->Stack.top().increment(ec) == end_itr);

                                                           
    if (State->Stack.empty())
      State.reset();
  }

                                                        
  void no_push() { State->HasNoPushRequest = true; }

  bool operator==(const recursive_directory_iterator &RHS) const {
    return State == RHS.State;
  }

  bool operator!=(const recursive_directory_iterator &RHS) const {
    return !(*this == RHS);
  }
};

      

}                    
}                     
}                      

#endif                             

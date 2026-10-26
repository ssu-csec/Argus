#ifndef CONFIG_H
#define CONFIG_H

                            
#include "llvh/Config/llvm-config.h"

                     
#define BUG_REPORT_URL "${BUG_REPORT_URL}"

                                                           
#cmakedefine01 ENABLE_BACKTRACES

                                                                
#cmakedefine01 ENABLE_CRASH_OVERRIDES

                                                                   
#cmakedefine01 LLVM_ENABLE_CRASH_DUMPS

                                                       
#cmakedefine HAVE_BACKTRACE ${HAVE_BACKTRACE}

#define BACKTRACE_HEADER <${BACKTRACE_HEADER}>

                                                                      
#cmakedefine HAVE_CRASHREPORTERCLIENT_H

                                    
#cmakedefine01 HAVE_CRASHREPORTER_INFO

                                                                           
            
#cmakedefine01 HAVE_DECL_ARC4RANDOM

                                                                              
            
#cmakedefine01 HAVE_DECL_FE_ALL_EXCEPT

                                                                           
            
#cmakedefine01 HAVE_DECL_FE_INEXACT

                                                                           
            
#cmakedefine01 HAVE_DECL_STRERROR_S

                                                                           
#cmakedefine01 LLVM_ENABLE_DIA_SDK

                                                        
#cmakedefine HAVE_DLFCN_H ${HAVE_DLFCN_H}

                                                       
#cmakedefine HAVE_DLOPEN ${HAVE_DLOPEN}

                                                       
#cmakedefine HAVE_DLADDR ${HAVE_DLADDR}

                                                        
#cmakedefine HAVE_ERRNO_H ${HAVE_ERRNO_H}

                                                        
#cmakedefine HAVE_FCNTL_H ${HAVE_FCNTL_H}

                                                       
#cmakedefine HAVE_FENV_H ${HAVE_FENV_H}

                                                     
#cmakedefine HAVE_FFI_CALL ${HAVE_FFI_CALL}

                                                          
#cmakedefine HAVE_FFI_FFI_H ${HAVE_FFI_FFI_H}

                                                      
#cmakedefine HAVE_FFI_H ${HAVE_FFI_H}

                                                      
#cmakedefine HAVE_FUTIMENS ${HAVE_FUTIMENS}

                                                     
#cmakedefine HAVE_FUTIMES ${HAVE_FUTIMES}

                                                         
#cmakedefine HAVE_GETPAGESIZE ${HAVE_GETPAGESIZE}

                                                       
#cmakedefine HAVE_GETRLIMIT ${HAVE_GETRLIMIT}

                                                       
#cmakedefine HAVE_GETRUSAGE ${HAVE_GETRUSAGE}

                                                    
#cmakedefine HAVE_ISATTY 1

                                                          
#cmakedefine HAVE_LIBEDIT ${HAVE_LIBEDIT}

                                                        
#cmakedefine HAVE_LIBPFM ${HAVE_LIBPFM}

                                                            
#cmakedefine HAVE_LIBPSAPI ${HAVE_LIBPSAPI}

                                                                
#cmakedefine HAVE_LIBPTHREAD ${HAVE_LIBPTHREAD}

                                                                
#cmakedefine HAVE_PTHREAD_GETNAME_NP ${HAVE_PTHREAD_GETNAME_NP}

                                                                
#cmakedefine HAVE_PTHREAD_SETNAME_NP ${HAVE_PTHREAD_SETNAME_NP}

                                                    
#cmakedefine HAVE_LIBZ ${HAVE_LIBZ}

                                                       
#cmakedefine HAVE_LINK_H ${HAVE_LINK_H}

                                                     
#cmakedefine HAVE_LSEEK64 ${HAVE_LSEEK64}

                                                            
#cmakedefine HAVE_MACH_MACH_H ${HAVE_MACH_MACH_H}

                                                     
#cmakedefine HAVE_MALLCTL ${HAVE_MALLCTL}

                                                      
#cmakedefine HAVE_MALLINFO ${HAVE_MALLINFO}

                                                         
#cmakedefine HAVE_MALLOC_H ${HAVE_MALLOC_H}

                                                                
#cmakedefine HAVE_MALLOC_MALLOC_H ${HAVE_MALLOC_MALLOC_H}

                                                                    
#cmakedefine HAVE_MALLOC_ZONE_STATISTICS ${HAVE_MALLOC_ZONE_STATISTICS}

                                                             
#cmakedefine HAVE_POSIX_FALLOCATE ${HAVE_POSIX_FALLOCATE}

                                                         
#cmakedefine HAVE_POSIX_SPAWN ${HAVE_POSIX_SPAWN}

                                                   
#cmakedefine HAVE_PREAD ${HAVE_PREAD}

                              
#cmakedefine HAVE_PTHREAD_GETSPECIFIC ${HAVE_PTHREAD_GETSPECIFIC}

                                                          
#cmakedefine HAVE_PTHREAD_H ${HAVE_PTHREAD_H}

                             
#cmakedefine HAVE_PTHREAD_MUTEX_LOCK ${HAVE_PTHREAD_MUTEX_LOCK}

                              
#cmakedefine HAVE_PTHREAD_RWLOCK_INIT ${HAVE_PTHREAD_RWLOCK_INIT}

                                                      
#cmakedefine HAVE_REALPATH ${HAVE_REALPATH}

                                                  
#cmakedefine HAVE_SBRK ${HAVE_SBRK}

                                                    
#cmakedefine HAVE_SETENV ${HAVE_SETENV}

                                                               
#cmakedefine HAVE_SCHED_GETAFFINITY ${HAVE_SCHED_GETAFFINITY}

                                                    
#cmakedefine HAVE_CPU_COUNT ${HAVE_CPU_COUNT}

                                                       
#cmakedefine HAVE_SETRLIMIT ${HAVE_SETRLIMIT}

                                                         
#cmakedefine HAVE_SIGALTSTACK ${HAVE_SIGALTSTACK}

                                                         
#cmakedefine HAVE_SIGNAL_H ${HAVE_SIGNAL_H}

                                                      
#cmakedefine HAVE_STRERROR ${HAVE_STRERROR}

                                                        
#cmakedefine HAVE_STRERROR_R ${HAVE_STRERROR_R}

                                                     
#cmakedefine HAVE_SYSCONF ${HAVE_SYSCONF}

                                                            
#cmakedefine HAVE_SYS_IOCTL_H ${HAVE_SYS_IOCTL_H}

                                                           
#cmakedefine HAVE_SYS_MMAN_H ${HAVE_SYS_MMAN_H}

                                                            
#cmakedefine HAVE_SYS_PARAM_H ${HAVE_SYS_PARAM_H}

                                                               
#cmakedefine HAVE_SYS_RESOURCE_H ${HAVE_SYS_RESOURCE_H}

                                                           
#cmakedefine HAVE_SYS_STAT_H ${HAVE_SYS_STAT_H}

                                                           
#cmakedefine HAVE_SYS_TIME_H ${HAVE_SYS_TIME_H}

                                                            
#cmakedefine HAVE_SYS_TYPES_H ${HAVE_SYS_TYPES_H}

                                                                    
#cmakedefine HAVE_TERMINFO ${HAVE_TERMINFO}

                                                                   
#cmakedefine HAVE_LIBXAR ${HAVE_LIBXAR}

                                                          
#cmakedefine HAVE_TERMIOS_H ${HAVE_TERMIOS_H}

                                                         
#cmakedefine HAVE_UNISTD_H ${HAVE_UNISTD_H}

                                                                    
#cmakedefine HAVE_VALGRIND_VALGRIND_H ${HAVE_VALGRIND_VALGRIND_H}

                                                       
#cmakedefine HAVE_ZLIB_H ${HAVE_ZLIB_H}

                         
#cmakedefine HAVE__ALLOCA ${HAVE__ALLOCA}

                                                       
#cmakedefine HAVE__CHSIZE_S ${HAVE__CHSIZE_S}

                                                               
#cmakedefine HAVE__UNWIND_BACKTRACE ${HAVE__UNWIND_BACKTRACE}

                          
#cmakedefine HAVE___ALLOCA ${HAVE___ALLOCA}

                           
#cmakedefine HAVE___ASHLDI3 ${HAVE___ASHLDI3}

                           
#cmakedefine HAVE___ASHRDI3 ${HAVE___ASHRDI3}

                          
#cmakedefine HAVE___CHKSTK ${HAVE___CHKSTK}

                             
#cmakedefine HAVE___CHKSTK_MS ${HAVE___CHKSTK_MS}

                          
#cmakedefine HAVE___CMPDI2 ${HAVE___CMPDI2}

                          
#cmakedefine HAVE___DIVDI3 ${HAVE___DIVDI3}

                           
#cmakedefine HAVE___FIXDFDI ${HAVE___FIXDFDI}

                           
#cmakedefine HAVE___FIXSFDI ${HAVE___FIXSFDI}

                             
#cmakedefine HAVE___FLOATDIDF ${HAVE___FLOATDIDF}

                           
#cmakedefine HAVE___LSHRDI3 ${HAVE___LSHRDI3}

                        
#cmakedefine HAVE___MAIN ${HAVE___MAIN}

                          
#cmakedefine HAVE___MODDI3 ${HAVE___MODDI3}

                           
#cmakedefine HAVE___UDIVDI3 ${HAVE___UDIVDI3}

                           
#cmakedefine HAVE___UMODDI3 ${HAVE___UMODDI3}

                           
#cmakedefine HAVE____CHKSTK ${HAVE____CHKSTK}

                              
#cmakedefine HAVE____CHKSTK_MS ${HAVE____CHKSTK_MS}

                                              
#cmakedefine HOST_LINK_VERSION "${HOST_LINK_VERSION}"

                                                          
                                                                  
#define LLVM_DEFAULT_TARGET_TRIPLE "${CMAKE_CXX_COMPILER_TARGET}"

                                             
#cmakedefine01 LLVM_ENABLE_ZLIB

                                                   
#cmakedefine LLVM_TARGET_TRIPLE_ENV "${LLVM_TARGET_TRIPLE_ENV}"

                              
#cmakedefine LLVM_VERSION_INFO "${LLVM_VERSION_INFO}"

                                                                         
#cmakedefine01 LLVM_VERSION_PRINTER_SHOW_HOST_TARGET_INFO

                                                      
#cmakedefine LLVM_LIBXML2_ENABLED ${LLVM_LIBXML2_ENABLED}

                                                                    
#cmakedefine LTDL_SHLIB_EXT "${LTDL_SHLIB_EXT}"

                                                                              
#cmakedefine PACKAGE_BUGREPORT "${PACKAGE_BUGREPORT}"

                                              
#cmakedefine PACKAGE_NAME "${PACKAGE_NAME}"

                                                          
#cmakedefine PACKAGE_STRING "${PACKAGE_STRING}"

                                            
#cmakedefine PACKAGE_VERSION "${PACKAGE_VERSION}"

                                           
#cmakedefine PACKAGE_VENDOR "${PACKAGE_VENDOR}"

                                                                     
#cmakedefine RETSIGTYPE ${RETSIGTYPE}

                                               
#cmakedefine stricmp ${stricmp}

                                              
#cmakedefine strdup ${strdup}

                                                         
#cmakedefine01 LLVM_GISEL_COV_ENABLED

                                                           
#cmakedefine LLVM_GISEL_COV_PREFIX "${LLVM_GISEL_COV_PREFIX}"

#endif

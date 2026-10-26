                                                                            
                                                                            
                                                                            
                                                                            
                                                                            
                                                                            
/*   Copyright 1996 Institut National de Recherche en Informatique et     */
                                                                            
                                                                            
/*   All rights reserved.  This file is distributed under the terms of    */
/*   the GNU Lesser General Public License version 2.1, with the          */
/*   special exception on linking described in the file LICENSE.          */
                                                                            
                                                                            

#ifndef CAML_CONFIG_H
#define CAML_CONFIG_H

#ifndef __PIC__
#  define ARCH_CODE32
#endif
#define ARCH_SIXTYFOUR
#define SIZEOF_INT 4
#define SIZEOF_LONG 8
#define SIZEOF_PTR 8
#define SIZEOF_SHORT 2
#define SIZEOF_LONGLONG 8
#define INT64_LITERAL(s) s ## LL
#undef ARCH_BIG_ENDIAN
#undef ARCH_ALIGN_DOUBLE
#undef ARCH_ALIGN_INT64
#define ASM_CFI_SUPPORTED
#define PROFINFO_WIDTH 0
#define CAML_WITH_CPLUGINS
#define OCAML_OS_TYPE "Unix"
#define OCAML_STDLIB_DIR "/home/opam/.opam/4.05.0/lib/ocaml"
#define POSIX_SIGNALS
#define HAS_C99_FLOAT_OPS
#define HAS_GETRUSAGE
#define HAS_TIMES
#define HAS_SECURE_GETENV
#define HAS_TERMCAP
#define HAS_SOCKETS
#define HAS_SOCKLEN_T
#define HAS_INET_ATON
#define HAS_IPV6
#define HAS_STDINT_H
#define HAS_UNISTD
#define HAS_OFF_T
#define HAS_DIRENT
#define HAS_REWINDDIR
#define HAS_LOCKF
#define HAS_MKFIFO
#define HAS_GETCWD
#define HAS_GETWD
#define HAS_GETPRIORITY
#define HAS_UTIME
#define HAS_UTIMES
#define HAS_DUP2
#define HAS_FCHMOD
#define HAS_TRUNCATE
#define HAS_SYS_SELECT_H
#define HAS_SELECT
#define HAS_NANOSLEEP
#define HAS_SYMLINK
#define HAS_WAITPID
#define HAS_WAIT4
#define HAS_GETGROUPS
#define HAS_SETGROUPS
#define HAS_INITGROUPS
#define HAS_TERMIOS
#define HAS_ASYNC_IO
#define HAS_SETITIMER
#define HAS_GETHOSTNAME
#define HAS_UNAME
#define HAS_GETTIMEOFDAY
#define HAS_MKTIME
#define HAS_SETSID
#define HAS_PUTENV
#define HAS_LOCALE
#define SUPPORT_DYNAMIC_LINKING
#define HAS_MMAP
#define HAS_PWRITE
#define HAS_NANOSECOND_STAT 1
#define HAS_GETHOSTBYNAME_R 6
#define HAS_GETHOSTBYADDR_R 8
#define HAS_MKSTEMP
#define HAS_NICE
#define HAS_DUP3
#define HAS_PIPE2
#define HAS_ACCEPT4
#define HAS_STACK_OVERFLOW_DETECTION
#define HAS_SIGWAIT
#define HAS_HUGE_PAGES
#define HUGE_PAGE_SIZE (4 * 1024 * 1024)

#ifndef CAML_NAME_SPACE
#include "compatibility.h"
#endif

#ifdef HAS_STDINT_H
#include <stdint.h>
#endif

                                                  
                                                 

#ifndef ARCH_INT32_TYPE
#if SIZEOF_INT == 4
#define ARCH_INT32_TYPE int
#define ARCH_UINT32_TYPE unsigned int
#define ARCH_INT32_PRINTF_FORMAT ""
#elif SIZEOF_LONG == 4
#define ARCH_INT32_TYPE long
#define ARCH_UINT32_TYPE unsigned long
#define ARCH_INT32_PRINTF_FORMAT "l"
#elif SIZEOF_SHORT == 4
#define ARCH_INT32_TYPE short
#define ARCH_UINT32_TYPE unsigned short
#define ARCH_INT32_PRINTF_FORMAT ""
#else
#error "No 32-bit integer type available"
#endif
#endif

#ifndef ARCH_INT64_TYPE
#if SIZEOF_LONGLONG == 8
#define ARCH_INT64_TYPE long long
#define ARCH_UINT64_TYPE unsigned long long
#define ARCH_INT64_PRINTF_FORMAT "ll"
#elif SIZEOF_LONG == 8
#define ARCH_INT64_TYPE long
#define ARCH_UINT64_TYPE unsigned long
#define ARCH_INT64_PRINTF_FORMAT "l"
#else
#error "No 64-bit integer type available"
#endif
#endif

#ifndef HAS_STDINT_H
                                                                       
typedef ARCH_INT32_TYPE int32_t;
typedef ARCH_UINT32_TYPE uint32_t;
typedef ARCH_INT64_TYPE int64_t;
typedef ARCH_UINT64_TYPE uint64_t;
#if SIZEOF_SHORT == 2
typedef short int16_t;
typedef unsigned short uint16_t;
#else
#error "No 16-bit integer type available"
#endif
#endif

#if SIZEOF_PTR == SIZEOF_LONG
                                       
typedef long intnat;
typedef unsigned long uintnat;
#define ARCH_INTNAT_PRINTF_FORMAT "l"
#elif SIZEOF_PTR == SIZEOF_INT
                                
typedef int intnat;
typedef unsigned int uintnat;
#define ARCH_INTNAT_PRINTF_FORMAT ""
#elif SIZEOF_PTR == 8
                          
typedef int64_t intnat;
typedef uint64_t uintnat;
#define ARCH_INTNAT_PRINTF_FORMAT ARCH_INT64_PRINTF_FORMAT
#else
#error "No integer type available to represent pointers"
#endif

                          

                                                                      
                                                                      
                                                                 
                                   

#if defined(__arm__) && !defined(__ARM_EABI__)
#define ARCH_FLOAT_ENDIANNESS 0x45670123
#elif defined(ARCH_BIG_ENDIAN)
#define ARCH_FLOAT_ENDIANNESS 0x76543210
#else
#define ARCH_FLOAT_ENDIANNESS 0x01234567
#endif


                                                                      
                                      

#if defined(__GNUC__) && __GNUC__ >= 2 && !defined(DEBUG) \
    && !defined (SHRINKED_GNUC) && !defined(CAML_JIT)
#define THREADED_CODE
#endif


                             

                                                                          
                                                      
                                        
                                                  
#define Page_log 12                                         
#define Page_size (1 << Page_log)

                                    
#define Stack_size (4096 * sizeof(value))

                                                                        
#define Stack_threshold (256 * sizeof(value))

                                                
#define Max_stack_def (1024 * 1024)


                                                                        
                 
#define Max_young_wosize 256
#define Max_young_whsize (Whsize_wosize (Max_young_wosize))


                                          
                                                   
#define Minor_heap_min 4096

                                          
                                                     
  
#define Minor_heap_max (1 << 28)

                                              
#define Minor_heap_def 262144


                                                        
                                                         
#define Heap_chunk_min (15 * Page_size)

                                                
                                                                  
                                              
#define Heap_chunk_def 15

                                                  
                                                         
#define Init_heap_def (31 * Page_size)
                                                                       


                                                                    
                                                                      
                                 
#define Percent_free_def 80

                                          
                                                                       
                                                                    
                             
   
#define Max_percent_free_def 500

                                                             
                      
  
#define Major_window_def 1

                                                          
#define Max_major_window 50

#endif                    

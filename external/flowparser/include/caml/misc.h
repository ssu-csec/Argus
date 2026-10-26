                                                                            
                                                                            
                                                                            
                                                                            
                                                                            
                                                                            
/*   Copyright 1996 Institut National de Recherche en Informatique et     */
                                                                            
                                                                            
/*   All rights reserved.  This file is distributed under the terms of    */
/*   the GNU Lesser General Public License version 2.1, with the          */
/*   special exception on linking described in the file LICENSE.          */
                                                                            
                                                                            

                                         

#ifndef CAML_MISC_H
#define CAML_MISC_H

#ifndef CAML_NAME_SPACE
#include "compatibility.h"
#endif
#include "config.h"

                          

#include <stddef.h>
#include <stdlib.h>

                               

typedef size_t asize_t;

#ifndef NULL
#define NULL 0
#endif

#ifdef CAML_INTERNALS
typedef char * addr;
#endif                     

                                                   
                                       
                  
                    
                                             
                                          

                                                               
                                                                   
  
#ifdef __GNUC__
                                       
  #define CAMLnoreturn_start
  #define CAMLnoreturn_end __attribute__ ((noreturn))
  #define Noreturn __attribute__ ((noreturn))
#elif _MSC_VER >= 1500
  #define CAMLnoreturn_start __declspec(noreturn)
  #define CAMLnoreturn_end
  #define Noreturn
#else
  #define CAMLnoreturn_start
  #define CAMLnoreturn_end
  #define Noreturn
#endif



                                                                   

#define CAMLexport
#define CAMLprim
#define CAMLextern extern

                                                                      
                                                           
#if defined(__GNUC__) && (defined (__ELF__) || defined(__APPLE__))
#define CAMLweakdef __attribute__((weak))
#else
#define CAMLweakdef
#endif

#ifdef __cplusplus
extern "C" {
#endif

                                                      
                                                                          
                                                            
  
typedef void (*caml_timing_hook) (void);
extern caml_timing_hook caml_major_slice_begin_hook, caml_major_slice_end_hook;
extern caml_timing_hook caml_minor_gc_begin_hook, caml_minor_gc_end_hook;
extern caml_timing_hook caml_finalise_begin_hook, caml_finalise_end_hook;

                

#ifdef DEBUG
#define CAMLassert(x) \
  ((x) ? (void) 0 : caml_failed_assert ( #x , __FILE__, __LINE__))
CAMLnoreturn_start
CAMLextern int caml_failed_assert (char *, char *, int)
CAMLnoreturn_end;
#else
#define CAMLassert(x) ((void) 0)
#endif

CAMLnoreturn_start
CAMLextern void caml_fatal_error (char *msg)
CAMLnoreturn_end;

CAMLnoreturn_start
CAMLextern void caml_fatal_error_arg (char *fmt, char *arg)
CAMLnoreturn_end;

CAMLnoreturn_start
CAMLextern void caml_fatal_error_arg2 (char *fmt1, char *arg1,
                                       char *fmt2, char *arg2)
CAMLnoreturn_end;

                            

CAMLextern char * caml_strdup(const char * s);
CAMLextern char * caml_strconcat(int n, ...);                                  

                                                                   
                                                                      
                            


#ifndef CAML_WITH_CPLUGINS

#define CAML_SYS_EXIT(retcode) exit(retcode)
#define CAML_SYS_OPEN(filename,flags,perm) open(filename,flags,perm)
#define CAML_SYS_CLOSE(fd) close(fd)
#define CAML_SYS_STAT(filename,st) stat(filename,st)
#define CAML_SYS_UNLINK(filename) unlink(filename)
#define CAML_SYS_RENAME(old_name,new_name) rename(old_name, new_name)
#define CAML_SYS_CHDIR(dirname) chdir(dirname)
#define CAML_SYS_GETENV(varname) getenv(varname)
#define CAML_SYS_SYSTEM(command) system(command)
#define CAML_SYS_READ_DIRECTORY(dirname,tbl) caml_read_directory(dirname,tbl)

#else


#define CAML_CPLUGINS_EXIT 0
#define CAML_CPLUGINS_OPEN 1
#define CAML_CPLUGINS_CLOSE 2
#define CAML_CPLUGINS_STAT 3
#define CAML_CPLUGINS_UNLINK 4
#define CAML_CPLUGINS_RENAME 5
#define CAML_CPLUGINS_CHDIR 6
#define CAML_CPLUGINS_GETENV 7
#define CAML_CPLUGINS_SYSTEM 8
#define CAML_CPLUGINS_READ_DIRECTORY 9
#define CAML_CPLUGINS_PRIMS_MAX 9

#define CAML_CPLUGINS_PRIMS_BITMAP  ((1 << CAML_CPLUGINS_PRIMS_MAX)-1)

extern intnat (*caml_cplugins_prim)(int,intnat,intnat,intnat);

#define CAML_SYS_PRIM_1(code,prim,arg1)               \
  (caml_cplugins_prim == NULL) ? prim(arg1) :    \
  caml_cplugins_prim(code,(intnat) (arg1),0,0)
#define CAML_SYS_STRING_PRIM_1(code,prim,arg1)               \
  (caml_cplugins_prim == NULL) ? prim(arg1) :    \
  (char*)caml_cplugins_prim(code,(intnat) (arg1),0,0)
#define CAML_SYS_VOID_PRIM_1(code,prim,arg1)               \
  (caml_cplugins_prim == NULL) ? prim(arg1) :    \
  (void)caml_cplugins_prim(code,(intnat) (arg1),0,0)
#define CAML_SYS_PRIM_2(code,prim,arg1,arg2)                         \
  (caml_cplugins_prim == NULL) ? prim(arg1,arg2) :              \
  caml_cplugins_prim(code,(intnat) (arg1), (intnat) (arg2),0)
#define CAML_SYS_PRIM_3(code,prim,arg1,arg2,arg3)                            \
  (caml_cplugins_prim == NULL) ? prim(arg1,arg2,arg3) :                 \
  caml_cplugins_prim(code,(intnat) (arg1), (intnat) (arg2),(intnat) (arg3))

#define CAML_SYS_EXIT(retcode) \
  CAML_SYS_VOID_PRIM_1(CAML_CPLUGINS_EXIT,exit,retcode)
#define CAML_SYS_OPEN(filename,flags,perm)                      \
  CAML_SYS_PRIM_3(CAML_CPLUGINS_OPEN,open,filename,flags,perm)
#define CAML_SYS_CLOSE(fd)                      \
  CAML_SYS_PRIM_1(CAML_CPLUGINS_CLOSE,close,fd)
#define CAML_SYS_STAT(filename,st)                      \
  CAML_SYS_PRIM_2(CAML_CPLUGINS_STAT,stat,filename,st)
#define CAML_SYS_UNLINK(filename)                       \
  CAML_SYS_PRIM_1(CAML_CPLUGINS_UNLINK,unlink,filename)
#define CAML_SYS_RENAME(old_name,new_name)                              \
  CAML_SYS_PRIM_2(CAML_CPLUGINS_RENAME,rename,old_name,new_name)
#define CAML_SYS_CHDIR(dirname)                         \
  CAML_SYS_PRIM_1(CAML_CPLUGINS_CHDIR,chdir,dirname)
#define CAML_SYS_GETENV(varname)                        \
  CAML_SYS_STRING_PRIM_1(CAML_CPLUGINS_GETENV,getenv,varname)
#define CAML_SYS_SYSTEM(command)                        \
  CAML_SYS_PRIM_1(CAML_CPLUGINS_SYSTEM,system,command)
#define CAML_SYS_READ_DIRECTORY(dirname,tbl)                            \
  CAML_SYS_PRIM_2(CAML_CPLUGINS_READ_DIRECTORY,caml_read_directory,     \
                  dirname,tbl)

#define CAML_CPLUGIN_CONTEXT_API 0

struct cplugin_context {
  int api_version;
  int prims_bitmap;
  char *exe_name;
  char** argv;
  char *plugin;                                                              
  char *ocaml_version;
                                               
};

extern void caml_cplugins_init(char * exe_name, char **argv);

                                                                        

                                                   
  

                                                                 
                                                  

#endif                         

                     

struct ext_table {
  int size;
  int capacity;
  void ** contents;
};

extern void caml_ext_table_init(struct ext_table * tbl, int init_capa);
extern int caml_ext_table_add(struct ext_table * tbl, void * data);
extern void caml_ext_table_remove(struct ext_table * tbl, void * data);
extern void caml_ext_table_free(struct ext_table * tbl, int free_entries);
extern void caml_ext_table_clear(struct ext_table * tbl, int free_entries);

CAMLextern int caml_read_directory(char * dirname, struct ext_table * contents);


#ifdef CAML_INTERNALS

                           

extern uintnat caml_verb_gc;
void caml_gc_message (int, char *, uintnat);

                      
extern uintnat caml_runtime_warnings;
int caml_runtime_warnings_active(void);

                     

char *caml_aligned_malloc (asize_t bsize, int, void **);

#ifdef DEBUG
#ifdef ARCH_SIXTYFOUR
#define Debug_tag(x) (0xD700D7D7D700D6D7ul \
                      | ((uintnat) (x) << 16) \
                      | ((uintnat) (x) << 48))
#else
#define Debug_tag(x) (0xD700D6D7ul | ((uintnat) (x) << 16))
#endif                     

  
                                
                                                
                                                 
                                                 
                                             
                                             
                                                           
                                             

                              
                                                       
  
#define Debug_free_minor     Debug_tag (0x00)
#define Debug_free_major     Debug_tag (0x01)
#define Debug_free_shrink    Debug_tag (0x03)
#define Debug_free_truncate  Debug_tag (0x04)
#define Debug_uninit_minor   Debug_tag (0x10)
#define Debug_uninit_major   Debug_tag (0x11)
#define Debug_uninit_align   Debug_tag (0x15)
#define Debug_filler_align   Debug_tag (0x85)

#define Debug_uninit_stat    0xD7

                                                                       
                                                                         
  
extern void caml_set_fields (intnat v, unsigned long, unsigned long);
#endif            


#ifndef CAML_AVOID_CONFLICTS
#define Assert CAMLassert
#endif

                                  

#if defined(_WIN32) && !defined(_UCRT)
extern int caml_snprintf(char * buf, size_t size, const char * format, ...);
#define snprintf caml_snprintf
#endif

#ifdef CAML_INSTR
                                                               

#include <time.h>
#include <stdio.h>

extern intnat caml_stat_minor_collections;
extern intnat CAML_INSTR_STARTTIME, CAML_INSTR_STOPTIME;

struct CAML_INSTR_BLOCK {
  struct timespec ts[10];
  char *tag[10];
  int index;
  struct CAML_INSTR_BLOCK *next;
};

extern struct CAML_INSTR_BLOCK *CAML_INSTR_LOG;

                                                                    
#define CAML_INSTR_DECLARE(t)                                       \
  struct CAML_INSTR_BLOCK *t = NULL

                                            
                                                            
#define CAML_INSTR_ALLOC(t) do{                                     \
    if (caml_stat_minor_collections >= CAML_INSTR_STARTTIME         \
        && caml_stat_minor_collections < CAML_INSTR_STOPTIME){      \
      t = malloc (sizeof (struct CAML_INSTR_BLOCK));                \
      t->index = 0;                                                 \
      t->tag[0] = "";                                               \
      t->next = CAML_INSTR_LOG;                                     \
      CAML_INSTR_LOG = t;                                           \
    }                                                               \
  }while(0)

                                               
                                                        
                                            
#define CAML_INSTR_START(t, msg) do{                                \
    if (t != NULL){                                                 \
      t->tag[0] = msg;                                              \
      clock_gettime (CLOCK_REALTIME, &(t->ts[0]));                  \
    }                                                               \
  }while(0)

                                                    
                                      
#define CAML_INSTR_SETUP(t, msg)                                    \
  CAML_INSTR_DECLARE (t);                                           \
  CAML_INSTR_ALLOC (t);                                             \
  CAML_INSTR_START (t, msg)

                                                    
                                                          
#define CAML_INSTR_TIME(t, msg) do{                                 \
    if (t != NULL){                                                 \
      ++ t->index;                                                  \
      t->tag[t->index] = (msg);                                     \
      clock_gettime (CLOCK_REALTIME, &(t->ts[t->index]));           \
    }                                                               \
  }while(0)

                                
                                                                          
                                                                
  
#define CAML_INSTR_INT(msg, data) do{                               \
    CAML_INSTR_SETUP (__caml_tmp, "");                              \
    if (__caml_tmp != NULL){                                        \
      __caml_tmp->index = 1;                                        \
      __caml_tmp->tag[1] = msg;                                     \
      __caml_tmp->ts[1].tv_sec = 0;                                 \
      __caml_tmp->ts[1].tv_nsec = (data);                           \
    }                                                               \
  }while(0)

                                                                
                                 
  
extern void CAML_INSTR_INIT (void);

                                                                 
                                          
extern void CAML_INSTR_ATEXIT (void);

#else                 

#define CAML_INSTR_DECLARE(t)     
#define CAML_INSTR_ALLOC(t)     
#define CAML_INSTR_START(t, name)     
#define CAML_INSTR_SETUP(t, name)     
#define CAML_INSTR_TIME(t, msg)     
#define CAML_INSTR_INT(msg, c)     
#define CAML_INSTR_INIT()     
#define CAML_INSTR_ATEXIT()     

#endif                 

#endif                     

#ifdef __cplusplus
}
#endif

#endif                  

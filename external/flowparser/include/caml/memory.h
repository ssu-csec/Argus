                                                                            
                                                                            
                                                                            
                                                                            
                                                                            
                                                                            
/*   Copyright 1996 Institut National de Recherche en Informatique et     */
                                                                            
                                                                            
/*   All rights reserved.  This file is distributed under the terms of    */
/*   the GNU Lesser General Public License version 2.1, with the          */
/*   special exception on linking described in the file LICENSE.          */
                                                                            
                                                                            

                                     

#ifndef CAML_MEMORY_H
#define CAML_MEMORY_H

#ifndef CAML_NAME_SPACE
#include "compatibility.h"
#endif
#include "config.h"
#ifdef CAML_INTERNALS
#include "gc.h"
#include "major_gc.h"
#include "minor_gc.h"
#endif                     
#include "misc.h"
#include "mlvalues.h"

#ifdef __cplusplus
extern "C" {
#endif


CAMLextern value caml_alloc_shr (mlsize_t wosize, tag_t);
#ifdef WITH_PROFINFO
CAMLextern value caml_alloc_shr_with_profinfo (mlsize_t, tag_t, intnat);
CAMLextern value caml_alloc_shr_preserving_profinfo (mlsize_t, tag_t,
                                                     header_t);
#else
#define caml_alloc_shr_with_profinfo(size, tag, profinfo) \
  caml_alloc_shr(size, tag)
#define caml_alloc_shr_preserving_profinfo(size, tag, header) \
  caml_alloc_shr(size, tag)
#endif                    
CAMLextern value caml_alloc_shr_no_raise (mlsize_t wosize, tag_t);
CAMLextern void caml_adjust_gc_speed (mlsize_t, mlsize_t);
CAMLextern void caml_alloc_dependent_memory (mlsize_t bsz);
CAMLextern void caml_free_dependent_memory (mlsize_t bsz);
CAMLextern void caml_modify (value *, value);
CAMLextern void caml_initialize (value *, value);
CAMLextern value caml_check_urgent_gc (value);
CAMLextern void * caml_stat_alloc (asize_t);                                  
CAMLextern void caml_stat_free (void *);
CAMLextern void * caml_stat_resize (void *, asize_t);                         
CAMLextern int caml_init_alloc_for_heap (void);
CAMLextern char *caml_alloc_for_heap (asize_t request);                       
CAMLextern void caml_free_for_heap (char *mem);
CAMLextern void caml_disown_for_heap (char *mem);
CAMLextern int caml_add_to_heap (char *mem);
CAMLextern color_t caml_allocation_color (void *hp);

CAMLextern int caml_huge_fallback_count;

                                                                   

#ifdef CAML_INTERNALS

extern uintnat caml_use_huge_pages;

#ifdef HAS_HUGE_PAGES
#include <sys/mman.h>
#define Heap_page_size HUGE_PAGE_SIZE
#define Round_mmap_size(x)                                      \
    (((x) + (Heap_page_size - 1)) & ~ (Heap_page_size - 1))
#endif


int caml_page_table_add(int kind, void * start, void * end);
int caml_page_table_remove(int kind, void * start, void * end);
int caml_page_table_initialize(mlsize_t bytesize);

#ifdef DEBUG
#define DEBUG_clear(result, wosize) do{ \
  uintnat caml__DEBUG_i; \
  for (caml__DEBUG_i = 0; caml__DEBUG_i < (wosize); ++ caml__DEBUG_i){ \
    Field ((result), caml__DEBUG_i) = Debug_uninit_minor; \
  } \
}while(0)
#else
#define DEBUG_clear(result, wosize)
#endif

#define Alloc_small_with_profinfo(result, wosize, tag, profinfo) do {       \
                                                CAMLassert ((wosize) >= 1); \
                                          CAMLassert ((tag_t) (tag) < 256); \
                                 CAMLassert ((wosize) <= Max_young_wosize); \
  caml_young_ptr -= Whsize_wosize (wosize);                                 \
  if (caml_young_ptr < caml_young_trigger){                                 \
    caml_young_ptr += Whsize_wosize (wosize);                               \
    CAML_INSTR_INT ("force_minor/alloc_small@", 1);                         \
    Setup_for_gc;                                                           \
    caml_gc_dispatch ();                                                    \
    Restore_after_gc;                                                       \
    caml_young_ptr -= Whsize_wosize (wosize);                               \
  }                                                                         \
  Hd_hp (caml_young_ptr) =                                                  \
    Make_header_with_profinfo ((wosize), (tag), Caml_black, profinfo);      \
  (result) = Val_hp (caml_young_ptr);                                       \
  DEBUG_clear ((result), (wosize));                                         \
}while(0)

#if defined(NATIVE_CODE) && defined(WITH_SPACETIME)
extern uintnat caml_spacetime_my_profinfo(struct ext_table**, uintnat);
#define Alloc_small(result, wosize, tag) \
  Alloc_small_with_profinfo(result, wosize, tag, \
    caml_spacetime_my_profinfo(NULL, wosize))
#else
#define Alloc_small(result, wosize, tag) \
  Alloc_small_with_profinfo(result, wosize, tag, (uintnat) 0)
#endif

                                        

#define Modify(fp,val) caml_modify((fp), (val))

#endif                     

struct caml__roots_block {
  struct caml__roots_block *next;
  intnat ntables;
  intnat nitems;
  value *tables [5];
};

CAMLextern struct caml__roots_block *caml_local_roots;                          

                                                                 
                                       

                                                                   
                                                                      
                                                                       
                                                
                                                                       
                                                                        
                         
                                                              
                                                                     
                                                 

                                                                     
                                                                  
                                                                   
                                                              

                                                                    
                                                                      
                                                                     
                                                                     
                                                                         
                                                                         

                                                                     
                                                                     
                            
  

#define CAMLparam0() \
  struct caml__roots_block *caml__frame = caml_local_roots

#define CAMLparam1(x) \
  CAMLparam0 (); \
  CAMLxparam1 (x)

#define CAMLparam2(x, y) \
  CAMLparam0 (); \
  CAMLxparam2 (x, y)

#define CAMLparam3(x, y, z) \
  CAMLparam0 (); \
  CAMLxparam3 (x, y, z)

#define CAMLparam4(x, y, z, t) \
  CAMLparam0 (); \
  CAMLxparam4 (x, y, z, t)

#define CAMLparam5(x, y, z, t, u) \
  CAMLparam0 (); \
  CAMLxparam5 (x, y, z, t, u)

#define CAMLparamN(x, size) \
  CAMLparam0 (); \
  CAMLxparamN (x, (size))

                                                     
                                       
                    
                    
                                         
                                          
  
#if defined(__GNUC__) && (__GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ > 7))
  #define CAMLunused_start __attribute__ ((unused))
  #define CAMLunused_end
  #define CAMLunused __attribute__ ((unused))
#elif _MSC_VER >= 1500
  #define CAMLunused_start  __pragma( warning (push) )           \
    __pragma( warning (disable:4189 ) )
  #define CAMLunused_end __pragma( warning (pop))
  #define CAMLunused
#else
  #define CAMLunused_start
  #define CAMLunused_end
  #define CAMLunused
#endif

#define CAMLxparam1(x) \
  struct caml__roots_block caml__roots_##x; \
  CAMLunused_start int caml__dummy_##x = ( \
    (void) caml__frame, \
    (caml__roots_##x.next = caml_local_roots), \
    (caml_local_roots = &caml__roots_##x), \
    (caml__roots_##x.nitems = 1), \
    (caml__roots_##x.ntables = 1), \
    (caml__roots_##x.tables [0] = &x), \
    0) \
   CAMLunused_end

#define CAMLxparam2(x, y) \
  struct caml__roots_block caml__roots_##x; \
  CAMLunused_start int caml__dummy_##x = ( \
    (void) caml__frame, \
    (caml__roots_##x.next = caml_local_roots), \
    (caml_local_roots = &caml__roots_##x), \
    (caml__roots_##x.nitems = 1), \
    (caml__roots_##x.ntables = 2), \
    (caml__roots_##x.tables [0] = &x), \
    (caml__roots_##x.tables [1] = &y), \
    0) \
   CAMLunused_end

#define CAMLxparam3(x, y, z) \
  struct caml__roots_block caml__roots_##x; \
  CAMLunused_start int caml__dummy_##x = ( \
    (void) caml__frame, \
    (caml__roots_##x.next = caml_local_roots), \
    (caml_local_roots = &caml__roots_##x), \
    (caml__roots_##x.nitems = 1), \
    (caml__roots_##x.ntables = 3), \
    (caml__roots_##x.tables [0] = &x), \
    (caml__roots_##x.tables [1] = &y), \
    (caml__roots_##x.tables [2] = &z), \
    0) \
  CAMLunused_end

#define CAMLxparam4(x, y, z, t) \
  struct caml__roots_block caml__roots_##x; \
  CAMLunused_start int caml__dummy_##x = ( \
    (void) caml__frame, \
    (caml__roots_##x.next = caml_local_roots), \
    (caml_local_roots = &caml__roots_##x), \
    (caml__roots_##x.nitems = 1), \
    (caml__roots_##x.ntables = 4), \
    (caml__roots_##x.tables [0] = &x), \
    (caml__roots_##x.tables [1] = &y), \
    (caml__roots_##x.tables [2] = &z), \
    (caml__roots_##x.tables [3] = &t), \
    0) \
  CAMLunused_end

#define CAMLxparam5(x, y, z, t, u) \
  struct caml__roots_block caml__roots_##x; \
  CAMLunused_start int caml__dummy_##x = ( \
    (void) caml__frame, \
    (caml__roots_##x.next = caml_local_roots), \
    (caml_local_roots = &caml__roots_##x), \
    (caml__roots_##x.nitems = 1), \
    (caml__roots_##x.ntables = 5), \
    (caml__roots_##x.tables [0] = &x), \
    (caml__roots_##x.tables [1] = &y), \
    (caml__roots_##x.tables [2] = &z), \
    (caml__roots_##x.tables [3] = &t), \
    (caml__roots_##x.tables [4] = &u), \
    0) \
  CAMLunused_end

#define CAMLxparamN(x, size) \
  struct caml__roots_block caml__roots_##x; \
  CAMLunused_start int caml__dummy_##x = (     \
    (void) caml__frame, \
    (caml__roots_##x.next = caml_local_roots), \
    (caml_local_roots = &caml__roots_##x), \
    (caml__roots_##x.nitems = (size)), \
    (caml__roots_##x.ntables = 1), \
    (caml__roots_##x.tables[0] = &(x[0])), \
    0) \
  CAMLunused_end

#define CAMLlocal1(x) \
  value x = Val_unit; \
  CAMLxparam1 (x)

#define CAMLlocal2(x, y) \
  value x = Val_unit, y = Val_unit; \
  CAMLxparam2 (x, y)

#define CAMLlocal3(x, y, z) \
  value x = Val_unit, y = Val_unit, z = Val_unit; \
  CAMLxparam3 (x, y, z)

#define CAMLlocal4(x, y, z, t) \
  value x = Val_unit, y = Val_unit, z = Val_unit, t = Val_unit; \
  CAMLxparam4 (x, y, z, t)

#define CAMLlocal5(x, y, z, t, u) \
  value x = Val_unit, y = Val_unit, z = Val_unit, t = Val_unit, u = Val_unit; \
  CAMLxparam5 (x, y, z, t, u)

#define CAMLlocalN(x, size) \
  value x [(size)]; \
  int caml__i_##x; \
  for (caml__i_##x = 0; caml__i_##x < size; caml__i_##x ++) { \
    x[caml__i_##x] = Val_unit; \
  } \
  CAMLxparamN (x, (size))


#define CAMLdrop caml_local_roots = caml__frame

#define CAMLreturn0 do{ \
  CAMLdrop; \
  return; \
}while (0)

#define CAMLreturnT(type, result) do{ \
  type caml__temp_result = (result); \
  CAMLdrop; \
  return caml__temp_result; \
}while(0)

#define CAMLreturn(result) CAMLreturnT(value, result)

#define CAMLnoreturn ((void) caml__frame)


                       
#define Store_field(block, offset, val) do{ \
  mlsize_t caml__temp_offset = (offset); \
  value caml__temp_val = (val); \
  caml_modify (&Field ((block), caml__temp_offset), caml__temp_val); \
}while(0)

  
                                                                      
                                             

                                                                            
                                                                          
                                      
         
                                                                            
                                                                          
                                                                           
                      
                                    

                                                                        
                                                                          

                                                                      
  

#define Begin_root Begin_roots1

#define Begin_roots1(r0) { \
  struct caml__roots_block caml__roots_block; \
  caml__roots_block.next = caml_local_roots; \
  caml_local_roots = &caml__roots_block; \
  caml__roots_block.nitems = 1; \
  caml__roots_block.ntables = 1; \
  caml__roots_block.tables[0] = &(r0);

#define Begin_roots2(r0, r1) { \
  struct caml__roots_block caml__roots_block; \
  caml__roots_block.next = caml_local_roots; \
  caml_local_roots = &caml__roots_block; \
  caml__roots_block.nitems = 1; \
  caml__roots_block.ntables = 2; \
  caml__roots_block.tables[0] = &(r0); \
  caml__roots_block.tables[1] = &(r1);

#define Begin_roots3(r0, r1, r2) { \
  struct caml__roots_block caml__roots_block; \
  caml__roots_block.next = caml_local_roots; \
  caml_local_roots = &caml__roots_block; \
  caml__roots_block.nitems = 1; \
  caml__roots_block.ntables = 3; \
  caml__roots_block.tables[0] = &(r0); \
  caml__roots_block.tables[1] = &(r1); \
  caml__roots_block.tables[2] = &(r2);

#define Begin_roots4(r0, r1, r2, r3) { \
  struct caml__roots_block caml__roots_block; \
  caml__roots_block.next = caml_local_roots; \
  caml_local_roots = &caml__roots_block; \
  caml__roots_block.nitems = 1; \
  caml__roots_block.ntables = 4; \
  caml__roots_block.tables[0] = &(r0); \
  caml__roots_block.tables[1] = &(r1); \
  caml__roots_block.tables[2] = &(r2); \
  caml__roots_block.tables[3] = &(r3);

#define Begin_roots5(r0, r1, r2, r3, r4) { \
  struct caml__roots_block caml__roots_block; \
  caml__roots_block.next = caml_local_roots; \
  caml_local_roots = &caml__roots_block; \
  caml__roots_block.nitems = 1; \
  caml__roots_block.ntables = 5; \
  caml__roots_block.tables[0] = &(r0); \
  caml__roots_block.tables[1] = &(r1); \
  caml__roots_block.tables[2] = &(r2); \
  caml__roots_block.tables[3] = &(r3); \
  caml__roots_block.tables[4] = &(r4);

#define Begin_roots_block(table, size) { \
  struct caml__roots_block caml__roots_block; \
  caml__roots_block.next = caml_local_roots; \
  caml_local_roots = &caml__roots_block; \
  caml__roots_block.nitems = (size); \
  caml__roots_block.ntables = 1; \
  caml__roots_block.tables[0] = (table);

#define End_roots() caml_local_roots = caml__roots_block.next; }


                                                                             
                                                                         
             

CAMLextern void caml_register_global_root (value *);

                                                                           
                                                

CAMLextern void caml_remove_global_root (value *);

                                                                
                                                                      
                                                    
                                                                   
                                                                 
                                                       
                                                                 
                                                                  
                                       
                                                                   
                                              

CAMLextern void caml_register_generational_global_root (value *);

                                                               
                                         
                                               

CAMLextern void caml_remove_generational_global_root (value *);

                                                    
                                                                
                                                             
                                                                 
                                                               
                                                                          

CAMLextern void caml_modify_generational_global_root(value *r, value newval);

#ifdef __cplusplus
}
#endif

#endif                    

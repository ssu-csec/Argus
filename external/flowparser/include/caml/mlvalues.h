                                                                            
                                                                            
                                                                            
                                                                            
                                                                            
                                                                            
/*   Copyright 1996 Institut National de Recherche en Informatique et     */
                                                                            
                                                                            
/*   All rights reserved.  This file is distributed under the terms of    */
/*   the GNU Lesser General Public License version 2.1, with the          */
/*   special exception on linking described in the file LICENSE.          */
                                                                            
                                                                            

#ifndef CAML_MLVALUES_H
#define CAML_MLVALUES_H

#ifndef CAML_NAME_SPACE
#include "compatibility.h"
#endif
#include "config.h"
#include "misc.h"

#ifdef __cplusplus
extern "C" {
#endif

              

                                                  
                                            
                                                              
                                                                          
                                                                       
                                                             
                                                              
                                                                       
                                                   
                                                       
                                                         
                                                   
                                           
                                            

                                                                          
                                   

                                              
                                               
                                                       
                                                       

               
                                                
                                                    
                                        
  

typedef intnat value;
typedef uintnat header_t;
typedef uintnat mlsize_t;
typedef unsigned int tag_t;                                             
typedef uintnat color_t;
typedef uintnat mark_t;

                      
#define Is_long(x)   (((x) & 1) != 0)
#define Is_block(x)  (((x) & 1) == 0)

                                                               
                                                               
#define Val_long(x)     ((intnat) (((uintnat)(x) << 1)) + 1)
#define Long_val(x)     ((x) >> 1)
#define Max_long (((intnat)1 << (8 * sizeof(value) - 2)) - 1)
#define Min_long (-((intnat)1 << (8 * sizeof(value) - 2)))
#define Val_int(x) Val_long(x)
#define Int_val(x) ((int) Long_val(x))
#define Unsigned_long_val(x) ((uintnat)(x) >> 1)
#define Unsigned_int_val(x)  ((int) Unsigned_long_val(x))

                           

                                    
                             
                             
                             
                            

                         

                             
                             
                             
                            

                                    
                                                                        
                                         
                                                      
                                                      
                                                      
                                                     

  

#define PROFINFO_SHIFT (64 - PROFINFO_WIDTH)
#define PROFINFO_MASK ((1ull << PROFINFO_WIDTH) - 1ull)

#define Tag_hd(hd) ((tag_t) ((hd) & 0xFF))
#ifdef WITH_PROFINFO
#define Hd_no_profinfo(hd) ((hd) & ~(PROFINFO_MASK << PROFINFO_SHIFT))
#define Wosize_hd(hd) ((mlsize_t) ((Hd_no_profinfo(hd)) >> 10))
#else
#define Wosize_hd(hd) ((mlsize_t) ((hd) >> 10))
#endif                    
#if defined(ARCH_SIXTYFOUR) && defined(WITH_PROFINFO)
                                                                          
                                    
#define Profinfo_hd(hd) (((mlsize_t) ((hd) >> PROFINFO_SHIFT)) & PROFINFO_MASK)
#else
#define Profinfo_hd(hd) ((hd) & 0)
#endif                                      

#define Hd_val(val) (((header_t *) (val)) [-1])                              
#define Hd_op(op) (Hd_val (op))                                              
#define Hd_bp(bp) (Hd_val (bp))                                              
#define Hd_hp(hp) (* ((header_t *) (hp)))                                    
#define Hp_val(val) (((header_t *) (val)) - 1)
#define Hp_op(op) (Hp_val (op))
#define Hp_bp(bp) (Hp_val (bp))
#define Val_op(op) ((value) (op))
#define Val_hp(hp) ((value) (((header_t *) (hp)) + 1))
#define Op_hp(hp) ((value *) Val_hp (hp))
#define Bp_hp(hp) ((char *) Val_hp (hp))

#define Num_tags (1 << 8)
#ifdef ARCH_SIXTYFOUR
#define Max_wosize (((intnat)1 << (54-PROFINFO_WIDTH)) - 1)
#else
#define Max_wosize ((1 << 22) - 1)
#endif                     

#define Wosize_val(val) (Wosize_hd (Hd_val (val)))
#define Wosize_op(op) (Wosize_val (op))
#define Wosize_bp(bp) (Wosize_val (bp))
#define Wosize_hp(hp) (Wosize_hd (Hd_hp (hp)))
#define Whsize_wosize(sz) ((sz) + 1)
#define Wosize_whsize(sz) ((sz) - 1)
#define Wosize_bhsize(sz) ((sz) / sizeof (value) - 1)
#define Bsize_wsize(sz) ((sz) * sizeof (value))
#define Wsize_bsize(sz) ((sz) / sizeof (value))
#define Bhsize_wosize(sz) (Bsize_wsize (Whsize_wosize (sz)))
#define Bhsize_bosize(sz) ((sz) + sizeof (header_t))
#define Bosize_val(val) (Bsize_wsize (Wosize_val (val)))
#define Bosize_op(op) (Bosize_val (Val_op (op)))
#define Bosize_bp(bp) (Bosize_val (Val_bp (bp)))
#define Bosize_hd(hd) (Bsize_wsize (Wosize_hd (hd)))
#define Whsize_hp(hp) (Whsize_wosize (Wosize_hp (hp)))
#define Whsize_val(val) (Whsize_hp (Hp_val (val)))
#define Whsize_bp(bp) (Whsize_val (Val_bp (bp)))
#define Whsize_hd(hd) (Whsize_wosize (Wosize_hd (hd)))
#define Bhsize_hp(hp) (Bsize_wsize (Whsize_hp (hp)))
#define Bhsize_hd(hd) (Bsize_wsize (Whsize_hd (hd)))

#define Profinfo_val(val) (Profinfo_hd (Hd_val (val)))

#ifdef ARCH_BIG_ENDIAN
#define Tag_val(val) (((unsigned char *) (val)) [-1])
                                                                       
#define Tag_hp(hp) (((unsigned char *) (hp)) [sizeof(value)-1])
                                                                       
#else
#define Tag_val(val) (((unsigned char *) (val)) [-sizeof(value)])
                                                                       
#define Tag_hp(hp) (((unsigned char *) (hp)) [0])
                                                                       
#endif

                                                    
#define No_scan_tag 251


                                                   

                                 
#define Op_val(x) ((value *) (x))
                                 
#define Field(x, i) (((value *)(x)) [i])                                 

typedef int32_t opcode_t;
typedef opcode_t * code_t;

                                                         
                                                 
                                                        

                                                           
   

                                                                     
                         
#define Forward_tag 250
#define Forward_val(v) Field(v, 0)

                                                            
                                                                             
                                                                          
                                           

#define Infix_tag 249
#define Infix_offset_hd(hd) (Bosize_hd(hd))
#define Infix_offset_val(v) Infix_offset_hd(Hd_val(v))

                                   
#define Object_tag 248
#define Class_val(val) Field((val), 0)
#define Oid_val(val) Long_val(Field((val), 1))
CAMLextern value caml_get_public_method (value obj, value tag);
             
                                                                              
                                                            
                                                                          
                       

                                                
#define Closure_tag 247
#define Code_val(val) (((code_t *) (val)) [0])                           

                                                                
                                        
#define Lazy_tag 246

                                    
CAMLextern value caml_hash_variant(char const * tag);

                                                     

                               
#define Bp_val(v) ((char *) (v))
#define Val_bp(p) ((value) (p))
                                
#define Byte(x, i) (((char *) (x)) [i])                                  
#define Byte_u(x, i) (((unsigned char *) (x)) [i])                       

                                                                           
                                                                          
                                                                    
  
#define Abstract_tag 251
#define Data_abstract_val(v) ((void*) Op_val(v))

              
#define String_tag 252
#define String_val(x) ((char *) Bp_val(x))
CAMLextern mlsize_t caml_string_length (value);                      
CAMLextern int caml_string_is_c_safe (value);
                                                       

                             
#define Double_tag 253
#define Double_wosize ((sizeof(double) / sizeof(value)))
#ifndef ARCH_ALIGN_DOUBLE
#define Double_val(v) (* (double *)(v))
#define Store_double_val(v,d) (* (double *)(v) = (d))
#else
CAMLextern double caml_Double_val (value);
CAMLextern void caml_Store_double_val (value,double);
#define Double_val(v) caml_Double_val(v)
#define Store_double_val(v,d) caml_Store_double_val(v,d)
#endif

                                       
#define Double_array_tag 254
#define Double_field(v,i) Double_val((value)((double *)(v) + (i)))
#define Store_double_field(v,i,d) do{ \
  mlsize_t caml__temp_i = (i); \
  double caml__temp_d = (d); \
  Store_double_val((value)((double *) (v) + caml__temp_i), caml__temp_d); \
}while(0)
CAMLextern mlsize_t caml_array_length (value);                      
CAMLextern int caml_is_double_array (value);                              


                                                             
                                                            
                                                                        
                                                        
                                                     
#define Custom_tag 255
#define Data_custom_val(v) ((void *) &Field((v), 1))
struct custom_operations;                                  

                                                                        

#define Int32_val(v) (*((int32_t *) Data_custom_val(v)))
#define Nativeint_val(v) (*((intnat *) Data_custom_val(v)))
#ifndef ARCH_ALIGN_INT64
#define Int64_val(v) (*((int64_t *) Data_custom_val(v)))
#else
CAMLextern int64_t caml_Int64_val(value v);
#define Int64_val(v) caml_Int64_val(v)
#endif

                                                                             

CAMLextern header_t caml_atom_table[];
#define Atom(tag) (Val_hp (&(caml_atom_table [(tag)])))

                                  

#define Val_bool(x) Val_int((x) != 0)
#define Bool_val(x) Int_val(x)
#define Val_false Val_int(0)
#define Val_true Val_int(1)
#define Val_not(x) (Val_false + Val_true - (x))

                                  

#define Val_unit Val_int(0)

                       
#define Val_emptylist Val_int(0)
#define Tag_cons 0

                                     

extern value caml_global_data;

CAMLextern value caml_set_oo_id(value obj);

#ifdef __cplusplus
}
#endif

#endif                      

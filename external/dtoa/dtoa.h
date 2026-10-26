/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

                                                                     

#ifndef HERMES_DTOA_DTOA_H
#define HERMES_DTOA_DTOA_H

#ifdef __cplusplus
extern "C" {
#endif

                                                                              
                                                                               
                                                                         
                                                            
   
                                                                              
                                                                                
                                                                          
                                                                                
                                                
   
                                                                               
                                                                               
                                                                          
                             
   
                                                                          
                                                                                
                                                                                
                                                  
   
                                                                            
                                                                             
                       
typedef struct dtoa_alloc dtoa_alloc;

                                                                              
                                                                         
#define DTOA_ALLOC_MIN_SIZE 256
                                                                           
                                                                         
                                                                            
#define DTOA_ALLOC_DEFAULT_SIZE 1200

                                                                              
                                                                                
                                                         
#define DECL_DTOA_ALLOC_MEM(name, bytelen) \
  union {                                  \
    void *p;                               \
    double d;                              \
    long long l;                           \
    char mem[(bytelen)];                   \
  } name

                                                                           
                                                                        
                                       
dtoa_alloc *dtoa_alloc_init(void *mem, int bytelen);

                                                                            
                                          
void dtoa_alloc_done(dtoa_alloc *dalloc);

                                      
                                    
                                                     
                                                            
                                       
                                                                
                                                             
                                                               
                                                                  
                                                            
                                                   
                                                               
                                                               
                                                              
                                        
                                                             
                                                               
                                                                  
                                                         
                                                                 
                                                      
                                                                   
                                                             
                                                                
         
                                                                
                                                                           
                                                                             
                                                                           
                                                     
char *g_dtoa(
    dtoa_alloc *dalloc,
    double dd,
    int mode,
    int ndigits,
    int *decpt,
    int *sign,
    char **rve);

                                                                            
                                                                             
                                                                    
                                                                                
                                                                         
                                                                
                                                                                
char *dtoa_fixedpoint(
    dtoa_alloc *dalloc,
    double dd,
    int mode,
    int ndigits,
    int *decpt,
    int *sign,
    char **rve);

                                                            
void g_freedtoa(dtoa_alloc *dalloc, char *);

char *g_fmt(char *, double);
double hermes_g_strtod(const char *s00, char **se);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
                                                                           
                                                                               
                                                              
template <int bytelen = DTOA_ALLOC_DEFAULT_SIZE>
class DtoaAllocator {
 public:
  DtoaAllocator(const DtoaAllocator &) = delete;
  void operator=(const DtoaAllocator &) = delete;

  DtoaAllocator() {
    dalloc_ = dtoa_alloc_init(&mem_, bytelen);
  }
  ~DtoaAllocator() {
    dtoa_alloc_done(dalloc_);
  }

  operator dtoa_alloc *() {
    return dalloc_;
  }

 private:
  DECL_DTOA_ALLOC_MEM(mem_, bytelen);
  dtoa_alloc *dalloc_;
};
#endif

#endif                      

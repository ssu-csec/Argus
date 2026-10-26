/*
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#pragma once
#ifndef ZIP_H
#define ZIP_H

#include <string.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_POSIX_C_SOURCE) && defined(_MSC_VER)
typedef intptr_t ssize_t;                          
#endif

#ifndef MAX_PATH
#define MAX_PATH 32767                                            
#endif

   
            
  
                             
   

   
                  
     
   

   
                                 
   
#define ZIP_DEFAULT_COMPRESSION_LEVEL 6

   
              
   
#define ZIP_ENOINIT -1                        
#define ZIP_EINVENTNAME -2                       
#define ZIP_ENOENT -3                         
#define ZIP_EINVMODE -4                        
#define ZIP_EINVLVL -5                                  
#define ZIP_ENOSUP64 -6                         
#define ZIP_EMEMSET -7                     
#define ZIP_EWRTENT -8                                   
#define ZIP_ETDEFLINIT -9                                        
#define ZIP_EINVIDX -10                     
#define ZIP_ENOHDR -11                         
#define ZIP_ETDEFLBUF -12                               
#define ZIP_ECRTHDR -13                                  
#define ZIP_EWRTHDR -14                                 
#define ZIP_EWRTDIR -15                                   
#define ZIP_EOPNFILE -16                       
#define ZIP_EINVENTTYPE -17                      
#define ZIP_EMEMNOALLOC -18                                              
#define ZIP_ENOFILE -19                      
#define ZIP_ENOPERM -20                     
#define ZIP_EOOMEM -21                      
#define ZIP_EINVZIPNAME -22                            
#define ZIP_EMKDIR -23                       
#define ZIP_ESYMLINK -24                    
#define ZIP_ECLSZIP -25                           
#define ZIP_ECAPSIZE -26                              
#define ZIP_EFSEEK -27                    
#define ZIP_EFREAD -28                    
#define ZIP_EFWRITE -29                    

   
                                                                     
                             
                                                                              
         
   
extern const char *zip_strerror(int errnum);

   
                
  
                                                                                
                       
   
struct zip_t;

   
                                                                 
  
                                        
                                                                           
                                
                                                                            
                                                   
                                                
  
                                                   
   
extern struct zip_t *zip_open(const char *zipname, int level, char mode);

   
                                                                
  
                                  
   
extern void zip_close(struct zip_t *zip);

   
                                                                          
  
                                  
  
                                                                          
                 
   
extern int zip_is64(struct zip_t *zip);

   
                                             
  
                                                                     
                                                                       
                        
  
                                  
                                                      
  
                                                                          
   
extern int zip_entry_open(struct zip_t *zip, const char *entryname);

   
                                                 
  
                                                                                
  
                                  
                                          
  
                                                                          
   
extern int zip_entry_openbyindex(struct zip_t *zip, int index);

   
                                                             
  
                                  
  
                                                                          
   
extern int zip_entry_close(struct zip_t *zip);

   
                                                 
  
                                                                     
                             
                                                                              
                                                
                                                                              
                                                          
  
                                   
  
                                                                       
   
extern const char *zip_entry_name(struct zip_t *zip);

   
                                             
  
                                  
  
                                                                
   
extern int zip_entry_index(struct zip_t *zip);

   
                                                            
  
                                  
  
                                                                          
                 
   
extern int zip_entry_isdir(struct zip_t *zip);

   
                                                         
  
                                  
  
                                          
   
extern unsigned long long zip_entry_size(struct zip_t *zip);

   
                                                    
  
                                  
  
                               
   
extern unsigned int zip_entry_crc32(struct zip_t *zip);

   
                                                        
  
                                  
                           
                                               
  
                                                                          
   
extern int zip_entry_write(struct zip_t *zip, const void *buf, size_t bufsize);

   
                                               
  
                                  
                              
  
                                                                          
   
extern int zip_entry_fwrite(struct zip_t *zip, const char *filename);

   
                                                     
  
                                                                
  
                                  
                            
                                                
  
                                                                  
                                                                             
  
                                                                          
                                   
   
extern ssize_t zip_entry_read(struct zip_t *zip, void **buf, size_t *bufsize);

   
                                                                      
              
  
                                  
                                         
                                                
  
                                                       
                                                                           
                                                                  
                                                                             
  
                                                                          
                                                                      
   
extern ssize_t zip_entry_noallocread(struct zip_t *zip, void *buf,
                                     size_t bufsize);

   
                                                   
  
                                  
                               
  
                                                                          
   
extern int zip_entry_fread(struct zip_t *zip, const char *filename);

   
                                                                         
  
                                  
                                       
                                                                          
                              
  
                                                                          
   
extern int
zip_entry_extract(struct zip_t *zip,
                  size_t (*on_extract)(void *arg, unsigned long long offset,
                                       const void *data, size_t size),
                  void *arg);

   
                                                                                
  
                                  
  
                                                                              
                          
   
extern int zip_entries_total(struct zip_t *zip);

   
                               
  
                                  
                                                             
                                                  
                                                                            
   
extern int zip_entries_delete(struct zip_t *zip, char *const entries[],
                              const size_t len);

   
                                                
  
                                                               
                                         
                                                                              
                                                                              
                                   
  
                                    
                           
                               
                                         
                             
  
                                                                          
   
extern int zip_stream_extract(const char *stream, size_t size, const char *dir,
                              int (*on_extract)(const char *filename,
                                                void *arg),
                              void *arg);

   
                                        
  
                                    
                           
  
                                                   
   
extern struct zip_t *zip_stream_open(const char *stream, size_t size, int level,
                                     char mode);

   
                                         
  
                                  
                                                  
                                                
  
                    
   
extern ssize_t zip_stream_copy(struct zip_t *zip, void **buf, ssize_t *bufsize);

   
                                        
  
                                  
  
          
   
extern void zip_stream_close(struct zip_t *zip);

   
                                                                  
  
                                   
                                
                                     
  
                                                                          
   
extern int zip_create(const char *zipname, const char *filenames[], size_t len);

   
                                              
  
                                                                     
                                         
                                                                              
                                                                              
                                         
  
                                   
                               
                                               
                             
  
                                                                          
   
extern int zip_extract(const char *zipname, const char *dir,
                       int (*on_extract_entry)(const char *filename, void *arg),
                       void *arg);

         
#ifdef __cplusplus
}
#endif

#endif

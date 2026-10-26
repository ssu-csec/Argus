//===- llvm/Support/Path.h - Path Operating System Concept ------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the llvh::sys::path namespace. It is designed after
// TR2/boost filesystem (v3), but modified to remove exception handling and the
// path class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_PATH_H
#define LLVM_SUPPORT_PATH_H

#include "llvh/ADT/Twine.h"
#include "llvh/ADT/iterator.h"
#include "llvh/Support/DataTypes.h"
#include <iterator>
#include <system_error>

namespace llvh {
namespace sys {
namespace path {

enum class Style { windows, posix, native };

                                    
      

                  
   
                                                                             
                                               
                                        
                                             
                                                   
                                                                         
                                                             
   
                                                           
         
                     
                         
                         
                             
                        
                                
            
class const_iterator
    : public iterator_facade_base<const_iterator, std::input_iterator_tag,
                                  const StringRef> {
  StringRef Path;                           
  StringRef Component;                                                     
  size_t    Position;                                                  
  Style S;                                        

                                                    
  friend const_iterator begin(StringRef path, Style style);
  friend const_iterator end(StringRef path);

public:
  reference operator*() const { return Component; }
  const_iterator &operator++();                   
  bool operator==(const const_iterator &RHS) const;

                                               
  ptrdiff_t operator-(const const_iterator &RHS) const;
};

                          
   
                                                                             
                                                                               
                        
class reverse_iterator
    : public iterator_facade_base<reverse_iterator, std::input_iterator_tag,
                                  const StringRef> {
  StringRef Path;                           
  StringRef Component;                                                     
  size_t    Position;                                                  
  Style S;                                        

  friend reverse_iterator rbegin(StringRef path, Style style);
  friend reverse_iterator rend(StringRef path);

public:
  reference operator*() const { return Component; }
  reverse_iterator &operator++();                   
  bool operator==(const reverse_iterator &RHS) const;

                                               
  ptrdiff_t operator-(const reverse_iterator &RHS) const;
};

                                    
                           
                                                                      
const_iterator begin(StringRef path, Style style = Style::native);

                                  
                           
                                                        
const_iterator end(StringRef path);

                                            
                           
                                                                              
reverse_iterator rbegin(StringRef path, Style style = Style::native);

                                          
                           
                                                                
reverse_iterator rend(StringRef path);

      
                           
      

                                                                     
   
         
                                          
                                         
                                       
                                 
            
   
                                                                     
void remove_filename(SmallVectorImpl<char> &path, Style style = Style::native);

                                                            
   
         
                                            
                                            
                                    
            
   
                                                                         
                                                                            
                                                                             
                               
void replace_extension(SmallVectorImpl<char> &path, const Twine &extension,
                       Style style = Style::native);

                                                   
   
         
                              
                                      
                                     
                                     
            
   
                                                                     
                                   
                                                           
                                                                  
void replace_path_prefix(SmallVectorImpl<char> &Path,
                         const StringRef &OldPrefix, const StringRef &NewPrefix,
                         Style style = Style::native);

                   
   
         
                                 
                                 
                                
            
   
                                              
                                                     
void append(SmallVectorImpl<char> &path, const Twine &a,
                                         const Twine &b = "",
                                         const Twine &c = "",
                                         const Twine &d = "");

void append(SmallVectorImpl<char> &path, Style style, const Twine &a,
            const Twine &b = "", const Twine &c = "", const Twine &d = "");

                   
   
         
                                   
                                   
                                  
            
   
                                                    
                                               
                                                        
void append(SmallVectorImpl<char> &path, const_iterator begin,
            const_iterator end, Style style = Style::native);

      
                                                
      

                                                                            
                                                                                
                                 
   
                                                            
                                                         
void native(const Twine &path, SmallVectorImpl<char> &result,
            Style style = Style::native);

                                                                           
                                                                               
                                            
   
                                                            
void native(SmallVectorImpl<char> &path, Style style = Style::native);

                                                 
   
                              
                                                                                
                                                                        
              
std::string convert_to_slash(StringRef path, Style style = Style::native);

      
                           
      

                  
   
         
                          
                                                                
                            
            
   
                           
                                                                 
StringRef root_name(StringRef path, Style style = Style::native);

                       
   
         
                     
                     
                           
            
   
                           
                                                                  
                     
StringRef root_directory(StringRef path, Style style = Style::native);

                  
   
                                             
   
                           
                                                                 
StringRef root_path(StringRef path, Style style = Style::native);

                      
   
         
                                   
                               
                               
            
   
                           
                                                                          
StringRef relative_path(StringRef path, Style style = Style::native);

                    
   
         
                           
                     
                          
            
   
                           
                                                                   
StringRef parent_path(StringRef path, Style style = Style::native);

                 
   
         
                            
                     
                      
                     
            
   
                           
                                                                               
                       
StringRef filename(StringRef path, Style style = Style::native);

             
   
                                                                            
                                                                               
                   
   
         
                         
                         
                             
                       
                        
            
   
                           
                                
StringRef stem(StringRef path, Style style = Style::native);

                  
   
                                                                            
                                                                              
                                        
   
         
                          
                             
                          
            
   
                           
                                     
StringRef extension(StringRef path, Style style = Style::native);

                                                                    
   
                            
                                                                         
bool is_separator(char value, Style style = Style::native);

                                                     
   
                                                                  
StringRef get_separator(Style style = Style::native);

                                                             
                           
   
                                                                          
                                                                            
                                                                          
                                                                             
   
                                                
void system_temp_directory(bool erasedOnReboot, SmallVectorImpl<char> &result);

                                  
   
                                                
                                                             
bool home_directory(SmallVectorImpl<char> &result);

                  
   
                   
   
                           
                                                              
bool has_root_name(const Twine &path, Style style = Style::native);

                       
   
                        
   
                           
                                                                   
bool has_root_directory(const Twine &path, Style style = Style::native);

                  
   
                   
   
                           
                                                              
bool has_root_path(const Twine &path, Style style = Style::native);

                      
   
                       
   
                           
                                                                  
bool has_relative_path(const Twine &path, Style style = Style::native);

                    
   
                     
   
                           
                                                                
bool has_parent_path(const Twine &path, Style style = Style::native);

                 
   
                  
   
                           
                                                             
bool has_filename(const Twine &path, Style style = Style::native);

             
   
              
   
                           
                                                         
bool has_stem(const Twine &path, Style style = Style::native);

                  
   
                   
   
                           
                                                              
bool has_extension(const Twine &path, Style style = Style::native);

                     
   
                           
                                                             
bool is_absolute(const Twine &path, Style style = Style::native);

                     
   
                           
                                                             
bool is_relative(const Twine &path, Style style = Style::native);

                                                                    
   
                           
                                   
StringRef remove_leading_dotslash(StringRef path, Style style = Style::native);

                                                                         
   
                              
                                                                               
           
                                    
bool remove_dots(SmallVectorImpl<char> &path, bool remove_dot_dot = false,
                 Style style = Style::native);

#if defined(_WIN32)
std::error_code widenPath(const Twine &Path8, SmallVectorImpl<wchar_t> &Path16);
#endif

}                      
}                     
}                      

#endif

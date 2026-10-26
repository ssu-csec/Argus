//===- llvm/ADT/UniqueVector.h ----------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_UNIQUEVECTOR_H
#define LLVM_ADT_UNIQUEVECTOR_H

#include <cassert>
#include <cstddef>
#include <map>
#include <vector>

namespace llvh {

                                                                                
                                                                               
                                                                             
                                                                       
                                                              
template<class T> class UniqueVector {
public:
  using VectorType = typename std::vector<T>;
  using iterator = typename VectorType::iterator;
  using const_iterator = typename VectorType::const_iterator;

private:
                                                            
  std::map<T, unsigned> Map;

                                                                             
  VectorType Vector;

public:
                                                                               
                                                      
  unsigned insert(const T &Entry) {
                                                
    unsigned &Val = Map[Entry];

                                                  
    if (Val) return Val;

                            
    Val = static_cast<unsigned>(Vector.size()) + 1;

                        
    Vector.push_back(Entry);
    return Val;
  }

                                                                             
                
  unsigned idFor(const T &Entry) const {
                                   
    typename std::map<T, unsigned>::const_iterator MI = Map.find(Entry);

                                            
    if (MI != Map.end()) return MI->second;

               
    return 0;
  }

                                                                          
  const T &operator[](unsigned ID) const {
    assert(ID-1 < size() && "ID is 0 or out of range!");
    return Vector[ID - 1];
  }

                                                    
  iterator begin() { return Vector.begin(); }

                                                    
  const_iterator begin() const { return Vector.begin(); }

                                                  
  iterator end() { return Vector.end(); }

                                                  
  const_iterator end() const { return Vector.end(); }

                                                         
  size_t size() const { return Vector.size(); }

                                                  
  bool empty() const { return Vector.empty(); }

                                     
  void reset() {
    Map.clear();
    Vector.resize(0, 0);
  }
};

}                      

#endif                           

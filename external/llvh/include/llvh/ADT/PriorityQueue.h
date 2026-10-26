//===- llvm/ADT/PriorityQueue.h - Priority queues ---------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the PriorityQueue class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_PRIORITYQUEUE_H
#define LLVM_ADT_PRIORITYQUEUE_H

#include <algorithm>
#include <queue>

namespace llvh {

                                                                   
                                                    
   
template<class T,
         class Sequence = std::vector<T>,
         class Compare = std::less<typename Sequence::value_type> >
class PriorityQueue : public std::priority_queue<T, Sequence, Compare> {
public:
  explicit PriorityQueue(const Compare &compare = Compare(),
                         const Sequence &sequence = Sequence())
    : std::priority_queue<T, Sequence, Compare>(compare, sequence)
  {}

  template<class Iterator>
  PriorityQueue(Iterator begin, Iterator end,
                const Compare &compare = Compare(),
                const Sequence &sequence = Sequence())
    : std::priority_queue<T, Sequence, Compare>(begin, end, compare, sequence)
  {}

                                                                     
                                                                          
                                                                     
                          
     
  void erase_one(const T &t) {
                                         
    typename Sequence::size_type i = find(this->c, t) - this->c.begin();

                                       
    while (i != 0) {
      typename Sequence::size_type parent = (i - 1) / 2;
      this->c[i] = this->c[parent];
      i = parent;
    }

                                                                      
                                               
    this->pop();
  }

                                                                      
                                                                  
                                                                    
                                                                   
                                                                     
                                    
     
  void reheapify() {
    std::make_heap(this->c.begin(), this->c.end(), this->comp);
  }

                                                
     
  void clear() {
    this->c.clear();
  }
};

}                      

#endif

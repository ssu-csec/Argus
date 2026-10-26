/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/VM/JSLib/Sorting.h"

#include "hermes/Support/Compiler.h"

#include "llvh/Support/MathExtras.h"

#include <algorithm>
#include <vector>

namespace hermes {
namespace vm {

SortModel::~SortModel() = default;

namespace {

                                                 
                             
                              
                                               
CallResult<bool> _less(
    SortModel *sm,
    const std::vector<uint32_t> &index,
    uint32_t i,
    uint32_t j) {
  auto res = sm->compare(i, j);
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  assert(i < index.size() && "OOB should be impossible");
  assert(j < index.size() && "OOB should be impossible");
  return (*res != 0) ? (*res < 0) : (index[i] < index[j]);
}

                                                        
ExecutionStatus
_swap(SortModel *sm, std::vector<uint32_t> &index, uint32_t i, uint32_t j) {
  if (sm->swap(i, j) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  assert(i < index.size() && "OOB should be impossible");
  assert(j < index.size() && "OOB should be impossible");
  std::swap(index[i], index[j]);
  return ExecutionStatus::RETURNED;
}

   
                                                 
   
LLVM_NODISCARD ExecutionStatus heapFixDown(
    SortModel *sm,
    std::vector<uint32_t> &index,
    uint32_t base,
    uint32_t begin,
    uint32_t end) {
  CallResult<bool> res{false};
  if (LLVM_UNLIKELY(end - begin <= 1)) {
    return ExecutionStatus::RETURNED;
  }

  uint32_t lastGood = base + (end - base - 2) / 2;
  uint32_t i = begin;

  while (i <= lastGood) {
    uint32_t j = (i - base) * 2 + 1 + base;
                                           
    if (j + 1 < end) {
      res = _less(sm, index, j, j + 1);
      if (res == ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
      if (*res) {
        ++j;
      }
    }
                                                       
    res = _less(sm, index, i, j);
    if (res == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    if (!*res) {
      break;
    }

    if (_swap(sm, index, i, j) == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    i = j;
  }

  return ExecutionStatus::RETURNED;
}

ExecutionStatus heapSort(
    SortModel *sm,
    std::vector<uint32_t> &index,
    uint32_t begin,
    uint32_t end) {
  if (LLVM_UNLIKELY(end - begin <= 1)) {
    return ExecutionStatus::RETURNED;
  }

              
  uint32_t start = (end - begin - 2) / 2 + begin;
  do {
    if (heapFixDown(sm, index, begin, start, end) ==
        ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
  } while (start-- != begin);

  while (end - begin > 1) {
    --end;
    if (_swap(sm, index, begin, end) == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    if (heapFixDown(sm, index, begin, begin, end) ==
        ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
  }

  return ExecutionStatus::RETURNED;
}

ExecutionStatus insertionSort(
    SortModel *sm,
    std::vector<uint32_t> &index,
    uint32_t begin,
    uint32_t end) {
  CallResult<bool> res{false};
  if (begin == end) {
    return ExecutionStatus::RETURNED;
  }

  for (uint32_t i = begin + 1; i != end; ++i) {
    for (uint32_t j = i; j != begin; --j) {
      res = _less(sm, index, j, j - 1);
      if (res == ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
      if (!*res) {
        break;
      }
      if (_swap(sm, index, j, j - 1) == ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
    }
  }
  return ExecutionStatus::RETURNED;
}

                                                   
const uint32_t INSERTION_THRESHOLD = 6;

                                                                
                                                              
                                                                               
                                                                        
              
                                       
CallResult<uint32_t> quickSortPartition(
    SortModel *sm,
    std::vector<uint32_t> &index,
    uint32_t l,
    uint32_t r) {
  CallResult<bool> res{false};
                            
                        
  uint32_t pivot = l + 1;

  uint32_t i = pivot + 1, j = r;
  for (;;) {
    for (; i <= j; ++i) {
      res = _less(sm, index, i, pivot);
      if (res == ExecutionStatus::EXCEPTION)
        return ExecutionStatus::EXCEPTION;
      if (!*res)
        break;
    }
    assert(i <= r + 1 && "i is out of range");

    for (; i <= j; --j) {
      res = _less(sm, index, pivot, j);
      if (res == ExecutionStatus::EXCEPTION)
        return ExecutionStatus::EXCEPTION;
      if (!*res)
        break;
    }
    assert(j > l && "j is out of range");

    if (i >= j)
      break;
    if (_swap(sm, index, i, j) == ExecutionStatus::EXCEPTION)
      return ExecutionStatus::EXCEPTION;
    ++i;
    --j;
  }

                                                               
  if (j != pivot) {
    if (_swap(sm, index, pivot, j) == ExecutionStatus::EXCEPTION)
      return ExecutionStatus::EXCEPTION;
  }

  return j;
}

ExecutionStatus doQuickSort(
    SortModel *sm,
    std::vector<uint32_t> &index,
    int limit,
    uint32_t l,
    uint32_t r) {
  CallResult<bool> res{false};
quicksort_top:
  if (limit <= 0) {
                        
    return heapSort(sm, index, l, r + 1);
  }

                    
                                      
  if (_swap(sm, index, l + 1, l + ((r - l) >> 1)) ==
      ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
                          
  res = _less(sm, index, r, l + 1);
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  if (*res) {
    if (_swap(sm, index, r, l + 1) == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
  }
  res = _less(sm, index, l + 1, l);
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  if (*res) {
    if (_swap(sm, index, l + 1, l) == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
  }
  res = _less(sm, index, r, l + 1);
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  if (*res) {
    if (_swap(sm, index, r, l + 1) == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
  }

                            
                                             
  CallResult<uint32_t> partitionResult{quickSortPartition(sm, index, l, r)};
  if (partitionResult == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  uint32_t j = *partitionResult;

                                                                      
                                      
  uint32_t lSize = j - l;
  uint32_t rSize = r - j;
  if (lSize <= rSize) {
    if (lSize > INSERTION_THRESHOLD) {
      if (doQuickSort(sm, index, limit - 1, l, j - 1) ==
          ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
    } else {
      if (insertionSort(sm, index, l, j) == ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
    }

    if (rSize > INSERTION_THRESHOLD) {
      l = j + 1;
      --limit;
      goto quicksort_top;
    } else {
      if (insertionSort(sm, index, j + 1, r + 1) ==
          ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
    }

  } else {
    if (rSize > INSERTION_THRESHOLD) {
      if (doQuickSort(sm, index, limit - 1, j + 1, r) ==
          ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
    } else {
      if (insertionSort(sm, index, j + 1, r + 1) ==
          ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
    }

    if (lSize > INSERTION_THRESHOLD) {
      r = j - 1;
      --limit;
      goto quicksort_top;
    } else {
      if (insertionSort(sm, index, l, j) == ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
    }
  }

  return ExecutionStatus::RETURNED;
}

}             

ExecutionStatus quickSort(SortModel *sm, uint32_t begin, uint32_t end) {
  if (begin >= end)
    return ExecutionStatus::RETURNED;
  uint32_t len = end - begin;
  std::vector<uint32_t> index(len);                                      
  for (uint32_t i = 0; i < len; ++i) {
    index[i] = i;
  }

  if (len > INSERTION_THRESHOLD) {
    return doQuickSort(sm, index, llvh::Log2_32(len) * 2, begin, end - 1);
  } else {
    return insertionSort(sm, index, begin, end);
  }
}

}                
}                    

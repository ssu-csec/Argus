/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/Support/Conversions.h"

#include "dtoa/dtoa.h"

#include <cmath>

namespace hermes {

                                                                        
                                                                            
                     
                                                                           
                                                                               
                                  
int32_t truncateToInt32SlowPath(double d) {
  double tmp = d;                                  
  uint64_t bits = llvh::DoubleToBits(tmp);
  int exp = (int)(bits >> 52) & 0x7FF;
                                                                            
                           
  int sign = 1 - ((int)((int64_t)bits >> 62) & 2);
  uint64_t m = bits & 0xFFFFFFFFFFFFFul;

                                                                       
  if (!exp)
    return 0;

                                                                           
                                                                        
  exp -= 1023 + 52;
                                   
  m |= 1ull << 52;

                                                          
  if (exp >= 0) {
                                                                            
                        
                                                                             
                                                                               
                                                                             
                        
    return exp <= 31 ? sign * (int64_t)(m << exp) : 0;
  } else {
                                                             
                                                             
                         
    return exp > -53 ? sign * (int64_t)(m >> -exp) : 0;
  }
}

               
size_t numberToString(double m, char *dest, size_t destSize) {
  assert(destSize >= NUMBER_TO_STRING_BUF_SIZE);
  (void)destSize;
  DtoaAllocator<> dalloc{};

  if (std::isnan(m)) {
    strcpy(dest, "NaN");
    return 3;
  }

  if (m == 0) {
    strcpy(dest, "0");
    return 1;
  }

  if (m == std::numeric_limits<double>::infinity()) {
    strcpy(dest, "Infinity");
    return 8;
  }
  if (m == -std::numeric_limits<double>::infinity()) {
    strcpy(dest, "-Infinity");
    return 9;
  }

                                              
                                                                   
                                                  

                                    
  char *destPtr = dest;

                         
  int n;

                           
  int sign;

                                                            
  char *sEnd;

  char *s = ::g_dtoa(dalloc, m, 0, 0, &n, &sign, &sEnd);

  if (sign)
    *destPtr++ = '-';

                                           
  int k = sEnd - s;

  if (k <= n && n <= 21) {
                       
    for (int i = 0; i < k; ++i) {
      *destPtr++ = s[i];
    }
    for (int i = 0; i < n - k; ++i) {
      *destPtr++ = '0';
    }
  } else if (0 < n && n <= 21) {
                       
    for (int i = 0; i < n; ++i) {
      *destPtr++ = s[i];
    }
    *destPtr++ = '.';
    for (int i = n; i < k; ++i) {
      *destPtr++ = s[i];
    }
  } else if (-6 < n && n <= 0) {
                       
    *destPtr++ = '0';
    *destPtr++ = '.';
    for (int i = 0; i < -n; ++i) {
      *destPtr++ = '0';
    }
    for (int i = 0; i < k; ++i) {
      *destPtr++ = s[i];
    }
  } else if (k == 1) {
                       
    char nBuf[NUMBER_TO_STRING_BUF_SIZE];
    int nLen = ::snprintf(nBuf, sizeof(nBuf), "%d", ::abs(n - 1));

    *destPtr++ = s[0];
    *destPtr++ = 'e';
    *destPtr++ = n - 1 < 0 ? '-' : '+';
    for (int i = 0; i < nLen; ++i) {
      *destPtr++ = nBuf[i];
    }
  } else {
                        
    char nBuf[NUMBER_TO_STRING_BUF_SIZE];
    int nLen = ::snprintf(nBuf, sizeof(nBuf), "%d", ::abs(n - 1));

    *destPtr++ = s[0];
    *destPtr++ = '.';
    for (int i = 1; i < k; ++i) {
      *destPtr++ = s[i];
    }
    *destPtr++ = 'e';
    *destPtr++ = n - 1 < 0 ? '-' : '+';
    for (int i = 0; i < nLen; ++i) {
      *destPtr++ = nBuf[i];
    }
  }

                   
  *destPtr++ = '\0';
  assert(static_cast<size_t>(destPtr - dest) < NUMBER_TO_STRING_BUF_SIZE);

  g_freedtoa(dalloc, s);
  return destPtr - dest - 1;
}
}                    

extern "C" {
size_t hermes_numberToString(double m, char *dest, size_t destSize) {
  return hermes::numberToString(m, dest, destSize);
}
}

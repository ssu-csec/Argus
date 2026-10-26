#include <cassert>
#include <mutex>

                                                                               
                                                        

static std::mutex mutex;

extern "C" void ACQUIRE_DTOA_LOCK(int n) {
  assert(n == 1 && "only dtoa lock 1 is supported");
  mutex.lock();
}

extern "C" void FREE_DTOA_LOCK(int n) {
  assert(n == 1 && "only dtoa lock 1 is supported");
  mutex.unlock();
}

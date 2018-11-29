#ifndef LIBSENC_OPENSSL_LOCKER_H_
#define LIBSENC_OPENSSL_LOCKER_H_

#include <stdint.h>

#if defined (WIN32) || defined (_WIN32) || defined (_WIN64)
#include <Windows.h>

#define _sleep_ms(x) Sleep(x)
#define INNER_ATOMIC_LOCK(x) {while(InterlockedCompareExchange(&x, 1, 0) == x){Sleep(10);}}
#define INNER_ATOMIC_UNLOCK(x) {InterlockedCompareExchange(&x, 0, 1);}

#elif defined (linux) || defined (__linux__)
#include <unistd.h>

#define _sleep_ms(x) usleep(1000*(x))
#define INNER_ATOMIC_LOCK(x) {while(!__sync_bool_compare_and_swap(&x, 0, 1)){usleep(10000);}}
#define INNER_ATOMIC_UNLOCK(x) {__sync_bool_compare_and_swap(&x, 1, 0);}

#endif

#ifdef __cplusplus
extern "C"{
#endif

void openssl_lock_cb(int mode, int type, char *file, int len);
uint64_t openssl_thread_id();
void init_openssl_locker();
void fini_openssl_locker();

#ifdef __cplusplus
}
#endif

#endif // LIBSENC_OPENSSL_LOCKER_H_

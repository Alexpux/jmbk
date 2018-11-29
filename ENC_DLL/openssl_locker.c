#include "openssl_locker.h"

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
#include <Windows.h>
#include <openssl/crypto.h>
#elif defined (linux) || defined (__linux__)
#include <openssl/crypto.h>
#include <pthread.h>
#endif



static char *g_openssl_mutex;

void openssl_lock_cb(int mode, int type, char *file, int line)
{
	(void)file;
	(void)line;

	if (mode & CRYPTO_LOCK) {
		INNER_ATOMIC_LOCK(g_openssl_mutex[type]);
	} else {
		INNER_ATOMIC_UNLOCK(g_openssl_mutex[type]);
	}
}

uint64_t openssl_thread_id()
{
#if defined (WIN32) || defined (_WIN32) || defined (_WIN64)
	return GetCurrentThreadId();
#elif defined (linux) || defined (__linux__)
	return pthread_self();
#endif
}

void init_openssl_locker()
{
	int i = 0;
	g_openssl_mutex = (char *)OPENSSL_malloc(CRYPTO_num_locks()*sizeof(char));
	for (i = 0; i < CRYPTO_num_locks(); ++i) {
		g_openssl_mutex[i] = 0;
	}
	CRYPTO_set_id_callback((uint64_t (*)())openssl_thread_id);
	CRYPTO_set_locking_callback((void (*)())openssl_lock_cb);
}

void fini_openssl_locker()
{
	CRYPTO_set_locking_callback(NULL);
	OPENSSL_free(g_openssl_mutex);
	g_openssl_mutex = NULL;
}

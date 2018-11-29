/*=========================================================
*	File name	£º	lock.h
*	Authored by	£º	xuxinyao
*	Date		£º	2004-10-9 14:23:41
*	Description	£º	
*
*	Modify  	£º	
*=========================================================*/

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)

#ifndef LIBSENC_LOCK_H_
#define LIBSENC_LOCK_H_

#include <windows.h>

class CLock 
{
public:
	CLock()
	{
		::InitializeCriticalSection(&m_lock);
	}
	~CLock()
	{
		::DeleteCriticalSection(&m_lock);
	}

	void lock()
	{
		::EnterCriticalSection(&m_lock);
	}
	void unlock()
	{
		::LeaveCriticalSection(&m_lock);
	}
	BOOL trylock()
	{
		return ::TryEnterCriticalSection(&m_lock);
	}

private:
	CLock(CLock const&);
	CLock& operator=(CLock const&);

	CRITICAL_SECTION m_lock;
};

class CGuard  
{
public:
	CGuard(CLock& lock) : m_lock(lock)
	{
		m_lock.lock();
	}
	~CGuard()
	{
		m_lock.unlock();
	}

private:
	CGuard(CGuard const&);
	CGuard& operator=(CGuard const&);

	CLock& m_lock;
};

class CGuardTlss
{
public:
	CGuardTlss(DWORD& lock) : m_lock(lock)
	{
		TlsSetValue(m_lock,(LPVOID)1);
	}
	~CGuardTlss()
	{
		TlsSetValue(m_lock, (LPVOID)0);
	}

private:
	CGuardTlss(CGuardTlss const&);
	CGuardTlss& operator=(CGuardTlss const&);

	DWORD & m_lock;
};

#endif // __LOCK_H__

#elif defined(linux) || defined(__linux__)

#ifndef TMUTEX_H
#define TMUTEX_H
#include <pthread.h>
struct ThreadMutex{
	ThreadMutex(){
		pthread_mutex_init(&mtx,NULL);
	}

	~ThreadMutex(){
		pthread_mutex_destroy(&mtx);
	}

	inline void lock(){
		pthread_mutex_lock(&mtx);
	}

	inline void unlock(){
		pthread_mutex_unlock(&mtx);
	}

	pthread_mutex_t mtx;
};

struct NullMutex{
	inline void lock(){

	}
	inline void unlock(){

	}
};

template<class T>
class CAutoGuard{
public:
	CAutoGuard(T &mtx):m_mtx(mtx){
		m_mtx.lock();
	}
	~CAutoGuard(){
		m_mtx.unlock();
	}
protected:
	T &m_mtx;
};

#define AUTO_GUARD(guard_tmp_var, MUTEX_TYPE, mtx) CAutoGuard<MUTEX_TYPE> guard_tmp_var(mtx);
#endif
#endif //LIBSENC_LOCK_H_

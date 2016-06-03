#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#ifdef __WIN32__
#  include "wimlib/win32_common.h"
#else
#  include <errno.h>
#  include <pthread.h>
#endif

#include "wimlib/error.h"
#include "wimlib/threads.h"
#include "wimlib/util.h"

#ifdef __WIN32__

static __stdcall DWORD
win32_thrproc(LPVOID lpParameter)
{
	struct thread *t = (struct thread *)lpParameter;
	t->arg = (*t->thrproc)(t->arg);
	return 0;
}

bool thread_create(struct thread *t, void *(*thrproc)(void *), void *arg)
{
	HANDLE h;

	t->thrproc = thrproc;
	t->arg = arg;
	h = CreateThread(NULL, 0, win32_thrproc, (LPVOID)t, 0, NULL);
	if (h == NULL) {
		win32_error(GetLastError(), L"Failed to create thread");
		return false;
	}
	t->win32_thread = (void *)h;
	return true;
}

void *thread_join(struct thread *t)
{
	WaitForSingleObject((HANDLE)t->win32_thread, INFINITE);
	return t->arg;
}

bool mutex_init(struct mutex *m)
{
	m->win32_critical_section = NULL;
	return true;
}

void mutex_destroy(struct mutex *m)
{
	if (m->win32_critical_section) {
		DeleteCriticalSection(m->win32_critical_section);
		FREE(m->win32_critical_section);
	}
}

void mutex_lock(struct mutex *m)
{
	CRITICAL_SECTION *crit = m->win32_critical_section;
	if (unlikely(!crit)) {
		CRITICAL_SECTION *old;

		crit = MALLOC(sizeof(CRITICAL_SECTION));
		InitializeCriticalSection(crit);
		old = InterlockedCompareExchangePointer(&m->win32_critical_section,
							crit, NULL);
		if (old) {
			DeleteCriticalSection(crit);
			crit = old;
		}
	}
	EnterCriticalSection(crit);
}

void mutex_unlock(struct mutex *m)
{
	LeaveCriticalSection(m->win32_critical_section);
}

bool condvar_init(struct condvar *c)
{
	return false;
}

void condvar_destroy(struct condvar *c)
{
}

void condvar_wait(struct condvar *c, struct mutex *m)
{
}

void condvar_signal(struct condvar *c)
{
}

void condvar_broadcast(struct condvar *c)
{
}

#else /* __WIN32__ */

bool thread_create(struct thread *t, void *(*thrproc)(void *), void *arg)
{
	int err = pthread_create(&t->pthread, NULL, thrproc, arg);
	if (err) {
		errno = err;
		ERROR_WITH_ERRNO("Failed to create thread");
		return false;
	}
	return true;
}

void *thread_join(struct thread *t)
{
	void *retval = NULL;
	pthread_join(t->pthread, &retval);
	return retval;
}

bool mutex_init(struct mutex *m)
{
	int err = pthread_mutex_init(&m->pthread_mutex, NULL);
	if (err) {
		errno = err;
		ERROR_WITH_ERRNO("Failed to initialize mutex");
		return false;
	}
	return true;
}


bool condvar_init(struct condvar *c)
{
	int err = pthread_cond_init(&c->pthread_cond, NULL);
	if (err) {
		errno = err;
		ERROR_WITH_ERRNO("Failed to initialize condition variable");
		return false;
	}
	return true;
}

#endif /* !__WIN32__ */

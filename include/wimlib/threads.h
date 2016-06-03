#ifndef _WIMLIB_THREADS_H
#define _WIMLIB_THREADS_H

#ifdef __WIN32__
struct thread {
	void *win32_thread;
	void *(*thrproc)(void *);
	void *arg;
};

struct mutex {
	void *win32_critical_section;
};

struct condvar {
	void *win32_cond;
};
#define MUTEX_INITIALIZER { NULL }

extern void mutex_destroy(struct mutex *m);
extern void mutex_lock(struct mutex *m);
extern void mutex_unlock(struct mutex *m);
extern void condvar_destroy(struct condvar *c);
extern void condvar_wait(struct condvar *c, struct mutex *m);
extern void condvar_signal(struct condvar *c);
extern void condvar_broadcast(struct condvar *c);

#else /* __WIN32__ */

#include <pthread.h>
struct thread {
	pthread_t pthread;
};

struct mutex {
	pthread_mutex_t pthread_mutex;
};

struct condvar {
	pthread_cond_t pthread_cond;
};

#define MUTEX_INITIALIZER { PTHREAD_MUTEX_INITIALIZER }

static inline void mutex_destroy(struct mutex *m)
{
	pthread_mutex_destroy(&m->pthread_mutex);
}

static inline void mutex_lock(struct mutex *m)
{
	pthread_mutex_lock(&m->pthread_mutex);
}

static inline void mutex_unlock(struct mutex *m)
{
	pthread_mutex_unlock(&m->pthread_mutex);
}

static inline void condvar_destroy(struct condvar *c)
{
	pthread_cond_destroy(&c->pthread_cond);
}

static inline void condvar_wait(struct condvar *c, struct mutex *m)
{
	pthread_cond_wait(&c->pthread_cond, &m->pthread_mutex);
}

static inline void condvar_signal(struct condvar *c)
{
	pthread_cond_signal(&c->pthread_cond);
}

static inline void condvar_broadcast(struct condvar *c)
{
	pthread_cond_broadcast(&c->pthread_cond);
}

#endif /* !__WIN32__ */

extern bool thread_create(struct thread *t, void *(*thrproc)(void *), void *arg);
extern void *thread_join(struct thread *t);
extern bool condvar_init(struct condvar *c);
extern bool mutex_init(struct mutex *m);



#endif /* _WIMLIB_THREADS_H */

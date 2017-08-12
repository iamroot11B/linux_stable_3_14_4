/*
 * include/asm-generic/mutex-null.h
 *
 * Generic implementation of the mutex fastpath, based on NOP :-)
 *
 * This is used by the mutex-debugging infrastructure, but it can also
 * be used by architectures that (for whatever reason) want to use the
 * spinlock based slowpath.
 */
#ifndef _ASM_GENERIC_MUTEX_NULL_H
#define _ASM_GENERIC_MUTEX_NULL_H

/*! 2017. 3.25 study -ing */
#define __mutex_fastpath_lock(count, fail_fn)		fail_fn(count)
/*! 2017. 8.12 study -ing */
#define __mutex_fastpath_lock_retval(count)		(-1)
/*! 2016-06-04 study -ing */
#define __mutex_fastpath_unlock(count, fail_fn)		fail_fn(count)
/*! 2017. 5.20 study -ing */
#define __mutex_fastpath_trylock(count, fail_fn)	fail_fn(count)
#define __mutex_slowpath_needs_to_unlock()		1

#endif

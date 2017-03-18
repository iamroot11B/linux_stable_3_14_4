/* rwsem-spinlock.c: R/W semaphores: contention handling functions for
 * generic spinlock implementation
 *
 * Copyright (c) 2001   David Howells (dhowells@redhat.com).
 * - Derived partially from idea by Andrea Arcangeli <andrea@suse.de>
 * - Derived also from comments by Linus
 */
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/export.h>

enum rwsem_waiter_type {
	RWSEM_WAITING_FOR_WRITE,
	RWSEM_WAITING_FOR_READ
};

struct rwsem_waiter {
	struct list_head list;
	struct task_struct *task;
	enum rwsem_waiter_type type;
};

int rwsem_is_locked(struct rw_semaphore *sem)
{
	int ret = 1;
	unsigned long flags;

	if (raw_spin_trylock_irqsave(&sem->wait_lock, flags)) {
		ret = (sem->activity != 0);
		raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
	}
	return ret;
}
EXPORT_SYMBOL(rwsem_is_locked);

/*
 * initialise the semaphore
 */
/*! 2016.07.09 study -ing */
void __init_rwsem(struct rw_semaphore *sem, const char *name,
		  struct lock_class_key *key)
{
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	/*
	 * Make sure we are not reinitializing a held semaphore:
	 */
	debug_check_no_locks_freed((void *)sem, sizeof(*sem));
	lockdep_init_map(&sem->dep_map, name, key, 0);
#endif
	/*! 세마포어, spin lock, list head 모두 init 수행  */
	sem->activity = 0;
	raw_spin_lock_init(&sem->wait_lock);
	INIT_LIST_HEAD(&sem->wait_list);
}
EXPORT_SYMBOL(__init_rwsem);

/*
 * handle the lock release when processes blocked on it that can now run
 * - if we come here, then:
 *   - the 'active count' _reached_ zero
 *   - the 'waiting count' is non-zero
 * - the spinlock must be held by the caller
 * - woken process blocks are discarded from the list after having task zeroed
 * - writers are only woken if wakewrite is non-zero
 */
/*! 2016.10.15 study -ing */
static inline struct rw_semaphore *
__rwsem_do_wake(struct rw_semaphore *sem, int wakewrite)
{
	struct rwsem_waiter *waiter;
	struct task_struct *tsk;
	int woken;

	/*! sem->wait_list의 next를 통해 waiter를 가져오고,  */
	waiter = list_entry(sem->wait_list.next, struct rwsem_waiter, list);

	/*! 가져온 waiter의  타입이 RWSEM_WAITING_FOR_WRITE이고 wakewrite이 1이면,
	 * wake_up_process를 수행
	 */
	if (waiter->type == RWSEM_WAITING_FOR_WRITE) {
		if (wakewrite)
			/* Wake up a writer. Note that we do not grant it the
			 * lock - it will have to acquire it when it runs. */
			wake_up_process(waiter->task);
		goto out;
	}

	/* grant an infinite number of read locks to the front of the queue */
	woken = 0;
	do {
		struct list_head *next = waiter->list.next;

		list_del(&waiter->list);
		tsk = waiter->task;
		smp_mb();
		waiter->task = NULL;
		wake_up_process(tsk);
		put_task_struct(tsk);
		woken++;
		if (next == &sem->wait_list)
			break;
		waiter = list_entry(next, struct rwsem_waiter, list);
	} while (waiter->type != RWSEM_WAITING_FOR_WRITE);

	sem->activity += woken;

 out:
	return sem;
}

/*
 * wake a single writer
 */
/*! 2017. 3.18 study -ing */
static inline struct rw_semaphore *
__rwsem_wake_one_writer(struct rw_semaphore *sem)
{
	struct rwsem_waiter *waiter;

	waiter = list_entry(sem->wait_list.next, struct rwsem_waiter, list);
	wake_up_process(waiter->task);

	return sem;
}

/*
 * get a read lock on the semaphore
 */
/*! 2017. 3.18 study -ing */
void __sched __down_read(struct rw_semaphore *sem)
{
	struct rwsem_waiter waiter;
	struct task_struct *tsk;
	unsigned long flags;

	raw_spin_lock_irqsave(&sem->wait_lock, flags);

	/*! 정상적으로 처리되면 sem->activity만 ++ 시켜주고 리턴  */
	if (sem->activity >= 0 && list_empty(&sem->wait_list)) {
		/* granted */
		sem->activity++;
		raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
		goto out;
	}

	/*! 아니면 waiter를 만들어서 scheduling 하면서 wait 수행  */
	tsk = current;
	set_task_state(tsk, TASK_UNINTERRUPTIBLE);

	/* set up my own style of waitqueue */
	waiter.task = tsk;
	waiter.type = RWSEM_WAITING_FOR_READ;
	get_task_struct(tsk);

	list_add_tail(&waiter.list, &sem->wait_list);

	/* we don't need to touch the semaphore struct anymore */
	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);

	/* wait to be given the lock */
	for (;;) {
		if (!waiter.task)
			break;
		schedule();
		set_task_state(tsk, TASK_UNINTERRUPTIBLE);
	}

	tsk->state = TASK_RUNNING;
 out:
	;
}

/*
 * trylock for reading -- returns 1 if successful, 0 if contention
 */
int __down_read_trylock(struct rw_semaphore *sem)
{
	unsigned long flags;
	int ret = 0;


	raw_spin_lock_irqsave(&sem->wait_lock, flags);

	if (sem->activity >= 0 && list_empty(&sem->wait_list)) {
		/* granted */
		sem->activity++;
		ret = 1;
	}

	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);

	return ret;
}

/*
 * get a write lock on the semaphore
 */
/*! 2016.10.15 study -ing */
void __sched __down_write_nested(struct rw_semaphore *sem, int subclass)
{
	struct rwsem_waiter waiter;
	struct task_struct *tsk;
	unsigned long flags;

	/*! spin lock을 걸고,  */
	raw_spin_lock_irqsave(&sem->wait_lock, flags);

	/* set up my own style of waitqueue */
	tsk = current;
	waiter.task = tsk;
	waiter.type = RWSEM_WAITING_FOR_WRITE;

	/*! sem->wait_list에 waiter.list를 추가  */
	list_add_tail(&waiter.list, &sem->wait_list);

	/* wait for someone to release the lock */
	for (;;) {
		/*
		 * That is the key to support write lock stealing: allows the
		 * task already on CPU to get the lock soon rather than put
		 * itself into sleep and waiting for system woke it or someone
		 * else in the head of the wait list up.
		 */
		/*! sem->activity가 0이 될때까지 기다린다. */
		if (sem->activity == 0)
			break;

		/*! tsk->state에 TASK_UNINTERRUPTIBLE를 대입  */
		set_task_state(tsk, TASK_UNINTERRUPTIBLE);
		raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
		schedule();
		raw_spin_lock_irqsave(&sem->wait_lock, flags);
	}
	/* got the lock */
	sem->activity = -1;
	list_del(&waiter.list);

	/*! 위에서 건 spin lock 해제  */
	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
}
/*! 2016.10.15 study -ing */
void __sched __down_write(struct rw_semaphore *sem)
{
	__down_write_nested(sem, 0);
}

/*
 * trylock for writing -- returns 1 if successful, 0 if contention
 */
int __down_write_trylock(struct rw_semaphore *sem)
{
	unsigned long flags;
	int ret = 0;

	raw_spin_lock_irqsave(&sem->wait_lock, flags);

	if (sem->activity == 0) {
		/* got the lock */
		sem->activity = -1;
		ret = 1;
	}

	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);

	return ret;
}

/*
 * release a read lock on the semaphore
 */
/*! 2017. 3.18 study -ing */
void __up_read(struct rw_semaphore *sem)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&sem->wait_lock, flags);

	if (--sem->activity == 0 && !list_empty(&sem->wait_list))
		sem = __rwsem_wake_one_writer(sem);

	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
}

/*
 * release a write lock on the semaphore
 */
/*! 2016.10.15 study -ing */
void __up_write(struct rw_semaphore *sem)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&sem->wait_lock, flags);

	sem->activity = 0;
	/*! sem->wait_list가 empty가 아니면 __rwsem_do_wake수행 */
	if (!list_empty(&sem->wait_list))
		sem = __rwsem_do_wake(sem, 1);

	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
}

/*
 * downgrade a write lock into a read lock
 * - just wake up any readers at the front of the queue
 */
void __downgrade_write(struct rw_semaphore *sem)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&sem->wait_lock, flags);

	sem->activity = 1;
	if (!list_empty(&sem->wait_list))
		sem = __rwsem_do_wake(sem, 0);

	raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
}

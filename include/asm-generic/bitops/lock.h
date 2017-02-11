#ifndef _ASM_GENERIC_BITOPS_LOCK_H_
#define _ASM_GENERIC_BITOPS_LOCK_H_

/**
 * test_and_set_bit_lock - Set a bit and return its old value, for lock
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is atomic and provides acquire barrier semantics.
 * It can be used to implement bit locks.
 */
/*! 2015.01.30 study -ing */
/*! addr의 nr 비트를 set 하고, 해당 bit의 기존값이 1 이었으면 1을 리턴,
 *  해당 비트가 0 이었으면 0 리턴
 */
#define test_and_set_bit_lock(nr, addr)	test_and_set_bit(nr, addr)

/**
 * clear_bit_unlock - Clear a bit in memory, for unlock
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * This operation is atomic and provides release barrier semantics.
 */
/*! 2017. 2.11 study -ing */
#define clear_bit_unlock(nr, addr)	\
do {					\
	smp_mb__before_clear_bit();	\
	clear_bit(nr, addr);		\
} while (0)

/**
 * __clear_bit_unlock - Clear a bit in memory, for unlock
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * This operation is like clear_bit_unlock, however it is not atomic.
 * It does provide release barrier semantics so it can be used to unlock
 * a bit lock, however it would only be used if no other CPU can modify
 * any bits in the memory until the lock is released (a good example is
 * if the bit lock itself protects access to the other bits in the word).
 */
#define __clear_bit_unlock(nr, addr)	\
do {					\
	smp_mb();			\
	__clear_bit(nr, addr);		\
} while (0)

#endif /* _ASM_GENERIC_BITOPS_LOCK_H_ */

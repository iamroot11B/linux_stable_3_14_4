/*
 *  arch/arm/include/asm/cache.h
 */
#ifndef __ASMARM_CACHE_H
#define __ASMARM_CACHE_H

#define L1_CACHE_SHIFT		CONFIG_ARM_L1_CACHE_SHIFT
#define L1_CACHE_BYTES		(1 << L1_CACHE_SHIFT)
/*! 1<<6 */

/*
 * Memory returned by kmalloc() may be used for DMA, so we must make
 * sure that all such allocations are cache aligned. Otherwise,
 * unrelated code may cause parts of the buffer to be read into the
 * cache before the transfer is done, causing old data to be seen by
 * the CPU.
 */
#define ARCH_DMA_MINALIGN	L1_CACHE_BYTES

/*
 * With EABI on ARMv5 and above we must have 64-bit aligned slab pointers.
 */
#if defined(CONFIG_AEABI) && (__LINUX_ARM_ARCH__ >= 5)
#define ARCH_SLAB_MINALIGN 8
#endif
/*! __read_mostly 매크로를 통해서 프로그래머는 컴파일러에게  " 이 데이터는 자주 수정되지 않으며 대부분 읽기 연산만 이루어진다" 라는 것을 알려준다. 
 * http://blog.daum.net/birdkiller/326  
 * http://stackoverflow.com/a/19233388
 */
#define __read_mostly __attribute__((__section__(".data..read_mostly")))

#endif

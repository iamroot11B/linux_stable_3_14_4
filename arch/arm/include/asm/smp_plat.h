/*
 * ARM specific SMP header, this contains our implementation
 * details.
 */
#ifndef __ASMARM_SMP_PLAT_H
#define __ASMARM_SMP_PLAT_H

#include <linux/cpumask.h>
#include <linux/err.h>

#include <asm/cputype.h>

/*
 * Return true if we are running on a SMP platform
 */
static inline bool is_smp(void)
{
#ifndef CONFIG_SMP
	return false;
#elif defined(CONFIG_SMP_ON_UP)
	extern unsigned int smp_on_up;
    /*! !! = ! 두번 쓴것
     * 결과를 bool(0, 1)로 반환, 그리고 코드 최적화 */
	return !!smp_on_up;
#else
	return true;
#endif
}

/* all SMP configurations have the extended CPUID registers */
#ifndef CONFIG_MMU
#define tlb_ops_need_broadcast()	0
#else
/*! 2016-04-02 study -ing */
static inline int tlb_ops_need_broadcast(void)
{
	if (!is_smp())
		return 0;

	/*! #define CPUID_EXT_MMFR3	"c1, 7"  */
	/*! tlb ops broadcast 가 필요한지 CP15 register를 읽어서 확인
	 *  (값이 0,1 인 경우 tlb가 local에만 영향을 미치므로 broadcast 필요
	 */
	return ((read_cpuid_ext(CPUID_EXT_MMFR3) >> 12) & 0xf) < 2;
}
#endif

#if !defined(CONFIG_SMP) || __LINUX_ARM_ARCH__ >= 7
#define cache_ops_need_broadcast()	0
#else
static inline int cache_ops_need_broadcast(void)
{
	if (!is_smp())
		return 0;

	return ((read_cpuid_ext(CPUID_EXT_MMFR3) >> 12) & 0xf) < 1;
}
#endif

/*
 * Logical CPU mapping.
 */

/*! __cpu_logical_map[] -> arch/arm/kernel/setup.c로 돌아가면 있음  */
extern u32 __cpu_logical_map[];
#define cpu_logical_map(cpu)	__cpu_logical_map[cpu]
/*
 * Retrieve logical cpu index corresponding to a given MPIDR[23:0]
 *  - mpidr: MPIDR[23:0] to be used for the look-up
 *
 * Returns the cpu logical index or -EINVAL on look-up error
 */
static inline int get_logical_index(u32 mpidr)
{
	int cpu;
	for (cpu = 0; cpu < nr_cpu_ids; cpu++)
		if (cpu_logical_map(cpu) == mpidr)
			return cpu;
	return -EINVAL;
}

/*
 * NOTE ! Assembly code relies on the following
 * structure memory layout in order to carry out load
 * multiple from its base address. For more
 * information check arch/arm/kernel/sleep.S
 */
struct mpidr_hash {
	u32	mask; /* used by sleep.S */
	u32	shift_aff[3]; /* used by sleep.S */
	u32	bits;
};

extern struct mpidr_hash mpidr_hash;

static inline u32 mpidr_hash_size(void)
{
	return 1 << mpidr_hash.bits;
}

extern int platform_can_cpu_hotplug(void);

#endif

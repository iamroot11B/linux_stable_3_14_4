/*
 *  linux/arch/arm/kernel/setup.c
 *
 *  Copyright (C) 1995-2001 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/ioport.h>
#include <linux/delay.h>
#include <linux/utsname.h>
#include <linux/initrd.h>
#include <linux/console.h>
#include <linux/bootmem.h>
#include <linux/seq_file.h>
#include <linux/screen_info.h>
#include <linux/of_platform.h>
#include <linux/init.h>
#include <linux/kexec.h>
#include <linux/of_fdt.h>
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/smp.h>
#include <linux/proc_fs.h>
#include <linux/memblock.h>
#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/sort.h>

#include <asm/unified.h>
#include <asm/cp15.h>
#include <asm/cpu.h>
#include <asm/cputype.h>
#include <asm/elf.h>
#include <asm/procinfo.h>
#include <asm/psci.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <asm/smp_plat.h>
#include <asm/mach-types.h>
#include <asm/cacheflush.h>
#include <asm/cachetype.h>
#include <asm/tlbflush.h>

#include <asm/prom.h>
#include <asm/mach/arch.h>
#include <asm/mach/irq.h>
#include <asm/mach/time.h>
#include <asm/system_info.h>
#include <asm/system_misc.h>
#include <asm/traps.h>
#include <asm/unwind.h>
#include <asm/memblock.h>
#include <asm/virt.h>

#include "atags.h"


#if defined(CONFIG_FPE_NWFPE) || defined(CONFIG_FPE_FASTFPE)
char fpe_type[8];

static int __init fpe_setup(char *line)
{
	memcpy(fpe_type, line, 8);
	return 1;
}

__setup("fpe=", fpe_setup);
#endif

extern void paging_init(const struct machine_desc *desc);
extern void early_paging_init(const struct machine_desc *,
			      struct proc_info_list *);
extern void sanity_check_meminfo(void);
extern enum reboot_mode reboot_mode;
extern void setup_dma_zone(const struct machine_desc *desc);

unsigned int processor_id;
EXPORT_SYMBOL(processor_id);
unsigned int __machine_arch_type __read_mostly;
EXPORT_SYMBOL(__machine_arch_type);
unsigned int cacheid __read_mostly;
EXPORT_SYMBOL(cacheid);

unsigned int __atags_pointer __initdata;

unsigned int system_rev;
EXPORT_SYMBOL(system_rev);

unsigned int system_serial_low;
EXPORT_SYMBOL(system_serial_low);

unsigned int system_serial_high;
EXPORT_SYMBOL(system_serial_high);

unsigned int elf_hwcap __read_mostly;
EXPORT_SYMBOL(elf_hwcap);


#ifdef MULTI_CPU
struct processor processor __read_mostly;
#endif
#ifdef MULTI_TLB
struct cpu_tlb_fns cpu_tlb __read_mostly;
#endif
#ifdef MULTI_USER
struct cpu_user_fns cpu_user __read_mostly;
#endif
#ifdef MULTI_CACHE
struct cpu_cache_fns cpu_cache __read_mostly;
#endif
#ifdef CONFIG_OUTER_CACHE
struct outer_cache_fns outer_cache __read_mostly;
EXPORT_SYMBOL(outer_cache);
#endif

/*
 * Cached cpu_architecture() result for use by assembler code.
 * C code should use the cpu_architecture() function instead of accessing this
 * variable directly.
 */
int __cpu_architecture __read_mostly = CPU_ARCH_UNKNOWN;

struct stack {
	u32 irq[3];
	u32 abt[3];
	u32 und[3];
} ____cacheline_aligned;
/*! 
 * L1캐쉬 크기에 맞게 구조체 정렬
 * #define ____cacheline_aligned __ attribute _ ( C_aligned _ (SMP_CACHE_BYTES))) */

#ifndef CONFIG_CPU_V7M
static struct stack stacks[NR_CPUS];
#endif

char elf_platform[ELF_PLATFORM_SIZE];
EXPORT_SYMBOL(elf_platform);

static const char *cpu_name;
static const char *machine_name;
static char __initdata cmd_line[COMMAND_LINE_SIZE];
const struct machine_desc *machine_desc __initdata;

static union { char c[4]; unsigned long l; } endian_test __initdata = { { 'l', '?', '?', 'b' } };
#define ENDIANNESS ((char)endian_test.l)

DEFINE_PER_CPU(struct cpuinfo_arm, cpu_data);

/*
 * Standard memory resources
 */
static struct resource mem_res[] = {
	{
		.name = "Video RAM",
		.start = 0,
		.end = 0,
		.flags = IORESOURCE_MEM
	},
	{
		.name = "Kernel code",
		.start = 0,
		.end = 0,
		.flags = IORESOURCE_MEM
	},
	{
		.name = "Kernel data",
		.start = 0,
		.end = 0,
		.flags = IORESOURCE_MEM
	}
};

#define video_ram   mem_res[0]
#define kernel_code mem_res[1]
#define kernel_data mem_res[2]

static struct resource io_res[] = {
	{
		.name = "reserved",
		.start = 0x3bc,
		.end = 0x3be,
		.flags = IORESOURCE_IO | IORESOURCE_BUSY
	},
	{
		.name = "reserved",
		.start = 0x378,
		.end = 0x37f,
		.flags = IORESOURCE_IO | IORESOURCE_BUSY
	},
	{
		.name = "reserved",
		.start = 0x278,
		.end = 0x27f,
		.flags = IORESOURCE_IO | IORESOURCE_BUSY
	}
};

#define lp0 io_res[0]
#define lp1 io_res[1]
#define lp2 io_res[2]

static const char *proc_arch[] = {
	"undefined/unknown",
	"3",
	"4",
	"4T",
	"5",
	"5T",
	"5TE",
	"5TEJ",
	"6TEJ",
	"7",
	"7M",
	"?(12)",
	"?(13)",
	"?(14)",
	"?(15)",
	"?(16)",
	"?(17)",
};

#ifdef CONFIG_CPU_V7M
static int __get_cpu_architecture(void)
{
	return CPU_ARCH_ARMv7M;
}
#else
static int __get_cpu_architecture(void)
{
	int cpu_arch;

	if ((read_cpuid_id() & 0x0008f000) == 0) {
		cpu_arch = CPU_ARCH_UNKNOWN;
	} else if ((read_cpuid_id() & 0x0008f000) == 0x00007000) {
		cpu_arch = (read_cpuid_id() & (1 << 23)) ? CPU_ARCH_ARMv4T : CPU_ARCH_ARMv3;
	} else if ((read_cpuid_id() & 0x00080000) == 0x00000000) {
		cpu_arch = (read_cpuid_id() >> 16) & 7;
		if (cpu_arch)
			cpu_arch += CPU_ARCH_ARMv3;
	} else if ((read_cpuid_id() & 0x000f0000) == 0x000f0000) {
		unsigned int mmfr0;

		/* Revised CPUID format. Read the Memory Model Feature
		 * Register 0 and check for VMSAv7 or PMSAv7 */
		asm("mrc	p15, 0, %0, c0, c1, 4"
		    : "=r" (mmfr0));
		if ((mmfr0 & 0x0000000f) >= 0x00000003 ||
		    (mmfr0 & 0x000000f0) >= 0x00000030)
			cpu_arch = CPU_ARCH_ARMv7;
		else if ((mmfr0 & 0x0000000f) == 0x00000002 ||
			 (mmfr0 & 0x000000f0) == 0x00000020)
			cpu_arch = CPU_ARCH_ARMv6;
		else
			cpu_arch = CPU_ARCH_UNKNOWN;
	} else
		cpu_arch = CPU_ARCH_UNKNOWN;

	return cpu_arch;
}
#endif

int __pure cpu_architecture(void)
{
	BUG_ON(__cpu_architecture == CPU_ARCH_UNKNOWN);

	return __cpu_architecture;
}

static int cpu_has_aliasing_icache(unsigned int arch)
{
	int aliasing_icache;
	unsigned int id_reg, num_sets, line_size;

	/* PIPT caches never alias. */
	if (icache_is_pipt())
		return 0;

	/* arch specifies the register format */
	switch (arch) {
	case CPU_ARCH_ARMv7:
		asm("mcr	p15, 2, %0, c0, c0, 0 @ set CSSELR"
		    : /* No output operands */
		    : "r" (1));
		isb();
		asm("mrc	p15, 1, %0, c0, c0, 0 @ read CCSIDR"
		    : "=r" (id_reg));
		line_size = 4 << ((id_reg & 0x7) + 2);
		num_sets = ((id_reg >> 13) & 0x7fff) + 1;
		aliasing_icache = (line_size * num_sets) > PAGE_SIZE;
		break;
	case CPU_ARCH_ARMv6:
		aliasing_icache = read_cpuid_cachetype() & (1 << 11);
		break;
	default:
		/* I-cache aliases will be handled by D-cache aliasing code */
		aliasing_icache = 0;
	}

	return aliasing_icache;
}

static void __init cacheid_init(void)
{
	unsigned int arch = cpu_architecture();

	if (arch == CPU_ARCH_ARMv7M) {
		cacheid = 0;
	} else if (arch >= CPU_ARCH_ARMv6) {
		unsigned int cachetype = read_cpuid_cachetype();
		if ((cachetype & (7 << 29)) == 4 << 29) {
			/* ARMv7 register format */
			arch = CPU_ARCH_ARMv7;
			cacheid = CACHEID_VIPT_NONALIASING;
			switch (cachetype & (3 << 14)) {
			case (1 << 14):
				cacheid |= CACHEID_ASID_TAGGED;
				break;
			case (3 << 14):
				cacheid |= CACHEID_PIPT;
				break;
			}
		} else {
			arch = CPU_ARCH_ARMv6;
			if (cachetype & (1 << 23))
				cacheid = CACHEID_VIPT_ALIASING;
			else
				cacheid = CACHEID_VIPT_NONALIASING;
		}
		if (cpu_has_aliasing_icache(arch))
			cacheid |= CACHEID_VIPT_I_ALIASING;
	} else {
		cacheid = CACHEID_VIVT;
	}

	pr_info("CPU: %s data cache, %s instruction cache\n",
		cache_is_vivt() ? "VIVT" :
		cache_is_vipt_aliasing() ? "VIPT aliasing" :
		cache_is_vipt_nonaliasing() ? "PIPT / VIPT nonaliasing" : "unknown",
		cache_is_vivt() ? "VIVT" :
		icache_is_vivt_asid_tagged() ? "VIVT ASID tagged" :
		icache_is_vipt_aliasing() ? "VIPT aliasing" :
		icache_is_pipt() ? "PIPT" :
		cache_is_vipt_nonaliasing() ? "VIPT nonaliasing" : "unknown");
}

/*
 * These functions re-use the assembly code in head.S, which
 * already provide the required functionality.
 */
extern struct proc_info_list *lookup_processor_type(unsigned int);

void __init early_print(const char *str, ...)
{
	extern void printascii(const char *);
	char buf[256];
	/*! char *va_list */
	va_list ap;

	/*!
	 * #define va_start(ap, A)         (void) ((ap) = (((char *) &(A)) + (_bnd (A,_AUPBND))))
	 * #define _bnd(X, bnd)            (((sizeof (X)) + (bnd)) & (~(bnd)))
	 * #define _AUPBND                (sizeof (acpi_native_int) - 1)
	 */
	va_start(ap, str);
	vsnprintf(buf, sizeof(buf), str, ap);
	/*!
	 * #define va_end(ap) (ap = (va_list) NULL)
	 */
	va_end(ap);

#ifdef CONFIG_DEBUG_LL
	printascii(buf);
#endif
	printk("%s", buf);
}

static void __init cpuid_init_hwcaps(void)
{
	unsigned int divide_instrs, vmsa;

	if (cpu_architecture() < CPU_ARCH_ARMv7)
		return;

	divide_instrs = (read_cpuid_ext(CPUID_EXT_ISAR0) & 0x0f000000) >> 24;

	switch (divide_instrs) {
	case 2:
		elf_hwcap |= HWCAP_IDIVA;
	case 1:
		elf_hwcap |= HWCAP_IDIVT;
	}

	/* LPAE implies atomic ldrd/strd instructions */
	vmsa = (read_cpuid_ext(CPUID_EXT_MMFR0) & 0xf) >> 0;
	if (vmsa >= 5)
		elf_hwcap |= HWCAP_LPAE;
}

static void __init feat_v6_fixup(void)
{
	int id = read_cpuid_id();

	if ((id & 0xff0f0000) != 0x41070000)
		return;

	/*
	 * HWCAP_TLS is available only on 1136 r1p0 and later,
	 * see also kuser_get_tls_init.
	 */
	if ((((id >> 4) & 0xfff) == 0xb36) && (((id >> 20) & 3) == 0))
		elf_hwcap &= ~HWCAP_TLS;
}

/*
 * cpu_init - initialise one CPU.
 *
 * cpu_init sets up the per-CPU stacks.
 */
/*!
 * notrace
 * no_instrument_function 으로 지정, 프로파일링에서 제외한다. 프로파일용 툴인 gprof를 통해 프로파일링 가능.
 * notrace 참고 : http://www.iamroot.org/xe/index.php?_filter=search&mid=FreeBoard&search_keyword=%EA%B5%AC%EB%A6%84%EA%B3%BC%EB%B9%84&search_target=nick_name&document_srl=218773
 * finstrument-functions 참고: https://gcc.gnu.org/onlinedocs/gcc-4.5.1/gcc/Code-Gen-Options.html#index-finstrument_002dfunctions-2114
 * 프로파일링 예제: http://balau82.wordpress.com/2010/10/06/trace-and-profile-function-calls-with-gcc/
 */
void notrace cpu_init(void)
{
#ifndef CONFIG_CPU_V7M
	/*!
	 * 사용중인 프로세서 id를 받아와서 stack 설정.
	 * NR_CPUS = 시스템이 지원할 수 있는 최대 CPU 개수
	 */
	unsigned int cpu = smp_processor_id();
	/*!
	 * cpu 모드에 따른 stack의 구분
	 * 참고: 모기향 p.167
	 */
	struct stack *stk = &stacks[cpu];

	if (cpu >= NR_CPUS) {
		pr_crit("CPU%u: bad primary CPU number\n", cpu);
		BUG();
	}

	/*
	 * This only works on resume and secondary cores. For booting on the
	 * boot cpu, smp_prepare_boot_cpu is called after percpu area setup.
	 */
	/*!
	 * cpu번호를 기준으로 자신의 per_cpu_offset을 가져와 CP15 - TPIDRPRW 레지스터에 저장
	 *  - per_cpu란?
	 * cpu마다 가지는 데이터 공간으로 해당 공간을 사용하면 동기화를 위해 lock을 걸 필요가 없어져서
	 * 성능향상을 가져올 수 있다.
	 * 부팅 과정에서는 0으로 만들어져 있고, 추 후 다시 불러질 때 새롭게 cpu_offset을 설정한다.
	 * 부팅과정에서는 조금 뒤 per_cpu_area 설정에서 per_cpu_offset을 새롭게 설정.
	 * percpu 변수 참고: http://nix102guri.blog.me/90098904482
	 * percpu 참고: http://thinkiii.blogspot.kr/2014/05/a-brief-introduction-to-per-cpu.html
	 * percpu 참고: http://www.iamroot.org/xe/Kernel_10_ARM/184082
	 * percpu 참고: http://studyfoss.egloos.com/5375570
	 *
	 */
	set_my_cpu_offset(per_cpu_offset(cpu));

	/*! 
	 * #define cpu_proc_init	__glue(CPU_NAME,_proc_init)
	 * -> cpu_v7_proc_init
	 * mv pc, lr;
	 */
	cpu_proc_init();

	/*
	 * Define the placement constraint for the inline asm directive below.
	 * In Thumb-2, msr with an immediate value is not allowed.
	 */
#ifdef CONFIG_THUMB2_KERNEL
#define PLC	"r"
#else
#define PLC	"I"
#endif

	/*
	 * setup stacks for re-entrant exception handlers
	 */
	/*!
	 * IRQ 모드일 때의 스택 포인터는 irq[O],
	 * ABORT 모드일 때의 스택 포인터는 abt[O] , UND(undefined) 모드일 때의 스택 포인터는
	 * und[O]으로 설정을 해주고， SVC 모드로 복귀한 다음에 반환된다.
	 * 여기서 스택안의 모드별 스택이 3개만 선언된 이유는 모드별로 가지는 자신만의 레지스터가 3개이기 때문에
	 * irq[3], abr[3], und[3]으로 잡혀있는 것 같습니다.
	 * 뱅크 레지스터 그림 참고.
	 */
	/*! 
	 * cpsr_c cpsr의 하위 8bit 
	 ***
	 * PLC의 차이: thumb모드일 경우 32비트의 상수값을 한번에 옮길 수 없기 때문에 r로 지정하여 두번에 나눠 넣어준다.
	 ***
	 * r = register로 대체할 필요가 있는 변수
	 * I = 상수값들(thumb의 경우 16비트 상수만 가능)
	 * cc = 값이 변하는 레지스터 명시
	 */
	__asm__ (
	"msr	cpsr_c, %1\n\t"
	"add	r14, %0, %2\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %3\n\t"
	"add	r14, %0, %4\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %5\n\t"
	"add	r14, %0, %6\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %7"
	    :
	    : "r" (stk),				/*! %0 */
	      PLC (PSR_F_BIT | PSR_I_BIT | IRQ_MODE),	/*! %1 */
	      "I" (offsetof(struct stack, irq[0])),	/*! %2 */
	      PLC (PSR_F_BIT | PSR_I_BIT | ABT_MODE),	/*! %3 */
	      "I" (offsetof(struct stack, abt[0])),	/*! %4 */
	      PLC (PSR_F_BIT | PSR_I_BIT | UND_MODE),	/*! %5 */
	      "I" (offsetof(struct stack, und[0])),	/*! %6 */
	      PLC (PSR_F_BIT | PSR_I_BIT | SVC_MODE)	/*! %7 */
	    : "r14");					/* r14 ->lr */
#endif
}

/*! ex) array[3] = { [0 ... 2] = 1}; -> 0 ~ 2 배열을 모두 1로 초기화
 *  http://gcc.gnu.org/onlinedocs/gcc-4.1.2/gcc/Designated-Inits.html  
 *  CONFIG_NR_CPUS=8 (exynos_defconfig)
 *  MPIDR_INVALID = 0xFF000000
 */
u32 __cpu_logical_map[NR_CPUS] = { [0 ... NR_CPUS-1] = MPIDR_INVALID };

void __init smp_setup_processor_id(void)
{
	int i;
    /*! is_smp = 1 */
    /*! MPIDR_HWID_BITMASK = 하위 24bit 만 체크.  */
	u32 mpidr = is_smp() ? read_cpuid_mpidr() & MPIDR_HWID_BITMASK : 0;
    /*! mpidr 레지스터에서 CPU ID Read.(0x0, 0x01, 0x02, 0x03 중 하나)  */
	u32 cpu = MPIDR_AFFINITY_LEVEL(mpidr, 0);

    /*! __cpu_logical_map[0] = cpu   
     * 현재 core(boot core) 의 CPU ID
     */
	cpu_logical_map(0) = cpu;
    /*! nr_cpu_ids = 8  */
    /*! example. 아래 for 문의 결과로 변경된 cpu_logical_map 배열 값
     * ( cpu_logical_map 가 4 배열일때의 예)
     * 그림 1)
     *         0   1   2   3
     *       +---------------+
     *       |   |   |   |   |
     *       +---------------+
     * cpu=0  [ 0  1  2  3]
     * cpu=2  [ 2  1  0  3]  
     */
	for (i = 1; i < nr_cpu_ids; ++i)
		cpu_logical_map(i) = i == cpu ? 0 : i;

	/*
	 * clear __my_cpu_offset on boot CPU to avoid hang caused by
	 * using percpu variable early, for example, lockdep will
	 * access percpu variable inside lock_release
	 */
    /*! 현재 쓰지 않는 TPIDRPRW 레지스터를 percpu 용도로 사용 
     * 그림 1 참조 cpu_logical_map에서 자신의 index를 offset으로 설정(?) 
     */
	set_my_cpu_offset(0);

	pr_info("Booting Linux on physical CPU 0x%x\n", mpidr);
}

struct mpidr_hash mpidr_hash;
#ifdef CONFIG_SMP
/**
 * smp_build_mpidr_hash - Pre-compute shifts required at each affinity
 *			  level in order to build a linear index from an
 *			  MPIDR value. Resulting algorithm is a collision
 *			  free hash carried out through shifting and ORing
 */
static void __init smp_build_mpidr_hash(void)
{
	u32 i, affinity;
	u32 fs[3], bits[3], ls, mask = 0;
	/*
	 * Pre-scan the list of MPIDRS and filter out bits that do
	 * not contribute to affinity levels, ie they never toggle.
	 */
	for_each_possible_cpu(i)
		mask |= (cpu_logical_map(i) ^ cpu_logical_map(0));
	pr_debug("mask of set bits 0x%x\n", mask);
	/*
	 * Find and stash the last and first bit set at all affinity levels to
	 * check how many bits are required to represent them.
	 */
	for (i = 0; i < 3; i++) {
		affinity = MPIDR_AFFINITY_LEVEL(mask, i);
		/*
		 * Find the MSB bit and LSB bits position
		 * to determine how many bits are required
		 * to express the affinity level.
		 */
		ls = fls(affinity);
		fs[i] = affinity ? ffs(affinity) - 1 : 0;
		bits[i] = ls - fs[i];
	}
	/*
	 * An index can be created from the MPIDR by isolating the
	 * significant bits at each affinity level and by shifting
	 * them in order to compress the 24 bits values space to a
	 * compressed set of values. This is equivalent to hashing
	 * the MPIDR through shifting and ORing. It is a collision free
	 * hash though not minimal since some levels might contain a number
	 * of CPUs that is not an exact power of 2 and their bit
	 * representation might contain holes, eg MPIDR[7:0] = {0x2, 0x80}.
	 */
	mpidr_hash.shift_aff[0] = fs[0];
	mpidr_hash.shift_aff[1] = MPIDR_LEVEL_BITS + fs[1] - bits[0];
	mpidr_hash.shift_aff[2] = 2*MPIDR_LEVEL_BITS + fs[2] -
						(bits[1] + bits[0]);
	mpidr_hash.mask = mask;
	mpidr_hash.bits = bits[2] + bits[1] + bits[0];
	pr_debug("MPIDR hash: aff0[%u] aff1[%u] aff2[%u] mask[0x%x] bits[%u]\n",
				mpidr_hash.shift_aff[0],
				mpidr_hash.shift_aff[1],
				mpidr_hash.shift_aff[2],
				mpidr_hash.mask,
				mpidr_hash.bits);
	/*
	 * 4x is an arbitrary value used to warn on a hash table much bigger
	 * than expected on most systems.
	 */
	if (mpidr_hash_size() > 4 * num_possible_cpus())
		pr_warn("Large number of MPIDR hash buckets detected\n");
	sync_cache_w(&mpidr_hash);
}
#endif

static void __init setup_processor(void)
{
	struct proc_info_list *list;

	/*
	 * locate processor in the list of supported processor
	 * types.  The linker builds this table for us from the
	 * entries in arch/arm/mm/proc-*.S
	 */
	/*!
	 * arch/arm/kernel/head-common.S
	 * 프로세서 proc_info_list 초기화
	 * arch/arm/mm/proc-v7.S의  __proc_info_begin 와 __proc_info_end 사이의 table entry 참고
	 */
	list = lookup_processor_type(read_cpuid_id());
	if (!list) {
		pr_err("CPU configuration botched (ID %08x), unable to continue.\n",
		       read_cpuid_id());
		while (1);
	}

	cpu_name = list->cpu_name;
	/*! cpuid를 읽어 아키텍처 번호 알려줌 */
	__cpu_architecture = __get_cpu_architecture();

#ifdef MULTI_CPU
	processor = *list->proc;
#endif
#ifdef MULTI_TLB
	cpu_tlb = *list->tlb;
#endif
#ifdef MULTI_USER
	cpu_user = *list->user;
#endif
#ifdef MULTI_CACHE
	cpu_cache = *list->cache;
#endif

	pr_info("CPU: %s [%08x] revision %d (ARMv%s), cr=%08lx\n",
		cpu_name, read_cpuid_id(), read_cpuid_id() & 15,
		proc_arch[cpu_architecture()], cr_alignment);

	/*! snprintf(버퍼, 버퍼사이즈, 포맷, ...) */
	/*! init_utsname->macine에 아키텍처 이름과 엔디안 기록  */
	snprintf(init_utsname()->machine, __NEW_UTS_LEN + 1, "%s%c",
		 list->arch_name, ENDIANNESS);
	/*! elf_platform 에 elf_name과 엔디안 기록 */
	snprintf(elf_platform, ELF_PLATFORM_SIZE, "%s%c",
		 list->elf_name, ENDIANNESS);
	elf_hwcap = list->elf_hwcap;

	/*!
	 * hwcap(Hardware Capability)은 말 그대로 하드웨어 지원사항을 나타내는 것입니다.
	 *
	 * divider는 정수형 나눗셈을 지원하는 명령어로, 하드웨어적으로 divider를 지원하는 것인지 체크하는 것입니다.
	 * 보통 하드웨어 divider는 10사이클 정도가 걸리며, 소프트웨어는 100사이클 이상 걸린다고 보면 됩니다.
	 */
	cpuid_init_hwcaps();

#ifndef CONFIG_ARM_THUMB
	elf_hwcap &= ~(HWCAP_THUMB | HWCAP_IDIVT);
#endif

	/*! 에러 처리 */
	erratum_a15_798181_init();
	/*! v6 관련 에러 처리 */
	feat_v6_fixup();

	/*! 캐쉬타입확인 후 출력  */
	cacheid_init();
	/*! percpu 셋팅 및 각 모드에 맞는 스택 주소 설정 */
	cpu_init();
}

void __init dump_machine_table(void)
{
	const struct machine_desc *p;

	early_print("Available machine support:\n\nID (hex)\tNAME\n");
	for_each_machine_desc(p)
		early_print("%08x\t%s\n", p->nr, p->name);

	early_print("\nPlease check your kernel config and/or bootloader.\n");

	while (true)
		/* can't use cpu_relax() here as it may require MMU setup */;
}

int __init arm_add_memory(u64 start, u64 size)
{
	/*! 
	 * bank: 접근 속도가 같은 메모리의 집합 
	 * meminfo는 struct meminfo 타입의 전역 변수로, 메모리 초기화 함수에서 사용되는 설정 정보를 가지고 있다.
	 * struct meminfo {
	 *	int nr_banks;
	 *	struct membank bank[NR_BANKS];
	 * };
	 * NR_BANKS = 8
	 */
	struct membank *bank = &meminfo.bank[meminfo.nr_banks];
	u64 aligned_start;

	if (meminfo.nr_banks >= NR_BANKS) {
		pr_crit("NR_BANKS too low, ignoring memory at 0x%08llx\n",
			(long long)start);
		return -EINVAL;
	}

	/*
	 * Ensure that start/size are aligned to a page boundary.
	 * Size is appropriately rounded down, start is rounded up.
	 */
	/*!
	 * #define PAGE_MASK (~((1 << PAGE_SHIFT) - 1))
	 * PAGE_MASK = ~((1 << 12) - 1) = 0xffff_f000
	 * size = size - start & 0x0000_0fff
	 *  - start = base = dt_mem_next_cell(dt_root_addr_cells, &reg);
	 *  - size = size = dt_mem_next_cell(dt_root_size_cells, &reg);
	 ****
	 * ex) 0x20000000 0x80000000
	 * size = size - start(0x0000_0fff mask)
	 * size = 0x80000000 - 0x00000000 = 0x80000000
	 */
	size -= start & ~PAGE_MASK;
	/*!
	 * 0   4096     8k   12k 
	 * |-----|--&&&-|-----|
	 * PAGE_ALIGN -->
	 * |-----|------|&&&--|
	 *
	 * #define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE) 
	 * #define ALIGN(x, a) __ALIGN_KERNEL((x), (a))
	 * #define __ALIGN_KERNEL(x, a)        __ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
	 * #define __ALIGN_KERNEL_MASK(x, mask)    (((x) + (mask)) & ~(mask)) : 올림 연산
	 * = (x + 0x0fff) & 0xf000
	 *
	 * 즉 4096 단위 얼라인
	 ***
	 * aligned_start = 0x20000000
	 * size = 0x80000000
	 */
	aligned_start = PAGE_ALIGN(start);

#ifndef CONFIG_ARCH_PHYS_ADDR_T_64BIT
	/*! 
	 * ULONG_MAX = 0xffff_ffff
	 * aligned_start 가 32bit 넘어가는지 체크
	 *
	 */
	if (aligned_start > ULONG_MAX) {
		pr_crit("Ignoring memory at 0x%08llx outside 32-bit physical address space\n",
			(long long)start);
		return -EINVAL;
	}
	
	/*!
	 * aligned_start + size 가 32bit 넘어가는지 체크
	 */
	if (aligned_start + size > ULONG_MAX) {
		pr_crit("Truncating memory at 0x%08llx to fit in 32-bit physical address space\n",
			(long long)start);
		/*
		 * To ensure bank->start + bank->size is representable in
		 * 32 bits, we use ULONG_MAX as the upper limit rather than 4GB.
		 * This means we lose a page after masking.
		 */
		/*!
		 * size가 32bit를 넘어가면 넘어가는 부분 버림
		 */
		size = ULONG_MAX - aligned_start;
	}
#endif

	/*!
	 * PHYS_OFFSET = vmlinux 끝 
	 */
	if (aligned_start < PHYS_OFFSET) {
		if (aligned_start + size <= PHYS_OFFSET) {
			/*!
			 * bank해둘려는 범위가 vmlinux안쪽이여서 뱅크안하고 지나감
			 *
			 * as = aligned_start
			 *              PHYS_OFFSET
			 * |----------------|
			 *         |------|
			 *	   as   as+size
			 */
			pr_info("Ignoring memory below PHYS_OFFSET: 0x%08llx-0x%08llx\n",
				aligned_start, aligned_start + size);
			return -EINVAL;
		}

		pr_info("Ignoring memory below PHYS_OFFSET: 0x%08llx-0x%08llx\n",
			aligned_start, (u64)PHYS_OFFSET);
		
		/*!
		 * 뱅크할려는 범위가 vmlinux 범위를 넘어갈 경우 넘어가는 부분만 뱅크 구성
		 *
		 * as = aligned_start
		 *             PHYS_OFFSET
		 * |---------------| - vmlinux 범위
		 *       |--------------|
		 *      as            as+size
		 * ->
		 *                 |----|
		 *                as  as+size
		 */
		size -= PHYS_OFFSET - aligned_start;
		aligned_start = PHYS_OFFSET;
	}

	/*!
	 * bank 구성
	 */
	bank->start = aligned_start;
	bank->size = size & ~(phys_addr_t)(PAGE_SIZE - 1);

	/*
	 * Check whether this memory region has non-zero size or
	 * invalid node number.
	 */
	if (bank->size == 0)
		return -EINVAL;

	meminfo.nr_banks++;
	return 0;
}

/*
 * Pick out the memory size.  We look for mem=size@start,
 * where start and size are "size[KkMm]"
 */
static int __init early_mem(char *p)
{
	static int usermem __initdata = 0;
	u64 size;
	u64 start;
	char *endp;

	/*
	 * If the user specifies memory size, we
	 * blow away any automatically generated
	 * size.
	 */
	if (usermem == 0) {
		usermem = 1;
		meminfo.nr_banks = 0;
	}

	start = PHYS_OFFSET;
	size  = memparse(p, &endp);
	if (*endp == '@')
		start = memparse(endp + 1, NULL);

	arm_add_memory(start, size);

	return 0;
}
early_param("mem", early_mem);

/*! 
 * request_standard_resources()
 * - 메모리 블럭 트리 구성
 *   1. memblock.memory 영역들(system mem) iomem_resource(PCI MEM)의 자식으로 넣어주고,
 *   2. kernel_code, kernel_data영영을 해당하는 System mem 영역에 넣어준다.
 *   3. video_ram 영역을 iomem_resource영역의 자식으로 넣어준다.
 *   4. mdesc의 lp0, lp1, lp2 가 셋팅 되어 있을 경우 ioport_resource의 자식으로 넣어준다.
 */
static void __init request_standard_resources(const struct machine_desc *mdesc)
{
	struct memblock_region *region;
	/*! include/linux/ioport.h */
	struct resource *res;

	kernel_code.start   = virt_to_phys(_text);
	kernel_code.end     = virt_to_phys(_etext - 1);
	kernel_data.start   = virt_to_phys(_sdata);
	kernel_data.end     = virt_to_phys(_end - 1);

	/*!
	 * 각 memory block 별로 resource memory 할당 후
	 * 각 영역에 대한 정보를 셋팅
	 */
	/*!
	 * #define for_each_memblock(memblock_type, region)					\
	 *	for (region = memblock.memblock_type.regions;					\
	 *		region < (memblock.memblock_type.regions + memblock.memblock_type.cnt);	\
	 *		region++)
	 */
	for_each_memblock(memory, region) {
		res = memblock_virt_alloc(sizeof(*res), 0);
		res->name  = "System RAM";
		res->start = __pfn_to_phys(memblock_region_memory_base_pfn(region));
		res->end = __pfn_to_phys(memblock_region_memory_end_pfn(region)) - 1;
		res->flags = IORESOURCE_MEM | IORESOURCE_BUSY;

		/*! 
		 * iomem_resource - PCI_mem resource(bank resource)
		 */
		request_resource(&iomem_resource, res);

		/*! kernel code, kernel data가 해당되는 system_ram 영역의 자식으로 넣음 */
		if (kernel_code.start >= res->start &&
		    kernel_code.end <= res->end)
			request_resource(res, &kernel_code);
		if (kernel_data.start >= res->start &&
		    kernel_data.end <= res->end)
			request_resource(res, &kernel_data);
	}

	/*! Video RAM memory 영역을 iomem_resource의 자식으로 등록 */
	if (mdesc->video_start) {
		video_ram.start = mdesc->video_start;
		video_ram.end   = mdesc->video_end;
		request_resource(&iomem_resource, &video_ram);
	}

	/*
	 * Some machines don't have the possibility of ever
	 * possessing lp0, lp1 or lp2
	 */
	if (mdesc->reserve_lp0)
		request_resource(&ioport_resource, &lp0);
	if (mdesc->reserve_lp1)
		request_resource(&ioport_resource, &lp1);
	if (mdesc->reserve_lp2)
		request_resource(&ioport_resource, &lp2);
}

#if defined(CONFIG_VGA_CONSOLE) || defined(CONFIG_DUMMY_CONSOLE)
struct screen_info screen_info = {
 .orig_video_lines	= 30,
 .orig_video_cols	= 80,
 .orig_video_mode	= 0,
 .orig_video_ega_bx	= 0,
 .orig_video_isVGA	= 1,
 .orig_video_points	= 8
};
#endif

static int __init customize_machine(void)
{
	/*
	 * customizes platform devices, or adds new ones
	 * On DT based machines, we fall back to populating the
	 * machine from the device tree, if no callback is provided,
	 * otherwise we would always need an init_machine callback.
	 */
	if (machine_desc->init_machine)
		machine_desc->init_machine();
#ifdef CONFIG_OF
	else
		of_platform_populate(NULL, of_default_bus_match_table,
					NULL, NULL);
#endif
	return 0;
}
arch_initcall(customize_machine);

static int __init init_machine_late(void)
{
	if (machine_desc->init_late)
		machine_desc->init_late();
	return 0;
}
late_initcall(init_machine_late);

#ifdef CONFIG_KEXEC
static inline unsigned long long get_total_mem(void)
{
	unsigned long total;

	total = max_low_pfn - min_low_pfn;
	return total << PAGE_SHIFT;
}

/**
 * reserve_crashkernel() - reserves memory are for crash kernel
 *
 * This function reserves memory area given in "crashkernel=" kernel command
 * line parameter. The memory reserved is used by a dump capture kernel when
 * primary kernel is crashing.
 */
static void __init reserve_crashkernel(void)
{
	unsigned long long crash_size, crash_base;
	unsigned long long total_mem;
	int ret;

	total_mem = get_total_mem();
	ret = parse_crashkernel(boot_command_line, total_mem,
				&crash_size, &crash_base);
	if (ret)
		return;

	ret = memblock_reserve(crash_base, crash_size);
	if (ret < 0) {
		pr_warn("crashkernel reservation failed - memory is in use (0x%lx)\n",
			(unsigned long)crash_base);
		return;
	}

	pr_info("Reserving %ldMB of memory at %ldMB for crashkernel (System RAM: %ldMB)\n",
		(unsigned long)(crash_size >> 20),
		(unsigned long)(crash_base >> 20),
		(unsigned long)(total_mem >> 20));

	crashk_res.start = crash_base;
	crashk_res.end = crash_base + crash_size - 1;
	insert_resource(&iomem_resource, &crashk_res);
}
#else
static inline void reserve_crashkernel(void) {}
#endif /* CONFIG_KEXEC */

static int __init meminfo_cmp(const void *_a, const void *_b)
{
	const struct membank *a = _a, *b = _b;
	long cmp = bank_pfn_start(a) - bank_pfn_start(b);
	return cmp < 0 ? -1 : cmp > 0 ? 1 : 0;
}

void __init hyp_mode_check(void)
{
#ifdef CONFIG_ARM_VIRT_EXT
	sync_boot_mode();

	if (is_hyp_mode_available()) {
		pr_info("CPU: All CPU(s) started in HYP mode.\n");
		pr_info("CPU: Virtualization extensions available.\n");
	} else if (is_hyp_mode_mismatched()) {
		pr_warn("CPU: WARNING: CPU(s) started in wrong/inconsistent modes (primary CPU mode 0x%x)\n",
			__boot_cpu_mode & MODE_MASK);
		pr_warn("CPU: This may indicate a broken bootloader or firmware.\n");
	} else
		pr_info("CPU: All CPU(s) started in SVC mode.\n");
#endif
}

void __init setup_arch(char **cmdline_p)
{
	const struct machine_desc *mdesc;
	
	/*! 
	 * lookup_processor_type 으로 받아온 proc_info_list를 통해 구조체들 초기화 
	 * cpu_name, processor, cpu_tlb, cpu_user, cpu_cache 
	 */
	setup_processor();
	/*!
	 * fdt에서 chosen, root, memory 노드들 초기화
	 * 머신 정보 구조체(machine_desc) 가져오기
	 */
	mdesc = setup_machine_fdt(__atags_pointer);
	/*!
	 * setup_machine_fdt()에서 fdt를 사용하지 않는다면 NULL 리턴
	 * __machine_arch_type -> compressed/misc.c 의 decompress_kernel 에서 초기화 해줌
	 */
	if (!mdesc)
		mdesc = setup_machine_tags(__atags_pointer, __machine_arch_type);
	machine_desc = mdesc;
	machine_name = mdesc->name;

	/*!
	 * reboot_mode 모드 셋팅
	 * reboot_mode에 대해 찾아보기( 10차 25주차 )
	 * 실제 하드웨어 디자인 할때 리셋방법이 여러가지 방법이 존재합니다.
	 *
	 * HARD는 hardware적으로 reset 시그널이 있고, 소프트리셋 시그널이 따로 있습니다.
	 * 결국 HARD reset은 칩 전체 reset, SOFT는 칩중 일부분만 reset입니다.
	 * SOFT의 경우 이렇게 하는 이유는, 일부 IP의 경우 reset을 안하는 경우가 있어서 그렇습니다.
	 *
	 * - REBOOT_COLD: 일반적으로 power on/off
	 * - REBOOT_HARD: chip에 연결된 HW reset (PC에서 reset 버튼)
	 * - REBOOT_WARM: chip에 연결된 HW reset (PLL, test logic 등의 일부 HW를 reset에서 제외, 주로 watchdog과 연결)
	 * - REBOOT_SOFT: software에 의한 reset (ctrl+alt+reset 키)
	 * - REBOOT_GPIO: GPIO signal에 의한 reset
	 *
	 * 개념적으로는 구분이 있으나 실제 chip에서 SOFT, WARM등의 경계가 모호하다.
	 */
	if (mdesc->reboot_mode != REBOOT_HARD)
		reboot_mode = mdesc->reboot_mode;

	init_mm.start_code = (unsigned long) _text;
	init_mm.end_code   = (unsigned long) _etext;
	init_mm.end_data   = (unsigned long) _edata;
	init_mm.brk	   = (unsigned long) _end;

	/* populate cmd_line too for later use, preserving boot_command_line */
	strlcpy(cmd_line, boot_command_line, COMMAND_LINE_SIZE);
	*cmdline_p = cmd_line;

	/*!
	 * do_early_param을 위한 코드지만, 엑시노스 5420의 경우 do_early_param가 해주는 일이 없음.
	 */
	parse_early_param();

	/*!
	 * lib/sort.c
	 * meminfo sort
	 * sort(정렬할 배열 시작 주소(뱅크 배열), 정렬할 크기(만들어진 뱅크 수),
	 *        배열 하나의 크기(뱅크 크기), 비교 함수, 스왑 함수)
	 */
	sort(&meminfo.bank, meminfo.nr_banks, sizeof(meminfo.bank[0]), meminfo_cmp, NULL);

	/*!
	 * exynos에서 mdesc->init_meminfo() 가 정의되지 않았기 때문에 해주는 일이 없음.
	 */
	early_paging_init(mdesc, lookup_processor_type(read_cpuid_id()));
	/*!
	 * linux_memory_관리
	 *
	 * 커널 영역과 사용자 영역은 1GB와 3GB로 나누어지는데,
	 * 이 경우 1GB의 공간만 직접 접근할 수 있고 그 이상의
	 * 공간은 직접 접근할 수가 없다. 이 때문에 128MB의 공간을 
	 * 896MB ~ 1024MB 사이에 두고 1GB 이상의 영역을 매핑하는
	 * 방식으로 사용하고 있다. 이 896MB ~ 4GB에 해당하는 영역을 
	 * 하이 메모리 (high memory) 라고한다.
	 *
	 * zone = node를 구간별로 나누어 관리
	 * zone_highmem = 896MB 이상의 메모리 영역
	 * zone_nomal = 16MB부터 896MB 까지의 메모리 영역 
	 * zone_dma = ISA 장치를 위한 16MB 아래의 메모리 영역
	 */
	/*!
	 * dma_limit 설정
	 */
	setup_dma_zone(mdesc);

	/*!
	 * meminfo 구조체에 값이 제대로 들어 있는지 정상성 (sanity) 검사를 수행하는 작업이 이루어진다.
	 */
	/*! 20141220, study start */
	/*!
	 * low memory(memblock) limit 설정
	 */
	sanity_check_meminfo();
	/*!
	 * memblock 구조체 초기화
	 *  - memory: 뱅크 저장
	 *  - reserved: 커널이미지, 페이지테이블, DTB, CMA, initrd 저장
	 */
	arm_memblock_init(&meminfo, mdesc);

	/*! 20150117, study start */
	/*! paging_init */
	paging_init(mdesc);
	/*! 20150523, study end */
	/*! 20150530, study start */
	request_standard_resources(mdesc);

	if (mdesc->restart)
		arm_pm_restart = mdesc->restart;
	/*! 20150530, study end */
	unflatten_device_tree();

	arm_dt_init_cpu_maps();
	psci_init();
#ifdef CONFIG_SMP
	if (is_smp()) {
		if (!mdesc->smp_init || !mdesc->smp_init()) {
			if (psci_smp_available())
				smp_set_ops(&psci_smp_ops);
			else if (mdesc->smp)
				smp_set_ops(mdesc->smp);
		}
		smp_init_cpus();
		smp_build_mpidr_hash();
	}
#endif

	if (!is_smp())
		hyp_mode_check();

	reserve_crashkernel();

#ifdef CONFIG_MULTI_IRQ_HANDLER
	handle_arch_irq = mdesc->handle_irq;
#endif

#ifdef CONFIG_VT
#if defined(CONFIG_VGA_CONSOLE)
	conswitchp = &vga_con;
#elif defined(CONFIG_DUMMY_CONSOLE)
	conswitchp = &dummy_con;
#endif
#endif

	if (mdesc->init_early)
		mdesc->init_early();
}


static int __init topology_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct cpuinfo_arm *cpuinfo = &per_cpu(cpu_data, cpu);
		cpuinfo->cpu.hotpluggable = 1;
		register_cpu(&cpuinfo->cpu, cpu);
	}

	return 0;
}
subsys_initcall(topology_init);

#ifdef CONFIG_HAVE_PROC_CPU
static int __init proc_cpu_init(void)
{
	struct proc_dir_entry *res;

	res = proc_mkdir("cpu", NULL);
	if (!res)
		return -ENOMEM;
	return 0;
}
fs_initcall(proc_cpu_init);
#endif

static const char *hwcap_str[] = {
	"swp",
	"half",
	"thumb",
	"26bit",
	"fastmult",
	"fpa",
	"vfp",
	"edsp",
	"java",
	"iwmmxt",
	"crunch",
	"thumbee",
	"neon",
	"vfpv3",
	"vfpv3d16",
	"tls",
	"vfpv4",
	"idiva",
	"idivt",
	"vfpd32",
	"lpae",
	"evtstrm",
	NULL
};

static int c_show(struct seq_file *m, void *v)
{
	int i, j;
	u32 cpuid;

	for_each_online_cpu(i) {
		/*
		 * glibc reads /proc/cpuinfo to determine the number of
		 * online processors, looking for lines beginning with
		 * "processor".  Give glibc what it expects.
		 */
		seq_printf(m, "processor\t: %d\n", i);
		cpuid = is_smp() ? per_cpu(cpu_data, i).cpuid : read_cpuid_id();
		seq_printf(m, "model name\t: %s rev %d (%s)\n",
			   cpu_name, cpuid & 15, elf_platform);

		/* dump out the processor features */
		seq_puts(m, "Features\t: ");

		for (j = 0; hwcap_str[j]; j++)
			if (elf_hwcap & (1 << j))
				seq_printf(m, "%s ", hwcap_str[j]);

		seq_printf(m, "\nCPU implementer\t: 0x%02x\n", cpuid >> 24);
		seq_printf(m, "CPU architecture: %s\n",
			   proc_arch[cpu_architecture()]);

		if ((cpuid & 0x0008f000) == 0x00000000) {
			/* pre-ARM7 */
			seq_printf(m, "CPU part\t: %07x\n", cpuid >> 4);
		} else {
			if ((cpuid & 0x0008f000) == 0x00007000) {
				/* ARM7 */
				seq_printf(m, "CPU variant\t: 0x%02x\n",
					   (cpuid >> 16) & 127);
			} else {
				/* post-ARM7 */
				seq_printf(m, "CPU variant\t: 0x%x\n",
					   (cpuid >> 20) & 15);
			}
			seq_printf(m, "CPU part\t: 0x%03x\n",
				   (cpuid >> 4) & 0xfff);
		}
		seq_printf(m, "CPU revision\t: %d\n\n", cpuid & 15);
	}

	seq_printf(m, "Hardware\t: %s\n", machine_name);
	seq_printf(m, "Revision\t: %04x\n", system_rev);
	seq_printf(m, "Serial\t\t: %08x%08x\n",
		   system_serial_high, system_serial_low);

	return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	return *pos < 1 ? (void *)1 : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static void c_stop(struct seq_file *m, void *v)
{
}

const struct seq_operations cpuinfo_op = {
	.start	= c_start,
	.next	= c_next,
	.stop	= c_stop,
	.show	= c_show
};

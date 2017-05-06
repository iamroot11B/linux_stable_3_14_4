/*
 *  linux/init/main.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  GK 2/5/95  -  Changed to support mounting root fs via NFS
 *  Added initrd & change_root: Werner Almesberger & Hans Lermen, Feb '96
 *  Moan early if gcc is old, avoiding bogus kernels - Paul Gortmaker, May '96
 *  Simplified starting of init:  Michael A. Griffith <grif@acm.org>
 */

#define DEBUG		/* Enable initcall_debug */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/stackprotector.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/bootmem.h>
#include <linux/acpi.h>
#include <linux/tty.h>
#include <linux/percpu.h>
#include <linux/kmod.h>
#include <linux/vmalloc.h>
#include <linux/kernel_stat.h>
#include <linux/start_kernel.h>
#include <linux/security.h>
#include <linux/smp.h>
#include <linux/profile.h>
#include <linux/rcupdate.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/writeback.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/cgroup.h>
#include <linux/efi.h>
#include <linux/tick.h>
#include <linux/interrupt.h>
#include <linux/taskstats_kern.h>
#include <linux/delayacct.h>
#include <linux/unistd.h>
#include <linux/rmap.h>
#include <linux/mempolicy.h>
#include <linux/key.h>
#include <linux/buffer_head.h>
#include <linux/page_cgroup.h>
#include <linux/debug_locks.h>
#include <linux/debugobjects.h>
#include <linux/lockdep.h>
#include <linux/kmemleak.h>
#include <linux/pid_namespace.h>
#include <linux/device.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/idr.h>
#include <linux/kgdb.h>
#include <linux/ftrace.h>
#include <linux/async.h>
#include <linux/kmemcheck.h>
#include <linux/sfi.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/perf_event.h>
#include <linux/file.h>
#include <linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/sched_clock.h>
#include <linux/context_tracking.h>
#include <linux/random.h>

#include <asm/io.h>
#include <asm/bugs.h>
#include <asm/setup.h>
#include <asm/sections.h>
#include <asm/cacheflush.h>

#ifdef CONFIG_X86_LOCAL_APIC
#include <asm/smp.h>
#endif

static int kernel_init(void *);

extern void init_IRQ(void);
extern void fork_init(unsigned long);
extern void radix_tree_init(void);
#ifndef CONFIG_DEBUG_RODATA
static inline void mark_rodata_ro(void) { }
#endif

/*
 * Debug helper: via this flag we know that we are in 'early bootup code'
 * where only the boot processor is running with IRQ disabled.  This means
 * two things - IRQ must not be enabled before the flag is cleared and some
 * operations which are not allowed with IRQ disabled are allowed while the
 * flag is set.
 */
bool early_boot_irqs_disabled __read_mostly;

enum system_states system_state __read_mostly;
EXPORT_SYMBOL(system_state);

/*
 * Boot command-line arguments
 */
#define MAX_INIT_ARGS CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS CONFIG_INIT_ENV_ARG_LIMIT

extern void time_init(void);
/* Default late time init is NULL. archs can override this later. */
void (*__initdata late_time_init)(void);

/* Untouched command line saved by arch-specific code. */
/*!
 * boot_command_line 초기화 시점
 * - start_kernel/setup_arch/setup_machine_fdt/early_init_dt_scan/early_init_dt_scan_chosen 에서
 *	dts 파일 안에 chosen 안의 bootarg에 들어있는 값으로 초기화
 * - else(문제 발생 시)
 *   - setup_arch -> setup_machine_tags에서 (setup_machine_fdt 함수 실패시)
 */
char __initdata boot_command_line[COMMAND_LINE_SIZE];

/*!
 * saved_command_line, initcall_command_line, static_command_line 초기화
 * 1. start_kernel->setup_arch->setup_command_line 에서 초기화
 */
/* Untouched saved command line (eg. for /proc) */
char *saved_command_line;
/* Command line for parameter parsing */
static char *static_command_line;
/* Command line for per-initcall parameter parsing */
static char *initcall_command_line;

static char *execute_command;
static char *ramdisk_execute_command;

/*
 * Used to generate warnings if static_key manipulation functions are used
 * before jump_label_init is called.
 */
bool static_key_initialized __read_mostly = false;
EXPORT_SYMBOL_GPL(static_key_initialized);

/*
 * If set, this is an indication to the drivers that reset the underlying
 * device before going ahead with the initialization otherwise driver might
 * rely on the BIOS and skip the reset operation.
 *
 * This is useful if kernel is booting in an unreliable environment.
 * For ex. kdump situaiton where previous kernel has crashed, BIOS has been
 * skipped and devices will be in unknown state.
 */
unsigned int reset_devices;
EXPORT_SYMBOL(reset_devices);

static int __init set_reset_devices(char *str)
{
	reset_devices = 1;
	return 1;
}

__setup("reset_devices", set_reset_devices);

static const char * argv_init[MAX_INIT_ARGS+2] = { "init", NULL, };
const char * envp_init[MAX_INIT_ENVS+2] = { "HOME=/", "TERM=linux", NULL, };
static const char *panic_later, *panic_param;

extern const struct obs_kernel_param __setup_start[], __setup_end[];

static int __init obsolete_checksetup(char *line)
{
	const struct obs_kernel_param *p;
	int had_early_param = 0;

	/*! param 이
	 * 1) parse_early_param에서 수행 되었거나
	 * 2) __setup_start->setup_func 이 NULL이거나,
	 * 3) __setup_start->setup_func(line + n) 의 리턴값이 true 일 때,
	 * obsolete param으로 판단한다.
	 */
	p = __setup_start;
	do {
		int n = strlen(p->str);
		if (parameqn(line, p->str, n)) {
			if (p->early) {
				/* Already done in parse_early_param?
				 * (Needs exact match on param part).
				 * Keep iterating, as we can have early
				 * params and __setups of same names 8( */
				if (line[n] == '\0' || line[n] == '=')
					had_early_param = 1;
			} else if (!p->setup_func) {
				pr_warn("Parameter %s is obsolete, ignored\n",
					p->str);
				return 1;
			} else if (p->setup_func(line + n))
				return 1;
		}
		p++;
	} while (p < __setup_end);

	return had_early_param;
}

/*
 * This should be approx 2 Bo*oMips to start (note initial shift), and will
 * still work even if initially too large, it will just take slightly longer
 */
unsigned long loops_per_jiffy = (1<<12);

EXPORT_SYMBOL(loops_per_jiffy);

static int __init debug_kernel(char *str)
{
	console_loglevel = 10;
	return 0;
}

static int __init quiet_kernel(char *str)
{
	console_loglevel = 4;
	return 0;
}

early_param("debug", debug_kernel);
early_param("quiet", quiet_kernel);

static int __init loglevel(char *str)
{
	int newlevel;

	/*
	 * Only update loglevel value when a correct setting was passed,
	 * to prevent blind crashes (when loglevel being set to 0) that
	 * are quite hard to debug
	 */
	if (get_option(&str, &newlevel)) {
		console_loglevel = newlevel;
		return 0;
	}

	return -EINVAL;
}

early_param("loglevel", loglevel);

/* Change NUL term back to "=", to make "param" the whole string. */
static int __init repair_env_string(char *param, char *val, const char *unused)
{
	if (val) {
		/* param=val or param="val"? */
		if (val == param+strlen(param)+1)
			val[-1] = '=';
		else if (val == param+strlen(param)+2) {
			val[-2] = '=';
			memmove(val-1, val, strlen(val)+1);
			val--;
		} else
			BUG();
	}
	return 0;
}

/*
 * Unknown boot options get handed to init, unless they look like
 * unused parameters (modprobe will find them in /proc/cmdline).
 */
static int __init unknown_bootoption(char *param, char *val, const char *unused)
{
	/*! param의 마지막 NULL 문자를 '='으로 복구 해 준다. */
	repair_env_string(param, val, unused);

	/* Handle obsolete-style parameters */
	if (obsolete_checksetup(param))
		return 0;

	/* Unused module parameter. */
	if (strchr(param, '.') && (!val || strchr(param, '.') < val))
		return 0;

	if (panic_later)
		return 0;

	if (val) {
		/* Environment option */
		unsigned int i;
		for (i = 0; envp_init[i]; i++) {
			if (i == MAX_INIT_ENVS) {
				panic_later = "env";
				panic_param = param;
			}
			if (!strncmp(param, envp_init[i], val - param))
				break;
		}
		envp_init[i] = param;
	} else {
		/* Command line option */
		unsigned int i;
		for (i = 0; argv_init[i]; i++) {
			if (i == MAX_INIT_ARGS) {
				panic_later = "init";
				panic_param = param;
			}
		}
		argv_init[i] = param;
	}
	return 0;
}

static int __init init_setup(char *str)
{
	unsigned int i;

	execute_command = str;
	/*
	 * In case LILO is going to boot us with default command line,
	 * it prepends "auto" before the whole cmdline which makes
	 * the shell think it should execute a script with such name.
	 * So we ignore all arguments entered _before_ init=... [MJ]
	 */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("init=", init_setup);

static int __init rdinit_setup(char *str)
{
	unsigned int i;

	ramdisk_execute_command = str;
	/* See "auto" comment in init_setup */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("rdinit=", rdinit_setup);

#ifndef CONFIG_SMP
static const unsigned int setup_max_cpus = NR_CPUS;
#ifdef CONFIG_X86_LOCAL_APIC
static void __init smp_init(void)
{
	APIC_init_uniprocessor();
}
#else
#define smp_init()	do { } while (0)
#endif

static inline void setup_nr_cpu_ids(void) { }
static inline void smp_prepare_cpus(unsigned int maxcpus) { }
#endif

/*
 * We need to store the untouched command line for future reference.
 * We also need to store the touched command line since the parameter
 * parsing is performed in place, and we should allow a component to
 * store reference of name/value for future reference.
 */
/*!
 * setup_command_line()
 * - saved_command_line, initcall_command_line, static_command_line 을 초기화
 */
static void __init setup_command_line(char *command_line)
{
	saved_command_line =
		memblock_virt_alloc(strlen(boot_command_line) + 1, 0);
	initcall_command_line =
		memblock_virt_alloc(strlen(boot_command_line) + 1, 0);
	static_command_line = memblock_virt_alloc(strlen(command_line) + 1, 0);
	strcpy (saved_command_line, boot_command_line);
	strcpy (static_command_line, command_line);
}

/*
 * We need to finalize in a non-__init function or else race conditions
 * between the root thread and the init thread may cause start_kernel to
 * be reaped by free_initmem before the root thread has proceeded to
 * cpu_idle.
 *
 * gcc-3.4 accidentally inlines this function, so use noinline.
 */

static __initdata DECLARE_COMPLETION(kthreadd_done);

/*! 2017. 4.30 study -ing */
static noinline void __init_refok rest_init(void)
{
	int pid;

	rcu_scheduler_starting();
	/*
	 * We need to spawn init first so that it obtains pid 1, however
	 * the init task will end up wanting to create kthreads, which, if
	 * we schedule it before we create kthreadd, will OOPS.
	 */
	/*! fork는 나중에 보기로하고, kernel_init을 봄 */
	kernel_thread(kernel_init, NULL, CLONE_FS | CLONE_SIGHAND);
	numa_default_policy();
	pid = kernel_thread(kthreadd, NULL, CLONE_FS | CLONE_FILES);
	rcu_read_lock();
	kthreadd_task = find_task_by_pid_ns(pid, &init_pid_ns);
	rcu_read_unlock();
	complete(&kthreadd_done);

	/*
	 * The boot idle thread must execute schedule()
	 * at least once to get things moving:
	 */
	init_idle_bootup_task(current);
	schedule_preempt_disabled();
	/* Call into cpu_idle with preempt disabled */
	cpu_startup_entry(CPUHP_ONLINE);
}

/* Check for early params. */
static int __init do_early_param(char *param, char *val, const char *unused)
{
	const struct obs_kernel_param *p;

	/*!
	 * setup_start, setup_end사이의 .init.section의 등록은
	 * drivers/tty/serial/8250/8250_early.c 마지막 줄
	 * early_param("earlycon", setup_early_serial8250_console);
	 * early_param에 의해 __setup_param이 호출되고, setup_func가 등록된지만,
	 * 엑시노스 5420의 경우 console 의 내용에 earlycon이 없어 do_early_param에서
	 * 해주는 정확한 일이 없다. -> 내용 수정. 아래 참조
	 */
	/*!
	 * 아래 (p->early && parameq(param, p->str))의 조건을 만족하면 if문 안의 내용을 수행한다.
	 * (early_param("mminit_loglevel", set_mminit_loglevel) 확인 중 발견)
	 * early_param 매크로에 의해 등록된 obs_kernel_param struct의 setup->func()을 수행한다.
	 * (아래 p->setup_func(val))
	 */
	for (p = __setup_start; p < __setup_end; p++) {
		if ((p->early && parameq(param, p->str)) ||
		    (strcmp(param, "console") == 0 &&
		     strcmp(p->str, "earlycon") == 0)
		) {
			if (p->setup_func(val) != 0)
				pr_warn("Malformed early option '%s'\n", param);
		}
	}
	/* We accept everything at this stage. */
	return 0;
}

void __init parse_early_options(char *cmdline)
{
	parse_args("early options", cmdline, NULL, 0, 0, 0, do_early_param);
}

/* Arch code calls this early on, or if not, just before other parsing. */
void __init parse_early_param(void)
{
	static __initdata int done = 0;
	static __initdata char tmp_cmdline[COMMAND_LINE_SIZE];

	if (done)
		return;

	/* All fall through to do_early_param. */
	strlcpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
	parse_early_options(tmp_cmdline);
	done = 1;
}

/*
 *	Activate the first processor.
 */

static void __init boot_cpu_init(void)
{
	/*!
	 * 현재 태스크가 수행 중인 CPU 번호를 얻어옴
	 */
	int cpu = smp_processor_id();
	/* Mark the boot cpu "present", "online" etc for SMP and UP case */
	/*!
	 * 얻어온 CPU에 대응하는 비트를 cpu_online_map, cpu_presenCmap, cpu_possible_map에 셋팅
	 * 해당 맵들은 CPU에 대한 상태 정보를 유지하는 비트맵들이다.
	 * online - online 상태이고, 스케쥴 되는 상태인 cpu 집합. present cpu 들 중 cpu_up() 호출되었을 때 추가됨.
	 * possible - 시스템에 존재할 수 있는 cpu 집합. config 최대값 이하.
	               boot time에 결정되어(per_cpu 변수 공간에 사용) static 하게 유지되고, 존재한다면 online 상태가 됨.
	 * present - 현재 시스템에 존재하는 cpu 집합. possible의 부분집합이며, online 또는 offline 일 수 있음.
	 * active - runqueue migration 등에 사용되는 cpu 집합.
	 *
	 * 핫플러그 참고: http://bonegineer.blogspot.kr/2014/01/cpu-onoff-cpu-hotplug.html
	 * cpu map 참고: 모기향 p.144
	 * 설명 참고: http://www.iamroot.org/xe/Kernel_9_ARM/172038
	 * Documentation/cpu-hotplug.txt
	 * Documentation/cputopology.txt
	 */
	set_cpu_online(cpu, true);
	set_cpu_active(cpu, true);
	set_cpu_present(cpu, true);
	set_cpu_possible(cpu, true);
}

void __init __weak smp_setup_processor_id(void)
{
}

# if THREAD_SIZE >= PAGE_SIZE
void __init __weak thread_info_cache_init(void)
{
}
#endif

/*
 * Set up kernel memory allocators
 */
static void __init mm_init(void)
{
	/*
	 * page_cgroup requires contiguous pages,
	 * bigger than MAX_ORDER unless SPARSEMEM.
	 */
	page_cgroup_init_flatmem();
    /*! 버디할당  */
	mem_init();
	/*! 2015.10.17 study end  */
	/*! mm/slub.c 로 jump 함 */
    /*! 2015.10.24 study start  */
    /*! 슬랩할당  */
	kmem_cache_init();
	percpu_init_late();
	/*! 2016.06.25 study end */
	/*! 2016.07.09 study start */
	pgtable_init();
	vmalloc_init();
}

/*! __init : 초기화 과정에서 사용
 * __cold : 잘 불리는 함수나 잘 안불리 함수의 구분
 * notrace : no_instrument_function 속성을 지정해주는 매크로입니다.
 * http://www.iamroot.org/xe/index.php?mid=FreeBoard&document_srl=218773&act=dispBoardReplyComment&comment_srl=219033 */
asmlinkage void __init start_kernel(void)
{
	char * command_line;
	extern const struct kernel_param __start___param[], __stop___param[];

	/*
	 * Need to run as early as possible, to initialize the
	 * lockdep hash:
	 */
	/*! http://studyfoss.egloos.com/5342153
	 * CONFIG_LOCKDEP 는 현재 셋팅 안되있음 */
	/*!do while(0) 의 이유
	 * http://kernelnewbies.org/FAQ/DoWhile0
	 * https://kldp.org/node/45597
	 */
	lockdep_init();
	/*! weak 애트리뷰트가 지정되지 않은 smp_setup_processor_id( ) 함수가 존재한다면 수
	 * 행되지 않는 함수다.
	 */
/****************************************
 *	2014/08/02  study end
 **************************************/
	smp_setup_processor_id();
	debug_objects_early_init();
/****************************************
 *	2014/08/09  study end
 **************************************/

	/*
	 * Set up the the initial canary ASAP:
	 */
	boot_init_stack_canary();
	/*
	 * cgroup 소개 및 구성 방법: https://access.redhat.com/documentation/ko-KR/Red_Hat_Enterprise_Linux/6/html/Resource_Management_Guide/ch01.html
	 * cgroups wiki: http://en.wikipedia.org/wiki/cgroups
	 * systemd 소개 및 토론: https://kldp.org/node/141175(cgroup을 사용한 초기화 데몬, 현재 많은 리눅스에서 채택 중)
	 * 11차 A조 cgroup 링크(18차): http://www.iamroot.org/xe/FreeBoard/223244
	 */
	cgroup_init_early();

	/*!
	 * 이전 상태플래그 저장하고 irq disable
	 */
	/*!
	 * early = 순서 상 init 보다 앞설 경우
	 */
	local_irq_disable();
	early_boot_irqs_disabled = true;

/*
 * Interrupts are still disabled. Do necessary setups, then
 * enable them
 */
	boot_cpu_init();
	/*!
	 * highmem 초기화
	 * zone 조사 필요
	 */
	page_address_init();
	/*!
	 * printk() - 수준을 맞추어줌
	 * linux 버전, 컴파일러 등 정보 출력
	 */
	pr_notice("%s", linux_banner);
	/*!
	 */
	setup_arch(&command_line);
	/*! 2015/06/27 study end */
	/*! 2015/06/27 study start */
	/*! 아래 두 함수에서 실행되는 부분 없음(설정X)*/
	mm_init_owner(&init_mm, &init_task);
	mm_init_cpumask(&init_mm);
	/*! boot_command_line 초기화 시점 찾아보기 */
	setup_command_line(command_line);
	setup_nr_cpu_ids();
	setup_per_cpu_areas();
	smp_prepare_boot_cpu();	/* arch-specific boot-cpu hooks */
	/*! 2015.07.25 study end */

	/*! 2015.08.08 study start */
	build_all_zonelists(NULL, NULL);
	page_alloc_init();

	idbg("I am rooot first debug msg\n");
	pr_notice("Kernel command line: %s\n", boot_command_line);

	/*! exynos - ARM은 setup_arch에서 해 줬기 때문에,
	 * 아래 parse_early_param은 아무것도 하지 않고 바로 빠져 나온다.
	 */
	parse_early_param();

	/*! __start___param : __param의 시작주소, __stop___param : __param의 끝 주소 */
	parse_args("Booting kernel", static_command_line, __start___param,
		   __stop___param - __start___param,
		   -1, -1, &unknown_bootoption);
	/*! 2015.08.22 study end */
	/*! 2015.08.29 study start */

	/*! HAVE_JUMP_LABEL define 안 돼있음.
	 * Optimize very unlikely/likely branches (from Kconfig)
	 */
	jump_label_init();

	/*
	 * These use large bootmem allocations and must precede
	 * kmem_cache_init()
	 */
	/*! 우리는 CONFIG_PRINTK define 돼 있음.
	 *  log_buf 에 new_log_buf_len 크기만큼 mem alloc 한다.
	 */
	setup_log_buf(0);
	pidhash_init();
	vfs_caches_init_early();
	/*! dcache_init_early 시 사용하는 hlist_bl_head 에 관해 좀 더 볼 필요있음. */
	/*! 2015.09.12 study end */
	/*! 2015.09.19 study start */
	sort_main_extable();
	/*! trap_init - arm에선 해주는게 없음 */
	trap_init();
	/*! 버디 할당, 슬랩 할당, vmalloc init 등 수행  */
	mm_init();

	/*
	 * Set up the scheduler prior starting any interrupts (such as the
	 * timer interrupt). Full topology setup happens at smp_init()
	 * time - but meanwhile we still have a functioning scheduler.
	 */
	/*! 2016.07.09 study -ing */
	sched_init();
	/*! 2016.07.09 study end */
	/*
	 * Disable preemption - early bootup scheduling is extremely
	 * fragile until we cpu_idle() for the first time.
	 */
    /*! 2016.07.16 study start */
	preempt_disable();
    /*! irqs_disabled - cpsr 에서 IRQMASK_I_BIT가 set 되어 있는지 확인 */
	if (WARN(!irqs_disabled(), "Interrupts were enabled *very* early, fixing it\n"))
		local_irq_disable();
	idr_init_cache();
    /*! 2016.07.16 study -ing */
	rcu_init();
	/*! Do nothing. (CONFIG_NO_HZ_FULL이 define 안 됨)  */
	tick_nohz_init();
	/*! Do nothing. (CONFIG_CONTEXT_TRACKING_FORCE 이 define 안 됨)  */
	context_tracking_init();
	radix_tree_init();
	/* init some links before init_ISA_irqs() */
	early_irq_init();
	/*! 2016.07.23 study end */
	/*! 2016.08.06 study start */
	init_IRQ();
	/*! 2016.10.15 study -ing */
	tick_init();
	init_timers();
	hrtimers_init();
	softirq_init();
	timekeeping_init();
	time_init();
	sched_clock_postinit();
	/*! 2016.10.15 study -ing */
	perf_event_init();
	profile_init();
	call_function_init();
	WARN(!irqs_disabled(), "Interrupts were enabled early\n");
	early_boot_irqs_disabled = false;
	/*! arch_local_irq_enable 를 통해 irq enable 수행  */
	local_irq_enable();

	/*! Do Nothing. */
	kmem_cache_init_late();

	/*
	 * HACK ALERT! This is early. We're enabling the console before
	 * we've done PCI setups etc, and console_init() must be aware of
	 * this. But we do want output early, in case something goes wrong.
	 */
	console_init();
	/*! panic_later가 set 되어있었으면, print 후 panic 돌입
	 *  panic_later는 unknown bootoption일때만 set 된다.
	 */
	if (panic_later)
		panic("Too many boot %s vars at `%s'", panic_later,
		      panic_param);

	/*! Do Nothing. */
	lockdep_info();

	/*
	 * Need to run this when irqs are enabled, because it wants
	 * to self-test [hard/soft]-irqs on/off lock inversion bugs
	 * too:
	 */
	/*! CONFIG_DEBUG_LOCKING_API_SELFTESTS 이 Not define.
	 *  -> Do Nothing.
	 */
	locking_selftest();

#ifdef CONFIG_BLK_DEV_INITRD
	/*! initrd_start 값이 있는데 나머지 조건들을 만족하지 않으면,
	 *  critical message 출력 후 initrd_start 값 0으로 변경
	 */
	if (initrd_start && !initrd_below_start_ok &&
	    page_to_pfn(virt_to_page((void *)initrd_start)) < min_low_pfn) {
		/*! critical print message 수행. */
		pr_crit("initrd overwritten (0x%08lx < 0x%08lx) - disabling it.\n",
		    page_to_pfn(virt_to_page((void *)initrd_start)),
		    min_low_pfn);
		initrd_start = 0;
	}
#endif
	page_cgroup_init();
	/*! 2016.10.29 study end */
	/*! 2016.11.05 study start */

	/*! Do nothing */
	debug_objects_mem_init();
	/*! Do nothing */
	kmemleak_init();
	setup_per_cpu_pageset();
	/*! Do nothing */
	numa_policy_init();
	/*! late_time_init 은 ct-ca9x4.c의 ct_ca9x4_init_irq 에서
	 *  값이 설정 될 수 있음.
	 *  설정 시 twd_timer_setup() 함수가 설정 된다.
	 *  결국 twd_timer_setup 함수가
	 *  twd_local_timer_common_register 에서 수행되거나, 여기서 수행됨
	 */
	/*! 2016.11.05 study -ing */
	/*! late_time_init => twd_timer_setup  */
	if (late_time_init)
		late_time_init();
	sched_clock_init();
	/*!lpj 를 설정해 준다 */
	calibrate_delay();
	pidmap_init();
	anon_vma_init();
	acpi_early_init();
#ifdef CONFIG_X86
	if (efi_enabled(EFI_RUNTIME_SERVICES))
		efi_enter_virtual_mode();
#endif
	thread_info_cache_init();
	cred_init();
	fork_init(totalram_pages);
	proc_caches_init();
	buffer_init();
	key_init();
	security_init();
	dbg_late_init();
	/*! 2016.11.19 study end */

	/*! 2016.12.03 study start */
	vfs_caches_init(totalram_pages);
	signals_init();
	/* rootfs populating might need page-writeback */
	page_writeback_init();
#ifdef CONFIG_PROC_FS
	proc_root_init();
#endif
	/*! 2017. 3.11 study -ing */
	cgroup_init();
	/*! 2017. 3.25 study end */
	/*! 2017. 4.30 study start */
	cpuset_init();
	/*! Do nothing */
	taskstats_init_early();
	/*! Do nothing */
	delayacct_init();

	/*! #define check_bugs() check_writebuffer_bugs() */
	check_bugs();

	/*! Do nothing */
	sfi_init_late();

	/*! efi_enabled는 0 반환 */
	if (efi_enabled(EFI_RUNTIME_SERVICES)) {
		efi_late_init();
		efi_free_boot_services();
	}

	/*! Do nothing */
	ftrace_init();

	/* Do the rest non-__init'ed, we're now alive */
	rest_init();
}

/* Call all constructor functions linked into the kernel. */
static void __init do_ctors(void)
{
#ifdef CONFIG_CONSTRUCTORS
	ctor_fn_t *fn = (ctor_fn_t *) __ctors_start;

	for (; fn < (ctor_fn_t *) __ctors_end; fn++)
		(*fn)();
#endif
}

bool initcall_debug;
core_param(initcall_debug, initcall_debug, bool, 0644);

static int __init_or_module do_one_initcall_debug(initcall_t fn)
{
	ktime_t calltime, delta, rettime;
	unsigned long long duration;
	int ret;

	pr_debug("calling  %pF @ %i\n", fn, task_pid_nr(current));
	calltime = ktime_get();
	ret = fn();
	rettime = ktime_get();
	delta = ktime_sub(rettime, calltime);
	duration = (unsigned long long) ktime_to_ns(delta) >> 10;
	pr_debug("initcall %pF returned %d after %lld usecs\n",
		 fn, ret, duration);

	return ret;
}

/*! 2017. 4.30 study -ing */
int __init_or_module do_one_initcall(initcall_t fn)
{
	int count = preempt_count();
	int ret;
	char msgbuf[64];

	if (initcall_debug)
		ret = do_one_initcall_debug(fn);
	else
		ret = fn();

	msgbuf[0] = 0;

	if (preempt_count() != count) {
		sprintf(msgbuf, "preemption imbalance ");
		preempt_count_set(count);
	}
	if (irqs_disabled()) {
		strlcat(msgbuf, "disabled interrupts ", sizeof(msgbuf));
		local_irq_enable();
	}
	WARN(msgbuf[0], "initcall %pF returned with %s\n", fn, msgbuf);

	return ret;
}


extern initcall_t __initcall_start[];
extern initcall_t __initcall0_start[];
extern initcall_t __initcall1_start[];
extern initcall_t __initcall2_start[];
extern initcall_t __initcall3_start[];
extern initcall_t __initcall4_start[];
extern initcall_t __initcall5_start[];
extern initcall_t __initcall6_start[];
extern initcall_t __initcall7_start[];
extern initcall_t __initcall_end[];

static initcall_t *initcall_levels[] __initdata = {
	__initcall0_start,
	__initcall1_start,
	__initcall2_start,
	__initcall3_start,
	__initcall4_start,
	__initcall5_start,
	__initcall6_start,
	__initcall7_start,
	__initcall_end,
};

/* Keep these in sync with initcalls in include/linux/init.h */
static char *initcall_level_names[] __initdata = {
	"early",
	"core",
	"postcore",
	"arch",
	"subsys",
	"fs",
	"device",
	"late",
};

static void __init do_initcall_level(int level)
{
	extern const struct kernel_param __start___param[], __stop___param[];
	initcall_t *fn;

	strcpy(initcall_command_line, saved_command_line);
	parse_args(initcall_level_names[level],
		   initcall_command_line, __start___param,
		   __stop___param - __start___param,
		   level, level,
		   &repair_env_string);

	for (fn = initcall_levels[level]; fn < initcall_levels[level+1]; fn++)
		do_one_initcall(*fn);
}

static void __init do_initcalls(void)
{
	int level;

	for (level = 0; level < ARRAY_SIZE(initcall_levels) - 1; level++)
		do_initcall_level(level);
}

/*
 * Ok, the machine is now initialized. None of the devices
 * have been touched yet, but the CPU subsystem is up and
 * running, and memory and process management works.
 *
 * Now we can finally start doing some real work..
 */
static void __init do_basic_setup(void)
{
	cpuset_init_smp();
	usermodehelper_init();
	shmem_init();
	driver_init();
	init_irq_proc();
	do_ctors();
	usermodehelper_enable();
	do_initcalls();
	random_int_secret_init();
}

/*! 2017. 4.30 study -ing */
static void __init do_pre_smp_initcalls(void)
{
	initcall_t *fn;

	/*! vmlinux.lds에 보면
	 * __initcall_start와 __initcall0_start의 사이에 있는 함수다.
	 */
	for (fn = __initcall_start; fn < __initcall0_start; fn++)
		do_one_initcall(*fn);
}

/*
 * This function requests modules which should be loaded by default and is
 * called twice right after initrd is mounted and right before init is
 * exec'd.  If such modules are on either initrd or rootfs, they will be
 * loaded before control is passed to userland.
 */
void __init load_default_modules(void)
{
	load_default_elevator_module();
}

static int run_init_process(const char *init_filename)
{
	argv_init[0] = init_filename;
	return do_execve(getname_kernel(init_filename),
		(const char __user *const __user *)argv_init,
		(const char __user *const __user *)envp_init);
}

static int try_to_run_init_process(const char *init_filename)
{
	int ret;

	ret = run_init_process(init_filename);

	if (ret && ret != -ENOENT) {
		pr_err("Starting init: %s exists but couldn't execute it (error %d)\n",
		       init_filename, ret);
	}

	return ret;
}

static noinline void __init kernel_init_freeable(void);

/*! 2017. 4.30 study -ing */
static int __ref kernel_init(void *unused)
{
	int ret;

	kernel_init_freeable();
	/* need to finish all async __init code before freeing the memory */
	async_synchronize_full();
	free_initmem();
	mark_rodata_ro();
	system_state = SYSTEM_RUNNING;
	numa_default_policy();

	flush_delayed_fput();

	if (ramdisk_execute_command) {
		ret = run_init_process(ramdisk_execute_command);
		if (!ret)
			return 0;
		pr_err("Failed to execute %s (error %d)\n",
		       ramdisk_execute_command, ret);
	}

	/*
	 * We try each of these until one succeeds.
	 *
	 * The Bourne shell can be used instead of init if we are
	 * trying to recover a really broken machine.
	 */
	if (execute_command) {
		ret = run_init_process(execute_command);
		if (!ret)
			return 0;
		pr_err("Failed to execute %s (error %d).  Attempting defaults...\n",
			execute_command, ret);
	}
	if (!try_to_run_init_process("/sbin/init") ||
	    !try_to_run_init_process("/etc/init") ||
	    !try_to_run_init_process("/bin/init") ||
	    !try_to_run_init_process("/bin/sh"))
		return 0;

	panic("No working init found.  Try passing init= option to kernel. "
	      "See Linux Documentation/init.txt for guidance.");
}

/*! 2017. 4.30 study -ing */
static noinline void __init kernel_init_freeable(void)
{
	/*
	 * Wait until kthreadd is all set-up.
	 */
	wait_for_completion(&kthreadd_done);

	/* Now the scheduler is fully set up and can do blocking allocations */
	gfp_allowed_mask = __GFP_BITS_MASK;

	/*
	 * init can allocate pages on any node
	 */
	set_mems_allowed(node_states[N_MEMORY]);
	/*
	 * init can run on any cpu.
	 */
	set_cpus_allowed_ptr(current, cpu_all_mask);

	cad_pid = task_pid(current);

	smp_prepare_cpus(setup_max_cpus);

	do_pre_smp_initcalls();
	/*! Do nothing */
	lockup_detector_init();

	smp_init();
	sched_init_smp();

	/*! 2017. 5. 6 study end */

	do_basic_setup();

	/* Open the /dev/console on the rootfs, this should never fail */
	if (sys_open((const char __user *) "/dev/console", O_RDWR, 0) < 0)
		pr_err("Warning: unable to open an initial console.\n");

	(void) sys_dup(0);
	(void) sys_dup(0);
	/*
	 * check if there is an early userspace init.  If yes, let it do all
	 * the work
	 */

	if (!ramdisk_execute_command)
		ramdisk_execute_command = "/init";

	if (sys_access((const char __user *) ramdisk_execute_command, 0) != 0) {
		ramdisk_execute_command = NULL;
		prepare_namespace();
	}

	/*
	 * Ok, we have completed the initial bootup, and
	 * we're essentially up and running. Get rid of the
	 * initmem segments and start the user-mode stuff..
	 */

	/* rootfs is available now, try loading default modules */
	load_default_modules();
}

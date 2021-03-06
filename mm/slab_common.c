/*
 * Slab allocator functions that are independent of the allocator strategy
 *
 * (C) 2012 Christoph Lameter <cl@linux.com>
 */
#include <linux/slab.h>

#include <linux/mm.h>
#include <linux/poison.h>
#include <linux/interrupt.h>
#include <linux/memory.h>
#include <linux/compiler.h>
#include <linux/module.h>
#include <linux/cpu.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/page.h>
#include <linux/memcontrol.h>
#include <trace/events/kmem.h>

#include "slab.h"

enum slab_state slab_state;
LIST_HEAD(slab_caches);
DEFINE_MUTEX(slab_mutex);
struct kmem_cache *kmem_cache;

#ifdef CONFIG_DEBUG_VM
static int kmem_cache_sanity_check(struct mem_cgroup *memcg, const char *name,
				   size_t size)
{
	struct kmem_cache *s = NULL;

	if (!name || in_interrupt() || size < sizeof(void *) ||
		size > KMALLOC_MAX_SIZE) {
		pr_err("kmem_cache_create(%s) integrity check failed\n", name);
		return -EINVAL;
	}

	list_for_each_entry(s, &slab_caches, list) {
		char tmp;
		int res;

		/*
		 * This happens when the module gets unloaded and doesn't
		 * destroy its slab cache and no-one else reuses the vmalloc
		 * area of the module.  Print a warning.
		 */
		res = probe_kernel_address(s->name, tmp);
		if (res) {
			pr_err("Slab cache with size %d has lost its name\n",
			       s->object_size);
			continue;
		}

#if !defined(CONFIG_SLUB) || !defined(CONFIG_SLUB_DEBUG_ON)
		/*
		 * For simplicity, we won't check this in the list of memcg
		 * caches. We have control over memcg naming, and if there
		 * aren't duplicates in the global list, there won't be any
		 * duplicates in the memcg lists as well.
		 */
		if (!memcg && !strcmp(s->name, name)) {
			pr_err("%s (%s): Cache name already exists.\n",
			       __func__, name);
			dump_stack();
			s = NULL;
			return -EINVAL;
		}
#endif
	}

	WARN_ON(strchr(name, ' '));	/* It confuses parsers */
	return 0;
}
#else
/*! 2016.07.16 study -ing */
static inline int kmem_cache_sanity_check(struct mem_cgroup *memcg,
					  const char *name, size_t size)
{
	return 0;
}
#endif

#ifdef CONFIG_MEMCG_KMEM
int memcg_update_all_caches(int num_memcgs)
{
	struct kmem_cache *s;
	int ret = 0;
	mutex_lock(&slab_mutex);

	list_for_each_entry(s, &slab_caches, list) {
		if (!is_root_cache(s))
			continue;

		ret = memcg_update_cache_size(s, num_memcgs);
		/*
		 * See comment in memcontrol.c, memcg_update_cache_size:
		 * Instead of freeing the memory, we'll just leave the caches
		 * up to this point in an updated state.
		 */
		if (ret)
			goto out;
	}

	memcg_update_array_size(num_memcgs);
out:
	mutex_unlock(&slab_mutex);
	return ret;
}
#endif

/*
 * Figure out what the alignment of the objects will be given a set of
 * flags, a user specified alignment and the size of the objects.
 */
/*! 2015.10.24 study -ing */
unsigned long calculate_alignment(unsigned long flags,
		unsigned long align, unsigned long size)
{
	/*
	 * If the user wants hardware cache aligned objects then follow that
	 * suggestion if the object is sufficiently large.
	 *
	 * The hardware cache alignment cannot override the specified
	 * alignment though. If that is greater then use it.
	 */
	if (flags & SLAB_HWCACHE_ALIGN) {
        /*! cache_line_size() = L1_CACHE_BYTES = 1<<6 = 64(0x40)  */
		unsigned long ralign = cache_line_size();
        /*! 아래 while문의 결과로 ralign은 size 보다 작거나 같은
         *  2의 승수 배의 숫자가 구해진다.
         */
		while (size <= ralign / 2)
			ralign /= 2;
		align = max(align, ralign);
	}

    /*! ARCH_SLAB_MINALIGN = 8 */
	if (align < ARCH_SLAB_MINALIGN)
		align = ARCH_SLAB_MINALIGN;

    /*! sizeof(void *) = 32bit : 4 , 64bit : 8
     * ALIGN(...) = 64 */
	return ALIGN(align, sizeof(void *));
}


/*
 * kmem_cache_create - Create a cache.
 * @name: A string which is used in /proc/slabinfo to identify this cache.
 * @size: The size of objects to be created in this cache.
 * @align: The required alignment for the objects.
 * @flags: SLAB flags
 * @ctor: A constructor for the objects.
 *
 * Returns a ptr to the cache on success, NULL on failure.
 * Cannot be called within a interrupt, but can be interrupted.
 * The @ctor is run when new pages are allocated by the cache.
 *
 * The flags are
 *
 * %SLAB_POISON - Poison the slab with a known test pattern (a5a5a5a5)
 * to catch references to uninitialised memory.
 *
 * %SLAB_RED_ZONE - Insert `Red' zones around the allocated memory to check
 * for buffer overruns.
 *
 * %SLAB_HWCACHE_ALIGN - Align the objects in this cache to a hardware
 * cacheline.  This can be beneficial if you're counting cycles as closely
 * as davem.
 */
/*! 2016.07.16 study -ing */
struct kmem_cache *
kmem_cache_create_memcg(struct mem_cgroup *memcg, const char *name, size_t size,
			size_t align, unsigned long flags, void (*ctor)(void *),
			struct kmem_cache *parent_cache)
{
	struct kmem_cache *s = NULL;
	int err;

	get_online_cpus();
	mutex_lock(&slab_mutex);

    /*! do nothing  */
	err = kmem_cache_sanity_check(memcg, name, size);
	if (err)
		goto out_unlock;

	if (memcg) {
		/*
		 * Since per-memcg caches are created asynchronously on first
		 * allocation (see memcg_kmem_get_cache()), several threads can
		 * try to create the same cache, but only one of them may
		 * succeed. Therefore if we get here and see the cache has
		 * already been created, we silently return NULL.
		 */
		if (cache_from_memcg_idx(parent_cache, memcg_cache_id(memcg)))
			goto out_unlock;
	}

	/*
	 * Some allocators will constraint the set of valid flags to a subset
	 * of all flags. We expect them to define CACHE_CREATE_MASK in this
	 * case, and we'll just provide them with a sanitized version of the
	 * passed flags.
	 */
    /*! CACHE_CREATE_MASK - (SLAB_CORE_FLAGS | SLAB_DEBUG_FLAGS | SLAB_CACHE_FLAGS)  */
	flags &= CACHE_CREATE_MASK;

    /*! find_mergeable을 통해 mergeable 한 kmem_cache가 리턴 됨.  */
	s = __kmem_cache_alias(memcg, name, size, align, flags, ctor);
	if (s)
		goto out_unlock;

    /*! mergeable 한 kmem_cache를 못 찾으면 아래 kmem_cache_zalloc으로 직접 alloc */
	err = -ENOMEM;
	s = kmem_cache_zalloc(kmem_cache, GFP_KERNEL);
	if (!s)
		goto out_unlock;

	s->object_size = s->size = size;
	s->align = calculate_alignment(flags, align, size);
	s->ctor = ctor;

    /*! name 이 NULL 일 경우 NULL, 아니면 문자열 복사 하여 리턴  */
	s->name = kstrdup(name, GFP_KERNEL);
	if (!s->name)
		goto out_free_cache;

    /*! 우리는 do nothing. return 0  */
	err = memcg_alloc_cache_params(memcg, s, parent_cache);
	if (err)
		goto out_free_cache;

	err = __kmem_cache_create(s, flags);
	if (err)
		goto out_free_cache;

    /*! 직접 alloc 한 kmem_cache에 아래 값들 설정  */
	s->refcount = 1;
	list_add(&s->list, &slab_caches);
    /*! do nothing.  */
	memcg_register_cache(s);

out_unlock:
	mutex_unlock(&slab_mutex);
	put_online_cpus();

    /*! 에러가 있으면 아래 에러 처리 */
	if (err) {
		/*
		 * There is no point in flooding logs with warnings or
		 * especially crashing the system if we fail to create a cache
		 * for a memcg. In this case we will be accounting the memcg
		 * allocation to the root cgroup until we succeed to create its
		 * own cache, but it isn't that critical.
		 */
		if (!memcg)
			return NULL;

		if (flags & SLAB_PANIC)
			panic("kmem_cache_create: Failed to create slab '%s'. Error %d\n",
				name, err);
		else {
			printk(KERN_WARNING "kmem_cache_create(%s) failed with error %d",
				name, err);
			dump_stack();
		}
		return NULL;
	}
    /*! 에러 없으면 설정한 kmem_cache s 를 리턴  */
	return s;

out_free_cache:
    /*! do nothing.  */
	memcg_free_cache_params(s);
	kfree(s->name);
	kmem_cache_free(kmem_cache, s);
	goto out_unlock;
}
/*! 2016.07.16 study -ing */
struct kmem_cache *
kmem_cache_create(const char *name, size_t size, size_t align,
		  unsigned long flags, void (*ctor)(void *))
{
	return kmem_cache_create_memcg(NULL, name, size, align, flags, ctor, NULL);
}
EXPORT_SYMBOL(kmem_cache_create);

void kmem_cache_destroy(struct kmem_cache *s)
{
	/* Destroy all the children caches if we aren't a memcg cache */
	kmem_cache_destroy_memcg_children(s);

	get_online_cpus();
	mutex_lock(&slab_mutex);
	s->refcount--;
	if (!s->refcount) {
		list_del(&s->list);

		if (!__kmem_cache_shutdown(s)) {
			memcg_unregister_cache(s);
			mutex_unlock(&slab_mutex);
			if (s->flags & SLAB_DESTROY_BY_RCU)
				rcu_barrier();

			memcg_free_cache_params(s);
			kfree(s->name);
			kmem_cache_free(kmem_cache, s);
		} else {
			list_add(&s->list, &slab_caches);
			mutex_unlock(&slab_mutex);
			printk(KERN_ERR "kmem_cache_destroy %s: Slab cache still has objects\n",
				s->name);
			dump_stack();
		}
	} else {
		mutex_unlock(&slab_mutex);
	}
	put_online_cpus();
}
EXPORT_SYMBOL(kmem_cache_destroy);

int slab_is_available(void)
{
	return slab_state >= UP;
}

#ifndef CONFIG_SLOB
/* Create a cache during boot when no slab services are available yet */
/*! from kmem_cache_init()
 * 	args = (kmem_cache_node,
 *      "kmem_cache_node",
 *      sizeof(struct kmem_cache_node),
 *      SLAB_HWCACHE_ALIGN(=0x00002000UL) )
 */
/*! 2015.10.24 study -ing */
void __init create_boot_cache(struct kmem_cache *s, const char *name, size_t size,
		unsigned long flags)
{
	int err;

	idbg1("name : %s, size : %d\n",name,size);
	s->name = name;
	s->size = s->object_size = size;
    /*! ARCH_KMALLOC_MINALIGN = ARCH_DMA_MINALIGN = L1_CACHE_BYTES =
     *      (1 << L1_CACHE_SHIFT) =  1 << CONFIG_ARM_L1_CACHE_SHIFT
     *      = 1<<6 = 64(0x40) */
	s->align = calculate_alignment(flags, ARCH_KMALLOC_MINALIGN, size);
	err = __kmem_cache_create(s, flags);

	if (err)
		panic("Creation of kmalloc slab %s size=%zu failed. Reason %d\n",
					name, size, err);

	s->refcount = -1;	/* Exempt from merging for now */
}

/*! 2016.06.25 study -ing */
/*! size 크기의 cache를 가지는 kmem_cache를 만들어서 반환한다. */
struct kmem_cache *__init create_kmalloc_cache(const char *name, size_t size,
				unsigned long flags)
{
	/*! kmem_cache를 0로 채워서 할당 */
	struct kmem_cache *s = kmem_cache_zalloc(kmem_cache, GFP_NOWAIT);

	if (!s)
		panic("Out of memory when creating slab %s\n", name);

	/*! size만큼 cache(kmalloc slab)를 생성해서 s에 연결 */
	create_boot_cache(s, name, size, flags);
	/*! s->list를 slab_caches에 추가 */
	list_add(&s->list, &slab_caches);
	s->refcount = 1;
	return s;
}

struct kmem_cache *kmalloc_caches[KMALLOC_SHIFT_HIGH + 1];
EXPORT_SYMBOL(kmalloc_caches);

#ifdef CONFIG_ZONE_DMA
struct kmem_cache *kmalloc_dma_caches[KMALLOC_SHIFT_HIGH + 1];
EXPORT_SYMBOL(kmalloc_dma_caches);
#endif

/*
 * Conversion table for small slabs sizes / 8 to the index in the
 * kmalloc array. This is necessary for slabs < 192 since we have non power
 * of two cache sizes there. The size of larger slabs can be determined using
 * fls.
 */
/*! 2016-06-18 study -ing */
/*!
 * 최적의 cache size 테이블
 * 2의 승수 (power of two)가 안되는 캐시에 대해서
 * 아래 주석 관련 개념을 활용함
 */
static s8 size_index[24] = {
	3,	/* 8 */
	4,	/* 16 */
	5,	/* 24 */
	5,	/* 32 */
	6,	/* 40 */
	6,	/* 48 */
	6,	/* 56 */
	6,	/* 64 */
/*! KMALLOC_MIN_SIZE 가 64보다 작을 때
 * 65~96 바이트는 index 1을 사용함 */
	1,	/* 72 */
	1,	/* 80 */
	1,	/* 88 */
	1,	/* 96 */
	7,	/* 104 */
	7,	/* 112 */
	7,	/* 120 */
	7,	/* 128 */
/*! KMALLOC_MIN_SIZE 가 64보다 작을 때
 * 129~193 바이트는 index 2를 사용함 */
	2,	/* 136 */
	2,	/* 144 */
	2,	/* 152 */
	2,	/* 160 */
	2,	/* 168 */
	2,	/* 176 */
	2,	/* 184 */
	2	/* 192 */
};

/*! 2016-06-18 study -ing */
static inline int size_index_elem(size_t bytes)
{
	/*!
	 * 8단위로 0부터 +1
	 * Ex: bytes 0~8 -> 0
	 *     bytes 9~16 -> 1
	 *     ...
	 */
	return (bytes - 1) / 8;
}

/*
 * Find the kmem_cache structure that serves a given size of
 * allocation
 */
/*! 2016-03-19 study -ing */
struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags)
{
	int index;

	/*! Max size 체크  */
	if (unlikely(size > KMALLOC_MAX_SIZE)) {
		WARN_ON_ONCE(!(flags & __GFP_NOWARN));
		return NULL;
	}

	if (size <= 192) {
		/*! size = 0 이면 ZERO_SIZE_PTR 리턴.   */
		if (!size)
			return ZERO_SIZE_PTR;
		/*! size 192보다 작으면 미리 정의된 size_index 테이블에서 최적의 값을 가져온다.
		 *  기본값이 있지만, create_kmalloc_caches 함수에서 init 된다.
		 */
		index = size_index[size_index_elem(size)];
	} else
		index = fls(size - 1);

#ifdef CONFIG_ZONE_DMA
	if (unlikely((flags & GFP_DMA)))
		return kmalloc_dma_caches[index];

#endif
	/*! kmalloc_caches는 create_kmalloc_caches에서 init 된다.  */
	return kmalloc_caches[index];
}

/*
 * Create the kmalloc array. Some of the regular kmalloc arrays
 * may already have been created because they were needed to
 * enable allocations for slab creation.
 */
/*! 2016-06-18 study -ing */
/*! kmalloc array를 생성한다. 일부는 slab 생성을 위해서 이미 생성되었음 */
void __init create_kmalloc_caches(unsigned long flags)
{
	int i;

	/*
	 * Patch up the size_index table if we have strange large alignment
	 * requirements for the kmalloc array. This is only the case for
	 * MIPS it seems. The standard arches will not generate any code here.
	 *
	 * Largest permitted alignment is 256 bytes due to the way we
	 * handle the index determination for the smaller caches.
	 *
	 * Make sure that nothing crazy happens if someone starts tinkering
	 * around with ARCH_KMALLOC_MINALIGN
	 */
	BUILD_BUG_ON(KMALLOC_MIN_SIZE > 256 ||
		(KMALLOC_MIN_SIZE & (KMALLOC_MIN_SIZE - 1)));

	/*! KMALLOC_MIN_SIZE = 64 */
	for (i = 8; i < KMALLOC_MIN_SIZE; i += 8) {
		/*! elem은 0~6 */
		int elem = size_index_elem(i);

		/*! size_index는 slab_common.c:379(현재 파일)에 있음 */
		if (elem >= ARRAY_SIZE(size_index))
			break;
		size_index[elem] = KMALLOC_SHIFT_LOW;
	}

	/*! 2016-06-18 study end */
	/*! 2016-06-25 study start */

	if (KMALLOC_MIN_SIZE >= 64) {
		/*
		 * The 96 byte size cache is not used if the alignment
		 * is 64 byte.
		 */
		/*!
		 * 2의 승수가 아닌 캐시에 대하여 (65~96 바이트)
		 * 96 바이트 캐시를 사용하지 않을 것이므로
		 * index를 7로 고친다. (128 바이트)
		 * (size_index를 참고)
		 */
		for (i = 64 + 8; i <= 96; i += 8)
			/*! size_index_elem : 8~11 */
			size_index[size_index_elem(i)] = 7;

	}

	if (KMALLOC_MIN_SIZE >= 128) {
		/*
		 * The 192 byte sized cache is not used if the alignment
		 * is 128 byte. Redirect kmalloc to use the 256 byte cache
		 * instead.
		 */
		/*!
		 * 2의 승수가 아닌 캐시에 대하여 (129~192 바이트)
		 * 192 바이트 캐시를 사용하지 않을 것이므로
		 * index를 8로 고친다. (256 바이트)
		 * (size_index를 참고)
		 */
		for (i = 128 + 8; i <= 192; i += 8)
			size_index[size_index_elem(i)] = 8;
	}
	/*!
	 * kmalloc_caches를 init
	 *
	 * KMALLOC_SHIFT_LOW : 6
	 * KMALLOC_SHIFT_HIGH : 13
	 * 
	 * kmalloc_cahces[0, 3~5]는 초기화 안될 것임
	 * [1]이나 [2]는 될 수도 있음 (우리 환경에선 [1]은 생성 X)
	 */
	for (i = KMALLOC_SHIFT_LOW; i <= KMALLOC_SHIFT_HIGH; i++) {
		if (!kmalloc_caches[i]) {
			/*!
			 * (2^i) 사이즈인 캐시를 생성함
			 * 즉, 2^6 ~ 2^13
			 */
			kmalloc_caches[i] = create_kmalloc_cache(NULL,
							1 << i, flags);
		}

		/*
		 * Caches that are not of the two-to-the-power-of size.
		 * These have to be created immediately after the
		 * earlier power of two caches
		 */
		/*! 번역
		 * 2의 승수 크기가 아닌 캐시. 이 것들은 바로 앞 2의 승수인 캐시의
		 * 바로 다음에 생성되어야 한다.
		 * Ex)
		 * 96은 64 - 128 사이에 생성
		 * 192는 128 - 256 사이에 생성
		 */
		if (KMALLOC_MIN_SIZE <= 32 && !kmalloc_caches[1] && i == 6)
			kmalloc_caches[1] = create_kmalloc_cache(NULL, 96, flags);

		/*!
		 * KMALLOC_MIN_SIZE = 64
		 * 64*3 192 이하의 바이트는 64 바이트 3개를 할당하여 처리가능
		 */
		if (KMALLOC_MIN_SIZE <= 64 && !kmalloc_caches[2] && i == 7)
			kmalloc_caches[2] = create_kmalloc_cache(NULL, 192, flags);
	}

	/* Kmalloc array is now usable */
	slab_state = UP;

	/*! NULL로 만들었던 cahce의 이름을 넣어줌 */
	for (i = 0; i <= KMALLOC_SHIFT_HIGH; i++) {
		struct kmem_cache *s = kmalloc_caches[i];
		char *n;

		if (s) {
			n = kasprintf(GFP_NOWAIT, "kmalloc-%d", kmalloc_size(i));

			BUG_ON(!n);
			s->name = n;
		}
	}

	/*! 없음 */
#ifdef CONFIG_ZONE_DMA
	for (i = 0; i <= KMALLOC_SHIFT_HIGH; i++) {
		struct kmem_cache *s = kmalloc_caches[i];

		if (s) {
			int size = kmalloc_size(i);
			char *n = kasprintf(GFP_NOWAIT,
				 "dma-kmalloc-%d", size);

			BUG_ON(!n);
			kmalloc_dma_caches[i] = create_kmalloc_cache(n,
				size, SLAB_CACHE_DMA | flags);
		}
	}
#endif
}
#endif /* !CONFIG_SLOB */

#ifdef CONFIG_TRACING
void *kmalloc_order_trace(size_t size, gfp_t flags, unsigned int order)
{
	void *ret = kmalloc_order(size, flags, order);
	trace_kmalloc(_RET_IP_, ret, size, PAGE_SIZE << order, flags);
	return ret;
}
EXPORT_SYMBOL(kmalloc_order_trace);
#endif

#ifdef CONFIG_SLABINFO

#ifdef CONFIG_SLAB
#define SLABINFO_RIGHTS (S_IWUSR | S_IRUSR)
#else
#define SLABINFO_RIGHTS S_IRUSR
#endif

void print_slabinfo_header(struct seq_file *m)
{
	/*
	 * Output format version, so at least we can change it
	 * without _too_ many complaints.
	 */
#ifdef CONFIG_DEBUG_SLAB
	seq_puts(m, "slabinfo - version: 2.1 (statistics)\n");
#else
	seq_puts(m, "slabinfo - version: 2.1\n");
#endif
	seq_puts(m, "# name            <active_objs> <num_objs> <objsize> "
		 "<objperslab> <pagesperslab>");
	seq_puts(m, " : tunables <limit> <batchcount> <sharedfactor>");
	seq_puts(m, " : slabdata <active_slabs> <num_slabs> <sharedavail>");
#ifdef CONFIG_DEBUG_SLAB
	seq_puts(m, " : globalstat <listallocs> <maxobjs> <grown> <reaped> "
		 "<error> <maxfreeable> <nodeallocs> <remotefrees> <alienoverflow>");
	seq_puts(m, " : cpustat <allochit> <allocmiss> <freehit> <freemiss>");
#endif
	seq_putc(m, '\n');
}

static void *s_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	mutex_lock(&slab_mutex);
	if (!n)
		print_slabinfo_header(m);

	return seq_list_start(&slab_caches, *pos);
}

void *slab_next(struct seq_file *m, void *p, loff_t *pos)
{
	return seq_list_next(p, &slab_caches, pos);
}

void slab_stop(struct seq_file *m, void *p)
{
	mutex_unlock(&slab_mutex);
}

static void
memcg_accumulate_slabinfo(struct kmem_cache *s, struct slabinfo *info)
{
	struct kmem_cache *c;
	struct slabinfo sinfo;
	int i;

	if (!is_root_cache(s))
		return;

	for_each_memcg_cache_index(i) {
		c = cache_from_memcg_idx(s, i);
		if (!c)
			continue;

		memset(&sinfo, 0, sizeof(sinfo));
		get_slabinfo(c, &sinfo);

		info->active_slabs += sinfo.active_slabs;
		info->num_slabs += sinfo.num_slabs;
		info->shared_avail += sinfo.shared_avail;
		info->active_objs += sinfo.active_objs;
		info->num_objs += sinfo.num_objs;
	}
}

int cache_show(struct kmem_cache *s, struct seq_file *m)
{
	struct slabinfo sinfo;

	memset(&sinfo, 0, sizeof(sinfo));
	get_slabinfo(s, &sinfo);

	memcg_accumulate_slabinfo(s, &sinfo);

	seq_printf(m, "%-17s %6lu %6lu %6u %4u %4d",
		   cache_name(s), sinfo.active_objs, sinfo.num_objs, s->size,
		   sinfo.objects_per_slab, (1 << sinfo.cache_order));

	seq_printf(m, " : tunables %4u %4u %4u",
		   sinfo.limit, sinfo.batchcount, sinfo.shared);
	seq_printf(m, " : slabdata %6lu %6lu %6lu",
		   sinfo.active_slabs, sinfo.num_slabs, sinfo.shared_avail);
	slabinfo_show_stats(m, s);
	seq_putc(m, '\n');
	return 0;
}

static int s_show(struct seq_file *m, void *p)
{
	struct kmem_cache *s = list_entry(p, struct kmem_cache, list);

	if (!is_root_cache(s))
		return 0;
	return cache_show(s, m);
}

/*
 * slabinfo_op - iterator that generates /proc/slabinfo
 *
 * Output layout:
 * cache-name
 * num-active-objs
 * total-objs
 * object size
 * num-active-slabs
 * total-slabs
 * num-pages-per-slab
 * + further values on SMP and with statistics enabled
 */
static const struct seq_operations slabinfo_op = {
	.start = s_start,
	.next = slab_next,
	.stop = slab_stop,
	.show = s_show,
};

static int slabinfo_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &slabinfo_op);
}

static const struct file_operations proc_slabinfo_operations = {
	.open		= slabinfo_open,
	.read		= seq_read,
	.write          = slabinfo_write,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init slab_proc_init(void)
{
	proc_create("slabinfo", SLABINFO_RIGHTS, NULL,
						&proc_slabinfo_operations);
	return 0;
}
module_init(slab_proc_init);
#endif /* CONFIG_SLABINFO */

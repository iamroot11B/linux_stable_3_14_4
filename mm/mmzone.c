/*
 * linux/mm/mmzone.c
 *
 * management codes for pgdats, zones and page flags
 */


#include <linux/stddef.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
/*! 2016.11.05 study -ing  */
struct pglist_data *first_online_pgdat(void)
{
	/*! (&contig_page_data)  */
	return NODE_DATA(first_online_node);
}

struct pglist_data *next_online_pgdat(struct pglist_data *pgdat)
{
	int nid = next_online_node(pgdat->node_id);

	if (nid == MAX_NUMNODES)
		return NULL;
	return NODE_DATA(nid);
}

/*
 * next_zone - helper magic for for_each_zone()
 */
/*! 2016.11.05 study -ing  */
struct zone *next_zone(struct zone *zone)
{
	pg_data_t *pgdat = zone->zone_pgdat;

	if (zone < pgdat->node_zones + MAX_NR_ZONES - 1)
		zone++;
	else {
		pgdat = next_online_pgdat(pgdat);
		if (pgdat)
			zone = pgdat->node_zones;
		else
			zone = NULL;
	}
	return zone;
}

static inline int zref_in_nodemask(struct zoneref *zref, nodemask_t *nodes)
{
#ifdef CONFIG_NUMA
	return node_isset(zonelist_node_idx(zref), *nodes);
#else
	return 1;
#endif /* CONFIG_NUMA */
}

/* Returns the next zone at or below highest_zoneidx in a zonelist */
/*! From 'alloc_large_system_hash' -> '__alloc_pages_nodemask' -> 'first_zones_zonelist'
 * *z = &(contig_page_data.node_zonelists[0])->_zonerefs
 * highest_zoneidx = 0
 * *nodes = NULL
 * **zone = &preferred_zone
 * : Next zone 을 찾아서 preffered_zone에 넣어주고, 찾은 zone을 return 해 주는 함수
 */
struct zoneref *next_zones_zonelist(struct zoneref *z,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes,
					struct zone **zone)
{
	/*
	 * Find the next suitable zone to use for the allocation.
	 * Only filter based on nodemask if it's set
	 */
	/*! zonelist_zone_idx는 0으로 initialize 된 후, ZONE_DMA일 경우 0, ZONE_NORMAL과 etc 일 경우 1로 set.  */
	if (likely(nodes == NULL))
		while (zonelist_zone_idx(z) > highest_zoneidx)
			z++;
	else
		while (zonelist_zone_idx(z) > highest_zoneidx ||
				(z->zone && !zref_in_nodemask(z, nodes)))
			z++;

	*zone = zonelist_zone(z);
	return z;
}

#ifdef CONFIG_ARCH_HAS_HOLES_MEMORYMODEL
int memmap_valid_within(unsigned long pfn,
					struct page *page, struct zone *zone)
{
	if (page_to_pfn(page) != pfn)
		return 0;

	if (page_zone(page) != zone)
		return 0;

	return 1;
}
#endif /* CONFIG_ARCH_HAS_HOLES_MEMORYMODEL */

void lruvec_init(struct lruvec *lruvec)
{
	enum lru_list lru;

	memset(lruvec, 0, sizeof(struct lruvec));

	/*!
	 * #define for_each_lru(lru) 
	 * -> for (lru = 0; lru < NR_LRU_LISTS; lru++)
	*/
	for_each_lru(lru)
		INIT_LIST_HEAD(&lruvec->lists[lru]);
}

#if defined(CONFIG_NUMA_BALANCING) && !defined(LAST_CPUPID_NOT_IN_PAGE_FLAGS)
int page_cpupid_xchg_last(struct page *page, int cpupid)
{
	unsigned long old_flags, flags;
	int last_cpupid;

	do {
		old_flags = flags = page->flags;
		last_cpupid = page_cpupid_last(page);

		flags &= ~(LAST_CPUPID_MASK << LAST_CPUPID_PGSHIFT);
		flags |= (cpupid & LAST_CPUPID_MASK) << LAST_CPUPID_PGSHIFT;
	} while (unlikely(cmpxchg(&page->flags, old_flags, flags) != old_flags));

	return last_cpupid;
}
#endif

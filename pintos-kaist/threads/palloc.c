#include "threads/palloc.h"
#include <bitmap.h>
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "threads/init.h"
#include "threads/loader.h"
#include "threads/synch.h"
#include "threads/vaddr.h"


/* 페이지 할당자. 메모리를 페이지 크기(또는 페이지의 배수) 단위로 할당합니다.
   더 작은 크기의 메모리 할당이 필요하다면 malloc.h를 참고하세요.

   시스템 메모리는 커널 풀과 유저 풀이라는 두 개의 "풀"로 나뉩니다.
   유저 풀은 사용자(가상) 메모리 페이지를 위한 것이고,
   커널 풀은 그 외 모든 용도를 위한 것입니다.
   이렇게 나누는 이유는, 사용자 프로세스가 아무리 스왑을 많이 하더라도
   커널은 자신의 작업을 위한 메모리를 반드시 확보할 수 있도록 하기 위함입니다.

   기본적으로 시스템 RAM의 절반은 커널 풀에, 절반은 유저 풀에 할당됩니다.
   이는 커널 풀에는 지나치게 많은 양이지만, 데모 목적에는 충분합니다.
*/

/* A memory pool. */
struct pool {
	struct lock lock;               /* Mutual exclusion. */
	struct bitmap *used_map;        /* Bitmap of free pages. */
	uint8_t *base;                  /* Base of pool. */
};

/* Two pools: one for kernel data, one for user pages. */
static struct pool kernel_pool, user_pool;

/* Maximum number of pages to put in user pool. */
size_t user_page_limit = SIZE_MAX;
static void
init_pool (struct pool *p, void **bm_base, uint64_t start, uint64_t end);

static bool page_from_pool (const struct pool *, void *page);

/* multiboot info */
struct multiboot_info {
	uint32_t flags;
	uint32_t mem_low;
	uint32_t mem_high;
	uint32_t __unused[8];
	uint32_t mmap_len;
	uint32_t mmap_base;
};

/* e820 entry */
struct e820_entry {
	uint32_t size;
	uint32_t mem_lo;
	uint32_t mem_hi;
	uint32_t len_lo;
	uint32_t len_hi;
	uint32_t type;
};

/* Represent the range information of the ext_mem/base_mem */
struct area {
	uint64_t start;
	uint64_t end;
	uint64_t size;
};

#define BASE_MEM_THRESHOLD 0x100000
#define USABLE 1
#define ACPI_RECLAIMABLE 3
#define APPEND_HILO(hi, lo) (((uint64_t) ((hi)) << 32) + (lo))

/* e820 엔트리를 순회하며, basemem과 extmem의 범위를 파싱합니다. */
static void
resolve_area_info (struct area *base_mem, struct area *ext_mem) {
	struct multiboot_info *mb_info = ptov (MULTIBOOT_INFO);
	struct e820_entry *entries = ptov (mb_info->mmap_base);
	uint32_t i;

	for (i = 0; i < mb_info->mmap_len / sizeof (struct e820_entry); i++) {
		struct e820_entry *entry = &entries[i];
		if (entry->type == ACPI_RECLAIMABLE || entry->type == USABLE) {
			uint64_t start = APPEND_HILO (entry->mem_hi, entry->mem_lo);
			uint64_t size = APPEND_HILO (entry->len_hi, entry->len_lo);
			uint64_t end = start + size;
			printf("%llx ~ %llx %d\n", start, end, entry->type);

			struct area *area = start < BASE_MEM_THRESHOLD ? base_mem : ext_mem;

			// First entry that belong to this area.
			if (area->size == 0) {
				*area = (struct area) {
					.start = start,
					.end = end,
					.size = size,
				};
			} else {  // otherwise
				// Extend start
				if (area->start > start)
					area->start = start;
				// Extend end
				if (area->end < end)
					area->end = end;
				// Extend size
				area->size += size;
			}
		}
	}
}

/*
 * 풀(pool)을 채웁니다.
 * 코드 페이지를 포함한 모든 페이지는 이 할당자가 관리합니다.
 * 기본적으로 메모리의 절반은 커널에, 절반은 유저에 할당합니다.
 * base_mem 부분은 최대한 커널에 할당합니다.
 */
static void
populate_pools (struct area *base_mem, struct area *ext_mem) {
	extern char _end;
	void *free_start = pg_round_up (&_end);

	uint64_t total_pages = (base_mem->size + ext_mem->size) / PGSIZE;
	uint64_t user_pages = total_pages / 2 > user_page_limit ?
		user_page_limit : total_pages / 2;
	uint64_t kern_pages = total_pages - user_pages;

	// Parse E820 map to claim the memory region for each pool.
	enum { KERN_START, KERN, USER_START, USER } state = KERN_START;
	uint64_t rem = kern_pages;
	uint64_t region_start = 0, end = 0, start, size, size_in_pg;

	struct multiboot_info *mb_info = ptov (MULTIBOOT_INFO);
	struct e820_entry *entries = ptov (mb_info->mmap_base);

	uint32_t i;
	for (i = 0; i < mb_info->mmap_len / sizeof (struct e820_entry); i++) {
		struct e820_entry *entry = &entries[i];
		if (entry->type == ACPI_RECLAIMABLE || entry->type == USABLE) {
			start = (uint64_t) ptov (APPEND_HILO (entry->mem_hi, entry->mem_lo));
			size = APPEND_HILO (entry->len_hi, entry->len_lo);
			end = start + size;
			size_in_pg = size / PGSIZE;

			if (state == KERN_START) {
				region_start = start;
				state = KERN;
			}

			switch (state) {
				case KERN:
					if (rem > size_in_pg) {
						rem -= size_in_pg;
						break;
					}
					// generate kernel pool
					init_pool (&kernel_pool,
							&free_start, region_start, start + rem * PGSIZE);
					// Transition to the next state
					if (rem == size_in_pg) {
						rem = user_pages;
						state = USER_START;
					} else {
						region_start = start + rem * PGSIZE;
						rem = user_pages - size_in_pg + rem;
						state = USER;
					}
					break;
				case USER_START:
					region_start = start;
					state = USER;
					break;
				case USER:
					if (rem > size_in_pg) {
						rem -= size_in_pg;
						break;
					}
					ASSERT (rem == size);
					break;
				default:
					NOT_REACHED ();
			}
		}
	}

	// generate the user pool
	init_pool(&user_pool, &free_start, region_start, end);

	// e820_entry를 순회하며, 사용 가능한 영역을 설정합니다.
	uint64_t usable_bound = (uint64_t) free_start;
	struct pool *pool;
	void *pool_end;
	size_t page_idx, page_cnt;

	for (i = 0; i < mb_info->mmap_len / sizeof (struct e820_entry); i++) {
		struct e820_entry *entry = &entries[i];
		if (entry->type == ACPI_RECLAIMABLE || entry->type == USABLE) {
			uint64_t start = (uint64_t)
				ptov (APPEND_HILO (entry->mem_hi, entry->mem_lo));
			uint64_t size = APPEND_HILO (entry->len_hi, entry->len_lo);
			uint64_t end = start + size;

		// TODO: 0x1000 ~ 0x200000 영역을 추가하세요. 지금 당장은 중요한 문제가 아닙니다.
		// 이 구간의 모든 페이지는 사용할 수 없습니다.
		if (end < usable_bound)
				continue;

			start = (uint64_t)
				pg_round_up (start >= usable_bound ? start : usable_bound);
split:
			if (page_from_pool (&kernel_pool, (void *) start))
				pool = &kernel_pool;
			else if (page_from_pool (&user_pool, (void *) start))
				pool = &user_pool;
			else
				NOT_REACHED ();

			pool_end = pool->base + bitmap_size (pool->used_map) * PGSIZE;
			page_idx = pg_no (start) - pg_no (pool->base);
			if ((uint64_t) pool_end < end) {
				page_cnt = ((uint64_t) pool_end - start) / PGSIZE;
				bitmap_set_multiple (pool->used_map, page_idx, page_cnt, false);
				start = (uint64_t) pool_end;
				goto split;
			} else {
				page_cnt = ((uint64_t) end - start) / PGSIZE;
				bitmap_set_multiple (pool->used_map, page_idx, page_cnt, false);
			}
		}
	}
}

/* Initializes the page allocator and get the memory size */
uint64_t
palloc_init (void) {

	/* 링커가 기록한 커널의 끝 주소입니다.
	자세한 내용은 kernel.lds.S를 참고하세요. */
	extern char _end;
	struct area base_mem = { .size = 0 };
	struct area ext_mem = { .size = 0 };

	resolve_area_info (&base_mem, &ext_mem);
	printf ("Pintos booting with: \n");
	printf ("\tbase_mem: 0x%llx ~ 0x%llx (Usable: %'llu kB)\n",
		  base_mem.start, base_mem.end, base_mem.size / 1024);
	printf ("\text_mem: 0x%llx ~ 0x%llx (Usable: %'llu kB)\n",
		  ext_mem.start, ext_mem.end, ext_mem.size / 1024);
	populate_pools (&base_mem, &ext_mem);
	return ext_mem.end;
}


/* PAGE_CNT 개수만큼 연속된 빈 페이지를 얻어 반환합니다.
   PAL_USER가 설정되어 있으면 유저 풀에서, 아니면 커널 풀에서 페이지를 할당합니다.
   FLAGS에 PAL_ZERO가 설정되어 있으면, 페이지를 0으로 초기화합니다.
   사용 가능한 페이지가 부족하면 널 포인터를 반환합니다.
   단, FLAGS에 PAL_ASSERT가 설정되어 있으면 커널 패닉이 발생합니다.
*/
void *
palloc_get_multiple (enum palloc_flags flags, size_t page_cnt) {
	struct pool *pool = flags & PAL_USER ? &user_pool : &kernel_pool;

	lock_acquire (&pool->lock);
	size_t page_idx = bitmap_scan_and_flip (pool->used_map, 0, page_cnt, false);
	lock_release (&pool->lock);
	void *pages;

	if (page_idx != BITMAP_ERROR)
		pages = pool->base + PGSIZE * page_idx;
	else
		pages = NULL;

	if (pages) {
		if (flags & PAL_ZERO)
			memset (pages, 0, PGSIZE * page_cnt);
	} else {
		if (flags & PAL_ASSERT)
			PANIC ("palloc_get: out of pages");
	}

	return pages;
}


/* 빈 페이지 한 개를 얻어 그 커널 가상 주소를 반환합니다.
   PAL_USER가 설정되어 있으면 유저 풀에서, 아니면 커널 풀에서 할당합니다.
   FLAGS에 PAL_ZERO가 설정되어 있으면, 페이지를 0으로 초기화합니다.
   사용 가능한 페이지가 없으면 널 포인터를 반환합니다.
   단, FLAGS에 PAL_ASSERT가 설정되어 있으면 커널 패닉이 발생합니다.
*/
void *
palloc_get_page (enum palloc_flags flags) {
	return palloc_get_multiple (flags, 1);
}

/* PAGES에서 시작하는 PAGE_CNT 개의 페이지를 해제합니다. */
void
palloc_free_multiple (void *pages, size_t page_cnt) {
	struct pool *pool;
	size_t page_idx;

	ASSERT (pg_ofs (pages) == 0);
	if (pages == NULL || page_cnt == 0)
		return;

	if (page_from_pool (&kernel_pool, pages))
		pool = &kernel_pool;
	else if (page_from_pool (&user_pool, pages))
		pool = &user_pool;
	else
		NOT_REACHED ();

	page_idx = pg_no (pages) - pg_no (pool->base);

#ifndef NDEBUG
	memset (pages, 0xcc, PGSIZE * page_cnt);
#endif
	ASSERT (bitmap_all (pool->used_map, page_idx, page_cnt));
	bitmap_set_multiple (pool->used_map, page_idx, page_cnt, false);
}

/* Frees the page at PAGE. */
void
palloc_free_page (void *page) {
	palloc_free_multiple (page, 1);
}

/* 풀 P를 START에서 시작하여 END에서 끝나도록 초기화합니다. */
static void
init_pool (struct pool *p, void **bm_base, uint64_t start, uint64_t end) {
	/* 풀의 used_map(사용 비트맵)을 풀의 시작 부분에 위치시킵니다.
   비트맵에 필요한 공간을 계산하여 풀 크기에서 뺍니다.
	*/
	uint64_t pgcnt = (end - start) / PGSIZE;
	size_t bm_pages = DIV_ROUND_UP (bitmap_buf_size (pgcnt), PGSIZE) * PGSIZE;

	lock_init(&p->lock);
	p->used_map = bitmap_create_in_buf (pgcnt, *bm_base, bm_pages);
	p->base = (void *) start;

	// 모든 영역을 사용 불가로 표시합니다.
	bitmap_set_all(p->used_map, true);

	*bm_base += bm_pages;
}

/* PAGE가 POOL에서 할당된 경우 true를 반환하고, 그렇지 않으면 false를 반환합니다. */
static bool
page_from_pool (const struct pool *pool, void *page) {
	size_t page_no = pg_no (page);
	size_t start_page = pg_no (pool->base);
	size_t end_page = start_page + bitmap_size (pool->used_map);
	return page_no >= start_page && page_no < end_page;
}

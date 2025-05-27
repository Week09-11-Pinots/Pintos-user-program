/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "lib/kernel/bitmap.h"
#include "devices/disk.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

struct bitmap *swap_table;

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void vm_anon_init(void)
{
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);
	/** TODO: bitmap 자료구조로 스왑 테이블 만들기
	 * bitmap_create로 만들기
	 * 스왑 테이블 엔트리에 이 엔트리가 비어있다는 비트 필요
	 * bitmap 공부가 필요할듯
	 */
	disk_sector_t size = disk_size(swap_disk);
	size_t sector_size = size / PGSIZE;
	swap_table = bitmap_create(sector_size);
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva)
{
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	anon_page->swap_idx = -1;
}

/* 스왑 디스크에서 내용을 읽어와 페이지를 스왑인합니다. */
static bool
anon_swap_in(struct page *page, void *kva)
{
	struct anon_page *anon_page = &page->anon;
	int swap_idx = anon_page->swap_idx;
	// disk_read에서 사용할 버퍼
	void *buffer[PGSIZE];
	/** TODO: 페이지 스왑 인
	 * disk_read를 데이터를 읽고 kva에 데이터 복사
	 * swap_idx를 -1로 바꿔주어야 함
	 * 프레임 테이블에 해당 프레임 넣어주기
	 * 프레임하고 페이지 매핑해주기
	 */
}

/* 페이지의 내용을 스왑 디스크에 기록하여 스왑아웃합니다. */
static bool
anon_swap_out(struct page *page)
{
	struct anon_page *anon_page = &page->anon;
	/** TODO: disk_write를 사용하여 disk에 기록
	 * 섹터 크기는 512바이트라 8번 반복해야합니다
	 * 비어있는 스왑 슬롯을 스왑 테이블에서 검색
	 * 검색된 스왑 슬롯 인덱스를 anon_page에 저장
	 * disk_write를 통해 해당 디스크 섹터에 저장
	 */
}

/* 익명 페이지를 소멸시킵니다. PAGE는 호출자가 해제합니다. */
static void
anon_destroy(struct page *page)
{
	struct anon_page *anon_page = &page->anon;
}

/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

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
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva)
{
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
}

/* 스왑 디스크에서 내용을 읽어와 페이지를 스왑인합니다. */
static bool
anon_swap_in(struct page *page, void *kva)
{
	struct anon_page *anon_page = &page->anon;
}

/* 페이지의 내용을 스왑 디스크에 기록하여 스왑아웃합니다. */
static bool
anon_swap_out(struct page *page)
{
	struct anon_page *anon_page = &page->anon;
}

/* 익명 페이지를 소멸시킵니다. PAGE는 호출자가 해제합니다. */
static void
anon_destroy(struct page *page)
{
	struct anon_page *anon_page = &page->anon;
}

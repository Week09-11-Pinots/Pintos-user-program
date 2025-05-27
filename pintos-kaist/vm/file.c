/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void)
{
	/* 전역 자료구조 초기화 */
	/** TODO: mmap 리스트 초기화
	 * mmap으로 만들어진 페이지를 리스트로 관리하면
	 * munmmap 시에 더 빠르게 할 수 있을 듯 합니다
	 *
	 */
}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva)
{
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
	/** TODO: file 백업 정보를 초기화
	 * file_page에 어떤 정보가 있는지에 따라 다름
	 * 타입도 변환?
	 */
}

/* 파일에서 내용을 읽어와 페이지를 스왑인합니다. */
static bool
file_backed_swap_in(struct page *page, void *kva)
{
	struct file_page *file_page UNUSED = &page->file;
	// swap_in을 위한 버퍼
	void *buffer[PGSIZE];
	/** TODO: 파일에서 정보를 읽어와 kva에 복사하세요
	 * aux에 저장된 백업 정보를 사용하세요
	 * file_open과 read를 사용하면 될 것 같아요
	 * 파일 시스템 동기화가 필요할수도 있어요
	 * 필요시 file_backed_initializer를 수정하세요
	 */
}

/* 페이지의 내용을 파일에 기록(writeback)하여 스왑아웃합니다. */
static bool
file_backed_swap_out(struct page *page)
{
	struct file_page *file_page UNUSED = &page->file;
	/** TODO: dirty bit 확인해서 write back
	 * pml4_is_dirty를 사용해서 dirty bit를 확인하세요
	 * write back을 할 때는 aux에 저장된 파일 정보를 사용
	 * file_write를 사용하면 될 것 같아요
	 * dirty_bit 초기화 (pml4_set_dirty)
	 */
}

/* 파일 기반 페이지를 소멸시킵니다. PAGE는 호출자가 해제합니다. */
static void
file_backed_destroy(struct page *page)
{
	struct file_page *file_page UNUSED = &page->file;
	/** TODO: dirty_bit 확인 후 write_back
	 * pml4_is_dirty를 사용해서 dirty bit 확인
	 * write back을 할 때는 aux에 저장된 파일 정보를 사용
	 * file_write를 사용하면 될 것 같아요
	 */
}

/* Do the mmap */
void *
do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset)
{
	// aux에 넣어줄 정보
	size_t zero_byte = PGSIZE - length;
	/** TODO: AUX 만들기
	 * file 포인터
	 * file 오프셋
	 * read byte = length
	 * zero byte
	 * mapping 카운트
	 */
	void *aux = NULL;

	// TODO: 지연 로딩 함수 포인터 집어넣기
	vm_alloc_page_with_initializer(VM_MMAP, addr, writable, NULL, aux);
}

/* Do the munmap */
void do_munmap(void *addr)
{
}

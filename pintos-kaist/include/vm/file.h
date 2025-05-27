#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;

struct file_page
{
	/* dirty bit가 명시적으로 필요한가??
	어차피 PTE의 dirty bit가 있는데  */

	// file_backup 정보를 필드로 두어도 될듯함
};

void vm_file_init(void);
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable,
			  struct file *file, off_t offset);
void do_munmap(void *va);
#endif

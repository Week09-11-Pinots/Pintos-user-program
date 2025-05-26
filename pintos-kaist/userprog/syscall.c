#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "lib/kernel/console.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "lib/user/syscall.h"
#include "vm/vm.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
static int sys_write(int fd, const void *buffer, unsigned size);
void sys_exit(int);
static void sys_halt();
bool sys_create(const char *file, unsigned initial_size);
bool sys_remove(const char *file);
int sys_open(const char *file);
int sys_filesize(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int find_unused_fd(const char *file);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void check_buffer(const void *buffer, unsigned size);
int sys_wait(tid_t pid);
int sys_dup2(int oldfd, int newfd);

struct lock filesys_lock;
/* 시스템 콜.
 *
 * 이전에는 시스템 콜 서비스가 인터럽트 핸들러(예: 리눅스의 int 0x80)에 의해 처리되었습니다.
 * 하지만 x86-64에서는 제조사가 시스템 콜을 요청하는 효율적인 경로인 `syscall` 명령어를 제공합니다.
 *
 * syscall 명령어는 모델별 레지스터(MSR)의 값을 읽어서 동작합니다.
 * 자세한 내용은 매뉴얼을 참고하세요.
 */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	/*시스템 콜 진입점 주소를 MSR_LSTAR에 기록. syscall_entry 는 시스템 콜 진입점, 유저 모드에서
	시스템 콜을 실행했을 때 커널 모드로 전환 */
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* 인터럽트 서비스 루틴은 시스템 엔트리가 유저모드 스택에서 커널모드 스택으로
	전환할때 까지 어떠한 인터럽트도 제공해서는 안된다. 그러므로, 우리는 만드시 FLAG_FL을 마스크 해야 한다.
	시스템 콜 핸들러 진입 시 유저가 조작할 수 없도록 마스킹할 플래그를 지정한다. 즉, 시스템 콜
	진입 시 위 플래그들은 자동으로 0이되어, 유저 프로세스가 커널에 영향을 주지 못하게 막는다.
 */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&filesys_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	uint64_t syscall_num = f->R.rax;
	uint64_t arg1 = f->R.rdi;
	uint64_t arg2 = f->R.rsi;
	uint64_t arg3 = f->R.rdx;
	uint64_t arg4 = f->R.r10;
	uint64_t arg5 = f->R.r8;
	uint64_t arg6 = f->R.r9;

	switch (syscall_num)
	{
	case SYS_HALT:
		sys_halt();
		break;
	case SYS_EXIT:
		sys_exit(arg1);
		break;
	case SYS_FORK:
		f->R.rax = process_fork((const char *)arg1, f);
		break;
	case SYS_EXEC:
		f->R.rax = sys_exec((void *)arg1);
		break;
	case SYS_WAIT:
		f->R.rax = sys_wait((tid_t)arg1);
		break;
	case SYS_CREATE:
		f->R.rax = sys_create(arg1, arg2);
		break;
	case SYS_REMOVE:
		f->R.rax = sys_remove(arg1);
		break;
	case SYS_OPEN:
		f->R.rax = sys_open(arg1);
		break;
	case SYS_FILESIZE:
		f->R.rax = sys_filesize(arg1);
		break;
	case SYS_READ:
		f->R.rax = sys_read(arg1, arg2, arg3);
		break;
	case SYS_WRITE:
		f->R.rax = sys_write(arg1, arg2, arg3);
		break;
	case SYS_SEEK:
		sys_seek(arg1, arg2);
		break;
	case SYS_TELL:
		f->R.rax = sys_tell(arg1);
		break;
	case SYS_CLOSE:
		sys_close(arg1);
		break;
	case SYS_DUP2:
		f->R.rax = sys_dup2(arg1, arg2);
		break;
	case SYS_MMAP:
		f->R.rax = sys_mmap(arg1, arg2, arg3, arg4, arg5);
		break;
	case SYS_MUNMAP:
		break;
	default:
		thread_exit();
		break;
	}
}

// 주소값이 유저 영역(0x8048000~0xc0000000)에서 사용하는 주소값인지 확인하는 함수
void check_address(const uint64_t *addr)
{
	struct thread *cur = thread_current();

	if (addr == "" || !(is_user_vaddr(addr)) || pml4_get_page(cur->pml4, addr) == NULL)
	{
		sys_exit(-1);
	}
}

void check_buffer(const void *buffer, unsigned size)
{
	uint8_t *start = (uint8_t *)pg_round_down(buffer);
	uint8_t *end = (uint8_t *)pg_round_down(buffer + size - 1);
	struct thread *cur = thread_current();

	for (uint8_t *addr = start; addr <= end; addr += PGSIZE)
	{
		if (!is_user_vaddr(addr) || pml4_get_page(cur->pml4, addr) == NULL)
		{
			// printf("Invalid page address: %p\n", addr);
			sys_exit(-1);
		}
	}
}

/* addr은 mmap으로 할당받은 시작주소 */
void sys_munmap(void *addr)
{
	/** TODO: mmap으로 매핑된 모든 페이지를 없애야함
	 * 1. SPT에서 제거
	 * 2. 물리 페이지에서도 제거
	 * 3. 매핑 카운트나 page 구조체 내의 카운트를 사용해서 제거
	 */
}

void *sys_mmap(void *addr, size_t length, int writable, int fd, off_t offset)
{
	int filesize = sys_filesize(fd);
	if (filesize == 0 || length == 0 || fd == 0 || fd == 1)
		return MAP_FAILED;

	if ((uint64_t)addr == 0 || (uint64_t)addr % PGSIZE != 0)
		return MAP_FAILED;

	void *start_page = addr;
	void *end_page = addr + length;

	for (; end_page > start_page; start_page + PGSIZE)
	{
		if (spt_find_page(thread_current()->spt, start_page) != NULL)
			return MAP_FAILED;
	}

	size_t remain_length = length;
	void *cur_addr = addr;
	off_t cur_offset = offset;

	while (remain_length > 0)
	{
		size_t allocate_length = remain_length > PGSIZE ? PGSIZE : remain_length;
		do_mmap(cur_addr, allocate_length, writable, thread_current()->fd_table[fd], cur_offset);
		remain_length -= PGSIZE;
		cur_addr += PGSIZE;
		cur_offset += PGSIZE;
	}

	return addr;
}

int sys_exec(char *file_name)
{
	check_address(file_name);

	int size = strlen(file_name) + 1;
	char *fn_copy = palloc_get_page(PAL_ZERO);
	if ((fn_copy) == NULL)
	{
		sys_exit(-1);
	}
	strlcpy(fn_copy, file_name, size);

	if (process_exec(fn_copy) == -1)
	{
		sys_exit(-1);
	}

	NOT_REACHED();
	return 0;
}

struct file *
process_get_file(int fd)
{
	struct thread *cur = thread_current();

	if (fd < 2 || fd > MAX_FD)
		return NULL;

	return cur->fd_table[fd];
}

void sys_halt()
{
	power_off();
}

static int sys_write(int fd, const void *buffer, unsigned size)
{
	check_buffer(buffer, size);
	// fd가 유효한지 먼저 검사
	if (fd < 0 || fd >= MAX_FD)
		return -1;

	struct thread *cur = thread_current();

	if (cur->fd_table[fd] == STDOUT && cur->stdout_count != 0)
	{
		putbuf(buffer, size);
		return size;
	}
	struct file *f = process_get_file(fd);
	if (f == NULL)
		return -1;

	lock_acquire(&filesys_lock);
	int bytes_written = file_write(f, buffer, size);
	lock_release(&filesys_lock);
	return bytes_written;
}

void sys_exit(int status)
{
	struct thread *cur = thread_current();
	cur->exit_status = status;

	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

bool sys_create(const char *file, unsigned initial_size)
{
	check_address(file);
	if (file == NULL || strcmp(file, "") == 0)
	{
		sys_exit(-1);
	}
	return filesys_create(file, initial_size);
}

bool sys_remove(const char *file)
{
	return filesys_remove(file);
}

int sys_filesize(int fd)
{
	// 현재 스레드의 fd_table에서 해당 fd에 대응되는 file 구조체를 가져온다
	struct thread *cur = thread_current();

	// fd가 음수거나 MAX_FD 초과인 경우
	if (fd < 0 || fd >= MAX_FD)
	{
		return -1;
	}

	// 파일 객체 가져오기
	struct file *file_obj = cur->fd_table[fd];
	if (file_obj == NULL)
	{
		return -1;
	}

	off_t size = file_length(file_obj);
	return size;
}

int sys_read(int fd, void *buffer, unsigned size)
{

	if (size == 0)
		return 0;

	check_buffer(buffer, size); // 페이지 단위 검사

	struct thread *cur = thread_current();

	if (fd < 0 || fd >= MAX_FD)
	{
		return -1;
	}

	// stdin 처리
	if (cur->fd_table[fd] == STDIN)
	{
		if (cur->stdin_count != 0)
		{
			for (unsigned i = 0; i < size; i++)
			{
				((char *)buffer)[i] = input_getc();
			}
			return size;
		}
		return -1;
	}

	struct file *file_obj = cur->fd_table[fd];

	if (file_obj == NULL || file_obj == STDIN || file_obj == STDOUT)
	{
		return -1;
	}

	// 파일 읽기
	lock_acquire(&filesys_lock);
	int bytes_read = file_read(file_obj, buffer, size);
	lock_release(&filesys_lock);
	return bytes_read;
}

int find_unused_fd(const char *file)
{
	struct thread *cur = thread_current();

	while (cur->fd_table[cur->fd_idx] && cur->fd_idx < MAX_FD)
		cur->fd_idx++;

	if (cur->fd_idx >= MAX_FD)
		return -1;

	cur->fd_table[cur->fd_idx] = file;

	return cur->fd_idx;
}

int sys_open(const char *file)
{
	check_address(file);
	if (file == NULL || strcmp(file, "") == 0)
	{
		return -1;
	}
	lock_acquire(&filesys_lock);
	struct file *file_obj = filesys_open(file);
	if (file_obj == NULL)
	{
		return -1;
	}

	int fd = find_unused_fd(file_obj);
	lock_release(&filesys_lock);
	return fd;
}

/* 현재 열린 파일의 커서 위치를 지정한 위치로 이동하는 시스템 콜 */
void sys_seek(int fd, unsigned position)
{
	struct thread *cur = thread_current();

	/* 유효하지 않은 파일 디스크립터인 경우 아무 작업도 하지 않음 */
	if (fd < 0 || fd >= MAX_FD || cur->fd_table[fd] == STDIN || cur->fd_table[fd] == STDOUT)
	{
		return;
	}

	/* fd 테이블에서 해당 파일 객체 가져오기 */
	struct file *file_obj = cur->fd_table[fd];

	/* 파일이 열려 있지 않다면 리턴 */
	if (file_obj == NULL)
	{
		return;
	}

	/* 파일 끝을 넘어가는 포인터 이동 방어 */
	off_t length = file_length(file_obj);
	if (position > length)
		position = length;

	/* 파일의 현재 읽기/쓰기 위치를 position으로 이동 */
	file_seek(file_obj, position);
}

/* 현재 열린 파일의 커서 위치를 바이트 단위로 반환하는 시스템 콜 */
unsigned sys_tell(int fd)
{
	struct thread *cur = thread_current();

	/* 유효하지 않은 파일 디스크립터인 경우 -1 반환 (unsigned지만 오류 표시로 사용) */
	if (fd < 0 || fd >= MAX_FD)
	{
		return -1;
	}

	/* fd 테이블에서 해당 파일 객체 가져오기 */
	struct file *file_obj = cur->fd_table[fd];

	/* 파일이 열려 있지 않다면 -1 반환 */
	if (file_obj == NULL)
	{
		return -1;
	}

	/* 현재 파일의 커서 위치 반환 */
	return file_tell(file_obj);
}

void sys_close(int fd)
{
	struct thread *curr = thread_current();
	if (fd < 0 || fd >= MAX_FD)
		return;

	if (curr->fd_table[fd] == STDIN)
		curr->stdin_count--;

	if (curr->fd_table[fd] == STDOUT)
		curr->stdout_count--;

	struct file *file_object = curr->fd_table[fd];
	if (file_object == NULL || file_object == STDIN || file_object == STDOUT)
	{
		curr->fd_table[fd] = NULL;
		return;
	}
	decrease_dup_count(file_object);

	if (check_dup_count(file_object) == 0)
		file_close(file_object);
	curr->fd_table[fd] = NULL;
}

int sys_wait(tid_t pid)
{
	int status = process_wait(pid);
	return status;
}

int sys_dup2(int oldfd, int newfd)
{
	struct thread *cur = thread_current();

	/* oldfd가 유효하지 않으면, 실패하며 -1을 반환하고, newfd는 닫히지 않습니다. */
	if (oldfd < 0 || oldfd >= MAX_FD)
		return -1;

	if (cur->fd_table[oldfd] == NULL)
		return -1;

	/* oldfd와 newfd가 같으면, 아무 동작도 하지 않고 newfd를 반환합니다. */
	if (oldfd == newfd)
		return newfd;

	if (cur->fd_table[oldfd] == STDIN)
		cur->stdin_count++;
	else if (cur->fd_table[oldfd] == STDOUT)
		cur->stdout_count++;
	else
		increase_dup_count(cur->fd_table[oldfd]);

	/* newfd가 이미 열려 있는 경우, 조용히 닫은 후에 oldfd를 복제합니다. */
	if (cur->fd_table[newfd] != NULL)
	{
		lock_acquire(&filesys_lock);
		sys_close(newfd);
		lock_release(&filesys_lock);
	}
	cur->fd_table[newfd] = cur->fd_table[oldfd];

	return newfd;
}
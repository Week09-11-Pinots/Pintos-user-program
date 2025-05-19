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
#include "filesys/file.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
static int sys_write(int fd, const void *buffer, unsigned size);
static void sys_exit(int);
static void sys_halt();
bool sys_create(const char *file, unsigned initial_size);
bool sys_remove(const char *file);
int sys_open(const char *file);
int sys_filesize(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int find_unused_fd(const char *file);
static struct file *find_file_by_fd(int fd);
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
		break;
	case SYS_WAIT:
		f->R.rax = process_wait((tid_t)arg1);
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
		break;
	case SYS_TELL:
		break;
	case SYS_CLOSE:
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
	// printf("buffer ? : %p\n", buffer);
	check_buffer(buffer, size);

	if (fd == 1)
	{
		putbuf(buffer, size);
		return size;
	}
	struct file *f = process_get_file(fd);
	if (f == NULL)
		return -1;

	int bytes_written = file_write(f, buffer, size);
	return bytes_written;
}

static void sys_exit(int status)
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

	for (size_t i = 0; i < size; i++)
	{
		uint8_t *addr = (uint8_t *)buffer + i;
		if (!is_user_vaddr(addr) || pml4_get_page(thread_current()->pml4, addr) == NULL)
			sys_exit(-1);
	}

	struct thread *cur = thread_current();

	if (fd < 0 || fd >= MAX_FD)
	{
		return -1;
	}

	// stdin 처리
	if (fd == 0)
	{
		for (unsigned i = 0; i < size; i++)
		{
			((char *)buffer)[i] = input_getc();
		}
		return size;
	}

	struct file *file_obj = cur->fd_table[fd];
	if (file_obj == NULL)
	{
		return -1;
	}

	// 파일 읽기
	int bytes_read = file_read(file_obj, buffer, size);
	return bytes_read;
}

int find_unused_fd(const char *file)
{
	struct thread *cur = thread_current();

	for (int i = 2; i <= MAX_FD; i++)
	{
		if (cur->fd_table[i] == NULL)
		{
			cur->fd_table[i] = file;
			return i;
		}
	}
}

int sys_open(const char *file)
{
	check_address(file);
	if (file == NULL || strcmp(file, "") == 0)
	{
		return -1;
	}
	struct file *file_obj = filesys_open(file);
	if (file_obj == NULL)
	{
		return -1;
	}
	int fd = find_unused_fd(file_obj);
	return fd;
}
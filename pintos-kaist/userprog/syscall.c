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

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
static int sys_write(int fd, const void *buffer, unsigned size);
static void sys_exit(int);
static void sys_halt();
bool sys_create(const char *file, unsigned initial_size);
bool sys_remove(const char *file);
int sys_open(const char *file);

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
		break;
	case SYS_READ:
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

void sys_halt(){
	power_off();
}

static int sys_write(int fd, const void *buffer, unsigned size)
{
	if (fd == 1)
	{
		putbuf(buffer, size);
		return size;
	}
	return -1;
}

static void sys_exit(int status)
{
	struct thread *cur = thread_current();
	cur->exit_status = status;

	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
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

bool sys_create(const char *file, unsigned initial_size){
	check_address(file);
	if(file==NULL||strcmp(file, "") == 0) {
		sys_exit(-1);
	}
	return filesys_create(file, initial_size);
}

bool sys_remove(const char *file)
{
	return filesys_remove(file);
}

int find_unused_fd(const char *file){
	struct thread *cur = thread_current();
	
	for(int i=2; i<=MAX_FD; i++ ){
		if(cur->fd_table[i]==NULL){
			cur->fd_table[i]=file;
			return i;
		}
	}
}

int
sys_open (const char *file) {
	check_address(file);
	if(file==NULL||strcmp(file, "") == 0){
		return -1;
	}
	struct file *file_obj= filesys_open(file);
	if(file_obj ==NULL) {
		return -1;
	}

	int fd=find_unused_fd(file_obj);
	return fd;
}
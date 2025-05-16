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

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
static int sys_write(int fd, const void *buffer, unsigned size);

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
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* 인터럽트 서비스 루틴은 syscall_entry가 사용자 스택을 커널 모드 스택으로
	 * 교체할 때까지 어떤 인터럽트도 처리하지 않아야 합니다.
	 * 따라서 FLAG_FL을 마스킹했습니다. */
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

	switch (syscall_num)
	{
	case SYS_WRITE:
		f->R.rax = sys_write(arg1, (const void *)arg2, arg3);
		break;

	default:
		break;
	}
	// TODO: Your implementation goes here.
	printf("system call!\n");
	thread_exit();
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
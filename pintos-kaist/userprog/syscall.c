#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
// #include "include/threads/init.h"
// #include "include/lib/kernel/console.h"
#include "filesys/file.h"
#include "filesys/filesys.h"


void syscall_entry (void);
void syscall_handler (struct intr_frame *);

void sys_halt();
int sys_exit(int status);
int sys_write(int fd, const void *buffer, unsigned size);
bool sys_create(const char *file, unsigned initial_size);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {

	// printf("SYSCALL_INIT \n");
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	/*시스템 콜 진입점 주소를 MSR_LSTAR에 기록. syscall_entry 는 시스템 콜 진입점, 유저 모드에서 
	시스템 콜을 실행했을 때 커널 모드로 전환 */
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry); 

	/* 인터럽트 서비스 루틴은 시스템 엔트리가 유저모드 스택에서 커널모드 스택으로 
	전환할때 까지 어떠한 인터럽트도 제공해서는 안된다. 그러므로, 우리는 만드시 FLAG_FL을 마스크 해야 한다.
	시스템 콜 핸들러 진입 시 유저가 조작할 수 없도록 마스킹할 플래그를 지정한다. 즉, 시스템 콜
	진입 시 위 플래그들은 자동으로 0이되어, 유저 프로세스가 커널에 영향을 주지 못하게 막는다.
 */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	// printf("SYSCALL_INIT END!!!!\n");

}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {

	struct gp_registers regi=f->R;
	/*
	1. rdi
	2. rsi
	3. rdx
	4. r10
	5. r8
	6. r9
	*/

	// printf("syscall_handler\n");
	// printf("%lld\n",regi.rax);
	switch (regi.rax)
	{
	case SYS_HALT:
		sys_halt();
		break;
	case SYS_EXIT:
		sys_exit(regi.rdi);
		break;
	case SYS_FORK:
		break;
	case SYS_EXEC:
		break;
	case SYS_CREATE:
		sys_create(regi.rdi, regi.rsi);
		break;
	case SYS_REMOVE:
		break;
	case SYS_OPEN:
		break;
	case SYS_FILESIZE:
		break;
	case SYS_READ:
		break;
	case SYS_WRITE:
		sys_write(regi.rdi,regi.rsi,regi.rdx);
		break;
	case SYS_SEEK:
		break;
	case SYS_TELL:
		break;
	case SYS_CLOSE:
		break;
	default:
		printf ("system call!\n");
		thread_exit ();
		break;
	}

}

void sys_halt(){
	printf("SYSCALL_HALT \n");

	power_off();
}

int sys_exit(int status){
	struct thread *curr = thread_current ();
	curr->exit_status=status;
	printf ("%s: exit(%d)\n", curr->name,  status);
	thread_exit();
}

int sys_write(int fd, const void *buffer, unsigned size){
	int byte=0;
	// printf("Write 잘못임?\n");
	if(fd==1){
		putbuf(buffer, size);
		byte=size;
		return byte;
	}
	return -1;
}

bool sys_create(const char *file, unsigned initial_size){
	return filesys_create(file, initial_size);
}

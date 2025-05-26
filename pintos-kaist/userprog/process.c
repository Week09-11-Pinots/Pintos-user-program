#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

#define MAX_ARGS 128
#define MAX_BUF 128

static void process_cleanup(void);
static bool load(const char *file_name, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);
static int parse_args(char *, char *[]);
static bool setup_stack(struct intr_frame *if_);
static struct thread *get_my_child(tid_t tid);

/* General process initializer for initd and other process. */
static void process_init(void)
{
	struct thread *current = thread_current();
	// current->fd_table = calloc(MAX_FD, sizeof(struct file *));
	current->fd_table = palloc_get_multiple(PAL_ZERO, FDT_PAGES);
	current->fd_idx = 2;
	current->fd_table[0] = STDIN;
	current->fd_table[1] = STDOUT;
	current->stdin_count = 1;
	current->stdout_count = 1;
	ASSERT(current->fd_table != NULL);
	sema_init(&current->fork_sema, 0);
}

/* 첫 번째 사용자 프로그램인 "initd"를 FILE_NAME에서 로드하여 시작합니다.
 * 새 스레드는 스케줄링 될 수 있으며 (그리고 심지어 종료될 수도 있음)
 * process_create_initd()가 반환되기 전에.
 * initd의 스레드 ID를 반환하거나, 생성할 수 없으면 TID_ERROR를 반환합니다.
 * 이 함수는 반드시 한 번만 호출되어야 합니다. */
tid_t process_create_initd(const char *file_name)
{
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page(0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy(fn_copy, file_name, PGSIZE);

	/* 이 코드를 넣어줘야 thread_name이 file name이 됩니다  */
	char *save_ptr;
	strtok_r(file_name, " ", &save_ptr);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create(file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page(fn_copy);

	return tid;
}

/* 첫 번째 사용자 프로세스를 시작하는 스레드 함수입니다. */
static void
initd(void *f_name)
{
#ifdef VM
	supplemental_page_table_init(&thread_current()->spt);
#endif

	process_init();

	if (process_exec(f_name) < 0)
	{
		PANIC("Fail to launch initd\n");
	}
	NOT_REACHED();
}

/* 현재 프로세스를 `name`이라는 이름으로 복제합니다.
 * 새 프로세스의 스레드 ID를 반환하거나, 생성할 수 없으면 TID_ERROR를 반환합니다. */

tid_t process_fork(const char *name, struct intr_frame *if_ UNUSED)
{
	struct fork_info *info = malloc(sizeof(struct fork_info));
	ASSERT(info != NULL);
	struct thread *parent = thread_current();
	info->parent = parent;
	memcpy(&info->parent_if, if_, sizeof(struct intr_frame));

	tid_t child_tid = thread_create(name, PRI_DEFAULT, __do_fork, info);

	if (child_tid == TID_ERROR || child_tid == NULL)
	{
		free(info);
		return TID_ERROR;
	}

	sema_down(&parent->fork_sema); // 동기화를 위한 sema_down
	struct thread *child = get_my_child(child_tid);
	free(info);
	if (child->exit_status == TID_ERROR)
		return TID_ERROR;
	return child_tid;
}

#ifndef VM
/* 부모의 주소 공간을 복제하기 위해 이 함수를 pml4_for_each에 전달합니다.
 * 이 함수는 project 2에서만 사용됩니다. */
static bool
duplicate_pte(uint64_t *pte, void *va, void *aux)
{
	struct thread *current = thread_current();
	struct thread *parent = (struct thread *)aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: parent_page가 커널 페이지이면 즉시 반환해야 합니다. */
	if (is_kernel_vaddr(va))
		return true;

	/* 2. 부모의 page map level 4에서 VA를 해석합니다. */
	parent_page = pml4_get_page(parent->pml4, va);
	if (parent_page == NULL)
		return true;

	/* 3. TODO: 자식 프로세스를 위해 새로운 PAL_USER 페이지를 할당하고 결과를
	 *    TODO: NEWPAGE에 저장해야 합니다. */
	/* PAL_USER = 유저 풀에서 페이지를 할당해라 */
	newpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (newpage == NULL)
		return false;

	/* 4. TODO: 부모 페이지를 새 페이지에 복사하고
	 *    TODO: 부모 페이지가 쓰기 가능한지 여부를 검사합니다.
	 *    TODO: 결과에 따라 WRITABLE을 설정합니다. */
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);

	/* 5. VA 주소에 WRITABLE 권한으로 새 페이지를 자식의 페이지 테이블에 추가합니다. */
	if (!pml4_set_page(current->pml4, va, newpage, writable))
	{
		palloc_free_page(newpage);
		return false;
	}
	return true;
}
#endif

/* 부모의 실행 컨텍스트를 복사하는 스레드 함수입니다.
 * 힌트) parent->tf는 프로세스의 사용자 영역 컨텍스트를 저장하지 않습니다.
 *       즉, 이 함수에는 process_fork의 두 번째 인자인 if_를 넘겨야 합니다. */
static void
__do_fork(void *aux)
{
	struct fork_info *info = aux;
	struct intr_frame if_;
	struct thread *parent = info->parent;
	struct thread *current = thread_current();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = &info->parent_if;
	bool succ = true;

	/* 1. CPU 컨텍스트를 지역 스택으로 복사합니다. */
	memcpy(&if_, parent_if, sizeof(struct intr_frame));

	/* 2. 페이지 테이블 복제 */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate(current);
#ifdef VM
	supplemental_page_table_init(&current->spt);
	if (!supplemental_page_table_copy(&current->spt, &parent->spt))
		goto error;
#else
	if (parent->pml4 == NULL)
		printf("pml4 is null\n");
	if (!pml4_for_each(parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	process_init();
	/* TODO: 이 아래에 코드를 작성해야 합니다.
	 * TODO: 힌트) 파일 객체를 복제하려면 include/filesys/file.h의 `file_duplicate`를 사용하세요.
	 * TODO:       이 함수가 부모의 자원을 성공적으로 복제할 때까지 부모는 fork()에서 반환되면 안 됩니다. */
	/* 부모의 fd_table을 순회하며 복사 */
	if (parent->fd_idx == MAX_FD)
		goto error;

	for (int fd = 0; fd < MAX_FD; fd++)
	{
		if (fd <= 1)
			current->fd_table[fd] = parent->fd_table[fd];
		else
		{
			if (parent->fd_table[fd] != NULL)
			{
				if (parent->fd_table[fd] == STDIN || parent->fd_table[fd] == STDOUT)
					current->fd_table[fd] = parent->fd_table[fd];
				else
					current->fd_table[fd] = file_duplicate(parent->fd_table[fd]);
			}
		}
	}
	current->fd_idx = parent->fd_idx;
	/* extra2 */
	current->stdin_count = parent->stdin_count;
	current->stdout_count = parent->stdout_count;

	if_.R.rax = 0;

	/* 마침내 새로 생성된 프로세스로 전환합니다. */
	sema_up(&parent->fork_sema); // 동기화 완료, 부모 프로세스 락 해제
	if (succ)
		do_iret(&if_); // 이 임시 인터럽트 프레임의 정보를 가지고 유저 모드로 점프
error:
	sema_up(&parent->fork_sema);
	sys_exit(TID_ERROR);
}

/* 현재 실행 컨텍스트를 f_name으로 전환합니다.
 * 실패 시 -1을 반환합니다. */
int process_exec(void *f_name)
{
	char *file_name = f_name;
	char cp_file_name[MAX_BUF];
	memcpy(cp_file_name, file_name, strlen(file_name) + 1);
	bool success;

	/* intr_frame을 thread 구조체 안의 것을 사용할 수 없습니다.
	 * 이는 현재 스레드가 재스케줄될 때,
	 * 그 실행 정보를 해당 멤버에 저장하기 때문입니다. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* 현재 컨텍스트를 제거합니다. */
	process_cleanup();

	/* 그리고 이진 파일을 로드합니다. */
	ASSERT(cp_file_name != NULL);
	success = load(cp_file_name, &_if);

	palloc_free_page(file_name);
	if (!success)
		return -1;
	thread_current()->running_file = filesys_open(cp_file_name);
	file_deny_write(thread_current()->running_file);

	// hex_dump(_if.rsp, _if.rsp, USER_STACK - (uint64_t)_if.rsp, true);
	/* 프로세스를 전환합니다. */
	do_iret(&_if);
	NOT_REACHED();
}

static int parse_args(char *target, char *argv[])
{
	int argc = 0;
	char *token;
	char *save_ptr; // 파싱 상태를 저장할 변수!

	for (token = strtok_r(target, " ", &save_ptr);
		 token != NULL;
		 token = strtok_r(NULL, " ", &save_ptr))
	{
		argv[argc++] = token; // 각 인자의 포인터 저장
	}
	argv[argc] = NULL; // 마지막에 NULL로 끝맺기(C 관례)

	return argc;
}

/* TID 프로세스가 종료되기를 기다리고, exit status를 반환합니다.
 * 만약 커널에 의해 종료되었다면 (즉, 예외로 인해 kill된 경우), -1을 반환합니다.
 * TID가 유효하지 않거나 호출 프로세스의 자식이 아니거나,
 * 이미 해당 TID에 대해 process_wait()가 호출된 적이 있다면,
 * 즉시 -1을 반환하고 기다리지 않습니다.
 *
 * 이 함수는 문제 2-2에서 구현될 예정입니다. 지금은 아무 것도 하지 않습니다. */
int process_wait(tid_t child_tid UNUSED)
{
	/* XXX: 힌트) pintos는 process_wait(initd)를 호출하면 종료되므로,
	 * XXX:       process_wait을 구현하기 전까지는 여기에 무한 루프를 넣는 것을 추천합니다. */

	struct thread *cur = thread_current();
	if (list_empty(&cur->children_list))
		return -1;

	struct thread *child = get_my_child(child_tid);
	if (child == NULL)
		return -1;
	/* 자식의 wait_sema를 대기합니다. process_exit에서 wait_sema를 up 해줍니다 */
	sema_down(&child->wait_sema);
	int status = child->exit_status;
	list_remove(&child->child_elem);
	sema_up(&child->free_sema);
	if (status < 0)
		return -1;
	return status;
}

/* 자신의 자식 리스트를 순회하며 인자로 받은 tid가 자신의 자식이 맞는지 확인하고, 해당 자식 스레드를 반환합니다 */
static struct thread *get_my_child(tid_t tid)
{
	struct list_elem *e;
	struct thread *cur = thread_current();
	for (e = list_begin(&cur->children_list); e != list_end(&cur->children_list); e = list_next(e))
	{
		struct thread *child = list_entry(e, struct thread, child_elem);
		if (child->tid == tid)
			return child;
	}
	return NULL;
}

/* 프로세스를 종료합니다. 이 함수는 thread_exit()에 의해 호출됩니다. */
void process_exit(void)
{
	struct thread *curr = thread_current();

	/* TODO: 여기에 코드를 작성하세요.
	 * TODO: 프로세스 종료 메시지를 구현하세요 (project2/process_termination.html 참고).
	 * TODO: 우리는 이곳에 프로세스 자원 정리를 구현하는 것을 추천합니다. */
	/* fd 테이블 정리 */

	if (curr->fd_table != NULL)
	{
		for (int i = 0; i < MAX_FD; i++)
		{
			if (curr->fd_table[i] != NULL)
			{
				sys_close(i);
				curr->fd_table[i] = NULL;
			}
		}
	}

	palloc_free_multiple(curr->fd_table, FDT_PAGES);
	if (curr->running_file != NULL)
	{
		file_allow_write(curr->running_file);
		file_close(curr->running_file);
	}

	sema_up(&curr->wait_sema);
	sema_down(&curr->free_sema);
	process_cleanup();
}

/* 현재 프로세스의 자원을 해제합니다. */
static void
process_cleanup(void)
{
	struct thread *curr = thread_current();

#ifdef VM
	supplemental_page_table_kill(&curr->spt);
#endif

	uint64_t *pml4;
	/* 현재 프로세스의 페이지 디렉터리를 제거하고,
	 * 커널 전용 페이지 디렉터리로 전환합니다. */
	pml4 = curr->pml4;
	if (pml4 != NULL)
	{

		/* 여기서의 순서가 매우 중요합니다. 우리는
		 * cur->pagedir를 NULL로 설정한 후에 페이지 디렉터리를 전환해야 합니다.
		 * 그렇지 않으면 timer 인터럽트가 다시 프로세스의 페이지 디렉터리로 전환될 수 있습니다.
		 * 활성 페이지 디렉터리를 제거하기 전에 커널 전용 페이지 디렉터리로 전환해야 합니다.
		 * 그렇지 않으면 현재 활성 페이지 디렉터리가 제거된 것(혹은 초기화된 것)이 될 수 있습니다. */
		curr->pml4 = NULL;
		pml4_activate(NULL);
		pml4_destroy(pml4);
	}
}

/* 사용자 코드 실행을 위해 CPU를 설정합니다.
 * 이 함수는 매 context switch 때마다 호출됩니다. */
void process_activate(struct thread *next)
{
	/* 스레드의 페이지 테이블을 활성화합니다. */
	pml4_activate(next->pml4);

	/* 인터럽트 처리를 위해 스레드의 커널 스택을 설정합니다. */
	tss_update(next);
}

/* ELF 실행 파일을 로드합니다.
다음 정의들은 ELF 사양서 [ELF1]에서 가져온 것입니다. */

/* ELF 타입. [ELF1] 1-2 참고. */
#define EI_NIDENT 16

#define PT_NULL 0			/* Ignore. */
#define PT_LOAD 1			/* Loadable segment. */
#define PT_DYNAMIC 2		/* Dynamic linking info. */
#define PT_INTERP 3			/* Name of dynamic loader. */
#define PT_NOTE 4			/* Auxiliary info. */
#define PT_SHLIB 5			/* Reserved. */
#define PT_PHDR 6			/* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

/* ELF 실행 파일의 헤더. [ELF1] 1-4 ~ 1-8 참고.
 * ELF 바이너리의 가장 앞에 위치합니다. */
struct ELF64_hdr
{
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR
{
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
						 uint32_t read_bytes, uint32_t zero_bytes,
						 bool writable);

/* FILE_NAME에서 현재 스레드로 ELF 실행 파일을 로드합니다.
 * 실행 진입점은 *RIP에, 초기 스택 포인터는 *RSP에 저장됩니다.
 * 성공 시 true, 실패 시 false를 반환합니다. */
static bool
load(const char *file_name, struct intr_frame *if_)
{
	struct thread *t = thread_current();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	char *argv[MAX_ARGS];
	int argc = parse_args(file_name, argv);
	uint64_t rsp_arr[argc];

	/* 페이지 디렉터리를 할당하고 활성화합니다. */
	t->pml4 = pml4_create();
	if (t->pml4 == NULL)
		goto done;
	process_activate(thread_current());

	/* 실행 파일을 엽니다. */
	file = filesys_open(file_name);
	if (file == NULL)
	{
		printf("load: %s: open failed\n", file_name);
		goto done;
	}

	/* 실행 헤더를 읽고 검증합니다. */
	if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 0x3E // amd64
		|| ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) || ehdr.e_phnum > 1024)
	{
		printf("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* 프로그램 헤더들을 읽습니다. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++)
	{
		struct Phdr phdr;

#ifdef WSL
		// WSL 전용 코드
		off_t phdr_ofs = ehdr.e_phoff + i * sizeof(struct Phdr);
		file_seek(file, phdr_ofs);
		if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
#else
		// docker(기본) 전용 코드
		if (file_ofs < 0 || file_ofs > file_length(file))
			goto done;
		file_seek(file, file_ofs);
#endif

		if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type)
		{
		case PT_NULL:
		case PT_NOTE:
		case PT_PHDR:
		case PT_STACK:
		default:
			/* 이 segment는 무시합니다. */
			break;
		case PT_DYNAMIC:
		case PT_INTERP:
		case PT_SHLIB:
			goto done;
		case PT_LOAD:
			if (validate_segment(&phdr, file))
			{
				bool writable = (phdr.p_flags & PF_W) != 0;
				uint64_t file_page = phdr.p_offset & ~PGMASK;
				uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
				uint64_t page_offset = phdr.p_vaddr & PGMASK;
				uint32_t read_bytes, zero_bytes;
				if (phdr.p_filesz > 0)
				{
					/* Normal segment.
					 * Read initial part from disk and zero the rest. */
					read_bytes = page_offset + phdr.p_filesz;
					zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
				}
				else
				{
					/* Entirely zero.
					 * Don't read anything from disk. */
					read_bytes = 0;
					zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
				}
				if (!load_segment(file, file_page, (void *)mem_page,
								  read_bytes, zero_bytes, writable))
					goto done;
			}
			else
				goto done;
			break;
		}
	}

	/* 스택을 설정합니다. */
	if (!setup_stack(if_))
		goto done;

	/* 시작 주소를 설정합니다. */
	if_->rip = ehdr.e_entry;

	/* TODO: 여기에 코드를 작성하세요.
	 * TODO: 인자 전달을 구현하세요 (project2/argument_passing.html 참고). */
	for (int i = argc - 1; i >= 0; i--)
	{
		if_->rsp -= strlen(argv[i]) + 1;
		rsp_arr[i] = if_->rsp;
		memcpy((void *)if_->rsp, argv[i], strlen(argv[i]) + 1);
	}

	while (if_->rsp % 8 != 0)
	{
		if_->rsp--;				  // 주소값을 1 내리고
		*(uint8_t *)if_->rsp = 0; // 데이터에 0 삽입 => 8바이트 저장
	}

	if_->rsp -= 8; // NULL 문자열을 위한 주소 공간, 64비트니까 8바이트 확보
	memset(if_->rsp, 0, sizeof(char **));

	for (int i = argc - 1; i >= 0; i--)
	{
		if_->rsp -= 8; // 8바이트만큼 rsp감소
		memcpy(if_->rsp, &rsp_arr[i], sizeof(char **));
	}

	if_->rsp -= 8;
	memset(if_->rsp, 0, sizeof(void *));

	if_->R.rdi = argc;
	if_->R.rsi = if_->rsp + 8;

	success = true;

done:
	/* load의 성공 여부와 상관없이 여기로 도달합니다. */
	file_close(file);
	return success;
}

/* PHDR가 FILE에서 유효하고 로드 가능한 세그먼트를 설명하는지 확인하고,
 * 그렇다면 true, 아니라면 false를 반환합니다. */
static bool
validate_segment(const struct Phdr *phdr, struct file *file)
{
	/* p_offset과 p_vaddr은 같은 페이지 오프셋을 가져야 합니다. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset은 FILE 내부를 가리켜야 합니다. */
	if (phdr->p_offset > (uint64_t)file_length(file))
		return false;

	/* p_memsz는 최소한 p_filesz보다 크거나 같아야 합니다. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* 세그먼트는 비어 있으면 안 됩니다. */
	if (phdr->p_memsz == 0)
		return false;

	/* 가상 메모리 영역은 사용자 주소 공간 범위 내에 있어야 합니다. */

	if (!is_user_vaddr((void *)phdr->p_vaddr))
		return false;
	if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* 메모리 영역은 커널 가상 주소 공간을 넘어 wrap-around 되면 안 됩니다. */

	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* 페이지 0 매핑을 금지합니다.
	 * 페이지 0을 매핑하는 것은 좋은 아이디어가 아닐 뿐만 아니라,
	 * 허용할 경우, 사용자 코드가 null 포인터를 시스템 콜에 넘길 때
	 * 커널에서 null 포인터 예외 (ex: memcpy 등)로 패닉이 발생할 수 있습니다. */

	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* 이 블록의 코드는 project 2에서만 사용됩니다.
 * 전체 project 2를 위해 이 함수를 구현하려면, #ifndef 바깥에 구현하세요. */

/* load() helpers. */
static bool install_page(void *upage, void *kpage, bool writable);

/* segment를 FILE의 OFS 오프셋에서 UPAGE 주소에 로드합니다.
 * 총 READ_BYTES + ZERO_BYTES 바이트의 가상 메모리가 다음과 같이 초기화됩니다:
 *
 * - READ_BYTES 바이트는 FILE에서 읽어옵니다.
 * - UPAGE + READ_BYTES 위치에서 ZERO_BYTES 바이트를 0으로 초기화합니다.
 *
 * 이 함수로 초기화된 페이지는 WRITABLE이 true이면 사용자 프로세스가 수정할 수 있으며,
 * 아니라면 읽기 전용입니다.
 *
 * 성공 시 true, 메모리 할당 오류나 디스크 읽기 오류 발생 시 false를 반환합니다. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
			 uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	file_seek(file, ofs);
	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* 이 페이지를 어떻게 채울지 계산합니다.
		 * FILE에서 PAGE_READ_BYTES 바이트를 읽고
		 * 남은 PAGE_ZERO_BYTES 바이트는 0으로 초기화합니다. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* 메모리 한 페이지를 가져옵니다. */
		uint8_t *kpage = palloc_get_page(PAL_USER);
		if (kpage == NULL)
			return false;

		/* 이 페이지를 로드합니다. */
		if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes)
		{
			palloc_free_page(kpage);
			return false;
		}
		memset(kpage + page_read_bytes, 0, page_zero_bytes);

		/* 프로세스 주소 공간에 페이지를 추가합니다. */
		if (!install_page(upage, kpage, writable))
		{
			printf("install page 실패: upage = %p\n", upage);
			printf("fail\n");
			palloc_free_page(kpage);
			return false;
		}

		/* 한 페이지씩 앞으로 진행합니다. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* USER_STACK 위치에 zero 페이지를 매핑하여 최소한의 스택을 생성합니다. */
static bool
setup_stack(struct intr_frame *if_)
{
	uint8_t *kpage;
	bool success = false;

	/* USER_STACK : 유저 스택의 최상단 주소, 즉 맨 마지막 페이지 (아래로 자라니까) */
	kpage = palloc_get_page(PAL_USER | PAL_ZERO); // 유저 공간에, 0으로 초기화된 페이지 할당
	if (kpage != NULL)
	{
		/* 유저 스택의 맨 마지막 페이지를 매핑 */
		success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK; /* 유저 스택 포인터 (rsp)를 맨 위로 지정 */
		else
			palloc_free_page(kpage); /* 실패하면 할당받은 페이지를 free */
	}
	return success;
}

/* 사용자 가상 주소 UPAGE를 커널 가상 주소 KPAGE에 매핑합니다.
 * WRITABLE이 true이면 사용자 프로세스는 해당 페이지를 수정할 수 있습니다.
 * 아니라면 읽기 전용입니다.
 * UPAGE는 이미 매핑되어 있으면 안 됩니다.
 * KPAGE는 보통 palloc_get_page()로 얻은 페이지여야 합니다.
 * 성공 시 true, 실패 시 false를 반환합니다. */
static bool
install_page(void *upage, void *kpage, bool writable)
{
	struct thread *t = thread_current();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page(t->pml4, upage) == NULL && pml4_set_page(t->pml4, upage, kpage, writable));
}
#else
/* 여기부터 코드는 project 3 이후 사용됩니다.
 * project 2만을 위해 함수를 구현하려면 위쪽 블록에서 구현하세요. */

static bool
lazy_load_segment(struct page *page, void *aux)
{
	/* TODO: Load the segment from the file */
	/* TODO: 이 함수는 해당 VA(가상 주소)에서 첫 페이지 폴트가 발생할 때 호출됩니다. */
	/* TODO: 이 함수를 호출할 때 VA는 사용할 수 있습니다. */

	// kva는 page 안에 이미 있다
	// 타입별로 다른 초기화 작업을 거쳐야하나?
}

/* FILE의 OFS 오프셋에서 시작하여 UPAGE 주소에 세그먼트를 로드합니다.
 * 총 READ_BYTES + ZERO_BYTES 바이트의 가상 메모리가 다음과 같이 초기화됩니다:
 *
 * - UPAGE에서 READ_BYTES 바이트는 FILE에서 OFS 오프셋부터 읽어옵니다.
 *
 * - UPAGE + READ_BYTES 위치에서 ZERO_BYTES 바이트는 0으로 초기화됩니다.
 *
 * 이 함수로 초기화된 페이지는 WRITABLE이 true이면 사용자 프로세스가 수정할 수 있으며,
 * 아니라면 읽기 전용입니다.
 *
 * 메모리 할당 오류나 디스크 읽기 오류가 발생하면 false를 반환하고,
 * 성공하면 true를 반환합니다.
 */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
			 uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* 이 페이지를 어떻게 채울지 계산합니다.
		 * FILE에서 PAGE_READ_BYTES 바이트를 읽고
		 * 남은 PAGE_ZERO_BYTES 바이트는 0으로 초기화합니다. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE; // 4KB까지만 읽어라
		size_t page_zero_bytes = PGSIZE - page_read_bytes;					// 0 패딩 사이즈는 4KB - read_byte

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL; // 전달해야할 인자
		if (!vm_alloc_page_with_initializer(VM_ANON, upage,
											writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack(struct intr_frame *if_)
{
	bool success = false;
	void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

	/* TODO: stack_bottom 위치에 스택을 매핑하고 즉시 페이지를 확보하세요.
	* TODO: 성공했다면 rsp 값을 적절히 설정하세요.
	* TODO: 해당 페이지가 스택임을 표시해야 합니다. */
	/* TODO: Your code goes here */
	vm_do_claim_page(stack_bottom);

	return success;
}
#endif /* VM */

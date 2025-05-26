#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "threads/fixed-point.h"
#include "threads/synch.h"

#ifdef VM
#include "vm/vm.h"
#endif

/* States in a thread's life cycle. */
enum thread_status
{
	THREAD_RUNNING, /* Running thread. */
	THREAD_READY,	/* Not running but ready to run. */
	THREAD_BLOCKED, /* Waiting for an event to trigger. */
	THREAD_DYING	/* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) - 1) /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0	   /* Lowest priority. */
#define PRI_DEFAULT 31 /* Default priority. */
#define PRI_MAX 63	   /* Highest priority. */
// #define MAX_FD 128
/* Project 2 */
#define FDT_PAGES 3					// pages to allocate for file descriptor tables (thread_create, process_exit)
#define MAX_FD FDT_PAGES * (1 << 9) // Limit fd_idx

/* Project2 - extra */
#define STDIN 1
#define STDOUT 2

/* 커널 스레드 또는 유저 프로세스.
 *
 * 각 스레드 구조체는 자신만의 4KB 페이지에 저장됩니다.
 * 스레드 구조체 자체는 페이지의 맨 아래(오프셋 0)에 위치합니다.
 * 페이지의 나머지 부분은 해당 스레드의 커널 스택을 위해 예약되어 있으며,
 * 커널 스택은 페이지의 맨 위(오프셋 4KB)에서 아래 방향으로 성장합니다.
 * 아래는 이를 나타낸 그림입니다:
 *
 *      4 kB +---------------------------------+
 *           |          커널 스택               |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         아래로 성장함            |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * 이 구조의 중요한 점은 두 가지입니다:
 *
 *    1. 첫째, `struct thread`의 크기가 너무 커지면 안 됩니다.
 *       만약 커진다면 커널 스택을 위한 공간이 부족해질 수 있습니다.
 *       기본 `struct thread`는 몇 바이트밖에 되지 않습니다.
 *       1KB 이하로 유지하는 것이 좋습니다.
 *
 *    2. 둘째, 커널 스택 역시 너무 커지면 안 됩니다.
 *       만약 스택이 오버플로우되면 스레드 상태가 손상될 수 있습니다.
 *       따라서 커널 함수에서는 큰 구조체나 배열을 비정적 지역 변수로 선언하지 말아야 합니다.
 *       대신 malloc()이나 palloc_get_page()와 같은 동적 할당을 사용하세요.
 *
 * 이 두 가지 문제 중 어느 하나라도 발생하면,
 * 실행 중인 스레드의 `struct thread`의 `magic` 멤버가 THREAD_MAGIC으로 설정되어 있는지 확인하는
 * thread_current()에서 assertion 실패가 가장 먼저 나타날 것입니다.
 * 스택 오버플로우가 발생하면 이 값이 변하게 되어 assertion이 트리거됩니다.
 */
/* `elem` 멤버는 두 가지 용도로 사용됩니다.
 * run queue(thread.c)의 요소가 될 수도 있고,
 * 세마포어 대기 리스트(synch.c)의 요소가 될 수도 있습니다.
 * 이 두 가지 용도로 사용할 수 있는 이유는 상호 배타적이기 때문입니다:
 * ready 상태의 스레드만 run queue에 들어가고,
 * blocked 상태의 스레드만 세마포어 대기 리스트에 들어갑니다.
 */

struct thread
{
	/* Owned by thread.c. */
	tid_t tid;				   /* Thread identifier. */
	enum thread_status status; /* Thread state. */
	char name[16];			   /* Name (for debugging purposes). */
	int priority;			   /* 기부받은 우선순위 */
	int original_priority;	   /* 원래의 우선순위 */

	/* Shared between thread.c and synch.c. */
	struct list_elem elem; /* List element. */
	struct list donations; /* 자신한테 기부해준 리스트 */
	struct lock *pending_lock;

	int nice;			// 양보하려는 정도?
	fixed_t recent_cpu; // CPU를 얼마나 점유했나?
	struct list_elem all_elem;
	// TODO : 동적할당으로 해야할지도
	struct file **fd_table; // 파일 디스크럽터 테이블
	int fd_idx;
	struct semaphore fork_sema; // fork 동기화를 위한 세마포어
	struct semaphore wait_sema; // wait를 위한 세마포어
	struct semaphore free_sema; // 받았음을 전달하는 세마포어

	struct list children_list; /* 나의 자식 프로세스 리스트 */
	struct list_elem child_elem;
	struct file *running_file;
	int exit_status; /* 종료 코드 저장 */

	int stdin_count;
	int stdout_count;

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4; /* Page map level 4 */

#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf; /* Information for switching */
	unsigned magic;		  /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority, thread_func *, void *);

void thread_block(void);
void thread_unblock(struct thread *);

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

int thread_get_priority(void);
void thread_set_priority(int);
void compare_cur_next_priority(void);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

void update_priority(struct thread *);
void update_all_priority(void);
void update_recent_cpu(void);
void update_recent_cpu_all(void);
void update_load_avg(void);
void mlfqs_on_tick(void);

void do_iret(struct intr_frame *tf);

typedef struct __donation__
{
	struct list_elem elem;
	int priority;
	struct thread *donor;
	struct lock *lock;
} donation;

struct fork_info
{
	struct thread *parent;
	struct intr_frame parent_if;
};

#endif /* threads/thread.h */
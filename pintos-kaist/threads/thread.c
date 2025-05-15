#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
// #include "threads/fixed-point.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;   /* # of timer ticks spent idle. */
static long long kernel_ticks; /* # of timer ticks in kernel threads. */
static long long user_ticks;   /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4		  /* # of timer ticks to give each thread. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;
static struct list all_list;

static void kernel_thread(thread_func *, void *aux);

static void idle(void *aux UNUSED);
static struct thread *next_thread_to_run(void);
static void init_thread(struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule(void);
static tid_t allocate_tid(void);
static bool compare_priority(const struct list_elem *a, const struct list_elem *b, void *aux);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *)(pg_round_down(rrsp())))

// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = {0,
						  0x00af9a000000ffff,
						  0x00cf92000000ffff};

fixed_t load_avg = 0;

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void thread_init(void)
{
	ASSERT(intr_get_level() == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof(gdt) - 1,
		.address = (uint64_t)gdt};
	lgdt(&gdt_ds);

	/* Init the globla thread context */
	lock_init(&tid_lock);
	list_init(&ready_list);
	list_init(&destruction_req);
	list_init(&all_list);

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread();
	init_thread(initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void thread_start(void)
{
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init(&idle_started, 0);
	thread_create("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down(&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void thread_tick(void)
{
	struct thread *t = thread_current();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	// 매 timer tick마다 MLFQS 업데이트 트리거
	if (thread_mlfqs)
	{
		mlfqs_on_tick(); // running thread의 recent_cpu++, 주기적 갱신 처리
	}
	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return();
}

/* Prints thread statistics. */
void thread_print_stats(void)
{
	printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
		   idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t thread_create(const char *name, int priority,
					thread_func *function, void *aux)
{
	struct thread *t;
	tid_t tid;

	ASSERT(function != NULL);

	/* Allocate thread. */
	t = palloc_get_page(PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread(t, name, priority);

	// 2. 고급 스케줄러가 켜져 있다면:

	// MLFQS가 활성화되어 있다면, 새 스레드의 priority를 자동 계산해줌
	if (thread_mlfqs)
	{
		update_priority(t); // recent_cpu, nice 기반으로 계산
	}

	tid = t->tid = allocate_tid();

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t)kernel_thread;
	t->tf.R.rdi = (uint64_t)function;
	t->tf.R.rsi = (uint64_t)aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	/* Add to run queue. */
	thread_unblock(t);

	struct thread *cur = thread_current();

	if (compare_priority(&t->elem, &cur->elem, NULL))
		thread_yield();

	return tid;
}

/* 인자로 받은 스레드의 recent_cpu를 수정하는 함수입니다.
모든 스레드 업데이트에서 사용하기 위해 인자를 void를 thread로 수정했습니다 */
void update_recent_cpu(void)
{
	thread_current()->recent_cpu = add_fp_int(thread_current()->recent_cpu, 1);
}

/* load_avg를 계산하는 함수입니다. mlfqs_on_tick에서 1초마다 호출되어야 합니다
다음 수식을 구현해야 합니다
load_avg = (59/60) * load_avg + (1/60) * ready_threads_size
*/
void update_load_avg(void)
{
	int ready_threads = list_size(&ready_list);
	if (thread_current() != idle_thread)
		ready_threads++;

	fixed_t term1 = div_fp_int(mul_fp_int(load_avg, 59), 60); // (59 * load_avg) / 60
	fixed_t term2 = mul_fp_int(div_fp_int(int_to_fp(1), 60), ready_threads);

	load_avg = add_fp(term1, term2);
}

/* 인자로 받은 스레드의 우선순위를 계산하는 함수입니다.
모든 스레드 업데이트에서 사용하기위해 인자를 void 에서 thread로 수정했습니다 */
void update_priority(struct thread *thread) // 4틱마다 계산
{
	if (thread == idle_thread)
		return;

	int new_priority = PRI_MAX - fp_to_int_round(div_fp_int(thread->recent_cpu, 4)) - (thread->nice * 2);

	// Clamp to [PRI_MIN, PRI_MAX]
	if (new_priority > PRI_MAX)
		new_priority = PRI_MAX;
	if (new_priority < PRI_MIN)
		new_priority = PRI_MIN;

	thread->priority = new_priority;
}

/* 모든 스레드의 CPU 점유율을 계산하는 함수입니다.
mlfqs_on_tick에서 사용되어야 합니다 */
void update_recent_cpu_all(void)
{
	/* TODO :
	recent_cpu = (2 * load_avg) / (2 * load_avg + 1) * recent_cpu + nice
	와 같은 계산식을 사용하여 CPU 점유율을 다시 계산해야 합니다
	*/
	struct list_elem *e;
	for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e))
	{
		struct thread *entry = list_entry(e, struct thread, all_elem);
		if (entry->status == THREAD_DYING || entry == idle_thread)
			continue;
		fixed_t coeff = div_fp(
			mul_fp_int(load_avg, 2),
			add_fp_int(mul_fp_int(load_avg, 2), 1));

		entry->recent_cpu = add_fp(
			mul_fp(coeff, entry->recent_cpu),
			int_to_fp(entry->nice));
	}
}

/* 모든 스레드의 우선순위를 계산하는 함수입니다.
mlfqs_on_tick에서 사용되어야 합니다 */
void update_all_priority(void)
{
	// TODO : 모든 리스트 순회하며 update_priority 호출
	struct list_elem *e;
	for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e))
	{
		struct thread *entry = list_entry(e, struct thread, all_elem);
		if (entry->status == THREAD_DYING || entry == idle_thread)
			continue;
		update_priority(entry);
	}
	compare_cur_next_priority();
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void thread_block(void)
{
	ASSERT(!intr_context());
	ASSERT(intr_get_level() == INTR_OFF);
	thread_current()->status = THREAD_BLOCKED;
	schedule();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void thread_unblock(struct thread *t)
{
	enum intr_level old_level;

	ASSERT(is_thread(t));

	old_level = intr_disable(); // 인터럽트 끄기 -> 레이스 컨디션 방지
	ASSERT(t->status == THREAD_BLOCKED);

	list_insert_ordered(&ready_list, &t->elem, compare_priority, NULL); // 우선순위 순으로 레디 큐에 저장
	t->status = THREAD_READY;

	intr_set_level(old_level); // 인터럽트 다시 켜기
}

static bool compare_priority(const struct list_elem *a, const struct list_elem *b, void *aux)
{
	struct thread *t1 = list_entry(a, struct thread, elem);
	struct thread *t2 = list_entry(b, struct thread, elem);

	return t1->priority > t2->priority;
}

/* Returns the name of the running thread. */
const char *
thread_name(void)
{
	return thread_current()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current(void)
{
	struct thread *t = running_thread();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT(is_thread(t));
	ASSERT(t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t thread_tid(void)
{
	return thread_current()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void thread_exit(void)
{
	ASSERT(!intr_context());

#ifdef USERPROG
	process_exit();
#endif
	struct thread *cur = thread_current();
	list_remove(&cur->all_elem);

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable();
	do_schedule(THREAD_DYING);
	NOT_REACHED();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void thread_yield(void)
{
	// dprintf("thread_yield\n");
	struct thread *curr = thread_current();
	enum intr_level old_level;
	// dprintf("현재 실행 쓰레드 : %s\n", thread_name());
	// dprintf("현재 레디 리스트 사이즈 : %d\n", list_size(&ready_list));

	ASSERT(!intr_context());

	old_level = intr_disable();
	if (curr != idle_thread)
		// list_push_back(&ready_list, &curr->elem);
		list_insert_ordered(&ready_list, &curr->elem, compare_priority, NULL); // 우선순위 순으로 레디 큐에 저장
	do_schedule(THREAD_READY);
	intr_set_level(old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void thread_set_priority(int new_priority)
{
	// 고급 스케줄러에서는 priority를 수동으로 설정할 수 없기 때문에 무시
	if (thread_mlfqs)
		return;

	// (기존 donation 처리 등은 기본 스케줄러일 때만 유효)
	struct thread *cur = thread_current();
	thread_current()->original_priority = new_priority;

	if (list_empty(&cur->donations))
	{
		cur->priority = new_priority;
	}
	else
	{
		int first_priority = list_entry(list_front(&cur->donations), donation, elem)->priority;
		if (first_priority > new_priority)
			cur->priority = first_priority;
		else
			cur->priority = new_priority;
	}

	compare_cur_next_priority();
}

void compare_cur_next_priority(void)
{
	if (list_empty(&ready_list))
	{
		return;
	}

	list_sort(&ready_list, compare_priority, NULL);
	struct thread *next = list_entry(list_front(&ready_list), struct thread, elem);
	if (next->priority > thread_current()->priority)
	{
		if (intr_context())
			intr_yield_on_return();
		else
			thread_yield();
	}
}

/* Returns the current thread's priority. */
int thread_get_priority(void)
{
	return thread_current()->priority;
}

/* Sets the current thread's nice value to NICE. */
void thread_set_nice(int nice UNUSED)
{
	struct thread *cur = thread_current();
	cur->nice = nice;

	// nice값이 바뀌었으니 priority도 다시 계산함
	update_priority(cur);

	// 만약 ready_list에 더 높은 priority가 있으면 양보
	compare_cur_next_priority();
}

/* Returns the current thread's nice value. */
int thread_get_nice(void)
{
	return thread_current()->nice;
}

/* Returns 100 times the system load average. */
int thread_get_load_avg(void)
{
	return fp_to_int_round(load_avg * 100);
}

/* Returns 100 times the current thread's recent_cpu value. */
int thread_get_recent_cpu(void)
{
	return fp_to_int_round(thread_current()->recent_cpu * 100);
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle(void *idle_started_ UNUSED)
{
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current();
	sema_up(idle_started);

	for (;;)
	{
		/* Let someone else run. */
		intr_disable();
		thread_block();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread(thread_func *function, void *aux)
{
	ASSERT(function != NULL);

	intr_enable(); /* The scheduler runs with interrupts off. */
	function(aux); /* Execute the thread function. */
	thread_exit(); /* If function() returns, kill the thread. */
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread(struct thread *t, const char *name, int priority)
{
	ASSERT(t != NULL);
	ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT(name != NULL);

	memset(t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy(t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t)t + PGSIZE - sizeof(void *);
	t->priority = priority;
	t->original_priority = priority;
	t->pending_lock = NULL;
	t->magic = THREAD_MAGIC;

	if (thread_mlfqs)
	{
		if (t == initial_thread)
		{
			// 최초 스레드는 기본값으로 초기화
			t->nice = 0;
			t->recent_cpu = int_to_fp(0);
		}
		else if (t != initial_thread)
		{
			// 새로 생성되는 스레드는 부모(현재 스레드)의 값을 상속받음
			t->nice = thread_current()->nice;
			t->recent_cpu = thread_current()->recent_cpu;
		}
	}

	list_init(&t->donations);
	list_push_back(&all_list, &t->all_elem);
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run(void)
{
	if (list_empty(&ready_list))
		return idle_thread;
	else
		return list_entry(list_pop_front(&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void do_iret(struct intr_frame *tf)
{
	__asm __volatile(
		"movq %0, %%rsp\n"
		"movq 0(%%rsp),%%r15\n"
		"movq 8(%%rsp),%%r14\n"
		"movq 16(%%rsp),%%r13\n"
		"movq 24(%%rsp),%%r12\n"
		"movq 32(%%rsp),%%r11\n"
		"movq 40(%%rsp),%%r10\n"
		"movq 48(%%rsp),%%r9\n"
		"movq 56(%%rsp),%%r8\n"
		"movq 64(%%rsp),%%rsi\n"
		"movq 72(%%rsp),%%rdi\n"
		"movq 80(%%rsp),%%rbp\n"
		"movq 88(%%rsp),%%rdx\n"
		"movq 96(%%rsp),%%rcx\n"
		"movq 104(%%rsp),%%rbx\n"
		"movq 112(%%rsp),%%rax\n"
		"addq $120,%%rsp\n"
		"movw 8(%%rsp),%%ds\n"
		"movw (%%rsp),%%es\n"
		"addq $32, %%rsp\n"
		"iretq"
		: : "g"((uint64_t)tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch(struct thread *th)
{
	uint64_t tf_cur = (uint64_t)&running_thread()->tf;
	uint64_t tf = (uint64_t)&th->tf;
	ASSERT(intr_get_level() == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile(
		/* Store registers that will be used. */
		"push %%rax\n"
		"push %%rbx\n"
		"push %%rcx\n"
		/* Fetch input once */
		"movq %0, %%rax\n"
		"movq %1, %%rcx\n"
		"movq %%r15, 0(%%rax)\n"
		"movq %%r14, 8(%%rax)\n"
		"movq %%r13, 16(%%rax)\n"
		"movq %%r12, 24(%%rax)\n"
		"movq %%r11, 32(%%rax)\n"
		"movq %%r10, 40(%%rax)\n"
		"movq %%r9, 48(%%rax)\n"
		"movq %%r8, 56(%%rax)\n"
		"movq %%rsi, 64(%%rax)\n"
		"movq %%rdi, 72(%%rax)\n"
		"movq %%rbp, 80(%%rax)\n"
		"movq %%rdx, 88(%%rax)\n"
		"pop %%rbx\n" // Saved rcx
		"movq %%rbx, 96(%%rax)\n"
		"pop %%rbx\n" // Saved rbx
		"movq %%rbx, 104(%%rax)\n"
		"pop %%rbx\n" // Saved rax
		"movq %%rbx, 112(%%rax)\n"
		"addq $120, %%rax\n"
		"movw %%es, (%%rax)\n"
		"movw %%ds, 8(%%rax)\n"
		"addq $32, %%rax\n"
		"call __next\n" // read the current rip.
		"__next:\n"
		"pop %%rbx\n"
		"addq $(out_iret -  __next), %%rbx\n"
		"movq %%rbx, 0(%%rax)\n" // rip
		"movw %%cs, 8(%%rax)\n"	 // cs
		"pushfq\n"
		"popq %%rbx\n"
		"mov %%rbx, 16(%%rax)\n" // eflags
		"mov %%rsp, 24(%%rax)\n" // rsp
		"movw %%ss, 32(%%rax)\n"
		"mov %%rcx, %%rdi\n"
		"call do_iret\n"
		"out_iret:\n"
		: : "g"(tf_cur), "g"(tf) : "memory");
}

/* 새로운 프로세스를 스케줄링합니다. 진입 시 인터럽트는 꺼져 있어야 합니다.
 * 이 함수는 현재 스레드의 상태를 status로 수정한 다음,
 * 실행할 다른 스레드를 찾아 해당 스레드로 전환합니다.
 * schedule()에서 printf()를 호출하는 것은 안전하지 않습니다. */
static void
do_schedule(int status)
{
	ASSERT(intr_get_level() == INTR_OFF);
	ASSERT(thread_current()->status == THREAD_RUNNING);
	while (!list_empty(&destruction_req))
	{
		struct thread *victim =
			list_entry(list_pop_front(&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current()->status = status;
	schedule();
}

static void
schedule(void)
{
	struct thread *curr = running_thread();
	struct thread *next = next_thread_to_run();

	ASSERT(intr_get_level() == INTR_OFF);
	ASSERT(curr->status != THREAD_RUNNING);
	ASSERT(is_thread(next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate(next);
#endif

	if (curr != next)
	{
		/* 우리가 전환한 스레드가 종료 상태라면, 해당 스레드의 구조체를 파괴합니다.
		   이는 thread_exit()가 실행 중인 스레드의 자원을 미리 해제하지 않도록
		   하기 위해 늦게 실행되어야 합니다.
		   현재는 페이지 해제 요청만 큐에 추가하며, 페이지는 현재 스택에서 사용 중입니다.
		   실제 파괴 로직은 schedule()의 시작 부분에서 호출됩니다. */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread)
		{
			ASSERT(curr != next);
			list_push_back(&destruction_req, &curr->elem);
		}

		/* 스레드를 전환하기 전에, 현재 실행 중인 스레드의 정보를 먼저 저장합니다. */
		thread_launch(next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid(void)
{
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire(&tid_lock);
	tid = next_tid++;
	lock_release(&tid_lock);

	return tid;
}
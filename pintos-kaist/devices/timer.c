#include "devices/timer.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include "threads/interrupt.h"
#include "threads/io.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* See [8254] for hardware details of the 8254 timer chip. */

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/* Number of timer ticks since OS booted. */
static int64_t ticks;

/* Number of loops per timer tick.
   Initialized by timer_calibrate(). */
static unsigned loops_per_tick;

static intr_handler_func timer_interrupt;
static bool too_many_loops(unsigned loops);
static void busy_wait(int64_t loops);
static void real_time_sleep(int64_t num, int32_t denom);
static void wake_up(int64_t cur_tick);
static bool compare_tick(const struct list_elem *a, const struct list_elem *b, void *aux);

typedef struct block_threads_struct
{
	struct thread *block_threads;
	int64_t wakeup_tick;
	struct list_elem elem;
} block_thread;

struct list block_thread_list;
int64_t closet_tick = NULL; // 다음에 깨워야할 틱

/* Sets up the 8254 Programmable Interval Timer (PIT) to
   interrupt PIT_FREQ times per second, and registers the
   corresponding interrupt. */
void timer_init(void)
{
	/* 8254 input frequency divided by TIMER_FREQ, rounded to
	   nearest. */
	uint16_t count = (1193180 + TIMER_FREQ / 2) / TIMER_FREQ;

	outb(0x43, 0x34); /* CW: counter 0, LSB then MSB, mode 2, binary. */
	outb(0x40, count & 0xff);
	outb(0x40, count >> 8);
	list_init(&block_thread_list); // 블락 스레드 리스트 초기화

	intr_register_ext(0x20, timer_interrupt, "8254 Timer");
}

/* Calibrates loops_per_tick, used to implement brief delays. */
void timer_calibrate(void)
{
	unsigned high_bit, test_bit;

	ASSERT(intr_get_level() == INTR_ON);
	printf("Calibrating timer...  ");

	/* Approximate loops_per_tick as the largest power-of-two
	   still less than one timer tick. */
	loops_per_tick = 1u << 10;
	while (!too_many_loops(loops_per_tick << 1))
	{
		loops_per_tick <<= 1;
		ASSERT(loops_per_tick != 0);
	}

	/* Refine the next 8 bits of loops_per_tick. */
	high_bit = loops_per_tick;
	for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1)
		if (!too_many_loops(high_bit | test_bit))
			loops_per_tick |= test_bit;

	printf("%'" PRIu64 " loops/s.\n", (uint64_t)loops_per_tick * TIMER_FREQ);
}

/* Returns the number of timer ticks since the OS booted. */
int64_t
timer_ticks(void)
{
	enum intr_level old_level = intr_disable();
	int64_t t = ticks;
	intr_set_level(old_level);
	barrier();
	return t;
}

/* timer_ticks()가 한 번 반환했던 값인 THEN 이후로
   경과한 타이머 틱 수를 반환합니다. */
int64_t
timer_elapsed(int64_t then)
{
	return timer_ticks() - then;
}

/* Suspends execution for approximately TICKS timer ticks. */
void timer_sleep(int64_t ticks)
{

	ASSERT(intr_get_level() == INTR_ON);

	struct thread *cur = thread_current(); // 현재 쓰레드 가져오기
	block_thread *target = malloc(sizeof(block_thread));

	target->block_threads = cur;				 // 블락되는 쓰레드
	target->wakeup_tick = timer_ticks() + ticks; // 깨울 틱 저장
	dprintf("깨울 틱 : %d\n", target->wakeup_tick);

	enum intr_level old_level = intr_disable(); // 인터럽트 끄기 -> 레이스 컨디션을 막기 위해 먼저
	if (closet_tick == NULL || closet_tick > target->wakeup_tick)
	{
		closet_tick = target->wakeup_tick;
	}

	list_insert_ordered(&block_thread_list, &target->elem, compare_tick, NULL);
	thread_block();			   // 쓰레드 블락
	intr_set_level(old_level); // 원래 상태 복원
}

static bool compare_tick(const struct list_elem *a, const struct list_elem *b, void *aux)
{
	block_thread *t1 = list_entry(a, block_thread, elem);
	block_thread *t2 = list_entry(b, block_thread, elem);

	return t1->wakeup_tick < t2->wakeup_tick;
}

/* Suspends execution for approximately MS milliseconds. */
void timer_msleep(int64_t ms)
{
	real_time_sleep(ms, 1000);
}

/* Suspends execution for approximately US microseconds. */
void timer_usleep(int64_t us)
{
	real_time_sleep(us, 1000 * 1000);
}

/* Suspends execution for approximately NS nanoseconds. */
void timer_nsleep(int64_t ns)
{
	real_time_sleep(ns, 1000 * 1000 * 1000);
}

/* Prints timer statistics. */
void timer_print_stats(void)
{
	printf("Timer: %" PRId64 " ticks\n", timer_ticks());
}

// 여기서 틱을 보고 같으면 쓰레드 꺠우기
static void
timer_interrupt(struct intr_frame *args UNUSED)
{
	ticks++;
	thread_tick();
	int64_t cur_tick = timer_ticks();
	// printf("현재 틱 : %d\n", cur_tick);
	// dprintf("실행 쓰레드 %s, 우선순위 : %d\n", thread_name(), thread_get_priority());
	if (closet_tick != NULL && cur_tick >= closet_tick) // 현재 틱이 블락된 쓰레드 로컬 틱이랑 같거나 크면
	{
		// printf("wakeup\n");
		wake_up(cur_tick);
	}
}

static void wake_up(int64_t cur_tick)
{
	struct list_elem *e;
	for (e = list_begin(&block_thread_list); e != list_end(&block_thread_list);)
	{
		block_thread *entry = list_entry(e, block_thread, elem);
		struct list_elem *next = list_next(e);
		if (entry->wakeup_tick <= cur_tick)
		{
			dprintf("wakeup\n");
			list_remove(e);
			thread_unblock(entry->block_threads);
		}
		else
			break;

		e = next;
	}

	if (list_empty(&block_thread_list)) // 리스트가 비어있을 경우
		closet_tick = NULL;				// 깨워야할 틱이 없으니까 -1로
	else								// 있을 경우
	{
		e = list_front(&block_thread_list); // 맨 앞의 엔트리를 가져와서 전역 틱에 저장
		block_thread *entry = list_entry(e, block_thread, elem);
		closet_tick = entry->wakeup_tick;
	}
}

/* mlfqs에서 틱마다 발생하는 상황에 대응하기 위한 함수입니다 */
void mlfqs_on_tick()
{
	update_recent_cpu();

	if (timer_ticks() % TIMER_FREQ == 0)
	{
		update_load_avg();
		update_recent_cpu_all();
	} // 모든 스레드 recent_cpu 계산

	if (timer_ticks() % 4 == 0)
	{
		// update_priority(thread_current());
		update_all_priority();
		compare_cur_next_priority();
	}
}

/* Returns true if LOOPS iterations waits for more than one timer
   tick, otherwise false. */
static bool
too_many_loops(unsigned loops)
{
	/* Wait for a timer tick. */
	int64_t start = ticks;
	while (ticks == start)
		barrier();

	/* Run LOOPS loops. */
	start = ticks;
	busy_wait(loops);

	/* If the tick count changed, we iterated too long. */
	barrier();
	return start != ticks;
}

/* Iterates through a simple loop LOOPS times, for implementing
   brief delays.

   Marked NO_INLINE because code alignment can significantly
   affect timings, so that if this function was inlined
   differently in different places the results would be difficult
   to predict. */
static void NO_INLINE
busy_wait(int64_t loops)
{
	while (loops-- > 0)
		barrier();
}

/* Sleep for approximately NUM/DENOM seconds. */
static void
real_time_sleep(int64_t num, int32_t denom)
{
	/* Convert NUM/DENOM seconds into timer ticks, rounding down.

	   (NUM / DENOM) s
	   ---------------------- = NUM * TIMER_FREQ / DENOM ticks.
	   1 s / TIMER_FREQ ticks
	   */
	int64_t ticks = num * TIMER_FREQ / denom;

	ASSERT(intr_get_level() == INTR_ON);
	if (ticks > 0)
	{
		/* We're waiting for at least one full timer tick.  Use
		   timer_sleep() because it will yield the CPU to other
		   processes. */
		timer_sleep(ticks);
	}
	else
	{
		/* Otherwise, use a busy-wait loop for more accurate
		   sub-tick timing.  We scale the numerator and denominator
		   down by 1000 to avoid the possibility of overflow. */
		ASSERT(denom % 1000 == 0);
		busy_wait(loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000));
	}
}

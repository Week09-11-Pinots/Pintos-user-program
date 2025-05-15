/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
   */

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static bool compare_priority(const struct list_elem *a, const struct list_elem *b, void *aux);
static bool compare_priority_for_donate(const struct list_elem *a, const struct list_elem *b, void *aux);
static bool compare_priority_for_cond(const struct list_elem *a,
									  const struct list_elem *b,
									  void *aux UNUSED);
static donation *create_donation(struct thread *thread, struct lock *lock);
static void remove_donation_for_lock(struct lock *);
static void recalc_priority();

int idx = 0;

static bool compare_priority(const struct list_elem *a, const struct list_elem *b, void *aux)
{
	struct thread *t1 = list_entry(a, struct thread, elem);
	struct thread *t2 = list_entry(b, struct thread, elem);

	return t1->priority > t2->priority;
}

static bool compare_priority_for_donate(const struct list_elem *a, const struct list_elem *b, void *aux)
{
	donation *t1 = list_entry(a, donation, elem);
	donation *t2 = list_entry(b, donation, elem);
	return t1->priority > t2->priority;
}

/* 세마포어 SEMA를 VALUE로 초기화합니다. 세마포어는 다음과 같은 두 가지 원자적 연산을 통해 조작되는
	음수가 아닌 정수입니다:

	- down 또는 "P": 값이 양수가 될 때까지 기다린 후, 값을 감소시킵니다.

	- up 또는 "V": 값을 증가시키고 (대기 중인 스레드가 있다면 하나를 깨웁니다). */
void sema_init(struct semaphore *sema, unsigned value)
{
	ASSERT(sema != NULL);

	sema->value = value;
	list_init(&sema->waiters);
}

/* Down or "P" operation on a semaphore. SEMA의 값이 양수가 될 때까지 기다린 후
	원자적으로 값을 감소시킵니다.

	이 함수는 대기 상태로 들어갈 수 있으므로 인터럽트 핸들러 내에서 호출되어서는 안 됩니다.
	이 함수는 인터럽트가 비활성화된 상태에서 호출될 수 있지만, 대기 상태로 들어가면
	다음에 스케줄된 스레드가 인터럽트를 다시 활성화할 가능성이 높습니다.
	이 함수는 sema_down 함수입니다. */
void sema_down(struct semaphore *sema)
{
	enum intr_level old_level;

	ASSERT(sema != NULL);
	ASSERT(!intr_context());

	old_level = intr_disable();
	while (sema->value == 0)
	{
		list_insert_ordered(&sema->waiters, &thread_current()->elem, compare_priority, NULL);
		thread_block();
	}
	sema->value--;
	intr_set_level(old_level);
}

/* Down 또는 "P" 연산을 수행하지만, 세마포어가 이미 0이 아닌 경우에만 수행합니다.
	세마포어가 감소되면 true를 반환하고, 그렇지 않으면 false를 반환합니다.

	이 함수는 인터럽트 핸들러에서 호출될 수 있습니다. */
bool sema_try_down(struct semaphore *sema)
{
	enum intr_level old_level;
	bool success;

	ASSERT(sema != NULL);

	old_level = intr_disable();
	if (sema->value > 0)
	{
		sema->value--;
		success = true;
	}
	else
		success = false;
	intr_set_level(old_level);

	return success;
}

/* Up 또는 "V" 연산을 수행합니다. SEMA의 값을 증가시키고,
	SEMA를 기다리고 있는 스레드 중 하나를 깨웁니다 (대기 중인 스레드가 있는 경우).

	이 함수는 인터럽트 핸들러에서 호출될 수 있습니다. */
void sema_up(struct semaphore *sema)
{
	enum intr_level old_level;

	ASSERT(sema != NULL);

	old_level = intr_disable();
	if (!list_empty(&sema->waiters))
	{
		list_sort(&sema->waiters, compare_priority, NULL);		  // 먼저 정렬 -> 굳이 해야하나 싶다
		thread_unblock(list_entry(list_pop_front(&sema->waiters), // 쓰레드 웨이트 리스트에 있는 쓰레드 하나 깨움
								  struct thread, elem));
	}
	sema->value++;
	compare_cur_next_priority(); // 깨어난 쓰레드가 우선순위가 더 높다면 양보
	intr_set_level(old_level);
}

static void sema_test_helper(void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void sema_self_test(void)
{
	struct semaphore sema[2];
	int i;

	printf("Testing semaphores...");
	sema_init(&sema[0], 0);
	sema_init(&sema[1], 0);
	thread_create("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
	for (i = 0; i < 10; i++)
	{
		sema_up(&sema[0]);
		sema_down(&sema[1]);
	}
	printf("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper(void *sema_)
{
	struct semaphore *sema = sema_;
	int i;

	for (i = 0; i < 10; i++)
	{
		sema_down(&sema[0]);
		sema_up(&sema[1]);
	}
}

/* LOCK을 초기화합니다. 락은 주어진 시간에 최대 하나의 스레드만 소유할 수 있습니다.
	우리의 락은 "재귀적"이지 않으며, 즉 현재 락을 소유하고 있는 스레드가
	해당 락을 다시 획득하려고 시도하는 것은 오류입니다.

	락은 초기 값이 1인 세마포어의 특수화된 형태입니다. 락과 세마포어의 차이점은 두 가지입니다.
	첫째, 세마포어는 1보다 큰 값을 가질 수 있지만, 락은 한 번에 하나의 스레드만 소유할 수 있습니다.
	둘째, 세마포어는 소유자가 없으므로 한 스레드가 세마포어를 "다운"하고 다른 스레드가 "업"할 수 있지만,
	락은 동일한 스레드가 락을 획득하고 해제해야 합니다. 이러한 제한이 불편하다면,
	락 대신 세마포어를 사용하는 것이 좋습니다. */
void lock_init(struct lock *lock)
{
	ASSERT(lock != NULL);

	lock->holder = NULL;
	sema_init(&lock->semaphore, 1); // 바이너리 세마포어
}

/* LOCK을 획득하며, 필요하다면 사용할 수 있을 때까지 대기 상태로 들어갑니다.
	현재 스레드가 이미 LOCK을 보유하고 있어서는 안 됩니다.

	이 함수는 대기 상태로 들어갈 수 있으므로 인터럽트 핸들러 내에서 호출되어서는 안 됩니다.
	이 함수는 인터럽트가 비활성화된 상태에서 호출될 수 있지만, 대기 상태로 들어가면
	다음에 스케줄된 스레드가 인터럽트를 다시 활성화할 가능성이 높습니다. */
void lock_acquire(struct lock *lock)
{
	ASSERT(lock != NULL);
	ASSERT(!intr_context());
	ASSERT(!lock_held_by_current_thread(lock));

	struct thread *cur = thread_current(); // 현재 쓰레드
	struct lock *pending = NULL;

	if (lock->holder)
	{
		cur->pending_lock = lock;	 // 현재 쓰레드의 대기 락 설정
		pending = cur->pending_lock; // 대기하는 락
		ASSERT(cur->pending_lock != NULL);
	}
	ASSERT(lock != NULL);

	while (pending != NULL) // 재귀적으로 가자
	{
		struct thread *holder = pending->holder;						// 대기하는 락의 홀더
		if (holder == NULL || thread_get_priority() < holder->priority) // 홀더의 우선순위가 자신보다 크다면 기부 안해도 됨
		{
			break;
		}

		donation *donate = create_donation(cur, pending);

		if (holder->priority < thread_get_priority()) // 홀더의 우선순위 갱신
		{
			holder->priority = thread_get_priority();
		}

		list_insert_ordered(&holder->donations, &donate->elem, compare_priority_for_donate, NULL);
		if (holder->pending_lock != NULL)
		{
			list_sort(&holder->pending_lock->semaphore.waiters, compare_priority, NULL);
		}

		pending = holder->pending_lock; // 홀더가 대기하는 다른 락 확인
	}

	sema_down(&lock->semaphore); // 락을 잡으려고 시도하고, 이미 잡혀있다면 대기함
	cur->pending_lock = NULL;
	lock->holder = thread_current(); // 현재 스레드가 락을 잡음
}

static donation *create_donation(struct thread *thread, struct lock *lock)
{
	struct lock *pending_lock = thread->pending_lock;
	donation *donate = malloc(sizeof(donation)); // 기부자 목록도 유지해야함 !!
	thread->pending_lock = pending_lock;
	donate->priority = thread_get_priority(); // 기부받은 우선순위 저장 -> 복구를 위해서
	donate->donor = thread;					  // 기부자 저장
	donate->lock = lock;					  // 락 저장
	ASSERT(donate != NULL);
	return donate;
}

/* LOCK을 획득하려 시도하며, 성공하면 true를 반환하고 실패하면 false를 반환합니다.
	현재 스레드가 이미 LOCK을 보유하고 있어서는 안 됩니다.

	이 함수는 대기 상태로 들어가지 않으므로 인터럽트 핸들러 내에서 호출될 수 있습니다. */
bool lock_try_acquire(struct lock *lock)
{
	bool success;

	ASSERT(lock != NULL);
	ASSERT(!lock_held_by_current_thread(lock)); // 실행 쓰레드가 이 락을 갖고있는지 검사

	/* 현재 락을 누군가가 갖고 있다면 false, 아니라면 true */
	success = sema_try_down(&lock->semaphore);
	if (success)
		/* 현재 락의 홀더는 실행 쓰레드가 됨 */
		lock->holder = thread_current();
	return success;
}

/* 현재 스레드가 소유하고 있는 LOCK을 해제합니다.
	이 함수는 lock_release 함수입니다.

	인터럽트 핸들러는 락을 획득할 수 없으므로, 락을 해제하려고 시도하는 것도
	의미가 없습니다. */
void lock_release(struct lock *lock)
{
	ASSERT(lock != NULL);
	ASSERT(lock_held_by_current_thread(lock));
	ASSERT(lock->holder != NULL);

	remove_donation_for_lock(lock);

	recalc_priority();

	lock->holder = NULL;
	sema_up(&lock->semaphore);
	compare_cur_next_priority();
}

static void remove_donation_for_lock(struct lock *lock)
{
	struct list_elem *e;
	struct thread *cur = thread_current();

	for (e = list_begin(&cur->donations); e != list_end(&cur->donations); e = list_next(e))
	{
		donation *d = list_entry(e, donation, elem);
		if (d->lock == lock)
		{
			list_remove(&d->elem);
		}
	}
}

static void recalc_priority()
{
	struct thread *cur = thread_current();

	cur->priority = cur->original_priority;
	if (list_empty(&cur->donations))
		return;

	list_sort(&cur->donations, compare_priority_for_donate, NULL);
	int front_priority = list_entry(list_front(&cur->donations), donation, elem)->priority;
	if (cur->priority < front_priority)
		cur->priority = front_priority;
}

/* 현재 스레드가 LOCK을 보유하고 있으면 true를 반환하고,
	그렇지 않으면 false를 반환합니다.
	(다른 스레드가 락을 보유하고 있는지 테스트하는 것은 경쟁 상태를 초래할 수 있습니다.) */
bool lock_held_by_current_thread(const struct lock *lock)
{
	ASSERT(lock != NULL);

	return lock->holder == thread_current();
}

/* One semaphore in a list. */
struct semaphore_elem
{
	struct list_elem elem;		/* List element. */
	struct semaphore semaphore; /* This semaphore. */
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void cond_init(struct condition *cond)
{
	ASSERT(cond != NULL);

	list_init(&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void cond_wait(struct condition *cond, struct lock *lock)
{
	struct semaphore_elem waiter;

	ASSERT(cond != NULL);
	ASSERT(lock != NULL);
	ASSERT(!intr_context());
	ASSERT(lock_held_by_current_thread(lock));

	sema_init(&waiter.semaphore, 0);
	/* wait 리스트에 쓰레드 우선순위 순으로 저장 */
	list_insert_ordered(&cond->waiters, &waiter.elem, compare_priority_for_cond, NULL);
	lock_release(lock);
	sema_down(&waiter.semaphore);
	lock_acquire(lock);
}

static bool compare_priority_for_cond(const struct list_elem *a,
									  const struct list_elem *b,
									  void *aux UNUSED)
{
	struct semaphore_elem *sema_a = list_entry(a, struct semaphore_elem, elem);
	struct semaphore_elem *sema_b = list_entry(b, struct semaphore_elem, elem);

	if (list_empty(&sema_a->semaphore.waiters))
		return false; // b가 더 높음
	if (list_empty(&sema_b->semaphore.waiters))
		return true; // a가 더 높음

	struct thread *t1 = list_entry(list_front(&sema_a->semaphore.waiters),
								   struct thread, elem);
	struct thread *t2 = list_entry(list_front(&sema_b->semaphore.waiters),
								   struct thread, elem);

	return t1->priority > t2->priority;
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_signal(struct condition *cond, struct lock *lock UNUSED)
{
	ASSERT(cond != NULL);
	ASSERT(lock != NULL);
	ASSERT(!intr_context());
	ASSERT(lock_held_by_current_thread(lock));

	if (!list_empty(&cond->waiters))
	{
		list_sort(&cond->waiters, compare_priority_for_cond, NULL);
		sema_up(&list_entry(list_pop_front(&cond->waiters),
							struct semaphore_elem, elem)
					 ->semaphore);
	}
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_broadcast(struct condition *cond, struct lock *lock)
{
	ASSERT(cond != NULL);
	ASSERT(lock != NULL);

	while (!list_empty(&cond->waiters))
		cond_signal(cond, lock);
}

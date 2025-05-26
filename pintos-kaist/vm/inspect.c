/* inspect.c: Testing utility for VM. */
/* DO NOT MODIFY THIS FILE. */

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "vm/inspect.h"

static void
inspect (struct intr_frame *f) {
	const void *va = (const void *) f->R.rax;
	f->R.rax = PTE_ADDR (pml4_get_page (thread_current ()->pml4, va));
}

/* VM(가상 메모리) 컴포넌트 테스트용 도구입니다. 이 함수는 int 0x42를 통해 호출합니다.
 * 입력:
 *   @RAX - 조사할 가상 주소
 * 출력:
 *   @RAX - 입력된 가상 주소에 매핑된 물리 주소 */
void
register_inspect_intr (void) {
	intr_register_int (0x42, 3, INTR_OFF, inspect, "Inspect Virtual Memory");
}

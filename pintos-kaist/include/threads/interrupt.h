#ifndef THREADS_INTERRUPT_H
#define THREADS_INTERRUPT_H

#include <stdbool.h>
#include <stdint.h>

/* Interrupts on or off? */
enum intr_level {
	INTR_OFF,             /* Interrupts disabled. */
	INTR_ON               /* Interrupts enabled. */
};

enum intr_level intr_get_level (void);
enum intr_level intr_set_level (enum intr_level);
enum intr_level intr_enable (void);
enum intr_level intr_disable (void);

/* Interrupt stack frame. */
struct gp_registers {
	uint64_t r15;
	uint64_t r14;
	uint64_t r13;
	uint64_t r12;
	uint64_t r11; 
	uint64_t r10; //4번째 인자
	uint64_t r9; //6번째 인자 
	uint64_t r8; //5번째 인자
	uint64_t rsi; //2번째 인자
	uint64_t rdi; //1번째 인자
	uint64_t rbp;
	uint64_t rdx; //3번째 인자 
	uint64_t rcx;
	uint64_t rbx;
	uint64_t rax; //함수의 반환값 저장. 시스템 콜 번호
} __attribute__((packed));

struct intr_frame {
	/* Pushed by intr_entry in intr-stubs.S.
	   These are the interrupted task's saved registers. */
	struct gp_registers R;
	uint16_t es; //ES(Extra Segment) 세그먼트 레지스터 값
	uint16_t __pad1; //패딩 
	uint32_t __pad2; //패딩 
	uint16_t ds; //DS(Data Segment) 세그먼트 레지스터 값. 
	uint16_t __pad3; //패딩
	uint32_t __pad4; //패딩 
	/* Pushed by intrNN_stub in intr-stubs.S. */
	uint64_t vec_no; /* 인터럽트 벡터 번호. 어떤 인터럽트(예외,시스템 콜 등)가 발생했는지 구분하는 번호다. */
/* 일부 예외(페이지 폴트 등)에서 CPU가 자동으로 푸시하는 에러 코드. 
해당 예외가 아닌 경우 0으로 채워진다.
*/
	uint64_t error_code; 
/* Pushed by the CPU.
   These are the interrupted task's saved registers. */
	uintptr_t rip; //인터럽트 발생 당시 실행중이던 명령어의 주소(Instruction Pointer, 즉 EIP/RIP)
	uint16_t cs; //코드 세그먼트 레지스터 값
	uint16_t __pad5; 
	uint32_t __pad6;
	uint64_t eflags; /*EFLAGS 레지스터 값. CPU의 플래그(인터럽트 플래그, 방향 플래그 등) 상태를 저장.*/
	uintptr_t rsp; //인터럽트 발생 당시의 스택 포인터(RSP)
	uint16_t ss; //스택 세그먼트 레지스터 값 
	uint16_t __pad7;
	uint32_t __pad8;
} __attribute__((packed)); /* 구조체 필드들이 패딩 없이 메모리에 연속적으로 배치되도록 함.*/

typedef void intr_handler_func (struct intr_frame *);

void intr_init (void);
void intr_register_ext (uint8_t vec, intr_handler_func *, const char *name);
void intr_register_int (uint8_t vec, int dpl, enum intr_level,
                        intr_handler_func *, const char *name);
bool intr_context (void);
void intr_yield_on_return (void);

void intr_dump_frame (const struct intr_frame *);
const char *intr_name (uint8_t vec);

#endif /* threads/interrupt.h */

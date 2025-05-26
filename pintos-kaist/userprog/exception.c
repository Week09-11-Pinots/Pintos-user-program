#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "intrinsic.h"

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill(struct intr_frame *);
static void page_fault(struct intr_frame *);

/* 사용자 프로그램에 의해 발생할 수 있는 인터럽트에 대한 핸들러를 등록합니다.

   실제 유닉스 계열 운영체제에서는 이러한 인터럽트 대부분을
   [SV-386] 3-24와 3-25에 설명된 것처럼 시그널의 형태로
   사용자 프로세스에 전달합니다. 하지만 우리는 시그널을 구현하지 않습니다.
   대신, 이런 인터럽트가 발생하면 단순히 해당 사용자 프로세스를 종료시킵니다.

   페이지 폴트는 예외입니다. 여기서는 다른 예외들과 동일하게 처리하지만,
   가상 메모리를 구현하려면 이 부분을 변경해야 합니다.

   각 예외에 대한 설명은 [IA32-v3a] 5.15절 "Exception and Interrupt Reference"를 참고하세요.
*/
void exception_init(void)
{
	/* 이 예외들은 사용자 프로그램이 INT, INT3, INTO, BOUND 명령어 등을 통해
   명시적으로 발생시킬 수 있습니다. 따라서 DPL==3으로 설정하여,
   사용자 프로그램이 이러한 명령어를 통해 예외를 호출할 수 있도록 합니다.
	*/
	intr_register_int(3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
	intr_register_int(4, 3, INTR_ON, kill, "#OF Overflow Exception");
	intr_register_int(5, 3, INTR_ON, kill,
					  "#BR BOUND Range Exceeded Exception");

	/* 이 예외들은 DPL==0으로 설정되어 있어,
   사용자 프로세스가 INT 명령어를 통해 직접 호출할 수 없습니다.
   하지만 간접적으로는 발생할 수 있습니다.
   예를 들어 #DE(0으로 나누기 예외)는 0으로 나눌 때 발생할 수 있습니다.
	*/
	intr_register_int(0, 0, INTR_ON, kill, "#DE Divide Error");
	intr_register_int(1, 0, INTR_ON, kill, "#DB Debug Exception");
	intr_register_int(6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
	intr_register_int(7, 0, INTR_ON, kill,
					  "#NM Device Not Available Exception");
	intr_register_int(11, 0, INTR_ON, kill, "#NP Segment Not Present");
	intr_register_int(12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
	intr_register_int(13, 0, INTR_ON, kill, "#GP General Protection Exception");
	intr_register_int(16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
	intr_register_int(19, 0, INTR_ON, kill,
					  "#XF SIMD Floating-Point Exception");

	/* 대부분의 예외는 인터럽트가 활성화된 상태에서 처리할 수 있습니다.
   하지만 페이지 폴트의 경우, 폴트 주소가 CR2에 저장되므로
   이 값을 보존하기 위해 인터럽트를 비활성화해야 합니다.
	*/
	intr_register_int(14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void exception_print_stats(void)
{
	printf("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill(struct intr_frame *f)
{
	/* 이 인터럽트는 (아마도) 사용자 프로세스에 의해 발생한 것입니다.
   예를 들어, 프로세스가 매핑되지 않은 가상 메모리에 접근해
   페이지 폴트가 발생했을 수 있습니다.
   현재로서는 단순히 해당 사용자 프로세스를 종료합니다.
   나중에는 커널에서 페이지 폴트를 처리할 수 있도록 해야 합니다.
   실제 유닉스 계열 운영체제는 대부분의 예외를 시그널을 통해
   프로세스에 다시 전달하지만, 우리는 시그널을 구현하지 않습니다.
	*/

	/* 인터럽트 프레임의 코드 세그먼트 값은
   예외가 어디서 발생했는지(유저/커널 모드)를 알려줍니다.
	*/

	switch (f->cs)
	{
	case SEL_UCSEG:
	{
		struct thread *t = thread_current(); // 이 줄이 꼭 필요함
		printf("%s: exit(-1)\n", t->name);

		/* User's code segment, so it's a user exception, as we
		   expected.  Kill the user process.  */
		// printf ("%s: dying due to interrupt %#04llx (%s).\n",
		// 		thread_name (), f->vec_no, intr_name (f->vec_no));
		// intr_dump_frame (f);
		t->exit_status = -1;
		thread_exit();
	}
	case SEL_KCSEG:
		/* 커널 코드 세그먼트인 경우, 이는 커널 버그를 의미합니다.
	커널 코드는 예외를 발생시키면 안 됩니다.
	(페이지 폴트가 커널 예외를 유발할 수는 있지만,
	이 위치까지 도달해서는 안 됩니다.)
	커널 패닉을 일으켜 문제를 알립니다.
		*/
		intr_dump_frame(f);
		PANIC("Kernel bug - unexpected interrupt in kernel");

	default:
		/* 그 밖의 다른 코드 세그먼트? 이런 경우는 발생해서는 안 됩니다.
		커널 패닉을 일으킵니다.
		*/
		printf("Interrupt %#04llx (%s) in unknown segment %04x\n",
			   f->vec_no, intr_name(f->vec_no), f->cs);
		thread_exit();
	}
}

/* 페이지 폴트 핸들러.  
   이 코드는 가상 메모리 구현을 위해 반드시 채워야 하는 뼈대(skeleton)입니다.  
   프로젝트 2의 일부 솔루션에서도 이 코드를 수정해야 할 수 있습니다.

   진입 시, 폴트가 발생한 주소는 CR2(컨트롤 레지스터 2)에 저장되어 있고,  
   폴트에 대한 정보는 exception.h의 PF_* 매크로에 설명된 포맷으로  
   F의 error_code 멤버에 들어 있습니다.  
   아래 예제 코드는 이 정보를 어떻게 파싱하는지 보여줍니다.  
   이에 대한 더 자세한 정보는  
   [IA32-v3a] 5.15절 "Exception and Interrupt Reference"의  
   "Interrupt 14--Page Fault Exception (#PF)" 설명에서 찾을 수 있습니다.
*/

static void
page_fault(struct intr_frame *f)
{
	bool not_present; /* True: not-present page, false: writing r/o page. */
	bool write;		  /* True: access was write, false: access was read. */
	bool user;		  /* True: access by user, false: access by kernel. */
	void *fault_addr; /* Fault address. */

	/* 폴트를 일으킨 주소, 즉 폴트의 원인이 된 가상 주소를 얻습니다.
   이 주소는 코드일 수도 있고 데이터일 수도 있습니다.
   이 주소가 반드시 폴트를 일으킨 명령어의 주소(즉, f->rip)는 아닙니다. */

	fault_addr = (void *)rcr2();

	/* 인터럽트를 다시 활성화합니다.
   (인터럽트는 CR2 레지스터가 변경되기 전에 안전하게 값을 읽기 위해 잠시 꺼두었던 것입니다.) */
	intr_enable();

	/* Determine cause. */
	not_present = (f->error_code & PF_P) == 0;
	write = (f->error_code & PF_W) != 0;
	user = (f->error_code & PF_U) != 0;

#ifdef VM
	/* For project 3 and later. */
	if (vm_try_handle_fault(f, fault_addr, user, write, not_present))
		return;
#endif

	/* Count page faults. */
	page_fault_cnt++;

	/* If the fault is true fault, show info and exit. */
	printf("Page fault at %p: %s error %s page in %s context.\n",
		   fault_addr,
		   not_present ? "not present" : "rights violation",
		   write ? "writing" : "reading",
		   user ? "user" : "kernel");
	kill(f);
}

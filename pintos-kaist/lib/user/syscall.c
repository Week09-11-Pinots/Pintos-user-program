#include <syscall.h>
#include <stdint.h>
#include "../syscall-nr.h"

/* 항상 인라인되도록 지정된 함수.
 * 유저 모드에서 커널로 시스템 콜을 호출하기 위한 인터페이스.
 * 최대 6개의 인자를 받아 syscall 명령어를 통해 커널에 요청을 보냄. */
__attribute__((always_inline)) static __inline int64_t syscall(uint64_t num_, uint64_t a1_, uint64_t a2_,
															   uint64_t a3_, uint64_t a4_, uint64_t a5_, uint64_t a6_)
{
	int64_t ret; // 커널에서 반환될 결과 값을 저장할 변수
	/* 시스템 콜 번호 및 인자들을 해당하는 레지스터에 바인딩.
	 * 각 레지스터는 x86-64 시스템 콜 호출 규약(System V ABI)에 따라 사용됨. */
	register uint64_t *num asm("rax") = (uint64_t *)num_; // syscall 번호 → rax
	register uint64_t *a1 asm("rdi") = (uint64_t *)a1_;	  // 첫 번째 인자 → rdi
	register uint64_t *a2 asm("rsi") = (uint64_t *)a2_;	  // 두 번째 인자 → rsi
	register uint64_t *a3 asm("rdx") = (uint64_t *)a3_;	  // 세 번째 인자 → rdx
	register uint64_t *a4 asm("r10") = (uint64_t *)a4_;	  // 네 번째 인자 → r10
	register uint64_t *a5 asm("r8") = (uint64_t *)a5_;	  // 다섯 번째 인자 → r8
	register uint64_t *a6 asm("r9") = (uint64_t *)a6_;	  // 여섯 번째 인자 → r9

	/* 인라인 어셈블리: 레지스터에 값을 넣고 syscall 명령 실행.
	 * 'volatile'은 컴파일러가 이 코드를 최적화로 제거하지 않도록 함. */

	__asm __volatile(
		"mov %1, %%rax\n"												 // rax ← 시스템 콜 번호
		"mov %2, %%rdi\n"												 // rdi ← 첫 번째 인자
		"mov %3, %%rsi\n"												 // rsi ← 두 번째 인자
		"mov %4, %%rdx\n"												 // rdx ← 세 번째 인자
		"mov %5, %%r10\n"												 // r10 ← 네 번째 인자 (함수 호출 convention과 다름)
		"mov %6, %%r8\n"												 // r8  ← 다섯 번째 인자
		"mov %7, %%r9\n"												 // r9  ← 여섯 번째 인자
		"syscall\n"														 // 시스템 콜 호출 (커널 모드로 진입)
		: "=a"(ret)														 // 출력: 커널에서 반환된 값은 rax → ret로 저장
		: "g"(num), "g"(a1), "g"(a2), "g"(a3), "g"(a4), "g"(a5), "g"(a6) // 입력: 각 레지스터에 인자 매핑
		: "cc", "memory");												 // 부수효과: condition code와 메모리가 바뀜을 알림
	return ret;															 // 시스템 콜 결과값 반환
}

/* syscall0:
 * 인자가 없는 시스템 콜을 호출한다.
 * NUMBER는 시스템 콜 번호이며, 결과는 int형으로 반환된다.
 * 나머지 인자 6개는 모두 0으로 채워진다. */
#define syscall0(NUMBER) ( \
	syscall(((uint64_t)NUMBER), 0, 0, 0, 0, 0, 0))

/* syscall1:
 * 하나의 인자를 받는 시스템 콜을 호출한다.
 * 첫 번째 인자(ARG0)는 rdi 레지스터에 들어간다.
 * 나머지 5개 인자는 0으로 채운다. */
#define syscall1(NUMBER, ARG0) ( \
	syscall(((uint64_t)NUMBER),  \
			((uint64_t)ARG0), 0, 0, 0, 0, 0))
/* syscall2:
 * 두 개의 인자를 받는 시스템 콜을 호출한다.
 * ARG0 → rdi, ARG1 → rsi로 들어간다.
 * 나머지 4개 인자는 0으로 채운다. */
#define syscall2(NUMBER, ARG0, ARG1) ( \
	syscall(((uint64_t)NUMBER),        \
			((uint64_t)ARG0),          \
			((uint64_t)ARG1),          \
			0, 0, 0, 0))
/* syscall3:
 * 세 개의 인자를 받는 시스템 콜을 호출한다.
 * ARG0 → rdi, ARG1 → rsi, ARG2 → rdx.
 * 나머지 3개 인자는 0으로 채운다. */
#define syscall3(NUMBER, ARG0, ARG1, ARG2) ( \
	syscall(((uint64_t)NUMBER),              \
			((uint64_t)ARG0),                \
			((uint64_t)ARG1),                \
			((uint64_t)ARG2), 0, 0, 0))
/* syscall4:
 * 네 개의 인자를 받는 시스템 콜을 호출한다.
 * ARG0 → rdi, ARG1 → rsi, ARG2 → rdx, ARG3 → r10.
 * 나머지 2개 인자는 0으로 채운다.
 *
 * ❗주의: NUMBER를 (uint64_t *)로 잘못 형변환하고 있음.
 * 실제 구현에서는 (uint64_t)로 고쳐야 함. */
#define syscall4(NUMBER, ARG0, ARG1, ARG2, ARG3) ( \
	syscall(((uint64_t *)NUMBER),                  \
			((uint64_t)ARG0),                      \
			((uint64_t)ARG1),                      \
			((uint64_t)ARG2),                      \
			((uint64_t)ARG3), 0, 0))
/* syscall5:
 * 다섯 개의 인자를 받는 시스템 콜을 호출한다.
 * ARG0 → rdi, ARG1 → rsi, ARG2 → rdx, ARG3 → r10, ARG4 → r8.
 * 마지막 인자 1개는 0으로 채운다. */
#define syscall5(NUMBER, ARG0, ARG1, ARG2, ARG3, ARG4) ( \
	syscall(((uint64_t)NUMBER),                          \
			((uint64_t)ARG0),                            \
			((uint64_t)ARG1),                            \
			((uint64_t)ARG2),                            \
			((uint64_t)ARG3),                            \
			((uint64_t)ARG4),                            \
			0))
void halt(void)
{
	syscall0(SYS_HALT);
	NOT_REACHED();
}
/* exit:
 * 현재 프로세스를 종료하고, 종료 코드를 커널에 전달한다.
 * SYS_EXIT 시스템 콜 번호와 함께 status 값을 인자로 syscall1을 호출한다.
 * 이후의 코드는 실행되지 않음 → NOT_REACHED 사용. */
void exit(int status)
{
	syscall1(SYS_EXIT, status);
	NOT_REACHED();
}
/* fork:
 * 현재 프로세스를 복제하여 자식 프로세스를 생성한다.
 * SYS_FORK 시스템 콜 번호와 thread_name을 전달하고,
 * 반환값으로 자식의 pid를 받아온다.
 * 부모는 자식의 pid를, 자식은 0을 받게 된다 (커널에서 처리됨). */
pid_t fork(const char *thread_name)
{
	return (pid_t)syscall1(SYS_FORK, thread_name);
}
/* exec:
 * 현재 프로세스를 주어진 실행 파일로 대체한다.
 * SYS_EXEC 시스템 콜 번호와 실행할 파일명을 전달한다.
 * 성공 시 반환되지 않고, 실패하면 -1을 반환한다. */
int exec(const char *file)
{
	return (pid_t)syscall1(SYS_EXEC, file);
}
/* wait:
 * 주어진 pid의 자식 프로세스가 종료될 때까지 대기한다.
 * SYS_WAIT 시스템 콜 번호와 대기할 자식의 pid를 전달한다.
 * 자식이 종료되면 exit status를 반환받는다. */
int wait(pid_t pid)
{
	return syscall1(SYS_WAIT, pid);
}
/* create:
 * 파일 시스템에 새 파일을 생성하는 시스템 콜을 호출한다.
 * file: 생성할 파일의 이름 (문자열 포인터)
 * initial_size: 파일의 초기 크기 (바이트 단위)
 * SYS_CREATE: create syscall 번호
 * syscall2를 통해 인자 2개를 전달하고, 생성 성공 여부를 bool로 반환한다. */
bool create(const char *file, unsigned initial_size)
{
	return syscall2(SYS_CREATE, file, initial_size);
}
/* remove:
 * 파일 시스템에서 주어진 파일을 삭제하는 시스템 콜을 호출한다.
 * file: 삭제할 파일 이름
 * SYS_REMOVE: remove syscall 번호
 * syscall1로 파일 이름을 넘기고, 삭제 성공 여부를 bool로 반환한다. */
bool remove(const char *file)
{
	return syscall1(SYS_REMOVE, file);
}
/* open:
 * 주어진 이름의 파일을 연다. 성공하면 파일 디스크립터를 반환한다.
 * file: 열고자 하는 파일 이름
 * SYS_OPEN: open syscall 번호
 * syscall1로 파일 이름을 넘기고, 결과는 열린 파일의 FD (정수형)이다.
 * 실패 시 -1을 반환할 수 있다. */
int open(const char *file)
{
	return syscall1(SYS_OPEN, file);
}
/* filesize:
 * 열린 파일의 크기를 반환한다.
 * fd: 파일 디스크립터 (open을 통해 얻은 값)
 * SYS_FILESIZE: filesize syscall 번호
 * syscall1로 fd를 넘기고, 해당 파일의 크기 (바이트)를 반환한다. */
int filesize(int fd)
{
	return syscall1(SYS_FILESIZE, fd);
}
/* read:
 * 열린 파일 디스크립터로부터 데이터를 읽는다.
 * fd: 읽을 대상 파일 디스크립터
 * buffer: 데이터를 저장할 버퍼 (사용자 메모리 주소)
 * size: 읽을 바이트 수
 * SYS_READ: read syscall 번호
 * syscall3을 사용하여 fd, buffer, size 세 개의 인자를 전달한다.
 * 반환값은 실제로 읽은 바이트 수이고, 실패 시 -1을 반환할 수 있다. */
int read(int fd, void *buffer, unsigned size)
{
	return syscall3(SYS_READ, fd, buffer, size);
}
/* write:
 * 열린 파일 디스크립터에 데이터를 쓴다.
 * fd: 쓸 대상 파일 디스크립터
 * buffer: 쓸 데이터가 담긴 메모리 주소
 * size: 쓸 바이트 수
 * SYS_WRITE: write syscall 번호
 * syscall3을 통해 fd, buffer, size를 전달한다.
 * 반환값은 실제로 쓴 바이트 수이고, 실패 시 -1을 반환할 수 있다. */
int write(int fd, const void *buffer, unsigned size)
{
	return syscall3(SYS_WRITE, fd, buffer, size);
}
/* seek:
 * 파일 디스크립터의 읽기/쓰기 포인터를 지정한 위치로 이동시킨다.
 * fd: 대상 파일 디스크립터
 * position: 이동할 바이트 위치 (파일 시작 기준 오프셋)
 * SYS_SEEK: seek syscall 번호
 * syscall2를 사용하여 fd와 위치 인자를 전달한다.
 * 반환값은 없으며, 위치 이동만 수행된다. */
void seek(int fd, unsigned position)
{
	syscall2(SYS_SEEK, fd, position);
}
/* tell:
 * 현재 파일 디스크립터의 읽기/쓰기 포인터 위치를 반환한다.
 * fd: 대상 파일 디스크립터
 * SYS_TELL: tell syscall 번호
 * syscall1을 통해 fd만 전달한다.
 * 반환값은 현재 오프셋 위치 (바이트 단위)이다. */
unsigned
tell(int fd)
{
	return syscall1(SYS_TELL, fd);
}
/* close:
 * 열린 파일 디스크립터를 닫는다.
 * fd: 닫을 대상 파일 디스크립터
 * SYS_CLOSE: close syscall 번호
 * syscall1로 fd만 전달하면 되고, 반환값은 없다.
 * 커널 내부에서 자원 해제와 파일 핸들 정리를 수행한다. */
void close(int fd)
{
	syscall1(SYS_CLOSE, fd);
}

int dup2(int oldfd, int newfd)
{
	// 추가 과제
	return syscall2(SYS_DUP2, oldfd, newfd);
}

// 아래부터는 일부는 프로젝트3에서, 나머지는 프로젝트 4에서 구현하게 됨.
void *
mmap(void *addr, size_t length, int writable, int fd, off_t offset)
{
	return (void *)syscall5(SYS_MMAP, addr, length, writable, fd, offset);
}

void munmap(void *addr)
{
	syscall1(SYS_MUNMAP, addr);
}

bool chdir(const char *dir)
{
	return syscall1(SYS_CHDIR, dir);
}

bool mkdir(const char *dir)
{
	return syscall1(SYS_MKDIR, dir);
}

bool readdir(int fd, char name[READDIR_MAX_LEN + 1])
{
	return syscall2(SYS_READDIR, fd, name);
}

bool isdir(int fd)
{
	return syscall1(SYS_ISDIR, fd);
}

int inumber(int fd)
{
	return syscall1(SYS_INUMBER, fd);
}

int symlink(const char *target, const char *linkpath)
{
	return syscall2(SYS_SYMLINK, target, linkpath);
}

int mount(const char *path, int chan_no, int dev_no)
{
	return syscall3(SYS_MOUNT, path, chan_no, dev_no);
}

int umount(const char *path)
{
	return syscall1(SYS_UMOUNT, path);
}

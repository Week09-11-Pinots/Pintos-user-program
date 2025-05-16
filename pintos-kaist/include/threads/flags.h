#ifndef THREADS_FLAGS_H
#define THREADS_FLAGS_H

#define FLAG_MBS   (1<<1) //항상 1이어야 하는 예약 비트
#define FLAG_TF    (1<<8) /*트랩 플래그(단일 명령어 단위 디버깅 )
이 비트가 1이면 CPU가 한 명령어 실행 후 마다 디버거에게 제어를 넘긴다. 
*/
#define FLAG_IF    (1<<9) //인터럽트 활성화 플래그. 1이면 인터럽트 허용, 0이면 CPU가 인터럽트 무시
#define FLAG_DF    (1<<10) /* 방향 플래그(문자열 명령의 처리 방향 제어 )
문자열 처리 명령(movs, cmps등 )에서 증가/감소 방향을 결정한다. 
*/
#define FLAG_IOPL  (3<<12) // IO 권한 레벨(2비트. 커널/유저 모드 I/O 권한 ) 커널은 0, 유저는 3이 일반적 
#define FLAG_AC    (1<<18) /*정렬 검사 플래그(메모리 접근 정렬 검사)
 1이면 메모리 접근시 정렬이 맞지 않으면 예외 발생(디버깅 목적 )*/
#define FLAG_NT    (1<<14) //네스티드 테스크 플래그(테스크 중첩 여부 )

#endif /* threads/flags.h */

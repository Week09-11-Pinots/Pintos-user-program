#include <random.h>
#include "tests/lib.h"
#include "tests/main.h"

/* 커널 부팅 -> 파일 시스템 등 초기화 -> ititd(첫 유저 프로세스) 실행 ->
 initd가 실행되면 main이 실행됨.*/

int
main (int argc UNUSED, char *argv[]) 
{
  test_name = argv[0];

  msg ("begin");
  random_init (0);
  test_main ();
  msg ("end");
  return 0;
}


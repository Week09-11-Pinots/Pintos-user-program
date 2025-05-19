/* wait-killed 테스트에서 실행되는 자식 프로세스입니다.
  pintos를 실행하려고 시도하지만, Pintos에 `pintos`가 존재하지 않으므로
  프로세스는 -1 종료 코드로 종료되어야 합니다. */

#include "tests/lib.h"
#include "tests/main.h"

void test_main(void)
{
  exec("pintos");
  fail("should have exited with -1");
}

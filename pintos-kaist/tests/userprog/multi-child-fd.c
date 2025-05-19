/* 파일을 연 다음, 해당 파일을 닫으려고 시도하는 하위 프로세스를 실행합니다.
  (Pintos는 파일 핸들 상속을 지원하지 않으므로, 이 시도는 실패해야 합니다.)
  이후 부모 프로세스가 파일 핸들을 사용하려고 시도하며, 이 동작은 성공해야 합니다. */

#include <stdio.h>
#include <syscall.h>
#include "tests/userprog/sample.inc"
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void)
{
  char child_cmd[128];
  int handle;

  CHECK((handle = open("sample.txt")) > 1, "open \"sample.txt\"");

  snprintf(child_cmd, sizeof child_cmd, "child-close %d", handle);

  pid_t pid;
  if (!(pid = fork("child-close")))
  {
    exec(child_cmd);
  }
  msg("wait(exec()) = %d", wait(pid));

  check_file_handle(handle, "sample.txt", sample, sizeof sample - 1);
}

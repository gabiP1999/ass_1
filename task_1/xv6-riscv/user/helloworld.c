#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  char* h = "hello world!\n";
  write(1,h,strlen(h));
  exit(0);
}

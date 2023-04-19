#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  printf("Set priority test\n");
  int x;
  x = set_ps_priority(4);
  printf("Back from the test x: %d\n", x);
  exit(0,"Goodbye World xv6\n");
}

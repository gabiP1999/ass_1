#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  printf("memsize: %d\n",memsize());
  void* ptr = malloc(20000);
  printf("memsize:%d\n",memsize());  
  free(ptr);
  printf("memsize:%d\n",memsize());  
  exit(0,"");
}

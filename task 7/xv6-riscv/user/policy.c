#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  if(argc != 2){
  	printf("Ileagal number of arguments!\n");
  	exit(0,"");
  }
  if(*argv[1] == '0')
  	set_policy(0);
  else if(*argv[1] == '1')
  	set_policy(1);
  else if(*argv[1] == '2')
  	set_policy(2);
  else {
  	printf("Ileagal policy number, should be 0,1,2\n");
  }
  
  exit(0,"");
}

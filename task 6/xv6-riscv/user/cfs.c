#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

struct cfs_stats {
  int pid;                     //Process ID
  int cfs_priority;            // CFS priority for task 6
  long long rtime;             // Process RUNNING time for task 6
  long long stime;             // Process SLEEPING time for task 6
  long long retime;            // Process RUNNABLE time for task 6
};

void iter()
{
  int i;
  for( i = 1; i <= 100000000; i++){
    if( i % 10000000 == 0)
      sleep(1);
  }
}

int
main(int argc, char *argv[])
{
  struct cfs_stats s1,s2,s3;
  int pid1,pid2,pid3;

  if( fork() == 0){
    set_cfs_priority(0);
    iter();
    pid1 = getpid();
    get_cfs_stats(pid1,&s1);
    printf("\npid:%d\ncfs_priority:%d\nrunning time:%d\nsleep time:%d\nrunnable time:%d\n", s1.pid,s1.cfs_priority,s1.rtime,s1.stime,s1.retime);
    exit(0,"");
  }
    if( fork() == 0){
    set_cfs_priority(1);
    iter();
    pid2 = getpid();
    get_cfs_stats(pid2,&s2);
    sleep(15);//sleep so that the printf dont get mixed up
    printf("\npid:%d\ncfs_priority:%d\nrunning time:%d\nsleep time:%d\nrunnable time:%d\n", s2.pid,s2.cfs_priority,s2.rtime,s2.stime,s2.retime);
    exit(0,"");
  }
    if( fork() == 0){
    set_cfs_priority(2);
    iter();
    pid3 = getpid();
    get_cfs_stats(pid3,&s3);
    sleep(30);//sleep so that the printf dont get mixed up
    printf("\npid:%d\ncfs_priority:%d\nrunning time:%d\nsleep time:%d\nrunnable time:%d\n", s3.pid,s3.cfs_priority,s3.rtime,s3.stime,s3.retime);
    printf("\nWith these short processes you can't really tell the difference between all priorities :(\n");
    exit(0,"");
  }
   
  exit(0,"");
}


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

int
main(int argc, char *argv[])
{
  struct cfs_stats c;
  int pid;
  pid = getpid();
  get_cfs_stats(pid,&c);
  printf("###CFS stats: ###\npid:%d\ncfs_priority:%d\nrtime:%d\nstime:%d\nretime:%d\n",
         c.pid,c.cfs_priority,c.rtime,c.stime,c.retime);
  sleep(100);
  get_cfs_stats(pid,&c);
  printf("###CFS stats: ###\npid:%d\ncfs_priority:%d\nrtime:%d\nstime:%d\nretime:%d\n",
         c.pid,c.cfs_priority,c.rtime,c.stime,c.retime);

  exit(0,"");
}

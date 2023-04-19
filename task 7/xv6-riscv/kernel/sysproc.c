#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"

uint64
sys_exit(void)
{
  int n;
  char exit_msg[32];
  if(argint(0, &n) < 0)
    return -1;
  argstr(1,exit_msg,32);
  exit(n, exit_msg);
  return 0;  // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return fork();
}

uint64
sys_wait(void)
{
  uint64 p;
  uint64 exit_msg_addr;
  if(argaddr(0, &p) < 0)
    return -1;
  argaddr(1,&exit_msg_addr);
  return wait(p,exit_msg_addr);
}

uint64
sys_sbrk(void)
{
  int addr;
  int n;

  if(argint(0, &n) < 0)
    return -1;
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

uint64
sys_sleep(void)
{
  int n;
  uint ticks0;

  if(argint(0, &n) < 0)
    return -1;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(myproc()->killed){
      release(&tickslock);
      return -1;
    }
    
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  if(argint(0, &pid) < 0)
    return -1;
  return kill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}
uint64
sys_memsize(void)
{
	return myproc()->sz;
}
//Task 5
uint64
sys_set_ps_priority(void)
{
  int priority;
  argint(0,&priority);
  if(priority < 1 || priority > 10)
    return -1;
  struct proc * p = myproc();
  p->ps_priority = priority;
  return 0;
}
//Task 6
uint64
sys_set_cfs_priority(void)
{
  int priority;
  if (argint(0,&priority) < 0 || priority < 0 || priority > 2)
    return -1;
  set_cfs_priority(priority);
  return 0;
}
uint64
sys_get_cfs_stats(void)
{
  int pid;
  uint64 cfs_addr;
  if(argint(0,&pid) < 0 || argaddr(1,&cfs_addr) < 0)
    return -1;
  get_cfs_stats(pid, ( struct cfs_stats * )cfs_addr);
  return 0;
}
uint64
sys_set_policy(void)
{
  int policy;
  if(argint(0,&policy) < 0 || policy < 0 || policy > 2)
    return -1;
  set_policy(policy);
  return 0;
}

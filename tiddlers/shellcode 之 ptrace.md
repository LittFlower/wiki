## 一. 介绍

对于一道 shellcode 题目，常规的考法是 orw 及其变种 or execve 这些。

假如题目禁用了所有的文件描述符，那么可以考虑通过 /dev 重新打开标准输入输出。

但如果远程存在 chroot 的话，上面这个方法也不行。

一旦 `close(1)`，pwntools 交互会直接进入 EOF，尽管 TCP 链接实际上并没有断开，因此盲注也同样无法使用。

所以可以创建一个 `socket` 通信，读取 flag 并发送至 VPS。

但如果禁止使用 `socket` 的话，怎么打呢（？


## 二. ptrace syscall

```c
#include <sys/ptrace.h>

long ptrace(enum __ptrace_request op, pid_t pid,
		void *addr, void *data);
```

主要是得看 ptrace 的 man 手册。

第一个参数的枚举值：

```c
enum __ptrace_request
{
	PTRACE_TRACEME = 0,		//被调试进程调用
	PTRACE_PEEKDATA = 2,	//查看内存
  	PTRACE_PEEKUSER = 3,	//查看struct user 结构体的值
  	PTRACE_POKEDATA = 5,	//修改内存
  	PTRACE_POKEUSER = 6,	//修改struct user 结构体的值
  	PTRACE_CONT = 7,		//让被调试进程继续
  	PTRACE_SINGLESTEP = 9,	//让被调试进程执行一条汇编指令
  	PTRACE_GETREGS = 12,	//获取一组寄存器(struct user_regs_struct)
  	PTRACE_SETREGS = 13,	//修改一组寄存器(struct user_regs_struct)
  	PTRACE_ATTACH = 16,		//附加到一个进程
  	PTRACE_DETACH = 17,		//解除附加的进程
  	PTRACE_SYSCALL = 24,	//让被调试进程在系统调用前和系统调用后暂停
};
```

`PTRACE_GETREGS` 和 `PTRACE_SETREGS` 可以对寄存器操作，这个寄存器结构体如下：


```c
struct user_regs_struct
{
  __extension__ unsigned long long int r15;
  __extension__ unsigned long long int r14;
  __extension__ unsigned long long int r13;
  __extension__ unsigned long long int r12;
  __extension__ unsigned long long int rbp;
  __extension__ unsigned long long int rbx;
  __extension__ unsigned long long int r11;
  __extension__ unsigned long long int r10;
  __extension__ unsigned long long int r9;
  __extension__ unsigned long long int r8;
  __extension__ unsigned long long int rax;
  __extension__ unsigned long long int rcx;
  __extension__ unsigned long long int rdx;
  __extension__ unsigned long long int rsi;
  __extension__ unsigned long long int rdi;
  __extension__ unsigned long long int orig_rax; // 0x78
  __extension__ unsigned long long int rip;      // 0x80
  __extension__ unsigned long long int cs;
  __extension__ unsigned long long int eflags;
  __extension__ unsigned long long int rsp;
  __extension__ unsigned long long int ss;
  __extension__ unsigned long long int fs_base;
  __extension__ unsigned long long int gs_base;
  __extension__ unsigned long long int ds;
  __extension__ unsigned long long int es;
  __extension__ unsigned long long int fs;
  __extension__ unsigned long long int gs;
};
```

主要注意的点：
- 系统调用号保存在 `orig_rax`，而不是 `rax`
- 读写内存的时候以 4 字节为单位
- 只有当子进程的状态发生改变（也就是发出信号 `SIGNTRAP` 这种时），父进程才需要 `wait`
- ptrace 一些操作会忽视参数，所以需要仔细看 man 手册

## 三. 打法


一般来讲如果已知子进程进程号，父进程执行 shellcode 的话，可以：
1. PTRACE_ATTACH 附加到子进程
2. PTRACE_SYSCALL 在子进程 syscall 前断点，此时父进程执行 `wait` 可以接受断点信号，子进程暂停在 syscall 前
3. 通过 `PTRACE_GETREGS` 和 `PTRACE_SETREGS` 对寄存器操作，绕过 syscall 的检查

这里注意，syscall 会调用 syscall_trace_enter()，该函数依次处理 Syscall User Dispatch、ptrace 和 seccomp，所以可以先用 ptrace bypass seccomp，然后再 ptrace 恢复想调用的 syscall 或者在某些内存写入 orw，从而提权。

如果不知道进程号的话，可以：
1. `fork` 开个子进程（返回值就是子进程的进程号），让子进程执行 PTRACE_TRACEME，这样哪怕不知道进程号也能 ptrace 标记上
2. `int3` 指令可以用来发送 `SIGTRAP` 信号（类似于打断点），然后另外一个进程 `wait` 可以断下来，这样就可以断在被沙箱 ban 的 syscall 前
3. 由于已知了子进程的进程号，所以打法和上面“已知时”类似了。

注意，`ptrace` attach 到子进程上就不能再 gdb 调试那个进程了，因为 gdb 走的也是 `ptrace`，所以一般对子进程操作时只能 gdb 调试父进程。



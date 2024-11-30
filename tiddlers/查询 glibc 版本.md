已知一个 libc.so.6 文件，想知道它是哪个版本的 glibc，可以用以下命令查看：

```bash
strings ./libc.so.6 | grep 'GNU C'
```
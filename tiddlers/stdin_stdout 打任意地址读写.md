## 简介

FILE 在 Linux 系统的标准 IO 库中是用于描述文件的结构，称为文件流。 FILE 结构在程序执行 fopen 等函数时会进行创建，并分配在堆中。我们常定义一个指向 FILE 结构的指针来接收这个返回值。

在标准 I/O 库中，每个程序启动时有三个文件流是自动打开的：stdin、stdout、stderr。因此在初始状态下，_IO_list_all 指向了一个有这些文件流构成的链表，但是需要注意的是这三个文件流位于 libc.so 的数据段。而我们使用 fopen 创建的文件流是分配在堆内存上的。

`FILE` 的结构这里不再详细描述了，之前学 apple 的时候已经看过了，简单来说在 pwndbg 调试时，可以 `p _IO_2_1_stdin` 查看它们的详细结构。

## 原理

以 `scanf` 函数为例子：

`scanf` 函数在 glibc 的 `stdio-common/scanf.c` 里，是 `__scanf`，如下：

```c
int
__scanf (const char *format, ...)
{
  va_list arg;
  int done;

  va_start (arg, format);
  done = _IO_vfscanf (stdin, format, arg, NULL);
  va_end (arg);

  return done;
}
ldbl_strong_alias (__scanf, scanf) // 这里可以看到，glibc 把 __scanf 强绑定到了 scanf 上
```

调用了 `_IO_vfscanf`，它在 `stdio-common/vfscanf.c`，如下：

```c
int
___vfscanf (FILE *s, const char *format, va_list argptr)
{
  return _IO_vfscanf_internal (s, format, argptr, NULL);
}
ldbl_strong_alias (_IO_vfscanf_internal, _IO_vfscanf)
ldbl_hidden_def (_IO_vfscanf_internal, _IO_vfscanf)
ldbl_strong_alias (___vfscanf, __vfscanf)
ldbl_hidden_def (___vfscanf, __vfscanf)
ldbl_weak_alias (___vfscanf, vfscanf)
```

这里发现主要起作用的是 `_IO_vfscanf_internal`，这个函数很长
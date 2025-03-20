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

这里发现主要起作用的是 `_IO_vfscanf_internal`，这个函数很长，关注关键调用：


```c
# define inchar()	(c == EOF ? ((errno = inchar_errno), EOF)	      \
			 : ((c = _IO_getc_unlocked (s)),		      \
			    (void) (c != EOF				      \
				    ? ++read_in				      \
				    : (size_t) (inchar_errno = errno)), c))

int
_IO_vfscanf_internal (_IO_FILE *s, const char *format, _IO_va_list argptr,
		      int *errp)
{
	...
	  /* Run through the format string.  */
  while (*f != '\0')
    {
		...
	  fc = *f++;
	  if (fc != '%')
		{
		  /* Remember to skip spaces.  */
		  if (ISSPACE (fc))
		    {
		      skip_space = 1;
		      continue;
		    }
	
		  /* Read a character.  */
	  c = inchar ();
		...
	  }
	  ...
	}
	...
}
```

这里调用的 `inchar ()` 会去调用 `_IO_getc_unlocked`:

```c
#define _IO_getc_unlocked(_fp) \
       (_IO_BE ((_fp)->_IO_read_ptr >= (_fp)->_IO_read_end, 0) \
	? __uflow (_fp) : *(unsigned char *) (_fp)->_IO_read_ptr++)

int
__uflow (_IO_FILE *fp)
{
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  if (_IO_vtable_offset (fp) == 0 && _IO_fwide (fp, -1) != -1)
    return EOF;
#endif

  if (fp->_mode == 0)
    _IO_fwide (fp, -1);
  if (_IO_in_put_mode (fp))
    if (_IO_switch_to_get_mode (fp) == EOF)
      return EOF;
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr++;
  if (_IO_in_backup (fp))
    {
      _IO_switch_to_main_get_area (fp);
      if (fp->_IO_read_ptr < fp->_IO_read_end)
	return *(unsigned char *) fp->_IO_read_ptr++;
    }
  if (_IO_have_markers (fp))
    {
      if (save_for_backup (fp, fp->_IO_read_end))
	return EOF;
    }
  else if (_IO_have_backup (fp))  // 注意这里
    _IO_free_backup_area (fp);
  return _IO_UFLOW (fp);
}

#define _IO_UFLOW(FP) JUMP0 (__uflow, FP)

```

然后这里会调用 `_IO_UFLOW`，也就是通过虚标跳到 `__uflow`，然后会 jump 到 `_IO_underflow_t`，然后这个虚表函数会指向 `_IO_file_underflow`：

```c
# define _IO_new_file_underflow _IO_file_underflow

int
_IO_new_file_underflow (_IO_FILE *fp)
{
  _IO_ssize_t count;
#if 0
  /* SysV does not make this test; take it out for compatibility */
  if (fp->_flags & _IO_EOF_SEEN)
    return (EOF);
#endif

  if (fp->_flags & _IO_NO_READS)  // 需要过的 check1
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  if (fp->_IO_read_ptr < fp->_IO_read_end)  // 需要过的 check2
    return *(unsigned char *) fp->_IO_read_ptr;

  if (fp->_IO_buf_base == NULL)  // 需要过的 check3
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_IO_save_base != NULL)
	{
	  free (fp->_IO_save_base);
	  fp->_flags &= ~_IO_IN_BACKUP;
	}
      _IO_doallocbuf (fp);
    }

  ...

  _IO_switch_to_get_mode (fp);

  /* This is very tricky. We have to adjust those
     pointers before we call _IO_SYSREAD () since
     we may longjump () out while waiting for
     input. Those pointers may be screwed up. H.J. */
  fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
  fp->_IO_read_end = fp->_IO_buf_base;
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end
    = fp->_IO_buf_base;

  count = _IO_SYSREAD (fp, fp->_IO_buf_base,
		       fp->_IO_buf_end - fp->_IO_buf_base);  // 重点关注这里
  ...
  fp->_IO_read_end += count; // 关注这里
  ...
  return *(unsigned char *) fp->_IO_read_ptr;
}
libc_hidden_ver (_IO_new_file_underflow, _IO_file_underflow)
```

总结下来调用链就是：

```
scanf
  -> vfscanf
	-> _IO_vfscanf_internal
	  -> _IO_getc_unlocked
		-> __uflow
		  -> _IO_new_file_underflow
			-> _IO_SYSREAD
```

为了绕过保护，需要构造有：
- 设置 `fp->_flags & (~0x4)`
- 设置 `_IO_read_end` 等于 `_IO_read_ptr`
- 设置 `_fileno == 0`
- 设置 `fp->_IO_buf_base` 为写入的起始位置，`fp->_IO_buf_end` 为写入的终止位置，`fp->_IO_buf_end - fp->_IO_buf_base` 为读入的长度
- `_IO_write_xxx` 不能随便写，保持原来的值
- `_IO_save_base` 不要写东西，这个是因为下面这个函数：

```c
#define _IO_have_backup(fp) ((fp)->_IO_save_base != NULL)

void
_IO_free_backup_area (_IO_FILE *fp)
{
  if (_IO_in_backup (fp))
    _IO_switch_to_main_get_area (fp);  /* Just in case. */
  free (fp->_IO_save_base);
  fp->_IO_save_base = NULL;
  fp->_IO_save_end = NULL;
  fp->_IO_backup_base = NULL;
}
libc_hidden_def (_IO_free_backup_area)
```

这里会 `free` 一个地址，如果不合法的话程序就会 dump。

一个思路：这里可以释放任意合法 chunk，不过感觉没什么用。

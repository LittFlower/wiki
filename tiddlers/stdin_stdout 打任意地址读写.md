## 简介

FILE 在 Linux 系统的标准 IO 库中是用于描述文件的结构，称为文件流。 FILE 结构在程序执行 fopen 等函数时会进行创建，并分配在堆中。我们常定义一个指向 FILE 结构的指针来接收这个返回值。

在标准 I/O 库中，每个程序启动时有三个文件流是自动打开的：stdin、stdout、stderr。因此在初始状态下，_IO_list_all 指向了一个有这些文件流构成的链表，但是需要注意的是这三个文件流位于 libc.so 的数据段。而我们使用 fopen 创建的文件流是分配在堆内存上的。

`FILE` 的结构这里不再详细描述了，之前学 apple 的时候已经看过了，简单来说在 pwndbg 调试时，可以 `p _IO_2_1_stdin` 查看它们的详细结构。

这里主要介绍一下比较常用的指针：

- `_IO_buf_base`：输入（出）缓冲区的基地址，例如 `_IO_file_xsgetn` 函数会通过它来判断输入缓冲区是否为空，为空则会调用 `_IO_doallocbuf` 函数来进行初始化。
- `_IO_buf_end`：输入（出）缓冲区的结束地址。

在建立输入输出缓冲区后，如果缓冲区作为输入缓冲区使用，则会将 `_IO_buf_base` 基地址赋值给 `_IO_read_base`，结束地址 `_IO_buf_end` 赋值给 `_IO_read_end`
- `_IO_read_ptr`：指向当前已经写入的地址。
- `_IO_read_base`：输入缓冲区的基地址。
- `_IO_read_end`：一般和 `_IO_read_ptr` 共同使用，`_IO_read_end-_IO_read_ptr` 表示可用的输入缓冲区大小。

如果缓冲区作为输出缓冲区使用则同理。

而我们在 CTF 题目中非常常见的一个初始化函数是：

```c
setvbuf(stdin, 0LL, 2, 0LL);
setvbuf(stdout, 0LL, 2, 0LL);
setvbuf(stderr, 0LL, 2, 0LL);
```

这个函数的作用是设置 `_IO_buf_end - _IO_buf_base = 1`，这样的效果是缓冲区长度只有 1，也就是 1 字节输入/出一次。

另一个比较常用的指针是 `_flags`，这个常量的定义在 `glibc/libio/libio.h`：

```c
/* Magic number and bits for the _flags field.  The magic number is
mostly vestigial, but preserved for compatibility.  It occupies the
high 16 bits of _flags; the low 16 bits are actual flag bits.  */
#define _IO_MAGIC         0xFBAD0000 /* Magic number */
#define _IO_MAGIC_MASK    0xFFFF0000
#define _IO_USER_BUF          0x0001 /* Don't deallocate buffer on close. */
#define _IO_UNBUFFERED        0x0002
#define _IO_NO_READS          0x0004 /* Reading not allowed.  */
#define _IO_NO_WRITES         0x0008 /* Writing not allowed.  */
#define _IO_EOF_SEEN          0x0010
#define _IO_ERR_SEEN          0x0020
#define _IO_DELETE_DONT_CLOSE 0x0040 /* Don't call close(_fileno) on close.  */
#define _IO_LINKED            0x0080 /* In the list of all open files.  */
#define _IO_IN_BACKUP         0x0100
#define _IO_LINE_BUF          0x0200
#define _IO_TIED_PUT_GET      0x0400 /* Put and get pointer move in unison.  */
#define _IO_CURRENTLY_PUTTING 0x0800
#define _IO_IS_APPENDING      0x1000
#define _IO_IS_FILEBUF        0x2000
/* 0x4000  No longer used, reserved for compat.  */
#define _IO_USER_LOCK         0x8000
```


## 原理

### stdin 攻击面分析

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

  // 注意下面三行
  // 也就是：_IO_new_file_underflow 中在执行系统调用之前会设置一次 FILE 指针，将
  // _IO_read_base、_IO_read_ptr、_IO_read_end、
  // _IO_write_base、IO_write_ptr、IO_write_end
  // 全部设置为 _IO_buf_base。

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

这个 `_IO_SYSREAD` 会调用虚表里的 `__read` 也就是 `__GI__IO_file_read`，这个函数会 `jmp` 到 `__GI___libc_read`。

总结下来调用链就是：

```
scanf
  -> vfscanf
	-> _IO_vfscanf_internal
	  -> _IO_getc_unlocked
		-> __uflow
		  -> _IO_new_file_underflow
			-> _IO_SYSREAD
			  -> __read = __GI___libc_read
```

为了绕过保护，需要构造有：
- 设置 `fp->_flags & (~0x4)`（这里最好就是用原来的 `_flags`）（也就是要设置倒数第二字节为 `\x00`）
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



可以看到，如想通过 `stdin` 打任意地址写，需要修改的字节还是比较多的。

另外，`fread`、`fgets` 等函数也是调用 stdin 中的 `_IO_new_file_underflow` 去调用 `read` 的。



### stdout 攻击面分析


以 `puts` 为例。

```c
int
_IO_puts (const char *str)
{
  int result = EOF;
  size_t len = strlen (str);
  _IO_acquire_lock (stdout);

  if ((_IO_vtable_offset (stdout) != 0
       || _IO_fwide (stdout, -1) == -1)
      && _IO_sputn (stdout, str, len) == len  // 关注这里
      && _IO_putc_unlocked ('\n', stdout) != EOF)
    result = MIN (INT_MAX, len + 1);

  _IO_release_lock (stdout);
  return result;
}
```

可以看到调用了 `_IO_sputn`，跟进分析：

```c
size_t
_IO_new_file_xsputn (FILE *f, const void *data, size_t n)
{
  const char *s = (const char *) data;
  size_t to_do = n;
  int must_flush = 0;
  size_t count = 0;

  if (n <= 0)
    return 0;
  /* This is an optimized implementation.
     If the amount to be written straddles a block boundary
     (or the filebuf is unbuffered), use sys_write directly. */

  /* First figure out how much space is available in the buffer. */
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
    {
      count = f->_IO_buf_end - f->_IO_write_ptr;
      if (count >= n)
	{
	  const char *p;
	  for (p = s + n; p > s; )
	    {
	      if (*--p == '\n')
		{
		  count = p - s + 1;
		  must_flush = 1;
		  break;
		}
	    }
	}
    }
  else if (f->_IO_write_end > f->_IO_write_ptr)
    count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */

  /* Then fill the buffer. */
  if (count > 0)
    {
      if (count > to_do)
	count = to_do;
      f->_IO_write_ptr = __mempcpy (f->_IO_write_ptr, s, count);  // 注意这里1️⃣
      s += count;
      to_do -= count;
    }
  if (to_do + must_flush > 0)
    {
      size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)  // 注意这里
	/* If nothing else has to be written we must not signal the
	   caller that everything has been written.  */
	return to_do == 0 ? EOF : n - to_do;

	  ...
    }
  return n - to_do;
}
```

这里看到会去调用 `_IO_OVERFLOW`，实际上在虚表里是 `_IO_new_file_overflow`，这个函数实现如下，需要绕过的重要的检测也都在这个函数里：

```c
int
_IO_new_file_overflow (FILE *f, int ch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */   // check1
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)   // check2
    {
      /* Allocate a buffer if needed. */
      if (f->_IO_write_base == NULL)
	{
	  _IO_doallocbuf (f);
	  _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
	}
      ...

      if (f->_IO_read_ptr == f->_IO_buf_end)
	f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;
      f->_IO_write_ptr = f->_IO_read_ptr;
      f->_IO_write_base = f->_IO_write_ptr;
      f->_IO_write_end = f->_IO_buf_end;
      f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;

      f->_flags |= _IO_CURRENTLY_PUTTING;
      if (f->_mode <= 0 && f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
	f->_IO_write_end = f->_IO_write_ptr;
    }
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,   // 注意这里2️⃣
			 f->_IO_write_ptr - f->_IO_write_base);
  ...
}
```

这里会调用 `_IO_do_write`，这个作用是输出缓冲区。

#### 任意写

这一部分的攻击面来自于上面那段“注意这里1️⃣”，如果我们劫持了 `fp->_IO_write_ptr` 就可以任意地址写了。

也就是说，只需要构造：`fp -> _IO_write_ptr` 和 `fp -> _IO_write_end`，指向要写的位置。

#### 任意读


这一部分的攻击面来自于上面那段“注意这里2️⃣”

再看一下 `_IO_do_write`：


```c
// 位于libio/fileops.c
int _IO_new_do_write(_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
    return (to_do == 0 || (_IO_size_t)new_do_write(fp, data, to_do) == to_do) ? 0 : EOF;
}
libc_hidden_ver(_IO_new_do_write, _IO_do_write)

static _IO_size_t
    new_do_write(_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
    _IO_size_t count;
    // 有两个判断，第一个看起来不影响，但else if里面比较复杂不可控，需要绕过
    if (fp->_flags & _IO_IS_APPENDING)       // check3
        /* On a system without a proper O_APPEND implementation,
           you would need to sys_seek(0, SEEK_END) here, but is
           not needed nor desirable for Unix- or Posix-like systems.
           Instead, just indicate that offset (before and after) is
           unpredictable. */
        fp->_offset = _IO_pos_BAD;
    else if (fp->_IO_read_end != fp->_IO_write_base)   // check4
    {
        _IO_off64_t new_pos = _IO_SYSSEEK(fp, fp->_IO_write_base - fp->_IO_read_end, 1);
        if (new_pos == _IO_pos_BAD)
            return 0;
        fp->_offset = new_pos;
    }
    // 满足条件后通过系统调用执行_IO_SYSWRITE
    // data从上面传过来的，是f->_IO_write_base, to_do是f->_IO_write_ptr - f->_IO_write_base
    // 意思就是输出f -> _IO_write_base和_IO_write_ptr之间的内容
    count = _IO_SYSWRITE(fp, data, to_do); 
    // 后面已经和我们无关
    if (fp->_cur_column && count)
        fp->_cur_column = _IO_adjust_column(fp->_cur_column - 1, data, count) + 1;
    _IO_setg(fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
    fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
    fp->_IO_write_end = (fp->_mode <= 0 && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
                             ? fp->_IO_buf_base
                             : fp->_IO_buf_end);
    return count;
}
```

这个函数有两个分支，一般是选择第一个分支来打。

总结一下这部分源码注释里标注的4次 check，总结如下：

- 设置 `fp->_flags & _IO_NO_WRITES == 0`
- 设置 `fp->_flags & _IO_CURRENTLY_PUTTING == 1`
- 设置 `fp -> _fileno = 1`
- 以下二选一
  * 设置 `fp->_flags & _IO_IS_APPENDING == 1`
  * 设置 `fp->_IO_read_end == fp->_IO_write_base`

也就是把 `fp->flags` 设置为 ???

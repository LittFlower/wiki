## 前置知识

House of Some 2 是独立的一条 IO_FILE 利用链，主要关注的函数是 `_IO_wfile_jumps_maybe_mmap` 中的`_IO_wfile_underflow_maybe_mmap`

## 利用链分析

分析如下函数调用链：

```c
wint_t
_IO_wfile_underflow_maybe_mmap (FILE *fp)
{
  /* This is the first read attempt.  Doing the underflow will choose mmap
     or vanilla operations and then punt to the chosen underflow routine.
     Then we can punt to ours.  */
  if (_IO_file_underflow_maybe_mmap (fp) == EOF)
    return WEOF;

  return _IO_WUNDERFLOW (fp);
}

int
_IO_file_underflow_maybe_mmap (FILE *fp)
{
  /* This is the first read attempt.  Choose mmap or vanilla operations
     and then punt to the chosen underflow routine.  */
  decide_maybe_mmap (fp);
  return _IO_UNDERFLOW (fp);
}


static void
decide_maybe_mmap (FILE *fp)
{
  /* We use the file in read-only mode.  This could mean we can
     mmap the file and use it without any copying.  But not all
     file descriptors are for mmap-able objects and on 32-bit
     machines we don't want to map files which are too large since
     this would require too much virtual memory.  */
  struct __stat64_t64 st;

  if (_IO_SYSSTAT (fp, &st) == 0
      && S_ISREG (st.st_mode) && st.st_size != 0
      /* Limit the file size to 1MB for 32-bit machines.  */
      && (sizeof (ptrdiff_t) > 4 || st.st_size < 1*1024*1024)
      /* Sanity check.  */
      && (fp->_offset == _IO_pos_BAD || fp->_offset <= st.st_size))
    {
      /* Try to map the file.  */
      void *p;

		...  // 这里只是做了一些 mmap
    }

  /* We couldn't use mmap, so revert to the vanilla file operations.  */

  if (fp->_mode <= 0)
    _IO_JUMPS_FILE_plus (fp) = &_IO_file_jumps;
  else
    _IO_JUMPS_FILE_plus (fp) = &_IO_wfile_jumps;
  fp->_wide_data->_wide_vtable = &_IO_wfile_jumps;
}
```


整理一下可以知道，如果一个 FILE 进入了函数 `_IO_wfile_underflow_maybe_mmap`，那么他将会运行如下的流程：

1. `_IO_SYSSTAT(fp, &st)` 调用虚表，传入栈指针
2. `decide_maybe_mmap` 函数结束，恢复两个虚表
3. `_IO_UNDERFLOW (fp)` 调用虚表
4. `_IO_WUNDERFLOW (fp)` 调用虚表

在 `_IO_file_jumps` 虚表的 `_IO_UNDERFLOW` 函数中会调用 house of some 利用到的那个任意地址写的链子，也就是下面这一步：

```c
count = _IO_SYSREAD (fp, fp->_IO_buf_base,
       fp->_IO_buf_end - fp->_IO_buf_base);
```


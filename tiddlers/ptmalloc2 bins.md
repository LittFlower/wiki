主要介绍一下 ptmalloc2 的各种 bins。

**提前规定一下：下面说的所有 chunk 大小都是包含 chunk header 的大小。**

首先讲一下常见的宏，`SIZE_SZ` 在 64 位下是 8 字节，在 32 位下是 4 字节。

在 ./malloc/malloc-internal.h 里定义了 `SIZE_SZ` 和 `MALLOC_ALIGN_MASK`，如下：

```c
#ifndef INTERNAL_SIZE_T
# define INTERNAL_SIZE_T size_t
#endif

/* The corresponding word size.  */
#define SIZE_SZ (sizeof (INTERNAL_SIZE_T))

/* The corresponding bit mask value.  */
#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)
```

在 ./sysdeps/generic/malloc-alignment.h 里定义了 `MALLOC_ALIGNMENT`，如下：

```c
#define MALLOC_ALIGNMENT (2 * SIZE_SZ < __alignof__ (long double) \
			  ? __alignof__ (long double) : 2 * SIZE_SZ)
```

因此在 x86-64 机子上，MALLOC_ALIGNMENT 是 0x10.

```c
/* pad request bytes into a usable size -- internal version */

#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
```

上面这个宏可以把用户申请的 `req` 字节对齐后再加 0x10，所以返回给用户的最小 chunk 大小是 0x20。



## fast bin

### chunk 个数

```c
/* offset 2 to use otherwise unindexable first 2 bins */
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)

/* The maximum fastbin request size we support */
// x86 下是 80，x86-64 下是 160
#define MAX_FAST_SIZE     (80 * SIZE_SZ / 4)
#define NFASTBINS  (fastbin_index (request2size (MAX_FAST_SIZE)) + 1)
```

那么口算一下这个 `NFASTBINS`，感觉等于 10（不管是 x86 还是 x86-64），但其实实际测试下来只有 7 个，即从 0x20 ~ 0x80。

这个 fast bin 的 max size 可以在 gdb 里看到：

```bash
pwndbg> p/x global_max_fast
$1 = 0x80
```

```c
static void
malloc_init_state (mstate av)
{
  int i;
  mbinptr bin;

  /* Establish circular links for normal bins */
  for (i = 1; i < NBINS; ++i)
    {
      bin = bin_at (av, i);
      bin->fd = bin->bk = bin;
    }

#if MORECORE_CONTIGUOUS
  if (av != &main_arena)
#endif
  set_noncontiguous (av);
  if (av == &main_arena)
    set_max_fast (DEFAULT_MXFAST);
  atomic_store_relaxed (&av->have_fastchunks, false);

  av->top = initial_top (av);
}
```
这个 `global_max_size` 就是在 `malloc_init_state` 函数里设置的。 

### chunk size 的公差

因为 fast bin 对于每个大小的 chunk 都维护了一个链表，所以链表表头（即存储的 size 大小）之间亦有差距。

存储数据的 chunk size 的公差也可以通过 `fastbin_index` 看，x86 下大小是 0x8 bytes，在 x86-64 下是 0x10 bytes。



## small bin

```c
#define NSMALLBINS 64
#define SMALLBIN_WIDTH MALLOC_ALIGNMENT
// 是否需要对small bin的下标进行纠正
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)

#define MIN_LARGE_SIZE ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)
//判断chunk的大小是否在small bin范围内
#define in_smallbin_range(sz)                                                  \
    ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)
// 根据chunk的大小得到small bin对应的索引。
#define smallbin_index(sz)                                                     \
    ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4)                          \
                           : (((unsigned) (sz)) >> 3)) +                       \
     SMALLBIN_CORRECTION)
```

x64 下，这两行注释表明，smallbin 的个数最多是 64，公差为 0x10。但其实 smallbin 最多 62 个（这一点可以从 0x20 ~ MIN_LARGE_SIZE / 0x10 只有 62 个和 BINs[] 给 smallbin 的只有 62 个导出）


![](https://azeria-labs.com/wp-content/uploads/2019/05/bins-new.png)


## large bin

## unsort bin


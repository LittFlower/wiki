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

x64 下，这两行注释表明，smallbin 的个数最多是 64，公差为 0x10。但其实 smallbin 最多 62 个（这一点可以从 $(MIN_LARGE_SIZE - 0x20) / 0x10$ 只有 62 个和 BINs[] 给 smallbin 的只有 62 个导出）


![](https://azeria-labs.com/wp-content/uploads/2019/05/bins-new.png)


## large bin

由上图可以看到 large bin 的 index 范围是 64 ~ 126 一共 63 个 chunk

根据上面的 small bin 宏中的 `MIN_LARGE_SIZE` 可以推出 x86-64 下最小的 Large Bins size 是 0x400。

```c
#define largebin_index(sz) \
  (SIZE_SZ == 8 ? largebin_index_64 (sz)                                     \
   : MALLOC_ALIGNMENT == 16 ? largebin_index_32_big (sz)                     \
   : largebin_index_32 (sz))
```

在常见的 x86-64 环境下，`SIZE_SZ == 8` 这个条件基本上都是满足的，所以就是用 `largebin_index_64` 这个宏，看看这个：

```c
#define largebin_index_64(sz)                                                \
  (((((unsigned long) (sz)) >> 6) <= 48) ?  48 + (((unsigned long) (sz)) >> 6) :\
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
   126)
```

根据这个推一下，当 `sz = 0x400` 时，`sz >> 6 = 16` 故起始 index 确确实实是 64，根据这个宏可以推出 x86-64 下的 largebin 的取值范围情况，它将 bin 分为 6 组，每个组内的 chunk 大小的公差一致。

简单说一下这里怎么调试，main_arena 作为 libc.so.6 的全局静态变量，可以在 gdb 里直接查看 bins 数组，然后可以查看当前的 largebin 在 bins 里的 index。

总之你可以看出来，就算在同一个 largebin index 中，其 chunk 大小也有差别，这和 fastbin 是不一样的。

```c
/*
  This struct declaration is misleading (but accurate and necessary).
  It declares a "view" into memory allowing access to necessary
  fields at known offsets from a given base. See explanation below.
*/
struct malloc_chunk {
  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */
  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;
  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

所以堆管理器就利用这个结构中的 fd_nextsize 和 bk_nextsize 来链接到下一个 size 的堆块头部和上一个 size 的堆块头部。然后在相同 size 的堆块内部再通过 fd 和 bk 来进行内部的管理。

比如说我释放 0x400 0x410 0x420 （这里的释放顺序不重要）三个大小的 chunk 进入 largebin，首先他们三个会在同一个 index 里，其次他们三个会按照从大到小的顺序排序：即表头是最大的 chunk，在这个循环链表中 fd 可以理解为下一个堆块、bk 是上一个堆块、nfd 指向下一个大小的堆块、nbk 指向上一个大小的堆块，这里就能体现出 nfd/nbk 和 fd/bk 的区别了：

- 首先规定一下双向循环链表的 “上” 和 “下”，只需将 `bk = largebin_addr` 的 chunk 放在最上面、`fd = largebin_addr` 的 chunk 放在最下面，即可确定“顺序”（而且在 pwndbg 中查看 largebins 时，也会表现为一种从左到右的单向链表）
- largebin 中同一个 index 的 chunk 总是有序的，最大的在上面，最小的在下面，最上面 chunk 的 bk 是 largebin_addr，最下面 chunk 的 fd 是 largbin_addr；
- 在一个 index 中，同一大小（指大小完全相同）的 chunk 会按照释放顺序排序，即最先释放的在最上面，最后释放的最下面（fd 可能为 largebin_addr）。
- fd/bk 永远不可能为 0，但是 nfd/nbk 可能为 0，这种情况发生在同一大小的 chunk 排列时，只有最上面的 chunk 作为此大小的 chunk 代表参与到 nfd/nbk 的排序中，其余的 nfd/nbk 都为 0。
- size 最大的 chunk 的 bk_nextsize 指向最小的 chunk，size 最小的 chunk 的 fd_nextsize 指向最大的 chunk

![](https://pic.imgdb.cn/item/676cdeedd0e0a243d4ea7b71.png)
![](https://pic.imgdb.cn/item/676cd9a6d0e0a243d4ea7a91.png)


## unsort bin


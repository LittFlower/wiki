主要介绍一下 ptmalloc2 的各种 bins。



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

上面这个宏可以把申请的 `req` 自动补全到字节对齐。



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

那么口算一下这个 `NFASTBINS`，感觉等于 9（不管是 x86 还是 x86-64）。

### chunk size 的公差

因为 fast bin 对于每个大小的 chunk 都维护了一个链表，所以链表表头（即存储的 size 大小）之间亦有差距。

存储数据的 chunk size 的公差也可以通过 `fastbin_index` 看，x86 下大小是 8 bytes，在 x86-64 下是 16 bytes。


## small bin

## large bin

## unsort bin


## 什么是 Tcache bin

Tcache bin 是自 glibc 2.26 开始出现的，源码位置在 `/glibc-2.26/malloc/malloc.c`。

它的数据结构部分的定义在这里：

```c
/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;

/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

简单来说，这个数据结构长这样:

![](https://pic.imgdb.cn/item/674ef704d0e0a243d4dcd773.png)

主要有以下几个点：

- TPS 里维护了两个数组，`counts[]` 和 `*entries[]`，它们的大小都是 64，即最多可以放下从 0x20 ~ 0x410 一共 64 种大小的 chunk。
- `*entries[]` 里存放的是 chunk 的 fd 指针处的 addr，并且 chunk 的 fd 指针会被设置成下一个同大小的 free chunk（就是那个 *next），而 bk 指针会被设置成一个 key（glibc2.27_0ubuntu1_amd64 及以下的 glibc 会把 bk 设置成 TPS_addr，再高一点的版本（2.27-3ubuntu1.5_amd64）都会设置成一个随机数），这个 key 可以用来校验 double free。

在 Glibc 2.31 以下，TPS 的大小为 0x250 = (0x10 + 64 * 1 + 64 * 8)，0x10 是 header，1 字节是 `char count[idx]`，8 字节是 `*entry`。

这里可以打 TPS 结构体，做到任意大小、地址申请。


直接把相关部分的关键代码贴一下，具体来讲在 2923 ～ 3015 行：

```c
#if USE_TCACHE

/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  return (void *) e;
}

static void
tcache_thread_shutdown (void)
{
  int i;
  tcache_perthread_struct *tcache_tmp = tcache;

  if (!tcache)
    return;

  /* Disable the tcache and prevent it from being reinitialized.  */
  tcache = NULL;
  tcache_shutting_down = true;

  /* Free all of the entries and the tcache itself back to the arena
     heap for coalescing.  */
  for (i = 0; i < TCACHE_MAX_BINS; ++i)
    {
      while (tcache_tmp->entries[i])
	{
	  tcache_entry *e = tcache_tmp->entries[i];
	  tcache_tmp->entries[i] = e->next;
	  __libc_free (e);
	}
    }

  __libc_free (tcache_tmp);
}

static void
tcache_init(void)
{
  mstate ar_ptr;
  void *victim = 0;
  const size_t bytes = sizeof (tcache_perthread_struct);

  if (tcache_shutting_down)
    return;

  arena_get (ar_ptr, bytes);
  victim = _int_malloc (ar_ptr, bytes);
  if (!victim && ar_ptr != NULL)
    {
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }


  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);

  /* In a low memory situation, we may not be able to allocate memory
     - in which case, we just keep trying later.  However, we
     typically do this very early, so either there is sufficient
     memory, or there isn't enough memory to do non-trivial
     allocations anyway.  */
  if (victim)
    {
      tcache = (tcache_perthread_struct *) victim;
      memset (tcache, 0, sizeof (tcache_perthread_struct));
    }

}

# define MAYBE_INIT_TCACHE() \
  if (__glibc_unlikely (tcache == NULL)) \
    tcache_init();

#else  /* !USE_TCACHE */
```

主要看一下 tcache bin 的数据结构和关键操作函数 `tcache_put` 和 `tcache_get`。

`tcache_get` 会在 `_int_malloc` 里调用

`tcache_put` 会在 `_int_free` 和 `_int_malloc` 里调用

具体可以参考源码。

还有一些宏定义：

```c
/* We want 64 entries.  This is an arbitrary limit, which tunables can reduce.  */
# define TCACHE_MAX_BINS		64
```


## 漏洞分析

`tcache_get` 如下：

```c
/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  return (void *) e;
}
```

显然，这里也没有任何安全性校验，直接把 `tcache_entries[tc_idx]` 设置成了 chunk 的 fd 指针，由此引发出 [[tcache poisoning]] 攻击。

重新审视一下 `tcache_put`，如下：

```c
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

可以看到函数中几乎没有任何安全性校验，只需要保证 `tc_idx < 64` 就行，然后就会把 `tcache->entries[tc_idx]` 更新成一个新 free chunk，且它的 fd 是上一个同大小 free chunk。

而这种逻辑上的不严谨可能造成多种漏洞，例如 double free 漏洞，即 [[tcache dup]]；还可以伪造一个 size 使得其满足 `tc_idx` 的检查，构造一个 fake chunk，这就是 [[tcache house of spirit]]。


## 高版本的 tcache

glibc 2.31 版本中，加入了对 tcache double free 的 check，也就是说不能像以前那样无脑 free 两个一样的 tcache chunk 进行攻击了，但是依然可以打 house of botcake，也就是把 fastbin / unsortbin 和 tcache 结合起来打。
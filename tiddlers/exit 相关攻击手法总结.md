## 源码分析

用的源码是 glibc 2.35 的，具体版本是 Ubuntu GLIBC 2.35-0ubuntu3.9，在 glibc all in one 里可以下载到。

调试信息我是用 docker 下载的，然后拷出来在我的 arch linux 上慢慢调试。

`exit` 函数定义在 glibc 的 stdlib/exit.c 中，如下：

```c
void
exit (int status)
{
  __run_exit_handlers (status, &__exit_funcs, true, true);
}
libc_hidden_def (exit)
```

有一个很重要的结构 `__exit_funcs`，如下：


```c
enum
{
  ef_free,	/* `ef_free' MUST be zero!  */
  ef_us,
  ef_on,
  ef_at,
  ef_cxa
};

struct exit_function  // 析构函数的类型，可以是 {ef_free, ef_us, ef_on, ef_at, ef_cxa} 之一
  {                   // ef_free 表示此位置空闲
					  // ef_us 表示此位置被占用，但是不知道函数类型
					  // ef_on ef_at ef_cxa 都表示了具体的函数类型，差别在参数上
    /* `flavour' should be of type of the `enum' above but since we need
       this element in an atomic operation we have to use `long int'.  */
    long int flavor;
    union             // 使用 union 声明结构
      {
	void (*at) (void);
	struct
	  {
	    void (*fn) (int status, void *arg);
	    void *arg;
	  } on;
	struct
	  {
	    void (*fn) (void *arg, int status);
	    void *arg;
	    void *dso_handle;
	  } cxa;
      } func;
  };
struct exit_function_list
  {
    struct exit_function_list *next; // 单链表
    size_t idx;                      // 记录当前节点有多少个析构函数
    struct exit_function fns[32];    // 析构函数数组
  };

extern struct exit_function_list *__exit_funcs attribute_hidden;
```

**总结**：这里的 `__exit_funcs` 是一个单向链表，链表中每个节点都会注册若干个析构函数用来释放/回收资源。

剩下的看注释。


同时可以看到调用了 `__run_exit_handlers`，其中


跟进去看：

```c
/* Call all functions registered with `atexit' and `on_exit',
   in the reverse of the order in which they were registered
   perform stdio cleanup, and terminate program execution with STATUS.  */
/* 上面这段注释的意思是，调用 atexit 和 on_exit 注册的函数，
   调用顺序为注册时的逆序
   最后会带着状态码终止程序执行                                              */
void
attribute_hidden
__run_exit_handlers (int status, struct exit_function_list **listp,
		     bool run_list_atexit, bool run_dtors)
{
  /* First, call the TLS destructors.  */
  /* 首先释放线程局部储存, 即 TLS \
	 这里是一个攻击点                     */

#ifndef SHARED
  if (&__call_tls_dtors != NULL)
#endif
    if (run_dtors)
      __call_tls_dtors ();

  __libc_lock_lock (__exit_funcs_lock);

  /* We do it this way to handle recursive calls to exit () made by
     the functions registered with `atexit' and `on_exit'. We call
     everyone on the list and use the status value in the last
     exit (). */
  while (true)
    {
      struct exit_function_list *cur;

    restart:
      cur = *listp;  // 取出链表中的节点

      if (cur == NULL)
	{
	  /* Exit processing complete.  We will not allow any more
	     atexit/on_exit registrations.  */
	  __exit_funcs_done = true;
	  break;
	}

      while (cur->idx > 0)  // 如果该节点有注册的函数，那么遍历取出
	{
	  struct exit_function *const f = &cur->fns[--cur->idx];  // 取出
	  const uint64_t new_exitfn_called = __new_exitfn_called;

	  switch (f->flavor)
	    {
	      void (*atfct) (void);
	      void (*onfct) (int status, void *arg);
	      void (*cxafct) (void *arg, int status);
	      void *arg;

	    case ef_free:  // 如果注册的函数是 ef_free ef_us，不执行
	    case ef_us:
	      break;
	    case ef_on:
	      onfct = f->func.on.fn;  // 取出函数指针
	      arg = f->func.on.arg;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (onfct);
#endif
	      /* Unlock the list while we call a foreign function.  */
	      __libc_lock_unlock (__exit_funcs_lock);
	      onfct (status, arg);  // 调用
	      __libc_lock_lock (__exit_funcs_lock);
	      break;
	    case ef_at:
	      atfct = f->func.at;  // 取出函数指针
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (atfct);
#endif
	      /* Unlock the list while we call a foreign function.  */
	      __libc_lock_unlock (__exit_funcs_lock);
	      atfct ();  // 调用
	      __libc_lock_lock (__exit_funcs_lock);
	      break;
	    case ef_cxa:
	      /* To avoid dlclose/exit race calling cxafct twice (BZ 22180),
		 we must mark this function as ef_free.  */
	      f->flavor = ef_free;
	      cxafct = f->func.cxa.fn;
	      arg = f->func.cxa.arg;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (cxafct);
#endif
	      /* Unlock the list while we call a foreign function.  */
	      __libc_lock_unlock (__exit_funcs_lock);
	      cxafct (arg, status);  // 调用
	      __libc_lock_lock (__exit_funcs_lock);
	      break;
	    }

	  if (__glibc_unlikely (new_exitfn_called != __new_exitfn_called))
	    /* The last exit function, or another thread, has registered
	       more exit functions.  Start the loop over.  */
	    goto restart;
	}

      *listp = cur->next;
      if (*listp != NULL)
	/* Don't free the last element in the chain, this is the statically
	   allocate element.  */
	/* 上面这段注释的意思是，最后一个链表节点为 libc .data 段中的 initial，不需要释放
	   除此以外的节点都是malloc申请得到的, 所以需要释放  */
	free (cur);
    }

  __libc_lock_unlock (__exit_funcs_lock);

  if (run_list_atexit)  // 调用 _atexit
    RUN_HOOK (__libc_atexit, ());

  _exit (status);
}
```


比如一个比较简单的程序，在 exit 释放资源时，调用 `__run_exit_handlers` 如下：

![](https://pic1.imgdb.cn/item/67dbb71388c538a9b5c1a060.png)

这里比较明显的看到 `__exit_funcs` 里只有一个 `initial`，它就在 libc 里。


### `__exit_funcs` 里有什么

比较显然的是这些函数都是在 main 运行前注册的，那么就要去思考，[[elf 程序是如何启动的？]]

所以 `__exit_funcs` 里的析构函数应该都是通过 `__libc_start_main` 注册的。

看一下 `__libc_start_main`:

```c
/* Note: The init and fini parameters are no longer used.  fini is
   completely unused, init is still called if not NULL, but the
   current startup code always passes NULL.  (In the future, it would
   be possible to use fini to pass a version code if init is NULL, to
   indicate the link-time glibc without introducing a hard
   incompatibility for new programs with older glibc versions.)

   For dynamically linked executables, the dynamic segment is used to
   locate constructors and destructors.  For statically linked
   executables, the relevant symbols are access directly.  */

/* 上面这段注释的意思是，`init` 参数和 `fini` 参数都已经弃用了 */
STATIC int
LIBC_START_MAIN (int (*main) (int, char **, char ** MAIN_AUXVEC_DECL),
		 int argc, char **argv,
#ifdef LIBC_START_MAIN_AUXVEC_ARG
		 ElfW(auxv_t) *auxvec,
#endif
		 __typeof (main) init,
		 void (*fini) (void),
		 void (*rtld_fini) (void), void *stack_end)
{
#ifndef SHARED
  char **ev = &argv[argc + 1];

  __environ = ev;

  /* Store the lowest stack address.  This is done in ld.so if this is
     the code for the DSO.  */
  __libc_stack_end = stack_end;

  ...

  /* Do static pie self relocation after tunables and cpu features
     are setup for ifunc resolvers. Before this point relocations
     must be avoided.  */
  _dl_relocate_static_pie ();

  /* Perform IREL{,A} relocations.  */
  ARCH_SETUP_IREL ();

  /* The stack guard goes into the TCB, so initialize it early.  */
  ARCH_SETUP_TLS ();

  /* In some architectures, IREL{,A} relocations happen after TLS setup in
     order to let IFUNC resolvers benefit from TCB information, e.g. powerpc's
     hwcap and platform fields available in the TCB.  */
  ARCH_APPLY_IREL ();

  /* Set up the stack checker's canary.  */
  uintptr_t stack_chk_guard = _dl_setup_stack_chk_guard (_dl_random);
# ifdef THREAD_SET_STACK_GUARD
  THREAD_SET_STACK_GUARD (stack_chk_guard);
# else
  __stack_chk_guard = stack_chk_guard;
# endif

  ...

  /* Set up the pointer guard value.  */
  uintptr_t pointer_chk_guard = _dl_setup_pointer_guard (_dl_random,
							 stack_chk_guard);
# ifdef THREAD_SET_POINTER_GUARD
  THREAD_SET_POINTER_GUARD (pointer_chk_guard);
# else
  __pointer_chk_guard_local = pointer_chk_guard;
# endif

#endif /* !SHARED  */

  /* Register the destructor of the dynamic linker if there is any.  */
  if (__glibc_likely (rtld_fini != NULL))
    __cxa_atexit ((void (*) (void *)) rtld_fini, NULL, NULL);  // 重点看这里

  ...

  /* Register the destructor of the statically-linked program.  */
  __cxa_atexit (call_fini, NULL, NULL);

  ...

  if (init != NULL)
    /* This is a legacy program which supplied its own init
       routine.  */
    (*init) (argc, argv, __environ MAIN_AUXVEC_PARAM);  // 注意这里，`init` 如果有的话也会调用
  else
    /* This is a current program.  Use the dynamic segment to find
       constructors.  */
    call_init (argc, argv, __environ);

  /* Auditing checkpoint: we have a new object.  */
  _dl_audit_preinit (GL(dl_ns)[LM_ID_BASE]._ns_loaded);

  if (__glibc_unlikely (GLRO(dl_debug_mask) & DL_DEBUG_IMPCALLS))
    GLRO(dl_debug_printf) ("\ntransferring control: %s\n\n", argv[0]);
#else /* !SHARED */
  call_init (argc, argv, __environ);

  _dl_debug_initialize (0, LM_ID_BASE);
#endif

  __libc_start_call_main (main, argc, argv MAIN_AUXVEC_PARAM);
}
```

也就是说，glibc 2.31 之后的 `initial` 里的析构函数只有 `rtld_fini` 这个指针对应的函数，而在 glibc2.31 之前，这个 `rtld_fini` 函数指针都是 `_dl_fini`。

关于 `init` 和 `fini` 函数指针，前者会遍历程序 .init_array 段里的所有构造函数地址，而后者往往是空指针，所以 .fini_array 里的析构函数地址一般都是由`rtld_fini` 指针里存放的函数管理。

一般情况下，`rtld_fini` 里存放的最常见的析构函数就是 `_dl_fini`，这个在源码里还是能找到：

```c
void
_dl_fini (void)
{
  ...
  for (Lmid_t ns = GL(dl_nns) - 1; ns >= 0; --ns)
    {
      /* Protect against concurrent loads and unloads.  */
      __rtld_lock_lock_recursive (GL(dl_load_lock));    // 重点看这个

      unsigned int nloaded = GL(dl_ns)[ns]._ns_nloaded;
      /* No need to do anything for empty namespaces or those used for
	 auditing DSOs.  */
      if (nloaded == 0
#ifdef SHARED
	  || GL(dl_ns)[ns]._ns_loaded->l_auditing != do_audit
#endif
	  )
	__rtld_lock_unlock_recursive (GL(dl_load_lock));  // 重点看这个
      else
	{
#ifdef SHARED
	  _dl_audit_activity_nsid (ns, LA_ACT_DELETE);
#endif

	  /* Now we can allocate an array to hold all the pointers and
	     copy the pointers in.  */
	  struct link_map *maps[nloaded];

	  unsigned int i;
	  struct link_map *l;
	  assert (nloaded != 0 || GL(dl_ns)[ns]._ns_loaded == NULL);
	  for (l = GL(dl_ns)[ns]._ns_loaded, i = 0; l != NULL; l = l->l_next)
	    /* Do not handle ld.so in secondary namespaces.  */
	    if (l == l->l_real)
	      {
		assert (i < nloaded);

		maps[i] = l;
		l->l_idx = i;
		++i;

		/* Bump l_direct_opencount of all objects so that they
		   are not dlclose()ed from underneath us.  */
		++l->l_direct_opencount;
	      }
	  assert (ns != LM_ID_BASE || i == nloaded);
	  assert (ns == LM_ID_BASE || i == nloaded || i == nloaded - 1);
	  unsigned int nmaps = i;

	  /* Now we have to do the sorting.  We can skip looking for the
	     binary itself which is at the front of the search list for
	     the main namespace.  */
	  /* 对maps进行排序, 确定析构顺序 */
	  _dl_sort_maps (maps, nmaps, (ns == LM_ID_BASE), true);

	  /* We do not rely on the linked list of loaded object anymore
	     from this point on.  We have our own list here (maps).  The
	     various members of this list cannot vanish since the open
	     count is too high and will be decremented in this loop.  So
	     we release the lock so that some code which might be called
	     from a destructor can directly or indirectly access the
	     lock.  */
	  __rtld_lock_unlock_recursive (GL(dl_load_lock));

	  /* 'maps' now contains the objects in the right order.  Now
	     call the destructors.  We have to process this array from
	     the front.  */
	  for (i = 0; i < nmaps; ++i)
	    {
	      struct link_map *l = maps[i];

	      if (l->l_init_called)
		{
		  _dl_call_fini (l);  // 调用的这个函数的实现在下方
#ifdef SHARED
		  /* Auditing checkpoint: another object closed.  */
		  _dl_audit_objclose (l);
#endif
		}

	      /* Correct the previous increment.  */
	      --l->l_direct_opencount;
	    }
	  ...
}
```

注意，这个函数在高版本并没有被移除，不要被一些博客误导了。


```c
void
_dl_call_fini (void *closure_map)
{
  struct link_map *map = closure_map;

  /* When debugging print a message first.  */
  if (__glibc_unlikely (GLRO(dl_debug_mask) & DL_DEBUG_IMPCALLS))
    _dl_debug_printf ("\ncalling fini: %s [%lu]\n\n", map->l_name, map->l_ns);

  /* Make sure nothing happens if we are called twice.  */
  map->l_init_called = 0;

  ElfW(Dyn) *fini_array = map->l_info[DT_FINI_ARRAY];
  if (fini_array != NULL)
    {
        /*
            l->l_addr: 模块 l 的加载基地址
            l->l_info[DT_FINI_ARRAY]: 模块 l 中 fini_array 节的描述符
            l->l_info[DT_FINI_ARRAY]->d_un.d_ptr: 模块 l 中 fini_arrary 节的偏移
            array: 为模块 l 的 fini_array 节的内存地址
        */
      ElfW(Addr) *array = (ElfW(Addr) *) (map->l_addr
                                          + fini_array->d_un.d_ptr);
      size_t sz = (map->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
                   / sizeof (ElfW(Addr)));

      while (sz-- > 0) //从后往前, 调用fini_array中的每一个析构函数
        ((fini_t) array[sz]) ();
    }

  /* Next try the old-style destructor.  */
  /* 调用fini段中的函数 */
  ElfW(Dyn) *fini = map->l_info[DT_FINI];
  if (fini != NULL)
    DL_CALL_DT_FINI (map, ((void *) map->l_addr + fini->d_un.d_ptr));
}
```

在低版本里这个函数被实现在 `_dl_fini.c` 里，但是内容基本上是差不多的。

这里 `fini_array->d_un.d_ptr` 是不可写的，所以只能通过修改 `map->l_addr` 的方式劫持程序执行流。

而且实际调试发现，高版本中并没有直接去 call 这个函数，用的是 `jmp` 之类的方式，所以一开始调试的时候找不到符号搞得人很蒙圈。


## 攻击

### 劫持 `__exit_funcs`

并非不能劫持，但是比较麻烦。

![](https://pic1.imgdb.cn/item/67dbb77788c538a9b5c1a155.png)

重点看这里的 `ror` 对节点的 `fn` 字段进行循环异或，然后用 `fs:[0x30]` 异或，fs 指向当前线程的控制块，也就是 `tcbhead_t` 结构体：[[tcbhead_t 结构体的定义]]

所以如果要伪造这个链表的话，需要能泄漏或者能修改 `pointer_guard` 的值，然后能往 libc 的 `__exit_funcs` 写入伪造好的链表位置。

这个异或加密是全版本都有的。

### 打 exit hook

其实就是打原理部分提到的 `_dl_fini` 里的 `__rtld_lock_lock_recursive` 和 `__rtld_lock_unlock_recursive`，这两个函数在低版本（大致为 2.31 前）被实现成函数指针的形式，也就是存放在 ld 里，并且是存放的地方是可写的，这是常说的 exit hook。

也就是

```
_rtld_global._dl_rtld_lock_recursive(&(_rtld_global._dl_load_lock).mutex)
_rtld_global._dl_rtld_unlock_recursive(&(_rtld_global._dl_load_lock).mutex)
```

这两个指针可以调试得出，可以把函数指针改为 `system`，参数改为 `binsh` 实现 getshell。

高版本把这个地方设置为了不可写，如下图

![](https://pic1.imgdb.cn/item/67eab2410ba3d5a1d7e85be9.png)
![](https://pic1.imgdb.cn/item/67eab26e0ba3d5a1d7e85c0c.png)

所以也就没办法打这个了。


### 打 `_dl_fini` 的 `l_addr`

前面说过 `rtld_fini` 会负责调用程序的 .fini_array 里的析构函数，其实就是在 `_dl_call_fini` 里做的。

```c
  if (fini_array != NULL)
    {
      ElfW(Addr) *array = (ElfW(Addr) *) (map->l_addr
                                          + fini_array->d_un.d_ptr);
      size_t sz = (map->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
                   / sizeof (ElfW(Addr)));

      while (sz-- > 0)
        ((fini_t) array[sz]) ();
    }
```


仔细调试一下这一部分函数，会发现这里有大量可以操作的函数逻辑，例如，笔者在本地调试一个很简单的 poc 时，`maps` 里一共存储了 4 个 link_map 指针，如下图（存在栈上）：

![](https://pic1.imgdb.cn/item/67eabf7d0ba3d5a1d7e863b4.png)

而在 pwndbg 中也可以输入 `linkmap` 直接看到。

显然这四个模块里存放的析构函数都应该是要被调用的，所以理论上都可以打。最常见的打法就是打第一个模块，它的 `map->l_addr` 是一个 pie 地址，通过调整（做部分写）可以实现无限 main 函数执行等功能。

因此这里的利用点有很多，具体题目具体分析即可。

### 劫持 `l_info` 伪造 `fini_array` 节

攻击面还是在上面那个函数，局部变量 `fini_array` 是通过 `map->l_info[26]` 确定的，那么如果这个地址可控，那就可以把 `fini_array` 伪造到堆上，最终可以打出一个 rop 的效果，实现 orw 等等。

但是这个在高版本中利用面并不广泛，因为需要任意地址写堆地址这种，那为什么不打 house of apple2 呢？

### 打 fini

由于 `_dl_call_fini` 最后会调用 

```c
  ElfW(Dyn) *fini = map->l_info[DT_FINI];
  if (fini != NULL)
    DL_CALL_DT_FINI (map, ((void *) map->l_addr + fini->d_un.d_ptr));
```

这么个东西，所以这里也可以尝试去劫持 fini 实现攻击。

### 打 `__libc_atexit`

这个函数在 `run_exit_handlers` 里，遍历完 `exit_funcs` 后会 `RUN_HOOK(__libc_atexit, ());`，那么劫持 `__libc_atexit` 就可以打 ogg。

但是这个打法不稳定，高版本栈基本上不满足条件，而且这个地址不可写。

### 打 `__call_tls_dtors`

```c
void
__call_tls_dtors (void)
{
  while (tls_dtor_list)
    {
      struct dtor_list *cur = tls_dtor_list;
      dtor_func func = cur->func;
#ifdef PTR_DEMANGLE
      PTR_DEMANGLE (func);
#endif
​
      tls_dtor_list = tls_dtor_list->next;
      func (cur->obj);
      atomic_fetch_add_release (&cur->map->l_tls_dtor_count, -1);
      free (cur);
    }
}
```

这个全版本都能用，但是最大的问题在于 `fs:[0x30]` 也就是 `pointer_guard` 不好泄漏或者修改，如果可以修改/泄漏的话，那依然可以随便打，但还是那句话，高版本既然可以任意地址写了，为什么不打 house of apple2 呢？
## 源码分析

用的源码是 glibc 2.35 的。

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




## 攻击

### 劫持 `__exit_funcs`

并非不能劫持，但是比较麻烦。

![](https://pic1.imgdb.cn/item/67dbb77788c538a9b5c1a155.png)

重点看这里的 `ror` 对节点的 `fn` 字段进行循环异或，然后用 `fs:[0x30]` 异或，fs 指向当前线程的控制块，也就是 `tcbhead_t` 结构体：[[tcbhead_t 结构体的定义]]

所以如果要伪造这个链表的话，需要能泄漏或者能修改 `pointer_guard` 的值，然后能往 libc 的 `__exit_funcs` 写入伪造好的链表位置。

这个异或加密是全版本都有的。


## 打 `_dl_fini` 的 `l_addr`

适用版本：

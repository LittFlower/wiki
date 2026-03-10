一些概念辨析。

## 名词

1. buddy system -> page allocator：buddy system 是页分配算法，page allocator 是上层接口；
2. slab allocator 是建立在 page allocator 之上的“小对象分配器”，也就是负责管理 object
	- slab page：是“已经被某个 slab cache 接管的一页或多页”，一般有三种状态：full/empty/partial，即“全满/全空/部分满”
	- slab freelist：是 slab 内部“空闲对象链表”
	- SLAB：老实现。维护方式更传统，队列和元数据更重。
	- SLUB：新实现，也是现代 Linux 常见默认实现。名字可以理解成 “the unqueued slab allocator”，但它不是“不用 slab”，而是“用更简单的方式实现 slab allocator”。
	- SLOB：更简单、偏小系统的实现，现在不常见。
3. kmem_cache_cpu
	- freelist：只是当前 CPU 手上的空闲对象槽位
	- partial：当前 CPU 暂存的几张半空 slab
4. kmem_cache_node
	- partial：整个 node 共享的半空 slab 链表，也叫 node_list.
5. slab：一般是指一张具体的对象页
  
在 per-CPU 本地路径（也就是 `kmem_cache_cpu`）里的 slab page，不一定会立刻被真正释放回页分配器。

但如果一个 slab page 已经进入了 node partial list，再变成 empty，就更容易被作为整页从 slab allocator 释放回 buddy/page allocator。[[linux kernel cross-cache attack 手法解析]]


 
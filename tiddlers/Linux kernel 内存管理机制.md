## 简介

linux kernel 下的内存管理机制主要有两套，一套是 Buddy system（伙伴系统），一套是 slub allocator。前者有点像用户态下的 `mmap`，正如我们在操作系统课上学到的那样，这个系统专门用于分配整页的内存，是 SLUB 分配器的上游；后者就是分配更小、更细碎的内存，可以用来减少内部碎片。

先介绍 slub allocator。

### slub allocator


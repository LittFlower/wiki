## 原理与打法

原理基本上就是源码里那些东西，这里懒得写了，直接写怎么打。

### 流程

不论版本，首先要申请两个堆块 A B:
- size(A) > size(B)
- A 在 largebin 里，B 在 unsortbin 里
- size(A) 和 size(B) 要在同一个对应的 largbin 范围内。

#### 2.29 及以下

要求被整理进 largebin 的 unsortedbin chunk size 不为 largebin 中的最小

只需要修改 A 的 `bk` 和 `bk_nextsize` 字段分别为 `target_addr1 - 0x10` 和 `target_addr2 - 0x20` 就可以了，然后申请一个大于 A、B 的堆块 C，这样就能往两个地址里写当前这个 chunk 的堆地址。



#### 2.29 以上

只需要满足：被整理进 largebin 的 unsortedbin chunk size 为 largebin 中的最小

只能写 `bk_nextsize` 为 `target_addr - 0x20` 然后申请一个 chunk C 触发来实现攻击了。


## 效果

任意地址写一个堆地址，效果和 house of apple1 类似，可以用来修改 `_IO_list_all` 来打 `house of apple2` 组合拳。

## 要求

至少得能够 edit uaf largebin chunk。

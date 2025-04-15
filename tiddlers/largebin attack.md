## 原理与打法

原理基本上就是源码里那些东西，这里懒得写了，直接写怎么打。

### 2.29 及以下

只需要修改一个 largebin chunk 的 `bk` 和 `bk_nextsize` 字段分别为 `target_addr1 - 0x10` 和 `target_addr2 - 0x20` 就可以了，然后申请一个可以从 unsortbin 里切割出来的小 chunk，这样就能往两个地址里写当前这个 chunk 的堆地址。


### 2.29 以上

只能写 `bk_nextsize` 为 `target_addr - 0x20` 然后申请一个大于 a 和 b 的 chunk 触发来实现攻击了。


## 效果

任意地址写一个堆地址，效果和 house of apple1 类似，可以用来修改 `_IO_list_all` 来打 `house of apple2` 组合拳。

## 要求

至少得能够 edit uaf largebin chunk。

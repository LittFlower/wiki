这里主要说动态链接的 elf 程序是如何启动的。

放一张经典的图：

![](https://ctf-wiki.org/executable/elf/figure/run_dynamic_linking.png)


这里主要关注通过 ld.so 重定位完 elf 中相关地址（初始化 GOT 表）后，跳转至 `_start` 的流程。

`_start` 函数会将以下项目交给 `libc_start_main`

- 环境变量起始地址
- .init
- 启动 main 函数前的初始化工作
- fini
- 程序结束前的收尾工作。

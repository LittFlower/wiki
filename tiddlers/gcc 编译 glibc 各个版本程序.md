解决一个很简单的问题，如何自己编写一个涉及到低版本 glibc 漏洞的 poc。

之前一直是 `gcc poc.c -o poc`，但是这样编译出来的 poc 哪怕 patchelf 替换动态链接库和链接器后，也会因为符号表版本差太多的原因无法执行。

究其根本，patchelf 没办法把链接器查找的符号表信息一起换了。

但是可以根据 how2heap 里的 Makefile，写一个能用的版本出来，如下：

```bash
gcc -std=c99 -g -Wno-unused-result -Wno-free-nonheap-object ./test.c -o test -ldl \
    -Xlinker -rpath=/home/flower/.../libs/2.27-3ubuntu1.5_amd64/ \
    -Xlinker -I/home/flower/.../libs/2.27-3ubuntu1.5_amd64/ld-linux-x86-64.so.2 \
    -Xlinker /home/flower/.../libs/2.27-3ubuntu1.5_amd64/libc.so.6 \
	-Xlinker /home/flower/.../libc/2.27-3ubuntu1.5_amd64/libdl.so.2
```
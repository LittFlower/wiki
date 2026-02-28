一些 trick

pwndbg 版本 >2026.02.18

1. 实现了类似于 beta24/gef 的 `v2p` 和 `p2v`
2. 通过 `kbase -v` 可以同时查看物理基地址和虚拟基地址
3. `slab contains <addr>` 可以查看当前地址属于哪个 slab，然后 `slab list -v` 可以详细列出
4. 对于无符号 vmlinux，可以用 `kallsyms -a` 在 gdb 里恢复一部分调试符号
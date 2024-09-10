在 [[C++ 异常处理机制简介]] 中已经介绍过了相关背景知识。下面着重介绍利用原理与方法。

# 攻击原语

## Exception Handler Landing Pad Confusion

对于抛出异常的函数，其返回地址会被 unwinder 用作第一个寻找 EH handler 的地址，所以 return address 不能任意修改，必须填充一个存在 try-catch 块的函数地址。

这个攻击方式是基于 return address 的利用，在论文中被称之为 Cleanup Handler Landing Pad Confusion.		

## Cleanup Handler Landing Pad Confusion

与上一个类似，都是通过修改 return address 的利用。通过执行任意对象的析构函数（即 Cleanup 函数）即可释放掉某些局部变量，之后就有 Use-After-Free 等攻击方式。 

# 攻击方法

传统的攻击方法仅仅基于[[劫持程序中的后向控制流]]。

针对这种攻击方法常见的保护措施有 [[Canary 金丝雀保护]]、[[Shadow Stack 影子堆栈保护]]等。

以下攻击方式均以存在缓冲区溢出为前提。

## Piovt-to-ROP

考虑到性能优化，编译器并不会为所有函数都添加 Canary 保护，也就是说，对于某个函数，如果它：

- 函数中没有动态分配堆空间 `alloca()`;
- 函数没有使用缓冲区；
- 函数中不存在局部变量；

那么是不会为它添加 Canary 保护的。而考虑到 C++ 异常处理时遵循[[终止语义和恢复语义]]中的终止语义，当抛出异常时，异常位置之后的代码（也就是 canary 校验代码）不会继续执行。

如果 unwinder 找到的能够处理异常的 EH handler 执行后以 `leave; ret` 返回，那么程序就存在通过控制 rbp 栈迁移的可能性。当然，如果 EH handler 函数对应的 Landing pad 不存在后向边缘保护，那么直接利用传统的 ROP 和 return-to-libc 即可攻击。

## Golden Gadget

所谓 Golden Gadget，其实就是一个提供了可以任意指针调用的函数，通过它可以做到前向劫持控制流。

```cpp
void __cxa_call_unexpected (void *exc_obj_in) {
 try { /* ... */ }
 catch (...) {
    __cxa_call_unexpected_cold(a1)
 }
}
void _cxa_call_unexpected_cold(void *a1) {
    void (*v2)(void); // r12
    void *retaddr; // [rsp+0h] [rbp+0h] BYREF
    /*...*/
    if (!check_exception_spec(&retaddr, ...)) {
        if (check_exception_spec(&retaddr, ... )) {
          /*...*/
          _cxa_throw();
        }
        __terminate(v2);
    }
}

void __terminate (void (*handler)()) throw () {
 /* ... */
 handler();
 std::abort();
}
```

局部变量还是比较好控制的，但是寄存器如何控制呢？我们已知栈溢出可以控制栈上数据，如果有方法将栈上数据与寄存器做以联系，寄存器就应该可控了。这时我们就需要利用到 `[[.eh_frame]]`上的信息了，使用 `readelf -wF file`，我们可以窥见其中的奥秘。

通过 readelf 可以得到的信息的形式基本如下，可以看到寄存器的值与 [[CFA]] 相关，而 CFA 均为栈地址。一般我们找rsp+8的条目且能控制寄存器的即可。

```
00000654 000000000000004c 000005f8 FDE cie=00000060 pc=00000000004027e0..0000000000402db0
   LOC           CFA      rbx   rbp   r12   r13   r14   r15   ra    
00000000004027e0 rsp+8    u     u     u     u     u     u     c-8   
00000000004027e6 rsp+16   u     u     u     u     u     c-16  c-8   
00000000004027e8 rsp+24   u     u     u     u     c-24  c-16  c-8   
00000000004027ea rsp+32   u     u     u     c-32  c-24  c-16  c-8   
00000000004027ec rsp+40   u     u     c-40  c-32  c-24  c-16  c-8   
00000000004027ed rsp+48   u     c-48  c-40  c-32  c-24  c-16  c-8   
00000000004027ee rsp+56   c-56  c-48  c-40  c-32  c-24  c-16  c-8   
00000000004027f5 rsp+240  c-56  c-48  c-40  c-32  c-24  c-16  c-8   
00000000004028a3 rsp+56   c-56  c-48  c-40  c-32  c-24  c-16  c-8   
00000000004028a4 rsp+48   c-56  c-48  c-40  c-32  c-24  c-16  c-8   
00000000004028a5 rsp+40   c-56  c-48  c-40  c-32  c-24  c-16  c-8   
00000000004028a7 rsp+32   c-56  c-48  c-40  c-32  c-24  c-16  c-8   
00000000004028a9 rsp+24   c-56  c-48  c-40  c-32  c-24  c-16  c-8   
00000000004028ab rsp+16   c-56  c-48  c-40  c-32  c-24  c-16  c-8   
00000000004028ad rsp+8    c-56  c-48  c-40  c-32  c-24  c-16  c-8   
00000000004028b0 rsp+240  c-56  c-48  c-40  c-32  c-24  c-16  c-8
```




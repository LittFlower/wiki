## get_started_3dsctf_2016

ret2text，注意下栈帧的构造和函数调用约定，调试就能出。


## other_shellcode

搞不懂，连上去就给 shell 了，不知所谓。

## [OGeek2019]babyrop

ret2libc，注意下 onegadget 使用时要调整栈帧（参数里会有 [esp+xxx] 相关的），如果有涉及 eax 等通用寄存器的话可以先用 gadget 调整寄存器以满足 onegadget 的条件。

## ciscn_2019_n_5

ret2libc，注意 onegadget 里例如 `rsp & 0xf === 0` 这种条件看的是，溢出点 ret 时那个 rsp，针对这个 rsp 值调就可以了。

## not_the_same_3dsctf_2016

ret2text + rop。

## ciscn_2019_en_2

ret2libc，注意 `strlen()` 可以被 `\x00` 截断。 


## ciscn_2019_ne_5

ret2libc，注意 `strcpy` 可以被栈溢出 and `scanf("%s")` 读入字符串会被空格符（"\x20"）和截断符（"\x00"）截断。

## 铁人三项(第五赛区)_2018_rop

ret2libc。

## bjdctf_2020_babystack2

ret2text，注意整数溢出（ida 静态分析时别隐藏变量类型）

## bjdctf_2020_babyrop

ret2libc。

## jarvisoj_fm

fmt，fmtstr_payload 一把梭。注意第一个参数 offset 是你能控制的字符串在栈上的位置，可以在 gdb 里用 `fmtarg` 看。

## jarvisoj_tell_me_something

ret2text，好玩的是题目使用了 bp 寄存器却没有使用 leave 指令。
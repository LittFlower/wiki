## 如何启动

以下是一个启动脚本 `start.sh`:

```bash
./qemu-system-x86_64 \
	-m 1G \
	-device strng \
	-hda my-disk.img \
	-hdb my-seed.img \
	-nographic \
	-L pc-bios/ \
	-enable-kvm \
	-device e1000,netdev=net0 \
	-netdev user,id=net0,hostfwd=tcp::5555-:22
```

其中 `-device` 后面的是设备名。

## 静态分析

然后 ida 打开 qemu，直接搜这个设备名可以看到：

![](https://pic.imgdb.cn/item/674a9244d0e0a243d4db5d10.png)

然后从 `do_qemu_init_pci_strng_register_types()` 函数往后跟就行，一般漏洞点都在 `strng_mmio_read` `strng_mmio_write` `strng_pmio_read` `strng_pmio_write` 这些函数里。

ida 这里在 type info 栏可以看结构体类型，这里主要看 `STRNGState` 和 `PCIDeviceClass`，前者是设备的具体结构体，后者是注册设备的结构体。

## 查看 mmio pmio

### lspci

启动 qemu 后，登陆进去，先查看设备信息：

```bash
ubuntu@ubuntu:~$ lspci
00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma] (rev 02)
00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]
00:01.1 IDE interface: Intel Corporation 82371SB PIIX3 IDE [Natoma/Triton II]
00:01.3 Bridge: Intel Corporation 82371AB/EB/MB PIIX4 ACPI (rev 03)
00:02.0 VGA compatible controller: Device 1234:1111 (rev 02)
00:03.0 Unclassified device [00ff]: Device 1234:11e9 (rev 10)
00:04.0 Ethernet controller: Intel Corporation 82540EM Gigabit Ethernet Controller (rev 03)
```

找到设备 `00:03.0 Unclassified device [00ff]: Device 1234:11e9 (rev 10)`，其中 `xx:yy:z` 的格式为总线:设备:功能的格式。

`lspci -v -s 00:03.0` 可以查看设备详细信息：

```bash
ubuntu@ubuntu:~$ lspci -v -s 00:03.0
00:03.0 Unclassified device [00ff]: Device 1234:11e9 (rev 10)
        Subsystem: Red Hat, Inc Device 1100
        Physical Slot: 3
        Flags: fast devsel
        Memory at febf1000 (32-bit, non-prefetchable) [size=256]
        I/O ports at c050 [size=8]
```

可以看到有MMIO地址为 0xfebf1000，大小为 256 (**意味者传入的地址空间不能大于 0xff**)；PMIO 地址为 0xc050，总共有 8 个端口。

### resource 文件

```bash
ubuntu@ubuntu:~$ cat /sys/devices/pci0000:00/0000:00:03.0/resource
0x00000000febf1000 0x00000000febf10ff 0x0000000000040200
0x000000000000c050 0x000000000000c057 0x0000000000040101
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
```

从这里也能看到基地址。

## 访问 mmio pmio

首先本地写个 exp.c，常用的头文件如下：

```c
#include <stdio.h>
#include <stdlib.h> // exit()
#include <fcntl.h>  // open()
#include <unistd.h>
#include <sys/mman.h> // mmap()
#include <stdint.h> // uint32 uint64
#include <sys/io.h> // in() out() iopl()
```

### 访问 mmio

如何把 mmio 的内存映射到程序内存上呢？

```c
int main() {
	// 打开 resource0 文件，获得一个 fd
    mmio_fd = open("/sys/devices/pci0000:00/0000:00:03.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1) {
        errExit("mmio_fd open failed.");
    }
	// mmap 把这个 fd 映射到 exp 的虚拟地址空间，然后就可以正常读写了
    mmio_addr = (uint64_t) mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_addr == (uint64_t) MAP_FAILED) {
        errExit("mmio_addr mmap failed.");
    }
    printf("[+] mmio_addr => 0x%lx\n", mmio_addr);
}
```

### 查看 pmio

pmio 直接用端口访问，大概这样：

```c
int main() {
    if (iopl(3) < 0) {
        errExit("I/O permisson is not enough.");
    }
}


## 动态调试

编译 exp:

```makefile
ALL:
	cc -m32 -O0 -static -o exp exp.c
```

`make` 编译 exp 后，上传到本地的 qemu 里：

```bash
$ scp -P5555 exp ubuntu@127.0.0.1:/home/ubuntu
```

开个 shell2，`sudo gdb -q -pid=[pid]`，其中 pid 是 shell1 里运行的 qemu 进程的 pid，可以 `ps -ax | grep qemu` 查看。

### 打断点

题目是有符号的，所以可以 `file qemu-system-x86_64`，然后 `b *strng_mmio_write` 等等。

### 查看结构体

gdb 可以直接以结构体形式解析数据（当然还是得有符号），可以这么看 `print *(STRNGState*)$rdi`。
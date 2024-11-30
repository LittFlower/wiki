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







Linux 设备管理 = device model 负责发现、建模、匹配、生命周期；
bus 负责匹配规则；
driver 负责 probe/remove 和硬件控制；
subsystem 负责把设备变成 char/block/net/input 等接口；
sysfs 暴露内核对象关系；
udev 根据 uevent 和 sysfs 信息生成 /dev 用户态入口。
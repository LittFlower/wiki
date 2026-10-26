第一优先级：文件与 capability broker

这是最适合你现有经验的方向。

目标族包括：

FileProvider / Files 文档管理链
document import / export
security-scoped bookmark
文件 bookmark 的解析与权限恢复
sandbox extension 的签发、传递与消费
Photos / Image Capture / 媒体导入
BackgroundAssets / MobileAsset 类资源下载和安装服务
系统级 archive / copy / clone / coordinated file operation

重点不是某一个固定 daemon 名，而是下面这种边界：

普通 App 提供 NSURL / bookmark / FD / token
→ 系统服务验证权限
→ 系统服务以更高权限打开、复制、移动、导入或修改对象

这组目标与你的 Finder、hdiutil、文件格式和路径处理经验最接近，而且逻辑漏洞很容易形成可复用原语：

read-only capability 变成 write；
对 A 路径做验证，却对 B 文件执行操作；
bookmark 恢复后权限范围扩大；
FD 与路径指向不同对象；
symlink 或 rename 发生在验证与使用之间；
capability 没有绑定调用者；
服务端错误信任客户端提交的 bundle ID、PID 或 team ID；
服务端在检查 entitlement 前已经产生副作用。


第二优先级：CoreML / BackgroundAssets 一类“输入对象 → 系统编译或安装服务”

这类服务的优势是：

输入结构丰富
+ 普通 App 有公开入口
+ 经常跨 XPC
+ 可能涉及临时文件、模型包、缓存和编译产物
+ 可能继续触及 ANE 等内核/固件边界

优先分析：

模型目录和附属文件如何枚举；
编译前后使用哪个路径；
临时目录由谁创建；
symlink、hard link、clone 或 rename 后是否重新验证；
服务是否接受 bookmark、FD 或 sandbox extension；
编译缓存 key 是否与调用者绑定；
取消、重试和并发编译时对象生命周期是否正确；
输出文件是否可能覆盖其他位置；
模型元数据与实际文件内容是否可能不一致。


第三优先级：CoreMedia / VideoToolbox 的用户态服务边界

这一组同时具备三种研究价值：

内容解析入口
用户态跨进程服务
通往媒体驱动的内核入口

Agent 应画出：

AVFoundation / CoreMedia / VideoToolbox API
→ 用户态 framework
→ XPC helper 或媒体 daemon
→ IOSurface / shared memory
→ Video encoder/decoder user client
→ 驱动

先不要让 agent“直接找 OOB”。先回答：

哪些操作留在调用进程；
哪些操作进入独立媒体进程；
哪些参数被重新序列化；
哪些 buffer 通过 IOSurface 或共享内存传递；
谁负责验证尺寸、stride、plane、pixel format 和生命周期；
用户态服务是否替调用者打开了其本来不能访问的对象。



第四优先级：只选一个 App 可达的内核管线

不要扫描整个 XNU，也不要让 agent 无差别反编译全部 kernelcache。

你的第一个内核支线，我建议从以下二选一：

选择 A：VideoToolbox → AVEVideoEncoder / AppleAVD

更适合作为默认选择：

公开 API 容易构造 harness
输入参数和 buffer 结构较明确
普通 App 场景真实
能同时观察用户态与内核态
目标范围比整个 GPU 栈窄

选择 B：CoreML → ANE

适合在以下条件下选择：

你已经把 CoreML 用户态模型处理链摸清；
普通 App 可以稳定触发设备侧编译或执行；
Agent 能比较好地恢复模型描述、张量和 command buffer；
你愿意承受更多 proprietary 协议和硬件队列逆向工作。



① FileProvider / bookmark / 文档导入导出链
② BackgroundAssets 或 CoreML 服务链
③ VideoToolbox → AVEVideoEncoder user client



先研究 SBE：

1. FileProvider.framework：/System/Library/Frameworks/FileProvider.framework/FileProvider
2. fileproviderd：/System/Library/Frameworks/FileProvider.framework/Support/fileproviderd
3. FileProviderDaemon.framework：/System/Library/PrivateFrameworks/FileProviderDaemon.framework/FileProviderDaemon
4. DocumentManagerCore.framework：/System/Library/PrivateFrameworks/DocumentManagerCore.framework/DocumentManagerCore
   
首先看一张图 [[glibc malloc/free/realloc 执行流程]]

从比较大的 unsortbin 中切割一个 chunk 时，有可能将这个 chunk 先放进 largebin 从而踩一个**堆地址**出来。
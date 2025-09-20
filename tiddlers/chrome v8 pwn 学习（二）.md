## 前置知识

### chrome 查看快照

首先打开浏览器开发者工具，在控制台中运行一段 js 代码：

![](https://pic1.imgdb.cn/item/689aecdd58cb8da5c81e0808.png)

然后在内存选项卡查看快照 ![](https://pic1.imgdb.cn/item/689aed2658cb8da5c81e0c13.png)

## v8 JsObject 简介

这里我们要先区分一个概念，即 JavaScript 语言层面和 V8 引擎内部实现层面上对于数据结构的理解是不一样的。

我们先说V8 引擎内部实现层面，在这个层面上，V8 引擎将所有类型大体划分为 smi 和 HeapObject，这个划分的方式称作 Tagged Value 技术，它利用了最低位来区别 Smi 和对象指针，当最低位为 0 时，表明这是一个 Smi；当最低位为 1 时，表明这是一个对象指针。

下面介绍一下 v8 对象（JsObject）的结构。

### v8 对象结构简介

首先有一张很经典的图：![v8 对象结构](https://pic1.imgdb.cn/item/689b280158cb8da5c81ee86c.png)

v8 的对象由三个部分组成：
- Hidden Class(隐藏类)
- Property
- Element


总结：

1. 隐藏类用于描述对象的结构，Property 和 Element 用于存放对象的属性，两者的区别主要体现在键名能否被索引：前者用于存放命名属性（不可索引），后者用于存放可索引属性（可索引）。
2. 参照ECMA规范中的要求，可索引属性需要按照索引值大小升序排列，而命令属性根据创建的顺序升序排列。
3. 同时使用两种属性时，两个属性分开存储。
4. 拥有不相同的属性一般并不会影响隐藏类（map）

测试代码如下：

```js
function Foo1 () {};
var a = new Foo1();
var b = new Foo1();

a.name = 'aaa';
a.text = 'aaa';
b.name = 'bbb';
b.text = 'bbb';

a[1] = 'aaa';
a[2] = 'aaa';

%DebugPrint(a);
%DebugPrint(b);
%SystemBreak();
```

调试信息如下：

```
0x154024d8def9 <Foo1 map = 0xac0e3a0ac79>  // 这是 a 的
0x154024d8df61 <Foo1 map = 0xac0e3a0ac79>  // 这是 b 的

pwndbg> job 0x154024d8def9
0x154024d8def9: [JS_OBJECT_TYPE]
	- map: 0x0ac0e3a0ac79 <Map(HOLEY_ELEMENTS)> [FastProperties]
	- prototype: 0x154024d8ddf9 <Object map = 0xac0e3a0acc9>
	- elements: 0x154024d8e091 <FixedArray[19]> [HOLEY_ELEMENTS]
	- properties: 0x14ae053c0c71 <FixedArray[0]> {
		#name: 0x1e9491b1f229 <String[#3]: aaa> (const data field 0)
		#text: 0x1e9491b1f229 <String[#3]: aaa> (const data field 1)
	}
	- elements: 0x154024d8e091 <FixedArray[19]> {
		0: 0x14ae053c05b1 <the_hole>
		1-2: 0x1e9491b1f229 <String[#3]: aaa>
		3-18: 0x14ae053c05b1 <the_hole>
	}
pwndbg> job 0x154024d8df61
0x154024d8df61: [JS_OBJECT_TYPE]
	- map: 0x0ac0e3a0ac79 <Map(HOLEY_ELEMENTS)> [FastProperties]
	- prototype: 0x154024d8ddf9 <Object map = 0xac0e3a0acc9>
	- elements: 0x14ae053c0c71 <FixedArray[0]> [HOLEY_ELEMENTS]
	- properties: 0x14ae053c0c71 <FixedArray[0]> {
		#name: 0x1e9491b1f259 <String[#3]: bbb> (const data field 0)
		#text: 0x1e9491b1f259 <String[#3]: bbb> (const data field 1)
}
```

可以发现他们的 Map（隐藏类）是相同的（尽管 a 比 b 多了很多可索引属性），然后这两种属性也是分开储存的，符合上面的结论。


### 命名属性的不同存储方式

V8 中命名属性有三种的不同存储方式：对象内属性（in-object）、快属性（fast）和慢属性（slow）。

![v8 命名属性的存储方式](https://pic1.imgdb.cn/item/689b2f1758cb8da5c81f1732.png)


- 对象内属性，保存在对象本身，访问速度最快
- 快属性，比前者多一次寻址次数
- 慢属性速度最慢，将属性的完整结构存储在内（前两种属性的结构会将结构放在隐藏类中描述）

对象内属性和快属性的结构基本相同，对象内属性因为对象存储空间的限制，所以在超过10个属性之后多余的部分就会进入property（命名属性）中。

而当使用慢属性时，可以发现 property 中的索引变得无序，说明这个对象已经采用了 hash 存取结构了。

至于为什么要采用三种方式进行存储，无非是为了让v8更快一些。

例子如下：

```js
//三种不同类型的 Property 存储模式
function Foo2() {}

var a = new Foo2()
var b = new Foo2()
var c = new Foo2()
for (var i = 0; i < 10; i ++) {
  a[new Array(i+2).join('a')] = 'aaa'
}
for (var i = 0; i < 12; i ++) {
  b[new Array(i+2).join('b')] = 'bbb'
}
for (var i = 0; i < 30; i ++) {
  c[new Array(i+2).join('c')] = 'ccc'
}
```


自行在浏览器中使用快照技术查看内存即可。


### 隐藏类

在 V8 的 Memory 检查器中，隐藏类被称为 Map。隐藏类的目的只有两个，运行更快和占内存空间更小。我们这里从节省内存空间讨论。

#### 隐藏类的概念

在 ECMAScript 中，对象属性的 Attribute 被描述为以下结构。

- [\[Value]]：属性的值
- [\[Writable]]：定义属性是否可写（即是否能被重新分配）
- [\[Get]]：断言这个对象是函数对象，调用该函数的内部方法，传入空参数列表并获取返回值
- [\[Set]]：断言这个对象是函数对象，调用该函数的内部方法，传入赋值的值为参数并获取返回值
- [\[Enumerable]]：定义属性是否可枚举
- [\[Configurable]]：定义属性是否可配置（删除）

隐藏类的引入，将属性的 Value 与其它 Attributes（也就是 Writable、Get 等）分开。一般情况下，对象的 Value 是经常会发生变动的，而 Attribute 是几乎不怎么会变的。没有没有必要重复Attribute的剩余部分。

#### 隐藏类的创建

对象创建过程中，每添加一个命名属性，都会对应一个生成一个新的隐藏类。在 V8 的底层实现了一个将隐藏类连接起来的转换树，如果以相同的顺序添加相同的属性，转换树会保证最后得到相同的隐藏类。

下面的例子中，a 在空对象时、添加 name属性后、添加 text属性后会分别对应不同的隐藏类。

```js
function Foo3 (){};
let a = new Foo3();
a.name = 'migraine1'
a.text = 'migraine2'
```

生成概念图：![隐藏类生成概念图](https://pic1.imgdb.cn/item/689b31ee58cb8da5c81f1a76.png)

可以理解为，按照代码顺序一步一步添加命名属性，中间每添加一个属性都对应一个不同的 map，同时 map 中会维护一个叫 `back_pointer` 的指针，实现一个单链表结构。

#### 隐藏类的结构

示例代码：

```js
function Foo1 () {};
var a = new Foo1();
var b = new Foo1();

a.name = 'aaa';
a.text = 'aaa';
b.name = 'bbb';
b.text = 'bbb';

a[1] = 'aaa';
a[2] = 'aaa';

%DebugPrint(a);
%DebugPrint(b);
%SystemBreak();
```

```
pwndbg> job 0x0ac0e3a0ac79
0xac0e3a0ac79: [Map]
	- type: JS_OBJECT_TYPE                                                          // 实例类型
	- instance size: 104                                                            // 实例大小
	- inobject properties: 10                                                       // 对象内属性存储空间
	- elements kind: HOLEY_ELEMENTS
	- unused property fields: 8                                                     // 未使用slot数
	- enum length: invalid
	- stable_map                                                                    // 处于快属性模式 （dictionary_map：慢属性/字典模式）
	- back pointer: 0x0ac0e3a0ac29 <Map(HOLEY_ELEMENTS)>                            // 维护一个单链表
	- prototype_validity cell: 0x1e9491b1f881 <Cell value= 1>
	// 标识对象实例的属性名与其值的存取位置（a 和 b 的描述符相同，结构也相同）
	- instance descriptors (own) #2: 0x154024d8e031 <DescriptorArray[2]>
	- layout descriptor: (nil)
	- prototype: 0x154024d8ddf9 <Object map = 0xac0e3a0acc9>
	- constructor: 0x1e9491b1f6a9 <JSFunction Foo1 (sfi = 0x1e9491b1f3a1)>
	- dependent code: 0x14ae053c02c1 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
	- construction counter: 5
pwndbg> job 0x154024d8e031
0x154024d8e031: [DescriptorArray]
	- map: 0x14ae053c0271 <Map>
	- enum_cache: empty
	- nof slack descriptors: 0
	- nof descriptors: 2
	- raw marked descriptors: mc epoch 0, marked 0
		[0]: #name (const data field 0:h, p: 1, attrs: [WEC]) @ Any
		[1]: #text (const data field 1:h, p: 0, attrs: [WEC]) @ Any
```

参考注释可以看的很清楚了，通过访问 backpointer 里的值可以看到在添加 `text` 属性前 a 的 map 结构：

```
pwndbg> job 0x0ac0e3a0ac29
0xac0e3a0ac29: [Map]
	- type: JS_OBJECT_TYPE
	- instance size: 104
	- inobject properties: 10
	- elements kind: HOLEY_ELEMENTS
	- unused property fields: 9
	- enum length: invalid
	- back pointer: 0x0ac0e3a0aae9 <Map(HOLEY_ELEMENTS)>
	- prototype_validity cell: 0x1e9491b1f881 <Cell value= 1>
	- instance descriptors #1: 0x154024d8e031 <DescriptorArray[2]>  // 这时 map 对应的命名属性只存了一个 `name`，所以只有 1
	- layout descriptor: (nil)
	- transitions #1: 0x0ac0e3a0ac79 <Map(HOLEY_ELEMENTS)>
		#text: (transition to (const data field, attrs: [WEC]) @ Any) -> 0x0ac0e3a0ac79 <Map(HOLEY_ELEMENTS)>
	- prototype: 0x154024d8ddf9 <Object map = 0xac0e3a0acc9>
	- constructor: 0x1e9491b1f6a9 <JSFunction Foo1 (sfi = 0x1e9491b1f3a1)>
	- dependent code: 0x14ae053c02c1 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
	- construction counter: 5
```

再往前也可以继续看到，不再赘述。

## V8 内存模型

首先贴一个继承关系图，这一节主要介绍的内存模型有以下这些，我们从 Smi 开始依次往下介绍。

```
+--------------------------------+
|        V8 Memory Layout        |
+--------------------------------+
| Object                         |
| ├─ Smi                         |
| └─ HeapObject                  |
|   ├─ HeapNumber                 |
|   ├─ PropertyCell               |
|   ├─ FixedArrayBase             |  
|   │  ├─ FixedArray              | 
|   │  └─ FixedDoubleArray        |
|   └─ JSReceiver ─────┐         |
|       └─ JSObject ────┤         |
|         ├─ JSFunction           |
|         ├─ JSArray              |
|         └─ JSArrayBuffer        |
+--------------------------------+
```

### Smi

Smi 是 Small Integer 的缩写，也就是专门用来表示小整数值。

基于 tagged value 技术，通过最低位是 0 或者 1 来区分是立即数还是一个内存指针。

- 在32位环境中，Smi占据32位，其中最低位为标记位（为0），所以Smi只使用了31位来表示值。
- 在64位环境中，Smi占据64位，其中最低位为标记位（为0），但是只有高32位用于表示值，低32位都为0（包括标记位）

其内存结构如下图：

```
 Smi on 32Bits                      
+----------------------------+-----+
|                            |     |
|     Signed Value(31Bits)   |  0  |
|                            |     |
+----------------------------+-----+

 Smi on 64Bits                                                    
+-------------------------------+-----------------------+-----+
|                               |                       |     |
|     Signed Value(32Bits)      |  0-Padding(31Bits)    |  0  |
|                               |                       |     |
+-------------------------------+-----------------------+-----+
```


### Heap Object


同样基于 Tagged Value 技术，通过将一个内存值最低位置为 1 来表示这是一个内存指针。

这个就不画图了，只需要记得不管是 32 位还是 64 位情况下，最低位都是 1。


### HeapNumber

继承自 Object->HeapObject，对象的数值范围为 double，一般是用来表示无法在 Smi 范围内表示的整数值。

它的内存结构如下图：

```
+------------------+---+                         
|  Object Pointer  | 1 +----+                    
+------------------+---+    |                    
                            |                    
                +-----------+                    
                |                                
                |       +-----------+-----------+
                +------>|   (Map*)  |  (Value)  |
                        +-----------+-----------+
                        ^           ^            
                        |           |            
                    KMapOffset     KValueOffset  
                       =0                =8      
```

这里的 `Object Pointer` 的意思是，当我们查询一个 HeapNumber 的内存时，会先得到一个指向其具体内存结构的指针（也就是这个 Object Pointer），而其具体的内存结构则是在 offset=0 处存放一个指向 map 的指针，而在 offset=8 处存放一个 IEEE754 编码的 double 型 value。

也就是说，实际上在源码中，V8 的诸如 HeapNumber 这类 class 基本没有成员变量，它们都是通过偏移量独立表示的。为了方便画图，将它画成下面这个样子：

```
+------------------+---+                               
|  Object Pointer  | 1 +----+                          
+------------------+---+    |                          
                            |                          
                +-----------+                          
                |                                      
                |       +--------------+--------------+
                +------>|  KMapOffset* |  KValueOffset|
                        +--------------+--------------+
```

后面我们都会用这种方式画图。


### JsObject

为了完整性，这里简单回顾一下 JsObject，具体细节可以看上一大节。

在V8中，JsObject 内存结构如下所示：

```
[ hiddenClass / map ] -> ... ; 指向Map
[ properties        ] -> [empty array]
[ elements          ] -> [empty array]
[ reserved #1       ] -\
[ reserved #2       ]  |
[ reserved #3       ]  }- in object properties,即预分配的内存空间
...............        |
[ reserved #N       ] -/
```

- `Map` 中存储了一个对象的元信息，包括对象上属性的个数，对象的大小以及指向构造函数和原型的指针等等。同时，Map中保存了Js对象的属性信息，也就是各个属性在对象中存储的偏移。然后属性的值将根据不同的类型，放在 properties、element 以及预留空间中。
- `properties` 指针，用于保存通过属性名作为索引的元素值，类似于字典类型
- `elements` 指针，用于保存通过整数值作为索引的元素值，类似于常规数组
- `reserved #n`，为了提高访问速度，V8在对象中预分配了的一段内存区域，用来存放 in-object 属性，当向 object 中添加属性时，会先尝试将新属性放入这些预留的槽位。当 in-onject 槽位满后，V8才会尝试将新的属性放入 properties 中。

### ArrayBuffer && TypedArray

- ArrayBuffer 对象用来表示通用的、固定长度的原始二进制数据缓冲区。ArrayBuffer 不能直接操作，而是要通过“视图”进行操作。“视图”部署了数组接口，这意味着，可以用数组的方法操作内存。
- TypedArray 用来生成内存的视图，通过9个构造函数，可以生成9种数据格式的视图，比如Uint8Array（无符号8位整数）数组视图, Int16Array（16位整数）数组视图, Float64Array（64位浮点数）数组视图等等。

简单的说，ArrayBuffer就代表一段原始的二进制数据，而TypedArray代表了一个确定的数据类型，当TypedArray与ArrayBuffer关联，就可以通过特定的数据类型格式来访问内存空间。

这在我们的利用中十分重要，因为这意味着我们可以在一定程度上像C语言一样直接操作内存。


内存结构如图：

![ArrayBuffer && TypedArray](https://pic1.imgdb.cn/item/689b798f58cb8da5c81f8cdc.png)

在 ArrayBuffer 中存在一个 BackingStore 指针，这个指针指向的就是 ArrayBuffer 开辟的内存空间，可以使用 TypedArray 指定的类型读取和写入该区域，并且，这片内存区域是位于系统堆中的而不是属于GC管理的区域。


测试用例：

```js
arr = new ArrayBuffer(0x20);
u32 = new Uint32Array(arr);

u32[0] = 0x1234;
u32[1] = 0x5678;

%DebugPrint(u32);
%SystemBreak();
readline();
```

![](https://pic1.imgdb.cn/item/689e0b7c58cb8da5c82560ec.png)

可以清楚的看到上面的结构和结论。

常见利用有：

1. 可以如果修改 ArrayBuffer 中的 Length，那么就能够造成越界访问。
2. 如果能够修改 BackingStore 指针，那么就可以获得任意读写的能力了，这是非常常用的一个手段
3. 可以通过 BackingStore 指针泄露堆地址，还可以在堆中布置 shellcode。


### JsFunction

内存结构如图：

![JsFunction 内存结构图](https://pic1.imgdb.cn/item/689e0bad58cb8da5c8256105.png)

其中，CodeEntry 是一个指向 JIT 代码的指针（RWX区域），如果具有任意写能力，那么可以向JIT代码处写入自己的 shellcode，实现任意代码执行。

但是，在 v8 6.7 版本之后，function 的 code 不再可写，所以不能够直接修改 jit 代码了。

另外，我自己测试的时候不知道是不是版本原因，这里实际上是 kLiteralsOffset 指向函数区域。

测试代码：

```js
function func() {
  let sum = 0;
  for (let i = 0; i < 100; ++i)
    sum += i;
  return sum;
}

for (let i = 0; i < 100; ++i) {
  func();
}

%DebugPrint(func);
readline();
```


调试结果如下图所示：

![](https://pic1.imgdb.cn/item/689e113c58cb8da5c82563c4.png)

### FixedArray

它的数据区被定义为 `TaggedValue data[]`，`TaggedValue` 是一种可以存储 SMI（小整数）或指向其他 HeapObject 的指针的类型。这使得 FixedArray 成为一个通用的指针容器。

```
+----------------+---------------+
|                |               |
|     length     |     map       |
|                |               |
+----------------+---------------+
|                |               |
|    elements2   |    elements1  |
|                |               |
+----------------+---------------+
```


### FixedDoubleArray

它的数据区被定义为 double data[]。这意味着它只能存储原始的、未装箱的 64 位浮点数值。这使得它成为一个专用的数值容器。

```
+----------------+---------------+
|                |               |
|     length     |     map       |
|                |               |
+----------------+---------------+
|                                |
|     elements in double         |
|                                |
+--------------------------------+
```





## 参考文章

* [v8 Base](https://migraine-sudo.github.io/2020/02/15/v8/)
* [V8 javascript engine代码阅读](https://web.archive.org/web/20181207172933/https://eternalsakura13.com/2018/07/09/zujian/)
* [v8 exploit](https://eternalsakura13.com/2018/05/06/v8/)
* [v8 exploit入门[PlaidCTF roll a d8]](https://xz.aliyun.com/news/4822#toc-9)

## 前置知识

### chrome 查看快照

首先打开浏览器开发者工具，在控制台中运行一段 js 代码：

![](https://pic1.imgdb.cn/item/689aecdd58cb8da5c81e0808.png)

然后在内存选项卡查看快照 ![](https://pic1.imgdb.cn/item/689aed2658cb8da5c81e0c13.png)

## v8 内存模型

这里我们要先区分一个概念，即 JavaScript 语言层面和 V8 引擎内部实现层面上对于数据结构的理解是不一样的。

我们先说V8 引擎内部实现层面，在这个层面上，V8 引擎将所有类型大体划分为 smi 和 HeapObject，这个划分的方式称作 Tagged Value 技术，它利用了最低位来区别 Smi 和对象指针，当最低位为 0 时，表明这是一个 Smi；当最低位为 1 时，表明这是一个对象指针。

下面介绍一下 v8 对象结构。

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
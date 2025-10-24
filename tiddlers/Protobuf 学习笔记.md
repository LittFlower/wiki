## 简介

近两年国内的比赛里，Protobuf 和 pwn 结合的题目越来越多，这里记录一下一些基本的逆向方法和注意事项。

> Protocol Buffers（简称：ProtoBuf）是一种开源跨平台的序列化数据结构的协议。其对于存储资料或在网络上进行通信的程序是很有用的。这个方法包含一个接口描述语言，描述一些数据结构，并提供程序工具根据这些描述产生代码，这些代码将用来生成或解析代表这些数据结构的字节流。
>  —— WikiPedia


## 环境搭建

由于我用的是 arch linux，所以以下安装方式主要适用于 arch linux，其他发行版或者 macos 用户可自行寻找安装方法。

```shellscript
sudo pacman -S protobuf protobuf-c
sudo pacman -S python-grpcio python-googleapis-common-protos
paru -S pbtk-git
```

可以通过 `protoc --version` 的输出判断是否配置成功。

## 基本语法

先来看一个官方文档给出的例子，一些语法注释我直接写在 demo 里了：

```proto
// demo.proto
// 编译为 C 代码：protoc --c_out=. demo.proto
// 编译为 python 代码：protoc --python_out=. demo.proto
//


// syntax = "proto2"  // 有proto2和proto3两个版本，省略默认为proto2。
syntax = "proto3";

package tutorial;  // 防止命名空间冲突

/*
每个字段包括修饰符 类型 字段名，并且末尾通过等号设置唯一字段编号。

修饰符包括如下几种：
    - optional：可以不提供字段值，字段将被初始化为默认值。（Proto3 中不允许显示声明，不加修饰符即 optional）
    - repeated：类似vector，表明该字段为动态数组，可重复任意次。
    - required：必须提供字段值。（Proto3 不再支持 required）
常见的基本类型：
    - bool
    - int32
    - float
    - double
    - string
*/


message Person {  // 用于定义消息结构体，类似C语言中的struct。
  string name = 1;
  int32 id = 2;
  string email = 3;

  enum PhoneType {
    PHONE_TYPE_UNSPECIFIED = 0;
    PHONE_TYPE_MOBILE = 1;
    PHONE_TYPE_HOME = 2;
    PHONE_TYPE_WORK = 3;
  }

  message PhoneNumber {
    string number = 1;
    PhoneType type = 2;
  }

  repeated PhoneNumber phones = 4;
}

message AddressBook {
  repeated Person people = 1;
}
```

`protoc --c_out=. demo.proto` 编译后得到 `demo.pb-c.c` 和 `demo.pb-c.h` 两个文件。


## 逆向分析

CTF 题目通常为 C 语言编写，因此为了后续逆向工作，需要理解编译后的 C 语言文件相关结构。

先来看 `demo.pb-c.c` 文件，搜索 `unpack` 定位到 `tutorial__person__unpack` 函数（一般就是 `tutorial__xxxx__unpack`）：

```c
Tutorial__Person *
       tutorial__person__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Tutorial__Person *)
     protobuf_c_message_unpack (&tutorial__person__descriptor,
                                allocator, len, data);
}
```

跟进到 `protobuf_c_message_unpack`，看一下函数原型：

```c
/**
 * Unpack a serialised message into an in-memory representation.
 *
 * \param descriptor
 *      The message descriptor.
 * \param allocator
 *      `ProtobufCAllocator` to use for memory allocation. May be NULL to
 *      specify the default allocator.
 * \param len
 *      Length in bytes of the serialised message.
 * \param data
 *      Pointer to the serialised message.
 * \return
 *      An unpacked message object.
 * \retval NULL
 *      If an error occurred during unpacking.
 */
PROTOBUF_C__API
ProtobufCMessage *
protobuf_c_message_unpack(
	const ProtobufCMessageDescriptor *descriptor,
	ProtobufCAllocator *allocator,
	size_t len,
	const uint8_t *data);

typedef struct ProtobufCMessageDescriptor ProtobufCMessageDescriptor;
```


阅读注释，可以看到这里比较重要的参数 1 就是一个 message descriptor，看一下这个结构体：

```c
/**
 * Describes a message.
 */
struct ProtobufCMessageDescriptor {
	/** Magic value checked to ensure that the API is used correctly. */
	uint32_t			magic;

	/** The qualified name (e.g., "namespace.Type"). */
	const char			*name;
	/** The unqualified name as given in the .proto file (e.g., "Type"). */
	const char			*short_name;
	/** Identifier used in generated C code. */
	const char			*c_name;
	/** The dot-separated namespace. */
	const char			*package_name;

	/**
	 * Size in bytes of the C structure representing an instance of this
	 * type of message.
	 */
	size_t				sizeof_message;

	/** Number of elements in `fields`. */
	unsigned			n_fields;
	/** Field descriptors, sorted by tag number. */
	const ProtobufCFieldDescriptor	*fields;
	/** Used for looking up fields by name. */
	const unsigned			*fields_sorted_by_name;

	/** Number of elements in `field_ranges`. */
	unsigned			n_field_ranges;
	/** Used for looking up fields by id. */
	const ProtobufCIntRange		*field_ranges;

	/** Message initialisation function. */
	ProtobufCMessageInit		message_init;

	/** Reserved for future use. */
	void				*reserved1;
	/** Reserved for future use. */
	void				*reserved2;
	/** Reserved for future use. */
	void				*reserved3;
};
```

如注释所说。这个 `magic` 一般是等于 `0x28AAEEF9`，在 IDA 中通过 `Search -> Immediate value ...` 勾选 `find all` 即可搜索这个魔术，找到位于 data 段的数据，就是这个结构体。

另一个需要重点关注的结构体是 `ProtobufCFieldDescriptor`：

```c
/**
 * Describes a single field in a message.
 */
struct ProtobufCFieldDescriptor {
	/** Name of the field as given in the .proto file. */
	const char		*name;

	/** Tag value of the field as given in the .proto file. */
	uint32_t		id;

	/** Whether the field is `REQUIRED`, `OPTIONAL`, or `REPEATED`. */
	ProtobufCLabel		label;

	/** The type of the field. */
	ProtobufCType		type;

	/**
	 * The offset in bytes of the message's C structure's quantifier field
	 * (the `has_MEMBER` field for optional members or the `n_MEMBER` field
	 * for repeated members or the case enum for oneofs).
	 */
	unsigned		quantifier_offset;

	/**
	 * The offset in bytes into the message's C structure for the member
	 * itself.
	 */
	unsigned		offset;

	/**
	 * A type-specific descriptor.
	 *
	 * If `type` is `PROTOBUF_C_TYPE_ENUM`, then `descriptor` points to the
	 * corresponding `ProtobufCEnumDescriptor`.
	 *
	 * If `type` is `PROTOBUF_C_TYPE_MESSAGE`, then `descriptor` points to
	 * the corresponding `ProtobufCMessageDescriptor`.
	 *
	 * Otherwise this field is NULL.
	 */
	const void		*descriptor; /* for MESSAGE and ENUM types */

	/** The default value for this field, if defined. May be NULL. */
	const void		*default_value;

	/**
	 * A flag word. Zero or more of the bits defined in the
	 * `ProtobufCFieldFlag` enum may be set.
	 */
	uint32_t		flags;

	/** Reserved for future use. */
	unsigned		reserved_flags;
	/** Reserved for future use. */
	void			*reserved2;
	/** Reserved for future use. */
	void			*reserved3;
};
```

注释里写的也很清晰了，需要关注的字段 `name`、`label`、`type`、`descriptor`。


基本上在 IDA 里导入这些结构体，然后找到对应的数据段，先选中右键 `Undefined` 这些数据，然后在起始段右键 `Structure` 选择对应的结构体就可以恢复的非常清楚了。


## 做题流程

### pbtk

一般来讲，可以先用 pbtk 去一把梭恢复 proto 文件，似乎默认只能识别 proto3？？不清楚为什么有的 proto2 题目无法正常恢复。


一般只需要使用 `pbtk/extractors/from_binary.py` 就可以直接梭哈。


### 手动恢复

例如说一道 proto2 题目，先依次在 IDA 导入如下结构体：



```c
enum ProtobufCLabel
{
  PROTOBUF_C_LABEL_REQUIRED = 0x0,      
  PROTOBUF_C_LABEL_OPTIONAL = 0x1,    
  PROTOBUF_C_LABEL_REPEATED = 0x2,         
  PROTOBUF_C_LABEL_NONE = 0x3,   
};

enum ProtobufCType
{
  PROTOBUF_C_TYPE_INT32 = 0x0,    
  PROTOBUF_C_TYPE_SINT32 = 0x1,   
  PROTOBUF_C_TYPE_SFIXED32 = 0x2, 
  PROTOBUF_C_TYPE_INT64 = 0x3,    
  PROTOBUF_C_TYPE_SINT64 = 0x4,   
  PROTOBUF_C_TYPE_SFIXED64 = 0x5, 
  PROTOBUF_C_TYPE_UINT32 = 0x6,   
  PROTOBUF_C_TYPE_FIXED32 = 0x7,  
  PROTOBUF_C_TYPE_UINT64 = 0x8,   
  PROTOBUF_C_TYPE_FIXED64 = 0x9,  
  PROTOBUF_C_TYPE_FLOAT = 0xA,    
  PROTOBUF_C_TYPE_DOUBLE = 0xB,   
  PROTOBUF_C_TYPE_BOOL = 0xC,     
  PROTOBUF_C_TYPE_ENUM = 0xD,     
  PROTOBUF_C_TYPE_STRING = 0xE,   
  PROTOBUF_C_TYPE_BYTES = 0xF,    
  PROTOBUF_C_TYPE_MESSAGE = 0x10, 
};

struct ProtobufCMessageDescriptor {
	uint32_t			magic;
	const char			*name;
	const char			*short_name;
	const char			*c_name;
	const char			*package_name;
	size_t				sizeof_message;
	unsigned			n_fields;
	const ProtobufCFieldDescriptor	*fields;
	const unsigned			*fields_sorted_by_name;
	unsigned			n_field_ranges;
	void         		*field_ranges;
	void		        *message_init;
	void				*reserved1;
	void				*reserved2;
	void				*reserved3;
};

struct ProtobufCFieldDescriptor {
	const char		*name;
	uint32_t		id;
	ProtobufCLabel		label;
	ProtobufCType		type;
	unsigned		quantifier_offset;
	unsigned		offset;
	const void		*descriptor;
	const void		*default_value;
	uint32_t		flags;
	unsigned		reserved_flags;
	void			*reserved2;
	void			*reserved3;
};
```

把上面的结构体导入，恢复即可。

以 ciscn2023 初赛的一道题目为例：

![恢复结果](https://pic1.imgdb.cn/item/68fae8863203f7be00932cb2.png)

从逆向结果可以得知，题目的标准结构体为 0x40 大小，有 4 个字段，字段对应的类型也很清楚，`label` 是 `required`，`type` 是 `sint64` or `bytes`。

重写一个 `test.proto`，`protoc` 编译后得到 `demo.pb-c.c`，查看结构体：

```c
/* --- messages --- */

struct  Devicemsg
{
  ProtobufCMessage base;  // ProtobufCMessage 是一个 0x18 的结构体
  int64_t actionid;
  int64_t msgidx;
  int64_t msgsize;
  ProtobufCBinaryData msgcontent;  // ProtobufCBinaryData 是一个 0x10 的结构体
};

struct ProtobufCBinaryData {
	size_t	len;        /**< Number of bytes in the `data` field. */
	uint8_t	*data;      /**< Data bytes. */
};
```

然后再把以上结构体导入 IDA 进一步逆向即可。

在确认结构体正确后，`protoc --python_out=. message.proto` 得到 `message_pb2.py`，然后就可以用来封装交互函数了。

使用 `SerializeToString` 序列化，`ParseFromString` 反序列化。



对 v8 最基本的对象模型的一个基本的 overview (继承树):


```c++
// Inheritance hierarchy:
// - MaybeObject    (an object or a failure)
//   - Failure      (immediate for marking failed operation)
//   - Object
//     - Smi          (immediate small integer)
//     - HeapObject   (superclass for everything allocated in the heap)
//       - JSReceiver  (suitable for property access)
//         - JSObject
//           - JSArray
//           - JSSet
//           - JSMap
//           - JSWeakMap
//           - JSRegExp
//           - JSFunction
//           - JSModule
//           - GlobalObject
//             - JSGlobalObject
//             - JSBuiltinsObject
//           - JSGlobalProxy
//           - JSValue
//             - JSDate
//           - JSMessageObject
//         - JSProxy
//           - JSFunctionProxy
//       - FixedArrayBase
//         - ByteArray
//         - FixedArray
//           - DescriptorArray
//           - HashTable
//             - Dictionary
//             - SymbolTable
//             - CompilationCacheTable
//             - CodeCacheHashTable
//             - MapCache
//           - Context
//           - JSFunctionResultCache
//           - ScopeInfo
//           - TransitionArray
//         - FixedDoubleArray
//         - ExternalArray
//           - ExternalPixelArray
//           - ExternalByteArray
//           - ExternalUnsignedByteArray
//           - ExternalShortArray
//           - ExternalUnsignedShortArray
//           - ExternalIntArray
//           - ExternalUnsignedIntArray
//           - ExternalFloatArray
//       - String
//         - SeqString
//           - SeqOneByteString
//           - SeqTwoByteString
//         - SlicedString
//         - ConsString
//         - ExternalString
//           - ExternalAsciiString
//           - ExternalTwoByteString
//       - HeapNumber
//       - Code
//       - Map
//       - Oddball
//       - Foreign
//       - SharedFunctionInfo
//       - Struct
//         - AccessorInfo
//         - AccessorPair
//         - AccessCheckInfo
//         - InterceptorInfo
//         - CallHandlerInfo
//         - TemplateInfo
//           - FunctionTemplateInfo
//           - ObjectTemplateInfo
//         - Script
//         - SignatureInfo
//         - TypeSwitchInfo
//         - DebugInfo
//         - BreakPointInfo
//         - CodeCache
``

tagged value:

```c++
// Formats of Object*:
//  Smi:        [31 bit signed int] 0
//  HeapObject: [32 bit direct pointer] (4 byte aligned) | 01
//  Failure:    [30 bit signed int] 11
```



### Object

继承自 `MaybeObject`，`Object` 里没有数据成员，这样做是为了避免继承自 `Object` 的 `Smi` 无法表示为一个 `tagged value`，同时也没有虚函数，避免 c++ 分配虚表影响内存布局。所有类型检查都基于 tag 或 Map。


`Object` 类定义常量：

```c++
  // Layout description.
  static const int kHeaderSize = 0;  // Object does not take up any space.
```

### Smi

smi 存储的是可以被存在 31 位以内的立即数：

```c++
// The this pointer has the following format: [31 bit signed int] 0
// For long smis it has the following format:
//     [32 bit signed int] [31 bits zero padding] 0
// Smi stands for small integer.
```

Smi 继承自 `Object`，没有任何的内存字段，它的解引用很简单：

```c++
// Smi constants for 64-bit systems.
template <> struct SmiTagging<8> {
  static const int kSmiShiftSize = 31;
  static const int kSmiValueSize = 32;
  V8_INLINE(static int SmiToInt(internal::Object* value)) {
    int shift_bits = kSmiTagSize + kSmiShiftSize;
    // Shift down and throw away top 32 bits.
    return static_cast<int>(reinterpret_cast<intptr_t>(value) >> shift_bits);
  }
};
```


定义了以下常量：

```c++
  static const int kMinValue =
      (static_cast<unsigned int>(-1)) << (kSmiValueSize - 1);
  static const int kMaxValue = -(kMinValue + 1);
```

### HeapObject

继承自 `Object`，同样的，只定义了常量，没有任何数据成员，其他都设计成了成员函数：

```c++
  // Layout description.
  // First field in a heap object is map.
  // 所有 HeapObject 的首字段布局固定为 map word，很多汇编和快路径硬编码该偏移。
  static const int kMapOffset = Object::kHeaderSize;
  static const int kHeaderSize = kMapOffset + kPointerSize;

  STATIC_CHECK(kMapOffset == Internals::kHeapObjectMapOffset);
```


### JSReceiver

继承自 `HeapObject`，SReceiver 是 JS 语义上“可接收属性操作”的抽象基类。普通对象走 `JSObject`，Harmony proxy 走 `JSProxy`；`Object::GetProperty` 等会提升到这里。

JSReceiver 自己不定义新的对象内字段，它更多是一个“属性语义接口层”。真正内存布局由子类定义，后面会讲解子类的时候会提到。


1. 属性 aka named properties

先声明了一些写入/删除属性相关的成员函数：

```c++
  static Handle<Object> SetProperty(Handle<JSReceiver> object,
                                    Handle<String> key,
                                    Handle<Object> value,
                                    PropertyAttributes attributes,
                                    StrictModeFlag strict_mode);
  // Can cause GC.
  // 属性写入可能分配新 Map、扩容属性数组、调用 setter/interceptor，因此返回
  // MaybeObject 以传播 GC/异常。
  MUST_USE_RESULT MaybeObject* SetProperty(
      String* key,
      Object* value,
      PropertyAttributes attributes,
      StrictModeFlag strict_mode,
      StoreFromKeyed store_from_keyed = MAY_BE_STORE_FROM_KEYED);
  MUST_USE_RESULT MaybeObject* SetProperty(
      LookupResult* result,
      String* key,
      Object* value,
      PropertyAttributes attributes,
      StrictModeFlag strict_mode,
      StoreFromKeyed store_from_keyed = MAY_BE_STORE_FROM_KEYED);
  MUST_USE_RESULT MaybeObject* SetPropertyWithDefinedSetter(JSReceiver* setter,
                                                            Object* value);
	MUST_USE_RESULT MaybeObject* DeleteProperty(String* name, DeleteMode mode);													
```

具体的实现在 `Objects.cc` 里

2. 元素 aka integer-indexed properties

```c++
  MUST_USE_RESULT MaybeObject* DeleteElement(uint32_t index, DeleteMode mode);

  // Set the index'th array element.
  // Can cause GC, or return failure if GC is required.
  // 元素写入可能触发数组增长、elements kind 迁移、dictionary 化或原型链 setter。
  MUST_USE_RESULT MaybeObject* SetElement(uint32_t index,
                                          Object* value,
                                          PropertyAttributes attributes,
                                          StrictModeFlag strict_mode,
                                          bool check_prototype);
```




### JsObject

继承自 `JsReceiver`，主要有以下几个字段：



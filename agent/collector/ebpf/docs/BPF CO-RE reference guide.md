# CO-RE guide

CO-RE, 即 compile once run everywhere, 是我们编写 BPF 程序的时候经常会看到的概念。本文即笔记 & 理解

## bpf_core_read(小写的, 注意没写错)

在 kernel 上的细微差异, 主要体现在 bpf 程序读取结构体的时候 offset 区别, bpf_core_read 来解决这一问题

## bpf_core_read_str

跟上述基本相同, 唯一一个容易混淆的地方在于:

```c
struct my_kernel_type {
    const char *name;
    char type[32];
};
```

注意一下字符串指针和字符串 array 的区别, 在 C 里面两者可交替的, 因为编译器自动的把 array 识别成了一个 pointer, 但是在 BPF 里是不一样的

我们在读 pointer 的时候, 直接用 bpf_core_read 没问题, 就跟我们读取任意一个结构体一样。原文为：name field points to where a string is stored, but type field actually is the memory that contains a string。意思是 *name 是一个指向字符串的指针, 而 type 其实是存储字符串的 memory, 所以实际上在CO-RE里，合理的处理方式为：读取指针的值。所以用 bpf_core_read_str, 对应的就是 bpf_probe_read_kernel_str。

[ 注 ]: 原话为 except it records CO-RE relocation information of the source character array field, which contains a zero-terminated C string. 多了一个结束符注意一下

## BPF_CORE_READ()

...
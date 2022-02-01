# Reconsidering CO-RE in eBPF

I was pretty confused about CO-RE with questions like the minimum kernel version we need for running or compiling or the impact of BTF in CO-RE both running and compiling. So this README is about to record the answers to those trivial issues that I came across.

# Q1: What is BTF?

BTF(BPF Type Format) is the metadata format that encodes the debug info related to the BPF program/map. The BTF was later extended to include function info for defined subroutines, and line info for source/line information.

# Q2: What is the relationship between BTF and libbpf and BPF program?

Firstly, it is important to know some basic information about CO-RE and libbpf. 

CO-RE(compile once - run everywhere) is the future of eBPF since portable is extremely important in the real world. We have to compile the program from different distribution and kernel version for every machine without CO-RE. Some toolkits like bcc, have to rely on runtime compilations in such situations. CO-RE works like this

[ bpf program ] - [ libbpf ] - [ BTF - kernel ]

But unfortunately, only the lastest version of Linux kernels, here is the [list](https://github.com/aquasecurity/btfhub/blob/main/docs/supported-distros.md) of supporting. BTF start to be a built-in feature from like 4.18 in centos and 5.4.0+ in ubuntu. A backported patch is needed if we want to run the BPF program in a CO-RE way. 

This is different from the original purpose. It seems more convenient to compile from kernel-headers if BTF is not supported.

# Q3: How to call strncmp/strcpy in eBPF program.

The answer is NO. **BPF programs cannot use functions from the libc.**

Dealing with strings in BPF program can be a tricky thing. Only a few built-in helper functions and __builtin_ functions are available during the coding.

# Reference

- [bpf-portability-and-co-re](https://nakryiko.com/posts/bpf-portability-and-co-re/)
- [failure-to-compile-strings-with-eBPF](https://stackoverflow.com/questions/60383861/failure-to-compare-strings-with-ebpf)